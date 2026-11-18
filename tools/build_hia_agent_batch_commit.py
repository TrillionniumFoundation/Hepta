"""Bootstrap the explicit Linux x86-64 HIA Agent transaction executables."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import assemble
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable


PARTS = {
    'writer': 'examples/hia_bootstrap/agent_transaction_writer.hepta',
    'stager': 'examples/hia_bootstrap/agent_transaction_stager.hepta',
    'producer': 'examples/hia_bootstrap/agent_transaction_producer.hepta',
}
VARIANTS = {
    'batch': ('hia-agent-batch-commit', b'HIA3PK01',
              'examples/hia_bootstrap/agent_transaction_stager_packer.hepta',
              'tools/hia_agent_transaction_stager_syscalls.S',
              {name: name + '_call_hole' for name in PARTS}),
    'sealed': ('hia-agent-sealed-commit', b'HIAWPK01',
               'examples/hia_bootstrap/agent_transaction_writer_packer.hepta',
               'tools/hia_agent_transaction_writer_syscalls.S',
               {'writer': 'policy_call_hole'}),
}
DRIVER = 'tools/build_hia_agent_batch_commit.py'
ELF_HEADER_SIZE = 176


def digest(raw):
    return sha256(raw).hexdigest()


def adapter_layout(output, adapter, source, call_symbols):
    # Build-time verification only. The checked-in HIA packer assembles the
    # actual ELF; these tools independently check the retained syscall bytes.
    object_bytes = assemble(output, adapter, source)
    object_path = Path(adapter).name + '.o'
    commands = {
        'relocations': ['readelf', '-r', object_path],
        'symbols': ['nm', '-n', object_path],
        'text': ['objcopy', '-O', 'binary', '-j', '.text', object_path, 'adapter.text.bin'],
    }
    observations = {}
    for label, (command, *arguments) in commands.items():
        observations[label] = subprocess.run(
            ['/usr/bin/' + command, *arguments], stdin=subprocess.DEVNULL, capture_output=True,
            cwd=output, env={'PATH': '', 'LC_ALL': 'C'}, timeout=10, check=True,
        ).stdout
    if observations['relocations'].strip() != b'There are no relocations in this file.':
        raise ValueError('transaction syscall adapter must not contain ELF relocations')
    symbols = {}
    for row in observations['symbols'].splitlines():
        fields = row.split()
        if len(fields) == 3 and fields[1] == b'T':
            symbols[fields[2].decode('ascii')] = int(fields[0], 16)
    stub = (output / 'adapter.text.bin').read_bytes()
    holes = {name: symbols.get(symbol, 0) for name, symbol in call_symbols.items()}
    if ((output / object_path).read_bytes() != object_bytes or not stub
            or symbols.get('_start') != 0 or len(set(holes.values())) != len(holes)
            or any(not 0 < offset <= len(stub) - 4
                   or stub[offset - 1:offset + 4] != b'\xe8\0\0\0\0' for offset in holes.values())):
        raise ValueError('invalid transaction syscall adapter entry or call placement')
    return stub, holes, digest(object_bytes)


def verify_placement(binary, stub, holes, parts):
    laid_out = bytearray(stub)
    for name, image in parts.items():
        laid_out.extend(bytes((-len(laid_out)) % 8))
        hole = holes[name]
        struct.pack_into('<i', laid_out, hole, len(laid_out) - (hole + 4))
        laid_out.extend(image)
    if binary[ELF_HEADER_SIZE:] != laid_out:
        raise ValueError('native packer changed the admitted syscall adapter or HIA images')


def build(output, compiler, cold_report, *, kind='batch'):
    executable_name, tag, packer, adapter, call_symbols = VARIANTS[kind]
    source_units = {label: PARTS[label] for label in call_symbols}
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    sources = {name: (ROOT / name).read_bytes() for name in (*source_units.values(), packer, adapter, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('transaction commit build source differs from admitted cold source')
    output.mkdir(mode=0o700)
    compiled = {}
    receipts = {}
    for label, source_name in {**source_units, 'packer': packer}.items():
        image_path, receipts[label] = compile_stage(output, label, compiler, sources[source_name])
        compiled[label] = (image_path, image_path.read_bytes())
        if digest(compiled[label][1]) != receipts[label]['produced_sha256']:
            raise ValueError('compiled transaction image identity changed')
    parts = {label: compiled[label][1] for label in source_units}
    payload = tag + b''.join(struct.pack('<Q', len(image)) for image in parts.values())
    payload += b''.join(parts.values())
    native_path, pack_receipt = compile_stage(output, executable_name, compiled['packer'][0],
                                             payload, output_extension='.elf')
    binary = native_path.read_bytes()
    if digest(binary) != pack_receipt['produced_sha256']:
        raise ValueError('native transaction executable identity changed')
    inspection = inspect_executable(binary)
    stub, holes, adapter_object = adapter_layout(output, adapter, sources[adapter], call_symbols)
    verify_placement(binary, stub, holes, parts)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes
            or any(path.read_bytes() != data for path, data in compiled.values())
            or (output / Path(adapter).name).read_bytes() != sources[adapter]
            or native_path.read_bytes() != binary):
        raise ValueError('transaction commit build input changed before publication')
    executable = output / executable_name
    with executable.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    report = {
        'schema': 'hepta.hia.agent-batch-commit-build.v1',
        'status': {'batch': 'NATIVE_AGENT_BATCH_COMMIT_BUILT',
                   'sealed': 'NATIVE_AGENT_SEALED_COMMIT_BUILT'}[kind],
        'executable_path': executable_name,
        'source_sha256': {name: digest(raw) for name, raw in sources.items()},
        'compiler_sha256': digest(compiler_bytes),
        'cold_report_sha256': digest(cold_bytes),
        'adapter_object_sha256': adapter_object,
        'adapter_text_sha256': digest(stub),
        'executable_sha256': digest(binary),
        'executable': inspection,
        'compile_receipts': receipts,
        'pack_receipt': pack_receipt,
        'agent_store_replaced': False,
    }
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--kind', choices=VARIANTS, default='batch')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(), kind=args.kind))


if __name__ == '__main__':
    main()
