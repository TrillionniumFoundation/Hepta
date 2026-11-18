"""Build the explicit native HIA persistent Agent transaction root and modules."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_batch_commit import ELF_HEADER_SIZE, assemble_adapter, digest
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

PROGRAMS = 'examples/hia_bootstrap/agent_store/'
ADAPTER = 'tools/hia_agent_store_syscalls.S'
DRIVER = 'tools/build_hia_agent_store.py'
ADAPTER_READER = 'tools/build_hia_agent_batch_commit.py'
PLAN = PROGRAMS + 'build-plan.json'
CANARY = b'\xb3' * 64
CAPACITY = 1 << 20


def write_new(path, raw, mode=0o600):
    with path.open('xb') as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), mode)


def apply_filter(image, flat, spec):
    payload = bytes.fromhex(spec['input_prefix_hex']) + flat
    size = spec['image_bytes']
    if (digest(flat) != spec['raw_sha256'] or digest(payload) != spec['frame_sha256']
            or type(size) is not int or not 0 < size <= CAPACITY):
        raise ValueError('native unit differs from its fixed word-filter contract')
    source = bytearray(CANARY + payload + CANARY)
    output = bytearray(CANARY + b'\xa7' * size + CANARY)
    workspace = bytearray(CANARY + bytes(16 << 10) + CANARY)
    buffers = (source, output, workspace)
    pointers = [ctypes.addressof(ctypes.c_ubyte.from_buffer(buffer)) + len(CANARY) for buffer in buffers]
    for count in range(1, 4097):
        status = image._entry(pointers[0], len(payload), pointers[1], size, pointers[2], 16 << 10)
        if status:
            break
    else:
        raise ValueError('native word filter did not reach a terminal result')
    result = bytes(memoryview(output)[len(CANARY):-len(CANARY)])
    if (status != size or digest(result) != spec['image_sha256']
            or memoryview(source)[len(CANARY):-len(CANARY)] != payload
            or any(buffer[:len(CANARY)] != CANARY or buffer[-len(CANARY):] != CANARY for buffer in buffers)):
        raise ValueError('native word filter refused or changed protected bytes')
    return result, count


def build_modules(output, plan, images, packer):
    modules = output / 'module-root'
    modules.mkdir(mode=0o700)
    records = []
    for group in plan:
        role = group['role']
        if role != len(records) or not 1 <= len(group['units']) <= 8:
            raise ValueError('invalid native module role or unit count')
        parts = [images[name] for name in group['units']]
        sizes = [len(part) for part in parts]
        padded = sizes + [0] * (8 - len(sizes))
        payload = struct.pack('<8s11Q', b'HIAUBPK1', 1, len(parts), 0, *padded) + b''.join(parts)
        name = f'module-{role}.bin'
        path, receipt = compile_stage(output, f'module-{role}', packer, payload,
                                      output_extension='.bundle.bin')
        bundle = path.read_bytes()
        want = group['sha256']
        if not digest(bundle) == want == receipt['produced_sha256']:
            raise ValueError(f'native role {role} differs from its admitted bundle')
        write_new(modules / name, bundle, 0o400)
        records.append(name.encode().ljust(64, b'\0') + struct.pack('<Q', len(bundle))
                       + sha256(bundle).digest()
                       + struct.pack('<3Q', group['workspace'], group['output'], role))
    return struct.pack('<8s3Q', b'HIAMSI01', 1, len(records), 0) + b''.join(records)


def verify_root(binary, stub, symbols, parts):
    starts = {
        'loader': ('loader_call_hole', b'\xe8'),
        'owner': ('owner_call_hole', b'\xe8'),
        'manifest': ('manifest_address_hole', b'\x48\x8d\x35'),
        'json': ('json_call_hole', b'\xe8'),
    }
    expected = bytearray(stub)
    for label, img in parts.items():
        symbol, instruction = starts[label]
        at = symbols[symbol]
        if (not len(instruction) <= at <= len(stub) - 4
                or stub[at - len(instruction):at + 4] != instruction + bytes(4)):
            raise ValueError(f'wrong adapter placement for {label}')
        expected.extend(bytes((-len(expected)) % 8))
        struct.pack_into('<i', expected, at, len(expected) - (at + 4))
        expected.extend(img)
    if binary[ELF_HEADER_SIZE:] != expected:
        raise ValueError('root ELF disagrees with the exact adapter, module manifest or HIA inputs')


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    plan_bytes = (ROOT / PLAN).read_bytes()
    if admitted.get(PLAN) != digest(plan_bytes):
        raise ValueError('native Agent Store plan differs from admitted cold source')
    plan = json.loads(plan_bytes)
    if plan.get('schema') != 'hepta.hia.agent-store-build-plan.v1' or len(plan['modules']) != 4:
        raise ValueError('invalid native Agent Store build plan')
    unit_files = {label: PROGRAMS + row['source'] for label, row in plan['units'].items()}
    filters = {'word-filter': PROGRAMS + 'word_filter.hepta',
               'bundle-packer': PROGRAMS + 'bundle_packer.hepta'}
    sources = {name: (ROOT / name).read_bytes() for name in
               (*unit_files.values(), *filters.values(), ADAPTER, DRIVER, ADAPTER_READER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('native Agent Store source differs from admitted cold source')
    output.mkdir(mode=0o700)
    compiled, receipts = {}, {}
    for label, name in {**filters, **unit_files}.items():
        path, receipts[label] = compile_stage(output, label, compiler, sources[name])
        flat = path.read_bytes()
        if digest(flat) != receipts[label]['produced_sha256']:
            raise ValueError(f'compiled Agent Store unit changed: {label}')
        compiled[label] = (path, flat)
    filter_bytes = compiled['word-filter'][1]
    relocator = NativeHiaJsonImage(filter_bytes, digest(filter_bytes))
    images, calls = {}, {}
    for name, unit in plan['units'].items():
        if 'id' not in unit:
            continue
        images[name], calls[name] = apply_filter(relocator, compiled[name][1], unit)
    if digest(compiled['bundle-packer'][1]) != plan['bundle_packer_sha256']:
        raise ValueError('native bundle packer identity changed')
    manifest = build_modules(output, plan['modules'], images, compiled['bundle-packer'][0])
    if digest(manifest) != plan['expected_manifest_sha256']:
        raise ValueError('native Agent Store module manifest identity changed')
    parts = {'loader': images['loader'], 'owner': images['owner'],
             'manifest': manifest, 'json': images['JSON_hub']}
    packet = struct.pack('<8s4Q', b'HIA4PK01', *(len(part) for part in parts.values()))
    packet += b''.join(parts.values())
    elf, pack_receipt = compile_stage(output, 'hia-agent-store', compiled['packer'][0], packet,
                                      output_extension='.elf')
    binary = elf.read_bytes()
    if not digest(binary) == pack_receipt['produced_sha256'] == plan['expected_root_sha256']:
        raise ValueError('native Agent Store root identity changed')
    inspection = inspect_executable(binary)
    stub, symbols, object_sha = assemble_adapter(output, ADAPTER, sources[ADAPTER])
    verify_root(binary, stub, symbols, parts)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or (ROOT / PLAN).read_bytes() != plan_bytes
            or any(path.read_bytes() != data for path, data in compiled.values())
            or elf.read_bytes() != binary or (output / Path(ADAPTER).name).read_bytes() != sources[ADAPTER]
            or any(digest((output / 'module-root' / f"module-{group['role']}.bin").read_bytes()) != group['sha256']
                   for group in plan['modules'])):
        raise ValueError('Agent Store build inputs changed before publication')
    executable = output / 'hia-agent-store'
    write_new(executable, binary, 0o500)
    report = {
        'schema': 'hepta.hia.agent-store-build.v1',
        'status': 'NATIVE_AGENT_STORE_ROOT_BUILT',
        'source_sha256': {PLAN: digest(plan_bytes), **{name: digest(raw) for name, raw in sources.items()}},
        'compiler_sha256': digest(compiler_bytes),
        'cold_report_sha256': digest(cold_bytes),
        'module_root': 'module-root',
        'module_manifest_sha256': digest(manifest),
        'module_sha256': {f"module-{group['role']}.bin": group['sha256'] for group in plan['modules']},
        'executable_path': executable.name,
        'executable_sha256': digest(binary),
        'executable': inspection,
        'adapter_object_sha256': object_sha,
        'compile_receipts': receipts,
        'word_filter_calls': calls,
        'pack_receipt': pack_receipt,
        'default_agent_store_replaced': False,
    }
    write_new(output / 'build.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
