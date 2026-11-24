"""Cold-build the native HIA scalar NDU evaluator and framed process owner."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_ndu_native import SCHEMA, PROFILE, SOURCES, UPSTREAM
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_ndu_scalar_packer import ADAPTER, PACKER, MAGIC
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/ndu_scalar.hepta'


def digest(data):
    return sha256(data).hexdigest()


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    cold_bytes = None if development else Path(cold_report).read_bytes()
    admitted = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    captured = {name: (ROOT / name).read_bytes() for name in SOURCES}
    pins = {name: digest(raw) for name, raw in captured.items()}
    if admitted is not None and any(admitted.get(name) != value for name, value in pins.items()):
        raise ValueError('HIA NDU component inputs differ from matching cold source')
    binding = read_adapter_binding(captured[PACKER], captured[ADAPTER], calls=1)
    output.mkdir(mode=0o700)
    application, application_receipt = compile_stage(output, 'ndu-scalar', compiler, captured[SOURCE])
    packer, packer_receipt = compile_stage(output, 'ndu-scalar-packer', compiler, captured[PACKER])
    code, packer_bytes = application.read_bytes(), packer.read_bytes()
    if digest(code) != application_receipt['produced_sha256'] or digest(packer_bytes) != packer_receipt['produced_sha256']:
        raise ValueError('HIA NDU compiler outputs changed')
    packet = struct.pack('<2Q', MAGIC, len(code)) + code
    packed, pack_receipt = compile_stage(output, 'packed-ndu', packer, packet, output_extension='.elf')
    binary = packed.read_bytes()
    if digest(binary) != pack_receipt['produced_sha256']:
        raise ValueError('HIA NDU packer output changed')
    verify_adapter(binary, code, binding, entries=(0,))
    inspection = inspect_executable(binary)
    if (compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or application.read_bytes() != code or packer.read_bytes() != packer_bytes
            or packed.read_bytes() != binary
            or (admitted is not None and (Path(cold_report).read_bytes() != cold_bytes or current_sources() != admitted))):
        raise ValueError('HIA NDU build inputs or outputs changed before publication')
    executable = output / 'hia-ndu-scalar'
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report = {
        'schema': SCHEMA, 'implementation': 'HIA', 'profile': PROFILE,
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'compatibility_upstream_commit': UPSTREAM,
        'executable_path': executable.name, 'executable_sha256': digest(binary),
        'source_sha256': pins, 'compiler_sha256': digest(compiler_bytes),
        'cold_report_sha256': None if development else digest(cold_bytes),
        'transport_adapter_sha256': binding[0].hex(),
        'transport_assembled_during_build': False, 'build_inputs_unchanged': True,
        'executable': inspection, 'native_compile_receipt': application_receipt,
        'native_packer_receipt': packer_receipt, 'native_pack_receipt': pack_receipt,
    }
    with (output / 'build-receipt.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == '__main__':
    main()
