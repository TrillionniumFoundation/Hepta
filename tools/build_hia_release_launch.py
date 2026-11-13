"""Build the explicit selected-release launcher from matching cold authority.

This build-time custody driver is hosted. No retained-development shortcut is
accepted here. The produced executable does not import this module at runtime.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_release_launch import MAGIC
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/release_install_policy.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'examples/hia_bootstrap/release_selection_policy.hepta',
    'examples/hia_bootstrap/release_launch_policy.hepta',
    'examples/hia_bootstrap/release_launch_packer.hepta',
    'tools/generate_hia_release_install.py',
    'tools/hia_release_install_syscalls.S',
    'tools/generate_hia_release_selection.py',
    'tools/hia_release_selection_syscalls.S',
    'tools/generate_hia_release_launch.py',
    'tools/hia_release_launch_syscalls.S',
    'tools/build_hia_release_launch.py',
)


def build(output: Path, compiler: Path, cold_report: Path):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    source_bytes = {name: (ROOT/name).read_bytes() for name in SOURCES}
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in source_bytes.items()):
        raise ValueError('selected-launch source missing from matching cold contract')
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for label, name in zip(('installer', 'sha256', 'selection', 'launch', 'packer'), SOURCES[:5]):
        path, receipts[label] = compile_stage(output, label, compiler, source_bytes[name])
        images[label] = path, path.read_bytes()
    payloads = [images[key][1] for key in ('installer', 'sha256', 'selection', 'launch')]
    frame = struct.pack('<5Q', MAGIC, *map(len, payloads)) + b''.join(payloads)
    result, packed = invoke(output, 'launch-pack', images['packer'][0], frame)
    size = result.get('core_u32')
    if result.get('status') != 'returned' or type(size) is not int or not 0 < size <= len(packed):
        raise ValueError('native HIA selected-launch packer refused image frame')
    raw = packed[:size]
    inspection = inspect_executable(raw)
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or any((ROOT/name).read_bytes() != data for name, data in source_bytes.items())
            or any(path.read_bytes() != data for path, data in images.values())
            or current_sources() != admitted):
        raise ValueError('selected-launch inputs changed before publication')
    executable = output/'hia-run-selected'
    with executable.open('xb') as stream:
        stream.write(raw)
    executable.chmod(0o700)
    report = {
        'schema': 'hepta.hia.release-launch-build.v1',
        'status': 'NATIVE_SELECTED_RELEASE_LAUNCHER_BUILT',
        'source_manifest': admitted,
        'source_sha256': {name: sha256(data).hexdigest() for name, data in source_bytes.items()},
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'image_sha256': {name: sha256(data).hexdigest() for name, (_, data) in images.items()},
        'executable_path': executable.name,
        'executable_sha256': sha256(raw).hexdigest(),
        'executable': inspection,
        'compile_receipts': receipts,
        'pack_receipt': result,
        'runtime_python_or_libc_required': False,
        'runtime_fork_or_supervisor_required': False,
        'explicit_in_place_native_exec': True,
        'captured_package_fd': 3,
        'business_stdio': [0, 1, 2],
        'unchanged_selection_verification': True,
        'old_verify_grants_execution': False,
        'package_hash_proves_hia_code': False,
        'host_build_and_code_custody': True,
        'default_cli_or_worker_replaced': False,
        'live_service_or_mcp_migrated': False,
        'automatic_retry_or_release_retirement': False,
        'whole_native_delivery_qualified': False,
    }
    with (output/'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
