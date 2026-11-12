"""Build explicit source-bound native release selection from a qualified compiler.

This build/custody driver remains hosted. Its produced ELF has no interpreter,
libc, child executable or hosted state/verification decision at runtime.
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
from tools.generate_hia_release_selection import MAGIC
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/release_install_policy.hiaasm',
    'examples/hia_bootstrap/sha256_stream.hiaasm',
    'examples/hia_bootstrap/release_selection_policy.hiaasm',
    'examples/hia_bootstrap/release_selection_packer.hiaasm',
    'tools/generate_hia_release_install.py',
    'tools/hia_release_install_syscalls.S',
    'tools/generate_hia_release_selection.py',
    'tools/hia_release_selection_syscalls.S',
    'tools/build_hia_release_selection.py',
)


def build(output: Path, compiler: Path, cold_report: Path):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    source_bytes = {name: (ROOT/name).read_bytes() for name in SOURCES}
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in source_bytes.items()):
        raise ValueError('release selection source missing from matching cold contract')
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for label, name in zip(('policy', 'sha256', 'selection', 'packer'), SOURCES[:4]):
        image, receipts[label] = compile_stage(output, label, compiler, source_bytes[name])
        images[label] = image, image.read_bytes()
    payloads = [images[key][1] for key in ('policy', 'sha256', 'selection')]
    frame = struct.pack('<4Q', MAGIC, *map(len, payloads)) + b''.join(payloads)
    result, packed = invoke(output, 'selection-pack', images['packer'][0], frame)
    size = result.get('core_u32')
    if result.get('status') != 'returned' or type(size) is not int or not 0 < size <= len(packed):
        raise ValueError('native HIA selection packer refused image frame')
    raw = packed[:size]
    inspection = inspect_executable(raw)
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or any((ROOT/name).read_bytes() != data for name, data in source_bytes.items())
            or any(path.read_bytes() != data for path, data in images.values())
            or current_sources() != admitted):
        raise ValueError('release selection inputs changed before publication')
    executable = output/'hia-select'
    with executable.open('xb') as stream:
        stream.write(raw)
    executable.chmod(0o700)
    report = {
        'schema': 'hepta.hia.release-selection-build.v1',
        'status': 'NATIVE_RELEASE_SELECTION_BUILT',
        'source_manifest': admitted,
        'source_sha256': {name: sha256(data).hexdigest() for name, data in source_bytes.items()},
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'image_sha256': {name: sha256(data).hexdigest() for name, (_, data) in images.items()},
        'executable_path': executable.name, 'executable_sha256': sha256(raw).hexdigest(),
        'executable': inspection, 'compile_receipts': receipts, 'pack_receipt': result,
        'runtime_python_or_libc_or_child_required': False,
        'host_build_and_code_custody': True,
        'actual_installer_policy_and_verifier_reused': True,
        'operator_expected_sequence_and_current_required': True,
        'kernel_flock_serialization': True,
        'atomic_selection_and_fsync_readback': True,
        'old_release_bytes_overwritten': False,
        'live_service_migration_or_default_cli_cutover': False,
        'automatic_stage_cleanup_or_release_retirement': False,
        'complete_native_build_or_release_lifecycle': False,
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
