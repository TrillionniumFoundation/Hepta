"""Build a source-bound HIA release installer or directory packager.

This remains the explicit hosted bootstrap/custody driver. The produced ELF
installs/verifies packages, or builds packages from a private directory, without
Python, libc or another executable.
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
from tools.generate_hia_release_install import MAGIC
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/release_install_policy.hepta',
    'examples/hia_bootstrap/release_install_packer.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'tools/generate_hia_release_install.py',
    'tools/hia_release_install_syscalls.S',
    'tools/build_hia_release_install.py',
)
DIRECTORY_SOURCES = (
    'examples/hia_bootstrap/release_directory_policy.hepta',
    'examples/hia_bootstrap/release_directory_packer.hepta',
    SOURCES[2],
    SOURCES[3],
    'tools/hia_release_directory_syscalls.S',
    SOURCES[5],
)


def build(output: Path, compiler: Path, cold_report: Path, *, kind='installer'):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources, executable_name = {
        'installer': (SOURCES, 'hia-release'),
        'directory': (DIRECTORY_SOURCES, 'hia-directory-package-build'),
    }[kind]
    source_bytes = {name: (ROOT/name).read_bytes() for name in sources}
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in source_bytes.items()):
        raise ValueError('release tool source missing from matching cold contract')
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for label, name in zip(('policy', 'packer', 'sha256'), sources[:3]):
        image, receipts[label] = compile_stage(output, label, compiler, source_bytes[name])
        images[label] = (image, image.read_bytes())
    policy, sha = images['policy'][1], images['sha256'][1]
    frame = struct.pack('<3Q', MAGIC, len(policy), len(sha)) + policy + sha
    result, packed = invoke(output, 'release-pack', images['packer'][0], frame)
    size = result.get('core_u32')
    if result.get('status') != 'returned' or type(size) is not int or not 0 < size <= len(packed):
        raise ValueError('native HIA release packer refused image frame')
    raw = packed[:size]
    inspection = inspect_executable(raw)
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or any((ROOT/name).read_bytes() != data for name, data in source_bytes.items())
            or any(path.read_bytes() != data for path, data in images.values())
            or current_sources() != admitted):
        raise ValueError('release installer inputs changed before publication')
    executable = output/executable_name
    with executable.open('xb') as stream:
        stream.write(raw)
    executable.chmod(0o700)
    report = {
        'schema': 'hepta.hia.release-install-build.v1',
        'status': 'NATIVE_RELEASE_INSTALLER_BUILT',
        'source_manifest': admitted,
        'source_sha256': {name: sha256(data).hexdigest() for name, data in source_bytes.items()},
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'image_sha256': {name: sha256(data).hexdigest() for name, (_, data) in images.items()},
        'executable_path': executable.name, 'executable_sha256': sha256(raw).hexdigest(),
        'executable': inspection, 'compile_receipts': receipts, 'pack_receipt': result,
        'runtime_python_or_libc_or_child_required': False,
        'host_build_and_code_custody': True,
        'explicit_linux_x86_64_syscall_adapter': True,
        'operator_expected_package_sha256_required': kind == 'installer',
        'release_publication_no_replace': kind == 'installer',
        'failed_stages_retained': True,
        'default_activation_or_worker_migration': False,
        'complete_native_build_or_release_lifecycle': False,
        'whole_native_delivery_qualified': False,
    }
    if kind == 'directory':
        report['schema'] = 'hepta.hia.release-directory-build.v1'
        report['status'] = 'NATIVE_RELEASE_DIRECTORY_BUILDER_BUILT'
    with (output/'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--kind', choices=('installer', 'directory'), default='installer')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(), kind=args.kind))


if __name__ == '__main__':
    main()
