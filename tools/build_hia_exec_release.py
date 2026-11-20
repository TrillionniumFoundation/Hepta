"""Explicit bootstrap for the HIA-owned executable release builder.

The output is a standalone Linux x86-64 ELF. Python is only this bootstrap and
evidence driver; the executable does not call it, parse a Python policy, start a
compiler subprocess or reconstruct a release package in a host language.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_compile_receipt, _check_pack_output
from tools.generate_hia_exec_release import MAGIC, LIMIT, MAPPING_BYTES
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/exec_release_policy.hepta',
    'examples/hia_bootstrap/exec_release_packer.hepta',
    'examples/hia_bootstrap/core_json_frontend.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'examples/hia_bootstrap/selfhost.hepta',
    'tools/generate_hia_exec_release.py',
    'tools/hia_exec_release_syscalls.S',
    'tools/build_hia_exec_release.py',
    'tools/qualify_hia_exec_release.py',
    'tools/hia_exec_release_child.py',
    'tools/read_hia_exec_release.py',
    'tests/hia_exec_release_controls.py',
    'tests/test_hia_exec_release.py',
    'docs/HIA_EXEC_RELEASE_NATIVE.md',
)
IMAGE_SOURCES = (
    ('policy', SOURCES[0]), ('packer', SOURCES[1]),
    ('frontend', SOURCES[2]), ('sha256', SOURCES[3]),
)
SCHEMA = 'hepta.hia.exec-release-build.v1'


def exact_file(path, raw, mode):
    path = Path(path)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short private build file write')
        stream.flush()
    path.chmod(mode)
    if path.read_bytes() != raw or path.stat().st_mode & 0o777 != mode:
        raise ValueError('private build file differs')
    return path


def _admission(compiler_raw, cold_raw, *, development, expected_compiler_sha256):
    if type(development) is not bool:
        raise ValueError('explicit development choice must be bool')
    if development:
        if cold_raw is not None:
            raise ValueError('development and completed cold authority are disjoint')
        if (type(expected_compiler_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', expected_compiler_sha256) is None
                or sha256(compiler_raw).hexdigest() != expected_compiler_sha256):
            raise ValueError('explicit development compiler byte pin is required')
        return current_sources(), 'EXPLICIT_DEVELOPMENT_BUILD_ONLY'
    if cold_raw is None or expected_compiler_sha256 is not None:
        raise ValueError('completed matching cold authority is required')
    return admit_cold_build(compiler_raw, cold_raw), 'CURRENT_SOURCE_COLD'


def build(output: Path, compiler: Path, cold_report: Path | None, *,
          development=False, expected_compiler_sha256=None) -> Path:
    compiler_raw = compiler.read_bytes()
    cold_raw = None if cold_report is None else cold_report.read_bytes()
    admitted, authority = _admission(compiler_raw, cold_raw,
        development=development, expected_compiler_sha256=expected_compiler_sha256)
    source_raw = {name: (ROOT / name).read_bytes() for name in SOURCES}
    if (not 0 < len(compiler_raw) <= LIMIT
            or any(admitted.get(name) != sha256(raw).hexdigest()
                   for name, raw in source_raw.items())):
        raise ValueError('complete exec-release source closure differs from the admitted contract')
    # Admission precedes output creation. No cold failure reaches a DEV branch.
    output.mkdir(mode=0o700)
    pinned = exact_file(output / 'captured-compiler.image.bin', compiler_raw, 0o400)
    if cold_raw is not None:
        exact_file(output / 'captured-cold.json', cold_raw, 0o400)
    images, receipts, consumed = {}, {}, {pinned: compiler_raw}
    for label, name in IMAGE_SOURCES:
        path, receipt = compile_stage(output, label, pinned, source_raw[name])
        raw = path.read_bytes()
        _check_compile_receipt(receipt, compiler=compiler_raw, source=source_raw[name], produced=raw)
        if (type(receipt.get('result_u64')) is not int
                or receipt['result_u64'] != len(raw)
                or receipt.get('format') != 'flat-x86-64'
                or receipt.get('return_encoding') != 'zero-extended-u32'):
            raise ValueError('compiler return is not the complete ordinary flat-image ABI')
        images[label] = (path, raw)
        receipts[label] = receipt
        consumed[path] = raw
        receipt_path = output / (label + '.receipt.json')
        receipt_raw = receipt_path.read_bytes()
        if json.loads(receipt_raw) != receipt:
            raise ValueError('compile receipt raw does not bind returned metadata')
        consumed[receipt_path] = receipt_raw
    image_order = (images['policy'][1], images['frontend'][1],
                   compiler_raw, images['sha256'][1])
    frame = struct.pack('<5Q', MAGIC, *(len(raw) for raw in image_order)) + b''.join(image_order)
    if len(frame) > LIMIT:
        raise ValueError('four admitted images exceed the unchanged one-MiB packer input')
    result, packed = invoke(output, 'native-pack', images['packer'][0], frame)
    executable_raw = _check_pack_output(result, packed, artifact=images['packer'][1], source=frame)
    inspection = inspect_executable(executable_raw)
    if inspection['program_headers'] != ['PT_LOAD_RX', 'PT_GNU_STACK_RW']:
        raise ValueError('exec-release packer output is not its canonical two-segment executable')
    consumed[output / 'native-pack.receipt.json'] = (output / 'native-pack.receipt.json').read_bytes()
    if json.loads(consumed[output / 'native-pack.receipt.json']) != result:
        raise ValueError('packer receipt raw differs')
    if (compiler.read_bytes() != compiler_raw
            or (cold_report is not None and cold_report.read_bytes() != cold_raw)
            or any((ROOT / name).read_bytes() != raw for name, raw in source_raw.items())
            or any(path.read_bytes() != raw for path, raw in consumed.items())
            or current_sources() != admitted):
        raise ValueError('source, compiler, actual native artifact or receipt changed')
    executable = exact_file(output / 'hia-exec-release', executable_raw, 0o500)
    report = {
        'schema': SCHEMA, 'status': 'NATIVE_EXEC_RELEASE_BUILT',
        'authority': authority, 'development_only': development,
        'source_manifest': admitted,
        'source_sha256': {name: sha256(raw).hexdigest() for name, raw in source_raw.items()},
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'cold_report_sha256': None if cold_raw is None else sha256(cold_raw).hexdigest(),
        'image_paths': {name: path.name for name, (path, _) in images.items()},
        'image_sha256': {name: sha256(raw).hexdigest() for name, (_, raw) in images.items()},
        'compile_receipts': receipts, 'pack_receipt': result,
        'packer_frame_sha256': sha256(frame).hexdigest(), 'packer_frame_bytes': len(frame),
        'executable_path': executable.name,
        'executable_sha256': sha256(executable_raw).hexdigest(),
        'executable_bytes': len(executable_raw), 'executable': inspection,
        'memory_mapping_bytes': MAPPING_BYTES,
        'source_assembly_limit': LIMIT, 'source_json_limit': 8 << 20,
        'expanded_assembly_limit': LIMIT, 'produced_image_limit': LIMIT,
        'runtime_language': 'HIA plus fixed Linux syscall/three-buffer ABI transport',
        'runtime_python_or_libc_or_child_required': False,
        'runtime_generated_input_image_execution': False,
        'host_bootstrap_and_evidence_driver': True,
        'operator_expected_source_sha256_required': True,
        'installation_requires_separate_operator_expected_package_sha256': True,
        'ordinary_cli_default_changed': False, 'public_vm_replaced': False,
        'whole_native_delivery_qualified': False, 'all_input_equivalence_proved': False,
        'cold_or_gc_or_existing_resource_holds_resolved': False,
    }
    raw_report = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    exact_file(output / 'build.json', raw_report, 0o400)
    if (executable.read_bytes() != executable_raw
            or any(path.read_bytes() != raw for path, raw in consumed.items())
            or any((ROOT / name).read_bytes() != raw for name, raw in source_raw.items())
            or current_sources() != admitted):
        raise ValueError('exec-release bootstrap final readback changed')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--compiler-sha256')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(),
                None if args.cold_report is None else args.cold_report.resolve(),
                development=args.development, expected_compiler_sha256=args.compiler_sha256))


if __name__ == '__main__':
    main()
