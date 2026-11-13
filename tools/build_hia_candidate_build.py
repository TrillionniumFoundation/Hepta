"""Bootstrap the HIA candidate-build executable from captured native inputs.

Only this explicit bootstrap/cold-custody command is Python. The resulting
standalone executable performs catalog dispatch, source compilation, hashing
and manifest serialization in resident HIA images, with fixed syscall ports.
This command never invokes the original generic-candidate Python build body.
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
from tools.build_hia_source_build import _check_call_receipt, _check_compile_receipt
from tools.generate_hia_candidate_build import PACK_MAGIC, LAYOUT, WIRE_LIMIT
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE_NAMES = (
    'tools/build_hia_candidate_build.py',
    'tools/generate_hia_candidate_build.py',
    'tools/hia_candidate_build_catalog.json',
    'tools/hia_candidate_build_syscalls.S',
    'examples/hia_bootstrap/candidate_build_policy.hepta',
    'examples/hia_bootstrap/candidate_build_packer.hepta',
    'examples/hia_bootstrap/source_build_policy.hepta',
    'examples/hia_bootstrap/sha256.hepta',
    'examples/hia_bootstrap/selfhost.hepta',
    'tools/build_hia_json_preflight.py',
    'tools/build_hia_source_build.py',
    'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_child.py',
)


def build(output: Path, compiler: Path, *, cold_report: Path | None = None,
          development: bool = False):
    if type(development) is not bool or (cold_report is None) == (not development):
        raise ValueError('select exactly one matching cold report or explicit development scope')
    compiler_bytes = compiler.read_bytes()
    if not 0 < len(compiler_bytes) <= 1 << 20:
        raise ValueError('compiler exceeds the original one-MiB image limit')
    cold_bytes = None if cold_report is None else cold_report.read_bytes()
    sources = {name: (ROOT/name).read_bytes() for name in SOURCE_NAMES}
    admitted = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    if admitted is not None and any(admitted.get(name) != sha256(raw).hexdigest()
                                    for name, raw in sources.items()):
        raise ValueError('candidate builder is absent from the matching complete cold source contract')
    output.mkdir(mode=0o700)
    captured = output/'captured-compiler.image.bin'
    captured.write_bytes(compiler_bytes)
    captured.chmod(0o400)
    images, receipts = {}, {}
    for label, source in (
        ('candidate-build-policy', 'examples/hia_bootstrap/candidate_build_policy.hepta'),
        ('source-build-policy', 'examples/hia_bootstrap/source_build_policy.hepta'),
        ('sha256', 'examples/hia_bootstrap/sha256.hepta'),
        ('candidate-build-packer', 'examples/hia_bootstrap/candidate_build_packer.hepta'),
    ):
        path, receipt = compile_stage(output, label, captured, sources[source])
        raw = path.read_bytes()
        _check_compile_receipt(receipt, compiler=compiler_bytes, source=sources[source], produced=raw)
        images[label] = (path, raw)
        receipts[label] = receipt
    policy = images['candidate-build-policy'][1]
    source_policy = images['source-build-policy'][1]
    hasher = images['sha256'][1]
    frame = struct.pack('<5Q', PACK_MAGIC, len(policy), len(source_policy),
                        len(compiler_bytes), len(hasher))
    frame += policy + source_policy + compiler_bytes + hasher
    receipt, output_bytes = invoke(output, 'pack-candidate-build',
        images['candidate-build-packer'][0], frame)
    size = receipt.get('core_u32')
    if type(size) is not int or not 0 < size <= len(output_bytes):
        raise ValueError('native candidate-build packer rejected its captured resident images')
    _check_call_receipt(receipt, artifact=images['candidate-build-packer'][1], source=frame, size=size)
    if receipt.get('output_sha256') != sha256(output_bytes).hexdigest():
        raise ValueError('packer receipt does not bind the complete output buffer')
    executable = output_bytes[:size]
    inspection = inspect_executable(executable)
    if (compiler.read_bytes() != compiler_bytes or captured.read_bytes() != compiler_bytes
            or any((ROOT/name).read_bytes() != raw for name, raw in sources.items())
            or any(path.read_bytes() != raw for path, raw in images.values())
            or (cold_report is not None and cold_report.read_bytes() != cold_bytes)
            or (admitted is not None and current_sources() != admitted)):
        raise ValueError('candidate-build input custody changed before bootstrap publication')
    path = output/'hia-candidate-build'
    with path.open('xb') as stream:
        stream.write(executable)
    path.chmod(0o500)
    report = {
        'schema': 'hepta.hia.candidate-build-bootstrap.v1',
        'status': 'DEVELOPMENT_NATIVE_BUILDER_CREATED' if development else 'COLD_BOUND_NATIVE_BUILDER_CREATED',
        'development': development, 'cold_authority': admitted is not None,
        'source_identity': {name: sha256(raw).hexdigest() for name, raw in sources.items()},
        'cold_source_manifest': admitted,
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'resident_images': {name: sha256(raw).hexdigest() for name, (_, raw) in images.items()},
        'compile_receipts': receipts, 'pack_receipt': receipt,
        'executable_path': path.name, 'executable_sha256': sha256(executable).hexdigest(),
        'executable_bytes': len(executable), 'inspection': inspection, 'memory_layout': LAYOUT,
        'runtime_python_required': False, 'runtime_child_process_required': False,
        'catalog_manifest_and_compile_dispatch_owned_by_HIA': True,
        'cold_admission_provider_is_python': True,
        'bootstrap_and_publication_provider_is_python': True,
        'production_activated': False, 'whole_native_qualified': False,
    }
    (output/'BUILD.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--cold-report', type=Path)
    scope.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(),
                cold_report=None if args.cold_report is None else args.cold_report.resolve(),
                development=args.development))


if __name__ == '__main__':
    main()
