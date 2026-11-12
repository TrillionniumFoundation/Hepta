"""Build complete Core lowering only after matching-source cold admission."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from hepta.hia_core_lowering_native import SCHEMA
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.qualify_hia_selfhost import compile_stage

    compiler_raw, cold_raw = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_raw, cold_raw)
    relative = 'examples/hia_bootstrap/core_lowering.hiaasm'
    source = (ROOT / relative).read_bytes()
    if sources.get(relative) != sha256(source).hexdigest():
        raise ValueError('Core lowering source differs from the admitted cold report')
    # No output mutation, including a parent directory, precedes admission.
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'core_lowering', compiler, source)
    image_raw = image.read_bytes()
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or current_sources() != sources or (ROOT / relative).read_bytes() != source):
        raise ValueError('Core lowering compile inputs changed')
    manifest = {
        'schema': SCHEMA, 'source_sha256': sha256(source).hexdigest(),
        'image_path': image.name, 'image_sha256': sha256(image_raw).hexdigest(),
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
    }
    path = output / 'manifest.json'
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
    if path.read_bytes() != raw or image.read_bytes() != image_raw:
        raise ValueError('Core lowering published candidate changed')
    report = {
        'schema': 'hepta.hia.core-lowering-build.v2',
        'status': 'MATCHING_SOURCE_COLD_CANDIDATE_BUILT',
        'source_manifest': sources, 'cold_report_sha256': sha256(cold_raw).hexdigest(),
        'manifest': manifest, 'native_compile_receipt': receipt,
        'complete_Function_methods': 22, 'complete_shared_helpers': 5,
        'original_reference_retained': True, 'whole_backend_native': False,
        'Emitter_control_still_hosted': True, 'default_activated': False,
    }
    with (output / 'build.json').open('xb') as stream:
        stream.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--cold-report', required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
