"""Build the complete ordinary artifact-page decision from matching cold HIA."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_selfhost_contract import PROFILE

SOURCES = ('examples/hia_bootstrap/agent_read.hepta',
           'tools/generate_hia_agent_read.py', 'tools/build_hia_agent_read.py')

def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    source_bytes = {name: (ROOT / name).read_bytes() for name in SOURCES}
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in source_bytes.items()):
        raise ValueError('artifact-read owner source differs from the admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'agent-read', compiler, source_bytes[SOURCES[0]])
    image_bytes = image.read_bytes()
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in source_bytes.items())
            or current_sources() != admitted or image.read_bytes() != image_bytes):
        raise ValueError('artifact-read build inputs or produced image changed')
    manifest = {'schema': 'hepta.hia.agent-read-native.v1',
        'source_sha256': sha256(source_bytes[SOURCES[0]]).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image_bytes).hexdigest(), 'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    with path.open('x') as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write('\n')
    report = {'schema': 'hepta.hia.agent-read-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'profile': PROFILE, 'source_manifest': admitted, 'manifest': manifest,
        'cold_report_sha256': sha256(cold_bytes).hexdigest(), 'native_compile_receipt': receipt,
        'ordinary_hia_read_page_and_cursor_decisions_native': True,
        'complete_artifact_utf8_classification_native': True,
        'both_original_json_wire_page_budgets_native': True,
        'original_cursor_sha256_and_sql_row_values_native': True,
        'original_artifact_get_and_metadata_authority_hosted': True,
        'original_sqlite_connection_and_insert_or_ignore_preserved': True,
        'installed_pinned_worker_bundle_required_for_default_native_read': True,
        'unselected_source_and_wheel_remain_hosted': True,
        'source_selected_service_activated': False, 'all_input_equivalence_proved': False,
        'whole_stack_rewritten_in_hia': False}
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))

if __name__ == '__main__':
    main()
