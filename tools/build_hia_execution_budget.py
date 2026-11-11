"""Build the execution-budget owner only from matching source-complete cold HIA."""
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


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    name = 'examples/hia_bootstrap/execution_budget.hepta'
    source_path = ROOT / name
    source = source_path.read_bytes()
    if sources.get(name) != sha256(source).hexdigest():
        raise ValueError('HIA execution-budget source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'execution-budget', compiler, source)
    image_bytes = image.read_bytes()
    if (source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('HIA execution-budget build inputs changed')
    manifest = {'schema': 'hepta.hia.execution-budget-native.v1',
        'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({'schema': 'hepta.hia.execution-budget-build.v1',
        'status': 'NATIVE_CANDIDATE_BUILT', 'profile': PROFILE, 'source_manifest': sources,
        'manifest': manifest, 'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'native_compile_receipt': receipt, 'execution_budget_policy_and_claim_state_native': True,
        'original_sqlite_journal_preserved': True, 'sql_and_process_effect_adapters_hosted': True,
        'requests_and_context_authority_replaced': False, 'historical_completion_receipts_added': False,
        'source_selected_service_activated': False, 'all_input_equivalence_proved': False,
        'whole_stack_rewritten_in_hia': False}, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
