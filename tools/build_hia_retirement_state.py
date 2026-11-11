"""Build an explicitly selected retirement state owner from matching cold HIA."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_selfhost_contract import PROFILE

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    cold = cold_report.read_bytes()
    compiler_bytes = compiler.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold)
    source_name = 'examples/hia_bootstrap/retirement_state.hiaasm'
    source_path = ROOT / source_name
    source = source_path.read_bytes()
    if sources.get(source_name) != sha256(source).hexdigest():
        raise ValueError('HIA retirement state source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'retirement-state', compiler, source)
    image_bytes = image.read_bytes()
    if (source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('HIA retirement build inputs changed')
    manifest = {'schema': 'hepta.hia.retirement-state-native.v1',
        'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.retirement-state-build.v1',
        'status': 'NATIVE_CANDIDATE_BUILT', 'profile': PROFILE,
        'source_manifest': sources, 'manifest': manifest,
        'cold_report_sha256': sha256(cold).hexdigest(), 'native_compile_receipt': receipt,
        'production_activated': False, 'retained_retirement_state_is_native': True,
        'foreign_loader_handles_and_effect_adapter_are_hosted': True,
        'durable_agent_journal_replaced': False, 'release_garbage_collection_implemented': False,
        'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
    }, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
