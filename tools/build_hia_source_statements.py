"""Build an operator-selected HIA source statement parser plus its actual HIA lexer.

Requires a completed matching cold compiler. This does not activate a default
backend or claim that declarations/semantics or the complete stack are HIA.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.build_hia_source_lexer import build as build_lexer
    from tools.qualify_hia_selfhost import compile_stage
    source_path = ROOT / 'examples/hia_bootstrap/source_statements.hiaasm'
    source = source_path.read_bytes()
    compiler_bytes = compiler.read_bytes()
    cold_bytes = cold_report.read_bytes()
    output.mkdir(mode=0o700)
    # This builder validates all eleven original cold-replay checks and all
    # three exact matching compiler generation hashes before compilation.
    lexer_manifest = build_lexer(output / 'source-lexer', compiler, cold_report)
    image, receipt = compile_stage(output, 'source-statements', compiler, source)
    if (source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes):
        raise ValueError('HIA source statement build inputs changed')
    manifest = {'schema': 'hepta.hia.source-statements-native.v1',
        'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image.read_bytes()).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.source-statements-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'manifest': manifest, 'lexer_manifest': str(lexer_manifest.relative_to(output)),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(), 'native_compile_receipt': receipt,
        'production_activated': False, 'all_input_equivalence_proved': False,
        'declarations_and_semantic_passes_rewritten': False, 'whole_stack_rewritten_in_hia': False},
        indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__': main()
