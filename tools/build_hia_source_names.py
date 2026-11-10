"""Build HIA name/parameter grammar with the actual bundled native lexer."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.build_hia_source_lexer import build as build_lexer, _checked_compile_receipt
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_source_names_native import SCHEMA, SOURCE
    source, compiler_bytes, cold = SOURCE.read_bytes(), compiler.read_bytes(), cold_report.read_bytes()
    output.mkdir(mode=0o700)
    build_lexer(output / 'source-lexer', compiler, cold_report)
    image, receipt = compile_stage(output, 'source-names', compiler, source)
    if SOURCE.read_bytes() != source or compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold:
        raise ValueError('HIA name build inputs changed')
    identity = _checked_compile_receipt(receipt, compiler_bytes, source, image.read_bytes())
    manifest = {'schema': SCHEMA, **identity, 'image_path': image.name}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({'schema': 'hepta.hia.source-names-build.v1',
        'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': manifest,
        'cold_report_sha256': sha256(cold).hexdigest(), 'native_compile_receipt': receipt,
        'production_activated': False, 'whole_stack_rewritten_in_hia': False}, indent=2, sort_keys=True) + '\n')
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
