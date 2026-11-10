"""Build a single selected bundle of HIA source grammar components.

Requires an actually completed matching source-only cold compiler. The build
does not change defaults, services, release locks or whole-stack closure state.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from hepta.hia_source_frontend_native import MANIFESTS, SCHEMA, read_manifest
    from tools.build_hia_source_names import build as names
    from tools.build_hia_source_clauses import build as clauses
    from tools.build_hia_source_expressions import build as expressions
    compiler_bytes, cold = compiler.read_bytes(), cold_report.read_bytes()
    output.mkdir(mode=0o700)
    names(output / 'names', compiler, cold_report)
    clauses(output / 'clauses', compiler, cold_report)
    expressions(output / 'expressions', compiler, cold_report)
    if compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold:
        raise ValueError('HIA frontend compiler or cold evidence changed')
    manifest = {'schema': SCHEMA, 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
                'manifests': {path: sha256((output / path).read_bytes()).hexdigest() for path in MANIFESTS}}
    staging = output / 'manifest.pending.json'
    staging.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    read_manifest(staging)
    target = output / 'manifest.json'
    staging.rename(target)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.source-frontend-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'manifest_sha256': sha256(target.read_bytes()).hexdigest(),
        'compiler_sha256': manifest['compiler_sha256'], 'cold_report_sha256': sha256(cold).hexdigest(),
        'native_grammar': ['lexical recognition and numeric conversion', 'complete type grammar',
                           'qualified names and declaration parameter lists', 'effects and resources clauses',
                           'complete expression grammar'],
        'still_foreign': ['declarations and statements', 'AST object materialization and validation',
                          'semantic checking', 'modules and packages', 'production runtime and tooling'],
        'production_activated': False, 'whole_stack_rewritten_in_hia': False},
        indent=2, sort_keys=True) + '\n')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
