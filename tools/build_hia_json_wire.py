"""Build source-bound HIA foreign-graph wire code without selecting production.

The ordinary build consumes a matching-source completed cold report. The
separately named development function only reuses a compiler as development
input and makes no cold-qualification claim for the changed source.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE_PATH = 'examples/hia_bootstrap/json_wire.hiaasm'
SCHEMA = 'hepta.hia.json-wire-native.v1'


def _build(output, compiler, source, compiler_raw, *, scope, cold_report=None, cold_raw=None, sources=None):
    output = Path(output)
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'json-wire', compiler, source)
    if (ROOT / SOURCE_PATH).read_bytes() != source or compiler.read_bytes() != compiler_raw:
        raise ValueError('native JSON wire build inputs changed')
    if cold_report is not None and (cold_report.read_bytes() != cold_raw or current_sources() != sources):
        raise ValueError('native JSON wire cold identity changed')
    manifest = {'schema': SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler_raw).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.json-wire-build.v1', 'scope': scope,
        'manifest': manifest, 'source_manifest': sources,
        'cold_report_sha256': sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        'native_compile_receipt': receipt, 'production_activated': False,
        'foreign_object_transport_is_python': True, 'whole_stack_native': False,
    }, sort_keys=True, indent=2) + '\n')
    return output / 'manifest.json'


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    compiler_raw, cold_raw = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_raw, cold_raw)
    source = (ROOT / SOURCE_PATH).read_bytes()
    if sources.get(SOURCE_PATH) != sha256(source).hexdigest():
        raise ValueError('native JSON wire source is outside current cold closure')
    return _build(output, compiler, source, compiler_raw, scope='MATCHING_SOURCE_COLD_BUILD',
                  cold_report=cold_report, cold_raw=cold_raw, sources=sources)


def build_development(output: Path, compiler: Path) -> Path:
    """Explicit compiler reuse; never upgrades old cold evidence to new source."""
    compiler_raw = compiler.read_bytes()
    source = (ROOT / SOURCE_PATH).read_bytes()
    return _build(output, compiler, source, compiler_raw,
                  scope='DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    if args.development:
        result = build_development(args.output, args.compiler)
    else:
        result = build(args.output, args.compiler, args.cold_report)
    print(result)


if __name__ == '__main__':
    main()
