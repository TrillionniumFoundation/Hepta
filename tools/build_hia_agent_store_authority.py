"""Build explicit HIA AgentStore authority from matching cold or marked development B3."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE = 'examples/hia_bootstrap/agent_store_authority.hiaasm'


def _build(output, compiler, cold_report=None):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes() if cold_report is not None else None
    sources = admit_cold_build(compiler_raw, cold_raw) if cold_raw is not None else None
    raw = (ROOT / SOURCE).read_bytes()
    if sources is not None and sources.get(SOURCE) != sha256(raw).hexdigest():
        raise ValueError('AgentStore authority source is outside the current cold closure')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'agent-store-authority', compiler, raw)
    if (compiler.read_bytes() != compiler_raw or (ROOT / SOURCE).read_bytes() != raw
            or (cold_report is not None and (cold_report.read_bytes() != cold_raw or current_sources() != sources))):
        raise ValueError('AgentStore authority build inputs changed')
    manifest = {'schema': 'hepta.hia.agent-store-authority-native.v1',
                'source_sha256': sha256(raw).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler_raw).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.agent-store-authority-build.v1',
        'scope': 'MATCHING_SOURCE_COLD_BUILD' if cold_raw is not None else 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD',
        'manifest': manifest, 'native_compile_receipt': receipt,
        'source_manifest': sources, 'cold_report_sha256': sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        'compiler_sha256': sha256(compiler_raw).hexdigest(), 'production_activated': False,
        'native_owners': ['reference projection and issuance', 'retained reference and kind authority',
                          'URI lookup routing', 'profile issuance and retained binding', 'metadata read routing'],
        'retained_boundaries': ['field-shape admission', 'SQL and transactions', 'unselected file publication',
                                'independently selected JSON/hash/publication owners', 'foreign object operations'],
        'whole_store_or_durability_native': False, 'all_python_extension_inputs_equivalent': False,
    }, indent=2, sort_keys=True) + '\n')
    return path


def build(output, compiler, cold_report):
    return _build(Path(output), Path(compiler), Path(cold_report))


def build_development(output, compiler):
    return _build(Path(output), Path(compiler))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))
