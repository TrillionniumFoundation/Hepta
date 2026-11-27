"""Build the ordinary artifact-read policy and HIA wire from admitted sources."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.build_hia_json_wire import build as build_wire, build_development as build_wire_development
from tools.qualify_hia_selfhost import compile_stage

SOURCE_PATH = 'examples/hia_bootstrap/artifact_page.hiaasm'
WIRE_SOURCE_PATH = 'examples/hia_bootstrap/json_wire.hiaasm'
POLICY_SCHEMA = 'hepta.hia.artifact-page-native.v2'
BUNDLE_SCHEMA = 'hepta.hia.artifact-page-bundle.v2'


def _build(output, compiler, cold_report=None):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes() if cold_report is not None else None
    sources = admit_cold_build(compiler_raw, cold_raw) if cold_raw is not None else None
    raw_sources = {name: (ROOT / name).read_bytes() for name in (SOURCE_PATH, WIRE_SOURCE_PATH)}
    if sources is not None and any(sources.get(name) != sha256(raw).hexdigest() for name, raw in raw_sources.items()):
        raise ValueError('artifact-page bundle source is outside the current cold closure')
    output.mkdir(mode=0o700)
    policy_dir = output / 'policy'; policy_dir.mkdir(mode=0o700)
    image, receipt = compile_stage(policy_dir, 'artifact-page', compiler, raw_sources[SOURCE_PATH])
    policy = {'schema': POLICY_SCHEMA, 'source_sha256': sha256(raw_sources[SOURCE_PATH]).hexdigest(),
              'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
              'compiler_sha256': sha256(compiler_raw).hexdigest()}
    policy_manifest = policy_dir / 'manifest.json'
    policy_manifest.write_text(json.dumps(policy, indent=2, sort_keys=True) + '\n')
    wire_manifest = (build_wire_development(output / 'wire', compiler) if cold_report is None
                     else build_wire(output / 'wire', compiler, cold_report))
    if (compiler.read_bytes() != compiler_raw
            or any((ROOT / name).read_bytes() != raw for name, raw in raw_sources.items())
            or (cold_report is not None and (cold_report.read_bytes() != cold_raw or current_sources() != sources))):
        raise ValueError('artifact-page bundle build inputs changed')
    bundle = {'schema': BUNDLE_SCHEMA,
              'policy_manifest': policy_manifest.relative_to(output).as_posix(),
              'policy_manifest_sha256': sha256(policy_manifest.read_bytes()).hexdigest(),
              'wire_manifest': wire_manifest.relative_to(output).as_posix(),
              'wire_manifest_sha256': sha256(wire_manifest.read_bytes()).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.artifact-page-build.v1',
        'scope': 'MATCHING_SOURCE_COLD_BUILD' if cold_report is not None else 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD',
        'bundle': bundle, 'policy_manifest': policy, 'policy_compile_receipt': receipt,
        'wire_build': json.loads((output / 'wire/build.json').read_bytes()),
        'source_manifest': sources, 'cold_report_sha256': sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'native_owners': ['cursor binding and SQL operation order', 'complete-artifact UTF-8 classification',
            'page trimming and base64', 'three ordered wire calls and 230000 double-wire limit',
            'cursor canonical digest and insertion instruction', 'result graph'],
        'hosted_owners': ['AgentStore get and its independent selection', 'actual SQL and durability',
            'foreign object access, arithmetic errors and interpreter ABI', 'installation and code custody'],
        'production_activated': False, 'whole_store_or_durability_native': False,
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
