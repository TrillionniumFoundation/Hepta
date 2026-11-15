"""Build complete service discovery control with exact source custody."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_service_describe_protocol import SCHEMA, SOURCE_NAME
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

ORIGINAL_DIRECTORY = 'tests/fixtures/hia_service_describe_original_3424/'
INPUTS = (
    SOURCE_NAME, 'tools/generate_hia_service_describe.py',
    'tools/build_hia_service_describe.py',
    'tools/qualify_hia_service_describe_callers.py',
    'tools/qualify_hia_emission_callers.py',
    'hepta/hia_service_describe_native.py', 'hepta/hia_service_describe_protocol.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_emission_native.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_opcodes.py', 'tools/generate_hia_service_context.py',
    'tools/generate_hia_selfhost.py', 'tests/test_hia_service_describe_native.py',
    'tests/hia_service_describe_oracle.py',
    'tests/hia_service_describe_faults.py',
    'tests/fixtures/hia_emission_original_73f1634/original-freeze.json',
    *(ORIGINAL_DIRECTORY + name for name in (
        'describe.3424.py.txt', 'source-identity.json', 'cases.json', 'freeze.json')),
)


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    if sources is not None and any(sources.get(name) != sha256(raw).hexdigest()
                                   for name, raw in captured.items()):
        raise ValueError('service describe inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_describe', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_describe.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service describe construction inputs or output changed')
    manifest = {
        'schema': SCHEMA,
        'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
    }
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-describe-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owner': 'complete HIAAgentService._hia_describe control',
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_original_still_present': True,
        'opaque_object_catalog_and_store_protocols_hosted': True,
        'module_loading_and_sqlite_native': False,
        'resource_custody_policy': 'actual child handoff or completed resource scope; matching parent foreign ACK',
        'resource_qualification_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'new_replay_retry_or_production_deadline': False,
        'all_python_versions_tested': False,
        'whole_native_stack_qualified': False,
    }
    (output / 'build.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return output / 'manifest.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == '__main__':
    main()
