"""Build complete service inspection control with exact source custody."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_component_input_custody import capture_component_custody, verify_component_custody
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/service_inspection.hepta'
ORIGINAL_DIRECTORY = 'tests/fixtures/hia_service_inspection_original_bc011/'
INPUTS = ('tools/hia_component_input_custody.py',
    'tests/hia_service_inspection_public_lifetime_oracle.py',
    'tests/hia_service_inspection_public_lifetime_observer.py',
    'tools/qualify_hia_service_inspection_public_lifetime.py',
    'tests/test_hia_service_inspection_public_lifetime.py',
    'tests/fixtures/hia_service_inspection_public_lifetime_v1/cases.json',
    'tests/fixtures/hia_service_inspection_public_lifetime_v1/source-identity.json',
    SOURCE_NAME, 'tools/generate_hia_service_inspection.py',
    'tools/build_hia_service_inspection.py',
    'tools/qualify_hia_service_inspection_callers.py',
    'tools/qualify_hia_service_inspection_finite.py',
    'tools/observe_hia_service_inspection_originals.py',
    'hepta/hia_service_inspection_native.py', 'hepta/hia_service_inspection_protocol.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
    'hepta/hia_store_lifecycle_selection.py', 'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_store_artifact_profile_native.py', 'hepta/artifact_publication_native.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_agent_contract.py', 'hepta/hia_emission_native.py',
    'hepta/hia_json_preflight_native.py', 'tools/generate_hia_service_context.py',
    'tools/generate_hia_selfhost.py',
    'tests/test_hia_service_inspection_native.py',
    'tests/hia_service_inspection_oracle.py',
    'tests/hia_service_inspection_controls.py',
    'tests/hia_service_inspection_installed.py',
    'tests/hia_service_inspection_vm.py',
    'tests/fixtures/hia_emission_original_73f1634/original-freeze.json',
    *(ORIGINAL_DIRECTORY + name for name in (
        'inspect.bc011.py.txt', 'candidate.bc011.py.txt', 'source-identity.json', 'cases.json')),
)


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    custody = None if development else capture_component_custody(
        compiler_bytes, cold_bytes, sources, captured, root=ROOT)
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_inspection', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_inspection.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service inspection construction inputs or output changed')
    if not development:
        verify_component_custody(custody, compiler_bytes, cold_bytes, sources, captured, root=ROOT)
    manifest = {'schema': 'hepta.hia.service-inspection.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-inspection-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owner': 'complete HIAAgentService._hia_inspect and _hia_candidate control',
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_original_still_present': True,
        'opaque_object_and_provider_protocols_hosted': True,
        'original_Core_patch_graph_compiler_and_Store_providers_hosted': True,
        'resource_custody_policy': 'independent per-port and whole-method weak registered-resource facts; terminal FINALIZE ACK',
        'resource_qualification_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'new_replay_retry_or_production_deadline': False,
        'all_python_versions_tested': False,
        'whole_native_stack_qualified': False,
    }
    if custody is not None:
        report['component_input_custody'] = custody
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
