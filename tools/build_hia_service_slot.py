"""Build complete service rollback/adoption control with exact source custody."""
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
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/service_slot.hepta'
ORIGINAL_DIRECTORY = 'tests/fixtures/hia_service_slot_original_bc011/'
INPUTS = (
    SOURCE_NAME, 'tools/generate_hia_service_slot.py', 'tools/build_hia_service_slot.py',
    'hepta/hia_service_slot_native.py', 'hepta/hia_service_slot_protocol.py',
    'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
    'hepta/hia_slot_ledger_native.py', 'hepta/hia_agent_journal_native.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_native_helpers.py',
    'hepta/hia_emission_native.py', 'hepta/hia_json_preflight_native.py',
    'hepta/hia_store_lifecycle_native.py', 'hepta/hia_store_artifact_profile_native.py',
    'hepta/hia_store_transaction_native.py', 'hepta/hia_native_build_admission_native.py',
    'tools/generate_hia_service_context.py', 'tools/generate_hia_selfhost.py',
    "tests/test_hia_service_slot_native.py",
    "tests/hia_service_slot_original_oracle.py",
    "tests/hia_service_slot_observer.py",
    "tests/hia_service_slot_controls.py",
    "tests/hia_service_slot_resources.py",
    "tests/hia_service_slot_transport.py",
    "tests/hia_service_slot_public_workflow.py",
    "tests/hia_service_slot_installed.py",
    "tests/hia_service_slot_suite_observer.py",
    "tests/fixtures/hia_service_slot_observation_inputs_v1/inputs.json",
    "tools/qualify_hia_service_slot_originals.py",
    "tools/qualify_hia_service_slot_callers.py",
    "tools/qualify_hia_service_slot.py",
    *(ORIGINAL_DIRECTORY + name for name in (
        'rollback.bc011.py.txt', 'adopt.bc011.py.txt', 'source-identity.json',
        'inherited-17-module-caller-freeze.json', 'current-caller-files.json',
        'route-and-transaction-sources.json', 'input-observation-plan.json',
        'literal-caller-search.txt', 'FREEZE.json')),
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
        raise ValueError('service slot inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_slot', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_slot.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service slot construction inputs or output changed')
    manifest = {'schema': 'hepta.hia.service-slot.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-slot-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owners': ['HIAAgentService._hia_rollback', 'HIAAgentService._hia_adopt'],
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_originals_still_present': True,
        'outer_transaction_owned_by_original_service_or_journal': True,
        'new_handler_transaction_or_retry_or_deadline': False,
        'opaque_object_and_provider_protocols_hosted': True,
        'separate_slot_store_sql_owner_replaced': False,
        'whole_method_pending_resources': 'weak registered observations until separate FINALIZE ACK',
        'per_port_ACK_retires_whole_method_observation': False,
        'same_frame_reentry_refused_before_cleanup_region': True,
        'normal_local_storage_transferred_without_clearing_held_tracebacks': True,
        'multi_sql_or_ancestor_resource_qualification_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'current_caller_controls_not_replaced_by_build': True,
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
