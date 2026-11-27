"""Build all four complete service lease methods with exact source custody."""
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

SOURCE_NAME = 'examples/hia_bootstrap/service_lease.hepta'
INPUTS = ('tools/hia_component_input_custody.py',
    "examples/hia_bootstrap/service_lease.hepta",
    "tools/generate_hia_service_lease.py",
    "tools/build_hia_service_lease.py",
    "hepta/hia_service_lease_native.py",
    "hepta/hia_service_lease_protocol.py",
    "hepta/hia_agent_service.py",
    "hepta/hia_agent_store.py",
    "hepta/hia_agent_runner.py",
    "hepta/hia_agent_buffers.py",
    "hepta/hia_agent_contract.py",
    "hepta/hia_slot_ledger_native.py",
    "hepta/hia_slot_operations_native.py",
    "hepta/hia_slot_operations_protocol.py",
    "hepta/hia_slot_operation_series.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_native_helpers.py",
    "hepta/hia_emission_native.py",
    "hepta/hia_json_preflight_native.py",
    "hepta/hia_store_lifecycle_native.py",
    "hepta/hia_store_artifact_profile_native.py",
    "hepta/hia_store_transaction_native.py",
    "hepta/hia_agent_assembly.py",
    "hepta/hia_program.py",
    "hepta/hia_program_runtime.py",
    "hepta/hia_program_runtime_prepared.py",
    "tools/generate_hia_service_context.py",
    "tools/generate_hia_selfhost.py",
    "tools/build_hia_store_artifact_profile.py",
    "tools/build_hia_store_transaction.py",
    "tools/build_hia_slot_ledger.py",
    "tools/build_hia_slot_operations.py",
    "tests/test_hia_service_lease_native.py",
    "tests/hia_service_lease_original_oracle.py",
    "tests/hia_service_lease_observer.py",
    "tests/hia_service_lease_controls.py",
    "tests/hia_service_lease_resources.py",
    "tests/hia_service_lease_installed.py",
    "tests/hia_service_lease_suite_observer.py",
    "tools/read_hia_service_lease.py",
    "tools/qualify_hia_service_lease.py",
    "tools/qualify_hia_service_lease_callers.py",
    "tests/hia_slot_operations_qualification_support.py",
    "tests/fixtures/hia_service_lease_original_r3/acquire_slot.py.txt",
    "tests/fixtures/hia_service_lease_original_r3/_lease.py.txt",
    "tests/fixtures/hia_service_lease_original_r3/invoke_lease.py.txt",
    "tests/fixtures/hia_service_lease_original_r3/release_slot.py.txt",
    "tests/fixtures/hia_service_lease_original_r3/source-identity.json",
    "tests/fixtures/hia_service_lease_original_r3/cases.json",
    "tests/fixtures/hia_service_lease_original_r3/inputs-freeze.json",
    "tests/fixtures/hia_service_lease_original_r3/callers.json",
    "tests/fixtures/hia_emission_original_73f1634/original-freeze.json",
    "tools/qualify_hia_emission_callers.py",
    "tools/run_hia_unittest_gate.py",
    "tests/test_hia_agent_native_lease_snapshot.py",
    "tests/test_hia_agent_native_machine_validation.py",
    "tests/test_hia_agent_native_tools.py",
    "tests/test_hia_agent_buffer_lifecycle.py",
    "tests/test_hia_slot_ledger_native_integration.py",
    "tests/test_hia_native_byte_abi.py",
    "tests/test_hia_agent_installed_resources.py",
    ".github/workflows/hia-core.yml",
    "tests/fixtures/hia_service_lease_original_r3/gate-plan.json",
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
    image, receipt = compile_stage(output, 'service_lease', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_lease.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service lease construction inputs or output changed')
    if not development:
        verify_component_custody(custody, compiler_bytes, cold_bytes, sources, captured, root=ROOT)
    manifest = {'schema': 'hepta.hia.service-lease.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-lease-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owners': ['HIAAgentService.acquire_slot', 'HIAAgentService._lease',
                            'HIAAgentService.invoke_lease', 'HIAAgentService.release_slot'],
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_originals_still_present': True,
        'acquire_release_context_policy_owned_by_HIA': True,
        'original_dynamic_ledger_and_worker_calls_preserved': True,
        'separate_slot_policy_or_SQL_owner_replaced': False,
        'opaque_object_and_provider_protocols_hosted': True,
        'whole_method_pending_resources': 'weak registered observations until separate FINALIZE ACK',
        'per_port_ACK_retires_whole_method_observation': False,
        'new_transaction_or_retry_or_deadline': False,
        'same_frame_reentry_refused_before_cleanup_region': True,
        'normal_local_storage_detached_without_clearing_held_tracebacks': True,
        'finite_original_input_count': 258,
        'original_observation_or_resource_qualification_established_by_build': False,
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
