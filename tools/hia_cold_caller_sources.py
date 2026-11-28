"""Exact source inverses for native cold caller wiring.

These bytes are historical test inputs only. The current callers still run.
The fixed authority never grants native qualification to host authoring code.
"""
from hashlib import sha256
import json
from pathlib import Path

FIXTURE = 'tests/fixtures/hia_native_cold_caller_integration_20261128.json'
SOURCE = 'tools/hia_cold_caller_sources.py'
FIXTURE_SHA256 = '783446c20de1023ad8c34c68bd08c841e68bd24745e3993a316ec3710dfaa3ae'
SCHEMA = 'hepta.hia.native-cold-caller-source-relations.v3'
PREVIOUS_FIXTURE = 'tests/fixtures/hia_native_cold_caller_integration_20261127.json'
PREVIOUS_PIN = {'bytes': 236242, 'sha256': 'ce9a293352ac12adb153ae91036915826f4a121a5b3668d8ffbd2f64e375e476'}
INTEGRATED_PATHS = ('tools/qualify_hia_evaluation_callers.py', 'tools/qualify_hia_service_bootstrap_callers.py', 'tools/qualify_hia_store_transaction.py', 'tests/test_hia_artifact_delivery.py')
PATHS = ('hepta/hia_agent_service.py', 'tests/hia_composite_function_fixture.py', 'tests/hia_service_bootstrap_controls.py', 'tests/hia_service_lease_controls.py', 'tests/hia_slot_operations_component_fixture.py', 'tests/test_hia_agent_installed_resources.py', 'tests/test_hia_agent_journal_extensions.py', 'tests/test_hia_agent_journal_native.py', 'tests/test_hia_agent_stdio.py', 'tests/test_hia_artifact_delivery.py', 'tests/test_hia_artifact_publication_native.py', 'tests/test_hia_artifact_publication_route.py', 'tests/test_hia_byte_wrapper_native.py', 'tests/test_hia_candidate_budget_native.py', 'tests/test_hia_capability_renaming_native.py', 'tests/test_hia_cli_native.py', 'tests/test_hia_composite_native_composition.py', 'tests/test_hia_composite_types_native.py', 'tests/test_hia_continuation_native.py', 'tests/test_hia_core_admission_cli.py', 'tests/test_hia_core_admission_native.py', 'tests/test_hia_core_emitter_native.py', 'tests/test_hia_core_json_bytes_native.py', 'tests/test_hia_core_lowering_native.py', 'tests/test_hia_core_module_graph_native.py', 'tests/test_hia_core_patch_cli.py', 'tests/test_hia_core_patch_native.py', 'tests/test_hia_core_patch_result_cli.py', 'tests/test_hia_core_workspace_json_native.py', 'tests/test_hia_core_workspace_pipeline.py', 'tests/test_hia_cost_ledger_native.py', 'tests/test_hia_default_native_release.py', 'tests/test_hia_emission_native.py', 'tests/test_hia_evaluation_capture.py', 'tests/test_hia_evaluation_native.py', 'tests/test_hia_execution_budget_native.py', 'tests/test_hia_execution_observation_native.py', 'tests/test_hia_full_cost_native.py', 'tests/test_hia_function_shape_native.py', 'tests/test_hia_generation_retention_native.py', 'tests/test_hia_instruction_policy_native.py', 'tests/test_hia_json_wire_native.py', 'tests/test_hia_machine_encoding_native.py', 'tests/test_hia_machine_instructions_native.py', 'tests/test_hia_machine_object_native.py', 'tests/test_hia_machine_plan_native.py', 'tests/test_hia_machine_state_native.py', 'tests/test_hia_native_admission_io.py', 'tests/test_hia_native_build_admission_native.py', 'tests/test_hia_native_build_dispatch.py', 'tests/test_hia_native_delivery.py', 'tests/test_hia_native_mapping_native.py', 'tests/test_hia_native_transport_failures.py', 'tests/test_hia_nominal_json_native.py', 'tests/test_hia_nominal_tokens_native.py', 'tests/test_hia_patch_impact_native.py', 'tests/test_hia_program_selfhost.py', 'tests/test_hia_program_shape_native.py', 'tests/test_hia_publication_measurement_native.py', 'tests/test_hia_release_install.py', 'tests/test_hia_release_selection.py', 'tests/test_hia_retirement_state_native.py', 'tests/test_hia_scalar_profile_native.py', 'tests/test_hia_selfhost_linked_observer.py', 'tests/test_hia_service_artifact_native.py', 'tests/test_hia_service_context_native.py', 'tests/test_hia_service_discovery_native.py', 'tests/test_hia_service_inspection_native.py', 'tests/test_hia_service_inspection_public_lifetime.py', 'tests/test_hia_service_read_native.py', 'tests/test_hia_service_slot_native.py', 'tests/test_hia_service_verification_finalization_native.py', 'tests/test_hia_service_verification_native.py', 'tests/test_hia_sha256_stream_transition_equivalence.py', 'tests/test_hia_slot_ledger_native.py', 'tests/test_hia_slot_ledger_native_integration.py', 'tests/test_hia_slot_operation_series_native.py', 'tests/test_hia_source_build.py', 'tests/test_hia_static_budget_native.py', 'tests/test_hia_store_artifact_profile_native.py', 'tests/test_hia_store_file_capture_native.py', 'tests/test_hia_store_file_capture_owned_fd_v2.py', 'tests/test_hia_store_lifecycle_native.py', 'tests/test_hia_store_native_delivery.py', 'tests/test_hia_store_transaction_native.py', 'tests/test_hia_store_transaction_owner_native.py', 'tests/test_hia_task_helpers_native.py', 'tests/test_hia_transaction_journal_cleanup.py', 'tests/test_hia_worker_native_helpers.py', 'tests/test_hia_worker_report_native.py', 'tests/test_hia_worker_request_native.py', 'tests/test_hia_worker_scheduling_bundle.py', 'tools/qualify_hia_agent_journal_callers.py', 'tools/qualify_hia_artifact_delivery_callers.py', 'tools/qualify_hia_byte_wrapper_callers.py', 'tools/qualify_hia_continuation_no_child.py', 'tools/qualify_hia_core_emitter_callers.py', 'tools/qualify_hia_core_lowering_callers.py', 'tools/qualify_hia_cost_ledger_callers.py', 'tools/qualify_hia_emission_callers.py', 'tools/qualify_hia_evaluation_callers.py', 'tools/qualify_hia_execution_observation_callers.py', 'tools/qualify_hia_full_cost_callers.py', 'tools/qualify_hia_generation_retention_callers.py', 'tools/qualify_hia_json_wire_native_callers.py', 'tools/qualify_hia_machine_encoding_native_callers.py', 'tools/qualify_hia_machine_instructions_callers.py', 'tools/qualify_hia_machine_object_callers.py', 'tools/qualify_hia_machine_plan_native_callers.py', 'tools/qualify_hia_machine_state_callers.py', 'tools/qualify_hia_native_build_admission_callers.py', 'tools/qualify_hia_native_delivery.py', 'tools/qualify_hia_patch_impact_callers.py', 'tools/qualify_hia_publication_measurement_callers.py', 'tools/qualify_hia_scalar_profile_callers.py', 'tools/qualify_hia_service_artifact_callers.py', 'tools/qualify_hia_service_bootstrap_callers.py', 'tools/qualify_hia_service_context_callers.py', 'tools/qualify_hia_service_discovery_callers.py', 'tools/qualify_hia_service_inspection_callers.py', 'tools/qualify_hia_service_lease_callers.py', 'tools/qualify_hia_service_read_callers.py', 'tools/qualify_hia_service_slot_callers.py', 'tools/qualify_hia_service_verification_callers.py', 'tools/qualify_hia_slot_operations_callers.py', 'tools/qualify_hia_static_budget_callers.py', 'tools/qualify_hia_store_artifact_profile_callers.py', 'tools/qualify_hia_store_file_capture_callers.py', 'tools/qualify_hia_store_lifecycle_callers.py', 'tools/qualify_hia_store_transaction.py', 'tools/qualify_hia_store_transaction_callers.py')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def read_relations(raw, *, previous_raw=None):
    if type(raw) is not bytes or sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('native cold caller source authority changed')
    value = json.loads(raw)
    if (type(value) is not dict
            or set(value) != {'schema', 'files', 'previous_authority', 'updated_paths'}
            or value['schema'] != SCHEMA or set(value['files']) != set(PATHS)
            or value['previous_authority'] != {'path': PREVIOUS_FIXTURE, **PREVIOUS_PIN}
            or value['updated_paths'] != list(INTEGRATED_PATHS)):
        raise ValueError('native cold caller source authority scope differs')
    if previous_raw is not None:
        if type(previous_raw) is not bytes or pin(previous_raw) != PREVIOUS_PIN:
            raise ValueError('native cold caller original authority changed')
        previous = json.loads(previous_raw)
        if (set(previous) != {'schema', 'files', 'previous_authority', 'updated_paths'}
                or previous['schema'] != 'hepta.hia.native-cold-caller-source-relations.v2'
                or previous['previous_authority'] != {'path': 'tests/fixtures/hia_native_cold_caller_relations_20261127.json', 'bytes': 234857, 'sha256': '28810aa4aea3e1297a2b09bc7f34a6aa8683f301f9aaab5eef5af1f0705f07b3'}
                or previous['updated_paths'] != ['tests/test_hia_store_native_delivery.py']
                or set(previous['files']) != set(PATHS)):
            raise ValueError('native cold caller original authority scope differs')
        for name, record in value['files'].items():
            old = previous['files'][name]
            changed = {key for key in set(record) | set(old) if record.get(key) != old.get(key)}
            if (set(record) != set(old) or record['predecessor'] != old['predecessor']
                    or not changed <= {'current', 'current_git_blob', 'splices'}
                    or (name not in INTEGRATED_PATHS and record != old)):
                raise ValueError('native cold caller integration changed an original relation: ' + name)
    return value['files']


def restore_caller_source(name, raw, relations):
    if name not in relations:
        return raw
    item = relations[name]
    if pin(raw) == item['predecessor']:
        return raw
    if pin(raw) != item['current']:
        raise ValueError('unreviewed native cold caller source: ' + name)
    end, result = 0, []
    for change in item['splices']:
        at, current, predecessor = change['offset'], bytes.fromhex(change['current_hex']), bytes.fromhex(change['predecessor_hex'])
        if (type(at) is not int or not end <= at <= at + len(current) <= len(raw)
                or raw[at:at + len(current)] != current):
            raise ValueError('native cold caller inverse does not match actual bytes: ' + name)
        result.extend((raw[end:at], predecessor))
        end = at + len(current)
    result.append(raw[end:])
    restored = b''.join(result)
    if pin(restored) != item['predecessor']:
        raise ValueError('native cold caller inverse differs from complete predecessor: ' + name)
    return restored


def original_caller_source(root, name, raw, *, take=Path.read_bytes):
    if name not in PATHS:
        return raw
    root = Path(root)
    frozen, previous = take(root / FIXTURE), take(root / PREVIOUS_FIXTURE)
    relations = read_relations(frozen, previous_raw=previous)
    result = restore_caller_source(name, raw, relations)
    if take(root / FIXTURE) != frozen or take(root / PREVIOUS_FIXTURE) != previous:
        raise ValueError('native cold caller authority changed during original readback')
    return result


def journal_preparation_from_predecessor(root, physical, predecessor, expected):
    """Run the unchanged historical source check on an exact inverse only."""
    from tempfile import TemporaryDirectory
    from tests import hia_journal_installed_preparation as journal
    from tests.hia_installed_distribution_history import journal_preparation_source
    root = Path(root)
    if physical == predecessor:
        return journal_preparation_source(root, physical, expected)
    from tests.hia_installed_distribution_history import FIXTURE as installed_fixture
    from tests.hia_component_authoring_history import FIXTURE as component_fixture
    names = (*journal.SOURCE_PATHS, installed_fixture, component_fixture)
    captured = {name: (root / name).read_bytes() for name in names}
    if captured[journal.PATH] != physical:
        raise ValueError('Journal physical source changed before historical admission')
    with TemporaryDirectory(prefix='hia-native-cold-caller-history-') as temporary:
        stage = Path(temporary)
        for name, raw in captured.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(predecessor if name == journal.PATH else raw)
        proof = journal_preparation_source(stage, predecessor, expected)
    if any((root / name).read_bytes() != raw for name, raw in captured.items()):
        raise ValueError('Journal physical source changed during historical admission')
    return proof
