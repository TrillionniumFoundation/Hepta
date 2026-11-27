"""Exact source inverses for native cold caller wiring.

These bytes are historical test inputs only. The current callers still run.
The fixed authority never grants native qualification to host authoring code.
"""
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

FIXTURE = 'tests/fixtures/hia_native_cold_caller_integration_20261127.json'
SOURCE = 'tools/hia_cold_caller_sources.py'
FIXTURE_SHA256 = 'ce9a293352ac12adb153ae91036915826f4a121a5b3668d8ffbd2f64e375e476'
SCHEMA = 'hepta.hia.native-cold-caller-source-relations.v2'
PREVIOUS_FIXTURE = 'tests/fixtures/hia_native_cold_caller_relations_20261127.json'
PREVIOUS_PIN = {'bytes': 234857, 'sha256': '28810aa4aea3e1297a2b09bc7f34a6aa8683f301f9aaab5eef5af1f0705f07b3'}
INTEGRATED_PATHS = ('tests/test_hia_store_native_delivery.py',)
PATHS = ('hepta/hia_agent_service.py', 'tests/hia_composite_function_fixture.py', 'tests/hia_service_bootstrap_controls.py', 'tests/hia_service_lease_controls.py', 'tests/hia_slot_operations_component_fixture.py', 'tests/test_hia_agent_installed_resources.py', 'tests/test_hia_agent_journal_extensions.py', 'tests/test_hia_agent_journal_native.py', 'tests/test_hia_agent_stdio.py', 'tests/test_hia_artifact_delivery.py', 'tests/test_hia_artifact_publication_native.py', 'tests/test_hia_artifact_publication_route.py', 'tests/test_hia_byte_wrapper_native.py', 'tests/test_hia_candidate_budget_native.py', 'tests/test_hia_capability_renaming_native.py', 'tests/test_hia_cli_native.py', 'tests/test_hia_composite_native_composition.py', 'tests/test_hia_composite_types_native.py', 'tests/test_hia_continuation_native.py', 'tests/test_hia_core_admission_cli.py', 'tests/test_hia_core_admission_native.py', 'tests/test_hia_core_emitter_native.py', 'tests/test_hia_core_json_bytes_native.py', 'tests/test_hia_core_lowering_native.py', 'tests/test_hia_core_module_graph_native.py', 'tests/test_hia_core_patch_cli.py', 'tests/test_hia_core_patch_native.py', 'tests/test_hia_core_patch_result_cli.py', 'tests/test_hia_core_workspace_json_native.py', 'tests/test_hia_core_workspace_pipeline.py', 'tests/test_hia_cost_ledger_native.py', 'tests/test_hia_default_native_release.py', 'tests/test_hia_emission_native.py', 'tests/test_hia_evaluation_capture.py', 'tests/test_hia_evaluation_native.py', 'tests/test_hia_execution_budget_native.py', 'tests/test_hia_execution_observation_native.py', 'tests/test_hia_full_cost_native.py', 'tests/test_hia_function_shape_native.py', 'tests/test_hia_generation_retention_native.py', 'tests/test_hia_instruction_policy_native.py', 'tests/test_hia_json_wire_native.py', 'tests/test_hia_machine_encoding_native.py', 'tests/test_hia_machine_instructions_native.py', 'tests/test_hia_machine_object_native.py', 'tests/test_hia_machine_plan_native.py', 'tests/test_hia_machine_state_native.py', 'tests/test_hia_native_admission_io.py', 'tests/test_hia_native_build_admission_native.py', 'tests/test_hia_native_build_dispatch.py', 'tests/test_hia_native_delivery.py', 'tests/test_hia_native_mapping_native.py', 'tests/test_hia_native_transport_failures.py', 'tests/test_hia_nominal_json_native.py', 'tests/test_hia_nominal_tokens_native.py', 'tests/test_hia_patch_impact_native.py', 'tests/test_hia_program_selfhost.py', 'tests/test_hia_program_shape_native.py', 'tests/test_hia_publication_measurement_native.py', 'tests/test_hia_release_install.py', 'tests/test_hia_release_selection.py', 'tests/test_hia_retirement_state_native.py', 'tests/test_hia_scalar_profile_native.py', 'tests/test_hia_selfhost_linked_observer.py', 'tests/test_hia_service_artifact_native.py', 'tests/test_hia_service_context_native.py', 'tests/test_hia_service_discovery_native.py', 'tests/test_hia_service_inspection_native.py', 'tests/test_hia_service_inspection_public_lifetime.py', 'tests/test_hia_service_read_native.py', 'tests/test_hia_service_slot_native.py', 'tests/test_hia_service_verification_finalization_native.py', 'tests/test_hia_service_verification_native.py', 'tests/test_hia_sha256_stream_transition_equivalence.py', 'tests/test_hia_slot_ledger_native.py', 'tests/test_hia_slot_ledger_native_integration.py', 'tests/test_hia_slot_operation_series_native.py', 'tests/test_hia_source_build.py', 'tests/test_hia_static_budget_native.py', 'tests/test_hia_store_artifact_profile_native.py', 'tests/test_hia_store_file_capture_native.py', 'tests/test_hia_store_file_capture_owned_fd_v2.py', 'tests/test_hia_store_lifecycle_native.py', 'tests/test_hia_store_native_delivery.py', 'tests/test_hia_store_transaction_native.py', 'tests/test_hia_store_transaction_owner_native.py', 'tests/test_hia_task_helpers_native.py', 'tests/test_hia_transaction_journal_cleanup.py', 'tests/test_hia_worker_native_helpers.py', 'tests/test_hia_worker_report_native.py', 'tests/test_hia_worker_request_native.py', 'tests/test_hia_worker_scheduling_bundle.py', 'tools/qualify_hia_agent_journal_callers.py', 'tools/qualify_hia_artifact_delivery_callers.py', 'tools/qualify_hia_byte_wrapper_callers.py', 'tools/qualify_hia_continuation_no_child.py', 'tools/qualify_hia_core_emitter_callers.py', 'tools/qualify_hia_core_lowering_callers.py', 'tools/qualify_hia_cost_ledger_callers.py', 'tools/qualify_hia_emission_callers.py', 'tools/qualify_hia_evaluation_callers.py', 'tools/qualify_hia_execution_observation_callers.py', 'tools/qualify_hia_full_cost_callers.py', 'tools/qualify_hia_generation_retention_callers.py', 'tools/qualify_hia_json_wire_native_callers.py', 'tools/qualify_hia_machine_encoding_native_callers.py', 'tools/qualify_hia_machine_instructions_callers.py', 'tools/qualify_hia_machine_object_callers.py', 'tools/qualify_hia_machine_plan_native_callers.py', 'tools/qualify_hia_machine_state_callers.py', 'tools/qualify_hia_native_build_admission_callers.py', 'tools/qualify_hia_native_delivery.py', 'tools/qualify_hia_patch_impact_callers.py', 'tools/qualify_hia_publication_measurement_callers.py', 'tools/qualify_hia_scalar_profile_callers.py', 'tools/qualify_hia_service_artifact_callers.py', 'tools/qualify_hia_service_bootstrap_callers.py', 'tools/qualify_hia_service_context_callers.py', 'tools/qualify_hia_service_discovery_callers.py', 'tools/qualify_hia_service_inspection_callers.py', 'tools/qualify_hia_service_lease_callers.py', 'tools/qualify_hia_service_read_callers.py', 'tools/qualify_hia_service_slot_callers.py', 'tools/qualify_hia_service_verification_callers.py', 'tools/qualify_hia_slot_operations_callers.py', 'tools/qualify_hia_static_budget_callers.py', 'tools/qualify_hia_store_artifact_profile_callers.py', 'tools/qualify_hia_store_file_capture_callers.py', 'tools/qualify_hia_store_lifecycle_callers.py', 'tools/qualify_hia_store_transaction.py', 'tools/qualify_hia_store_transaction_callers.py')


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('native cold caller source requires immutable bytes')
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
        if (set(previous) != {'schema', 'files'}
                or previous['schema'] != 'hepta.hia.native-cold-caller-source-relations.v1'
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


def _relative_name(name):
    if (type(name) is not str or not name or '\x00' in name or '\\' in name
            or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
            or str(PurePosixPath(name)) != name or name == '.'):
        raise ValueError('native cold caller source path is not canonical')
    return name


def original_caller_source(root, name, raw, *, take=Path.read_bytes):
    """Bind the complete supplied source to this root before and after inverse."""
    root = Path(root)
    name = _relative_name(name)
    pin(raw)
    captured = {}

    def capture(current):
        current = _relative_name(current)
        data = take(root / current)
        pin(data)
        if current in captured and captured[current] != data:
            raise ValueError('native cold caller physical input changed: ' + current)
        captured[current] = data
        return data

    if capture(name) != raw:
        raise ValueError('native cold caller supplied source differs from physical source')
    try:
        if name not in PATHS:
            return raw
        frozen, previous = capture(FIXTURE), capture(PREVIOUS_FIXTURE)
        relations = read_relations(frozen, previous_raw=previous)
        return restore_caller_source(name, raw, relations)
    finally:
        for current, expected in tuple(captured.items()):
            if capture(current) != expected:
                raise ValueError('native cold caller input changed during original readback')


def journal_preparation_from_predecessor(
        root, physical, predecessor, expected, *, take=Path.read_bytes):
    """Run the original gate on a declared view while capturing the physical root."""
    from tempfile import TemporaryDirectory
    from tests import hia_journal_installed_preparation as journal
    from tests.hia_installed_distribution_history import journal_preparation_source
    from tests.hia_installed_distribution_history import FIXTURE as installed_fixture
    from tests.hia_component_authoring_history import FIXTURE as component_fixture

    root = Path(root).resolve(strict=True)
    pin(physical)
    pin(predecessor)
    captured = {}

    def capture(path):
        path = Path(path)
        try:
            name = _relative_name(path.relative_to(root).as_posix())
        except ValueError as error:
            raise ValueError('Journal capture escaped the supplied physical root') from error
        data = take(root / name)
        pin(data)
        if name in captured and captured[name] != data:
            raise ValueError('Journal physical source changed between captures: ' + name)
        captured[name] = data
        return data

    if capture(root / journal.PATH) != physical:
        raise ValueError('Journal physical source changed before historical admission')
    try:
        if physical != predecessor:
            restored = original_caller_source(root, journal.PATH, physical, take=capture)
            if restored != predecessor:
                raise ValueError('Journal supplied predecessor is not the exact cold inverse')
        names = (*journal.SOURCE_PATHS, installed_fixture, component_fixture)
        inputs = {name: capture(root / name) for name in names}
        if physical == predecessor:
            # The canonical gate retains its original root. Its direct reads are
            # covered by the complete physical capture and terminal reread here.
            proof = journal_preparation_source(root, physical, expected, take=capture)
            view = dict(inputs)
        else:
            view = {name: predecessor if name == journal.PATH else data
                    for name, data in inputs.items()}
            with TemporaryDirectory(prefix='hia-native-cold-caller-history-') as temporary:
                stage = Path(temporary)
                for name, data in view.items():
                    target = stage / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)

                def stage_take(path):
                    try:
                        name = _relative_name(Path(path).relative_to(stage).as_posix())
                    except ValueError as error:
                        raise ValueError('Journal historical read escaped its declared view') from error
                    if name not in view:
                        raise ValueError('Journal historical read was not captured: ' + name)
                    current = capture(root / name)
                    projected = predecessor if name == journal.PATH else current
                    if projected != view[name] or (stage / name).read_bytes() != view[name]:
                        raise ValueError('Journal declared historical source changed: ' + name)
                    return view[name]

                proof = journal_preparation_source(
                    stage, predecessor, expected, take=stage_take)
                for name in view:
                    stage_take(stage / name)
    finally:
        for name, data in tuple(captured.items()):
            if capture(root / name) != data:
                raise ValueError('Journal physical source changed during historical admission')
    return {
        **proof,
        'native_cold_source_projection': {
            'path': journal.PATH,
            'physical_current': pin(physical),
            'declared_predecessor': pin(predecessor),
            'actual_captured_files': {name: pin(data) for name, data in captured.items()},
            'historical_view_files': {name: pin(data) for name, data in view.items()},
            'terminal_reread_identical': True,
            'whole_native_delivery_qualified': False,
        },
    }
