"""Actual sdist/wheel/installed native-worker resources, not source-path borrowing."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys,tarfile,tempfile,unittest,zipfile
from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, installation_manifest, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
from hepta.hia_agent_store import wire
from tools.hia_selfhost_contract import (
    ARTIFACT_CAPTURE_SDIST_FILES, CORE_EDIT_SDIST_FILES, CORE_NORMALIZE_SDIST_FILES,
    EXECUTION_LEDGER_SDIST_FILES, MCP_WIRE_SDIST_FILES, NATIVE_LINKER_SDIST_FILES,
    SCALAR_REFERENCE_SDIST_FILES,
    SQLITE_SNAPSHOT_SDIST_FILES, WORKER_REQUEST_SDIST_FILES,
)
ROOT=Path(__file__).resolve().parents[1]
RESOURCES=(tuple('docs/'+n for n in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
# Additional explicit sdist inputs stay separate from Agent RESOURCES.
# The two declared native package files also belong in the actual wheel;
# all other support paths remain absent from its package root.
SDIST_SUPPORT_FILES=(
    'examples/hia_bootstrap/source_filter_member.hepta',
    'examples/hia_bootstrap/source_helper_manifest.hepta',
    'examples/hia_bootstrap/source_compiler_manifest.hepta',
    'examples/hia_bootstrap/source_agent_stdio.hepta',
    'examples/hia_bootstrap/source_read_carrier.hepta',
    'examples/hia_bootstrap/source_owned_reference.hepta',
    'examples/hia_bootstrap/source_safe_proof.hepta',
    'examples/hia_bootstrap/source_core_application.hepta',
    'examples/hia_bootstrap/source_core_pin.hepta',
    'examples/hia_bootstrap/source_core_codec.hepta',
    'examples/hia_bootstrap/core_edit/source_codec_packer.hepta',
    'examples/hia_bootstrap/owned_reference_entry_wrapper.hepta',
    'examples/hia_bootstrap/owned_reference_entry_stub.hepta',
    'examples/hia_bootstrap/source_sqlite_unit.hepta',
    'examples/hia_bootstrap/source_agent_store.hepta',
    'tests/test_hia_source_filter_member.py',
    'examples/hia_bootstrap/job_terminal_receipt.hepta',
    'tools/generate_hia_job_terminal_receipt.py',
    'tests/test_hia_job_terminal_receipt.py',
    'tests/test_hia_worker_stream.py',
    'tests/fixtures/store_delivery_composition_successor.json',
    'tests/fixtures/worker_report_stream_successor.json',
    'tests/fixtures/store_legacy_provider_successor.json',
    'tests/fixtures/store_worker_metadata_successor.json',
    'tests/fixtures/store_worker_cost_successor.json',
    'tests/fixtures/worker_journal_cost_successor.json',
    'tests/fixtures/store_retained_read_successor.json',
    'tests/fixtures/store_evaluate_delivery_successor.json',
    'tests/fixtures/delivery_typed_sql_source.json',
    'tests/fixtures/store_caller_worker_helpers_successor.json',
    'tests/hia_historical_diagnostic_controls.py',
    'tests/fixtures/caller_terminal_store_composition_v1.json',
    'hepta/hia_agent_store_transport_native.py',
    'tests/test_hia_agent_store_transport_native.py',
    'tools/generate_hia_store_transport.py',
    'tests/fixtures/hia_compiler_rename_reference.json.gz',
    *ARTIFACT_CAPTURE_SDIST_FILES,
    *CORE_NORMALIZE_SDIST_FILES,
    *CORE_EDIT_SDIST_FILES,
    *MCP_WIRE_SDIST_FILES,
    *EXECUTION_LEDGER_SDIST_FILES,
    *NATIVE_LINKER_SDIST_FILES,
    *SCALAR_REFERENCE_SDIST_FILES,
    *WORKER_REQUEST_SDIST_FILES,
    *SQLITE_SNAPSHOT_SDIST_FILES,
    'tools/build_hia_nominal_json.py',
    'tools/hia_nominal_json_stdio.S',
    'tools/build_hia_nominal_constructor.py',
    'tools/hia_nominal_constructor.S',
    'docs/HIA_SLOT_MECHANICAL_BOUNDARY.md',
    'docs/HIA_SLOT_MECHANICAL_V5.md',
    'hepta/native/slot_mechanical.c',
    'hepta/native/slot_mechanical_build.py',
    'tests/hia_slot_mechanical_admission_controls.py',
    'tests/hia_slot_mechanical_capsule_observer.py',
    'tests/hia_slot_mechanical_installed_probe.py',
    'tests/hia_slot_mechanical_worker_probe.py',
    'tests/test_hia_slot_mechanical_native.py',
    'tools/build_hia_slot_mechanical.py',
    'tools/build_hia_slot_mechanical_bundle.py',
    'tools/qualify_hia_slot_mechanical_admission.py',
    'tools/qualify_hia_slot_mechanical_installed.py',
    'tools/qualify_hia_slot_mechanical_observations.py',
    'tools/qualify_hia_slot_mechanical_public.py',
    'tools/read_hia_slot_mechanical_admission.py',
    'tools/read_hia_slot_mechanical_installed.py',
    'tools/read_hia_slot_mechanical_observations.py',
    'examples/hia_bootstrap/executable_capture.hepta',
    'tools/hia_executable_capture_syscalls.S',
    'tools/generate_hia_executable_capture.py',
    'tools/build_hia_executable_capture.py',
    'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_store_file_capture_originals.py',
    'tools/generate_hia_selfhost.py',
    'tests/fixtures/executable_capture_r19_original.py.txt',
    'tests/hia_executable_capture_originals.py',
    'tests/fixtures/executable_capture_cases.json',
    'tests/test_hia_executable_capture.py',
    'docs/HIA_EXECUTABLE_CAPTURE.md',
    'tests/hia_executable_capture_receipt_controls.py',
    'tests/test_hia_executable_capture_receipt.py',
    'tests/fixtures/executable_capture_receipt_controls_v2.json',
    'examples/hia_bootstrap/vm_integer_divrem.hepta',
    'tools/build_hia_vm_integer_divrem.py',
    'tools/qualify_hia_vm_integer_divrem.py',
    'tools/read_hia_vm_integer_divrem.py',
    'tests/hia_vm_integer_divrem_cases.py',
    'tests/hia_vm_integer_divrem_controls.py',
    'tests/test_hia_vm_integer_divrem_native.py',
    'tests/fixtures/vm_integer_divrem_inputs_v1.json',
    'tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt',
    'docs/HIA_VM_INTEGER_DIVREM.md',
    'examples/hia_bootstrap/vm_integer_arithmetic.hepta',
    'tools/build_hia_vm_integer_arithmetic.py',
    'tools/qualify_hia_vm_integer_arithmetic.py',
    'tools/read_hia_vm_integer_arithmetic.py',
    'tests/hia_vm_integer_arithmetic_cases.py',
    'tests/hia_vm_integer_arithmetic_controls.py',
    'tests/test_hia_vm_integer_arithmetic_native.py',
    'tests/fixtures/vm_integer_arithmetic_inputs_v1.json',
    'docs/HIA_VM_INTEGER_ARITHMETIC.md',
    'examples/hia_bootstrap/vm_integer_scalar.hepta',
    'tools/build_hia_vm_integer_scalar.py',
    'tools/qualify_hia_vm_integer_scalar.py',
    'tools/read_hia_vm_integer_scalar.py',
    'tests/hia_vm_integer_scalar_cases.py',
    'tests/hia_vm_integer_scalar_controls.py',
    'tests/test_hia_vm_integer_scalar_native.py',
    'tests/fixtures/vm_integer_scalar_inputs_v1.json',
    'docs/HIA_VM_INTEGER_SCALAR.md',
    'tests/fixtures/caller_qualifier_successor_provenance_v1.json',
    'tests/fixtures/native_delivery_original_9c46166.json',
    'tests/fixtures/store_native_delivery_original_c019.json',
    'tests/hia_caller_terminal_admission.py',
    'tests/fixtures/hia_native_build_admission_callers_aac7550.json',
    'tests/fixtures/hia_emission_original_73f1634/original-freeze.json',
    'tests/fixtures/hia_store_artifact_profile_callers_73f1634.json',
    'tests/fixtures/native_transport_worker_terminal_v2_provenance.json',
    'tests/fixtures/evaluation_worker_terminal_v2_provenance.json',
    'tests/test_hia_native_delivery.py',
    'tests/test_hia_native_transport_failures.py',
    'tests/test_hia_evaluation_native.py',
    'tools/qualify_hia_native_build_admission_callers.py',
    'tools/qualify_hia_emission_callers.py',
    'tools/qualify_hia_store_artifact_profile_callers.py',
    'tests/hia_native_transport_worker_successor.py',
    'tests/hia_native_delivery_sql.py',
    'tests/test_hia_caller_qualifier_successor.py',
    'tests/test_hia_evaluation_worker_successor.py',
    'tests/test_hia_store_native_delivery.py',
    'tests/__init__.py',
    'examples/hia_bootstrap/exec_release_policy.hepta',
    'examples/hia_bootstrap/exec_release_packer.hepta',
    'tools/generate_hia_exec_release.py',
    'tools/hia_exec_release_syscalls.S',
    'tools/build_hia_exec_release.py',
    'tools/hia_exec_release_child.py',
    'tools/qualify_hia_exec_release.py',
    'tools/read_hia_exec_release.py',
    'tests/hia_exec_release_controls.py',
    'tests/test_hia_exec_release.py',
    'docs/HIA_EXEC_RELEASE_NATIVE.md',
    "tools/hia_cold_native_transport.h",
    "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_driver.c",
    "tools/hia_cold_native_transport_python.c",
    "tools/hia_cold_native_transport_handoff_controls.c",
    "tools/hia_cold_native_transport_bridge.py",
    "tools/generate_hia_cold_native_transport.py",
    "tools/build_hia_cold_native_transport.py",
    "tools/hia_cold_native_transport_evidence.py",
    "tools/qualify_hia_cold_native_transport.py",
    "tools/read_hia_cold_native_transport.py",
    "tests/test_hia_cold_native_transport.py",
    "tests/fixtures/cold_native_transport_original_gates_v3.json",
    "tests/fixtures/cold_native_transport_controls_v3.json",
    "docs/HIA_COLD_NATIVE_TRANSPORT.md",
    "examples/hia_bootstrap/cold_native_transport.hepta",
    "tools/hia_cold_native_transport_reference_controls.c",
    "tools/qualify_hia_cold_native_transport_references.py",
    "tools/hia_cold_native_transport_fd_controls.c",
    "tools/qualify_hia_cold_native_transport_fds.py",
    "tests/fixtures/cold_native_transport_fd_successor_v1.json",
    "tests/fixtures/cold_native_transport_controls_v4.json",
    "tools/hia_cold_native_transport_control_target.c",
    "tools/hia_cold_native_transport_policy_controls.c",
    "tests/hia_cold_native_transport_control_cases.py",
    "tools/qualify_hia_cold_native_transport_controls.py",
    "tools/read_hia_cold_native_transport_controls.py",
    "tests/test_hia_cold_native_transport_controls.py",
    # Current source successors and the exact inputs read by their new controls.
    "tests/hia_caller_diagnostics_admission.py",
    "tests/fixtures/caller_deadline_diagnostics_v1.json",
    "tests/test_hia_caller_diagnostics_admission.py",
    "tests/fixtures/caller_terminal_diagnostics_dependency_v1.json",
    "tests/test_hia_evaluation_caller_admission.py",
    "tests/fixtures/slot_worker_terminal_v2.json",
    "tests/hia_slot_worker_terminal.py",
    "tests/test_hia_slot_worker_terminal.py",
    "tools/read_hia_slot_worker_terminal.py",
    "tests/fixtures/hia_cli_discovery_verified_build.json",
    "tests/fixtures/hia_cli_discovery_word_memory.json",
    "tests/fixtures/hia_cli_discovery_default_successor.json",
    "tests/fixtures/static_budget_word_memory_d998.py.txt",
    "tests/test_hia_slot_word_memory.py",
    "tests/fixtures/slot_operations_word_memory_v8.json",
    "tests/fixtures/worker_unknown_original_r17b/hia_agent_worker.py.txt",
    "tests/hia_slot_operations_qualification_support.py",
    "tests/hia_slot_operations_installed_observer.py",
    "tests/test_hia_slot_operations_native.py",
    "tools/build_hia_slot_operations.py",
    "tools/read_hia_slot_definition_lifetime.py",
    "tests/fixtures/evaluation_callers_19065.json",
    "tests/fixtures/evaluation_historical_controls_v1.json",
    "tools/qualify_hia_evaluation_callers.py",
    "tools/run_hia_unittest_gate.py",
    "tools/generate_hia_slot_operations.py",
    "tools/generate_hia_service_context.py",
    "tools/generate_hia_store_lifecycle.py",
    "tools/hia_service_context_arithmetic.py",
    "tests/test_hia_agent_buffer_lifecycle.py",
    "tests/test_hia_agent_external_roots.py",
    "tests/test_hia_agent_native_campaign.py",
    "tests/test_hia_agent_native_lease_snapshot.py",
    "tests/test_hia_agent_native_machine_validation.py",
    "tests/test_hia_agent_native_tools.py",
    "tests/test_hia_candidate_budget_native.py",
    "tests/test_hia_cost_ledger_native.py",
    "tests/test_hia_execution_budget_native.py",
    "tests/test_hia_first_use.py",
    "tests/test_hia_slot_ledger_native_integration.py",
    "tests/test_hia_worker_native_helpers.py",
    # Exact existing Delivery guards and their consumed original source data.
    "tests/fixtures/delivery_diagnostic_source_successors_v1.json",
    "tests/fixtures/delivery_sqlite_boundary_source_v3.json",
    "tests/test_hia_delivery_diagnostic_sources.py",
    "tests/hia_store_delivery_successor.py",
    "tests/fixtures/store_delivery_successor_provenance.json",
    "docs/HIA_NATIVE_DELIVERY_CAUSALITY.md",
    "tests/fixtures/AgentStore._ref.py.txt",
    "tests/fixtures/AgentStore.check_profile.py.txt",
    "tests/fixtures/AgentStore.get.py.txt",
    "tests/fixtures/AgentStore.get_json.py.txt",
    "tests/fixtures/AgentStore.json.py.txt",
    "tests/fixtures/AgentStore.profile.py.txt",
    "tests/fixtures/AgentStore.put.py.txt",
    "tests/fixtures/AgentStore.resolve_uri.py.txt",
    "tests/fixtures/cost_ledger_b569c210.py.txt",
    "tests/fixtures/cost_ledger_callers_b569c210.json",
    "tests/fixtures/hia_agent_store_73f1634.py.txt",
    "tests/fixtures/hia_emission_original_73f1634/cases.json",
    "tests/fixtures/hia_emission_original_73f1634/hia_emission_compile_73f1634.py.txt",
    "tests/fixtures/hia_emission_original_73f1634/hia_emission_emit_73f1634.py.txt",
    "tests/fixtures/hia_emission_original_73f1634/hia_emission_original_oracle.py",
    "tests/fixtures/hia_evaluation_value_19065.py.txt",
    "tests/fixtures/hia_native_build_dispatch_cases_aac7550.json",
    "tests/fixtures/hia_native_build_inputs_aac7550.py.txt",
    "tests/fixtures/hia_native_build_native_aac7550.py.txt",
    "tests/fixtures/hia_native_build_receipt_aac7550.py.txt",
    "tests/fixtures/hia_native_build_signatures_aac7550.py.txt",
    "tests/fixtures/hia_store_artifact_profile_cases_73f1634.json",
    "tests/fixtures/service_context_b569c21.py.txt",
    "tests/fixtures/service_context_callers_b569c21.json",
    "tests/fixtures/store_lifecycle_ad352ee.py.txt",
    "tests/fixtures/store_lifecycle_callers_ad352ee.json",
    "tests/hia_evaluation_oracle.py",
    "tests/hia_evaluation_scenarios.py",
    "tests/hia_native_build_admission_oracle.py",
    "tests/hia_native_build_admission_scenarios.py",
    "tests/hia_native_build_dispatch_oracle.py",
    "tests/hia_native_delivery_cases.py",
    "tests/hia_service_context_fixtures.py",
    "tests/hia_store_artifact_profile_oracle.py",
    "tests/hia_store_lifecycle_fixtures.py",
    "tests/hia_store_limit_oracle.py",
    "tests/hia_store_literal_call_oracle.py",
    "tests/test_hia_agent_artifact_store_native.py",
    "tests/test_hia_agent_journal_native.py",
    "tests/test_hia_agent_native_machine_choices.py",
    "tests/test_hia_agent_native_proof_contract.py",
    "tests/test_hia_emission_native.py",
    "tests/test_hia_execution_observation_native.py",
    "tests/test_hia_native_build_admission_native.py",
    "tests/test_hia_native_build_dispatch.py",
    "tests/test_hia_service_context_native.py",
    "tests/test_hia_store_artifact_profile_native.py",
    "tests/test_hia_store_lifecycle_native.py",
    "tools/build_hia_cost_ledger.py",
    "tools/build_hia_emission.py",
    "tools/build_hia_evaluation.py",
    "tools/build_hia_native_build_admission.py",
    "tools/build_hia_service_context.py",
    "tools/build_hia_store_lifecycle.py",
    "tools/generate_hia_store_artifact_profile.py",
    "tools/qualify_hia_agent_journal_callers.py",
    "tools/qualify_hia_cost_ledger_callers.py",
    "tools/qualify_hia_native_delivery.py",
    "tools/qualify_hia_service_context_callers.py",
    "tools/qualify_hia_store_lifecycle_callers.py",
    # Complete Bootstrap caller source admission; no native qualification claim.
    "tests/test_hia_service_bootstrap_caller_admission.py",
    "tools/qualify_hia_service_bootstrap_callers.py",
    "tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json",
    # Independent Bootstrap caller readback and complete Source4 input closure.
    "tools/read_hia_service_bootstrap.py",
    "tests/hia_service_bootstrap_support.py",
    "tests/test_hia_service_bootstrap_caller_readback.py",
    # Versioned artifact preparation and the complete Source4 read closure.
    'tests/hia_service_artifact_preparation.py',
    'tests/test_hia_service_artifact_preparation.py',
    'tests/fixtures/hia_service_artifact_preparation_v2.json',
    'tests/fixtures/hia_service_artifact_original_5bf/oracle-preparation-v1.py.txt',
    'tests/hia_service_artifact_oracle.py',
    'tests/hia_service_artifact_observer.py',
    'tests/fixtures/hia_service_artifact_original_5bf/artifact.5bf.py.txt',
    'tests/fixtures/hia_service_artifact_original_5bf/profile.5bf.py.txt',
    'tests/fixtures/hia_service_artifact_original_5bf/cases.json',
    'tests/fixtures/hia_service_artifact_original_5bf/source-identity.json',
    'tests/fixtures/hia_service_artifact_original_5bf/freeze.json',
    # Complete original artifact Source3 and LocalRelease3.
    'tests/test_hia_service_artifact_local_release.py',
    'tests/hia_service_artifact_local_release_observer.py',
    'tests/test_hia_service_artifact_native.py',
    'tools/generate_hia_service_artifact.py',
    # Actual transitive authoring imports required by the original generator.
    'tools/hia_selfhost_chain_elf.py',
    'tools/hia_selfhost_cli.py',
    'tools/hia_selfhost_effects.py',
    'tools/hia_selfhost_exports.py',
    'tools/hia_selfhost_keywords.py',
    'tools/hia_selfhost_limits.py',
    'tools/hia_selfhost_multi_results.py',
    'tools/hia_selfhost_names.py',
    'tools/hia_selfhost_owned_elf.py',
    'tools/hia_selfhost_returned_loans.py',
    'tools/hia_selfhost_signed.py',
    'tools/hia_selfhost_traps.py',
    'tools/hia_selfhost_word_memory.py',
    # Journal preparation Source controls and their fixed complete caller input closure.
    'tests/fixtures/hia_service_discovery_original_r5/caller-scopes.json',
    'tests/fixtures/hia_service_verification_original_r12/caller-scopes.json',
    'tests/fixtures/hia_store_transaction_separate_5bf.json',
    'tests/fixtures/journal_installed_preparation_v1.py.txt',
    'tests/fixtures/journal_installed_preparation_v2.json',
    'tests/hia_journal_installed_preparation.py',
    'tests/test_hia_delivery_journal_preparation.py',
    'tests/test_hia_journal_caller_preparation.py',
    'tests/test_hia_journal_installed_preparation.py',
    'tests/test_hia_service_bootstrap_journal_preparation.py',
    'tests/test_hia_slot_ledger_native.py',
    'tools/qualify_hia_service_discovery_callers.py',
    'tools/qualify_hia_service_verification_callers.py',
    'tools/qualify_hia_store_transaction.py',
    'tests/hia_service_artifact_worker_terminal.py',
    'tools/read_hia_service_artifact_worker_terminal.py',
    'tests/test_hia_service_artifact_worker_terminal.py',
    'tests/fixtures/service_artifact_worker_terminal_v2.json',
    'tests/test_hia_service_context_caller_admission.py',
    'tools/build_hia_service_artifact.py',
    'tests/fixtures/cost_context_caller_source_successors_v1.json',
    'tests/fixtures/hia_artifact_delivery_callers_5bf69586.json',
    'tests/fixtures/hia_artifact_delivery_original_5da589f0.json',
    'tests/test_artifact_publication.py',
    'tests/test_hia_agent_assembly.py',
    'tests/test_hia_artifact_publication_native.py',
    'tests/test_hia_artifact_publication_route.py',
    'tests/test_hia_cost_artifact_caller_admission.py',
    'tests/test_hia_cost_context_caller_delivery_source.py',
    'tests/test_hia_ndu_bridge.py',
    'tools/qualify_hia_artifact_delivery_callers.py',
    'tests/test_hia_linked_observer_build_custody.py',
    'tests/test_hia_observer_stream_retention.py',
    'tests/test_hia_selfhost_linked_observer.py',
    'tests/test_hia_selfhost_native_observer.py',
    'tools/hia_selfhost_linked_observer.py',
    'tools/hia_selfhost_native_observer.py',
)
SDIST_SUPPORT_FILES=tuple(dict.fromkeys(SDIST_SUPPORT_FILES))
WHEEL_PACKAGE_FILES=(
    'hepta/hia_agent_store_transport_native.py',
    'hepta/native/slot_mechanical.c',
    'hepta/native/slot_mechanical_build.py',
)
# Independently selected executable-capture data; not Agent identity inputs.
EXECUTABLE_CAPTURE_RESOURCES=(
    'examples/hia_bootstrap/executable_capture.hepta',
    'tools/hia_executable_capture_syscalls.S',
    'tools/generate_hia_executable_capture.py',
    'tools/build_hia_executable_capture.py',
    'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_store_file_capture_originals.py',
    'tools/generate_hia_selfhost.py',
    'tests/fixtures/executable_capture_r19_original.py.txt',
    'tests/hia_executable_capture_originals.py',
    'tests/fixtures/executable_capture_cases.json',
    'tests/test_hia_executable_capture.py',
    'tests/hia_executable_capture_receipt_controls.py',
    'tests/test_hia_executable_capture_receipt.py',
    'tests/fixtures/executable_capture_receipt_controls_v2.json',
    'docs/HIA_EXECUTABLE_CAPTURE.md',
)
# Independent explicit div/rem data; no Agent helper/default selection.
VM_INTEGER_DIVREM_RESOURCES = ('examples/hia_bootstrap/vm_integer_divrem.hepta',)
VM_INTEGER_ARITHMETIC_RESOURCES = ('examples/hia_bootstrap/vm_integer_arithmetic.hepta',)
VM_INTEGER_SCALAR_RESOURCES = ('examples/hia_bootstrap/vm_integer_scalar.hepta',)
BUNDLED_SOURCE_BINDINGS={
    'owned_reference':('hepta.hia_scalar_reference_native','owned'),
    'cli_control':('hepta.hia_cli_native','control'),
    'cli_format':('hepta.hia_cli_native','format'),
    'composite_function_admit':('hepta.hia_composite_functions_native','admit'),
    'composite_function_records':('hepta.hia_composite_functions_native','records'),
    'composite_function_advanced':('hepta.hia_composite_functions_native','advanced'),
    'composite_function_terms':('hepta.hia_composite_functions_native','terms'),
    'composite_function_render':('hepta.hia_composite_functions_native','render'),
    'composite_constructor_owner':('hepta.hia_composite_constructor_native','owner'),
    'composite_constructor_render':('hepta.hia_composite_constructor_native','render'),
    'composite_outer_owner':('hepta.hia_composite_outer_native','owner'),
    'composite_outer_render':('hepta.hia_composite_outer_native','render'),
}

class AgentInstalledResourceSourceTests(unittest.TestCase):
    def test_source_builder_roles_remain_closed_and_compiler_data_remains_packaged(self):
        self.assertEqual(SOURCE_BUILD_FILES,(
            'examples/hia_bootstrap/source_build_policy.hepta',
            'examples/hia_bootstrap/selfhost.hepta',
            'examples/hia_bootstrap/source_build_packer.hepta',
        ))
        self.assertEqual(COMPILER_BUILD_FILES,('examples/hia_bootstrap/core_json_cli_packer.hepta',))
        self.assertTrue(set(COMPILER_BUILD_FILES).isdisjoint(
            (*NATIVE_SOURCE_FILES,*SOURCE_BUILD_FILES,*PUBLICATION_BUILD_FILES)))
        self.assertLessEqual(set(COMPILER_BUILD_FILES),set(RESOURCES))
        self.assertEqual(len(RESOURCES),len(set(RESOURCES)))
        from hepta.hia_core_lowering_selection import ABI_SOURCE, checked_abi, source_names
        backend_abi=checked_abi((ROOT/ABI_SOURCE).read_bytes())
        self.assertEqual(BACKEND_BUILD_FILES,(ABI_SOURCE,*source_names(backend_abi)))
        self.assertEqual(len(source_names(backend_abi)),33)
        self.assertTrue(set(BACKEND_BUILD_FILES).isdisjoint(
            (*NATIVE_SOURCE_FILES,*SOURCE_BUILD_FILES,*COMPILER_BUILD_FILES,*PUBLICATION_BUILD_FILES)))
        self.assertLessEqual(set(BACKEND_BUILD_FILES),set(RESOURCES))

    def test_actual_build_hook_uses_distinct_discovery_and_native_resource_paths(self):
        import ast
        source=ast.parse((ROOT/'setup.py').read_text())
        functions=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='agent_resources']
        self.assertEqual(len(functions),1)
        namespace={'ast':ast,'Path':Path,'ROOT':ROOT}
        exec(compile(ast.Module(body=functions,type_ignores=[]),'setup.py','exec'),namespace)
        self.assertEqual(namespace['agent_resources'](),RESOURCES)
        capture_functions=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='executable_capture_resources']
        self.assertEqual(len(capture_functions),1)
        exec(compile(ast.Module(body=capture_functions,type_ignores=[]),'setup.py','exec'),namespace)
        self.assertEqual(namespace['executable_capture_resources'](RESOURCES),EXECUTABLE_CAPTURE_RESOURCES)
        vm_resources=[node.value for node in source.body if isinstance(node,ast.Assign)
                      and any(isinstance(target,ast.Name) and target.id=='VM_INTEGER_DIVREM_RESOURCES'
                              for target in node.targets)]
        self.assertEqual(len(vm_resources),1)
        self.assertEqual(ast.literal_eval(vm_resources[0]),VM_INTEGER_DIVREM_RESOURCES)

    def test_sdist_manifest_explicitly_preserves_every_agent_resource(self):
        declared=[line.removeprefix('include ') for line in (ROOT/'MANIFEST.in').read_text().splitlines() if line.startswith('include ')]
        self.assertTrue(set(RESOURCES).isdisjoint(SDIST_SUPPORT_FILES))
        self.assertEqual(set(declared),set(RESOURCES)|set(SDIST_SUPPORT_FILES))
        self.assertEqual(len(declared),len(RESOURCES)+len(SDIST_SUPPORT_FILES))
        for name in SDIST_SUPPORT_FILES:
            self.assertTrue((ROOT/name).is_file(),name)

    def test_every_actual_worker_asset_is_in_source_release_and_shared_identity(self):
        from tools.hia_selfhost_contract import SOURCE_FILES,CONTRACT_PATH
        from tools.hia_release import BOOTSTRAP_FILES
        for paths in ((*SOURCE_FILES,CONTRACT_PATH),BOOTSTRAP_FILES):
            self.assertLessEqual(set(RESOURCES),set(paths))

    def test_complete_source_binding_map_matches_each_actual_runtime_bridge(self):
        from importlib import import_module
        observed={}
        for resource in NATIVE_SOURCE_FILES:
            name=Path(resource).stem
            if name in BUNDLED_SOURCE_BINDINGS:
                module,key=BUNDLED_SOURCE_BINDINGS[name]
                source=import_module(module).SOURCES[key]
            elif name=='native_mapping':
                source=import_module('hepta.native_mapping_native').SOURCE
            else:
                source=import_module('hepta.hia_'+name+'_native').SOURCE
            self.assertEqual(source,ROOT/resource)
            observed[name]=source
        self.assertEqual(len(observed),len(NATIVE_SOURCE_FILES))
        self.assertLessEqual(set(BUNDLED_SOURCE_BINDINGS),set(observed))

class AgentInstalledResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_agent_identity_native import witnesses
        witnesses() # Complete independent VM bytes precede native seed.
        from tests.test_hia_agent_slice_native import references
        references() # Graph result bytes also precede native seed.
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_agent_identity_native import SOURCE,SCHEMA
        from tests.test_hia_agent_entry import CHILD
        from tests.test_hia_artifact_publication_native import observe,fields,vm_pack
        observe(b'abc',b'abc',fields(p0=3,p16=3,p24=3))
        vm_pack(b'\xc3',b'\xc3')  # Publication policy/packer VM before native seed.
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-installed-resources-');cls.folder=Path(cls.temp.name)
        source=cls.folder/'source';source.mkdir();cls.source=source
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        def build(name,args):
            with (cls.folder/(name+'.log')).open('xb') as out:
                result=subprocess.run([sys.executable,'-B',*map(str,args)],cwd=source,
                    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout=out,stderr=subprocess.STDOUT)
            if result.returncode:raise AssertionError(name+': '+(cls.folder/(name+'.log')).read_text())
        # Exercise both source-distribution and wheel packaging, outside ROOT.
        build('sdist',['setup.py','sdist','--dist-dir',cls.folder/'sdist'])
        archive,=(cls.folder/'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as tar:
            paths=tar.getnames();prefix=paths[0].split('/')[0]+'/'
            for name in (*RESOURCES,*SDIST_SUPPORT_FILES):
                assert tar.extractfile(prefix+name).read()==(ROOT/name).read_bytes()
        build('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',cls.folder/'wheels',archive])
        wheel,=(cls.folder/'wheels').glob('*.whl');cls.wheel=wheel;cls.installed=cls.folder/'installed'
        build('install',['-m','pip','install','--no-deps','--no-index','--target',cls.installed,wheel])
        cls.native=cls.folder/'native';cls.native.mkdir()
        seed,_=build_seed(cls.native);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.native,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.native,'B2',first,compiler);assert first.read_bytes()==second.read_bytes()
        cls.compiler=second
        image,_=compile_stage(cls.native,'identity',second,SOURCE.read_bytes())
        cls.manifest=cls.native/'manifest.json';cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),image_path=image.name,image_sha256=sha256(image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_slice_native import SOURCE as SLICE_SOURCE,SCHEMA as SLICE_SCHEMA
        slice_image,_=compile_stage(cls.native,'slice',second,SLICE_SOURCE.read_bytes())
        cls.slice_manifest=cls.native/'slice-manifest.json'
        cls.slice_manifest.write_text(json.dumps(dict(schema=SLICE_SCHEMA,
            source_sha256=sha256(SLICE_SOURCE.read_bytes()).hexdigest(),image_path=slice_image.name,
            image_sha256=sha256(slice_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE, SCHEMA as DATA_SCHEMA
        data_image,_=compile_stage(cls.native,'agent-data-json',second,DATA_SOURCE.read_bytes())
        cls.data_manifest=cls.native/'data-manifest.json'
        cls.data_manifest.write_text(json.dumps(dict(schema=DATA_SCHEMA,
            source_sha256=sha256(DATA_SOURCE.read_bytes()).hexdigest(),image_path=data_image.name,
            image_sha256=sha256(data_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_binary64_native import SOURCE as FLOAT_SOURCE, SCHEMA as FLOAT_SCHEMA
        float_image,_=compile_stage(cls.native,'agent-binary64',second,FLOAT_SOURCE.read_bytes())
        cls.float_manifest=cls.native/'binary64-manifest.json'
        cls.float_manifest.write_text(json.dumps(dict(schema=FLOAT_SCHEMA,
            source_sha256=sha256(FLOAT_SOURCE.read_bytes()).hexdigest(),image_path=float_image.name,
            image_sha256=sha256(float_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        # These are the genuine B2-produced Core-policy images, not a fixture ABI.
        cls.core_manifests={}
        from importlib import import_module
        for key in ('program_shape','instruction_policy','core_admission'):
            module=import_module('hepta.hia_'+key+'_native')
            core_image,_=compile_stage(cls.native,key,second,module.SOURCE.read_bytes())
            core_manifest=cls.native/(key+'-manifest.json')
            core_manifest.write_text(json.dumps(dict(schema=module.SCHEMA,
                source_sha256=sha256(module.SOURCE.read_bytes()).hexdigest(),image_path=core_image.name,
                image_sha256=sha256(core_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
            cls.core_manifests[key]=core_manifest
        from hepta.hia_agent_binary64_format_native import SOURCE as PRINT_SOURCE, SCHEMA as PRINT_SCHEMA
        print_image,_=compile_stage(cls.native,'agent-binary64-format',second,PRINT_SOURCE.read_bytes())
        cls.print_manifest=cls.native/'binary64-format-manifest.json'
        cls.print_manifest.write_text(json.dumps(dict(schema=PRINT_SCHEMA,
            source_sha256=sha256(PRINT_SOURCE.read_bytes()).hexdigest(),image_path=print_image.name,
            image_sha256=sha256(print_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_native_helpers import SCHEMA as HELPERS_SCHEMA, TARGET as HELPERS_TARGET, ABI as HELPERS_ABI
        cls.helpers_manifest=cls.native/'worker-helpers.json'
        cls.helpers_manifest.write_text(json.dumps({
            'schema':HELPERS_SCHEMA,'target':HELPERS_TARGET,'abi':HELPERS_ABI,
            'helpers':[{'selector':selector,'manifest_path':manifest.name,
                        'manifest_sha256':sha256(manifest.read_bytes()).hexdigest()}
                       for selector,manifest in (
                           ('HEPTA_HIA_AGENT_IDENTITY_MANIFEST',cls.manifest),
                           ('HEPTA_HIA_AGENT_SLICE_MANIFEST',cls.slice_manifest),
                           ('HEPTA_HIA_AGENT_DATA_JSON_MANIFEST',cls.data_manifest),
                           ('HEPTA_HIA_AGENT_BINARY64_MANIFEST',cls.float_manifest),
                           ('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST',cls.print_manifest))]},
            sort_keys=True),encoding='utf-8')
        cls.helpers_sha256=sha256(cls.helpers_manifest.read_bytes()).hexdigest()
        cls.helper_flags=('--native-helpers-manifest',str(cls.helpers_manifest),
                          '--expected-native-helpers-sha256',cls.helpers_sha256)
        from tools.build_hia_artifact_publication import build,current_sources,SOURCES,OPERATIONS
        from tools.hia_selfhost_contract import PROFILE
        cls.publication=cls.native/'publication';cold_path=os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT')
        if cold_path:
            cold=json.loads(Path(cold_path).read_bytes());nested=json.loads(Path(cold['nested_report']).read_bytes())
            qualified=Path(nested['generations'][-1]['produced_image'])
            assert qualified.read_bytes()==second.read_bytes()
            build(cls.publication,qualified,Path(cold_path))
        else:
            # Honest actual B2 development build; never invent a cold PASS.
            from tools.qualify_hia_selfhost import invoke
            from tools.generate_hia_artifact_publication import MAGIC
            from tools.qualify_hia_selfhost_cli import inspect_executable
            import struct
            cls.publication.mkdir();images={}
            for label,name in zip(('policy','packer','sha256'),SOURCES[:3]):
                images[label],_=compile_stage(cls.publication,label,second,(ROOT/name).read_bytes())
            policy=images['policy'].read_bytes();sha=images['sha256'].read_bytes()
            result,raw=invoke(cls.publication,'pack',images['packer'],struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha)
            assert result['status']=='returned' and 0<result['core_u32']<=len(raw)
            code=raw[:result['core_u32']];inspect_executable(code)
            app=cls.publication/'hia-artifact';app.write_bytes(code);app.chmod(0o700)
            (cls.publication/'build.json').write_text(json.dumps(dict(schema='hepta.hia.artifact-publication-build.v1',
                status='NATIVE_ARTIFACT_PUBLICATION_BUILT',profile=PROFILE,source_manifest=current_sources(),operations=OPERATIONS,
                executable_path='hia-artifact',executable_sha256=sha256(code).hexdigest(),
                source_sha256={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES},development_only=True)))
        # Reuse this actual sdist/wheel and genuine compiler for the two new
        # components. A configured cold path must use each strict real builder.
        from hepta.hia_nominal_json_native import SOURCE as NOMINAL_SOURCE,SCHEMA as NOMINAL_SCHEMA
        nominal_cold=os.environ.get('HEPTA_HIA_NOMINAL_JSON_COLD_REPORT')
        if nominal_cold:
            from tools.build_hia_nominal_json import build as build_nominal
            outer=json.loads(Path(nominal_cold).read_bytes())
            nested=json.loads(Path(outer['nested_report']).read_bytes())
            qualified=Path(nested['generations'][-1]['produced_image'])
            assert qualified.read_bytes()==second.read_bytes()
            cls.nominal_manifest=build_nominal(cls.native/'nominal-cold',qualified,Path(nominal_cold))
        else:
            nominal_image,_=compile_stage(cls.native,'nominal-json',second,NOMINAL_SOURCE.read_bytes())
            cls.nominal_manifest=cls.native/'nominal-manifest.json'
            cls.nominal_manifest.write_text(json.dumps(dict(schema=NOMINAL_SCHEMA,
                source_sha256=sha256(NOMINAL_SOURCE.read_bytes()).hexdigest(),image_path=nominal_image.name,
                image_sha256=sha256(nominal_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        cls.source_build=cls.native/'source-build'
        source_build_cold=os.environ.get('HEPTA_HIA_SOURCE_BUILD_COLD_REPORT')
        if source_build_cold:
            from tools.build_hia_source_build import build as build_sources
            outer=json.loads(Path(source_build_cold).read_bytes())
            nested=json.loads(Path(outer['nested_report']).read_bytes())
            qualified=Path(nested['generations'][-1]['produced_image'])
            assert qualified.read_bytes()==second.read_bytes()
            cls.source_builder=build_sources(cls.source_build,qualified,Path(source_build_cold))
        else:
            # Actual bootstrap development, with no fabricated cold receipt.
            from tools.qualify_hia_selfhost import invoke
            from tools.generate_hia_source_build import PACK_MAGIC
            from tests.test_hia_source_build import vm_packer,expected_elf
            import struct
            vm_packer()
            cls.source_build.mkdir()
            images=[]
            for name in ('source_build_policy','source_build_packer'):
                image,_=compile_stage(cls.source_build,name,second,
                    (ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes())
                images.append(image)
            policy,packer=images
            parts=(policy.read_bytes(),second.read_bytes(),packer.read_bytes())
            packet=struct.pack('<4Q',PACK_MAGIC,*map(len,parts))+b''.join(parts)
            receipt,raw=invoke(cls.source_build,'bootstrap-pack',packer,packet)
            assert receipt['status']=='returned' and type(receipt['core_u32']) is int
            code=raw[:receipt['core_u32']]
            assert code==expected_elf(parts)
            cls.source_builder=cls.source_build/'hia-source-build'
            cls.source_builder.write_bytes(code);cls.source_builder.chmod(0o500)
        prefix=CHILD.split('from hepta.cli import')[0]
        cls.child='import sys\nsys.path.insert(0,sys.argv[1])\n'+prefix+'\nBUNDLED_SOURCE_BINDINGS='+repr(BUNDLED_SOURCE_BINDINGS)+'\n'+'''
from pathlib import Path
from hepta import hia_agent_store as store
from hepta.hia_agent_identity_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
assert not any('agent-identity-install-development' in p for p in sys.path)
def absent(*a,**kw):raise AssertionError('foreign scalar identity predicate')
store._reference_uint64=absent;store._reference_digest=absent
assert store.uint64('18446744073709551615','epoch')==18446744073709551615
assert store.canonical_digest('a'*64)
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_worker import main
if sys.argv[2]=='identity':print(__import__('json').dumps(installation_manifest()))
elif sys.argv[2]=='printing':
    from hepta.hia_agent_binary64_format_native import SOURCE as PRINT_SOURCE
    assert Path(sys.argv[1]) in PRINT_SOURCE.parents,PRINT_SOURCE
    import json
    json.JSONEncoder.iterencode=absent
    sys.stdout.buffer.write(store.wire({'zero':-0.0,'ratio':1.25,'tiny':5e-324,'large':1e16,'text':'中'}))
elif sys.argv[2] in ('publication','artifact-store'):
    import importlib.abc,os,inspect
    class NoBuildTools(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='tools' or fullname.startswith('tools.'):
                raise AssertionError('installed runtime tried to import checkout build tools')
    sys.meta_path.insert(0,NoBuildTools())
    manifest=sys.argv[3];case=Path(sys.argv[4]);payload=b'installed\\x00native\\xff'
    if sys.argv[2]=='publication':
        from hepta import artifact_publication as publication
        os.environ['HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST']=manifest
        publication._read_exact=absent;publication.sha256=absent
        stage=case/'stage';dest=case/'published'
        receipt=publication.publish_verified(stage,dest,payload)
        assert publication.verify_published(stage,dest,payload)==receipt
        assert stage.stat().st_ino==dest.stat().st_ino
        assert publication.withdraw_own_link(stage,dest) and not dest.exists()
        print(json.dumps(receipt,sort_keys=True))
    else:
        os.environ['HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST']=manifest
        original_hash=store.sha256;original_read=store.stable_read
        def guard_hash(data):
            if inspect.currentframe().f_back.f_code.co_name in ('put','get'):absent()
            return original_hash(data)
        def guard_read(*args,**kwargs):
            if inspect.currentframe().f_back.f_code.co_name in ('put','get'):absent()
            return original_read(*args,**kwargs)
        store.sha256=guard_hash;store.stable_read=guard_read
        state=store.AgentStore(case/'state')
        try:
            ref=state.put(payload,'input',{'installed':True})
            assert state.get(ref)==(payload,{'installed':True})
            assert state.put(payload,'input',{'installed':True})==ref
        finally:state.close()
        state=store.AgentStore(case/'state')
        try:assert state.get(ref)==(payload,{'installed':True})
        finally:state.close()
        print(json.dumps(ref,sort_keys=True))
    assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
elif sys.argv[2]=='data':
    from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE
    assert Path(sys.argv[1]) in DATA_SOURCE.parents,DATA_SOURCE
    import json
    json.loads=absent;store.re.compile=absent;store.preflight_hia_json=absent
    store.float=absent
    from hepta.hia_agent_binary64_native import SOURCE as FLOAT_SOURCE
    assert Path(sys.argv[1]) in FLOAT_SOURCE.parents,FLOAT_SOURCE
    print(json.dumps(store.decode_data(sys.stdin.buffer.read()),ensure_ascii=False,sort_keys=True))
elif sys.argv[2] in ('source-build','nominal-json'):
    import importlib.abc,struct,subprocess
    class NoBuildTools(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='tools' or fullname.startswith('tools.'):
                raise AssertionError('installed runtime tried to import checkout build tools')
    sys.meta_path.insert(0,NoBuildTools())
    if sys.argv[2]=='nominal-json':
        from hepta.hia_nominal_json_native import SOURCE,installed_nominal_json
        assert SOURCE==Path(sys.argv[1])/'hepta/_data/examples/hia_bootstrap/nominal_json.hepta'
        image=installed_nominal_json(sys.argv[3])
        import json
        from hepta import hia_instruction_policy_native as old_transport
        old_transport.transport=absent
        json.loads=absent;json.load=absent;json.dumps=absent;json.JSONDecoder.raw_decode=absent
        packet=image.constructor_packet(sys.stdin.buffer.read(),integer_digit_limit=4300)
        sys.stdout.buffer.write(packet)
    else:
        from hepta.hia_agent_contract import SOURCE_BUILD_FILES
        from hepta.artifact_publication_native import _installed_source_custody
        from hepta.hia_json_preflight_native import _source_resource_path
        _,source_pins=_installed_source_custody(Path(sys.argv[1]))
        from hashlib import sha256
        entries=[]
        for name in SOURCE_BUILD_FILES:
            source=_source_resource_path(name)
            assert source==Path(sys.argv[1])/'hepta/_data'/name
            assert source.suffix=='.hepta'
            raw=source.read_bytes();label=source.name.encode('ascii')
            assert sha256(raw).hexdigest()==source_pins[name]
            entries.append(struct.pack('<3Q',len(label),0o400,len(raw))+label+raw)
        wire=struct.pack('<3Q',int.from_bytes(b'HIAREL01','little'),len(entries),0)+b''.join(entries)
        executable=Path(sys.argv[3]);before=executable.read_bytes()
        built=subprocess.run([str(executable),'build'],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        assert built.returncode==0 and not built.stderr,(built.returncode,built.stderr)
        packed=subprocess.run([str(executable),'pack'],input=built.stdout,capture_output=True,env={'PATH':''},timeout=20)
        assert packed.returncode==0 and not packed.stderr,(packed.returncode,packed.stderr)
        assert packed.stdout==before and executable.read_bytes()==before
        _installed_source_custody(Path(sys.argv[1]))
        sys.stdout.buffer.write(packed.stdout)
    assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
elif sys.argv[2]=='source-bindings':
    from importlib import import_module
    from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
    names=[Path(name).stem for name in NATIVE_SOURCE_FILES]
    observed={}
    for name in names:
        if name in BUNDLED_SOURCE_BINDINGS:
            module,key=BUNDLED_SOURCE_BINDINGS[name]
            source=import_module(module).SOURCES[key]
        elif name=='native_mapping':
            source=import_module('hepta.native_mapping_native').SOURCE
        else:
            source=import_module('hepta.hia_'+name+'_native').SOURCE
        assert Path(sys.argv[1]) in source.parents,source
        assert source.is_file(),source
        observed[name]=str(source.relative_to(Path(sys.argv[1])/'hepta/_data'))
    print(__import__('json').dumps(observed,sort_keys=True))
elif sys.argv[2] in ('native-Core','native-Core-whole'):
    import os
    from hepta import hia_program as Core
    from hepta.hia_program_tools import decode_json
    os.environ['HEPTA_HIA_PROGRAM_SHAPE_MANIFEST']=sys.argv[3]
    os.environ['HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST']=sys.argv[4]
    Core._reference_primitive_structure=absent;Core._reference_function_shape=absent
    Core.opcode_spec=absent;Core.check_instruction=absent
    if sys.argv[2]=='native-Core-whole':
        os.environ['HEPTA_HIA_CORE_ADMISSION_MANIFEST']=sys.argv[5]
        Core._verify_function=absent
    checked=Core.verify_program(decode_json(sys.stdin.buffer.read()))
    print(__import__('json').dumps(Core.execute_program(checked,'answer',[])))
elif sys.argv[2]=='slice':
    from hepta import hia_edit_query as editing
    from hepta.hia_agent_slice_native import SOURCE as SLICE_SOURCE
    assert Path(sys.argv[1]) in SLICE_SOURCE.parents,SLICE_SOURCE
    editing._reference_edit_slice=absent;editing._cfg_downstream_slice=absent
    doc=__import__('json').loads(sys.stdin.buffer.read())
    print(__import__('json').dumps(editing.prepare_edit(doc,function='calculate',block='entry',output='y',fields=['op'])))
else:
    # Direct installed-helper controls above keep their explicit selectors.
    # Worker entry receives only the administrator-pinned CLI bundle.
    import os
    for key in tuple(os.environ):
        if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):
            del os.environ[key]
    result=main(['--state-root',sys.argv[2],'--request-json-stdin',*sys.argv[3:]])
    assert not blocked.intersection(sys.modules)
    raise SystemExit(result)
assert not blocked.intersection(sys.modules)
'''
        cls.identity=json.loads(cls.invoke('identity',b'').stdout)
        cls.request=dict(schema='hia-agent-worker-request-v1',tool='hia_describe',arguments={'section':'language'},profile_sha256='a'*64,catalog_sha256=cls.identity['catalog_sha256'])
        cls.request['request_sha256']=sha256(wire(cls.request)).hexdigest()

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    @classmethod
    def invoke(cls,state,request,extra=(),timeout=15):
        if str(state) not in ('identity','printing','publication','artifact-store','data',
                              'source-build','nominal-json','source-bindings',
                              'native-Core','native-Core-whole','slice'):
            extra=(*cls.helper_flags,*extra)
        return subprocess.run([sys.executable,'-I','-S','-B','-c',cls.child,str(cls.installed),str(state),*extra],input=request,capture_output=True,timeout=timeout,cwd=cls.folder,
            env={'PATH':'','LANG':'C','LC_ALL':'C','HEPTA_HIA_AGENT_IDENTITY_MANIFEST':str(cls.manifest),'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(cls.slice_manifest),
                 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST':str(cls.data_manifest),
                 'HEPTA_HIA_AGENT_BINARY64_MANIFEST':str(cls.float_manifest),
                 'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST':str(cls.print_manifest)})

    def publication_case(self,label):
        case=self.folder/label;case.mkdir()
        (case/'stage').write_bytes(b'installed\x00native\xff')
        return case

    def test_installed_source_builder_uses_exact_wheel_inputs_for_native_build_and_pack(self):
        before=self.source_builder.read_bytes()
        result=self.invoke('source-build',b'',(str(self.source_builder),),timeout=60)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stdout,before)
        self.assertEqual(self.source_builder.read_bytes(),before)

    def test_installed_source_builder_refuses_missing_or_changed_package_inputs(self):
        for name in SOURCE_BUILD_FILES:
            source=self.installed/'hepta/_data'/name
            original=source.read_bytes()
            held=source.with_suffix('.held')
            for action in ('missing','changed'):
                with self.subTest(source=name,action=action):
                    if action=='missing':source.rename(held)
                    else:source.write_bytes(original+b'\n')
                    try:
                        result=self.invoke('source-build',b'',(str(self.source_builder),))
                        self.assertNotEqual(result.returncode,0)
                        self.assertEqual(result.stdout,b'')
                    finally:
                        if action=='missing':held.rename(source)
                        else:source.write_bytes(original)

    def test_installed_nominal_packet_has_no_host_payload_parser_or_missing_source_fallback(self):
        from hepta.hia_instruction_policy_native import transport
        raw=b'{"z":[null,true,-0,18446744073709551616],"a":"\\ud83d\\ude00"}'
        expected=transport([json.loads(raw),False])
        result=self.invoke('nominal-json',raw,(str(self.nominal_manifest),))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stdout,expected)
        source=self.installed/'hepta/_data/examples/hia_bootstrap/nominal_json.hepta'
        original=source.read_bytes();held=source.with_suffix('.held')
        for action in ('missing','changed'):
            with self.subTest(action=action):
                if action=='missing':source.rename(held)
                else:source.write_bytes(original+b'\n')
                try:
                    refused=self.invoke('nominal-json',raw,(str(self.nominal_manifest),))
                    self.assertNotEqual(refused.returncode,0)
                    self.assertEqual(refused.stdout,b'')
                finally:
                    if action=='missing':held.rename(source)
                    else:source.write_bytes(original)

    def test_actual_installed_native_publication_and_store_without_tools_or_host_payload_fallback(self):
        for mode in ('publication','artifact-store'):
            case=self.publication_case('installed-'+mode)
            result=self.invoke(mode,b'',(str(self.publication/'build.json'),str(case)))
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout)
            self.assertEqual(value['sha256'],sha256(b'installed\x00native\xff').hexdigest())
            self.assertFalse((case/'published').exists())

    def test_installed_publication_missing_build_assets_refuse_before_filesystem_effects(self):
        for index,name in enumerate(PUBLICATION_BUILD_FILES):
            source=self.installed/'hepta/_data'/name;held=source.with_suffix(source.suffix+'.held')
            source.rename(held)
            try:
                case=self.publication_case('missing-publication-input-'+str(index))
                result=self.invoke('publication',b'',(str(self.publication/'build.json'),str(case)))
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
                self.assertFalse((case/'published').exists())
                self.assertEqual((case/'stage').read_bytes(),b'installed\x00native\xff')
            finally:held.rename(source)

    def test_installed_publication_rejects_tampered_package_contract_code_and_inventory(self):
        manifest=self.publication/'build.json';original_manifest=manifest.read_bytes()
        targets=[self.installed/'hepta/artifact_publication_native.py',
                 self.installed/'hepta/_data/docs/HIA_SELFHOST_CORE_SUPPORT.json',
                 self.publication/'hia-artifact']
        for index,target in enumerate(targets):
            original=target.read_bytes();target.write_bytes(original+b'\n')
            try:
                case=self.publication_case('tampered-publication-'+str(index))
                result=self.invoke('publication',b'',(str(manifest),str(case)))
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
                self.assertFalse((case/'published').exists())
            finally:target.write_bytes(original)
        extra=self.installed/'hepta/unexpected_installed_module.py';extra.write_text('# unbound production module\n')
        try:
            case=self.publication_case('extra-publication-module')
            result=self.invoke('publication',b'',(str(manifest),str(case)))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            self.assertFalse((case/'published').exists())
        finally:extra.unlink()
        record=json.loads(original_manifest);record['source_sha256']['tools/hia_artifact_publication_syscalls.S']='0'*64
        manifest.write_text(json.dumps(record))
        try:
            case=self.publication_case('mismatched-publication-source')
            result=self.invoke('publication',b'',(str(manifest),str(case)))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            self.assertFalse((case/'published').exists())
        finally:manifest.write_bytes(original_manifest)

    def test_installed_binary64_printing_has_no_host_printer_or_checkout_fallback(self):
        result=self.invoke('printing',b'')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'{"large":1e+16,"ratio":1.25,"text":"中","tiny":5e-324,"zero":-0.0}'.encode())
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_binary64_format.hepta'
        held=source.with_suffix('.held');source.rename(held)
        try:
            result=self.invoke('printing',b'')
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        finally:held.rename(source)

    def test_all_native_Source_bindings_are_actual_installed_package_bytes(self):
        result=self.invoke('source-bindings',b'')
        self.assertEqual(result.returncode,0,result.stderr)
        observed=json.loads(result.stdout)
        self.assertEqual(set(observed.values()),set(NATIVE_SOURCE_FILES))
        self.assertEqual(len(observed),len(NATIVE_SOURCE_FILES))
        for name in observed.values():
            self.assertEqual((self.installed/'hepta/_data'/name).read_bytes(),(ROOT/name).read_bytes())

    def test_actual_installed_native_Core_policies_preserve_body_guards_and_missing_source_refusal(self):
        from tests.test_hia_program import b,c,f,m,ret
        doc=m(f('answer',[],['u32'],[],[b('entry',[],[c('v','u32',42)],ret('v'))]))
        doc['schema']='hepta.hia.program.v8'
        manifests=tuple(str(self.core_manifests[key]) for key in ('program_shape','instruction_policy'))
        result=self.invoke('native-Core',wire(doc),manifests)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'],42)
        # Existing body type obligations remain mandatory after native shape.
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u64'
        refused=self.invoke('native-Core',wire(doc),manifests)
        self.assertNotEqual(refused.returncode,0)
        self.assertEqual(refused.stdout,b'')
        self.assertIn(b'E_HIA_TYPE',refused.stderr)
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u32'
        resource=self.installed/'hepta/_data/examples/hia_bootstrap/program_shape.hepta'
        held=resource.with_suffix('.held');resource.rename(held)
        try:
            refused=self.invoke('native-Core',wire(doc),manifests)
            self.assertNotEqual(refused.returncode,0)
            self.assertEqual(refused.stdout,b'')
        finally:held.rename(resource)

    def test_actual_installed_whole_native_Core_preserves_body_guards_and_missing_source_refusal(self):
        from tests.test_hia_program import b,c,f,m,ret
        doc=m(f('answer',[],['u32'],[],[b('entry',[],[c('v','u32',42)],ret('v'))]))
        doc['schema']='hepta.hia.program.v8'
        manifests=tuple(str(self.core_manifests[key]) for key in ('program_shape','instruction_policy','core_admission'))
        result=self.invoke('native-Core-whole',wire(doc),manifests)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'],42)
        # Existing body type obligations remain mandatory inside the selected native whole-body kernel.
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u64'
        refused=self.invoke('native-Core-whole',wire(doc),manifests)
        self.assertNotEqual(refused.returncode,0)
        self.assertEqual(refused.stdout,b'')
        self.assertIn(b'E_HIA_TYPE',refused.stderr)
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u32'
        resource=self.installed/'hepta/_data/examples/hia_bootstrap/core_admission.hepta'
        held=resource.with_suffix('.held');resource.rename(held)
        try:
            refused=self.invoke('native-Core-whole',wire(doc),manifests)
            self.assertNotEqual(refused.returncode,0)
            self.assertEqual(refused.stdout,b'')
        finally:held.rename(resource)

    def test_installed_binary64_source_has_no_decimal_converter_or_checkout_fallback(self):
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_binary64.hepta'
        held=source.with_suffix('.held');source.rename(held)
        try:
            result=self.invoke('data',b'1.25e-3')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
        finally:held.rename(source)

    def test_installed_data_decoder_has_no_payload_parser_or_source_fallback(self):
        wire=b'{"ratio":1.25e-3,"negative_zero":-0.0,"n":18446744073709551616}'
        result=self.invoke('data',wire)
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertEqual(value['ratio'],0.00125)
        self.assertEqual(value['negative_zero'].hex(),'-0x0.0p+0')
        self.assertEqual(value['n'],18446744073709551616)
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_data_json.hepta'
        held=source.with_suffix('.held');source.rename(held)
        try:
            rejected=self.invoke('data',wire)
            self.assertNotEqual(rejected.returncode,0)
        finally:held.rename(source)

    def test_wheel_resources_are_exact_and_worker_identity_matches_source(self):
        with zipfile.ZipFile(self.wheel) as z:
            bundled={name.removeprefix('hepta/_data/') for name in z.namelist()
                     if name.startswith('hepta/_data/') and not name.endswith('/')}
            self.assertEqual(bundled,set(RESOURCES)|set(EXECUTABLE_CAPTURE_RESOURCES)|set(VM_INTEGER_DIVREM_RESOURCES)|set(VM_INTEGER_ARITHMETIC_RESOURCES)|set(VM_INTEGER_SCALAR_RESOURCES))
            for name in (*RESOURCES,*EXECUTABLE_CAPTURE_RESOURCES,*VM_INTEGER_DIVREM_RESOURCES,*VM_INTEGER_ARITHMETIC_RESOURCES,*VM_INTEGER_SCALAR_RESOURCES):
                self.assertEqual(z.read('hepta/_data/'+name),(ROOT/name).read_bytes())
                self.assertEqual((self.installed/'hepta/_data'/name).read_bytes(),(ROOT/name).read_bytes())
            for name in SDIST_SUPPORT_FILES:
                if name in WHEEL_PACKAGE_FILES:
                    self.assertEqual(z.read(name),(ROOT/name).read_bytes())
                    self.assertEqual((self.installed/name).read_bytes(),(ROOT/name).read_bytes())
                else:
                    self.assertNotIn(name,z.namelist())
                    self.assertFalse((self.installed/name).exists())
        self.assertEqual(self.identity,installation_manifest())

    def test_real_installed_native_worker_without_checkout_or_reference_predicates(self):
        state=self.folder/'valid';r=self.invoke(state,wire(self.request))
        self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(r.stderr,b'')
        report=json.loads(r.stdout)
        self.assertEqual(report['native_helpers_sha256'],self.helpers_sha256)
        self.assertEqual(report['response']['status'],'completed');self.assertTrue(state.is_dir())

    def test_real_installed_edit_query_without_reference_graph_algorithms(self):
        from tests.test_hia_edit_query import fixture
        from hepta.hia_edit_query import prepare_edit
        doc=fixture();expected=prepare_edit(doc,function='calculate',block='entry',output='y',fields=['op'])
        result=self.invoke('slice',wire(doc))
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr,b'');self.assertEqual(json.loads(result.stdout),expected)

    def test_missing_slice_source_refuses_before_state_without_checkout_fallback(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_slice.hepta';hold=p.with_suffix('.held');p.rename(hold)
        try:
            state=self.folder/'missing-slice';result=self.invoke(state,wire(self.request))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)

    def test_missing_native_source_fails_before_service_no_source_fallback(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_identity.hepta';hold=p.with_suffix('.held');p.rename(hold)
        try:
            state=self.folder/'missing';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)

    def test_tampered_native_source_fails_before_service(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_identity.hepta';raw=p.read_bytes();p.write_bytes(raw+b'\n')
        try:
            state=self.folder/'tampered';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
            self.assertIn(b'source identity mismatch',r.stderr)
        finally:p.write_bytes(raw)

    def test_tampered_discovery_doc_invalidates_worker_pin_before_state(self):
        p=self.installed/'hepta/_data/docs/HIA_PROGRAM.md';raw=p.read_bytes();p.write_bytes(raw+b'\n')
        try:
            state=self.folder/'stale';r=self.invoke(state,wire(self.request),('--expected-worker-sha256',self.identity['worker_sha256']))
            self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
            self.assertIn(b'administrator source pin differs',r.stderr)
        finally:p.write_bytes(raw)

    def test_missing_entire_installed_resource_root_has_no_cwd_fallback(self):
        p=self.installed/'hepta/_data';hold=p.with_name('_data-held');p.rename(hold)
        try:
            state=self.folder/'no-data';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)
