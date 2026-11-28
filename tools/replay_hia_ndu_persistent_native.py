#!/usr/bin/env python3
"""Independent standard-library replay for the source-owned HIA NDU profile.

The fixed Rust reader remains unchanged. This explicit successor preserves its
complete 72-cell frame, cleanup, scalar and cost checks, while binding the exact
native receipt, HIA entry point, native hello and full actual source inventory.
It does not execute NDU or attest clocks, machine refinement or economics.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import itertools
import json
from pathlib import Path
import re
import statistics

ARMS = ("prepared_ndu", "persistent_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
PROFILE = "hepta.hia.ndu-ranking-persistent-framed.v1"
FIXED_SOURCE = set([
    "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json",
    "docs/HIA_NATIVE_NDU_EVALUATOR_QUALIFICATION.json",
    "docs/HIA_NATIVE_NDU_EVALUATOR_RECIPE.json",
    "docs/HIA_NATIVE_NDU_RANK_BUILD.json",
    "examples/hia_bootstrap/agent_binary64.hepta",
    "examples/hia_bootstrap/agent_binary64_format.hepta",
    "examples/hia_bootstrap/background_optimizer_freeze.hepta",
    "examples/hia_bootstrap/background_optimizer_json_capture.hepta",
    "examples/hia_bootstrap/background_optimizer_structure.hepta",
    "examples/hia_bootstrap/bounded_unroll_interface.hepta",
    "examples/hia_bootstrap/bounded_unroll_receipt.hepta",
    "examples/hia_bootstrap/bounded_unroll_solver.hepta",
    "examples/hia_bootstrap/bounded_unroll_transform.hepta",
    "examples/hia_bootstrap/bounded_unroll_workflow.hepta",
    "examples/hia_bootstrap/cnf.hepta",
    "examples/hia_bootstrap/core_admission.hepta",
    "examples/hia_bootstrap/evaluate_reference_wire.hepta",
    "examples/hia_bootstrap/general_call_cnf.hepta",
    "examples/hia_bootstrap/general_cnf.hepta",
    "examples/hia_bootstrap/json_canonical.hepta",
    "examples/hia_bootstrap/multiversion_background_payload.hepta",
    "examples/hia_bootstrap/multiversion_prepare_process.hepta",
    "examples/hia_bootstrap/multiversion_proof_graph.hepta",
    "examples/hia_bootstrap/native_call_closure_graph.hepta",
    "examples/hia_bootstrap/native_call_graph_linker.hepta",
    "examples/hia_bootstrap/native_call_proof_packer.hepta",
    "examples/hia_bootstrap/native_call_proof_policy.hepta",
    "examples/hia_bootstrap/native_filter_packer.hepta",
    "examples/hia_bootstrap/native_path_resolve.hepta",
    "examples/hia_bootstrap/native_public_call_proof_receipt.hepta",
    "examples/hia_bootstrap/native_public_proof_json.hepta",
    "examples/hia_bootstrap/native_public_proof_receipt.hepta",
    "examples/hia_bootstrap/native_scalar_proof_hash.hepta",
    "examples/hia_bootstrap/native_scalar_proof_packer.hepta",
    "examples/hia_bootstrap/native_scalar_proof_policy.hepta",
    "examples/hia_bootstrap/ndu_evaluator.hepta",
    "examples/hia_bootstrap/ndu_evaluator_debug.hepta",
    "examples/hia_bootstrap/ndu_evaluator_number.hepta",
    "examples/hia_bootstrap/ndu_evaluator_packer.hepta",
    "examples/hia_bootstrap/ndu_evaluator_transport.hepta",
    "examples/hia_bootstrap/ndu_evaluator_unicode.hiadat",
    "examples/hia_bootstrap/ndu_rank_admission.hepta",
    "examples/hia_bootstrap/ndu_rank_binding.hepta",
    "examples/hia_bootstrap/ndu_rank_canonical.hepta",
    "examples/hia_bootstrap/ndu_rank_clock_budget.hepta",
    "examples/hia_bootstrap/ndu_rank_context_payload_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_context_records.hepta",
    "examples/hia_bootstrap/ndu_rank_context_records_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_cost.hepta",
    "examples/hia_bootstrap/ndu_rank_engine_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_json.hepta",
    "examples/hia_bootstrap/ndu_rank_main.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_error.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_error_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_identity.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_json.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_native_owner_pump.hepta",
    "examples/hia_bootstrap/ndu_rank_process_current.hepta",
    "examples/hia_bootstrap/ndu_rank_proof_facade.hepta",
    "examples/hia_bootstrap/ndu_rank_proof_facade_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_report.hepta",
    "examples/hia_bootstrap/ndu_rank_selection.hepta",
    "examples/hia_bootstrap/ndu_rank_sha_stream_private.hepta",
    "examples/hia_bootstrap/ndu_rank_snapshot.hepta",
    "examples/hia_bootstrap/ndu_rank_source_kit_packer.hepta",
    "examples/hia_bootstrap/ndu_rank_tasks_current.hepta",
    "examples/hia_bootstrap/ndu_rank_threshold_00.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_01.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_02.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_03.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_04.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_05.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_06.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_07.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_08.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_09.hiadat",
    "examples/hia_bootstrap/ndu_rank_threshold_10.hiadat",
    "examples/hia_bootstrap/ndu_rank_unchanged.hepta",
    "examples/hia_bootstrap/public_proof_typed.hepta",
    "examples/hia_bootstrap/public_proof_values.hepta",
    "examples/hia_bootstrap/scalar_reference.hepta",
    "examples/hia_bootstrap/selfhost.hepta",
    "examples/hia_bootstrap/sha256_stream.hepta",
    "examples/hia_bootstrap/source_build_packer.hepta",
    "examples/hia_bootstrap/source_ndu_rank_pack.hepta",
    "examples/hia_bootstrap/source_ndu_rank_release_kit.hepta",
    "examples/hia_bootstrap/source_release_kit.hepta",
    "hepta/__init__.py",
    "hepta/__main__.py",
    "hepta/artifact_publication.py",
    "hepta/artifact_publication_native.py",
    "hepta/clang_capture.py",
    "hepta/cli.py",
    "hepta/darwin_capture.py",
    "hepta/elf_shared_abi.py",
    "hepta/hia_aarch64_elf.py",
    "hepta/hia_adaptive.py",
    "hepta/hia_agent_artifact_capture_native.py",
    "hepta/hia_agent_assembly.py",
    "hepta/hia_agent_binary64_format_native.py",
    "hepta/hia_agent_binary64_native.py",
    "hepta/hia_agent_buffers.py",
    "hepta/hia_agent_candidate_native.py",
    "hepta/hia_agent_contract.py",
    "hepta/hia_agent_data_json_native.py",
    "hepta/hia_agent_describe_answer_native.py",
    "hepta/hia_agent_discovery_native.py",
    "hepta/hia_agent_edit_query_native.py",
    "hepta/hia_agent_exec.py",
    "hepta/hia_agent_identity_native.py",
    "hepta/hia_agent_inspection_native.py",
    "hepta/hia_agent_journal_native.py",
    "hepta/hia_agent_json_wire_native.py",
    "hepta/hia_agent_macro_discovery.py",
    "hepta/hia_agent_macro_policy.py",
    "hepta/hia_agent_native_metadata_native.py",
    "hepta/hia_agent_payload_schema_native.py",
    "hepta/hia_agent_plan_schema_native.py",
    "hepta/hia_agent_query_native.py",
    "hepta/hia_agent_read_page_native.py",
    "hepta/hia_agent_read_request_native.py",
    "hepta/hia_agent_response_schema_native.py",
    "hepta/hia_agent_runner.py",
    "hepta/hia_agent_schema_native.py",
    "hepta/hia_agent_service.py",
    "hepta/hia_agent_slice_native.py",
    "hepta/hia_agent_snapshot_json_native.py",
    "hepta/hia_agent_snapshot_native.py",
    "hepta/hia_agent_store.py",
    "hepta/hia_agent_store_native.py",
    "hepta/hia_agent_store_transport_native.py",
    "hepta/hia_agent_verify_response_schema_native.py",
    "hepta/hia_agent_worker.py",
    "hepta/hia_artifact_delivery.py",
    "hepta/hia_artifact_delivery_protocol.py",
    "hepta/hia_artifact_delivery_worker.py",
    "hepta/hia_artifact_page_native.py",
    "hepta/hia_artifact_page_policy_native.py",
    "hepta/hia_artifact_page_worker_bundle.py",
    "hepta/hia_artifact_session.py",
    "hepta/hia_background_optimizer.py",
    "hepta/hia_behavior_inputs.py",
    "hepta/hia_bounded_memory.py",
    "hepta/hia_bounded_memory_native.py",
    "hepta/hia_bounded_read_native.py",
    "hepta/hia_bounded_unroll.py",
    "hepta/hia_bounded_wire.py",
    "hepta/hia_budget_resource_custody.py",
    "hepta/hia_byte_sum.py",
    "hepta/hia_byte_wrapper_native.py",
    "hepta/hia_byte_wrapper_selection.py",
    "hepta/hia_call_expansion.py",
    "hepta/hia_candidate_budget_native.py",
    "hepta/hia_capability_flow.py",
    "hepta/hia_capability_renaming_native.py",
    "hepta/hia_capture_descriptor_effects.py",
    "hepta/hia_cli_discovery_json_native.py",
    "hepta/hia_cli_discovery_selection.py",
    "hepta/hia_cli_inspect_native.py",
    "hepta/hia_cli_native.py",
    "hepta/hia_cnf_native.py",
    "hepta/hia_composite_constructor_errors.py",
    "hepta/hia_composite_constructor_native.py",
    "hepta/hia_composite_function_tokens.py",
    "hepta/hia_composite_functions_errors.py",
    "hepta/hia_composite_functions_native.py",
    "hepta/hia_composite_outer_native.py",
    "hepta/hia_composite_types_native.py",
    "hepta/hia_continuation.py",
    "hepta/hia_core_admission_native.py",
    "hepta/hia_core_api.py",
    "hepta/hia_core_companion_worker_bundle.py",
    "hepta/hia_core_compare_native.py",
    "hepta/hia_core_compare_selection.py",
    "hepta/hia_core_diagnostic_protocol.py",
    "hepta/hia_core_emitter_native.py",
    "hepta/hia_core_emitter_selection.py",
    "hepta/hia_core_integer_native.py",
    "hepta/hia_core_integer_selection.py",
    "hepta/hia_core_json_bytes_native.py",
    "hepta/hia_core_json_frontend_native.py",
    "hepta/hia_core_lowering_native.py",
    "hepta/hia_core_lowering_selection.py",
    "hepta/hia_core_module_graph_native.py",
    "hepta/hia_core_patch_native.py",
    "hepta/hia_core_proof_wire_native.py",
    "hepta/hia_core_unpack_native.py",
    "hepta/hia_core_unpack_selection.py",
    "hepta/hia_core_upgrade.py",
    "hepta/hia_core_workspace_facts_native.py",
    "hepta/hia_core_workspace_json_native.py",
    "hepta/hia_core_workspace_materialize_native.py",
    "hepta/hia_cost_ledger_native.py",
    "hepta/hia_crc_kernel.py",
    "hepta/hia_crc_linear.py",
    "hepta/hia_default_native.py",
    "hepta/hia_default_native_pin.py",
    "hepta/hia_durable_queue.py",
    "hepta/hia_economic_search.py",
    "hepta/hia_edit_batch.py",
    "hepta/hia_edit_query.py",
    "hepta/hia_elf_shared_linker_native.py",
    "hepta/hia_elf_verified_linker_native.py",
    "hepta/hia_emission_native.py",
    "hepta/hia_emission_protocol.py",
    "hepta/hia_entry_layout.py",
    "hepta/hia_evaluate_reference_wire_native.py",
    "hepta/hia_evaluation_native.py",
    "hepta/hia_evaluation_protocol.py",
    "hepta/hia_executable_capture.py",
    "hepta/hia_execution_budget.py",
    "hepta/hia_execution_budget_native.py",
    "hepta/hia_execution_ledger_native.py",
    "hepta/hia_execution_observation_native.py",
    "hepta/hia_execution_observation_selection.py",
    "hepta/hia_finite_actions.py",
    "hepta/hia_finite_context.py",
    "hepta/hia_full_cost_gate.py",
    "hepta/hia_full_cost_native.py",
    "hepta/hia_function_shape_native.py",
    "hepta/hia_generation_retention_native.py",
    "hepta/hia_guarded_batch.py",
    "hepta/hia_guarded_optimization.py",
    "hepta/hia_heap_bound.py",
    "hepta/hia_host_import.py",
    "hepta/hia_host_region.py",
    "hepta/hia_incremental.py",
    "hepta/hia_inductive.py",
    "hepta/hia_initialization.py",
    "hepta/hia_instruction_policy_native.py",
    "hepta/hia_invocation_bank.py",
    "hepta/hia_json_canonical_native.py",
    "hepta/hia_json_decode.py",
    "hepta/hia_json_decode_native.py",
    "hepta/hia_json_preflight.py",
    "hepta/hia_json_preflight_native.py",
    "hepta/hia_json_pretty_native.py",
    "hepta/hia_json_wire_native.py",
    "hepta/hia_linux_kernel.py",
    "hepta/hia_loaded_source.py",
    "hepta/hia_machine_elf.py",
    "hepta/hia_machine_encoding_native.py",
    "hepta/hia_machine_instructions_native.py",
    "hepta/hia_machine_object_native.py",
    "hepta/hia_machine_object_selection.py",
    "hepta/hia_machine_plan.py",
    "hepta/hia_machine_plan_native.py",
    "hepta/hia_machine_state_native.py",
    "hepta/hia_machine_x64.py",
    "hepta/hia_machine_x64_kernel.py",
    "hepta/hia_mechanical_worker_bundle.py",
    "hepta/hia_multiversion.py",
    "hepta/hia_narrowing.py",
    "hepta/hia_native_admission_io.py",
    "hepta/hia_native_build_admission_native.py",
    "hepta/hia_native_build_admission_protocol.py",
    "hepta/hia_native_byte_abi.py",
    "hepta/hia_native_byte_runner.py",
    "hepta/hia_native_continuation.py",
    "hepta/hia_native_continuation_inprocess.py",
    "hepta/hia_native_continuation_selection.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_native_differential.py",
    "hepta/hia_native_helpers.py",
    "hepta/hia_native_host_support.py",
    "hepta/hia_native_paired_replay.py",
    "hepta/hia_native_retirement.py",
    "hepta/hia_ndu.py",
    "hepta/hia_ndu_cache.py",
    "hepta/hia_ndu_cost.py",
    "hepta/hia_ndu_dynamic.py",
    "hepta/hia_ndu_evaluator_native.py",
    "hepta/hia_ndu_module_costs.py",
    "hepta/hia_ndu_native_policy.py",
    "hepta/hia_ndu_optimizer.py",
    "hepta/hia_ndu_persistent_ranker.py",
    "hepta/hia_ndu_policy.py",
    "hepta/hia_ndu_prepared_ranker.py",
    "hepta/hia_ndu_rank_native.py",
    "hepta/hia_ndu_raw_model.py",
    "hepta/hia_ndu_raw_session.py",
    "hepta/hia_ndu_response.py",
    "hepta/hia_ndu_scalar_selection.py",
    "hepta/hia_ndu_session.py",
    "hepta/hia_ndu_stateful.py",
    "hepta/hia_nominal_json_native.py",
    "hepta/hia_nominal_program_native.py",
    "hepta/hia_nominal_tokens_native.py",
    "hepta/hia_opcodes.py",
    "hepta/hia_optimization.py",
    "hepta/hia_optimization_contract.py",
    "hepta/hia_oracle.py",
    "hepta/hia_paired_holdout.py",
    "hepta/hia_patch_impact.py",
    "hepta/hia_patch_impact_native.py",
    "hepta/hia_planning.py",
    "hepta/hia_prepared.py",
    "hepta/hia_program.py",
    "hepta/hia_program_aarch64.py",
    "hepta/hia_program_composite.py",
    "hepta/hia_program_llvm.py",
    "hepta/hia_program_native.py",
    "hepta/hia_program_runtime.py",
    "hepta/hia_program_runtime_arithmetic.py",
    "hepta/hia_program_runtime_batch.py",
    "hepta/hia_program_runtime_prepared.py",
    "hepta/hia_program_selfhost.py",
    "hepta/hia_program_shape_native.py",
    "hepta/hia_program_tools.py",
    "hepta/hia_proof_contract.py",
    "hepta/hia_publication_measurement_native.py",
    "hepta/hia_queue_commit.py",
    "hepta/hia_reduction.py",
    "hepta/hia_reference_runtime_sources.py",
    "hepta/hia_result_cache.py",
    "hepta/hia_retirement_effects.py",
    "hepta/hia_retirement_state_native.py",
    "hepta/hia_routes.py",
    "hepta/hia_rust_byte_cleanup.py",
    "hepta/hia_rust_byte_dag.py",
    "hepta/hia_rust_crosscheck.py",
    "hepta/hia_safe_core.py",
    "hepta/hia_safe_core_binder_native.py",
    "hepta/hia_safe_core_elf.py",
    "hepta/hia_safe_core_elf_inventory_native.py",
    "hepta/hia_safe_core_x64.py",
    "hepta/hia_safe_core_x64_decode_native.py",
    "hepta/hia_scalar_call_validation.py",
    "hepta/hia_scalar_lowering_check.py",
    "hepta/hia_scalar_profile_native.py",
    "hepta/hia_scalar_proof_contract.py",
    "hepta/hia_scalar_reference_native.py",
    "hepta/hia_scalar_reference_wire.py",
    "hepta/hia_scalar_state.py",
    "hepta/hia_scalar_symbolic_native.py",
    "hepta/hia_scalar_totality.py",
    "hepta/hia_schema.py",
    "hepta/hia_service_artifact_native.py",
    "hepta/hia_service_artifact_protocol.py",
    "hepta/hia_service_bootstrap_native.py",
    "hepta/hia_service_bootstrap_protocol.py",
    "hepta/hia_service_context_native.py",
    "hepta/hia_service_context_selection.py",
    "hepta/hia_service_discovery_native.py",
    "hepta/hia_service_discovery_protocol.py",
    "hepta/hia_service_inspection_native.py",
    "hepta/hia_service_inspection_protocol.py",
    "hepta/hia_service_lease_native.py",
    "hepta/hia_service_lease_protocol.py",
    "hepta/hia_service_read_native.py",
    "hepta/hia_service_read_protocol.py",
    "hepta/hia_service_slot_native.py",
    "hepta/hia_service_slot_protocol.py",
    "hepta/hia_service_verification_native.py",
    "hepta/hia_service_verification_protocol.py",
    "hepta/hia_sha256_native.py",
    "hepta/hia_sha256_stream_native.py",
    "hepta/hia_slot_continuations.py",
    "hepta/hia_slot_ledger_native.py",
    "hepta/hia_slot_mechanical.py",
    "hepta/hia_slot_operation_series.py",
    "hepta/hia_slot_operations_native.py",
    "hepta/hia_slot_operations_protocol.py",
    "hepta/hia_slot_operations_selection.py",
    "hepta/hia_solver_identity.py",
    "hepta/hia_specialization.py",
    "hepta/hia_stateful.py",
    "hepta/hia_static_budget.py",
    "hepta/hia_static_budget_native.py",
    "hepta/hia_store_artifact_profile_native.py",
    "hepta/hia_store_artifact_profile_protocol.py",
    "hepta/hia_store_file_capture_native.py",
    "hepta/hia_store_file_capture_protocol.py",
    "hepta/hia_store_lifecycle_native.py",
    "hepta/hia_store_lifecycle_selection.py",
    "hepta/hia_store_transaction_native.py",
    "hepta/hia_store_transaction_protocol.py",
    "hepta/hia_swap_opt.py",
    "hepta/hia_task_helpers_native.py",
    "hepta/hia_translation_validation.py",
    "hepta/hia_verified_cpu.py",
    "hepta/hia_verified_image.py",
    "hepta/hia_verified_input_identity.py",
    "hepta/hia_verified_kernel.py",
    "hepta/hia_verified_kernel_load.py",
    "hepta/hia_verified_scalar.py",
    "hepta/hia_verified_simd.py",
    "hepta/hia_verified_simd_check.py",
    "hepta/hia_verified_simd_wide.py",
    "hepta/hia_verified_simd_wide_x64.py",
    "hepta/hia_vm_integer_divrem_native.py",
    "hepta/hia_vm_integer_divrem_protocol.py",
    "hepta/hia_vm_integer_divrem_runtime.py",
    "hepta/hia_worker_bundle.py",
    "hepta/hia_worker_inspection_request_native.py",
    "hepta/hia_worker_report_native.py",
    "hepta/hia_worker_request_native.py",
    "hepta/hia_worker_scheduling_bundle.py",
    "hepta/hia_worker_store_profile.py",
    "hepta/hia_x86_kernel_descriptor.py",
    "hepta/hia_x86_search.py",
    "hepta/native/slot_mechanical_build.py",
    "hepta/native_mapping_identity.py",
    "hepta/native_mapping_native.py",
    "hepta/native_tool_identity.py",
    "hepta/object_structure.py",
    "hepta/object_symbols.py",
    "hepta/windows_capture.py",
    "tests/test_hia_ndu_persistent_ranker.py",
    "tools/hia_ndu_evaluator_join.S",
    "tools/hia_ndu_evaluator_syscalls.S",
    "tools/qualify_hia_ndu_persistent_native.py",
    "tools/qualify_hia_ndu_persistent_ranker.py",
    "tools/qualify_hia_ndu_prepared_ranker.py",
    "tools/replay_hia_ndu_persistent_native.py",
    "tools/replay_hia_ndu_persistent_ranker.py"
])
EXPECTED_PRODUCER_SHA256 = "9833142fbbacbd81061eb7c077a05de877013a2af0a261000b4907eccb7eba75"
OWNED_RUNTIME_PINS = {'hepta/hia_ndu_optimizer.py': 'a8cf6b21015f591a34f6a733a5e6f3def6db3a48b940f057fc8c9a7b7f237c0d', 'hepta/hia_ndu_prepared_ranker.py': '0f65fee29e09712388cf969a00189ef0bfe20be69b8801e38db759ecd4e8401f', 'hepta/hia_ndu_persistent_ranker.py': '19b1d1b632c86acffaa130888de6b73aa9943d4b0c78de21360a60b03db85ae5', 'hepta/hia_ndu_scalar_selection.py': '280e287cde21fec7e49f38c07ada2f9f15a9b3c7fd8038432951abbf4b95f101', 'hepta/hia_ndu_evaluator_native.py': '6483c3aa93e32e0e04673688b92f963f8fef93567f7b24f01a3d0f34ebc75d00', 'hepta/hia_ndu_native_policy.py': '5102db32159d6383dee34135a25418dfee0511b84bd480d286e450895f616d2a', 'hepta/hia_ndu_rank_native.py': 'be745c4ef401f78674a2ab1453ab8385595b5ca64138f7c5faad0261c3c623f5', 'hepta/hia_rust_crosscheck.py': '9125fe4136d9e4c3120f364e13e6a158661d8799a5107773e3a256f123c93884', 'tools/qualify_hia_ndu_prepared_ranker.py': '0d37f42553c98219b7cf72cc27869afa9322aec84f9c41d52187353f284db2fa', 'tests/test_hia_ndu_persistent_ranker.py': '826bad4e9c5a45f8d5b1e56958708430c25356f96a873a29b15e9ea89e7d3ee1'}
_SELF = Path(__file__).read_bytes()
BUILD_SHA256 = "9d04ec9fab8a0f0ce2d467a951793fc92a890baae8cae985ab9cbfe7476b89a2"



def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_NDU_PERSISTENT_REPLAY: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def integer(value, *, positive=False):
    require(type(value) is int and value >= (1 if positive else 0), "invalid observed integer")
    return value


def raw_bytes(value):
    require(type(value) is dict and set(value) == {"encoding", "bytes", "sha256", "data"},
            "original byte record shape")
    require(value["encoding"] == "base64" and len(value["data"]) <= 2 * 1024 * 1024,
            "original byte record bound")
    integer(value["bytes"])
    raw = base64.b64decode(value["data"], validate=True)
    require(len(raw) == value["bytes"] and sha256(raw).hexdigest() == value["sha256"],
            "original byte record hash/length")
    return raw


def summary(value):
    result = {}
    for key, item in value.items():
        if type(item) is dict and item.get("encoding") == "base64":
            raw = raw_bytes(item)
            result[key] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        else:
            result[key] = item
    return result


def decode_frame(raw, sequence, session):
    require(len(raw) >= 73 and len(raw) <= 1024 * 1024 + 72,
            "frame memory bound")
    require(int.from_bytes(raw[:4], "big") == len(raw) - 4,
            "complete length-prefixed frame")
    require(int.from_bytes(raw[4:8], "big") == sequence
            and raw[8:72] == session.encode("ascii"), "frame session/sequence")
    return raw[72:]


def choose(request):
    feasible = [row for row in request["candidates"] if row["hard_violation"] is False
                and row["resource_q32"] <= request["resource_cap_q32"]]
    minimum = min(row["cost_q32"] for row in feasible)
    frontier = sorted(row["id"] for row in feasible if row["cost_q32"] == minimum)
    return ("abstain" if "abstain" in frontier else frontier[0]), frontier, len(feasible)


def verify_response(raw, result, request, identity):
    response = json.loads(raw)
    require(type(response["generation"]) is int, "native generation integer type")
    selected, frontier, feasible_count = choose(request)
    require(response == result["native_response"]
            and response["schema"] == "hepta.hia.ndu-native-response.v1"
            and response["request_sha256"] == sha256(wire(request)).hexdigest()
            and response["objective_sha256"] == request["objective_sha256"]
            and response["generation"] == request["generation"]
            and response["upstream_commit"] == identity["upstream_commit"]
            and response["entry_point"] == "hepta.hia.ndu_evaluator.v1"
            and response["reference_entry_point"] == "codex_hepta_ndu::evaluate_candidates_with_policy"
            and response["pareto_frontier"] == frontier
            and response["authority"] == "ADVISORY_ONLY"
            and response["proves_program_safety"] is False
            and response["global_optimality_established"] is False, "native response binding or scope")
    for key in ("evaluation_digest_v2", "evaluation_policy_digest", "utility_profile_digest"):
        require(type(response[key]) is str and re.fullmatch("[0-9a-f]{64}", response[key]), "native digest")
    expected_advice = "abstain" if feasible_count == 1 else frontier[0] if len(frontier) == 1 else None
    require(response["advisory_recommendation"] == expected_advice
            and result["selection"]["selected_id"] == selected, "native/caller tie rule")
    require(all(result["native_identity"][key] == value for key, value in identity.items()),
            "returned native image identity")


def expected_analysis(cells):
    values = []
    for horizon in HORIZONS:
        pairs = []
        for pair in range(1, 7):
            rows = {row["arm"]: row for row in cells if row["horizon"] == horizon and row["pair"] == pair}
            cost = {arm: rows[arm]["wall_ns"] for arm in ARMS}
            pairs.append({"pair": pair, "complete": True, "all_attempt_arm_wall_ns": cost,
                          "prepared_minus_persistent_ns": cost["prepared_ndu"] - cost["persistent_ndu"],
                          "ordinary_minus_persistent_ns": cost["ordinary_scalar"] - cost["persistent_ndu"]})
        differences = [row["prepared_minus_persistent_ns"] for row in pairs]
        values.append({"horizon": horizon, "all_registered_cells_completed": True, "pairs": pairs,
                       "persistent_saving_summary_ns": {
                           "observations": 6, "sum": sum(differences), "mean": statistics.mean(differences),
                           "median": statistics.median(differences), "min": min(differences),
                           "max": max(differences), "sample_stdev": statistics.stdev(differences),
                           "positive_pairs": sum(value > 0 for value in differences)}})
    return values


def check_cost_intervals(cells, report):
    """Check the serial campaign's measured intervals as nested bounds.

    Both owners are created before the cell's calls and closed afterwards.
    Bookkeeping occupies unclassified outer time; nested timers must not be
    added to the campaign again or escape their enclosing call/cell interval.
    """
    campaign = integer(report["actual_campaign_wall_ns_to_summary"], positive=True)
    require(report["nested_cell_wall_added_again"] is False,
            "campaign timer must not add nested cell costs again")
    cell_total = 0
    for cell in cells:
        cell_wall = integer(cell["wall_ns"], positive=True)
        cell_total += cell_wall
        call_walls = [integer(row["wall_ns"], positive=True) for row in cell["calls"]]
        require(sum(call_walls) <= cell_wall,
                "serial call intervals exceed their enclosing cell")
        if cell["arm"] != "ordinary_scalar":
            cost = cell["owner_cost"]
            require(len(cost["attempts"]) == len(call_walls),
                    "owner attempts differ from recorded calls")
            preparation = (cost["preparation_wall_ns"] if cell["arm"] == "persistent_ndu"
                           else cost["preparation"]["preparation_wall_ns"])
            serial_cost = integer(preparation, positive=True) + integer(cost["close_wall_ns"], positive=True)
            for attempt, call_wall in zip(cost["attempts"], call_walls):
                service = integer(attempt["wall_ns"], positive=True)
                queued = integer(attempt["queue_wait_ns"])
                caller = integer(attempt["caller_wall_ns"], positive=True)
                require(caller == service + queued and caller <= call_wall,
                        "owner caller interval or queue differs from enclosing call")
                serial_cost += caller
            require(serial_cost <= cell_wall,
                    "owner serial intervals exceed their enclosing cell")
    require(cell_total <= campaign,
            "serial cell intervals exceed the measured campaign")



def checked_build(raw, identity):
    require(type(raw) is bytes and sha256(raw).hexdigest() == BUILD_SHA256,
            "fixed whole native construction receipt")
    value = json.loads(raw)
    require(type(identity) is dict and identity == {
        "upstream_commit": value["upstream_commit"],
        "binary_sha256": value["binary_sha256"],
        "build_receipt_sha256": BUILD_SHA256,
        "build_inputs_sha256": value["build_inputs_sha256"],
        "source_attestation": "exact_source_owned_hia_native_evaluator",
        "implementation": "HIA",
        "response_schema": "hepta.hia.ndu-native-response.v1",
        "entry_point": "hepta.hia.ndu_evaluator.v1",
        "reference_entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy"},
        "source-owned native image identity")
    require(value["schema"] == "hepta.hia.ndu-native-build.v1" and
            value["native_runtime_only"] is True and
            sha256(wire(value["build_inputs"])).hexdigest() == value["build_inputs_sha256"],
            "native build inputs and scope")
    return value

def replay(directory, registration_sha256):
    captures = {}

    def _file_identity(path):
        st = path.stat()
        return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def take(path):
        path = Path(path).absolute()
        require(path.resolve() == path and (not path.is_symlink()), 'physical input path')
        before = _file_identity(path)
        raw = path.read_bytes()
        after = _file_identity(path)
        require(before == after and len(raw) == after[3], 'input changed while captured')
        if path in captures:
            require(captures[path] == (raw, after), 'input changed between reads')
        captures[path] = (raw, after)
        return raw
    require(take(Path(__file__)) == _SELF, 'executed reader changed since import')
    try:
        root = Path(directory)
        reg_raw = take(root / 'registration.json')
        require(sha256(reg_raw).hexdigest() == registration_sha256, 'explicit registration digest')
        reg = json.loads(reg_raw)
        report = json.loads(take(root / 'result.json'))
        expected_source = FIXED_SOURCE | {str(path.relative_to(root / 'frozen-source')) for path in (root / 'frozen-source/hepta').rglob('*.py') if path.is_file() and '_data' not in path.parts}
        require(set(reg['source_files']) == expected_source and reg['source_domain'] == 'native_package_required_418_plus_current_v2', 'closed native source inventory')
        require(reg['schema'] == 'hepta.hia.ndu-native-persistent-ranking-registration.v1' and report['schema'] == 'hepta.hia.ndu-native-persistent-ranking-result.v1', 'native campaign profile')
        require(reg['source_files']['tools/replay_hia_ndu_persistent_native.py'] == sha256(_SELF).hexdigest(), 'executed independent reader identity')
        require(reg['source_files']['tools/qualify_hia_ndu_persistent_ranker.py'] == '7552241ba93d30fe28e6075b4881aa9358bac5db673e77329bb40e9f114162e4' and reg['source_files']['tools/replay_hia_ndu_persistent_ranker.py'] == '0bfe5bfe6b5b78d4afeb9ca34e4d90a464bb98aff1d7b6beac02e6bc17d3f805', 'historical full source changed')
        require(reg["source_files"]["tools/qualify_hia_ndu_persistent_native.py"]
                == EXPECTED_PRODUCER_SHA256, "exact native producer source")
        for name, expected in OWNED_RUNTIME_PINS.items():
            require(reg["source_files"].get(name) == expected, "exact native execution source: " + name)
        for name, digest in reg['source_files'].items():
            require(sha256(take(root / 'frozen-source' / name)).hexdigest() == digest, 'frozen source: ' + name)
        receipt_raw = take(root / 'original-build-receipt.json')
        build = json.loads(receipt_raw)
        identity = reg['native_identity']
        checked_build(receipt_raw, identity)
        require(sha256(receipt_raw).hexdigest() == reg['original_build_receipt_sha256'] and receipt_raw == take(root / 'frozen-source/docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json'), 'exact native construction and source contract')
        for name, digest in build['source_files'].items():
            require(reg['source_files'].get(name) == digest, 'native leaf source identity')
        rank_raw = take(root / "original-rank-contract.json")
        rank_sha = "d0a4b5d83dd0f6802728adf19cd4b2e2349af72416c894420e612cb1fdd232fd"
        require(sha256(rank_raw).hexdigest() == rank_sha == reg["rank_contract_sha256"]
                == report["rank_contract_sha256"]
                and rank_raw == take(root / "frozen-source/docs/HIA_NATIVE_NDU_RANK_BUILD.json"),
                "exact current rank policy contract")
        rank = json.loads(rank_raw)
        expected_products = {row["resource"]: {"bytes": row["bytes"], "sha256": row["sha256"]}
                             for row in rank["products"].values()}
        require(wire(reg["rank_products"]) == wire(expected_products)
                and wire(report["rank_products"]) == wire(expected_products), "native rank products")
        for name, expected in expected_products.items():
            body = take(root / "recorded-products" / name)
            require(len(body) == expected["bytes"] and sha256(body).hexdigest() == expected["sha256"],
                    "native rank product complete bytes")
        for name, digest in rank["source_files"].items():
            require(reg["source_files"].get(name) == digest, "native rank source identity")

        require(type(reg['source_git']) is dict and set(reg['source_git']) == {'head', 'status'} and (type(reg['source_git']['head']) is str) and re.fullmatch('[0-9a-f]{40}', reg['source_git']['head']) and (reg['source_git']['status'] == ''), 'committed source identity')
        for object_, keys in ((reg, ('maximum_native_processes', 'maximum_native_evaluations', 'maximum_ordinary_calls', 'whole_campaign_wall_budget_ns', 'automatic_retries', 'native_binary_bytes')), (report, ('planned_cells', 'completed_cells', 'failed_cells', 'unstarted_cells', 'automatic_retries', 'native_processes_started', 'native_responses_checked'))):
            for key in keys:
                integer(object_[key])
        require(type(reg['per_call_timeout_s']) is float and type(reg['maximum_session_lifetime_s']) is float, 'original floating timeout declarations')
        require(report['registration_sha256'] == registration_sha256 and report['source_files'] == reg['source_files'] and (report['source_git'] == reg['source_git']) and (report['native_identity'] == identity) and (report['source_unchanged'] is True), 'source/report binding')
        require(report['p2_acceptance'] == 'HOLD' and report['authority'] == 'DENY_ALL' and (report['economic_benefit_established'] is False) and (report['ndu_incremental_value_established'] is False) and (report['whole_lifecycle_cost_complete'] is False) and (report['production_activation_allowed'] is False), 'scope promotion')
        schedule = [{'horizon': horizon, 'pair': index + 1, 'arms': list(order)} for horizon in HORIZONS for index, order in enumerate(itertools.permutations(ARMS))]
        require(reg['schedule'] == schedule and len(reg['requests']) == 64 and (reg['arms'] == list(ARMS)) and (reg['persistent_profile'] == PROFILE) and (reg['per_call_timeout_s'] == 1.0) and (reg['maximum_session_lifetime_s'] == 60.0) and (reg['whole_campaign_wall_budget_ns'] == 120000000000), 'registered tasks, orders and bounded budget')
        cells = [json.loads(line) for line in take(root / 'cell-ledger.jsonl').splitlines()]
        expected_cells = [(row['horizon'], row['pair'], arm) for row in schedule for arm in row['arms']]
        require([(row['horizon'], row['pair'], row['arm']) for row in cells] == expected_cells, 'cell order/denominator')
        require(report['planned_cells'] == report['completed_cells'] == len(cells) == 72 and report['failed_cells'] == report['unstarted_cells'] == 0 and (report['automatic_retries'] == reg['automatic_retries'] == 0) and (report['mechanism_execution_complete'] is True), 'campaign completion')
        ordinary_count = native_responses = prepared_processes = persistent_processes = 0
        native_replies = {}
        selected_rows = {}
        observed_pids = []
        for cell in cells:
            horizon, pair, arm = (cell['horizon'], cell['pair'], cell['arm'])
            integer(horizon, positive=True)
            integer(pair, positive=True)
            for key in ('completed_calls', 'unexecuted_calls', 'native_processes_started', 'native_responses_checked'):
                integer(cell[key])
            stem = 'h%02d-p%02d-%s' % (horizon, pair, arm)
            require(cell['status'] == 'completed' and cell['completed_calls'] == horizon and (len(cell['calls']) == horizon) and (cell['unexecuted_calls'] == 0), 'incomplete cell cannot qualify')
            integer(cell['wall_ns'], positive=True)
            require(json.loads(take(root / (stem + '.json'))) == cell, 'journal/cell mismatch')
            require(cell['originals']['path'] == stem + '-originals.jsonl', 'original path')
            originals_raw = take(root / cell['originals']['path'])
            require(len(originals_raw) == cell['originals']['bytes'] and sha256(originals_raw).hexdigest() == cell['originals']['sha256'], 'original journal bytes')
            originals = [json.loads(line) for line in originals_raw.splitlines()]
            expected_length = horizon if arm == 'ordinary_scalar' else horizon * 2 + (2 if arm == 'persistent_ndu' else 0)
            require(len(originals) == expected_length, 'missing or extra original event')
            cost = cell.get('owner_cost')
            session = worker_pid = None
            counted_wire = {'stdin': 0, 'stdout': 0, 'stderr': 0}
            if arm == 'persistent_ndu':
                require(cost['session_accepted'] is True and cost['closed'] is True and (cost['complete'] is True) and (cost['profile'] == PROFILE) and (cost['native_processes_started'] == 1) and (cost['original_native_requests_completed'] == horizon) and (cost['max_requests'] == horizon) and (cost['result_cache_hits'] == 0) and (cost['native_process_reuse'] is True), 'persistent owner completion')
                session = cost['session']
                require(type(session) is str and re.fullmatch('[0-9a-f]{64}', session), 'session nonce')
                worker_pid = integer(cost['worker_pid'], positive=True)
                first, last = (originals[0], originals[-1])
                require(first['kind'] == last['kind'] == 'original_persistent_transport' and first['index'] == -1 and (last['index'] == horizon - 1) and (first['event']['phase'] == 'startup') and (last['event']['phase'] == 'close'), 'persistent lifecycle event order')
                startup = first['event']['observation']
                require(startup['sequence'] == 0 and startup['worker_pid'] == worker_pid and (startup['session'] == session) and (startup['frame_complete'] is True) and (startup['error'] is None) and (startup['stdin_bytes_written'] == 0) and (raw_bytes(startup['stdin_frame']) == raw_bytes(startup['stderr']) == b''), 'startup transport')
                greeting_raw = raw_bytes(startup['stdout_frame'])
                greeting = json.loads(decode_frame(greeting_raw, 0, session))
                require(wire(greeting) == wire({'schema': 'hepta.hia.ndu-native-stream-hello.v1', 'transport_profile': PROFILE, 'upstream_commit': identity['upstream_commit'], 'entry_point': 'hepta.hia.ndu_evaluator.v1', 'reference_entry_point': 'codex_hepta_ndu::evaluate_candidates_with_policy', 'max_requests': horizon, 'max_frame_json_bytes': 1048576, 'max_session_bytes': 8388608, 'authority': 'ADVISORY_ONLY', 'result_cache': False, 'evaluates_each_request': True}), 'native stream greeting')
                counted_wire['stdout'] += len(greeting_raw)
                require(wire(summary(startup)) == wire(cost['startup']), 'startup cost observation')
                require(integer(startup['wall_ns'], positive=True) <= integer(cost['preparation_wall_ns'], positive=True), 'startup exchange interval exceeds owner preparation')
                close = last['event']['observation']
                require(close['cleanup']['pid'] == worker_pid and close['cleanup']['cleanup_confirmed'] is True and (close['cleanup']['signal_sent'] is True) and (close['cleanup']['returncode'] == 0) and (close['cleanup']['reason'] == 'explicit_close') and (close['cleanup']['error'] is None) and (close['protocol_error'] is None) and (close['pipe_errors'] == []) and (close['eof'] == {'stdout': True, 'stderr': True}) and (raw_bytes(close['stdout_suffix']) == raw_bytes(close['stderr_suffix']) == b''), 'persistent final protocol/cleanup')
                require(wire(cost['close']) == wire({**summary(close), 'image_close_error': None}), 'close cost binding')
                close_wall = integer(close['wall_ns'], positive=True)
                require(close['cleanup_wall_is_nested'] is True and integer(close['cleanup']['wall_ns'], positive=True) <= close_wall <= integer(cost['close_wall_ns'], positive=True), 'cleanup or transport close interval exceeds its enclosing close')
                persistent_processes += 1
                observed_pids.append(worker_pid)
            elif arm == 'prepared_ndu':
                require(cost['closed'] is True and cost['complete'] is True and (cost['close_confirmed'] is True) and (cost['all_native_cleanup_confirmed'] is True) and (cost['original_native_calls'] == horizon) and (cost['result_cache_hits'] == 0) and (cost['native_process_reuse'] is False), 'prepared owner completion')
                require(sha256(wire(cost['preparation'])).hexdigest() == cost['preparation_receipt_sha256'], 'prepared receipt identity')
            for index in range(horizon):
                row = cell['calls'][index]
                request = reg['requests'][index]
                requested = wire(request)
                selected, frontier, _ = choose(request)
                require(row['index'] == index and row['status'] == 'completed' and (row['error'] is None) and (row['selected_id'] == selected) and (row['request_sha256'] == sha256(requested).hexdigest()), 'call decision/request')
                integer(row['wall_ns'], positive=True)
                result_position = index if arm == 'ordinary_scalar' else index * 2 + (2 if arm == 'persistent_ndu' else 1)
                result_row = originals[result_position]
                require(result_row['kind'] == 'result' and result_row['index'] == index and (result_row['request'] == request) and (sha256(wire(result_row['result'])).hexdigest() == row['result_sha256']), 'original result identity')
                result = result_row['result']
                if arm == 'ordinary_scalar':
                    require(result['native_ndu_evaluated'] is False and result['selected_id'] == selected and (result['frontier'] == frontier) and (result['request_sha256'] == sha256(requested).hexdigest()), 'ordinary control changed')
                    ordinary_count += 1
                else:
                    event = originals[result_position - 1]
                    require(event['index'] == index, 'original native event index')
                    if arm == 'prepared_ndu':
                        require(event['kind'] == 'original_prepared_transport', 'prepared native event')
                        observed = event['observation']
                        require(raw_bytes(observed['stdin']) == requested and observed['response_admitted'] is True and (observed['error'] is None) and all((observed['native_identity'][key] == value for key, value in identity.items())), 'prepared request/admission/identity')
                        pump = observed['pump']
                        require(pump['started'] is True and pump['cleanup_confirmed'] is True and (pump['streams_complete'] is True) and (pump['returncode'] == 0) and (pump['error'] is None) and (raw_bytes(pump['stderr']) == b''), 'prepared process completion')
                        response_bytes = raw_bytes(pump['stdout'])
                        observed_pids.append(integer(pump['pid'], positive=True))
                        prepared_processes += 1
                        attempt = cost['attempts'][index]
                        require(attempt['status'] == 'completed' and attempt['native_started'] is True and (attempt['cleanup_confirmed'] is True) and (attempt['response_admitted'] is True) and (attempt['stdout_sha256'] == sha256(response_bytes).hexdigest()), 'prepared attempt cost status')
                        require(integer(pump['wall_ns'], positive=True) <= integer(attempt['wall_ns'], positive=True), 'prepared pump interval exceeds owner attempt')
                    else:
                        require(event['kind'] == 'original_persistent_transport' and event['event']['phase'] == 'round', 'persistent round event')
                        observed = event['event']['observation']
                        require(observed['worker_pid'] == worker_pid and observed['session'] == session and (observed['sequence'] == index + 1) and (observed['frame_complete'] is True) and (observed['error'] is None), 'persistent frame completion/owner')
                        input_frame, output_frame = (raw_bytes(observed['stdin_frame']), raw_bytes(observed['stdout_frame']))
                        require(decode_frame(input_frame, index + 1, session) == requested and observed['stdin_bytes_written'] == len(input_frame) and (raw_bytes(observed['stderr']) == b''), 'actual persistent input bytes')
                        response_bytes = decode_frame(output_frame, index + 1, session)
                        counted_wire['stdin'] += len(input_frame)
                        counted_wire['stdout'] += len(output_frame)
                        attempt = cost['attempts'][index]
                        require(attempt['status'] == 'completed' and attempt['sequence'] == index + 1 and (attempt['response_sha256'] == sha256(response_bytes).hexdigest()) and (wire(attempt['transport']) == wire(summary(observed))), 'persistent attempt cost binding')
                        require(integer(observed['wall_ns'], positive=True) <= integer(attempt['wall_ns'], positive=True), 'persistent exchange interval exceeds owner attempt')
                        require(result['native_identity']['worker_pid'] == worker_pid and result['native_identity']['worker_session'] == session and (result['native_identity']['transport_profile'] == PROFILE), 'persistent returned identity')
                    verify_response(response_bytes, result, request, identity)
                    native_replies[horizon, pair, arm, index] = response_bytes
                    native_responses += 1
                    require(attempt['request_sha256'] == sha256(requested).hexdigest() and attempt['caller_wall_ns'] == attempt['wall_ns'] + attempt['queue_wait_ns'], 'request cost or overlapping queue accounting')
                    integer(attempt['wall_ns'], positive=True)
                    integer(attempt['queue_wait_ns'])
                selected_rows[horizon, pair, arm, index] = selected
            expected_processes = 0 if arm == 'ordinary_scalar' else 1 if arm == 'persistent_ndu' else horizon
            require(cell['native_processes_started'] == expected_processes and cell['native_responses_checked'] == (0 if arm == 'ordinary_scalar' else horizon), 'cell native process/evaluation counts')
            if arm != 'ordinary_scalar':
                require(len(cost['attempts']) == horizon and cost['whole_lifecycle_cost_complete'] is False and (cost['economic_benefit_established'] is False), 'owner cost scope')
                preparation = cost['preparation_wall_ns'] if arm == 'persistent_ndu' else cost['preparation']['preparation_wall_ns']
                subtotal = integer(preparation, positive=True) + integer(cost['close_wall_ns'], positive=True)
                subtotal += sum((integer(row['wall_ns'], positive=True) for row in cost['attempts']))
                require(subtotal == cost['observed_disjoint_wall_ns'] and subtotal <= cell['wall_ns'], 'disjoint cost omissions or duplicate nested totals')
            if arm == 'persistent_ndu':
                require(cost['wire_bytes'] == counted_wire and sum(counted_wire.values()) <= 8388608, 'persistent session cumulative wire budget')
        paired_count = 0
        for horizon in HORIZONS:
            for pair in range(1, 7):
                for index in range(horizon):
                    require(native_replies[horizon, pair, 'prepared_ndu', index] == native_replies[horizon, pair, 'persistent_ndu', index], 'paired original native JSON bytes differ')
                    require(len({selected_rows[horizon, pair, arm, index] for arm in ARMS}) == 1, 'three-arm scalar decision mismatch')
                    paired_count += 1
        require(prepared_processes == 510 and persistent_processes == 24 and (prepared_processes + persistent_processes == report['native_processes_started'] == reg['maximum_native_processes'] == 534) and (native_responses == report['native_responses_checked'] == reg['maximum_native_evaluations'] == 1020) and (ordinary_count == reg['maximum_ordinary_calls'] == 510), 'complete denominator')
        require(wire(report['analysis']) == wire(expected_analysis(cells)), 'paired timing/statistics arithmetic or JSON types')
        check_cost_intervals(cells, report)
        return {'schema': 'hepta.hia.ndu-native-persistent-ranking-replay.v1', 'registration_sha256': registration_sha256, 'verifier_sha256': sha256(take(Path(__file__))).hexdigest(), 'prepared_native_processes': prepared_processes, 'persistent_native_processes': persistent_processes, 'original_native_responses_checked': native_responses, 'ordinary_calls': ordinary_count, 'paired_native_responses_byte_identical': paired_count, 'distinct_observed_pids': len(set(observed_pids)), 'source_files_rehashed': len(expected_source), 'cells_replayed': len(cells), 'raw_frame_identity_cleanup_and_cost_arithmetic_consistent': True, 'nested_cost_intervals_reconciled': True, 'timings_independently_authenticated': False, 'machine_refinement_proved': False, 'economic_benefit_established': False, 'authority': 'DENY_ALL'}
    finally:
        for path, (raw, pin) in captures.items():
            require(_file_identity(path) == pin and path.read_bytes() == raw and (_file_identity(path) == pin), 'physical input changed at terminal')



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--registration-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = replay(args.directory, args.registration_sha256)
    with Path(args.output).open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
