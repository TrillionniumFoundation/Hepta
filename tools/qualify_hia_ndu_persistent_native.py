#!/usr/bin/env python3
"""Source-owned HIA successor of the fixed Rust-profile transport campaign.

The complete 72-cell schedule, original request/cell/analysis methods, 120-second
campaign, one-second calls and 60-second sessions remain unchanged. Historical
Rust registration and its independent reader remain separate and unchanged.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_optimizer import _bridge_identity, _bytes
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
from hepta.hia_ndu_persistent_ranker import PersistentNduRanker, PROFILE
from hepta.hia_ndu_scalar_selection import resolve_scalar_selection
from tools.qualify_hia_ndu_prepared_ranker import requests, ordinary_scalar, _jsonable

ARMS = ("prepared_ndu", "persistent_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
ORDERS = tuple(itertools.permutations(ARMS))
MAX_WALL_NS = 120_000_000_000
PER_CALL_TIMEOUT_S = 1.0
MAX_SESSION_LIFETIME_S = 60.0
SOURCE_PATHS = [
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
]
_SELF = Path(__file__).read_bytes()



def _write(path, value):
    with path.open("xb") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _source_files():
    paths = set(SOURCE_PATHS)
    if Path(__file__).read_bytes() != _SELF:
        raise ValueError("executed native campaign changed after import")
    paths.update(str(path.relative_to(ROOT)) for path in
                 (ROOT / "hepta").rglob("*.py") if path.is_file() and "_data" not in path.parts)
    if any((ROOT / name).is_symlink() for name in paths):
        raise ValueError("native source inventory contains a symlink")
    for name, module in tuple(sys.modules.items()):
        if name == "hepta" or name.startswith("hepta."):
            path = getattr(module, "__file__", None)
            if path and str(Path(path).resolve().relative_to(ROOT)) not in paths:
                raise ValueError("executed package module is outside captured source")
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}



def _rank_products():
    raw = (ROOT / "docs/HIA_NATIVE_NDU_RANK_BUILD.json").read_bytes()
    if sha256(raw).hexdigest() != "d0a4b5d83dd0f6802728adf19cd4b2e2349af72416c894420e612cb1fdd232fd":
        raise ValueError("exact native rank policy contract changed")
    value = json.loads(raw)
    products = {}
    for role, expected in value["products"].items():
        path = ROOT / "hepta" / expected["resource"]
        def identity():
            st = path.stat()
            return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        before = identity()
        body = path.read_bytes()
        after = identity()
        if (before != after or len(body) != expected["bytes"]
                or sha256(body).hexdigest() != expected["sha256"]):
            raise ValueError("native ranking policy product changed: " + role)
        products[expected["resource"]] = {"bytes": len(body), "sha256": sha256(body).hexdigest()}
    if (ROOT / "docs/HIA_NATIVE_NDU_RANK_BUILD.json").read_bytes() != raw:
        raise ValueError("native rank contract changed during capture")
    return products

def _git():
    def command(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    return {"head": command("rev-parse", "HEAD"),
            "status": command("status", "--porcelain=v1", "--untracked-files=no")}


def schedule():
    return [{"horizon": horizon, "pair": index + 1, "arms": list(order)}
            for horizon in HORIZONS for index, order in enumerate(ORDERS)]


def register(bridge, output):
    started = time.perf_counter_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    image, identity = _bridge_identity(bridge)
    rank_products = _rank_products()
    source = _git()
    if source["status"]:
        raise ValueError("commit source before registering a timing experiment")
    sources = _source_files()
    subprocess.check_call(["git", "ls-files", "--error-unmatch", *sources],
                          cwd=ROOT, stdout=subprocess.DEVNULL)
    receipt_path = Path(bridge["build_receipt"]).resolve()
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    from tools.replay_hia_ndu_persistent_native import checked_build
    checked_build(receipt_bytes, identity)
    if receipt_bytes != (ROOT / "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json").read_bytes():
        raise ValueError("native campaign receipt differs from actual source")
    registration = {
        "schema": "hepta.hia.ndu-native-persistent-ranking-registration.v1",
        "registered_utc": _utc(), "source_git": source, "source_files": sources,
        "source_domain": "native_package_required_418_plus_current_v2",
        "historical_source_relation": {
            "producer_sha256": "7552241ba93d30fe28e6075b4881aa9358bac5db673e77329bb40e9f114162e4",
            "reader_sha256": "0bfe5bfe6b5b78d4afeb9ca34e4d90a464bb98aff1d7b6beac02e6bc17d3f805",
            "preserved_functions": ["schedule", "_cell", "analyze"],
            "original_budgets_and_denominators_unchanged": True},
        "bridge": {key: str(Path(value).resolve()) for key, value in bridge.items()},
        "native_identity": identity, "native_binary_bytes": len(image.data),
        "rank_products": rank_products,
        "rank_contract_sha256": "d0a4b5d83dd0f6802728adf19cd4b2e2349af72416c894420e612cb1fdd232fd",
        "original_build_receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "original_build_cost": receipt.get("build_cost"),
        "persistent_profile": PROFILE, "arms": list(ARMS), "schedule": schedule(),
        "requests": requests(), "per_call_timeout_s": PER_CALL_TIMEOUT_S,
        "maximum_session_lifetime_s": MAX_SESSION_LIFETIME_S,
        "whole_campaign_wall_budget_ns": MAX_WALL_NS,
        "maximum_native_processes": len(ORDERS) * (sum(HORIZONS) + len(HORIZONS)),
        "maximum_native_evaluations": 2 * len(ORDERS) * sum(HORIZONS),
        "maximum_ordinary_calls": len(ORDERS) * sum(HORIZONS),
        "timing_boundary": "each cell begins before owner preparation and ends after all original response observation, selection checks, actual attempt records, owner close/receipt and original stream close; cell-summary write is outside that cell but inside the campaign interval",
        "warmup_calls_inside_registered_campaign": 0, "automatic_retries": 0,
        "prior_functional_validation": "native protocol controls ran before registration; their observations are not campaign cells; host caches are not reset or independently measured",
        "analysis": "all six orders retained per horizon; report every paired difference without selection; descriptive statistics only, no significance or economic threshold",
        "shared_host": True, "other_sessions_excluded": False,
        "prior_source_acquisition_and_original_build_in_cell_cost": False,
        "provider_model_calls": 0, "monetary_cost": None,
        "economic_benefit_established": False, "production_activation_allowed": False,
        "registration_preparation_wall_ns": None,
    }
    for name, expected in sources.items():
        body = (ROOT / name).read_bytes()
        if sha256(body).hexdigest() != expected:
            raise ValueError("source changed during registration")
        target = output / "frozen-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    destination = output / "recorded-products"
    destination.mkdir()
    for name, expected in rank_products.items():
        body = (ROOT / "hepta" / name).read_bytes()
        if {"bytes": len(body), "sha256": sha256(body).hexdigest()} != expected:
            raise ValueError("native policy product changed before frozen capture")
        (destination / name).write_bytes(body)
    (output / "original-rank-contract.json").write_bytes(
        (ROOT / "docs/HIA_NATIVE_NDU_RANK_BUILD.json").read_bytes())
    if _rank_products() != rank_products:
        raise ValueError("native policy product changed at registration terminal")
    if _source_files() != sources or _git() != source:
        raise ValueError("source changed at registration terminal")
    registration["registration_preparation_wall_ns"] = time.perf_counter_ns() - started
    _write(output / "registration.json", registration)
    checksum = sha256((output / "registration.json").read_bytes()).hexdigest()
    (output / "registration.sha256").write_text(checksum + "\n")
    (output / "original-build-receipt.json").write_bytes(receipt_bytes)
    return {"registration_sha256": checksum, "planned_cells": len(schedule()) * len(ARMS),
            "maximum_native_processes": registration["maximum_native_processes"],
            "maximum_native_evaluations": registration["maximum_native_evaluations"]}


def _cell(arm, horizon, pair, bridge, raw_requests, output, deadline):
    started = time.perf_counter_ns()
    record = {"arm": arm, "horizon": horizon, "pair": pair, "status": "started",
              "planned_calls": horizon, "completed_calls": 0, "calls": [],
              "native_processes_started": 0, "native_responses_checked": 0, "error": None}
    path = output / ("h%02d-p%02d-%s-originals.jsonl" % (horizon, pair, arm))
    owner = None
    originals = None
    current_index = -1
    persistent_pids = set()
    interrupted = None

    def write_original(value):
        originals.write(_bytes(_jsonable(value)) + b"\n")
        originals.flush()

    def persistent_observer(event):
        observation = event["observation"]
        pid = (observation.get("cleanup") or {}).get("pid") if event["phase"] == "close" else observation.get("worker_pid")
        if pid is not None:
            persistent_pids.add(pid)
            record["native_processes_started"] = len(persistent_pids)
        write_original({"index": current_index, "kind": "original_persistent_transport", "event": event})

    def prepared_observer(value):
        pump = value.get("pump")
        record["native_processes_started"] += bool(pump and pump["started"])
        write_original({"index": current_index, "kind": "original_prepared_transport", "observation": value})

    try:
        originals = path.open("xb")
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise TimeoutError("registered whole-campaign budget exhausted before preparation")
        if arm == "prepared_ndu":
            owner = PreparedNduRanker(bridge, max_requests=horizon)
        elif arm == "persistent_ndu":
            owner = PersistentNduRanker(
                bridge, max_requests=horizon,
                startup_timeout_s=min(PER_CALL_TIMEOUT_S, remaining / 1_000_000_000),
                lifetime_s=min(MAX_SESSION_LIFETIME_S, remaining / 1_000_000_000),
                observer=persistent_observer)
        for current_index, raw in enumerate(raw_requests[:horizon]):
            call_started = time.perf_counter_ns()
            row = {"index": current_index, "request_sha256": sha256(raw).hexdigest(),
                   "status": "started", "error": None}
            record["calls"].append(row)
            try:
                remaining = deadline - time.perf_counter_ns()
                if remaining <= 0:
                    raise TimeoutError("registered whole-campaign budget exhausted")
                if arm == "ordinary_scalar":
                    result = ordinary_scalar(raw)
                    selected = result["selected_id"]
                else:
                    request = json.loads(raw)
                    timeout = min(PER_CALL_TIMEOUT_S, remaining / 1_000_000_000)
                    kwargs = {"timeout_s": timeout}
                    if arm == "prepared_ndu":
                        kwargs["observer"] = prepared_observer
                    response, identity = owner.rank(request, **kwargs)
                    record["native_responses_checked"] += 1
                    selection = resolve_scalar_selection(request, response)
                    selected = selection["selected_id"]
                    result = {"native_response": response, "native_identity": identity,
                              "selection": selection}
                reference = ordinary_scalar(raw)
                if selected != reference["selected_id"]:
                    raise ValueError("selection differs from the frozen scalar ordinary reference")
                write_original({"index": current_index, "kind": "result",
                                "request": json.loads(raw), "result": result})
                row.update(status="completed", selected_id=selected,
                           result_sha256=sha256(_bytes(result)).hexdigest())
                record["completed_calls"] += 1
            except BaseException as error:
                row.update(status="failed", error={"type": type(error).__name__, "message": str(error)[:2048]})
                raise
            finally:
                row["wall_ns"] = time.perf_counter_ns() - call_started
        record["status"] = "completed"
    except BaseException as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)[:2048]})
        if not isinstance(error, Exception):
            interrupted = error
    finally:
        if owner is not None:
            try:
                owner.close()
            except BaseException as error:
                record.update(status="failed", close_error={"type": type(error).__name__, "message": str(error)[:2048]})
            receipt = owner.receipt()
            record["owner_cost"] = receipt
            if not receipt["complete"] or arm == "persistent_ndu" and not receipt["session_accepted"]:
                record.update(status="failed", incomplete_owner=True)
        if originals is not None:
            originals.close()
        record["wall_ns"] = time.perf_counter_ns() - started
        record["unexecuted_calls"] = horizon - len(record["calls"])
    record["originals"] = {"path": path.name, "sha256": sha256(path.read_bytes()).hexdigest(),
                           "bytes": path.stat().st_size}
    _write(output / ("h%02d-p%02d-%s.json" % (horizon, pair, arm)), record)
    if interrupted is not None:
        raise interrupted
    return record


def analyze(cells):
    result = []
    for horizon in HORIZONS:
        rows = [row for row in cells if row["horizon"] == horizon]
        complete = len(rows) == len(ORDERS) * len(ARMS) and all(
            row["status"] == "completed" and row["completed_calls"] == horizon for row in rows)
        comparison = {"horizon": horizon, "all_registered_cells_completed": complete,
                      "pairs": [], "persistent_saving_summary_ns": None}
        for pair in range(1, len(ORDERS) + 1):
            group = {row["arm"]: row for row in rows if row["pair"] == pair}
            valid = set(group) == set(ARMS) and all(
                row["status"] == "completed" and row["completed_calls"] == horizon for row in group.values())
            comparison["pairs"].append({
                "pair": pair, "complete": valid,
                "all_attempt_arm_wall_ns": {arm: row.get("wall_ns") for arm, row in group.items()},
                "prepared_minus_persistent_ns": group["prepared_ndu"]["wall_ns"] - group["persistent_ndu"]["wall_ns"] if valid else None,
                "ordinary_minus_persistent_ns": group["ordinary_scalar"]["wall_ns"] - group["persistent_ndu"]["wall_ns"] if valid else None})
        if complete:
            differences = [row["prepared_minus_persistent_ns"] for row in comparison["pairs"]]
            comparison["persistent_saving_summary_ns"] = {
                "observations": len(differences), "sum": sum(differences),
                "mean": statistics.mean(differences), "median": statistics.median(differences),
                "min": min(differences), "max": max(differences),
                "sample_stdev": statistics.stdev(differences),
                "positive_pairs": sum(value > 0 for value in differences)}
        result.append(comparison)
    return result


def run(directory, expected_registration_sha256):
    started = time.perf_counter_ns()
    output = Path(directory).resolve()
    raw = (output / "registration.json").read_bytes()
    if sha256(raw).hexdigest() != expected_registration_sha256:
        raise ValueError("registration differs from the explicit precommitted digest")
    reg = json.loads(raw)
    if (reg["schedule"] != schedule() or reg["requests"] != requests()
            or reg["source_files"] != _source_files() or reg["source_git"] != _git()
            or reg["whole_campaign_wall_budget_ns"] != MAX_WALL_NS
            or reg["per_call_timeout_s"] != PER_CALL_TIMEOUT_S
            or reg["maximum_session_lifetime_s"] != MAX_SESSION_LIFETIME_S):
        raise ValueError("source, tasks, order or registered budget changed")
    _write(output / "run-started.json", {"started_utc": _utc(),
                                      "registration_sha256": expected_registration_sha256})
    before_source = _source_files()
    _, identity = _bridge_identity(reg["bridge"])
    if identity != reg["native_identity"]:
        raise ValueError("native build changed after registration")
    if _rank_products() != reg["rank_products"]:
        raise ValueError("native policy product changed after registration")
    raw_requests = [_bytes(request) for request in reg["requests"]]
    deadline = started + MAX_WALL_NS
    cells = []
    with (output / "cell-ledger.jsonl").open("xb") as journal:
        for group in reg["schedule"]:
            for arm in group["arms"]:
                if time.perf_counter_ns() >= deadline:
                    record = {"arm": arm, "horizon": group["horizon"], "pair": group["pair"],
                              "status": "not_started_budget_exhausted", "wall_ns": None,
                              "completed_calls": 0, "native_processes_started": 0, "native_responses_checked": 0}
                else:
                    record = _cell(arm, group["horizon"], group["pair"], reg["bridge"], raw_requests, output, deadline)
                cells.append(record)
                journal.write(_bytes(record) + b"\n")
                journal.flush()
    unchanged = (before_source == _source_files() and reg["source_git"] == _git()
                 and _rank_products() == reg["rank_products"])
    report = {
        "schema": "hepta.hia.ndu-native-persistent-ranking-result.v1",
        "registration_sha256": expected_registration_sha256, "finished_utc": _utc(),
        "source_unchanged": unchanged, "source_git": reg["source_git"], "source_files": before_source,
        "native_identity": identity, "rank_products": reg["rank_products"],
        "rank_contract_sha256": reg["rank_contract_sha256"],
        "planned_cells": len(reg["schedule"]) * len(ARMS),
        "completed_cells": sum(row["status"] == "completed" for row in cells),
        "failed_cells": sum(row["status"] == "failed" for row in cells),
        "unstarted_cells": sum(row["status"].startswith("not_started") for row in cells),
        "native_processes_started": sum(row["native_processes_started"] for row in cells),
        "native_responses_checked": sum(row["native_responses_checked"] for row in cells),
        "automatic_retries": 0, "analysis": analyze(cells),
        "actual_campaign_wall_ns_to_summary": time.perf_counter_ns() - started,
        "nested_cell_wall_added_again": False,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine(), "python": platform.python_version()},
        "shared_host": True, "other_sessions_excluded": False,
        "scope": "original native supplied-scalar ranking and explicit bounded persistent process transport; complete registered cells required for each horizon summary",
        "limitations": [
            "synthetic finite cost tables, no real task or model invocation",
            "shared nonexclusive host; counterbalanced orders do not prove stationarity",
            "prepared and persistent bind the same admitted immutable executable snapshot",
            "a persistent round is advisory until the owner closes successfully",
            "source acquisition and retained native build excluded from cells",
            "final summary write and caller startup excluded from campaign timer",
            "monetary, energy, authoring and complete engineering costs unknown"],
        "whole_lifecycle_cost_complete": False, "ndu_incremental_value_established": False,
        "economic_benefit_established": False, "p2_acceptance": "HOLD",
        "authority": "DENY_ALL", "production_activation_allowed": False}
    report["mechanism_execution_complete"] = (
        unchanged and report["completed_cells"] == report["planned_cells"]
        and report["native_processes_started"] == reg["maximum_native_processes"]
        and report["native_responses_checked"] == reg["maximum_native_evaluations"])
    _write(output / "result.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("register")
    freeze.add_argument("--binary", required=True)
    freeze.add_argument("--build-receipt", required=True)
    freeze.add_argument("--output", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--directory", required=True)
    execute.add_argument("--registration-sha256", required=True)
    args = parser.parse_args()
    if args.command == "register":
        result = register({"binary": args.binary, "build_receipt": args.build_receipt}, args.output)
    else:
        report = run(args.directory, args.registration_sha256)
        result = {key: report[key] for key in (
            "mechanism_execution_complete", "planned_cells", "completed_cells", "failed_cells",
            "native_processes_started", "native_responses_checked", "p2_acceptance", "analysis")}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if args.command == "register" or result["mechanism_execution_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
