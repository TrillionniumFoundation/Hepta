"""Qualify the native-build coordinator against all 114 retained ordinary callers.

The exact original 51 machine, 50 Core and 13 additional Agent buffer/lease
methods are discovered once, in their original order, without edits to their
bodies or limits. NativeBuild is explicit; downstream compiler and OS services
remain separately declared dependencies. This is not a whole-native gate.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import stat
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_native_build import build, current_sources, DEVELOPMENT_INPUT_NAMES

MODULES = ('tests.test_hia_machine_x64',
 'tests.test_hia_machine_plan',
 'tests.test_hia_machine_registers',
 'tests.test_hia_machine_leaf_registers',
 'tests.test_hia_agent_native_machine_choices',
 'tests.test_hia_program_native',
 'tests.test_hia_program_native_review',
 'tests.test_hia_machine_lowering_edges',
 'tests.test_hia_native_byte_abi',
 'tests.test_hia_agent_buffer_lifecycle',
 'tests.test_hia_agent_native_lease_snapshot')
MODULE_SOURCE_PINS = {'tests/test_hia_agent_buffer_lifecycle.py': 'b3f23d740436ae90c909b65a2fbca150459fe16807cf788f17825832964302bf',
 'tests/test_hia_agent_native_lease_snapshot.py': '476e49225ad1b2215f08323079f3521b5b9dbcdb33edc8b619013f426643e823',
 'tests/test_hia_agent_native_machine_choices.py': 'c35b13d6e94da9129456913ade57e362c901619e8b7d87a4a0fdfbb1d06681cc',
 'tests/test_hia_machine_leaf_registers.py': 'e7db1280fd2a0d4be8c5052ae0be262f39fb82aa877851bdb347095de2e7e6d4',
 'tests/test_hia_machine_lowering_edges.py': '58ec7cecf376d6639e1f6d1f40d3a6d24b4199cbd4545e66a10269436dd27ee2',
 'tests/test_hia_machine_plan.py': 'a1d090bbbb5021957ca550813afb78f061bf10412554379f5efad3ca96974af9',
 'tests/test_hia_machine_registers.py': '1d72a2b19d7d4c9b93892d2aa9282479553def0906558c3f7f53552327c76773',
 'tests/test_hia_machine_x64.py': '1ba1a51995c38ae93e5ce1a748a0b2bf3d2d6a19c0c48dfb9043c1ef639e094f',
 'tests/test_hia_native_byte_abi.py': 'eb9782f07e3735cb51142883b1bce2f5fb84c6ef1a7ed6c401f8d1a7b3ab0bda',
 'tests/test_hia_program_native.py': 'a958a2bb4c94302f73332ee133a9583b84f14eece861f51211558099446359b7',
 'tests/test_hia_program_native_review.py': '1506e11005e7c03d6df167cf343219d355ec8547cdafc434a5d77ba89f9fbab0'}

# The complete original caller set remains fixed. Main's canonical source
# publication changes exactly two resource suffix literals in one module.
# Admit that explicit projection by both full-file hashes and an inverse
# byte reconstruction; no other body, assertion, order or limit is changed.
ORIGINAL_MODULE_SOURCE_PINS = dict(MODULE_SOURCE_PINS)
CANONICAL_CALLER_PATH = "tests/test_hia_program_native.py"
CANONICAL_CALLER_SOURCE_SHA256 = "4f20d74f55b6c4e58964cd534891f05d1e78e7698262716510e0f96b876746c7"
CANONICAL_CALLER_REPLACEMENTS = (
    (b"        paths = sorted((ROOT / \"examples/hia_program\").glob(\"*.hia\"))", b"        paths = sorted((ROOT / \"examples/hia_program\").glob(\"*.hepta\"))"),
    (b"            document=(ROOT/\"examples/hia_recursive_chain\"/(basename+\".json\")).read_bytes()", b"            document=(ROOT/\"examples/hia_recursive_chain\"/(basename+\".hepta\")).read_bytes()"),
)
MODULE_SOURCE_PINS = {
    **ORIGINAL_MODULE_SOURCE_PINS,
    CANONICAL_CALLER_PATH: CANONICAL_CALLER_SOURCE_SHA256,
}


def admit_canonical_caller_source(raw):
    if type(raw) is not bytes or sha256(raw).hexdigest() != CANONICAL_CALLER_SOURCE_SHA256:
        raise ValueError('canonical caller source bytes differ')
    inverse = raw
    for original, canonical in CANONICAL_CALLER_REPLACEMENTS:
        if inverse.count(canonical) != 1:
            raise ValueError('canonical caller replacement is not unique')
        inverse = inverse.replace(canonical, original, 1)
    original_sha = sha256(inverse).hexdigest()
    if original_sha != ORIGINAL_MODULE_SOURCE_PINS[CANONICAL_CALLER_PATH]:
        raise ValueError('canonical caller source does not restore the original bytes')
    return {'path': CANONICAL_CALLER_PATH,
            'original_sha256': original_sha,
            'canonical_sha256': CANONICAL_CALLER_SOURCE_SHA256,
            'exact_literal_replacements': len(CANONICAL_CALLER_REPLACEMENTS),
            'all_other_bytes_preserved': True,
            'prior_qualification_inherited': False}

EXPECTED_IDS = ('tests.test_hia_machine_x64.EncoderExecutionTests.test_all_general_registers_rex_arithmetic_shifts_conditions_and_internal_calls',
 'tests.test_hia_machine_x64.EncoderExecutionTests.test_external_allocator_relocations_resolve_with_only_ld',
 'tests.test_hia_machine_x64.EncoderExecutionTests.test_independent_elf_and_isa_tools_accept_output',
 'tests.test_hia_machine_x64.EncoderExecutionTests.test_memory_sib_displacements_lea_and_low_byte_rex',
 'tests.test_hia_machine_x64.EncoderStructuralTests.test_elf_symbol_order_and_stack_flags',
 'tests.test_hia_machine_x64.EncoderStructuralTests.test_invalid_registers_immediates_labels_and_relocations_reject',
 'tests.test_hia_machine_x64.EncoderStructuralTests.test_relocation_and_local_branches_are_deterministic',
 'tests.test_hia_machine_plan.MachinePlanExecutionTests.test_immediate_boundaries_and_live_flags_on_real_machine',
 'tests.test_hia_machine_plan.MachinePlanExecutionTests.test_independent_scratch_selection_and_layout_observations',
 'tests.test_hia_machine_plan.MachinePlanExecutionTests.test_requested_alignment_survives_elf_linking_and_loading',
 'tests.test_hia_machine_plan.MachinePlanValidationTests.test_default_plan_is_byte_identical_and_plan_changes_are_sealed',
 'tests.test_hia_machine_plan.MachinePlanValidationTests.test_each_choice_is_explicit_and_core_bound',
 'tests.test_hia_machine_plan.MachinePlanValidationTests.test_encoder_rejects_unreviewed_registers_and_choices',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_arithmetic_retains_overflow_abort',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_indices_retain_trap_before_partial_memory_write',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_scalars_and_disjoint_register_reuse',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_caller_mutation_after_lifetime_check_cannot_change_emitted_registers',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_changed_plans_preserve_requested_loaded_symbol_alignment',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_cmov_preserves_signed_unsigned_boolean_and_unit_value_representations',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_cmov_selects_both_full_width_values_under_all_plans',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_failed_campaign_arm_retains_all_attempts_and_costs',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_independent_sysv_witness_preserves_all_callee_saved_registers_and_stack_arguments',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_permuted_backedges_and_reordered_blocks_preserve_staged_inputs',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_register_values_survive_calloc_memset_and_free',
 'tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_register_values_survive_internal_calls_multiple_results_and_recursion',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_dead_parameter_and_dead_definition_writes_cannot_clobber_live_values',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_default_v3_preserves_canonical_bytes_and_needs_every_explicit_field',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_disjoint_lifetimes_and_separate_blocks_have_independent_witnesses',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_live_inputs_outputs_and_branch_condition_interfere',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plain_json_v1_v2_v3_plans_keep_their_machine_bytes',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plan_snapshot_bounds_cycles_depth_fanout_and_bytes_before_semantic_checks',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plan_snapshot_rejects_copy_and_equality_hooks_before_running_them',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_unreviewed_locations_types_and_unknown_values_fail_closed',
 'tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_validated_assignments_are_immutable_and_sealed_in_native_images',
 'tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_borrowed_byte_addresses_lengths_returns_and_prewrite_traps',
 'tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_checked_arithmetic_traps_after_placing_inputs_in_new_registers',
 'tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_dirty_register_inputs_stack_arguments_page_probe_and_callee_saves',
 'tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_every_leaf_scalar_opcode_keeps_live_r8_r9_against_vm',
 'tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_parallel_loop_edges_multi_result_and_unassigned_stack_values',
 'tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_entire_function_gate_rejects_calls_allocations_and_recursive_calls',
 'tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_r8_swap_scratch_resources_and_overlapping_lifetimes_are_refused',
 'tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_v4_is_opt_in_and_v3_keeps_its_register_boundary',
 'tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor',
 'tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_one_plan_receipt_cannot_authorize_different_layout',
 'tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused',
 'tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_separate_checks_and_assumptions_remain_in_verification_receipt',
 'tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor',
 'tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_one_plan_receipt_cannot_authorize_different_layout',
 'tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused',
 'tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_register_lifetimes_are_retained_without_claiming_identical_slots',
 'tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_unknown_value_register_assignment_is_refused_through_domain_tools',
 'tests.test_hia_program_native.DirectExecutionTests.test_all_integer_widths_wrapping_bits_shifts_and_signed_division',
 'tests.test_hia_program_native.DirectExecutionTests.test_allocator_observer_checks_actual_frees_and_failed_allocation',
 'tests.test_hia_program_native.DirectExecutionTests.test_bulk_operations_v2_through_v6_match_vm',
 'tests.test_hia_program_native.DirectExecutionTests.test_checked_arithmetic_comparisons_casts_and_unary',
 'tests.test_hia_program_native.DirectExecutionTests.test_checked_failures_abort_in_isolated_native_processes',
 'tests.test_hia_program_native.DirectExecutionTests.test_owned_memory_zero_initialization_and_ordinary_error_cleanup',
 'tests.test_hia_program_native.DirectExecutionTests.test_real_loops_calls_multiple_returns_and_parallel_block_moves',
 'tests.test_hia_program_native.DirectExecutionTests.test_recursive_chain_and_composite_v7_have_real_dynamic_execution',
 'tests.test_hia_program_native.DirectExecutionTests.test_scalar_c_abi_register_and_stack_arguments',
 'tests.test_hia_program_native.DirectExecutionTests.test_v8_chain_head_returned_loans_and_pop',
 'tests.test_hia_program_native.DirectExecutionTests.test_v8_parameter_loans_calls_cfg_recursion_and_aliases',
 'tests.test_hia_program_native.DirectObjectTests.test_all_versioned_agent_core_examples_are_emitted_without_llvm',
 'tests.test_hia_program_native.DirectObjectTests.test_artifact_mutation_rejected_even_with_recomputed_object_digest',
 'tests.test_hia_program_native.DirectObjectTests.test_cli_native_object_and_explicit_target_rejection',
 'tests.test_hia_program_native.DirectObjectTests.test_existing_output_is_preserved',
 'tests.test_hia_program_native.DirectObjectTests.test_foreign_target_is_explicitly_rejected',
 'tests.test_hia_program_native.DirectObjectTests.test_forged_verified_core_is_reverified_before_emission',
 'tests.test_hia_program_native.DirectObjectTests.test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch',
 'tests.test_hia_program_native.DirectObjectTests.test_object_generation_is_deterministic_and_bound_to_exact_core',
 'tests.test_hia_program_native.DirectObjectTests.test_route_inventory_names_explicit_direct_machine_selection',
 'tests.test_hia_program_native.DirectSystemLinkerTests.test_cli_native_shared_library_is_callable_with_ld',
 'tests.test_hia_program_native.DirectSystemLinkerTests.test_system_linker_alone_produces_callable_shared_library',
 'tests.test_hia_program_native_review.DirectNativeIndependentReview.test_dirty_high_bits_callee_saves_stack_arguments_and_page_probe',
 'tests.test_hia_program_native_review.DirectNativeIndependentReview.test_invalid_complete_ranges_trap_before_any_partial_write',
 'tests.test_hia_program_native_review.DirectNativeIndependentReview.test_zero_byte_memory_operations_call_neither_allocator_nor_libc_memory',
 'tests.test_hia_program_native_review.DirectNativeProfileReview.test_future_verifier_admission_cannot_silently_extend_machine_lowering',
 'tests.test_hia_program_native_review.DirectNativeProfileReview.test_nonexported_core_hook_name_stays_a_private_renamed_function',
 'tests.test_hia_program_native_review.DirectNativeProfileReview.test_public_loader_hook_symbols_rejected_before_object_publication',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_all_integer_cast_pairs_at_both_sides_of_each_destination_boundary',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_division_remainder_shift_comparison_and_negation_boundaries',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_independent_vm_agrees_on_edge_semantics',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_linked_text_changes_only_declared_call_displacements',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_many_arguments_dirty_high_bits_parallel_edges_multiple_returns_and_large_frame',
 'tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_signed_unsigned_arithmetic_boundaries',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_direct_byte_object_emission_needs_no_llvm_or_subprocess',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_explicit_scalar_contract_and_public_resource_results_stay_closed',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_invalid_bounds_types_unknown_and_duplicate_names_fail_closed',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_and_instruction_mutations_cannot_reuse_origin',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_is_explicit_and_never_broadens_default_scalar_abi',
 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_public_loader_hook_name_is_rejected',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_invocation_owns_copies_and_preserves_costs',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_runner_contains_real_core_traps_and_infinite_loops',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_explicit_v2_machine_plan_preserves_byte_admission_and_native_output',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_extent_null_and_unsigned_address_wrap_reject_before_access',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_missing_launch_or_cleanup_evidence_never_claims_confirmed_termination',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_mixed_register_stack_argument_expansion_preserves_narrow_types',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_mutable_overlap_is_rejected_and_adjacent_ranges_are_allowed',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_ordinary_core_error_and_all_u32_status_values_remain_distinct',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_readonly_overlap_and_empty_mutable_ranges_are_allowed',
 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_real_source_output_buffers_and_surrounding_canaries',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_abort_snapshot_preserves_writes_and_detects_a_changed_prefix',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_adoption_consumer_bytes_survive_rollback_and_release_fences',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_cold_consumer_processes_preserve_lease_and_release_across_rollback',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_every_warmup_and_repetition_starts_with_fresh_owned_bytes',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_explicit_profile_exports_real_bytes_and_retains_abi_in_build',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_invalid_byte_shapes_and_extent_never_enter_native_execution',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_mixed_register_stack_scalars_and_empty_buffers_are_exact',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_normal_scalar_workload_does_not_opt_into_buffer_exports',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_refinement_stays_unsupported_and_required_proof_blocks_adoption',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_same_output_status_cannot_hide_changed_buffer_bytes',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_timeout_retains_partial_external_write_but_never_success',
 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_workload_byte_budget_and_duplicate_exports_are_rejected_at_context',
 'tests.test_hia_agent_native_lease_snapshot.LeaseSnapshotTests.test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers')
PUBLIC_ENTRIES = ('_implementation_hash', 'validate_block_layout_plan', 'emit_program_machine', '_inspect_object', '_read_artifact', '_run_logged', '_host', 'compile_program_machine', 'build_program_machine')

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def admit_original_discovery(loaded, loader_errors):
    if (len(loaded) != 114 or tuple(loaded) != EXPECTED_IDS
            or len(set(loaded)) != 114 or loader_errors):
        raise ValueError('exact original 114 ordered retained caller discovery required')


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def _bytes_pin(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _file_observation(path, maximum):
    requested = Path(path).resolve(strict=True)
    before = requested.stat()
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)
    descriptor = os.open(requested, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum
                or identity(opened) != identity(before)):
            raise ValueError('bounded ordinary native-build build file required')
        raw = stream.read(maximum + 1)
        if (len(raw) != opened.st_size or identity(os.fstat(stream.fileno())) != identity(opened)):
            raise ValueError('native-build build file changed during read')
    if identity(requested.stat()) != identity(before):
        raise ValueError('native-build build file changed after read')
    return {'path': str(requested), 'bytes': len(raw),
            'sha256': sha256(raw).hexdigest(), 'identity': list(identity(before))}, raw


def _bundle_observation(manifest):
    manifest_pin, raw = _file_observation(manifest, 16384)
    value = json.loads(raw)
    name = value['image_path']
    if type(name) is not str or not name or Path(name).name != name:
        raise ValueError('one-component native-build image filename required')
    image_pin, _ = _file_observation(Path(manifest_pin['path']).parent / name, 1 << 20)
    if image_pin['sha256'] != value['image_sha256']:
        raise ValueError('native-build image file differs from selected manifest')
    return {'manifest': manifest_pin, 'image': image_pin}, raw


def _development_sources():
    # Development scope is explicit; this map is not a cold source closure.
    from tools.hia_selfhost_contract import SOURCE_FILES
    return {name: _bytes_pin(ROOT / name)
            for name in sorted(set(SOURCE_FILES) | set(DEVELOPMENT_INPUT_NAMES) | set(MODULE_SOURCE_PINS) |
                               {p.relative_to(ROOT).as_posix() for p in (ROOT / 'hepta').rglob('*.py')})}


def qualify(output, *, cold_report=None, development_manifest=None):
    output = Path(output)
    if (cold_report is None) == (development_manifest is None):
        raise ValueError('choose exactly one current cold report or development manifest')
    output.mkdir(mode=0o700)
    report = {
        'schema': 'hepta.hia.native-build-callers.v1', 'status': 'HOLD',
        'scope': ('MATCHING_SOURCE_COLD_BUILD' if cold_report is not None
                  else 'EXPLICIT_DEVELOPMENT_ONLY_NOT_COLD'),
        'modules': list(MODULES),
        'whole_native_build_qualified': False, 'whole_native_delivery_qualified': False,
        'default_activated': False, 'original_limits_changed': False,
        'original_machine_count': 51, 'original_core_count': 50,
        'additional_buffer_and_lease_count': 13,
        'CPython_all_foreign_domains_proved': False,
        'retained_writer_calls': [], 'loader_errors': [],
        'expected_test_ids': list(EXPECTED_IDS), 'expected_count': 114,
        'expected_module_sources': MODULE_SOURCE_PINS,
        'original_module_sources': ORIGINAL_MODULE_SOURCE_PINS,
        'caller_input_scope': 'EXACT_CANONICAL_MAIN_PROJECTION_OF_ORIGINAL_114',
    }
    failure = None
    started = time.monotonic()
    sources = None
    before = None
    bundle_before = None
    try:
        module_sources = {name: _bytes_pin(ROOT / name) for name in MODULE_SOURCE_PINS}
        report['actual_module_sources'] = module_sources
        if module_sources != MODULE_SOURCE_PINS:
            raise ValueError('original 4b retained caller module bytes differ')
        report['canonical_caller_projection'] = admit_canonical_caller_source(
            (ROOT / CANONICAL_CALLER_PATH).read_bytes())
        if cold_report is not None:
            cold_report = Path(cold_report)
            cold_raw = cold_report.read_bytes()
            cold = json.loads(cold_raw)
            nested = json.loads(Path(cold['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(output / 'qualified', compiler, cold_report)
            report['cold_report_sha256'] = sha256(cold_raw).hexdigest()
            sources = current_sources
        else:
            manifest = Path(development_manifest).resolve(strict=True)
            sources = _development_sources
        before = sources()
        report['source_before'] = before
        bundle_before, manifest_raw = _bundle_observation(manifest)
        report['bundle_before'] = bundle_before
        from hepta import hia_program_native as public
        from hepta.hia_native_build_selection import installed_native_build
        from hepta.hia_native_build_native import NativeBuildFrame
        native = installed_native_build(str(manifest), vars(public))
        if native.image_sha256 != bundle_before['image']['sha256']:
            raise ValueError('mapped native-build image differs from observed file')
        from collections import Counter
        calls = Counter()
        frames = Counter()
        actual_prepare = native.prepare
        actual_invoke = NativeBuildFrame._invoke
        def observed_prepare(name, arguments, captures=(), *, witness=None):
            result = actual_prepare(name, arguments, captures, witness=witness)
            calls[str(name)] += 1
            return result
        def observed_invoke(frame, command, *args, **kwargs):
            result = actual_invoke(frame, command, *args, **kwargs)
            frames[(frame.mode, command, result, frame.image.image_sha256)] += 1
            return result

        def forbidden(*unused, **ignored):
            report['retained_writer_calls'].append('native_build_policy')
            raise AssertionError('retained native-build writer entered the selected caller gate')

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(MODULES)
        report['loader_errors'] = list(loader.errors)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_test_ids'] = loaded
        report['tests_loaded'] = len(loaded)
        admit_original_discovery(loaded, report['loader_errors'])
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'HEPTA_HIA_NATIVE_BUILD_MANIFEST': str(manifest)}))
            # Only this coordinator's nine retained policy bodies are poisoned.
            # Separately declared, unselected subowners still have their own
            # original error helpers; they are not claimed by this gate.
            for name in PUBLIC_ENTRIES:
                stack.enter_context(patch.object(public, '_reference_' + name.lstrip('_'), forbidden))
            stack.enter_context(patch.object(native, 'prepare', observed_prepare))
            stack.enter_context(patch.object(NativeBuildFrame, '_invoke', observed_invoke))
            result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        counts = {
            'errors': len(result.errors), 'failures': len(result.failures),
            'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
        }
        native_delta = dict(calls)
        report.update(
            tests_run=result.testsRun, executed_test_ids=result.executed,
            anomaly_counts=counts, native_operation_counts=native_delta,
            actual_native_frame_counts=[{'mode': key[0], 'command': key[1], 'status': key[2],
                                        'image_sha256': key[3], 'count': count}
                                       for key, count in sorted(frames.items())],
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            manifest_sha256=sha256(manifest_raw).hexdigest(),
            image_sha256=native.image_sha256,
        )
        if (result.testsRun != 114 or result.executed != loaded
                or any(counts.values()) or report['retained_writer_calls']
                or not frames or any(native_delta.get(name, 0) <= 0 for name in (*PUBLIC_ENTRIES, '_reject'))
                or manifest.read_bytes() != manifest_raw):
            raise ValueError('complete retained native-build caller conjunction failed')
        if cold_report is not None and cold_report.read_bytes() != cold_raw:
            raise ValueError('cold input changed during caller qualification')
        report['status'] = 'SELECTED_NATIVE_BUILD_CALLERS_PASS'
    except BaseException as exc:
        failure = exc
        report['failure'] = {
            'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
        }
    finally:
        try:
            if bundle_before is not None:
                bundle_after, _ = _bundle_observation(manifest)
                report['bundle_after'] = bundle_after
                if bundle_after != bundle_before:
                    raise ValueError('native-build manifest or actual executable file changed')
                report['bundle_stable'] = True
            if before is not None:
                report['source_after'] = sources()
                if report['source_after'] != before:
                    raise ValueError('retained caller source changed')
                report['source_stable'] = True
        except BaseException as exc:
            report['status'] = 'HOLD'
            report['source_failure'] = {
                'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
            }
            if failure is None:
                failure = exc
        report['seconds'] = time.monotonic() - started
        if failure is not None:
            report['status'] = 'HOLD'
        with (output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
    if failure is not None:
        raise failure
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    args = parser.parse_args()
    value = qualify(args.output, cold_report=args.cold_report,
                    development_manifest=args.development_manifest)
    print(json.dumps({'status': value['status'], 'tests_run': value['tests_run']}))


if __name__ == '__main__':
    main()
