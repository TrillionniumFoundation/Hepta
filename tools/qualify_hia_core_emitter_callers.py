"""Qualify complete original lowering callers with retained control disabled."""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from tools.qualify_hia_machine_encoding_native_callers import ORIGINAL_MODULES, flatten, strict_pass
from hepta.hia_core_emitter_selection import (
    SELECTOR, ABI_SOURCE, checked_abi, source_names, installed_core_emitter, active_core_emitter)
from hepta.hia_core_emitter_native import NativeCoreEmitter
from hepta.hia_core_lowering_native import LoweringSession
from hepta import hia_program_native as backend

COMPONENT_MODULES = ('tests.test_hia_core_emitter_native',)
CORE_MODULES = (
    'tests.test_hia_program_native', 'tests.test_hia_program_native_review',
    'tests.test_hia_machine_lowering_edges', 'tests.test_hia_native_byte_abi',
)
ORIGINAL_IDS = [
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_all_general_registers_rex_arithmetic_shifts_conditions_and_internal_calls",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_external_allocator_relocations_resolve_with_only_ld",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_independent_elf_and_isa_tools_accept_output",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_memory_sib_displacements_lea_and_low_byte_rex",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_elf_symbol_order_and_stack_flags",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_invalid_registers_immediates_labels_and_relocations_reject",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_relocation_and_local_branches_are_deterministic",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_immediate_boundaries_and_live_flags_on_real_machine",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_independent_scratch_selection_and_layout_observations",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_requested_alignment_survives_elf_linking_and_loading",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_default_plan_is_byte_identical_and_plan_changes_are_sealed",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_each_choice_is_explicit_and_core_bound",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_encoder_rejects_unreviewed_registers_and_choices",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_arithmetic_retains_overflow_abort",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_indices_retain_trap_before_partial_memory_write",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_assigned_scalars_and_disjoint_register_reuse",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_caller_mutation_after_lifetime_check_cannot_change_emitted_registers",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_changed_plans_preserve_requested_loaded_symbol_alignment",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_cmov_preserves_signed_unsigned_boolean_and_unit_value_representations",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_cmov_selects_both_full_width_values_under_all_plans",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_failed_campaign_arm_retains_all_attempts_and_costs",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_independent_sysv_witness_preserves_all_callee_saved_registers_and_stack_arguments",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_permuted_backedges_and_reordered_blocks_preserve_staged_inputs",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_register_values_survive_calloc_memset_and_free",
    "tests.test_hia_machine_registers.ScalarRegisterExecutionTests.test_register_values_survive_internal_calls_multiple_results_and_recursion",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_dead_parameter_and_dead_definition_writes_cannot_clobber_live_values",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_default_v3_preserves_canonical_bytes_and_needs_every_explicit_field",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_disjoint_lifetimes_and_separate_blocks_have_independent_witnesses",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_live_inputs_outputs_and_branch_condition_interfere",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plain_json_v1_v2_v3_plans_keep_their_machine_bytes",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plan_snapshot_bounds_cycles_depth_fanout_and_bytes_before_semantic_checks",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_plan_snapshot_rejects_copy_and_equality_hooks_before_running_them",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_unreviewed_locations_types_and_unknown_values_fail_closed",
    "tests.test_hia_machine_registers.ScalarRegisterValidationTests.test_validated_assignments_are_immutable_and_sealed_in_native_images",
    "tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_borrowed_byte_addresses_lengths_returns_and_prewrite_traps",
    "tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_checked_arithmetic_traps_after_placing_inputs_in_new_registers",
    "tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_dirty_register_inputs_stack_arguments_page_probe_and_callee_saves",
    "tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_every_leaf_scalar_opcode_keeps_live_r8_r9_against_vm",
    "tests.test_hia_machine_leaf_registers.LeafRegisterExecutionTests.test_parallel_loop_edges_multi_result_and_unassigned_stack_values",
    "tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_entire_function_gate_rejects_calls_allocations_and_recursive_calls",
    "tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_r8_swap_scratch_resources_and_overlapping_lifetimes_are_refused",
    "tests.test_hia_machine_leaf_registers.LeafRegisterValidationTests.test_v4_is_opt_in_and_v3_keeps_its_register_boundary",
    "tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor",
    "tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_one_plan_receipt_cannot_authorize_different_layout",
    "tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused",
    "tests.test_hia_agent_native_machine_choices.ExplicitMachineChoicesTests.test_separate_checks_and_assumptions_remain_in_verification_receipt",
    "tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor",
    "tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_one_plan_receipt_cannot_authorize_different_layout",
    "tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused",
    "tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_register_lifetimes_are_retained_without_claiming_identical_slots",
    "tests.test_hia_agent_native_machine_choices.ScalarRegisterChoicesTests.test_unknown_value_register_assignment_is_refused_through_domain_tools"
]
CORE_IDS = [
    "tests.test_hia_program_native.DirectExecutionTests.test_all_integer_widths_wrapping_bits_shifts_and_signed_division",
    "tests.test_hia_program_native.DirectExecutionTests.test_allocator_observer_checks_actual_frees_and_failed_allocation",
    "tests.test_hia_program_native.DirectExecutionTests.test_bulk_operations_v2_through_v6_match_vm",
    "tests.test_hia_program_native.DirectExecutionTests.test_checked_arithmetic_comparisons_casts_and_unary",
    "tests.test_hia_program_native.DirectExecutionTests.test_checked_failures_abort_in_isolated_native_processes",
    "tests.test_hia_program_native.DirectExecutionTests.test_owned_memory_zero_initialization_and_ordinary_error_cleanup",
    "tests.test_hia_program_native.DirectExecutionTests.test_real_loops_calls_multiple_returns_and_parallel_block_moves",
    "tests.test_hia_program_native.DirectExecutionTests.test_recursive_chain_and_composite_v7_have_real_dynamic_execution",
    "tests.test_hia_program_native.DirectExecutionTests.test_scalar_c_abi_register_and_stack_arguments",
    "tests.test_hia_program_native.DirectExecutionTests.test_v8_chain_head_returned_loans_and_pop",
    "tests.test_hia_program_native.DirectExecutionTests.test_v8_parameter_loans_calls_cfg_recursion_and_aliases",
    "tests.test_hia_program_native.DirectObjectTests.test_all_versioned_agent_core_examples_are_emitted_without_llvm",
    "tests.test_hia_program_native.DirectObjectTests.test_artifact_mutation_rejected_even_with_recomputed_object_digest",
    "tests.test_hia_program_native.DirectObjectTests.test_cli_native_object_and_explicit_target_rejection",
    "tests.test_hia_program_native.DirectObjectTests.test_existing_output_is_preserved",
    "tests.test_hia_program_native.DirectObjectTests.test_foreign_target_is_explicitly_rejected",
    "tests.test_hia_program_native.DirectObjectTests.test_forged_verified_core_is_reverified_before_emission",
    "tests.test_hia_program_native.DirectObjectTests.test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch",
    "tests.test_hia_program_native.DirectObjectTests.test_object_generation_is_deterministic_and_bound_to_exact_core",
    "tests.test_hia_program_native.DirectObjectTests.test_route_inventory_names_explicit_direct_machine_selection",
    "tests.test_hia_program_native.DirectSystemLinkerTests.test_cli_native_shared_library_is_callable_with_ld",
    "tests.test_hia_program_native.DirectSystemLinkerTests.test_system_linker_alone_produces_callable_shared_library",
    "tests.test_hia_program_native_review.DirectNativeIndependentReview.test_dirty_high_bits_callee_saves_stack_arguments_and_page_probe",
    "tests.test_hia_program_native_review.DirectNativeIndependentReview.test_invalid_complete_ranges_trap_before_any_partial_write",
    "tests.test_hia_program_native_review.DirectNativeIndependentReview.test_zero_byte_memory_operations_call_neither_allocator_nor_libc_memory",
    "tests.test_hia_program_native_review.DirectNativeProfileReview.test_future_verifier_admission_cannot_silently_extend_machine_lowering",
    "tests.test_hia_program_native_review.DirectNativeProfileReview.test_nonexported_core_hook_name_stays_a_private_renamed_function",
    "tests.test_hia_program_native_review.DirectNativeProfileReview.test_public_loader_hook_symbols_rejected_before_object_publication",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_all_integer_cast_pairs_at_both_sides_of_each_destination_boundary",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_division_remainder_shift_comparison_and_negation_boundaries",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_independent_vm_agrees_on_edge_semantics",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_linked_text_changes_only_declared_call_displacements",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_many_arguments_dirty_high_bits_parallel_edges_multiple_returns_and_large_frame",
    "tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_signed_unsigned_arithmetic_boundaries",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_direct_byte_object_emission_needs_no_llvm_or_subprocess",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_explicit_scalar_contract_and_public_resource_results_stay_closed",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_invalid_bounds_types_unknown_and_duplicate_names_fail_closed",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_and_instruction_mutations_cannot_reuse_origin",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_is_explicit_and_never_broadens_default_scalar_abi",
    "tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_public_loader_hook_name_is_rejected",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_invocation_owns_copies_and_preserves_costs",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_runner_contains_real_core_traps_and_infinite_loops",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_explicit_v2_machine_plan_preserves_byte_admission_and_native_output",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_extent_null_and_unsigned_address_wrap_reject_before_access",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_missing_launch_or_cleanup_evidence_never_claims_confirmed_termination",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_mixed_register_stack_argument_expansion_preserves_narrow_types",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_mutable_overlap_is_rejected_and_adjacent_ranges_are_allowed",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_ordinary_core_error_and_all_u32_status_values_remain_distinct",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_readonly_overlap_and_empty_mutable_ranges_are_allowed",
    "tests.test_hia_native_byte_abi.ByteABINativeTests.test_real_source_output_buffers_and_surrounding_canaries"
]
HELPERS = ()


def source_pins():
    from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests
    values = file_digests(ROOT)
    abi_raw = (ROOT / ABI_SOURCE).read_bytes()
    for name in (CONTRACT_PATH, ABI_SOURCE, 'tools/hia_core_emitter_policy.py',
                 'tools/hia_core_emitter_ir.py', 'tools/generate_hia_core_emitter.py',
                 'tools/build_hia_core_emitter.py',
                 'tools/qualify_hia_core_emitter_callers.py',
                 'tests/test_hia_core_emitter_native.py',
                 'tests/fixtures/hia_program_native_608.py.txt',
                 *source_names(checked_abi(abi_raw))):
        values[name] = sha256((ROOT / name).read_bytes()).hexdigest()
    return values


def bundle_files(manifest):
    raw = manifest.read_bytes()
    result = [(manifest, raw)]
    value = json.loads(raw)
    for name, relative in value['unit_manifests'].items():
        unit_path = manifest.parent / relative
        unit_raw = unit_path.read_bytes()
        unit = json.loads(unit_raw)
        image = (unit_path.parent / unit['image_path']).resolve(strict=True)
        result.extend(((unit_path, unit_raw), (image, image.read_bytes())))
    return result


def copy_bundle(original, destination):
    """Copy exact admitted mappings for one new development evidence root."""
    installed_core_emitter(str(original), vars(backend))
    before = bundle_files(original)
    destination.mkdir(mode=0o700)
    value = json.loads(before[0][1])
    for name, relative in value['unit_manifests'].items():
        old_path = original.parent / relative
        old = json.loads(old_path.read_bytes())
        image = (old_path.parent / old['image_path']).resolve(strict=True)
        raw = image.read_bytes()
        if sha256(raw).hexdigest() != old['image_sha256']:
            raise ValueError('development lowering image differs from its manifest')
        folder = destination / name
        folder.mkdir(mode=0o700)
        (folder / 'image.bin').write_bytes(raw)
        old['image_path'] = 'image.bin'
        (folder / 'manifest.json').write_text(json.dumps(old, indent=2, sort_keys=True) + '\n')
    path = destination / 'manifest.json'
    path.write_bytes(before[0][1])
    if any(p.read_bytes() != raw for p, raw in before):
        raise ValueError('original development lowering bundle changed during copy')
    installed_core_emitter(str(path), vars(backend))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--with-core-lowering', action='store_true',
                        help='Also admit and require the independent Core Function owner for original callers.')
    parser.add_argument('--paired-development-manifest', type=Path,
                        help='Explicit development-only Core Function bundle; requires --with-core-lowering.')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--development-group', choices=('component', 'original-machine', 'original-core'),
                        help='Run exactly one complete development group; never establishes whole qualification.')
    args = parser.parse_args()
    if args.development_group and args.cold_report:
        parser.error('--development-group is forbidden with --cold-report')
    if args.paired_development_manifest and (not args.with_core_lowering or args.cold_report):
        parser.error('paired development manifest requires development-only paired selection')
    if args.with_core_lowering and not (args.cold_report or args.paired_development_manifest):
        parser.error('paired selection requires its matching cold or explicit development bundle')
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    report = {
        'schema': 'hepta.hia.core-emitter-selected-callers.v1', 'status': 'STARTED',
        'scope': ('EXPLICIT_DEVELOPMENT_GROUP_ONLY' if args.development_group else
                  'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY'),
        'development_group': args.development_group,
        'complete_three_groups_required_for_qualification': True,
        'complete_three_groups_executed': False,
        'groups': [], 'retained_owner_entries': [], 'python': sys.version,
        'native_step_ledger_schema': 'hepta.hia.core-emitter-native-step-returns.v1',
        'native_step_return_semantics': 'Actual admitted HIA unit entry and output framing returned status0/1/2; not method or product success.',
        'native_mode_entries_are_attempts': True,
        'public_control_mode_count': 6, 'abi_control_mode_count': 6,
        'private_fixture_modes': [],
        'native_step_unit_index_basis': 'owner.images excludes literal pool; unit_index0 is core_emitter_000; bundle_image_index is unit_index+1; complete bundle index0 is core_emitter_pool.',
        'component_denominator': 11, 'original_machine_denominator': 51,
        'original_core_denominator': 50, 'original_methods_modified': False,
        'hosted_primitive_kinds': 18, 'Emitter_control_still_hosted': False, 'object_runtime_and_ELF_wrapper_still_hosted': True,
        'default_activated': False, 'whole_native_claimed': False,
    }
    started = time.monotonic()
    before = source_pins()
    report['source_before'] = before
    inputs, component_inputs = [], []
    report['group_bundle_roles'] = {
        'component': 'component', 'original-machine': 'caller', 'original-core': 'caller'}
    report['bundle_observations'] = {}
    expected_groups = ({args.development_group} if args.development_group else
                       {'component', 'original-machine', 'original-core'})
    expected_roles = {'caller', 'component'} if 'component' in expected_groups else {'caller'}
    report['expected_groups'] = sorted(expected_groups)
    report['expected_bundle_roles'] = sorted(expected_roles)
    def observed_inputs(manifest_path):
        values = bundle_files(manifest_path)
        build_receipt = manifest_path.parent / 'build.json'
        if args.cold_report or build_receipt.is_file():
            values.append((build_receipt, build_receipt.read_bytes()))
        return values
    def bindings(values):
        return [{'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                for path, raw in values]
    def describe_bundle(manifest_path, owner, values, scope):
        loaded = owner._admitted_bundle
        return {
            'scope': scope, 'manifest': str(manifest_path),
            'manifest_sha256': sha256(manifest_path.read_bytes()).hexdigest(),
            'abi_sha256': loaded.abi_sha256,
            'bundle_sha256': loaded.bundle_sha256,
            'unit_names': list(loaded.names),
            'unit_image_sha256': [image.image_sha256 for image in loaded.images],
            'source_sha256': dict(loaded.source_hashes),
            'input_bindings_before': bindings(values),
        }
    entries, actual_steps, per_test = Counter(), Counter(), Counter()
    paired_steps = Counter()
    paired_inputs = []
    paired_manifest = paired_owner = None
    mode_returns, group_attempts, step_returns = Counter(), Counter(), Counter()
    current = ['outside-test']
    current_group = ['outside-group']
    # Cache only immutable instrumentation descriptions, never a semantic
    # decision or foreign observation. Values retain each actual owner so ids
    # cannot be reused while a ledger description survives.
    owner_mode_records = {}
    original_invoke, original_step = NativeCoreEmitter.invoke, LoweringSession.step
    def invoke(owner, name, arguments):
        admitted = isinstance(owner, NativeCoreEmitter) and hasattr(owner, '_admitted_bundle')
        if admitted:
            entries[name] += 1
            per_test[current[0]] += 1
            group_attempts[(current_group[0], name)] += 1
        result = original_invoke(owner, name, arguments)
        if admitted:
            mode_returns[(current_group[0], name)] += 1
        return result
    def step(session, packet):
        owner = session.owner
        admitted = isinstance(owner, NativeCoreEmitter) and hasattr(owner, '_admitted_bundle')
        record = None
        if admitted:
            saved = getattr(session, '_qualification_step_records', None)
            if saved is None or saved[0] != current_group[0]:
                number = int.from_bytes(session.initial[24:32], 'little')
                key = (id(owner), current_group[0], number)
                cached = owner_mode_records.get(key)
                if cached is None:
                    loaded = owner._admitted_bundle
                    names = [name for name, mode in owner.modes.items()
                             if mode['number'] == number]
                    if len(names) != 1 or len(owner.images) + 1 != len(loaded.images):
                        raise AssertionError('native ledger mode/image inventory differs')
                    records = []
                    for index, image in enumerate(owner.images):
                        if image is not loaded.images[index + 1]:
                            raise AssertionError('native ledger image is not the admitted unit')
                        records.append((current_group[0], names[0], number, index,
                            loaded.names[index + 1], image.image_sha256,
                            loaded.abi_sha256, loaded.bundle_sha256))
                    cached = (owner, tuple(records))
                    owner_mode_records[key] = cached
                saved = (current_group[0], cached[1])
                session._qualification_step_records = saved
            record = saved[1][session.unit]
        # Record only after the actual entry and its bridge frame admission
        # return normally. A later HIA-selected RAISE observation can still
        # reject the method; it must not be mislabeled a successful method.
        result = original_step(session, packet)
        if admitted:
            actual_steps[str(result)] += 1
            step_returns[(*record, result)] += 1
        elif paired_owner is not None and owner is paired_owner:
            paired_steps[(current_group[0], result)] += 1
        return result
    def forbid(name):
        def reject(*arguments, **keywords):
            report['retained_owner_entries'].append(name)
            raise AssertionError('retained Core emitter owner entered: ' + name)
        return reject
    def helper_guard(name, original):
        def guarded(*arguments, **keywords):
            # These five helpers also reject inputs before ordinary emit entry.
            # Their old behavior outside the captured lowering scope is retained.
            if active_core_emitter() is not None:
                return forbid(name)(*arguments, **keywords)
            return original(*arguments, **keywords)
        return guarded
    try:
        if args.with_core_lowering:
            from hepta.hia_core_lowering_selection import installed_core_lowering
            if args.cold_report:
                from tools.build_hia_core_lowering import build as build_function
                outer = json.loads(args.cold_report.read_bytes())
                nested = json.loads(Path(outer['nested_report']).read_bytes())
                paired_manifest = build_function(directory / 'paired-function-build',
                    Path(nested['generations'][-1]['produced_image']), args.cold_report)
            else:
                paired_manifest = args.paired_development_manifest.resolve(strict=True)
            paired_owner = installed_core_lowering(str(paired_manifest), vars(backend))
            paired_inputs = bundle_files(paired_manifest)
            report['paired_function_bundle'] = dict(manifest=str(paired_manifest),
                source_sha256=dict(paired_owner._admitted_bundle.source_hashes),
                image_sha256=[im.image_sha256 for im in paired_owner._admitted_bundle.images],
                input_bindings_before=bindings(paired_inputs))
        if args.cold_report:
            from tools.build_hia_core_emitter import build
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            manifest = build(directory / 'build', Path(nested['generations'][-1]['produced_image']), args.cold_report)
        else:
            source_manifest = args.development_manifest.resolve(strict=True)
            manifest = copy_bundle(source_manifest, directory / 'build')
            report['original_development_manifest'] = str(source_manifest)
            report['original_development_manifest_sha256'] = sha256(source_manifest.read_bytes()).hexdigest()
        native = installed_core_emitter(str(manifest), vars(backend))
        inputs = observed_inputs(manifest)
        report['bundle_observations']['caller'] = describe_bundle(
            manifest, native, inputs,
            'MATCHING_SOURCE_COLD_BUILD' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY')
        report.update(manifest=str(manifest), manifest_sha256=sha256(manifest.read_bytes()).hexdigest(),
                      abi_sha256=native._admitted_bundle.abi_sha256,
                      complete_image_sha256=[image.image_sha256 for image in native._admitted_bundle.images],
                      input_bindings=[{'path': str(p), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                                      for p, raw in inputs])
        with patch.object(NativeCoreEmitter, 'invoke', invoke), patch.object(LoweringSession, 'step', step):
            for label, modules, count, expected_ids, guard_reference in (
                ('component', COMPONENT_MODULES, 11, None, False),
                ('original-machine', ORIGINAL_MODULES, 51, ORIGINAL_IDS, True),
                ('original-core', CORE_MODULES, 50, CORE_IDS, True)):
                if label not in expected_groups:
                    continue
                current_group[0] = label
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromNames(modules)
                loaded = [test.id() for test in flatten(suite)]
                executed = []
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        current[0] = test.id()
                        executed.append(test.id())
                        # unittest has completed this class's single actual
                        # setUpClass before startTest. Capture its build once
                        # before any method; never call setUpClass again.
                        if label == 'component' and not component_inputs and hasattr(type(test), 'manifest'):
                            component_manifest = Path(type(test).manifest).resolve(strict=True)
                            expected_component = (directory / 'component-fixture' / 'qualified' / 'manifest.json'
                                                  if args.cold_report else manifest)
                            if component_manifest != expected_component.resolve(strict=True):
                                raise AssertionError('component selected the wrong fresh bundle')
                            component_inputs.extend(observed_inputs(component_manifest))
                            report['bundle_observations']['component'] = describe_bundle(
                                component_manifest, type(test).owner, component_inputs, type(test).scope)
                        super().startTest(test)
                row = {'label': label, 'modules': list(modules), 'expected_methods': count,
                       'loaded_ids': loaded, 'loader_errors': list(loader.errors),
                       'frozen_original_ids': list(expected_ids) if expected_ids is not None else None}
                report['groups'].append(row)
                if (loader.errors or len(loaded) != count or len(set(loaded)) != count
                        or (expected_ids is not None and loaded != list(expected_ids))):
                    raise AssertionError('complete original caller identity differs: ' + label)
                with ExitStack() as stack:
                    if guard_reference:
                        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
                        for name, method in backend._Emitter.__dict__.items():
                            if inspect.isfunction(method) and name != '__new__':
                                stack.enter_context(patch.object(backend._Emitter, name, forbid('_Emitter.' + name)))
                        for name in HELPERS:
                            legacy = '_reference' + name
                            stack.enter_context(patch.object(backend, legacy,
                                helper_guard(legacy, getattr(backend, legacy))))
                        if paired_owner is not None:
                            from hepta.hia_core_lowering_selection import active_core_lowering
                            stack.enter_context(patch.dict(os.environ, {
                                'HEPTA_HIA_CORE_LOWERING_MANIFEST': str(paired_manifest)}))
                            for name, method in backend._Function.__dict__.items():
                                if inspect.isfunction(method) and name != '__new__':
                                    stack.enter_context(patch.object(backend._Function, name,
                                        forbid('_Function.' + name)))
                            for name in ('_reject', '_words', '_bounds', '_normalize', '_prologue'):
                                legacy = '_reference' + name
                                original_helper = getattr(backend, legacy)
                                def guarded_helper(*a, _name=legacy, _old=original_helper, **kw):
                                    if active_core_lowering() is not None:
                                        return forbid(_name)(*a, **kw)
                                    return _old(*a, **kw)
                                stack.enter_context(patch.object(backend, legacy, guarded_helper))
                    else:
                        stack.enter_context(patch.dict(os.environ, {
                            SELECTOR: '',
                            'HEPTA_HIA_CORE_EMITTER_COLD_REPORT': str(args.cold_report.resolve()) if args.cold_report else '',
                            'HEPTA_HIA_CORE_EMITTER_DEVELOPMENT_MANIFEST': '' if args.cold_report else str(manifest),
                            'HEPTA_HIA_CORE_EMITTER_FIXTURE_EVIDENCE': str(directory / 'component-fixture')}))
                    at = time.monotonic()
                    with (directory / (label + '.unittest.log')).open('x') as log:
                        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
                    row['seconds'] = time.monotonic() - at
                row.update(executed_ids=executed, tests_run=result.testsRun)
                for key in ('errors', 'failures', 'skipped', 'expectedFailures'):
                    row[key] = [[test.id(), detail] for test, detail in getattr(result, key)]
                row['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
                row['strict_pass'] = strict_pass(result, loaded, executed)
                if not row['strict_pass']:
                    raise AssertionError('complete caller group failed: ' + label)
        required = set(native.modes)
        observed_modes = {row[1] for row, count in step_returns.items() if count > 0}
        observed_groups = {row[0] for row, count in step_returns.items() if count > 0}
        if report['retained_owner_entries'] or observed_groups != expected_groups or not step_returns:
            raise AssertionError('selected complete group did not enter actual HIA lowering')
        report['all_required_modes_attempted'] = required <= set(entries)
        report['all_required_modes_have_actual_step_returns'] = required <= observed_modes
        report['all_native_step_statuses_observed'] = all(actual_steps[str(v)] for v in (0, 1, 2))
        if not args.development_group:
            if (not report['all_required_modes_attempted']
                    or not report['all_required_modes_have_actual_step_returns']
                    or not report['all_native_step_statuses_observed']):
                raise AssertionError('complete actual HIA lowering policy/continuation ownership was not observed')
            report['complete_three_groups_executed'] = True
        if paired_owner is not None:
            report['paired_actual_native_step_returns'] = [
                dict(group=group, status=status, count=count)
                for (group, status), count in sorted(paired_steps.items())]
            for group in expected_groups - {'component'}:
                if not any(key[0] == group and count for key, count in paired_steps.items()):
                    raise AssertionError('paired Core Function owner did not return native steps: ' + group)
        report['status'] = 'DEVELOPMENT_GROUP_PASS' if args.development_group else 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    finally:
        report['native_mode_entries'] = dict(entries)
        report['actual_native_step_statuses'] = dict(actual_steps)
        report['per_test_native_mode_entries'] = dict(per_test)
        report['group_native_mode_attempts'] = [
            {'group': group, 'mode': mode, 'count': count}
            for (group, mode), count in sorted(group_attempts.items())]
        report['native_mode_normal_returns'] = [
            {'group': group, 'mode': mode, 'count': count}
            for (group, mode), count in sorted(mode_returns.items())]
        report['native_step_returns'] = [
            {'group': row[0], 'mode': row[1], 'mode_number': row[2],
             'unit_index': row[3], 'bundle_image_index': row[3] + 1, 'unit_name': row[4],
             'image_sha256': row[5], 'abi_sha256': row[6],
             'bundle_sha256': row[7], 'status': row[8], 'count': count}
            for row, count in sorted(step_returns.items())]
        try:
            report['source_after'] = source_pins()
            report['source_stable'] = before == report['source_after']
            for role, values in (('caller', inputs), ('component', component_inputs)):
                observation = report['bundle_observations'].get(role)
                if observation is not None:
                    after = [(path, path.read_bytes()) for path, _ in values]
                    observation['input_bindings_after'] = bindings(after)
                    observation['stable'] = bool(values) and all(
                        old_path == new_path and old_raw == new_raw
                        for (old_path, old_raw), (new_path, new_raw) in zip(values, after))
                report[role + '_bundle_stable'] = bool(
                    observation is not None and observation.get('stable'))
            report['manifest_images_bundle_stable'] = all(
                report[role + '_bundle_stable'] for role in expected_roles)
            if not report['source_stable'] or not report['manifest_images_bundle_stable']:
                report['status'] = 'FAIL'
            if paired_owner is not None:
                after = [(path, path.read_bytes()) for path, _ in paired_inputs]
                report['paired_function_bundle']['input_bindings_after'] = bindings(after)
                report['paired_function_bundle']['stable'] = all(
                    path == current_path and raw == current_raw
                    for (path, raw), (current_path, current_raw) in zip(paired_inputs, after))
                if not report['paired_function_bundle']['stable']:
                    report['status'] = 'FAIL'
        except BaseException:
            report['status'] = 'FAIL'
            report['final_identity_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        (directory / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({k: report.get(k) for k in ('schema', 'scope', 'status', 'seconds',
            'source_stable', 'manifest_images_bundle_stable', 'exception')}, sort_keys=True))
    return 0 if report['status'] in {'PASS', 'DEVELOPMENT_GROUP_PASS'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
