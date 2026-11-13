"""Complete selected Core emitter controls and original 51 + 50 callers.

All seven selected native families are actually admitted on this source.
A development image never substitutes for a requested current-source cold.
Original caller IDs, assertions, compiler limits and process limits remain.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import inspect
import importlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time
import traceback
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from tools.qualify_hia_machine_state_callers import ORIGINAL_MODULES, flatten, strict_pass
from hepta import hia_program_native as backend
from hepta.hia_core_emitter_control_native import NativeCoreEmitter, EmitterFrame, SOURCE
from hepta.hia_core_emitter_control_selection import SELECTOR, installed_core_emitter, active_core_emitter
COMPONENT_MODULES = ('tests.test_hia_core_emitter_control_native',)
COMPONENT_COUNT = 15
HELPERS = ('_reject', '_words', '_bounds', '_normalize', '_prologue')
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

def source_pins():
    paths = {p for folder in ('hepta', 'tools', 'tests')
             for p in (ROOT / folder).rglob('*.py') if '__pycache__' not in p.parts}
    paths.update((ROOT / 'examples/hia_bootstrap').glob('*.hepta'))
    paths.update(p for p in (ROOT / 'tests/fixtures').rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts)
    from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
        SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES,
        BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES,
        MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES)
    paths.update(ROOT / name for name in (
        'setup.py', 'pyproject.toml', 'MANIFEST.in',
        *(tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES +
          SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES +
          BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES +
          MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES)))
    return {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}



def _dependency_module(label):
    # Existing input-map labels stay unchanged; each label names one explicit ABI.
    modules = {
        'machine_plan': 'hepta.hia_machine_plan_control_selection',
        'core_lowering': 'hepta.hia_core_lowering_control_native',
    }
    return importlib.import_module(modules.get(label, 'hepta.hia_' + label + '_native'))


def _dependency_builder(label):
    modules = {
        'machine_plan': 'tools.build_hia_machine_plan_control',
        'core_lowering': 'tools.build_hia_core_lowering_control',
    }
    return importlib.import_module(modules.get(label, 'tools.build_hia_' + label))


def bundle_files(manifest):
    raw = manifest.read_bytes()
    value = json.loads(raw)
    image = (manifest.parent / value['image_path']).resolve(strict=True)
    return [(manifest, raw), (image, image.read_bytes())]


def copy_bundle(original, destination):
    installed_core_emitter(str(original), vars(backend))
    before = bundle_files(original)
    destination.mkdir(mode=0o700)
    value = json.loads(before[0][1])
    raw = before[1][1]
    if sha256(raw).hexdigest() != value['image_sha256']:
        raise ValueError('development emitter image differs from its manifest')
    (destination / 'core_emitter.image.bin').write_bytes(raw)
    value['image_path'] = 'core_emitter.image.bin'
    path = destination / 'manifest.json'
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    if any(p.read_bytes() != data for p, data in before):
        raise ValueError('development emitter inputs changed while copied')
    installed_core_emitter(str(path), vars(backend))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--development-group', choices=('component', 'original-machine', 'original-core'))
    parser.add_argument('--composition-manifests', type=Path,
                        help='explicit development-only JSON map for the six Code/ELF/Plan/Function dependencies')
    args = parser.parse_args()
    if args.development_group and args.cold_report:
        parser.error('partial development groups cannot use a cold report')
    if args.cold_report and args.composition_manifests:
        parser.error('development dependencies cannot override current cold builders')
    if args.development_manifest and not args.composition_manifests:
        parser.error('explicit development requires the complete composition manifest map')
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    before = source_pins()
    report = {
        'schema': 'hepta.hia.core-emitter-selected-callers.v1', 'status': 'STARTED',
        'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
        'development_group': args.development_group,
        'original_machine_denominator': 51, 'original_core_denominator': 50,
        'current_protocol_component_denominator': COMPONENT_COUNT,
        'peer_twelve_old_protocol_results_inherited': False,
        'python': sys.version, 'source_before': before, 'groups': [],
        'retained_owner_entries': [], 'default_activated': False,
        'whole_backend_native': False, 'Emitter_control_still_hosted': False, 'outer_build_control_still_hosted': True, 'foreign_byte_wrapper_still_hosted': True,
    }
    original_invoke, original_entry = NativeCoreEmitter.prepare, EmitterFrame._invoke
    current, group = ['outside-test'], ['outside-group']
    attempts, returns, frames, by_test = Counter(), Counter(), Counter(), Counter()
    inputs = []
    started = time.monotonic()
    def invoke(owner, name, arguments):
        attempts[(group[0], name)] += 1
        result = original_invoke(owner, name, arguments)
        returns[(group[0], name)] += 1
        return result
    def entry(frame, command, *args, **kwargs):
        result = original_entry(frame, command, *args, **kwargs)
        frames[(group[0], frame.mode, command, result, frame.image.image_sha256)] += 1
        by_test[current[0]] += 1
        return result
    def forbid(name):
        def fail(*args, **kwargs):
            report['retained_owner_entries'].append(name)
            raise AssertionError('retained Core emitter owner entered: ' + name)
        return fail
    try:
        if args.cold_report:
            from tools.build_hia_core_emitter_control import build
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            manifest = build(directory / 'build', Path(nested['generations'][-1]['produced_image']), args.cold_report)
        else:
            manifest = copy_bundle(args.development_manifest.resolve(strict=True), directory / 'build')
        owner = installed_core_emitter(str(manifest), vars(backend))
        inputs = bundle_files(manifest)
        dependency_labels = ('machine_encoding', 'machine_state', 'machine_instructions',
                             'machine_elf', 'machine_plan', 'core_lowering')
        if args.cold_report:
            dependency_root = directory / 'composition-dependencies'
            dependency_root.mkdir(mode=0o700)
            compiler = Path(nested['generations'][-1]['produced_image'])
            dependencies = {label: _dependency_builder(label).build(
                dependency_root / label, compiler, args.cold_report) for label in dependency_labels}
        else:
            dependency_raw = args.composition_manifests.read_bytes()
            value = json.loads(dependency_raw)
            if (type(value) is not dict or set(value) != set(dependency_labels)
                    or any(type(path) is not str for path in value.values())):
                raise ValueError('development composition inventory differs')
            dependencies = {label: Path(value[label]).resolve(strict=True) for label in dependency_labels}
            inputs.append((args.composition_manifests, dependency_raw))
        dependency_env = {}
        for label, path in dependencies.items():
            module = _dependency_module(label)
            if label == 'core_lowering':
                from hepta.hia_core_lowering_control_selection import installed_core_lowering
                admitted = installed_core_lowering(str(path), vars(backend))
            else:
                admitted = getattr(module, 'installed_' + label)(str(path))
            record = json.loads(path.read_bytes())
            if (record['compiler_sha256'] != json.loads(manifest.read_bytes())['compiler_sha256']
                    or admitted.admitted_source_sha256 != sha256(module.SOURCE.read_bytes()).hexdigest()):
                raise ValueError('composition input does not match current source/compiler')
            dependency_env[module.SELECTOR] = str(path)
            inputs.extend(bundle_files(path))
        report['composition_dependencies'] = {label: str(path) for label, path in dependencies.items()}
        report['retained_callers_explicitly_select_all_seven_owners'] = True
        report.update(manifest=str(manifest), image_sha256=owner.image_sha256,
                      source_sha256=owner.admitted_source_sha256,
                      input_bindings=[{'path': str(p), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                                      for p, raw in inputs])
        with patch.object(NativeCoreEmitter, 'prepare', invoke), patch.object(EmitterFrame, '_invoke', entry):
            for label, modules, expected, guard_reference in (
                    ('component', COMPONENT_MODULES, None, False),
                    ('original-machine', ORIGINAL_MODULES, ORIGINAL_IDS, True),
                    ('original-core', CORE_MODULES, CORE_IDS, True)):
                if args.development_group and label != args.development_group:
                    continue
                group[0] = label
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromNames(modules)
                loaded = [test.id() for test in flatten(suite)]
                executed = []
                row = {'label': label, 'modules': list(modules), 'loaded_ids': loaded,
                       'loader_errors': list(loader.errors),
                       'frozen_original_ids': list(expected) if expected else None}
                report['groups'].append(row)
                if (loader.errors or not loaded or len(loaded) != len(set(loaded))
                        or expected is not None and loaded != list(expected)
                        or label == 'component' and len(loaded) != COMPONENT_COUNT):
                    raise AssertionError('complete original caller inventory differs: ' + label)
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        current[0] = test.id()
                        executed.append(test.id())
                        super().startTest(test)
                with ExitStack() as stack:
                    if guard_reference:
                        stack.enter_context(patch.dict(os.environ, {**dependency_env, SELECTOR: str(manifest)}))
                        for cls in (backend._Emitter, backend._Function):
                            for name, method in cls.__dict__.items():
                                if inspect.isfunction(method) and name != '__new__':
                                    stack.enter_context(patch.object(cls, name, forbid(cls.__name__ + '.' + name)))
                        for name in HELPERS:
                            original = getattr(backend, '_reference' + name)
                            def guarded(*args, _name=name, _original=original, **kwargs):
                                from hepta.hia_core_lowering_control_selection import active_core_lowering
                                if active_core_lowering() is not None:
                                    return forbid(_name)(*args, **kwargs)
                                return _original(*args, **kwargs)
                            stack.enter_context(patch.object(backend, '_reference' + name, guarded))
                    else:
                        stack.enter_context(patch.dict(os.environ, {
                            SELECTOR: '',
                            'HEPTA_HIA_CORE_EMITTER_CONTROL_COLD_REPORT': str(args.cold_report.resolve()) if args.cold_report else '',
                            'HEPTA_HIA_CORE_EMITTER_CONTROL_DEVELOPMENT_MANIFEST': '' if args.cold_report else str(manifest),
                            'HEPTA_HIA_CORE_EMITTER_CONTROL_FIXTURE_EVIDENCE': str(directory / 'component-fixture'),
                            'HEPTA_HIA_CORE_EMITTER_CONTROL_COMPOSITION_MANIFESTS': '' if args.cold_report else str(args.composition_manifests.resolve())}))
                    at = time.monotonic()
                    with (directory / (label + '.unittest.log')).open('x') as log:
                        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
                    row['seconds'] = time.monotonic() - at
                row.update(executed_ids=executed, tests_run=result.testsRun)
                for name in ('errors', 'failures', 'skipped', 'expectedFailures'):
                    row[name] = [[t.id(), detail] for t, detail in getattr(result, name)]
                row['unexpectedSuccesses'] = [t.id() for t in result.unexpectedSuccesses]
                row['strict_pass'] = strict_pass(result, loaded, executed)
                if not row['strict_pass']:
                    raise AssertionError('complete selected caller group failed: ' + label)
        if report['retained_owner_entries'] or not frames:
            raise AssertionError('selected callers did not return actual native HIA frames')
        expected_groups = {args.development_group} if args.development_group else {
            'component', 'original-machine', 'original-core'}
        if {row['label'] for row in report['groups']} != expected_groups:
            raise AssertionError('complete requested group inventory differs')
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    finally:
        report['seconds'] = time.monotonic() - started
        report['source_after'] = source_pins()
        report['inputs_unchanged'] = before == report['source_after'] and all(p.read_bytes() == raw for p, raw in inputs)
        if not report['inputs_unchanged']:
            report['status'] = 'FAIL'
        report['mode_attempts'] = [{'group': g, 'mode': m, 'count': n} for (g, m), n in sorted(attempts.items())]
        report['mode_returns'] = [{'group': g, 'mode': m, 'count': n} for (g, m), n in sorted(returns.items())]
        report['actual_native_frames'] = [{'group': g, 'mode': m, 'command': c, 'status': s,
            'image_sha256': im, 'count': n} for (g, m, c, s, im), n in sorted(frames.items())]
        report['per_test_native_frames'] = dict(by_test)
        report['subprocess_entries_in_parent_counts'] = False
        (directory / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'seconds': report['seconds'],
                          'report': str(directory / 'REPORT.json')}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
