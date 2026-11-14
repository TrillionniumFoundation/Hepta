"""Qualify complete Linux-process callers from matching current-source cold B3.

The five retained native groups keep their original 180+3 second owners,
20 second children, 1 MiB buffers and 10M VM limit. Cold preparation and the
original 71 public source callers are separate complete groups. Development
pins/results and mutable serialized fixtures are not qualification authority.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import os
import platform
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_process import PROFILE
from tools import hia_linux_process_cold as custody
from tools.build_hia_linux_process_cold import (
    build_toolchain, build_program, admit_toolchain, admit_program,
)
from tools.hia_linux_process_cold import (
    CAPACITY, admit_cold, check_bindings, decode, digest, guard_authority,
    pin, publish, re_admit_authority, require, wire,
)

COLD_FIXTURE_ENV = 'HEPTA_HIA_LINUX_PROCESS_COLD_FIXTURE'
EVIDENCE_ENV = 'HEPTA_HIA_LINUX_PROCESS_TEST_EVIDENCE'
SOURCE_EVIDENCE_ENV = 'HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE'
GROUP_SECONDS = 180
CLEANUP_SECONDS = 3
COMPILE_SECONDS = 20
FIXTURE_SCHEMA = 'hepta.hia.linux-process-current-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_PROCESS_INPUTS_PREPARED_NOT_QUALIFIED'
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures',
             'unexpected_successes', 'subtest_failures')
GROUP_ORDER = ('source', 'direct', 'packer', 'startup', 'entry', 'legacy', 'portable')
GROUP_SELECTORS = {
    'source': ('tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests',
               'tests.test_hia_program', 'tests.test_hia_agent_assembly',
               'tests.test_hia_linux_process.LinuxProcessPublicSourceTests'),
    'direct': ('tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests',),
    'packer': ('tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests',),
    'startup': ('tests.test_hia_linux_process_cold.LinuxProcessStartupMatchingColdNativeTests',),
    'entry': ('tests.test_hia_linux_process_cold.LinuxProcessEntryMatchingColdNativeTests',),
    'legacy': ('tests.test_hia_linux_process_cold.LinuxProcessDomainMatchingColdNativeTests',),
    'portable': ('tests.test_hia_linux_process_cold.LinuxProcessPortableSourceTests',),
}
GROUP_COUNTS = {'source': 71, 'direct': 33, 'packer': 13, 'startup': 4,
                'entry': 4, 'legacy': 4, 'portable': 1}
# Filled mechanically from the frozen exact methods before this author revision
# is admitted. Tests reject an absent pin or any changed complete test file.
TEST_SOURCE_PINS = {'tests/test_hia_linux_stdio.py': 'fd406365f9d846f7c90471e9054653dd53f77918d05d27d37792914c8ee53cd8', 'tests/test_hia_program.py': '73de53638397a1d564b3580551c83fa0ecf936c79af3ba1c5334b929aad45d3c', 'tests/test_hia_agent_assembly.py': '2f429e970da879bb5e4e65f414c415cfe4df6577cfb3d9618a9c8a64d992c7f7', 'tests/test_hia_linux_process.py': 'fcfbd5ec034895b2526b69290bdd001bcd0e20e5d879fa36b95607b22684314e', 'tests/test_hia_linux_process_cold.py': '93309d8cdfa4060a437eabe6d03b3ab7c28f5e9fd872929031fb9488fcadba28', 'tests/test_hia_agent_installed_resources.py': '28281f2ba1ba11c735b7a88db599aa1baae7614a9cb19d3e59c3cd196a67e511', 'tests/hia_linux_process_programs.py': 'f37997f9f3b176e2dbd291185ad07523c828b7970e4defa3b5aa568a40d4781a', 'tests/hia_linux_process_cases.py': '427f9be316fb61c6220ac5d15f46b37fd37dadeca8110edcf4dc76871ccf8931', 'tests/hia_linux_stdio_cases.py': 'c7085e1660cb04b54db46058e10ea1ef953261acc1d60c3b72499554b7c0a1ef', 'tests/hia_linux_process_cold_cases.py': 'a5159e8b481a26b6113fc227371838f4dbb4389bc245c886ab1fd92c82bb6dc9', 'tests/hia_linux_process_buffer_observer.py': 'bfae4102bea6642589d9d2a8941b334fd1c9b75d8a1b2c9c96e390891dd27107', 'tests/hia_linux_process_buffer_child.py': '7cb753661bad24fccb55f6a2fa10c957adc950463702e9ad28ff54707fa21ce5', 'tests/hia_linux_process_startup_fault_observer.py': '6f7f9199e985acc7fff3d922678fdf917f26326645bad62119a36b6a26715b58', 'tests/fixtures/hia_linux_process_retained_controls.json': '7a308746f98a62627ac1449d9391ad72ab3c17dd9b70c089bf8ca874731e66ba'}
EXPECTED_IDS = {'source': ('tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_bounds_proven_before_provider_including_overflow_and_zero_count', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_callee_effect_propagation_and_unknown_host_target_are_closed', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_default_assembly_core_vm_and_code_still_refuse_extended_input', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_default_global_opcode_and_effect_tables_are_not_extended', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_negative_errno_short_read_and_zero_still_issue_one_effect', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_one_mib_read_and_write_buffers_are_preserved', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_types_effects_and_empty_attributes_are_mandatory', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_explicit_profile_is_exact_and_never_guessed_from_module', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_forged_or_modified_verified_bytes_are_rechecked', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_original_compiler_bounds_and_entry_schema_are_not_widened', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_parent_suspend_and_loan_end_use_the_real_capability_checker', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_provider_domain_and_foreign_exception_identity_are_preserved', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_builder_rejects_bad_profile_and_compiler_pin_before_execution', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_byte_boundary_exact_types_and_original_extent_limits', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_roundtrip_checks_actual_io_opcodes_without_proxy_calls', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_reference_signal_is_explicit_exact_and_retains_full_state', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_request_carries_no_mutable_owner_or_implicit_real_fd_provider', 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_step_stop_is_not_errno_and_runs_no_provider', 'tests.test_hia_program.CanonicalInputAndCFGTests.test_canonical_input_and_duplicate_keys', 'tests.test_hia_program.CanonicalInputAndCFGTests.test_immutable_snapshot_and_rechecked_public_constructor', 'tests.test_hia_program.CanonicalInputAndCFGTests.test_malformed_values_reject_with_controlled_errors', 'tests.test_hia_program.CanonicalInputAndCFGTests.test_ssa_cfg_effect_and_unknown_claim_rejections', 'tests.test_hia_program.CanonicalInputAndCFGTests.test_wrong_json_container_at_each_schema_position_is_rejected', 'tests.test_hia_program.ResourceExecutionTests.test_allocation_failure_empty_owner_multireturn_and_error_cleanup', 'tests.test_hia_program.ResourceExecutionTests.test_borrowed_call_reborrow_and_resume_parent', 'tests.test_hia_program.ResourceExecutionTests.test_local_stored_view_and_owner_cross_blocks_together', 'tests.test_hia_program.ResourceExecutionTests.test_loop_carries_owner_and_mutable_loan_identity', 'tests.test_hia_program.ResourceExecutionTests.test_write_read_move_drop_and_bounds', 'tests.test_hia_program.ScalarExecutionTests.test_checked_and_wrapping_at_every_integer_width', 'tests.test_hia_program.ScalarExecutionTests.test_closed_block_loop_and_calls', 'tests.test_hia_program.ScalarExecutionTests.test_exact_arguments_and_no_host_fabricated_capabilities', 'tests.test_hia_program.ScalarExecutionTests.test_signed_division_remainder_and_shift_semantics', 'tests.test_hia_program.ScalarExecutionTests.test_step_heap_and_call_budgets_are_not_semantic_traps', 'tests.test_hia_program.StaticRejectionTests.test_callee_cannot_end_or_return_external_loan', 'tests.test_hia_program.StaticRejectionTests.test_consumed_owners_borrows_and_silent_loss', 'tests.test_hia_program.StaticRejectionTests.test_duplicate_edge_owner_and_missing_parent_reject', 'tests.test_hia_program.StaticRejectionTests.test_exclusive_call_arguments_must_not_alias', 'tests.test_hia_program.StaticRejectionTests.test_join_cannot_change_loan_root_despite_matching_types', 'tests.test_hia_program.StaticRejectionTests.test_suspended_parent_cannot_be_accessed_or_ended_first', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_accepted_diagnostic_is_not_a_deployment_receipt', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_actual_mathematical_wide_sum_and_canonical_rerender', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_atomic_cross_function_interface_upgrade_needs_both_changes', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_byte_line_and_inventory_limits_apply_before_core_verification', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_checked_overflow_and_declared_trap_are_not_dropped', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_dropped_owner_is_not_synthesized_to_repair_a_leak', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_duplicate_json_keys_nonfinite_and_nesting_are_not_accepted', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_duplicate_ssa_keeps_core_error_without_guessing_a_location', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_explicit_empty_exports_and_absence_are_distinct', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_missing_terminator_end_extra_text_and_duplicate_exports_reject', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_owner_move_loans_and_cleanup_execute_in_existing_vm', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_real_joined_loans_cfg_parameters_preserve_origin', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_recursive_chain_v7_roundtrip_and_failure_paths', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_unknown_header_historical_and_nominal_profiles_reject', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_unsafe_loan_overlap_is_rejected_by_original_verifier', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_use_after_move_is_rejected_by_original_verifier', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_utf8_controls_and_explicit_line_diagnostic', 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_wrong_signature_unknown_operation_and_missing_attribute_reject', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_callee_startup_effect_propagation_is_not_hidden_behind_call', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_copy_bounds_complete_before_mutation_including_zero_and_overflow', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_copy_uses_actual_linear_loan_checker_and_parent_suspension', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_default_and_stdio_v1_consumers_refuse_process_program', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_exact_snapshot_preserves_raw_duplicates_order_and_empty', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_fixed_opcode_inventory_does_not_modify_global_defaults', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_fixed_stderr_provider_is_single_call_even_for_negative_and_zero', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_forged_snapshot_or_profile_object_is_not_native_or_core_authority', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_original_finite_resource_limits_remain_unchanged', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_provider_result_domain_and_signal_remain_explicit_reference', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_public_parse_verify_render_uses_distinct_rechecked_authority', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_snapshot_accepts_empty_vectors_and_more_than_one_MiB_total', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_types_effects_and_attributes_cannot_grant_arbitrary_pointer_or_fd', 'tests.test_hia_linux_process.LinuxProcessPublicSourceTests.test_v1_and_default_reject_new_physical_provider_arguments'), 'direct': ('tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_01_kernel_empty_vector_count', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_02_empty_vectors_kernel_entry', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_03_explicit_empty_arg', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_04_ordered_raw_duplicates', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_05_raw_no_utf8_and_newlines', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_06_large_aggregate_over_1mib', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_07_fd2_three_raw_bytes', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_08_fd2_closed_full_negative_ebadf', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_09_fd2_inherited_default_sigpipe', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_10_fd2_inherited_ignore_full_epipe', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_11_fd2_zero_open', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_12_fd2_zero_closed_still_ebadf', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_13_fd2_exact_1mib', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_14_fd2_nonblocking_short_write', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_15_invalid_argv_index', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_16_invalid_env_index', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_17_copy_invalid_source', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_18_copy_invalid_destination', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_19_copy_source_overflow', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_20_copy_destination_overflow', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_21_copy_zero_at_both_ends', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_22_retained_empty_input', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_23_retained_short_binary_input', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_24_retained_zero_count_open', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_25_retained_zero_count_closed_read', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_26_retained_zero_count_closed_write', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_27_retained_full_signed_read_ebadf', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_28_retained_full_signed_write_ebadf', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_29_retained_sigpipe_default', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_30_retained_sigpipe_inherited_ignore_epipe', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_31_retained_exact_1mib', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_32_retained_over_1mib_rejected_before_write', 'tests.test_hia_linux_process_cold.LinuxProcessMatchingColdNativeTests.test_33_retained_bounds_before_read'), 'packer': ('tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_01_same_a5_full_observation', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_02_empty_frame', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_03_wrong_magic', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_04_wrong_version', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_05_reserved_field', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_06_zero_image', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_07_truncated_frame', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_08_trailing_byte', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_09_zero_output', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_10_short_output', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_11_image_one_over_entry_limit', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_12_exact_1mib_elf_structural_only', 'tests.test_hia_linux_process_cold.LinuxProcessPackerMatchingColdNativeTests.test_13_minimum_image_structural_only'), 'startup': ('tests.test_hia_linux_process_cold.LinuxProcessStartupMatchingColdNativeTests.test_01_prctl', 'tests.test_hia_linux_process_cold.LinuxProcessStartupMatchingColdNativeTests.test_02_mprotect_stack', 'tests.test_hia_linux_process_cold.LinuxProcessStartupMatchingColdNativeTests.test_03_mprotect_guard', 'tests.test_hia_linux_process_cold.LinuxProcessStartupMatchingColdNativeTests.test_04_mprotect_cap'), 'entry': ('tests.test_hia_linux_process_cold.LinuxProcessEntryMatchingColdNativeTests.test_01_empty_source_distinct_zero_1mib_buffers_both_ends', 'tests.test_hia_linux_process_cold.LinuxProcessEntryMatchingColdNativeTests.test_02_kernel_131071_byte_string_plus_nul', 'tests.test_hia_linux_process_cold.LinuxProcessEntryMatchingColdNativeTests.test_03_kernel_string_one_byte_over', 'tests.test_hia_linux_process_cold.LinuxProcessEntryMatchingColdNativeTests.test_04_kernel_aggregate_over_8mib_stack_limit'), 'legacy': ('tests.test_hia_linux_process_cold.LinuxProcessDomainMatchingColdNativeTests.test_01_selfhost_elf', 'tests.test_hia_linux_process_cold.LinuxProcessDomainMatchingColdNativeTests.test_02_selfhost_exec', 'tests.test_hia_linux_process_cold.LinuxProcessDomainMatchingColdNativeTests.test_03_explicit_scalar_exports', 'tests.test_hia_linux_process_cold.LinuxProcessDomainMatchingColdNativeTests.test_04_explicit_empty_exports'), 'portable': ('tests.test_hia_linux_process_cold.LinuxProcessPortableSourceTests.test_actual_sdist_wheel_installed_process_profile_and_missing_resources',)}


# The fourteen retained pins above remain the exact historical caller inputs.
# Only this explicit sdist-support declaration successor has a second identity.
SDIST_CALLER_PATH = 'tests/test_hia_agent_installed_resources.py'
SDIST_CALLER_RETAINED_BYTES = 51716
SDIST_CALLER_RETAINED_SHA256 = '28281f2ba1ba11c735b7a88db599aa1baae7614a9cb19d3e59c3cd196a67e511'
SDIST_CALLER_SUCCESSOR_BYTES = 52246
SDIST_CALLER_SUCCESSOR_SHA256 = 'fd0324146e29b41537325d08fb667d145bb4a5146d312b84990465c0716a81b4'
SDIST_CALLER_RETAINED_BLOCK = b"# Source-distribution test inputs are not installed Agent resources and must\n# never expand the worker's production source identity or _data payload.\nSDIST_SUPPORT_FILES=('tests/fixtures/hia_compiler_rename_reference.json.gz',\n                     'tests/fixtures/hia_reference_compiler_v64.json.xz')\n"
SDIST_CALLER_SUCCESSOR_BLOCK = b"# Source-distribution support includes retained test inputs and explicit\n# optional-profile build sources. It does not expand the default worker's\n# 210 resources or its default installed _data payload.\nSDIST_SUPPORT_FILES=(\n    'tests/fixtures/hia_compiler_rename_reference.json.gz',\n    'tests/fixtures/hia_reference_compiler_v64.json.xz',\n    'examples/hia_bootstrap/assembly_reparse.hepta',\n    'examples/hia_bootstrap/core_representation_internal.hepta',\n    'examples/hia_bootstrap/core_representation_private.hepta',\n    'examples/hia_bootstrap/file_render_checker_v4.hepta',\n    'examples/hia_bootstrap/linux_file_roundtrip_entry_packer.hepta',\n    'examples/hia_bootstrap/native_file_roundtrip.hepta',\n    'examples/hia_bootstrap/selfhost_linux_file_roundtrip.hepta',\n    'examples/hia_bootstrap/verified_report.hepta',\n)\n"


def _sdist_caller_admission(raw):
    require(type(raw) is bytes, 'complete process caller bytes required')
    require(TEST_SOURCE_PINS[SDIST_CALLER_PATH] == SDIST_CALLER_RETAINED_SHA256,
            'retained process caller declaration changed')
    actual_sha = digest(raw)
    if len(raw) == SDIST_CALLER_RETAINED_BYTES and actual_sha == SDIST_CALLER_RETAINED_SHA256:
        require(raw.count(SDIST_CALLER_RETAINED_BLOCK) == 1,
                'retained sdist declaration is not unique')
        projected = raw.replace(SDIST_CALLER_RETAINED_BLOCK, SDIST_CALLER_SUCCESSOR_BLOCK, 1)
        require(len(projected) == SDIST_CALLER_SUCCESSOR_BYTES
                and digest(projected) == SDIST_CALLER_SUCCESSOR_SHA256
                and projected.count(SDIST_CALLER_SUCCESSOR_BLOCK) == 1
                and projected.replace(SDIST_CALLER_SUCCESSOR_BLOCK, SDIST_CALLER_RETAINED_BLOCK, 1) == raw,
                'retained caller does not have the exact approved sdist successor')
        role = 'EXACT_RETAINED_ORIGINAL'
    else:
        require(len(raw) == SDIST_CALLER_SUCCESSOR_BYTES and actual_sha == SDIST_CALLER_SUCCESSOR_SHA256,
                'complete process caller has an unapproved successor identity')
        require(raw.count(SDIST_CALLER_SUCCESSOR_BLOCK) == 1,
                'successor sdist declaration is not unique')
        retained = raw.replace(SDIST_CALLER_SUCCESSOR_BLOCK, SDIST_CALLER_RETAINED_BLOCK, 1)
        require(len(retained) == SDIST_CALLER_RETAINED_BYTES
                and digest(retained) == SDIST_CALLER_RETAINED_SHA256
                and retained.count(SDIST_CALLER_RETAINED_BLOCK) == 1
                and retained.replace(SDIST_CALLER_RETAINED_BLOCK, SDIST_CALLER_SUCCESSOR_BLOCK, 1) == raw,
                'complete caller inverse differs from the retained original bytes')
        role = 'EXACT_SDIST_SUPPORT_DECLARATION_SUCCESSOR'
    return {'role': role, 'bytes': len(raw), 'actual_sha256': actual_sha,
            'retained_sha256': SDIST_CALLER_RETAINED_SHA256,
            'approved_successor_sha256': SDIST_CALLER_SUCCESSOR_SHA256,
            'projection': 'ONE_UNIQUE_TUPLE_AND_COMMENT_BLOCK_FULL_BYTE_INVERSE'}


def _check_test_sources():
    require(type(TEST_SOURCE_PINS) is dict and len(TEST_SOURCE_PINS) == 14,
            'complete exact process test/module/observer source pins required')
    actual_pins, admissions = {}, {}
    for name, expected in TEST_SOURCE_PINS.items():
        raw = (ROOT / name).read_bytes()
        if name == SDIST_CALLER_PATH:
            admission = _sdist_caller_admission(raw)
        else:
            actual_sha = digest(raw)
            require(actual_sha == expected,
                    'complete frozen process caller source changed: ' + name)
            admission = {'role': 'EXACT_RETAINED_ORIGINAL', 'bytes': len(raw),
                         'actual_sha256': actual_sha, 'retained_sha256': expected}
        actual_pins[name] = admission['actual_sha256']
        admissions[name] = admission
    retained = custody.retained_inputs()
    require(EXPECTED_IDS.get('source') == tuple(retained['original_71_ids'])
            and set(EXPECTED_IDS) == set(GROUP_ORDER)
            and all(len(EXPECTED_IDS[name]) == GROUP_COUNTS[name]
                    and len(set(EXPECTED_IDS[name])) == GROUP_COUNTS[name] for name in GROUP_ORDER),
            'complete fixed group identities differ')
    return {'schema': 'hepta.hia.process-caller-byte-admission.v1',
            'retained_test_source_pins': dict(TEST_SOURCE_PINS),
            'actual_test_source_pins': actual_pins, 'admissions': admissions}


def _case_source(name):
    from tests.hia_linux_process_cold_cases import case_source
    return case_source(name)


def prepare_fixture(output, cold_report):
    from tests.hia_linux_process_cold_cases import program_names
    authority = admit_cold(cold_report)
    caller_admission = _check_test_sources()
    folder = Path(output).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'hepta.hia.linux-process-cold-fixture-preparation.v1',
        'status': 'FAIL', 'matching_cold': False, 'qualification_complete': False,
        'whole_native': False, 'authority': authority, 'programs': {},
        'caller_source_admission': caller_admission}
    try:
        toolchain = build_toolchain(folder / 'toolchain', cold_report,
                                    compiler=authority['compiler'])
        chain = admit_toolchain(toolchain, authority=authority)
        for name in program_names():
            raw = _case_source(name)
            checked = assemble_program(raw, profile=PROFILE)
            require(render_assembly(checked, profile=PROFILE).encode() == raw,
                    'retained canonical program changed: ' + name)
            path = build_program(checked, folder / name, profile=PROFILE,
                cold_report=cold_report, compiler=authority['compiler'], toolchain=toolchain)
            built = admit_program(path, authority=authority)
            report['programs'][name] = {'build': pin(path), 'source_sha256': digest(raw),
                'program_sha256': checked.sha256, 'executable': built['executable']['path'],
                'executable_sha256': built['executable']['sha256']}
        fixture = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS,
            'profile': PROFILE, 'authority': authority, 'toolchain': pin(toolchain),
            'compiler_image': pin(chain['compiler_image']),
            'packer_image': pin(chain['packer_image']), 'cold_compiler': pin(authority['compiler']),
            'programs': report['programs'], 'matching_cold': True,
            'qualification_complete': False, 'whole_native': False,
            'test_source_pins': caller_admission['actual_test_source_pins']}
        require(_check_test_sources() == caller_admission,
                'complete process caller bytes changed during preparation')
        guard_authority(authority)
        publish(folder / 'FIXTURE.json', fixture)
        admit_fixture(folder / 'FIXTURE.json')
        report.update(status='PASS', matching_cold=True, fixture=pin(folder / 'FIXTURE.json'))
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc())
        raise
    finally:
        publish(folder / 'PREPARATION.json', report)
    return folder / 'FIXTURE.json'


def admit_fixture(path):
    from tests.hia_linux_process_cold_cases import program_names
    selected = pin(Path(path).absolute())
    path = Path(selected['path']).resolve(strict=True)
    raw = path.read_bytes()
    fixture = decode(raw)
    require(type(fixture) is dict and set(fixture) == {'schema', 'status', 'profile',
            'authority', 'toolchain', 'programs', 'compiler_image', 'packer_image',
            'cold_compiler', 'matching_cold', 'qualification_complete', 'whole_native',
            'test_source_pins'} and fixture.get('schema') == FIXTURE_SCHEMA
            and fixture.get('status') == FIXTURE_STATUS and fixture.get('profile') == PROFILE
            and fixture.get('matching_cold') is True
            and fixture.get('qualification_complete') is False and fixture.get('whole_native') is False,
            'explicit current-cold process fixture required; development is not authority')
    caller_admission = _check_test_sources()
    require(fixture['test_source_pins'] == caller_admission['actual_test_source_pins'],
            'fixture complete current caller pins differ')
    authority = re_admit_authority(fixture['authority'])
    check_bindings([fixture['toolchain'], fixture['compiler_image'], fixture['packer_image'],
                    fixture['cold_compiler']])
    chain = admit_toolchain(fixture['toolchain']['path'], authority=authority)
    require(fixture['compiler_image'] == pin(chain['compiler_image'])
            and fixture['packer_image'] == pin(chain['packer_image'])
            and fixture['cold_compiler'] == pin(authority['compiler']),
            'actual P3/packer/cold B3 providers differ')
    require(type(fixture['programs']) is dict and set(fixture['programs']) == set(program_names()),
            'all eighteen actually compiled test programs required')
    for name in program_names():
        item = fixture['programs'][name]
        require(type(item) is dict and set(item) == {'build', 'source_sha256', 'program_sha256',
                'executable', 'executable_sha256'}, 'unknown process program fixture fields')
        check_bindings([item['build']])
        program = admit_program(item['build']['path'], authority=authority)
        source = _case_source(name)
        require(program['toolchain'] == fixture['toolchain']
                and program['source_sha256'] == digest(source) == item['source_sha256']
                and program['program_sha256'] == assemble_program(source, profile=PROFILE).sha256
                    == item['program_sha256']
                and item['executable'] == program['executable']['path']
                and item['executable_sha256'] == program['executable']['sha256'],
                'actual process compiler/packer/program binding differs: ' + name)
    guard_authority(authority)
    require(pin(selected['path']) == selected and path.read_bytes() == raw,
            'fixture changed during complete fresh admission')
    return fixture


def load_fixture(environment=None):
    environment = os.environ if environment is None else environment
    require(type(environment.get(COLD_FIXTURE_ENV)) is str and environment[COLD_FIXTURE_ENV]
            and type(environment.get(EVIDENCE_ENV)) is str and environment[EVIDENCE_ENV],
            'explicit process cold fixture/evidence required; no development fallback')
    path = Path(environment[COLD_FIXTURE_ENV]).absolute()
    return path, admit_fixture(path), Path(environment[EVIDENCE_ENV]).absolute()


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_suite(group):
    _check_test_sources()
    require(group in GROUP_ORDER, 'unknown exact process group')
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(GROUP_SELECTORS[group])
    ids = [test.id() for test in flatten(suite)]
    require(not loader.errors and ids == list(EXPECTED_IDS[group])
            and len(ids) == len(set(ids)) == GROUP_COUNTS[group],
            'complete original process group discovery differs: ' + group)
    return suite, ids


def admit_child_report(report, request_sha, group):
    require(type(report) is dict and report.get('schema') == 'hepta.hia.linux-process-cold-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
            and report.get('group') == group and report.get('status') == 'PASS'
            and report.get('request_sha256') == request_sha
            and report.get('loaded_ids') == list(EXPECTED_IDS[group])
            and report.get('started_ids') == list(EXPECTED_IDS[group])
            and report.get('stopped_ids') == list(EXPECTED_IDS[group])
            and type(report.get('tests_run')) is int and report['tests_run'] == GROUP_COUNTS[group]
            and report.get('source_and_inputs_unchanged') is True,
            'complete exact process group observations required: ' + group)
    anomalies = report.get('anomalies')
    require(type(anomalies) is dict and set(anomalies) == set(ANOMALIES)
            and all(type(anomalies[name]) is list and not anomalies[name] for name in ANOMALIES),
            'failure/error/skip/subtest/expected failure cannot qualify')


def _actual_kernel(folder, executable, argv, environment, stdin, mode, ignored, *, fault=False):
    from tests.hia_linux_process_cases import LIMITS
    folder = Path(folder)
    actual = decode((folder / 'OBSERVATION.json').read_bytes())
    request = decode((folder / 'EXEC-REQUEST.json').read_bytes())
    closed = {'closed-stdin': [0], 'closed-stdout': [1], 'closed-stderr': [2]}.get(mode, [])
    expected_request = {'elf': str(Path(executable).resolve()),
        'elf_sha256': digest(Path(executable).read_bytes()),
        'argv_hex': [v.hex() for v in argv], 'environment_hex': [v.hex() for v in environment],
        'sigpipe_ignored': ignored, 'close_fds': closed,
        'exec_failure': str((folder / 'EXEC-FAILURE.json').resolve())}
    module = 'hia_linux_process_startup_fault_observer.py' if fault else 'hia_linux_process_cases.py'
    if fault:
        expected_request['deny'] = mode[5:] if mode.startswith('deny-') else None
    expected_command = [sys.executable, '-I', '-S', '-B', str((ROOT / 'tests' / module).resolve()),
                        '--raw-exec', str((folder / 'EXEC-REQUEST.json').resolve())]
    require(wire(request) == wire(expected_request) and type(request['sigpipe_ignored']) is bool
            and actual.get('command') == expected_command
            and actual.get('payload') == expected_request['elf']
            and actual.get('image_sha256') == actual.get('image_after_sha256') == expected_request['elf_sha256']
            and actual.get('limits') == LIMITS and all(type(v) is int for v in actual['limits'].values())
            and actual.get('timed_out') is False and actual.get('reaped_ECHILD') is True
            and actual.get('preexec_python_ctypes') is True
            and actual.get('runtime_payload_python_or_ctypes') is False
            and type(actual.get('returncode')) is int
            and type(actual.get('stdin_consumed')) is int
            and (folder / 'stdin.bin').read_bytes() == stdin
            and actual.get('stdout_hex') == (folder / 'stdout.bin').read_bytes().hex()
            and actual.get('stderr_hex') == (folder / 'stderr.bin').read_bytes().hex(),
            'complete raw exec request/limits/bytes/terminal differ: ' + folder.name)
    failure = folder / 'EXEC-FAILURE.json'
    require(actual.get('exec_failure') == (decode(failure.read_bytes()) if failure.exists() else None),
            'actual pre-exec admission record differs')
    return actual


def _actual_packer(folder, image, source, output, workspace):
    """Read the actual closed request, child report and all three shared files.

    This mechanical observation alone grants no image or cold authority. The
    caller separately binds the supplied image to the admitted toolchain.
    """
    folder, image = Path(folder), Path(image)
    request_raw = (folder / 'request.json').read_bytes()
    request = decode(request_raw)
    observed = decode((folder / 'OBSERVATION.json').read_bytes())
    child = decode((folder / 'CHILD-REPORT.json').read_bytes())
    guard = b'\xd3' * 64
    expected_buffers, values = [], []
    for label, initial in (('source', source), ('output', output), ('workspace', workspace)):
        path = folder / (label + '.shared')
        before = guard + initial + guard
        expected_buffers.append({'path': str(path), 'bytes': len(before),
                                 'sha256': digest(before), 'extent': len(initial)})
        current = path.read_bytes()
        require(len(current) == len(before) and current[:64] == guard and current[-64:] == guard,
                'actual shared extent or canary differs: ' + label)
        values.append(current[64:-64])
    expected = {'schema': 'hia.linux-stdio.native-request.v1', 'image': str(image),
        'image_sha256': digest(image.read_bytes()), 'buffers': expected_buffers,
        'mode': 'ordinary', 'report': str(folder / 'CHILD-REPORT.json')}
    require(wire(request) == wire(expected)
            and all(type(row['bytes']) is int and type(row['extent']) is int for row in request['buffers'])
            and (folder / 'stdin.bin').read_bytes() == b'',
            'complete original packer request or preimages differ')
    limits = {'wall_seconds': 20, 'cpu_seconds': 10, 'source_output_workspace_bytes': CAPACITY,
              'address_bytes': 268435456, 'stack_bytes': 8388608, 'core_dumpable': False}
    require(type(child) is dict and set(child) == {'schema','status','result_u64','native_elapsed_ns',
            'image_sha256','request_sha256','limits','forbidden_modules_loaded','matched_cold','whole'}
            and child['schema'] == 'hia.linux-stdio.native-observation.v1'
            and child['status'] == 'returned' and type(child['result_u64']) is int
            and 0 <= child['result_u64'] <= 0xffffffffffffffff
            and type(child['native_elapsed_ns']) is int and child['native_elapsed_ns'] >= 0
            and child['image_sha256'] == expected['image_sha256']
            and child['request_sha256'] == digest(request_raw)
            and child['limits'] == limits and child['limits']['core_dumpable'] is False
            and all(type(value) is int for key,value in child['limits'].items() if key != 'core_dumpable')
            and child['forbidden_modules_loaded'] == [] and child['matched_cold'] is False
            and child['whole'] is False,
            'actual packer child request/image/limits or observation-only scope differs')
    require(type(observed) is dict and wire(observed.get('child')) == wire(child)
            and type(observed.get('returncode')) is int and observed['returncode'] == 0
            and observed.get('timed_out') is False
            and type(observed.get('timeout_seconds')) is int and observed['timeout_seconds'] == 20
            and type(observed.get('cleanup_seconds')) is int and observed['cleanup_seconds'] == 3
            and type(observed.get('stdin_consumed')) is int and observed['stdin_consumed'] == 0
            and observed.get('stdout_hex') == (folder/'stdout.bin').read_bytes().hex() == ''
            and observed.get('stderr_hex') == (folder/'stderr.bin').read_bytes().hex() == ''
            and observed.get('source_hex') == values[0].hex() == source.hex()
            and observed.get('output_hex') == values[1].hex()
            and observed.get('workspace_hex') == values[2].hex()
            and type(observed.get('canaries')) is list and len(observed['canaries']) == 3
            and all(value is True for value in observed['canaries']),
            'actual packer raw buffers/streams/terminal differ')
    return observed


def _actual_portable(folder):
    import tarfile
    import zipfile
    from tests.test_hia_agent_installed_resources import RESOURCES
    from hepta import hia_agent_contract as contract
    folder = Path(folder)
    path = folder / 'PORTABLE-RESULT.json'
    proof = decode(path.read_bytes())
    roles = ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES',
             'PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES',
             'MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES','ENTRY_BUILD_FILES')
    resource_roles = {role: ['docs/' + name for name in contract.DISCOVERY_FILES]
                      if role == 'DISCOVERY_FILES' else list(getattr(contract, role)) for role in roles}
    resources = tuple(name for role in roles for name in resource_roles[role])
    require(resources == RESOURCES and len(resources) == len(set(resources)), 'complete portable resource union differs')
    require(proof.get('schema') == 'hepta.hia.linux-process-portable.v1'
            and proof.get('status') == 'PASS' and proof.get('profile') == PROFILE
            and proof.get('all_resource_bytes_equal') is True
            and proof.get('installed_profile_reference_only') is True
            and proof.get('actual_kernel_execution') is False
            and proof.get('whole_native') is False and proof.get('matching_cold') is False
            and type(proof.get('resource_count')) is int and proof['resource_count'] == len(resources)
            and proof.get('resource_roles') == resource_roles,
            'actual complete portable/reference-only observations required')
    check_bindings(proof['bindings'])
    archive, = (folder/'sdist').glob('*.tar.gz')
    wheel, = (folder/'wheel').glob('*.whl')
    installed = folder/'installed'
    require(proof['archive'] == pin(archive) and proof['wheel'] == pin(wheel)
            and proof['installed'] == str(installed), 'actual portable artifacts differ')
    original = {name:(ROOT/name).read_bytes() for name in resources}
    with tarfile.open(archive) as tar:
        prefix = tar.getmembers()[0].name.split('/')[0] + '/'
        for name in resources:
            require(tar.extractfile(prefix+name).read() == original[name], 'sdist resource changed: '+name)
    with zipfile.ZipFile(wheel) as zipped:
        require({name for name in zipped.namelist() if name.startswith('hepta/_data/') and not name.endswith('/')}
                == {'hepta/_data/'+name for name in resources}, 'whole wheel resource inventory differs')
        for name in resources:
            require(zipped.read('hepta/_data/'+name) == original[name]
                    == (installed/'hepta/_data'/name).read_bytes(), 'wheel/installed resource changed: '+name)
    readback = decode((folder/'RESOURCE-READBACK.json').read_bytes())
    require(readback == {'roles':resource_roles,
            'resources':{name:{'bytes':len(raw),'sha256':digest(raw)} for name,raw in original.items()},
            'sdist_wheel_installed_complete_bytes_equal':True}, 'full resource readback differs')
    commands = decode((folder/'COMMANDS.json').read_bytes())
    labels = ('sdist','wheel','install','installed','missing-0','missing-1','restored')
    require(type(commands) is list and [row['label'] for row in commands] == list(labels),
            'complete actual packaging/negative/restoration command order differs')
    bindings = [pin(p) for p in (archive,wheel,folder/'installed-observer.py',folder/'explicit-process.hepta',
                                folder/'RESOURCE-READBACK.json',folder/'COMMANDS.json')]
    bindings += [pin(installed/'hepta/_data'/name) for name in resources]
    observer = folder/'installed-observer.py'; input_path = folder/'explicit-process.hepta'
    arguments = {
        'sdist':['setup.py','sdist','--dist-dir',str(folder/'sdist')],
        'wheel':['-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',str(folder/'wheel'),str(archive)],
        'install':['-m','pip','install','--no-deps','--no-index','--target',str(installed),str(wheel)],
    }
    environment = {'PATH':os.environ.get('PATH',''),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE':'1','PIP_NO_INDEX':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1'}
    for row in commands:
        label = row['label']; record_path = folder/(label+'.COMMAND.json')
        expected_command = [sys.executable,'-B',*arguments.get(label,
                            ['-I',str(observer),str(installed),str(input_path)])]
        cwd = ROOT if label.startswith('missing-') else (folder/'source' if label in arguments else folder)
        require(type(row) is dict and set(row) == {'label','command','cwd','environment','timeout_seconds',
                'returncode','stdout','stderr'} and decode(record_path.read_bytes()) == row
                and type(row['returncode']) is int and type(row['timeout_seconds']) is int
                and row['timeout_seconds'] == 60 and row['command'] == expected_command
                and row['cwd'] == str(cwd) and row['environment'] == environment,
                'actual portable command record/limits differ: '+label)
        stdout, stderr = folder/(label+'.stdout'), folder/(label+'.stderr')
        require(row['stdout'] == pin(stdout) and row['stderr'] == pin(stderr), 'actual command stream changed')
        require((row['returncode'] != 0 and b'FileNotFoundError' in stderr.read_bytes()) if label.startswith('missing-')
                else row['returncode'] == 0, 'actual packaging command or missing-resource refusal failed')
        bindings.extend((row['stdout'],row['stderr'],pin(record_path)))
    require(proof['bindings'] == bindings, 'complete portable byte bindings differ')
    observed = decode((folder/'installed.stdout').read_bytes())
    from tests.hia_linux_process_cold_cases import encoded
    argv = (b'process',b'',b'\xff\xfe\n',b'x=x')
    environment_bytes = (b'A=1',b'A=2',b'',b'NO_EQUALS',b'\xff=\x80')
    calls = [[1,8],[1,8],[1,8]]
    for value in argv+environment_bytes:
        calls.append([1,8])
        if value: calls.append([1,len(value)])
    calls.append([2,3])
    require(observed == decode((folder/'restored.stdout').read_bytes()) == proof['observed']
            and observed['profile'] == PROFILE and observed['actual_kernel_execution'] is False
            and type(observed['default_and_stdio_refusals']) is int and observed['default_and_stdio_refusals'] == 4
            and observed['resources'] == {name:digest((ROOT/name).read_bytes())
                for name in (custody.COMPILER_SOURCE,custody.PACKER_SOURCE)}
            and observed['ordered_argv_hex'] == [value.hex() for value in argv]
            and observed['ordered_environment_hex'] == [value.hex() for value in environment_bytes]
            and observed['stdout_hex'] == encoded(argv,environment_bytes).hex()
            and observed['stderr_hex'] == 'ff000a'
            and wire(observed['provider_calls']) == wire(calls)
            and (folder/'explicit-process.hepta').read_bytes() == _case_source('inspect')
            and observed['program_sha256'] == assemble_program(_case_source('inspect'),profile=PROFILE).sha256,
            'actual installed/default refusal/restoration observations differ')
    return pin(path)


def verify_actual_observations(group, directory, fixture):
    from tests import hia_linux_process_cold_cases as cases
    directory = Path(directory)
    if group in ('source', 'portable'):
        if group == 'portable':
            return [_actual_portable(directory/'portable')]
        return []
    records = []
    names = custody.retained_inputs()['groups'][group]
    if group == 'direct':
        definitions = cases.definitions()
        require([x['name'] for x in definitions] == names, 'original33 identities differ')
        require({p.name for p in directory.iterdir()} == set(names), 'direct raw inventory differs')
        for case in definitions:
            folder = directory / case['name']
            build = fixture['programs'][case['program']]
            actual = _actual_kernel(folder, build['executable'], case['argv'], case['env'],
                                    case['data'], case['mode'], case['ignored'])
            expected = decode((folder / 'VM.json').read_bytes())
            checks = cases.kernel_checks(case, actual, expected, build)
            row = decode((folder / 'CHECKS.json').read_bytes())
            require(row == {'name': case['name'], 'status': 'PASS', 'checks': checks,
                    'native_returncode': actual['returncode'], 'vm_steps': expected['steps'],
                    'effects': len(expected['effects'])} and all(v is True for v in checks.values())
                    and expected.get('program_sha256') == build['program_sha256']
                    and expected.get('actual_kernel_execution') is False,
                    'complete original direct comparisons differ: ' + case['name'])
            records += [pin(folder / 'CHECKS.json'), pin(folder / 'VM.json'), pin(folder / 'OBSERVATION.json')]
    else:
        # The complete case methods are source pinned and their exact ordered
        # start/stop events are admitted separately. These additional reads bind
        # every complete raw observation used by those unchanged comparisons.
        if group != 'packer':
            require({p.name for p in directory.iterdir()} == set(names), 'complete case directory inventory differs')
        if group == 'packer':
            built = Path(fixture['programs']['counts']['build']['path']).parent
            image = (built/'program.image.bin').read_bytes()
            definitions = cases.packer_definitions(image)
            require([row[0] for row in definitions] == names, 'complete original thirteen packer cases differ')
            expected_paths = set(names) | {name+'.CHECKS.json' for name in names} | {name+'.VM.json' for name in names}
            expected_paths |= {name+'.ELF.json' for name,raw,capacity,result in definitions
                               if result not in (0xffffffff,0xfffffffe)}
            require({p.name for p in directory.iterdir()} == expected_paths, 'complete packer evidence inventory differs')
        for name in names:
            path = directory / (name + '.CHECKS.json') if group == 'packer' else directory / name / 'CHECKS.json'
            row = decode(path.read_bytes())
            require(row.get('name') == name and row.get('status') == 'PASS'
                    and type(row.get('checks')) is dict and row['checks']
                    and all(type(v) is bool and v for v in row['checks'].values()),
                    'complete fixed case comparisons failed: ' + name)
            records.append(pin(path))
            if group == 'packer':
                _,raw,capacity,result = definitions[names.index(name)]
                actual = _actual_packer(directory/name,fixture['packer_image']['path'],raw,
                                        b'\xa5'*capacity,bytes(CAPACITY))
                reference = decode((directory / (name + '.VM.json')).read_bytes())
                checks = cases.packer_checks(raw,capacity,result,reference['values'],reference,actual)
                if result not in (0xffffffff,0xfffffffe):
                    from tools.build_hia_linux_process_program import _elf_structure
                    inspection = _elf_structure(bytes.fromhex(actual['output_hex'])[:result],raw[32:])
                    require(decode((directory/(name+'.ELF.json')).read_bytes()) == inspection,
                            'actual packed ELF structural observation differs')
                    checks['W_X_and_exact_HIA_image'] = (inspection['writable_executable_segment'] is False
                        and inspection['executable_stack'] is False and inspection['elf_interpreter'] is False)
                if name == 'same-A5-full-observation':
                    checks['all_original_compile_output_bytes'] = actual['output_hex'] == (built/'packed.output.bin').read_bytes().hex()
                require(type(reference['steps']) is int and 0 <= reference['steps'] <= 10000000
                        and row == {'name':name,'status':'PASS','checks':checks,
                                    'vm_steps':reference['steps'],'packed_synthetic_image_executed':False}
                        and all(value is True for value in checks.values()),
                        'complete packer buffers/canaries differ: ' + name)
                records += [pin(directory / name / 'OBSERVATION.json'), pin(directory / (name + '.VM.json'))]
            elif group == 'startup':
                actual = _actual_kernel(directory / name, fixture['programs']['counts']['executable'],
                                        (b'process',), (b'A=1',), b'untouched', 'deny-' + name, False, fault=True)
                require(actual['exec_failure'] is None and actual['returncode'] == 126
                        and actual['stdin_consumed'] == 0
                        and actual['stdout_hex'] == actual['stderr_hex'] == '',
                        'startup refusal reached business HIA or lost kernel terminal')
                records.append(pin(directory / name / 'OBSERVATION.json'))
            elif group == 'entry':
                index = names.index(name)
                program = 'buffer-layout' if index == 0 else 'inspect'
                args, env = ((b'process',), ()) if index == 0 else (
                    ((b'x' * 131071,), ()) if index == 1 else (
                    ((b'x' * 131072,), ()) if index == 2 else ((b'process',), (b'x' * 65536,) * 48)))
                actual = _actual_kernel(directory / name, fixture['programs'][program]['executable'],
                                        args, env, b'', 'ordinary', False)
                require((actual['exec_failure'] is None and actual['returncode'] == 0) if index < 2
                        else actual['exec_failure'] == {'returncode': -1, 'errno': 7,
                            'payload_entered': False, 'stage': 'raw_execve'} and actual['returncode'] == 125,
                        'physical entry or pre-exec E2BIG boundary differs')
                records.append(pin(directory / name / 'OBSERVATION.json'))
            elif group == 'legacy':
                raw = custody.retained_inputs()['legacy_sources'][name]['source'].encode()
                first, output = custody.probe_observation(directory / name, 'original',
                    fixture['cold_compiler']['path'], raw)
                second, _ = custody.probe_observation(directory / name, 'process',
                    fixture['compiler_image']['path'], raw)
                require(row.get('old_receipt') == first and row.get('new_receipt') == second
                        and second['core_u32'] == second['result_u64'] == 0xffffffff
                        and second['workspace_header']['40'] == 93 and second['workspace_header']['64'] == 0,
                        'explicit new compiler output-domain rejection differs')
                from tools.qualify_hia_selfhost import _compile_observation_size
                size = _compile_observation_size(first, output, image_format='flat-x86-64',
                    compiler_sha256=fixture['cold_compiler']['sha256'], source_sha256=digest(raw), input_bytes=len(raw))
                require((size is None and first['workspace_header']['40'] == 68
                        and first['core_u32'] == first['result_u64'] == 0xffffffff)
                        if name == 'explicit-empty-exports' else size is not None,
                        'original closed output-domain evidence differs')
                records += [pin(directory / name / 'original.receipt.json'), pin(directory / name / 'process.receipt.json')]
    return records


def _child(request_path):
    raw = Path(request_path).read_bytes()
    request = decode(raw)
    require(type(request) is dict and set(request) == {'schema','group','fixture','fixture_binding',
            'source_manifest','output'} and request['schema'] == 'hepta.hia.linux-process-cold-request.v1'
            and request['group'] in GROUP_ORDER, 'unknown complete process request')
    group = request['group']
    output = Path(request['output'])
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.linux-process-cold-observations.v1',
        'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'status': 'FAIL', 'group': group,
        'request_sha256': digest(raw), 'python': sys.version,
        'loaded_ids': [], 'started_ids': [], 'stopped_ids': [], 'tests_run': 0,
        'anomalies': {name: [] for name in ANOMALIES}}
    fixture = None
    try:
        selected, fixture, observations = load_fixture()
        require(str(selected) == request['fixture'] and pin(selected) == request['fixture_binding']
                and str(observations) == str(output / 'observations')
                and fixture['authority']['source_manifest'] == request['source_manifest'],
                'child source or current-cold fixture selection differs')
        observations.mkdir(mode=0o700)
        suite, ids = load_suite(group)
        report['loaded_ids'] = ids
        publish(output / 'DISCOVERY.json', {'group':group,'loaded_ids':ids})
        with (output / 'EVENTS.jsonl').open('x') as events:
            class Result(unittest.TextTestResult):
                def startTest(self, test):
                    report['started_ids'].append(test.id())
                    events.write(wire({'event':'start','id':test.id()}).decode().replace('\n','')+'\n');events.flush()
                    super().startTest(test)
                def stopTest(self, test):
                    report['stopped_ids'].append(test.id())
                    events.write(wire({'event':'stop','id':test.id()}).decode().replace('\n','')+'\n');events.flush()
                    super().stopTest(test)
                def addSubTest(self, test, subtest, err):
                    if err is not None:
                        report['anomalies']['subtest_failures'].append((subtest.id(), ''.join(traceback.format_exception(*err))))
                    super().addSubTest(test, subtest, err)
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report['tests_run'] = result.testsRun
        report['anomalies'].update(
            failures=[(test.id(), trace) for test,trace in result.failures],
            errors=[(test.id(), trace) for test,trace in result.errors],
            skipped=[(test.id(), why) for test,why in result.skipped],
            expected_failures=[(test.id(), trace) for test,trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        if report['started_ids'] == report['stopped_ids'] == ids and result.testsRun == GROUP_COUNTS[group] and not any(report['anomalies'].values()):
            report['actual'] = verify_actual_observations(group, observations, fixture)
            report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            require(fixture is not None, 'child never admitted a strict process cold fixture')
            guard_authority(fixture['authority'])
            require(admit_fixture(request['fixture']) == fixture
                    and pin(request['fixture']) == request['fixture_binding']
                    and Path(request_path).read_bytes() == raw, 'child inputs changed')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        publish(output / 'RESULT.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _prepare(output, cold_report):
    report = {'schema': 'hepta.hia.linux-process-preparation-terminal.v1', 'status': 'FAIL'}
    try:
        selected = prepare_fixture(Path(output) / 'fixture', cold_report)
        report.update(status='PASS', fixture=str(selected), fixture_binding=pin(selected))
    except BaseException:
        report['traceback'] = traceback.format_exc()
    publish(Path(output) / 'PREPARE.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _owner(command, environment, folder):
    from tools.hia_selfhost_process_owner import run_owned
    folder.mkdir(mode=0o700)
    return run_owned(command, cwd=ROOT, env=environment,
        stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
        receipt_path=folder / 'OWNER.json', qualification_seconds=GROUP_SECONDS,
        cleanup_seconds=CLEANUP_SECONDS)


def _owner_pass(owner):
    return (type(owner) is dict and owner.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
        and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
        and type(owner.get('returncode')) is int and owner['returncode'] == 0
        and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == GROUP_SECONDS
        and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == CLEANUP_SECONDS
        and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
        and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True)


def qualify(cold_report, evidence):
    require(all(name not in os.environ for name in (COLD_FIXTURE_ENV,EVIDENCE_ENV,SOURCE_EVIDENCE_ENV)),
            'standalone process qualifier refuses ambient fixture/evidence overrides')
    authority = admit_cold(cold_report)
    require(sys.platform == 'linux' and platform.machine().lower() in ('x86_64','amd64'),
            'Linux x86-64 required; no skip fallback')
    caller_admission = _check_test_sources()
    folder = Path(evidence).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema':'hepta.hia.linux-process-cold-qualification.v1','status':'FAIL',
        'scope':'MATCHING_CURRENT_SOURCE_COLD','authority':authority,'matching_cold':False,
        'qualification_complete':False,'whole_native':False,'default_activated':False,
        'expected_ids':EXPECTED_IDS,'expected_counts':GROUP_COUNTS,'group_order':GROUP_ORDER,
        'group_seconds':GROUP_SECONDS,'cleanup_seconds':CLEANUP_SECONDS,
        'compile_seconds':COMPILE_SECONDS,'compiler_output_and_workspace_bytes':CAPACITY,
        'direct_control_wall_seconds':20,'direct_control_cleanup_seconds':3,
        'VM_steps':10000000,'python':sys.version,'source_before':authority['source_manifest'],
        'caller_source_admission':caller_admission,'groups':{}}
    environment = {'PATH':os.environ.get('PATH',''),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0'}
    started = time.monotonic_ns()
    fixture = None
    try:
        command = [sys.executable,'-I','-B',str(Path(__file__).resolve()),
                   '--prepare-output',str(folder),'--cold-report',authority['cold_report']]
        report['prepare_owner'] = _owner(command,environment,folder/'prepare-command')
        preparation = decode((folder/'PREPARE.json').read_bytes())
        report['preparation'] = preparation
        require(_owner_pass(report['prepare_owner']) and preparation.get('status')=='PASS',
                'strict process cold preparation did not complete')
        selected = Path(preparation['fixture'])
        require(pin(selected)==preparation['fixture_binding'],'prepared fixture changed')
        fixture = admit_fixture(selected)
        for group in GROUP_ORDER:
            result = {'status':'FAIL','group':group}
            try:
                guard_authority(authority)
                request = {'schema':'hepta.hia.linux-process-cold-request.v1','group':group,
                    'fixture':str(selected),'fixture_binding':pin(selected),
                    'source_manifest':authority['source_manifest'],'output':str(folder/group)}
                request_path = folder/(group+'-REQUEST.json');publish(request_path,request)
                request_raw = request_path.read_bytes()
                child_env = {**environment,COLD_FIXTURE_ENV:str(selected),
                             EVIDENCE_ENV:str(folder/group/'observations'),
                             SOURCE_EVIDENCE_ENV:str(folder/group/'observations/portable')}
                command = [sys.executable,'-I','-B',str(Path(__file__).resolve()),
                           '--child-request',str(request_path)]
                result['owner'] = _owner(command,child_env,folder/(group+'-command'))
                path = folder/group/'RESULT.json'
                if path.is_file():
                    child = decode(path.read_bytes());result['observations']=child
                else:
                    raise ValueError('owned group has no complete terminal report: '+group)
                require(_owner_pass(result['owner']),'original group owner deadline/exit/cleanup failed')
                admit_child_report(child,digest(request_raw),group)
                result['actual'] = verify_actual_observations(group,folder/group/'observations',fixture)
                require(request_path.read_bytes()==request_raw and pin(selected)==request['fixture_binding'],
                        'group request or fixture changed')
                result['status']='PASS'
            except BaseException:
                result.update(status='FAIL',traceback=traceback.format_exc())
            report['groups'][group]=result
            # A normal observation failure does not skip later retained groups.
            # Actual source drift is a refusal, not permission to keep executing.
            guard_authority(authority)
        require(set(report['groups'])==set(GROUP_ORDER)
                and all(report['groups'][g]['status']=='PASS' for g in GROUP_ORDER),
                'one or more complete process groups failed')
        require(admit_fixture(selected)==fixture,'final fixture differs')
        report.update(status='MATCHING_CURRENT_SOURCE_COLD_LINUX_PROCESS_PASS',
            matching_cold=True,qualification_complete=True,
            tests_run=sum(GROUP_COUNTS.values()))
    except BaseException:
        report.update(status='FAIL',matching_cold=False,qualification_complete=False,traceback=traceback.format_exc())
    finally:
        try:
            guard_authority(authority)
            if fixture is not None:
                require(admit_fixture(folder/'fixture/FIXTURE.json')==fixture,'final fixture changed')
            require(_check_test_sources() == caller_admission,
                    'complete process caller bytes changed during qualification')
            report.update(source_and_inputs_unchanged=True,source_after=authority['source_manifest'])
        except BaseException:
            report.update(status='FAIL',matching_cold=False,qualification_complete=False,
                          source_and_inputs_unchanged=False,final_guard_error=traceback.format_exc())
        report['wall_ns']=time.monotonic_ns()-started
        publish(folder/'QUALIFICATION.json',report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report',type=Path)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--prepare-output',type=Path)
    parser.add_argument('--child-request',type=Path)
    args=parser.parse_args(argv)
    if args.child_request is not None:
        require(args.cold_report is None and args.evidence is None and args.prepare_output is None,
                'child request cannot mix qualifier inputs')
        return _child(args.child_request)
    if args.prepare_output is not None:
        require(args.cold_report is not None and args.evidence is None,'explicit cold preparation required')
        return _prepare(args.prepare_output,args.cold_report)
    require(args.cold_report is not None and args.evidence is not None,'--cold-report and --evidence required')
    report=qualify(args.cold_report,args.evidence)
    print(wire({key:report[key] for key in ('status','scope','matching_cold','qualification_complete','whole_native')}).decode(),end='')
    return 0 if report['status']=='MATCHING_CURRENT_SOURCE_COLD_LINUX_PROCESS_PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
