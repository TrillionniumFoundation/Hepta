"""Fixed foreign operations for the two complete emission control flows.

HIA owns their branch, loop, context-exit and exception-continuation choices.
Opaque object protocols and the original Core, emitter, linker, filesystem,
Store, clock and digest implementations remain explicit foreign providers.
"""

PORTS = (
    'compile_arguments', 'compile_budget_expired', 'compile_deadline',
    'compile_emit', 'compile_object_not_bytes', 'compile_temporary',
    'compile_context_lookup_next', 'compile_context_lookup_enter',
    'compile_context_lookup_exit', 'compile_enter',
    'compile_output_prefix', 'compile_kind_object',
    'compile_output_object', 'compile_output_shared', 'compile_remaining',
    'compile_remaining_positive', 'compile_timeout_zero',
    'compile_timeout_remaining', 'compile_timeout_below_bound',
    'compile_timeout_bound', 'compile_call', 'compile_read',
    'compile_exit_normal', 'compile_exit_exception', 'compile_exit_truth',
    'compile_pop_output', 'compile_commands', 'compile_object_digest_differs',
    'compile_core_digest_differs', 'compile_artifact_digest_value', 'compile_artifact_digest_differs',
    'compile_final_kind_object', 'compile_final_bytes_differs',
    'compile_store_object', 'compile_result',
    'reject_budget', 'reject_object_bytes', 'reject_build',
    'unbound_compile_result', 'unbound_compile_data',
    'emit_arguments_profile', 'emit_context', 'emit_program',
    'emit_receipts_init', 'emit_receipt_next', 'emit_verify_receipt',
    'emit_receipts_release',
    'emit_codegen', 'emit_canonical', 'emit_lowering_profile',
    'emit_plan_profile', 'emit_plan_get', 'emit_plan_validate',
    'emit_plan_verify', 'emit_expected_subject', 'emit_subject_differs',
    'emit_checks_init', 'emit_checks_reiterate', 'emit_check_next', 'emit_claim_compare',
    'emit_claim_truth', 'emit_status_compare', 'emit_check_truth',
    'emit_checks_release_pass', 'emit_checks_release_reject',
    'reject_plan', 'emit_exports_init', 'emit_exports_next',
    'emit_exports_append', 'emit_exports_finish', 'emit_compile_function',
    'emit_compile_arguments', 'emit_exports_present',
    'emit_compile_with_exports', 'emit_compile_without_exports',
    'emit_metadata_prefix', 'emit_export_lists_init',
    'emit_export_lists_next', 'emit_export_lists_append',
    'emit_export_lists_release',
    'emit_metadata_finish', 'emit_native_put', 'emit_receipt_put',
    'emit_result',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
MODES = {'compile': 1, 'emit': 2}
