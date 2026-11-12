"""Fixed finite corpus; no case or product is executed on import."""

RUNTIME_IDS = (
    'runtime.exact_dso_layout',
    'runtime.base_eleven_live_symbols',
    'runtime.control_five_live_symbols',
    'runtime.reject_wrong_file_sha',
    'runtime.reject_wrong_file_size',
    'runtime.exact_rebind_is_idempotent',
    'runtime.changed_base_table_refused',
    'runtime.changed_control_table_refused',
)

LIFETIME_IDS = (
    'lifetime.normal_none_forward_locals',
    'lifetime.normal_ambient_exception_restored',
    'lifetime.error_stack_reverse_and_locals_retained',
    'lifetime.generator_handled_context_named_leaf',
    'lifetime.yield_preserves_owned_result_and_suspend',
    'lifetime.one_use_duplicate_no_new_calls',
    'lifetime.trace_overflow_continues_and_is_incomplete',
    'lifetime.dirty_workspace_preentry_rejection_keeps_owners',
    'lifetime.python_bookkeeping_failure_quarantines',
    'lifetime.owned_return_survives_actual_frame_clear',
)

RAW_LEAF_ONLY_IDS = (
    'lifetime.generator_handled_context_named_leaf',
    'lifetime.owned_return_survives_actual_frame_clear',
)
NORMAL_EFFECTS = (95, 17, 96, 6, 106)
YIELD_EFFECTS = (95, 107)
ERROR_TWO_STACK_EFFECTS = (95, 97, 100, 6, 100, 6, 96, 106)
EXPECTED_HIA_RETURNS = (6, 6, 9, 0, 9, 6, 6, 0, 6, 0)
EXPECTED_C_PUMP_CALLS = (1, 1, 1, 0, 2, 2, 1, 1, 2, 0)

UNEXECUTED_SCOPES = (
    'original 17 CLI methods', 'original 46 trace plan', 'complete JSON graph',
    'body CALL/SEND/UNPACK ports', 'whole evaluator activation and monitoring',
    'CPython 3.14 profiles', 'fresh B0/B1/B2 or matching cold qualification',
    'installation', 'default selection',
)
