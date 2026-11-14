"""Fixed object-port names for the original Agent evaluation continuation.

These numbers identify foreign primitives. They contain no routing, branch,
loop, outcome policy, executable paths or caller-supplied code.
"""

PORTS = (
    'start', 'context', 'baseline', 'candidate', 'build_receipt',
    'baseline_not_shared', 'candidate_not_shared', 'abi_equal',
    'baseline_pinned', 'baseline_equal', 'claims', 'workload',
    'validate_workload', 'validate_cases', 'exports_init', 'exports_next',
    'exports_append', 'exports_finish', 'collections', 'reference_started',
    'deadline_row', 'deadline', 'references_init', 'reference_run',
    'reference_returned', 'reference_complete', 'reference_budget',
    'reference_report_present', 'reference_rows_init', 'reference_rows_next',
    'reference_row_budget', 'cases_init', 'case_next', 'case_expired',
    'case_references', 'case_budget', 'expected_value', 'declared_present',
    'declared_buffers', 'declared_with_buffers', 'declared_without_init',
    'declared_without_next', 'declared_key_buffers', 'declared_insert',
    'declared_equal', 'observables_equal', 'prepared', 'expected_trapped',
    'append_trap', 'append_normal', 'reference_done', 'native_started',
    'owner', 'claim', 'arm_init', 'normal_present', 'normal_cases_init',
    'normal_cases_next', 'normal_cases_append', 'normal_run', 'normal_store',
    'normal_returned', 'normal_budget', 'normal_report',
    'normal_completed_differs', 'normal_observations_differ', 'normal_total',
    'normal_observations_init', 'normal_observations_next', 'normal_value',
    'normal_observation_store', 'normal_mismatch', 'normal_value_equal',
    'traps_init', 'trap_next', 'trap_run', 'trap_store', 'trap_has_buffers',
    'trap_buffer_store', 'trap_buffers_equal', 'trap_is_trapped',
    'trap_terminal_failure', 'trap_is_budget', 'claim_complete', 'native_ns',
    'complete_count', 'complete_rows_init', 'complete_rows_next',
    'complete_row_baseline', 'complete_row_candidate', 'metric_artifact',
    'measure_artifact', 'measure_native', 'before_nonzero', 'ratio',
    'ratio_zero', 'metric_latency', 'traps_present', 'after_smaller',
    'ratio_threshold', 'after_greater', 'measurements', 'costs', 'ledger',
    'receipt', 'result', 'reject_profile', 'reject_abi', 'reject_baseline',
    'reject_expected', 'reject_report',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
OUTCOMES = ('', 'budget_exceeded', 'incorrect', 'inconclusive',
            'improved', 'regressed', 'unchanged')
