#!/usr/bin/env python3
"""Fixed-source offline tests only; no native or performance qualification.

The workflow verifies Git commit/tree before invoking this runner. Auditing
begins before project imports. Guards prevent accidental external execution
by these reviewed tests, not arbitrary hostile Python code sandboxing.
Only stdout/stderr receipts are emitted; no artifacts are uploaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

SPEC = {'aot': {'commit': '7de8bc98cc51c0cc13376fa4031d63758921c9d8',
         'tree': 'd6cbf9de2d99e1b655e68cb93425fd7eef9e327a',
         'modules': ['tests.test_hia_outlined_aot_protocol',
                     'tests.test_hia_reduction_release',
                     'tests.test_hia_reduction_multiload',
                     'tests.test_hia_empty_reduction_observation'],
         'tests': ['tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_all_old_lengths_loads_thresholds_and_both_strong_rust_arms_remain',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_assessment_preserves_inputs_and_is_independent_of_row_order',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_committed_protocol_matches_executable_registration',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_declared_sample_count_is_required_and_exact_for_every_arm_and_load',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_elapsed_total_is_required_and_exact_for_every_arm_and_load',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_every_receipt_uses_the_existing_native_measurement_contract',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_exact_maximum_uint64_total_remains_admissible',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_final_cohort_accounting_cannot_be_ignored',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_missing_or_invalid_timing_vector_fails_closed',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_missing_rust_arm_duplicate_row_changed_sample_and_relaxed_gate_fail',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_native_uint64_sample_and_total_bounds_are_not_python_integer_bounds',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_one_tail_failure_stays_visible_in_its_own_load',
                   'tests.test_hia_outlined_aot_protocol.OutlineProtocolTests.test_wrapped_elapsed_total_cannot_mask_overflow',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_driver_rejects_wrong_work_even_for_zero_length_checksums',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_elapsed_total_and_sample_vector_must_reconcile',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_frozen_historical_registration_rejects_empty_or_relaxed_campaign',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_full_cost_selects_best_rust_at_each_horizon',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_missing_duplicate_or_trimmed_observation_cannot_pass',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_observed_work_requires_exact_native_integer_identity',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_one_negative_length_is_retained_in_full_gate',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_periodic_oracle_matches_direct_arbitrary_seeds_and_tails',
                   'tests.test_hia_reduction_release.ReductionReleaseTests.test_registration_does_not_equate_boolean_and_integer',
                   'tests.test_hia_reduction_multiload.ReductionMultiloadTests.test_all_lengths_loads_workloads_and_seeds_are_separate_observations',
                   'tests.test_hia_reduction_multiload.ReductionMultiloadTests.test_missing_load_changed_work_and_relaxed_protocol_cannot_qualify',
                   'tests.test_hia_reduction_multiload.ReductionMultiloadTests.test_multiload_receipts_retain_sample_count_and_elapsed_identity',
                   'tests.test_hia_reduction_multiload.ReductionMultiloadTests.test_one_tail_spike_cannot_be_pooled_away_by_a_different_batch_load',
                   'tests.test_hia_reduction_multiload.ReductionMultiloadTests.test_original_protocol_identity_is_preserved',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_boolean_integer_aliases_are_refused_in_both_profiles',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_empty_input_regression_is_not_erased_by_faster_nonempty_cases',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_full_v2_gate_and_both_rust_comparators_remain_present',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_missing_duplicate_boolean_or_padded_samples_fail_closed',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_native_sample_identity_and_elapsed_ledger_are_required',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_registration_mutations_fail_closed',
                   'tests.test_hia_empty_reduction_observation.EmptyReductionObservationTests.test_wrapper_profile_keeps_historical_gate_and_uses_new_lengths']},
 'ndu': {'commit': '5b56dcb9543611d7455c009ca79cd485480ed7c4',
         'tree': 'ea520855318ad1d588a797e7c927c9e1efba2ffd',
         'modules': ['tests.test_hia_ndu_failure_accounting',
                     'tests.test_hia_ndu_controller_deadline',
                     'tests.test_hia_ndu_current_profile.CurrentProfileTests',
                     'tests.test_hia_ndu_cost'],
         'tests': ['tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_failed_factory_keeps_cost_without_claiming_process_state',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_failed_request_keeps_cost_and_cleanup_for_new_or_existing_session',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_failed_startup_without_feasible_incumbent_remains_refusal',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_failure_then_retry_keeps_separate_attempt_costs',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_late_successful_startup_is_not_a_no_start_episode',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_non_bridge_exception_is_not_converted_to_a_native_refusal',
                   'tests.test_hia_ndu_failure_accounting.FailureAccountingTests.test_skip_with_existing_session_does_not_claim_no_session',
                   'tests.test_hia_ndu_failure_accounting.NoStartEvidenceTests.test_episode_receipts_require_zero_calls_no_session_and_nonempty_steps',
                   'tests.test_hia_ndu_failure_accounting.NoStartEvidenceTests.test_explicit_skips_count_once_without_mutating_receipts',
                   'tests.test_hia_ndu_failure_accounting.NoStartEvidenceTests.test_legacy_receipts_without_attempt_evidence_are_unknown',
                   'tests.test_hia_ndu_failure_accounting.NoStartEvidenceTests.test_unknown_or_conflicting_decision_evidence_cannot_count',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_deadline_fallback_retains_valid_incumbent',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_existing_session_also_rejects_late_projection',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_native_failure_keeps_error_and_incumbent_fallback',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_no_model_feasible_incumbent_returns_refusal',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_projection_time_is_also_charged_before_action_return',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_response_at_or_after_deadline_cannot_acquire_artifacts',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_timely_response_preserves_native_projection',
                   'tests.test_hia_ndu_controller_deadline.ControllerDeadlineTests.test_valid_receipt_is_preserved_when_its_optional_action_is_withheld',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_explicit_profiles_require_distinct_sources',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_failed_attempt_does_not_count_as_a_completed_model_evaluation',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_failed_call_cannot_be_hidden_by_a_matching_successful_subset',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_known_build_is_charged_once_only_to_native',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_known_execution_cost_does_not_fill_unmeasured_lifecycle_costs',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_no_invocation_is_unknown_agreement',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_started_session_without_evaluation_is_not_a_no_start_episode',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_unknown_build_never_becomes_zero_cost',
                   'tests.test_hia_ndu_current_profile.CurrentProfileTests.test_unknown_profile_refuses_before_io',
                   'tests.test_hia_ndu_cost.FullCostTests.test_all_first_actions_match_independent_budgeted_enumeration',
                   'tests.test_hia_ndu_cost.FullCostTests.test_budget_and_sunk_cost_are_not_double_charged',
                   'tests.test_hia_ndu_cost.FullCostTests.test_budget_filter_preserves_exact_boundary_and_ties',
                   'tests.test_hia_ndu_cost.FullCostTests.test_exact_matches_independent_enumeration',
                   'tests.test_hia_ndu_cost.FullCostTests.test_future_decisions_can_cancel_short_lived_gain',
                   'tests.test_hia_ndu_cost.FullCostTests.test_invalidation_retires_even_on_skip',
                   'tests.test_hia_ndu_cost.FullCostTests.test_native_request_charges_committed_current_call',
                   'tests.test_hia_ndu_cost.FullCostTests.test_native_witnesses_do_not_share_mutable_tail_actions',
                   'tests.test_hia_ndu_cost.FullCostTests.test_proof_prepare_holding_and_session_close_are_charged',
                   'tests.test_hia_ndu_cost.FullCostTests.test_rejected_variant_not_recovered_by_digest',
                   'tests.test_hia_ndu_cost.FullCostTests.test_skip_does_not_create_session',
                   'tests.test_hia_ndu_cost.FullCostTests.test_strict_model_rejects_unbounded_or_implicit_fields']}}


class OfflineViolation(RuntimeError):
    pass


def source_snapshot(root):
    inventory = {}
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(name for name in subdirectories if name != ".git")
        for name in sorted(files):
            path = Path(directory) / name
            if name == ".git":
                continue
            key = str(path.relative_to(root))
            if path.is_symlink():
                inventory[key] = ["symlink", os.readlink(path)]
            else:
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                inventory[key] = ["file", digest.hexdigest()]
    return hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()


def inside_source(path, root):
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    resolved = Path(os.fsdecode(path)).resolve()
    return resolved == root or root in resolved.parents


class ExecutionGuard:
    def __init__(self, root):
        self.root = root
        self.blocked = []

    def __call__(self, event, args):
        denied = (event.startswith("subprocess.") or event.startswith("socket.")
                  or event.startswith("ctypes.")
                  or event in {"os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty",
                               "os.startfile", "os.startfile/2", "pty.spawn"})
        if event == "open":
            path, mode, flags = args
            write = ((isinstance(mode, str) and any(flag in mode for flag in "wax+"))
                     or (isinstance(flags, int) and bool(flags &
                         (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))))
            denied = denied or (write and inside_source(path, self.root))
        if event in {"os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate",
                     "os.utime", "os.rename", "os.link", "os.symlink"}:
            denied = denied or any(inside_source(path, self.root) for path in args[:2])
        if denied:
            self.blocked.append(event)
            raise OfflineViolation("offline test guard rejected " + event)


def guard_selftest(guard):
    # Audit events precede these actions. No child or socket is created.
    controls = (
        ("subprocess.Popen", lambda: subprocess.Popen([sys.executable, "-c", "raise SystemExit(99)"])),
        ("socket.__new__", lambda: socket.socket()),
        ("ctypes.dlopen", lambda: sys.audit("ctypes.dlopen", "offline-denied-sentinel")),
    )
    observed = []
    for event, action in controls:
        before = len(guard.blocked)
        try:
            action()
        except OfflineViolation:
            pass
        else:
            raise AssertionError("execution guard self-test did not reject " + event)
        if guard.blocked[before:] != [event]:
            raise AssertionError("execution guard self-test identity differs")
        observed.append(event)
    guard.blocked.clear()
    return observed


class StrictResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.finished = []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished.append(test.id())
        super().stopTest(test)


def identities(suite):
    found = []
    for item in suite:
        found.extend(identities(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--suite", choices=tuple(SPEC), required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    specification = SPEC[args.suite]
    if os.environ.get("PINNED_COMMIT") != specification["commit"]:
        raise ValueError("workflow source commit does not match runner")
    if os.environ.get("PINNED_TREE") != specification["tree"]:
        raise ValueError("workflow source tree does not match runner")
    before = source_snapshot(root)
    sys.dont_write_bytecode = True
    guard = ExecutionGuard(root)
    sys.addaudithook(guard)
    selftests = guard_selftest(guard)
    # -I excludes inherited PYTHONPATH and the current directory. Only the
    # exact checked-out source becomes the project import root after guards.
    sys.path.insert(0, str(root))
    suite = unittest.defaultTestLoader.loadTestsFromNames(specification["modules"])
    planned = identities(suite)
    if planned != specification["tests"] or len(planned) != len(set(planned)):
        raise ValueError("offline test identity inventory changed")
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    after = source_snapshot(root)
    passed = (result.testsRun == len(planned) and result.started == planned
              and result.finished == planned and not result.errors and not result.failures
              and not result.skipped and not result.expectedFailures
              and not result.unexpectedSuccesses and before == after and not guard.blocked)
    receipt = {
        "schema": "hepta.isolated-offline-receipts.v1", "passed": passed,
        "suite": args.suite, "source_commit": specification["commit"],
        "source_tree": specification["tree"], "python": sys.version,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "planned": planned, "started": result.started, "finished": result.finished,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "guard_selftest_rejections": selftests, "forbidden_test_attempts": guard.blocked,
        "source_snapshot_before": before, "source_snapshot_after": after,
        "source_unchanged": before == after, "frozen_raw_replay_performed": False,
        "native_or_performance_qualification": False, "artifact_upload_performed": False,
        "pr_head_check": False,
    }
    print("OFFLINE_RECEIPT=" + json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

