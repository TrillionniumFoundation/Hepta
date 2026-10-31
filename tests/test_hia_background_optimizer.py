"""Actual scalar native publication with controlled optimizer races/cost inputs.

Ranking is replaced in lifecycle tests only. Canonical verification, Z3 proof,
LLVM compilation, sealed loading and native calls remain real. The separate
qualification tool also executes the original native NDU evaluator.
"""
from __future__ import annotations

import copy
from concurrent.futures import CancelledError, as_completed, wait
from hashlib import sha256
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hepta.hia_background_optimizer import (BackgroundOptimizationRejected, BackgroundOptimizer,
                                           _OptimizationFuture)
from hepta.hia_multiversion import (MultiversionRejected, PublicationCancellation,
                                   ScalarMultiversionRuntime)
from hepta.hia_ndu_optimizer import SCHEMA as RANK_SCHEMA
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import TARGET
from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def proposal(program=None):
    return [{"id": "rewrite", "action": "controlled_equivalent_rewrite",
             "program": scalar_program(None) if program is None else program}]


def measurements(baseline, candidates, *, incumbent_ns=1_000_000, candidate_ns=1):
    result = {"abstain": {"runtime_ns": incumbent_ns, "uncertainty_ns": 0, "search_ns": 0,
                           "program_sha256": verify_program(baseline).sha256}}
    for row in candidates:
        result[row["id"]] = {"runtime_ns": candidate_ns, "uncertainty_ns": 0, "search_ns": 0,
                              "program_sha256": verify_program(row["program"]).sha256}
    return result


def objective(*, calls=10_000):
    return {"expected_calls": calls, "resource_cap_ns": 5_000_000_000, "target": TARGET,
            "measurement_profile": "synthetic_lifecycle_test_not_a_speedup_measurement"}


def controlled_rank(baseline, candidates, observations, *, function, objective, generation, **unused):
    """Bind exact test inputs; deliberately leave real proof to the runtime."""
    before = verify_program(baseline)
    selected = candidates[0]["id"] if candidates else "abstain"
    supplied = sum(row["search_ns"] for row in observations.values())
    base = observations["abstain"]
    observed = observations[selected]
    margin = ((max(0, base["runtime_ns"] - base["uncertainty_ns"])
               - observed["runtime_ns"] - observed["uncertainty_ns"]) * objective["expected_calls"]
              - supplied)
    admitted = selected != "abstain" and margin > 0 and supplied <= objective["resource_cap_ns"]
    if not admitted:
        selected = "abstain"
    return {"schema": RANK_SCHEMA, "before_sha256": before.sha256,
            "before_input_sha256": before.input_sha256, "function": function,
            "generation": generation, "objective": objective,
            "objective_sha256": digest({"schema": RANK_SCHEMA, "objective": objective,
                                        "function": function, "before_sha256": before.sha256,
                                        "before_input_sha256": before.input_sha256}),
            "observations_sha256": digest(observations), "selected_id": selected,
            "admitted": admitted, "net_margin_ns": margin if admitted else 0,
            "selected_program": candidates[0]["program"] if admitted else before.as_dict(),
            "reason": "controlled_lifecycle_test",
            "costs": {"supplied_search_ns": supplied, "actual_adapter_ns": 0,
                      "total_search_ns": supplied}}


class CancellationTokenTests(unittest.TestCase):
    def test_cancel_is_idempotent_and_token_cannot_be_copied(self):
        token = PublicationCancellation()
        self.assertTrue(token.cancel())
        self.assertTrue(token.cancel())
        self.assertTrue(token.cancelled())
        self.assertFalse(token.committed())
        for clone in (copy.copy, copy.deepcopy):
            with self.assertRaises(MultiversionRejected):
                clone(token)

    def test_cancel_callbacks_can_join_a_worker_completing_the_same_future(self):
        future = _OptimizationFuture(PublicationCancellation())
        release = threading.Event()
        worker = threading.Thread(target=lambda: (release.wait(5), future._complete({"status": "abstained"})))
        worker.start()
        joined = []
        def cancel_callback(done):
            release.set()
            worker.join(1)
            joined.append(not worker.is_alive())
        future.add_done_callback(cancel_callback)
        try:
            self.assertTrue(future.cancel())
            self.assertEqual(joined, [True])
            self.assertEqual(wait([future], timeout=0).done, {future})
        finally:
            release.set()
            worker.join(5)


@unittest.skipUnless(_NATIVE, "actual Clang 20+, Z3 and Linux sealed memfd are required")
class BackgroundNativeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hia-background-test-")
        self.addCleanup(directory.cleanup)
        self.baseline = scalar_program()
        self.runtime = ScalarMultiversionRuntime(self.baseline, directory.name, clang=_CLANG)
        self.addCleanup(self.runtime.close)

    def coordinator(self, **options):
        coordinator = BackgroundOptimizer(self.runtime, self.baseline, function="calculate",
                                          bridge={"binary": "/unused/test-bridge",
                                                  "build_receipt": "/unused/test-receipt"}, **options)
        self.addCleanup(coordinator.shutdown)
        return coordinator

    def submit(self, coordinator, candidates=None, *, incumbent_ns=1_000_000, calls=10_000):
        candidates = proposal() if candidates is None else candidates
        return coordinator.submit(candidates, measurements(self.baseline, candidates,
                                                           incumbent_ns=incumbent_ns),
                                  objective(calls=calls))

    def assert_baseline(self):
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.runtime.call("calculate", [2**64 - 1]), 2**64 - 1)
        self.assertEqual(sorted(path.name for path in self.runtime._directory.iterdir()), ["generation-0.so"])

    def test_actual_conditional_publication_records_cost_and_commits_token(self):
        token = PublicationCancellation()
        published = self.runtime.publish_if_current(scalar_program(None), 0, expected_epoch=0,
                                                    max_prepare_ns=5_000_000_000, cancellation=token)
        self.assertEqual(published["selection_epoch"], 1)
        self.assertGreater(published["prepare_ns"], 0)
        self.assertLessEqual(published["prepare_ns"], published["max_prepare_ns"])
        self.assertEqual(published["generation"]["translation_proofs"], 1)
        self.assertTrue(token.committed())
        self.assertFalse(token.cancel())
        self.assertEqual(self.runtime.call("calculate", [2**63]), 2**63)
        with self.assertRaisesRegex(MultiversionRejected, "already committed"):
            self.runtime.publish_if_current(scalar_program(None), published["generation"]["generation"],
                                            expected_epoch=1, max_prepare_ns=5_000_000_000,
                                            cancellation=token)

    def test_cancelled_zero_budget_and_wrong_types_do_not_build(self):
        token = PublicationCancellation()
        token.cancel()
        cases = [(0, 0, 5_000_000_000, token), (0, 0, 0, PublicationCancellation()),
                 (False, 0, 100, PublicationCancellation()),
                 (0, False, 100, PublicationCancellation()),
                 (0, 0, True, PublicationCancellation())]
        with patch("hepta.hia_multiversion.build_program_native") as build:
            for generation, epoch, budget, cancellation in cases:
                with self.subTest(generation=generation, epoch=epoch, budget=budget):
                    with self.assertRaises(MultiversionRejected):
                        self.runtime.publish_if_current(scalar_program(None), generation,
                                                        expected_epoch=epoch, max_prepare_ns=budget,
                                                        cancellation=cancellation)
            build.assert_not_called()
        for timestamp in (True, time.perf_counter_ns() + 10**15):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(MultiversionRejected, "handoff"):
                self.runtime.publish_if_current(scalar_program(None), 0, expected_epoch=0,
                                                max_prepare_ns=5_000_000_000,
                                                cancellation=PublicationCancellation(),
                                                preparation_started_ns=timestamp)
        self.assert_baseline()

    def test_successive_jobs_rank_against_the_source_actually_published(self):
        coordinator = self.coordinator()
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank) as rank:
            first = self.submit(coordinator).result(10)
            self.assertEqual(first["status"], "published", first)
            now = scalar_program(None)
            candidates = proposal(scalar_program("bit.xor"))
            second = coordinator.submit(candidates, measurements(now, candidates), objective()).result(10)
            self.assertEqual(second["status"], "published", second)
        self.assertEqual(rank.call_count, 2)
        self.assertEqual(second["before_sha256"], verify_program(now).sha256)
        self.assertEqual(second["expected_generation"], first["publication"]["generation"]["generation"])
        self.assertEqual(second["decision_generation"], first["publication"]["selection_epoch"] + 1)
        self.assertGreater(second["costs"]["net_margin_before_postcommit_reporting_ns"], 0)
        self.assertFalse(second["claims"]["performance_improvement_established"])
        self.assertEqual(self.runtime.call("calculate", [37]), 37)

    def test_optimizer_admission_does_not_bypass_actual_behavior_proof(self):
        coordinator = self.coordinator()
        candidates = proposal(scalar_program(value=1))
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch("hepta.hia_multiversion.build_program_native") as build:
            result = self.submit(coordinator, candidates).result(10)
            build.assert_not_called()
        self.assertEqual(result["status"], "rejected")
        self.assertIn("disproved", result["detail"])
        self.assertIsNotNone(result["ranking"], "completed ranking was lost after publication refusal")
        self.assertGreater(result["costs"]["publication_call_wall_ns"], 0)
        receipt = coordinator.snapshot()["cost_accounting"]["recent_jobs"][-1]
        self.assertEqual(receipt["execution_status"], "rejected")
        self.assertTrue(receipt["ranking_returned"])
        self.assertFalse(receipt["publication_committed"])
        self.assertGreater(receipt["costs"]["observed_submit_and_worker_ns"], 0)
        self.assert_baseline()

    def test_unknown_publication_proof_preserves_the_native_head(self):
        coordinator = self.coordinator()
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch("hepta.hia_translation_validation.validate_translation", return_value={"status": "unknown"}):
            result = self.submit(coordinator).result(10)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("unknown", result["detail"])
        self.assert_baseline()

    def test_unbound_rank_output_and_wrong_exact_cost_types_reject(self):
        coordinator = self.coordinator()
        mutations = [lambda r: r.update(before_sha256="f" * 64),
                     lambda r: r.update(generation=True),
                     lambda r: r.update(objective_sha256="f" * 64),
                     lambda r: r.update(observations_sha256="f" * 64),
                     lambda r: r.update(net_margin_ns=True),
                     lambda r: r.update(selected_program=scalar_program(value=1)),
                     lambda r: r["costs"].update(actual_adapter_ns=2**62)]
        for mutation in mutations:
            def changed(*args, **kwargs):
                report = controlled_rank(*args, **kwargs)
                mutation(report)
                return report
            with self.subTest(mutation=mutation), patch("hepta.hia_background_optimizer.rank_candidates", side_effect=changed):
                result = self.submit(coordinator).result(10)
                self.assertEqual(result["status"], "rejected", result)
        self.assert_baseline()

    def test_no_positive_economic_margin_abstains_without_build(self):
        coordinator = self.coordinator()
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch("hepta.hia_multiversion.build_program_native") as build:
            result = self.submit(coordinator, incumbent_ns=1).result(10)
            build.assert_not_called()
        self.assertEqual(result["status"], "abstained", result)
        ledger = coordinator.snapshot()["cost_accounting"]
        self.assertEqual(ledger["settled_jobs"], 1)
        self.assertEqual(ledger["execution_outcomes_at_accounting"], {"abstained": 1})
        paid = ledger["observed_submit_and_worker_ns"]
        self.assertGreater(paid, 0)
        result["costs"].clear()
        ledger["recent_jobs"][0]["costs"].clear()
        retained = coordinator.snapshot()["cost_accounting"]
        self.assertEqual(retained["observed_submit_and_worker_ns"], paid)
        self.assertEqual(retained["recent_jobs"][0]["costs"]["observed_submit_and_worker_ns"], paid)
        self.assert_baseline()

    def test_cost_observation_does_not_predict_later_future_cancellation(self):
        coordinator = self.coordinator()
        recorded, release = threading.Event(), threading.Event()
        account = coordinator._account_job
        def observed_account(job, result):
            account(job, result)
            recorded.set()
            if not release.wait(10):
                raise RuntimeError("accounting barrier was not released")
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch.object(coordinator, "_account_job", side_effect=observed_account):
            future = self.submit(coordinator, incumbent_ns=1)
            try:
                self.assertTrue(recorded.wait(10))
                self.assertTrue(future.cancel())
            finally:
                release.set()
                coordinator.shutdown(cancel_pending=False)
        self.assertTrue(future.cancelled())
        ledger = coordinator.snapshot()["cost_accounting"]
        self.assertEqual(ledger["settled_jobs"], 1)
        self.assertEqual(ledger["execution_outcomes_at_accounting"], {"abstained": 1})
        receipt = ledger["recent_jobs"][0]
        self.assertEqual(receipt["execution_status"], "abstained")
        self.assertEqual(receipt["future_state_at_accounting"], "pending")
        self.assertIn("not a Future terminal-state claim", receipt["status_scope"])
        self.assertNotIn("status", receipt)
        self.assertGreater(ledger["observed_submit_and_worker_ns"], 0)
        self.assertEqual(ledger["observed_submit_and_worker_ns"],
                         receipt["costs"]["observed_submit_and_worker_ns"])
        self.assert_baseline()

    def test_real_preparation_over_budget_is_disposed_without_selection(self):
        coordinator = self.coordinator()
        prepare = self.runtime._prepare
        def slow_prepare(*args, **kwargs):
            state = prepare(*args, **kwargs)
            threading.Event().wait(0.15)
            return state
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch.object(self.runtime, "_prepare", side_effect=slow_prepare):
            result = self.submit(coordinator, incumbent_ns=101, calls=1_000_000).result(10)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("preparation budget", result["detail"])
        self.assert_baseline()

    def test_current_snapshot_change_and_rollback_aba_invalidate_queued_result(self):
        coordinator = self.coordinator()
        for rollback in (False, True):
            self.runtime.rollback()
            entered, release = threading.Event(), threading.Event()
            def delayed(*args, **kwargs):
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("test worker was not released")
                return controlled_rank(*args, **kwargs)
            with self.subTest(rollback=rollback), patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed):
                future = self.submit(coordinator)
                try:
                    self.assertTrue(entered.wait(10))
                    external = self.runtime.publish(scalar_program("bit.xor"))
                    if rollback:
                        self.runtime.rollback()
                    before = self.runtime.snapshot()
                finally:
                    release.set()
                result = future.result(10)
            self.assertEqual(result["status"], "stale", result)
            after = self.runtime.snapshot()
            self.assertEqual(before["current_generation"], after["current_generation"])
            self.assertEqual(before["selection_epoch"], after["selection_epoch"])
            if not rollback:
                self.assertEqual(after["current_generation"], external.generation)

    def test_queued_job_is_not_silently_rebased_after_first_publication(self):
        coordinator = self.coordinator(max_pending=2)
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test worker was not released")
            return controlled_rank(*args, **kwargs)
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                second = self.submit(coordinator)
            finally:
                release.set()
            self.assertEqual(first.result(10)["status"], "published")
            self.assertEqual(second.result(10)["status"], "stale")
        self.assertEqual(rank.call_count, 1)

    def test_cancel_during_real_native_preparation_reclaims_unpublished_artifact(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        prepare = self.runtime._prepare
        def paused_prepare(*args, **kwargs):
            state = prepare(*args, **kwargs)
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test worker was not released")
            return state
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch.object(self.runtime, "_prepare", side_effect=paused_prepare):
            future = self.submit(coordinator)
            callback_results = []
            future.add_done_callback(lambda done: callback_results.append(wait([done], timeout=0)))
            try:
                self.assertTrue(entered.wait(10))
                self.assertTrue(future.cancel())
                self.assertEqual(wait([future], timeout=0).done, {future})
                self.assertEqual(list(as_completed([future], timeout=1)), [future])
                self.assertEqual(callback_results[0].done, {future})
            finally:
                release.set()
            coordinator.shutdown()
        self.assertTrue(future.cancelled())
        ledger = coordinator.snapshot()["cost_accounting"]
        self.assertEqual(ledger["settled_jobs"], 1)
        receipt = ledger["recent_jobs"][0]
        self.assertEqual(receipt["execution_status"], "cancelled")
        self.assertEqual(receipt["future_state_at_accounting"], "cancelled")
        self.assertTrue(receipt["ranking_returned"])
        self.assertFalse(receipt["publication_committed"])
        self.assertGreater(receipt["costs"]["publication_call_wall_ns"], 0)
        self.assertGreater(receipt["costs"]["observed_submit_and_worker_ns"], 0)
        # This unit rank fixture explicitly reports zero adapter time. Preserve
        # that value; the real-bridge qualifier separately requires paid work.
        self.assertEqual(receipt["reported_ranking_costs"]["actual_adapter_ns"], 0)
        self.assertGreaterEqual(receipt["reported_ranking_costs"]["total_search_ns"],
                                receipt["reported_ranking_costs"]["actual_adapter_ns"])
        with self.assertRaises(CancelledError):
            future.result()
        self.assert_baseline()

    def test_cancel_after_atomic_commit_returns_false_even_before_future_completion(self):
        coordinator = self.coordinator()
        committed, release = threading.Event(), threading.Event()
        publish = self.runtime.publish_if_current
        def after_publish(*args, **kwargs):
            result = publish(*args, **kwargs)
            committed.set()
            if not release.wait(10):
                raise RuntimeError("test worker was not released")
            return result
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank), \
                patch.object(self.runtime, "publish_if_current", side_effect=after_publish):
            future = self.submit(coordinator)
            try:
                self.assertTrue(committed.wait(10))
                self.assertFalse(future.cancel())
            finally:
                release.set()
            self.assertEqual(future.result(10)["status"], "published")
        self.assertFalse(future.cancel())
        self.assertEqual(self.runtime.call("calculate", [91]), 91)

    def test_submission_freezes_caller_dicts_and_capacity_counts_the_active_job(self):
        coordinator = self.coordinator(max_pending=1)
        entered, release = threading.Event(), threading.Event()
        candidates = proposal()
        observed = measurements(self.baseline, candidates)
        goal = objective()
        def delayed(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test worker was not released")
            return controlled_rank(*args, **kwargs)
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed):
            future = coordinator.submit(candidates, observed, goal)
            try:
                self.assertTrue(entered.wait(10))
                candidates[0]["program"] = scalar_program(value=1)
                observed["abstain"]["runtime_ns"] = 0
                goal["expected_calls"] = 0
                with self.assertRaisesRegex(BackgroundOptimizationRejected, "capacity"):
                    self.submit(coordinator)
                self.assertEqual(coordinator.snapshot()["outstanding"], 1)
            finally:
                release.set()
            result = future.result(10)
        self.assertEqual(result["status"], "published", result)
        self.assertEqual(self.runtime.call("calculate", [13]), 13)

    def test_shutdown_cancels_running_and_queued_work_without_closing_runtime(self):
        coordinator = self.coordinator(max_pending=2)
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test worker was not released")
            return controlled_rank(*args, **kwargs)
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                second = self.submit(coordinator)
                coordinator.shutdown(wait=False)
                with self.assertRaisesRegex(BackgroundOptimizationRejected, "shut down"):
                    self.submit(coordinator)
            finally:
                release.set()
            coordinator.shutdown()
        self.assertTrue(first.cancelled())
        self.assertTrue(second.cancelled())
        self.assertEqual(rank.call_count, 1)
        self.assertEqual(coordinator.snapshot()["outstanding"], 0)
        accounting = coordinator.snapshot()["cost_accounting"]
        self.assertEqual(accounting["settled_jobs"], 2)
        self.assertEqual(accounting["execution_outcomes_at_accounting"], {"cancelled": 2})
        self.assertEqual(sum(row["costs"]["observed_submit_and_worker_ns"]
                             for row in accounting["recent_jobs"]),
                         accounting["observed_submit_and_worker_ns"])
        self.assertFalse(coordinator.snapshot()["worker_alive"])
        self.assert_baseline()

    def test_shutdown_can_drain_and_a_completion_callback_does_not_join_itself(self):
        coordinator = self.coordinator()
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank):
            future = self.submit(coordinator)
            future.add_done_callback(lambda unused: coordinator.shutdown(wait=True, cancel_pending=False))
            coordinator.shutdown(cancel_pending=False)
            self.assertEqual(future.result(10)["status"], "published")
        self.assertFalse(coordinator.snapshot()["worker_alive"])
        self.assertEqual(self.runtime.call("calculate", [5]), 5)

    def test_source_target_measurement_and_input_limits_fail_before_enqueue(self):
        coordinator = self.coordinator()
        candidates = proposal()
        observed = measurements(self.baseline, candidates)
        wrong_target = {**objective(), "target": "aarch64-unknown-linux-gnu"}
        with self.assertRaisesRegex(BackgroundOptimizationRejected, "target"):
            coordinator.submit(candidates, observed, wrong_target)
        stale = copy.deepcopy(observed)
        stale["abstain"]["program_sha256"] = "f" * 64
        with self.assertRaisesRegex(BackgroundOptimizationRejected, "incumbent observation"):
            coordinator.submit(candidates, stale, objective())
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(ValueError):
            coordinator.submit(cyclic, observed, objective())
        self.runtime.publish(scalar_program("bit.xor"))
        with self.assertRaisesRegex(BackgroundOptimizationRejected, "untracked"):
            self.submit(coordinator)
        self.assertEqual(coordinator.snapshot()["outstanding"], 0)
        for limit in (0, 9, True):
            with self.assertRaises(BackgroundOptimizationRejected):
                self.coordinator(max_pending=limit)
        for clone in (copy.copy, copy.deepcopy):
            with self.assertRaises(BackgroundOptimizationRejected):
                clone(coordinator)


if __name__ == "__main__":
    unittest.main()
