"""Budget-state regressions, not native NDU or solver qualification.

The clock, proof and native advice below are deterministic fixtures. They
exercise whether the public ranking path starts avoidable work after its
actual budget or possible net saving has already been consumed. Existing
native tests independently exercise the real evaluator and all-input prover.
"""
from __future__ import annotations

import importlib.util
import unittest
from unittest.mock import patch

from hepta.hia_ndu_optimizer import rank_candidates
from tests.test_hia_ndu_optimizer import baseline_program, observation, proposal
from tests.test_hia_program import arithmetic, b, f, jump, m
from tests.test_hia_translation_validation import identity


class RankingBudgetTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.proof_costs = []
        self.proof_timeouts = []
        self.rank_cost = 0
        self.native_requests = []
        self.native_timeouts = []
        self.baseline = baseline_program()
        self.candidate = identity("u32")
        self.observations = {
            "abstain": observation(self.baseline, 100_000),
            "cancel": observation(self.candidate, 1_000),
        }
        self.objective = {
            "expected_calls": 1_000_000,
            "resource_cap_ns": 5_500_000,
            "target": "x86_64-unknown-linux-gnu",
            "measurement_profile": "synthetic-budget-state-regression",
        }

    def fresh_proof(self, before, after, function, timeout_ms):
        self.proof_timeouts.append(timeout_ms)
        if self.proof_costs:
            self.now += self.proof_costs.pop(0)
        return True, {"status": "proved", "fixture_only": True,
                      "solver": {"timeout_ms": timeout_ms}}

    def native_rank(self, bridge, request, *, timeout_s):
        self.native_requests.append(request)
        self.native_timeouts.append(timeout_s)
        self.now += self.rank_cost
        candidate = next(row for row in request["candidates"] if row["id"] == "cancel")
        # Deliberately stale advice lets the host guard be tested independently
        # of the evaluator's own resource filtering.
        selected = "abstain" if candidate["hard_violation"] else "cancel"
        return {"advisory_recommendation": selected}, {"fixture_only": True}

    def rank(self, candidates=None):
        with patch("hepta.hia_ndu_optimizer.time.perf_counter_ns", side_effect=lambda: self.now), \
             patch("hepta.hia_ndu_optimizer._fresh_proof", side_effect=self.fresh_proof), \
             patch("hepta.hia_ndu_optimizer._native_rank", side_effect=self.native_rank):
            return rank_candidates(self.baseline, candidates or [proposal(self.candidate)], self.observations,
                function="calculate", bridge={}, objective=self.objective, timeout_ms=2000)

    def test_each_solver_timeout_uses_remaining_budget_including_paid_search(self):
        self.observations["abstain"]["search_ns"] = 1_000_000
        self.proof_costs = [1_500_000, 1_000_000]
        self.rank_cost = 500_000
        result = self.rank()
        self.assertTrue(result["admitted"])
        self.assertEqual(self.proof_timeouts, [4, 2])
        self.assertEqual(result["costs"]["total_search_ns"], 4_000_000)
        self.assertEqual(result["candidate_reports"][0]["proof_wall_ns"], 1_500_000)
        self.assertEqual(result["selected_proof_admission"]["wall_ns"], 1_000_000)
        self.assertEqual(self.native_timeouts, [0.003])

    def test_exhausted_search_never_starts_native_work_or_claims_native_receipt(self):
        self.objective["resource_cap_ns"] = 0
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [])
        self.assertEqual(self.native_requests, [])
        self.assertIsNone(result["native_response"])
        self.assertIsNone(result["bridge"])
        self.assertFalse(result["native_rank_admission"]["invoked"])
        self.assertEqual(result["reason"], "search_budget_exhausted_before_native")
        self.assertEqual(result["selected_id"], "abstain")

    def test_proof_spending_remaining_budget_does_not_renew_native_timeout(self):
        self.proof_costs = [5_500_000]
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [5])
        self.assertEqual(self.native_requests, [])
        self.assertEqual(result["costs"]["total_search_ns"], 5_500_000)
        self.assertFalse(result["admitted"])
        self.assertIsNone(result["selected_fresh_proof"])

    def test_all_candidates_share_one_cap_and_losing_search_costs(self):
        self.observations["abstain"]["search_ns"] = 1_000_000
        self.observations["second"] = observation(self.candidate, 1_000, search_ns=1_000_000)
        self.observations["third"] = observation(self.candidate, 1_000)
        self.proof_costs = [2_000_000, 2_000_000]
        result = self.rank([proposal(self.candidate, cid) for cid in ("cancel", "second", "third")])
        self.assertEqual(self.proof_timeouts, [3, 1])
        self.assertEqual(result["candidate_reports"][2]["reason"], "search_budget_exhausted_before_proof")
        self.assertEqual(result["costs"]["supplied_search_ns"], 2_000_000)
        self.assertEqual(result["costs"]["total_search_ns"], 6_000_000)
        self.assertIsNone(result["selected_fresh_proof"])
        self.assertFalse(result["admitted"])

    def test_native_budget_overrun_does_not_start_a_second_solver(self):
        self.proof_costs = [1_000_000, 40_000_000]
        self.rank_cost = 6_000_000
        result = self.rank()
        self.assertEqual(len(self.proof_timeouts), 1)
        self.assertEqual(result["costs"]["total_search_ns"], 7_000_000)
        self.assertIsNone(result["selected_fresh_proof"])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["selected_id"], "abstain")
        self.assertEqual(result["reason"], "actual_search_budget_exceeded")

    def test_native_cost_exhausting_possible_gain_does_not_start_a_second_solver(self):
        self.objective.update(expected_calls=100, resource_cap_ns=100_000_000)
        self.observations["abstain"]["runtime_ns"] = 60_000
        self.observations["cancel"]["runtime_ns"] = 0
        self.proof_costs = [1_000_000, 40_000_000]
        self.rank_cost = 6_000_000
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [5])
        self.assertIsNone(result["selected_fresh_proof"])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["reason"], "no_robust_net_saving_after_search")

    def test_less_than_one_solver_millisecond_never_rounds_the_budget_up(self):
        self.objective["resource_cap_ns"] = 999_999
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [])
        self.assertFalse(result["admitted"])
        report = result["candidate_reports"][0]
        self.assertEqual(report["reason"], "search_budget_insufficient_for_proof")
        self.assertFalse(report["equivalence_proved"])
        self.assertTrue(self.native_requests[0]["candidates"][1]["hard_violation"])

    def test_less_than_one_profitable_millisecond_does_not_start_a_solver(self):
        self.objective["expected_calls"] = 1
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_reports"][0]["reason"], "cost_margin_insufficient_for_proof")

    def test_native_remainder_cannot_be_rounded_up_for_the_final_solver(self):
        for margin_limited in (False, True):
            with self.subTest(margin_limited=margin_limited):
                self.setUp()
                self.objective["resource_cap_ns"] = 100_000_000 if margin_limited else 5_500_000
                if margin_limited:
                    self.objective["expected_calls"] = 100
                    self.observations["abstain"]["runtime_ns"] = 55_000
                    self.observations["cancel"]["runtime_ns"] = 0
                self.proof_costs = [1_000_000]
                self.rank_cost = 4_000_000
                result = self.rank()
                self.assertEqual(len(self.proof_timeouts), 1)
                self.assertFalse(result["selected_proof_admission"]["solver_started"])
                self.assertFalse(result["admitted"])
                self.assertEqual(result["reason"], "selected_proof_margin_insufficient"
                    if margin_limited else "selected_proof_budget_insufficient")

    def test_exact_budget_exhaustion_is_not_reported_as_an_overrun(self):
        self.proof_costs = [1_000_000]
        self.rank_cost = 4_500_000
        result = self.rank()
        self.assertEqual(len(self.proof_timeouts), 1)
        self.assertEqual(result["selected_proof_admission"]["remaining_budget_ns"], 0)
        self.assertEqual(result["costs"]["total_search_ns"], self.objective["resource_cap_ns"])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["reason"], "selected_proof_budget_insufficient")

    def test_final_proof_may_finish_exactly_at_cap_if_net_margin_remains(self):
        self.proof_costs = [1_000_000, 1_000_000]
        self.rank_cost = 3_500_000
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [5, 1])
        self.assertEqual(result["costs"]["total_search_ns"], self.objective["resource_cap_ns"])
        self.assertTrue(result["admitted"])
        self.assertGreater(result["net_margin_ns"], 0)

    def test_final_proof_overshoot_still_preserves_incumbent(self):
        self.proof_costs = [1_000_000, 8_000_000]
        result = self.rank()
        self.assertEqual(self.proof_timeouts, [5, 4])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["reason"], "actual_search_budget_exceeded")
        self.assertEqual(result["costs"]["total_search_ns"], 9_000_000)


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual pinned Z3 is required")
class RealProofBudgetTests(unittest.TestCase):
    """Real all-input proofs with advisory transport isolated as a fixture."""

    def rank(self, base, proposals, *, function="calculate"):
        seen = []

        def advice(bridge, request, *, timeout_s):
            seen.append(request)
            admitted = [row for row in request["candidates"]
                        if row["id"] != "abstain" and not row["hard_violation"]]
            return {"advisory_recommendation": admitted[0]["id"] if admitted else "abstain"}, {"fixture_only": True}

        observations = {"abstain": observation(base, 100_000)}
        observations.update({row["id"]: observation(row["program"], 1_000) for row in proposals})
        with patch("hepta.hia_ndu_optimizer._native_rank", side_effect=advice):
            report = rank_candidates(base, proposals, observations, function=function, bridge={},
                objective={"expected_calls": 1_000_000, "resource_cap_ns": 2_000_000_000,
                           "target": "x86_64-unknown-linux-gnu",
                           "measurement_profile": "real-solver-transport-fixture"})
        return report, seen

    def test_real_proofs_preserve_all_input_equivalence_and_reject_wrong_candidate(self):
        result, requests = self.rank(baseline_program(),
            [proposal(), proposal(arithmetic("int.sub.wrap", "u32"), "wrong")])
        self.assertTrue(result["admitted"], result)
        self.assertEqual(result["selected_id"], "cancel")
        reports = {row["id"]: row for row in result["candidate_reports"]}
        self.assertEqual(reports["cancel"]["proof"]["status"], "proved")
        self.assertEqual(reports["wrong"]["proof"]["status"], "disproved")
        self.assertTrue(next(row for row in requests[0]["candidates"] if row["id"] == "wrong")["hard_violation"])
        self.assertEqual(result["selected_fresh_proof"]["status"], "proved")
        for row in result["candidate_reports"]:
            self.assertGreater(row["proof_wall_ns"], 0)
            self.assertLess(row["proof_timeout_ms"], 2000)
            self.assertEqual(row["proof"]["solver"]["timeout_ms"], row["proof_timeout_ms"])
        final = result["selected_proof_admission"]
        self.assertTrue(final["solver_started"])
        self.assertGreater(final["wall_ns"], 0)
        self.assertEqual(result["selected_fresh_proof"]["solver"]["timeout_ms"], final["timeout_ms"])
        self.assertFalse(result["claims"]["global_optimality_established"])

    def test_unsupported_loop_remains_unknown_and_cannot_reach_final_proof(self):
        loop = m(f("forever", [], [], [],
            [b("entry", [], [], jump("loop")), b("loop", [], [], jump("loop"))]))
        result, _ = self.rank(loop, [proposal(loop)], function="forever")
        self.assertEqual(result["candidate_reports"][0]["proof"]["status"], "unknown")
        self.assertFalse(result["admitted"])
        self.assertIsNone(result["selected_fresh_proof"])
        self.assertIsNone(result["selected_proof_admission"])


if __name__ == "__main__":
    unittest.main()
