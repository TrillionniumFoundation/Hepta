"""Deterministic controller checks; these fixtures are not measured evidence."""
import unittest

from tools.qualify_hia_ndu_narrowed_candidates import (
    TARGETS, allocation_model, feedback_greedy)
from tools.qualify_hia_ndu_net_value import CompilationCredits, complete_budget_dp


def option(target, cost, credit=0, verified=True):
    return {"target": target, "cost_ns": cost, "credits": credit, "verified": verified}


class NarrowedControllerTests(unittest.TestCase):
    def test_current_epoch_control_does_not_amortize_over_the_future(self):
        # One actual build would cost 25 units. A 9-unit per-call saving pays
        # over four epochs, but not over the present epoch alone.
        bank = {"bank_sha256": "unit-fixture", "modules": {"module": {
            target: {"latency_ns": {"7": 1 if target == "guarded-narrowed" else 10},
                "setup_ns": 25 if target == "guarded-narrowed" else 100,
                "receipt": {"verification": {"status": "verified"}}}
            for target in TARGETS}}}
        artifacts, credits = {("module", "base"): {}}, CompilationCredits(1)
        current = allocation_model(bank, ["module"], [7] * 4, 0, [], artifacts,
            credits, current_epoch_only=True)
        suffix = allocation_model(bank, ["module"], [7] * 4, 0, [], artifacts, credits)
        self.assertEqual(current["modeled_horizon"], [7])
        self.assertEqual(suffix["modeled_horizon"], [7] * 4)
        self.assertEqual(feedback_greedy(current)["targets"], ["base"])
        self.assertEqual(complete_budget_dp(suffix)["targets"], ["guarded-narrowed"])

    def test_shared_credit_selects_largest_positive_admitted_improvement(self):
        model = {"remaining_credits": 1, "modules": [
            [option("base", 60), option("guarded-narrowed", 25, 1),
             option("unverified", 0, 1, False)],
            [option("base", 50), option("guarded-narrowed", 30, 1)]]}
        chosen = feedback_greedy(model)
        self.assertEqual(chosen["targets"], ["guarded-narrowed", "base"])
        self.assertEqual(chosen["credits"], 1)
        self.assertEqual(chosen["cost_ns"], 75)
        model["remaining_credits"] = 0
        self.assertEqual(feedback_greedy(model)["targets"], ["base", "base"])

    def test_completed_feedback_changes_reused_image_choice_without_new_credit(self):
        bank = {"bank_sha256": "unit-fixture", "modules": {"module": {
            target: {"latency_ns": {"7": 10 if target == "guarded-narrowed" else 60},
                "setup_ns": 15, "receipt": {"verification": {"status": "verified"}}}
            for target in TARGETS}}}
        artifacts = {("module", "base"): {}, ("module", "guarded-narrowed"): {}}
        credits = CompilationCredits(0)
        before = allocation_model(bank, ["module"], [7, 7], 1, [], artifacts,
            credits, current_epoch_only=True)
        self.assertEqual(feedback_greedy(before)["targets"], ["guarded-narrowed"])
        own = [{"module": "module", "target": "guarded-narrowed", "n": 7,
            "status": "measured", "delivery_cost_ns": 100}]
        after = allocation_model(bank, ["module"], [7, 7], 1, own, artifacts,
            credits, current_epoch_only=True)
        self.assertEqual(feedback_greedy(after)["targets"], ["base"])


if __name__ == "__main__":
    unittest.main()
