"""Independent finite checks for preparation-aware HIA invocation bounds."""
from copy import deepcopy
import random
import unittest
from unittest.mock import patch

from hepta.hia_ndu_cost import (AdvisoryController, CostModelError, invocation_gate,
                                validate_model)
from tests.test_hia_ndu_cost import fixture, independent_frontier


class PreparationBoundTests(unittest.TestCase):
    def one_variant(self, horizon=4):
        model = fixture(horizon)
        model["variants"] = model["variants"][:1]
        model["variants"][0].update(holding_ns=0, retire_ns=0)
        return model

    def test_short_request_cannot_amortize_prepare_and_proof(self):
        model = self.one_variant()
        model["variants"][0].update(prepare_ns=3500, proof_ns=501,
                                     latency_ns=[1] * 4)
        gate = invocation_gate(model)
        self.assertEqual(gate["free_execution_lower_ns"], 4)
        self.assertEqual(gate["preparation_execution_lower_ns"], 4000)
        self.assertEqual(gate["mode"], "skip")
        # The previous free-preparation bound admitted this optional search.
        call_and_close = sum(model["decision"][key] for key in
            ("search_ns", "native_ns", "transport_ns", "validation_ns", "startup_ns", "close_ns"))
        self.assertLess(gate["free_execution_lower_ns"] + 4 * model["decision"]["gate_ns"]
                        + call_and_close, gate["skip"]["total_ns"])
        with patch("hepta.hia_ndu_cost._Planner", side_effect=AssertionError("search launched")):
            controller = AdvisoryController(lambda: self.fail("native session launched"))
            action, receipt = controller.decide(model)
        self.assertEqual(action["mode"], "skip")
        self.assertFalse(receipt["native_invoked"])
        self.assertEqual(receipt["search_ns"], 0)
        self.assertIsNone(controller.session)

    def test_existing_resident_does_not_pay_preparation_again(self):
        model = self.one_variant()
        model["ready"] = ["a"]
        model["variants"][0].update(prepare_ns=900000, proof_ns=900000,
                                     holding_ns=9, latency_ns=[100] * 4)
        gate = invocation_gate(model)
        self.assertEqual(gate["preparation_execution_lower_ns"], 436)
        self.assertEqual(gate["mode"], "skip")
        self.assertEqual([step["dispatch"] for step in gate["skip"]["actions"]], ["a"] * 4)

    def test_each_invalidation_ends_the_free_resident_segment(self):
        for initially_resident in (False, True):
            model = self.one_variant()
            model["ready"] = ["a"] if initially_resident else []
            model["baseline"]["latency_ns"] = [100] * 4
            model["variants"][0].update(prepare_ns=70, proof_ns=50, holding_ns=1,
                                         latency_ns=[1] * 4, valid=[True, False, True, False])
            gate = invocation_gate(model)
            with self.subTest(initially_resident=initially_resident):
                self.assertEqual(gate["preparation_execution_lower_ns"], 302 if initially_resident else 400)
                self.assertEqual(gate["mode"], "skip")
                self.assertEqual(gate["skip"]["actions"][2]["dispatch"], "baseline")

    def test_invalid_initial_resident_does_not_prepay_a_later_epoch(self):
        model = self.one_variant()
        model["ready"] = ["a"]
        model["baseline"]["latency_ns"] = [100] * 4
        model["variants"][0].update(prepare_ns=100, proof_ns=1, holding_ns=0,
                                     latency_ns=[1] * 4, valid=[False, True, False, True])
        gate = invocation_gate(model)
        self.assertEqual(gate["preparation_execution_lower_ns"], 400)
        self.assertEqual(gate["skip"]["actions"][0]["invalidated"], ["a"])
        self.assertEqual(gate["mode"], "skip")

    def test_overlapping_savings_never_weaken_the_free_execution_bound(self):
        model = fixture()
        model["memory_budget_bytes"] = 1
        for row in model["variants"]:
            row.update(prepare_ns=0, proof_ns=0, retire_ns=0, holding_ns=0,
                       latency_ns=[1] * 3)
        gate = invocation_gate(model)
        self.assertEqual(gate["preparation_execution_lower_ns"], 3)
        self.assertEqual(gate["free_execution_lower_ns"], 3)
        self.assertEqual(gate["mode"], "consider")

    def test_individually_oversized_artifact_cannot_supply_a_saving(self):
        model = self.one_variant()
        model["variants"][0].update(resident_bytes=2, prepare_ns=0, proof_ns=0,
                                     latency_ns=[1] * 4)
        gate = invocation_gate(model)
        self.assertEqual(gate["preparation_execution_lower_ns"], 4000)
        self.assertEqual(gate["mode"], "skip")

    def test_holding_cost_can_require_releasing_an_initial_resident(self):
        model = self.one_variant()
        model["ready"] = ["a"]
        model["variants"][0].update(latency_ns=[100] * 4, holding_ns=2000)
        gate = invocation_gate(model)
        self.assertEqual(gate["preparation_execution_lower_ns"], 4000)
        self.assertEqual(gate["mode"], "consider")
        oracle = independent_frontier(model)
        self.assertLess(min(oracle.values()), gate["skip"]["total_ns"])

    def test_zero_costs_and_exact_ties_preserve_the_existing_contract(self):
        model = self.one_variant()
        model["budget_ns"] = 0
        model["baseline"]["latency_ns"] = [0] * 4
        model["decision"] = dict.fromkeys(model["decision"], 0)
        model["variants"][0].update(latency_ns=[0] * 4, prepare_ns=0, proof_ns=0)
        gate = invocation_gate(model)
        self.assertEqual(gate["invocation_lower_ns"], 0)
        self.assertEqual(gate["skip"]["total_ns"], 0)
        self.assertEqual(gate["mode"], "skip")
        self.assertEqual(set(independent_frontier(model).values()), {0})

    def test_negative_and_boolean_costs_are_still_rejected_before_the_bound(self):
        for key in ("prepare_ns", "proof_ns", "holding_ns", "retire_ns", "resident_bytes"):
            for value in (-1, False):
                model = self.one_variant()
                model["variants"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(CostModelError):
                    invocation_gate(model)

    def test_bound_and_gate_decisions_against_independent_all_schedule_oracle(self):
        rng = random.Random(67867967)
        for case in range(256):
            horizon = 1 + case % 4
            model = fixture(horizon)
            model["baseline"]["latency_ns"] = [rng.randrange(0, 1500) for _ in range(horizon)]
            model["session_ready"] = bool(case % 2)
            model["memory_budget_bytes"] = case % 5
            for index, row in enumerate(model["variants"]):
                row["resident_bytes"] = 1 + (case + index) % 2
                row["status"] = ("verified", "verified", "rejected", "unknown", "timeout")[(case + index) % 5]
                row["valid"] = [bool((case + index * 7) & (1 << batch)) for batch in range(horizon)]
                row["latency_ns"] = [rng.randrange(0, 1500) for _ in range(horizon)]
                for key in ("prepare_ns", "proof_ns", "retire_ns", "holding_ns"):
                    row[key] = rng.randrange(0, 800)
            model["ready"] = [row["id"] for index, row in enumerate(model["variants"])
                              if case & (1 << index)]
            model["memory_budget_bytes"] = max(model["memory_budget_bytes"],
                sum(row["resident_bytes"] for row in model["variants"] if row["id"] in model["ready"]))
            for key in model["decision"]:
                model["decision"][key] = rng.randrange(0, 400)
            model["budget_ns"] = 1_000_000
            original = deepcopy(model)
            gate = invocation_gate(model)
            minimum = min(independent_frontier(model).values())
            committed_minimum = min(independent_frontier(model, committed_call=True).values())
            with self.subTest(case=case, stage="bound"):
                self.assertEqual(model, original)
                self.assertEqual(validate_model(model), original)
                self.assertLessEqual(gate["free_execution_lower_ns"], gate["preparation_execution_lower_ns"])
                self.assertLessEqual(gate["invocation_lower_ns"], committed_minimum)
            for budget in (minimum - 1, minimum, minimum + 1, gate["skip"]["total_ns"]):
                if budget < 0:
                    continue
                model["budget_ns"] = budget
                checked = invocation_gate(model)
                oracle = independent_frontier(model)
                with self.subTest(case=case, budget=budget, stage="decision"):
                    if checked["mode"] == "skip":
                        self.assertEqual(min(oracle.values()), checked["skip"]["total_ns"])
                    elif checked["mode"] == "refuse":
                        self.assertEqual(oracle, {})


if __name__ == "__main__":
    unittest.main()
