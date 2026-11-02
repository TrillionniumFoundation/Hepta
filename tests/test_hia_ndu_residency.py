"""Reversible residency over the existing finite native protocol, with real costs."""
from copy import deepcopy
import random
import unittest

from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_stateful import (
    SCHEMA_V2, SCHEMA_V3, StatefulPlanningError, build_request, digest,
    graph_fields, invocation_gate, observe_residency, validate_model)
from tools.qualify_hia_ndu_costed import costed_fixtures, residency_fixtures
from tools.qualify_hia_ndu_stateful import SCALE, assert_agreement, canonical_schedules, fixtures
from tools.qualify_hia_ndu_stateful_reference import (
    exact_dp_control, exhaustive_oracle, fixed_configuration_control, greedy_control, score_schedule)


class ReversibleResidencyTests(unittest.TestCase):
    def test_v3_exact_field_and_graph_bounds_leave_historical_profiles_unchanged(self):
        model = residency_fixtures()[0]
        fields, binding = graph_fields(model)
        self.assertEqual(len(fields["states"]), 4)
        self.assertEqual(len(fields["transitions"]), 12)
        self.assertEqual(binding["complete_graph_transitions"], 12)
        for mutate in (
            lambda m: m.update(schema=SCHEMA_V2),
            lambda m: m.pop("future_decision_cost_ns"),
            lambda m: m["variants"][0].pop("eviction_ns"),
            lambda m: m["variants"][0].update(eviction_ns=True),
            lambda m: m["variants"][0].update(eviction_ns=-1),
            lambda m: m["variants"][0].update(eviction_ns=1.5),
            lambda m: m["variants"].append({**m["variants"][0], "id": "third"}),
        ):
            bad = deepcopy(model)
            mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(StatefulPlanningError):
                graph_fields(bad)
        for historical in fixtures() + costed_fixtures():
            original = deepcopy(historical)
            graph_fields(historical)
            self.assertEqual(historical, original)
            bad = deepcopy(historical)
            bad["variants"][0]["eviction_ns"] = 0
            with self.assertRaises(StatefulPlanningError):
                validate_model(bad)

    def test_complete_cost_bound_includes_repeated_preparation_and_eviction(self):
        model = residency_fixtures()[0]
        # A once-only charge would fit, but four possible reacquisitions do not.
        model["variants"][0]["preparation_ns"] = 300_000_000_000
        with self.assertRaisesRegex(StatefulPlanningError, "complete cost envelope"):
            validate_model(model)
        model = residency_fixtures()[0]
        model["variants"][0]["eviction_ns"] = 300_000_000_000
        with self.assertRaisesRegex(StatefulPlanningError, "complete cost envelope"):
            validate_model(model)

    def test_eviction_and_reacquisition_are_both_charged_without_union_residency(self):
        model = residency_fixtures()[0]
        oracle = exhaustive_oracle(model)
        schedule = [["early"], ["late"], ["early"], ["late"]]
        self.assertEqual(canonical_schedules(oracle), {tuple(tuple(x) for x in schedule)})
        self.assertEqual(score_schedule(model, schedule)["cost_ns"], 18 * SCALE)
        fields, binding = graph_fields(model)
        states = {tuple(row["ready"]): key for key, row in binding["states"].items()}
        transition = next(t for t in fields["transitions"]
                          if t["source"] == states[("early",)] and t["target"] == states[("late",)])
        self.assertEqual(transition["setup_ns"], 3 * SCALE)
        self.assertEqual(transition["status"], "verified")
        self.assertEqual(fields["states"][states[("early", "late")]]["status"], "rejected")
        bundle = build_request(model, search="dynamic-light")
        assert_agreement(bundle, bundle["advice"], oracle, native=False)

    def test_continuation_beats_fixed_and_greedy_but_only_matches_same_information_dp(self):
        model = residency_fixtures()[1]
        oracle = exhaustive_oracle(model)
        exact = exact_dp_control(model)
        fixed = fixed_configuration_control(model)
        greedy = greedy_control(model)
        self.assertEqual(canonical_schedules(oracle),
                         {(("early",), ("early",), ("late",), ("late",))})
        self.assertEqual({w["cost_ns"] for w in oracle["winners"]}, {262 * SCALE})
        self.assertEqual({w["cost_ns"] for w in fixed["winners"]}, {302 * SCALE})
        self.assertEqual(greedy["attempted_schedule"]["cost_ns"], 400 * SCALE)
        self.assertGreater(oracle["best_value_q32"], fixed["best_value_q32"])
        self.assertGreater(oracle["best_value_q32"], greedy["best_value_q32"])
        self.assertEqual(oracle["best_value_q32"], exact["best_value_q32"])
        self.assertEqual(canonical_schedules(oracle), canonical_schedules(exact))

    def test_expensive_eviction_stop_and_refused_targets_retain_cost_and_status(self):
        for model in residency_fixtures()[2:]:
            with self.subTest(case=model["name"]):
                oracle = exhaustive_oracle(model)
                exact = exact_dp_control(model)
                self.assertEqual(oracle["best_value_q32"], exact["best_value_q32"])
                self.assertEqual(canonical_schedules(oracle), canonical_schedules(exact))
                bundle = build_request(model, search="dynamic-light")
                assert_agreement(bundle, bundle["advice"], oracle, native=False)
        costly = exhaustive_oracle(residency_fixtures()[2])
        self.assertTrue(all(len({tuple(s) for s in row["schedule"]}) == 1 for row in costly["winners"]))
        refused = exhaustive_oracle(residency_fixtures()[4])
        self.assertTrue(all("late" not in s for row in refused["winners"] for s in row["schedule"]))
        self.assertTrue(exhaustive_oracle(residency_fixtures()[5])["abstain_is_optimal"])

    def test_invocation_bound_accounts_for_avoidable_incumbent_holding(self):
        model = residency_fixtures()[3]
        gate = invocation_gate(model, invocation_cost_ns=5 * SCALE)
        self.assertTrue(gate["invoke"])
        self.assertEqual(gate["incumbent_delivery_ns"], 160 * SCALE)
        self.assertEqual(gate["optimistic_delivery_lower_bound_ns"], 40 * SCALE)
        oracle = exhaustive_oracle(model)
        self.assertEqual(canonical_schedules(oracle), {((), (), (), ())})
        self.assertEqual({w["cost_ns"] for w in oracle["winners"]}, {44 * SCALE})
        self.assertFalse(invocation_gate(model, invocation_cost_ns=120 * SCALE)["invoke"])
        self.assertEqual(gate["authority"], "DENY_ALL")

    def test_v3_independent_lengths_costs_memory_and_q32_rounding_match(self):
        rng = random.Random(20261101)
        for case in range(80):
            model = deepcopy(residency_fixtures()[0])
            horizon = case % 4 + 1
            model.update(future_decision_cost_ns=0 if case % 3 == 0 else rng.randrange(1, 100),
                         budget_ns=rng.randrange(1, 12000), completion_value_ns=rng.randrange(1, 12000),
                         memory_budget_bytes=128 if case % 2 else 64,
                         initial_ready=["early"] if case % 5 == 0 else [])
            model["baseline"]["latency_ns"] = [rng.randrange(1, 1000) for _ in range(horizon)]
            for variant in model["variants"]:
                variant.update(preparation_ns=rng.randrange(0, 500), eviction_ns=rng.randrange(0, 500),
                               latency_ns=[rng.randrange(1, 1000) for _ in range(horizon)],
                               holding_ns=[rng.randrange(0, 100) for _ in range(horizon)])
            if case % 7 == 0:
                model["variants"][1]["status"] = "unknown"
            model = validate_model(model)
            with self.subTest(case=case, horizon=horizon):
                oracle = exhaustive_oracle(model)
                exact = exact_dp_control(model)
                self.assertEqual(oracle["best_value_q32"], exact["best_value_q32"])
                self.assertEqual(canonical_schedules(oracle), canonical_schedules(exact))
                bundle = build_request(model, search="dynamic-light")
                assert_agreement(bundle, bundle["advice"], oracle, native=False)
                gate = invocation_gate(model, invocation_cost_ns=3)
                for winner in oracle["winners"]:
                    self.assertLessEqual(gate["optimistic_delivery_lower_bound_ns"], winner["cost_ns"])
                    if not gate["invoke"] and gate["reason"] == "optimistic_savings_cannot_repay_invocation":
                        self.assertLessEqual(gate["incumbent_delivery_ns"], winner["cost_ns"] + 3)

    def test_observed_reuse_preserves_actual_cost_generation_and_overrun(self):
        model = residency_fixtures()[0]
        original = deepcopy(model)
        first = observe_residency(model, ready=["early"], actual_transition_ns=13,
                                  observation_digest=digest("actual-first-load"))
        second = observe_residency(first, ready=["late"], actual_transition_ns=17,
                                   observation_digest=digest("actual-release-and-load"))
        third = observe_residency(second, ready=["early"], actual_transition_ns=19,
                                  observation_digest=digest("actual-reacquisition"))
        self.assertEqual(model, original)
        self.assertEqual(third["generation"], 4)
        self.assertEqual(third["sunk_cost_ns"], 49)
        self.assertEqual(third["budget_ns"], model["budget_ns"] - 49)
        fields, binding = graph_fields(second)
        current = fields["initial_state"]
        transition = next(t for t in fields["transitions"]
                          if t["source"] == current and binding["states"][t["target"]]["ready"] == ["early"])
        self.assertEqual(transition["setup_ns"], 3 * SCALE)
        self.assertEqual(third["observations"][-1]["released"], ["late"])
        self.assertFalse(third["observations"][-1]["observation_authenticated"])
        with self.assertRaisesRegex(StatefulPlanningError, "already consumed"):
            observe_residency(third, ready=["late"], actual_transition_ns=17,
                              observation_digest=digest("actual-release-and-load"))
        exceeded = observe_residency({**model, "budget_ns": 5}, ready=["early"],
                                     actual_transition_ns=8, observation_digest=digest("actual-overrun"))
        self.assertEqual(exceeded["budget_ns"], 0)
        self.assertEqual(exceeded["observations"][-1]["budget_overrun_ns"], 3)

    def test_observation_rejects_invalid_or_unverified_state_before_cost_credit(self):
        model = residency_fixtures()[0]
        for ready in ([], ["absent"], ["early", "early"], ["early", "late"], [1], "early"):
            with self.subTest(ready=ready), self.assertRaises(StatefulPlanningError):
                observe_residency(model, ready=ready, actual_transition_ns=1,
                                  observation_digest=digest("invalid-target"))
        refused = residency_fixtures()[4]
        with self.assertRaisesRegex(StatefulPlanningError, "unverified"):
            observe_residency(refused, ready=["late"], actual_transition_ns=1,
                              observation_digest=digest("refused-target"))
        with self.assertRaisesRegex(StatefulPlanningError, "require v3"):
            observe_residency(fixtures()[0], ready=["fast"], actual_transition_ns=1,
                              observation_digest=digest("old-schema"))

    def test_full_enumeration_keeps_original_cap_without_partial_optimum(self):
        model = residency_fixtures()[0]
        with self.assertRaisesRegex(NduBridgeError, "complete enumeration exceeds"):
            build_request(model, search="enumerate")
        bundle = build_request(model, search="dynamic-frontier")
        self.assertTrue(bundle["search_complete"])
        self.assertFalse(bundle["enumeration_complete"])
        self.assertLessEqual(len(bundle["request"]["candidates"]), 128)


if __name__ == "__main__":
    unittest.main()
