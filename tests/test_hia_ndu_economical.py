"""Independent numerical and failure controls for the forecast-priced gate.

The native callback here is explicitly a test double. Real native execution is
covered by the separate pinned-backend integration campaign, not these tests.
"""
from dataclasses import replace
from fractions import Fraction
import json
import random
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import economical
from experiments.hia_ndu_feedback_20261106.model import (
    Q32, SCENARIOS, FeedbackError, Observation, Scenario, SearchBudgetExhausted,
    independent_oracle, plan, scalar_backend,
)


class RecordingBackend:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def evaluate(self, candidates, **kwargs):
        self.calls.append((candidates, kwargs))
        if self.error is not None:
            raise self.error
        return scalar_backend(candidates, **kwargs)


def reference_greedy(scenario, observation, future_fee_ns=0):
    """Full test-only enumeration, independently encoding the actual policy.

    Does not call the production forecast, cost, preference, greedy, CE, fixed
    point, or bound helpers. The root's sunk computation fee is excluded.
    """
    def round_value(value):
        return round(Fraction(value))

    def recurse(t, request, resident, budget, deadline, belief, charge_fee):
        remaining = scenario.horizon - t
        slack = min(budget, deadline)
        scarcity = max(Fraction(0), 1 - Fraction(slack, max(scenario.cost_unit, remaining * scenario.direct_cost))) if scenario.dynamic_preferences else Fraction(0)
        price = round_value((1 + scarcity) * Q32)
        risk = min(Q32, scenario.risk_aversion_q32 + round_value(scarcity * Q32 / 4))
        choices = [("abstain", None, -scenario.miss_penalty_q32 * remaining, 0)]
        for target in (-1, 0, 1):
            cost = scenario.hot_cost if request == target else scenario.direct_cost
            cost += scenario.load_cost * int(target >= 0 and target != resident)
            cost += scenario.retire_cost * int(resident >= 0 and target != resident)
            cost += scenario.holding_cost * int(target >= 0)
            if cost <= slack:
                raw_cost = round_value(Fraction(cost * Q32, scenario.cost_unit))
                reward = scenario.completion_reward_q32 - round_value(Fraction(price * raw_cost, Q32))
                choices.append(("direct" if target == -1 else "cache-" + str(target), target, reward, cost))
        name, action, reward, cost = min(choices, key=lambda row: (-row[2], row[0]))
        fee = (round_value(Fraction(price * round_value(Fraction(future_fee_ns * Q32, scenario.cost_unit)), Q32))
               if charge_fee else 0)
        if action is None or remaining == 1:
            return reward - fee
        branches = []
        for next_request in (0, 1):
            for signal in (0, 1):
                weights = []
                for regime in (0, 1):
                    p0 = (Fraction(scenario.request_p0_z0_num, scenario.request_p0_z0_den) if regime == 0 else
                          Fraction(scenario.request_p0_z1_num, scenario.request_p0_z1_den))
                    signal0 = Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
                    if regime == 1:
                        signal0 = 1 - signal0
                    weights.append((belief if regime == 0 else 1 - belief) *
                                   (p0 if next_request == 0 else 1 - p0) *
                                   (signal0 if signal == 0 else 1 - signal0))
                probability = sum(weights)
                if probability:
                    child = recurse(t + 1, next_request, action, budget - cost, deadline - cost,
                                    weights[0] / probability, True)
                    branches.append((probability, child))
        mean = sum(p * v for p, v in branches)
        downside = sum(p * max(Fraction(0), mean - v) for p, v in branches)
        continuation = round_value(mean - Fraction(risk, Q32) * downside)
        return reward - fee + round_value(Fraction(scenario.discount_q32 * continuation, Q32))
    return recurse(observation.step, observation.request, observation.resident, observation.budget,
                   observation.deadline, Fraction(observation.belief_num, observation.belief_den), False)


class EconomicalPlanningTests(unittest.TestCase):
    def observation(self, *, budget=20, deadline=20, resident=-1):
        return Observation(0, 0, 0, resident, budget, deadline, 1, 2)

    def priced(self, scenario=None, observation=None, *, arm="dynamic-ndu", backend=None,
               forecast=1_000_000_000, greedy_forecast=0, budget=20000):
        return economical.priced_plan(scenario or SCENARIOS["adaptive"], observation or self.observation(), arm,
            backend=backend, forecast_control_ns=forecast, greedy_forecast_ns=greedy_forecast,
            max_transitions=budget)

    def test_horizon_one_stops_after_root_even_with_zero_planner_price(self):
        scenario = replace(SCENARIOS["adaptive"], horizon=1)
        backend = RecordingBackend(error=AssertionError("must not call native"))
        with patch.object(economical, "plan", wraps=plan) as calls:
            result = self.priced(scenario, backend=backend, forecast=0, greedy_forecast=10**9, budget=4)
        self.assertEqual([c.args[2] for c in calls.call_args_list], ["state-greedy"])
        self.assertFalse(result["compute_gate"]["invoke"])
        self.assertEqual(result["compute_gate"]["reason"], "horizon_one")
        self.assertEqual(result["compute_gate"]["gross_gain_upper_q32"], 0)
        self.assertEqual(result["search"]["transitions"], 4)
        self.assertEqual(result["search"]["bound_backups"], 0)
        self.assertEqual(backend.calls, [])
        self.assertEqual(result["action"], independent_oracle(scenario, self.observation())["action"])

    def test_zero_task_gap_cannot_be_reopened_by_large_future_greedy_fee(self):
        scenario = replace(SCENARIOS["adaptive"], horizon=4, direct_cost=0, hot_cost=0, load_cost=0)
        backend = RecordingBackend(error=AssertionError("zero task gap must stop"))
        result = self.priced(scenario, backend=backend, forecast=0, greedy_forecast=10**9)
        gate = result["compute_gate"]
        self.assertEqual(gate["gross_gain_upper_q32"], 0)
        self.assertGreater(gate["priced_gain_upper_q32"], 0)
        self.assertFalse(gate["invoke"])
        self.assertEqual(gate["reason"], "zero_task_gain_upper_bound")
        self.assertEqual(backend.calls, [])

    def test_no_feasible_service_stops_with_real_abstention(self):
        result = self.priced(observation=self.observation(budget=0, deadline=0), forecast=0, budget=4)
        self.assertIsNone(result["action"])
        self.assertEqual(result["selected_action"], "abstain")
        self.assertEqual(result["compute_gate"]["reason"], "no_feasible_service")
        self.assertEqual(result["value_q32"], -90 * Q32)
        self.assertEqual(result["search"]["transitions"], 4)

    def test_same_bounds_and_price_rule_for_ordinary_and_native_planning(self):
        ordinary = self.priced(arm="same-objective", forecast=1000, greedy_forecast=3)
        native = self.priced(arm="dynamic-ndu", forecast=1000, greedy_forecast=3)
        for key in ("incumbent_gross_lower_q32", "incumbent_costed_lower_q32", "optimal_upper_q32",
                    "gross_gain_upper_q32", "priced_gain_upper_q32", "forecast_compute_penalty_q32",
                    "future_bounds", "gate_transitions", "reason", "invoke"):
            self.assertEqual(ordinary["compute_gate"][key], native["compute_gate"][key], key)
        self.assertEqual(ordinary["action"], native["action"])

    def test_different_training_prices_can_gate_equal_planners_differently(self):
        ordinary = self.priced(arm="same-objective", forecast=0)
        native = self.priced(arm="dynamic-ndu", forecast=1000)
        self.assertTrue(ordinary["compute_gate"]["invoke"])
        self.assertFalse(native["compute_gate"]["invoke"])
        self.assertEqual(ordinary["compute_gate"]["optimal_upper_q32"], native["compute_gate"]["optimal_upper_q32"])

    def test_forecast_price_uses_cost_unit_and_current_scarcity(self):
        scenario = replace(SCENARIOS["adaptive"], horizon=1, direct_cost=20, hot_cost=10, load_cost=0, cost_unit=10)
        result = self.priced(scenario, self.observation(budget=5, deadline=5), forecast=150, greedy_forecast=20)
        gate = result["compute_gate"]
        self.assertEqual(gate["current_price_q32"], 7 * Q32 // 4)
        self.assertEqual(gate["forecast_compute_penalty_q32"], 105 * Q32 // 4)
        self.assertEqual(gate["current_greedy_forecast_fee_q32"], 7 * Q32 // 2)
        self.assertTrue(gate["current_greedy_fee_is_sunk"])
        self.assertFalse(gate["cost_threshold_is_observed_guarantee"])
        self.assertFalse(gate["positive_net_benefit_claim"])

    def test_equality_to_forecast_price_stops(self):
        # With unit discount/costs, the bound has an integer utility price.
        scenario = replace(SCENARIOS["adaptive"], horizon=2, discount_q32=Q32, dynamic_preferences=False)
        first = self.priced(scenario, forecast=1000)
        gap = first["compute_gate"]["priced_gain_upper_q32"]
        self.assertEqual(gap % Q32, 0)
        result = self.priced(scenario, forecast=gap // Q32)
        self.assertEqual(result["compute_gate"]["forecast_compute_penalty_q32"], gap)
        self.assertFalse(result["compute_gate"]["invoke"])

    def test_cost_unit_floor_blocks_false_price_one_certificate(self):
        scenario = replace(SCENARIOS["adaptive"], direct_cost=1, hot_cost=1, load_cost=0, cost_unit=100)
        result = self.priced(scenario, self.observation(budget=3, deadline=3))
        gate = result["compute_gate"]
        self.assertTrue(gate["future_resources_sufficient"])
        self.assertFalse(gate["future_price_one_certified"])
        self.assertEqual(gate["future_price_upper_q32"], 2 * Q32)

    def test_later_abstention_is_not_replaced_by_one_immediate_stop_penalty(self):
        scenario = replace(SCENARIOS["adaptive"], direct_cost=0, hot_cost=0, load_cost=0,
                           completion_reward_q32=-59 * Q32, miss_penalty_q32=30 * Q32, discount_q32=Q32)
        result = self.priced(scenario, self.observation(budget=1, deadline=1))
        truth = reference_greedy(scenario, self.observation(budget=1, deadline=1))
        self.assertEqual(truth, -148 * Q32)
        self.assertEqual(result["compute_gate"]["incumbent_gross_lower_q32"], truth)
        self.assertLess(truth, -59 * Q32 - 60 * Q32)

    def test_bounds_cover_independent_full_greedy_and_optimal_enumerations(self):
        rng = random.Random(83621)
        for index in range(30):
            direct = rng.randrange(1, 7)
            scenario = replace(SCENARIOS["adaptive"], horizon=1 + index % 3,
                direct_cost=direct, hot_cost=rng.randrange(direct + 1), load_cost=rng.randrange(4),
                retire_cost=rng.randrange(2), holding_cost=rng.randrange(2),
                cost_unit=rng.choice((1, 2, 7, 100)), completion_reward_q32=rng.choice((-5, 0, 5, 20))*Q32,
                miss_penalty_q32=rng.choice((0, 3, 30))*Q32, discount_q32=rng.choice((0, Q32//2, Q32-1, Q32)),
                risk_aversion_q32=rng.choice((0, Q32//2, Q32)), dynamic_preferences=index % 5 != 0)
            observation = self.observation(budget=rng.randrange(31), deadline=rng.randrange(31), resident=rng.choice((-1, 0, 1)))
            fee = rng.randrange(10)
            result = self.priced(scenario, observation, greedy_forecast=fee)
            gate = result["compute_gate"]
            gross = reference_greedy(scenario, observation)
            costed = reference_greedy(scenario, observation, fee)
            optimum = independent_oracle(scenario, observation)["value_q32"]
            with self.subTest(index=index, scenario=scenario, observation=observation):
                self.assertLessEqual(gate["incumbent_gross_lower_q32"], gross)
                self.assertLessEqual(gross, optimum)
                self.assertLessEqual(optimum, gate["optimal_upper_q32"])
                self.assertLessEqual(gate["incumbent_costed_lower_q32"], costed)
                self.assertLessEqual(costed, gross)
                self.assertLessEqual(gate["gate_transitions"], 3 * scenario.horizon + 5)
                self.assertEqual(gate["future_state_enumerations"], 0)

    def test_skip_does_not_evaluate_future_policy_or_full_planner(self):
        with patch.object(economical, "plan", wraps=plan) as calls, \
             patch("experiments.hia_ndu_feedback_20261106.model.plan_gated", side_effect=AssertionError("old full policy gate")):
            result = self.priced(forecast=10**12)
        self.assertEqual([c.args[2] for c in calls.call_args_list], ["state-greedy"])
        self.assertFalse(result["compute_gate"]["invoke"])
        self.assertEqual(result["compute_gate"]["future_state_enumerations"], 0)
        self.assertEqual(result["search"]["backend_calls"], 0)

    def test_invoked_planner_gets_only_the_unspent_expansion_allowance(self):
        backend = RecordingBackend()
        with patch.object(economical, "plan", wraps=plan) as calls:
            result = self.priced(backend=backend, forecast=0, budget=10000)
        self.assertEqual([c.args[2] for c in calls.call_args_list], ["state-greedy", "dynamic-ndu"])
        used = result["compute_gate"]["gate_transitions"]
        self.assertEqual(calls.call_args_list[1].kwargs["max_transitions"], 10000 - used)
        self.assertEqual(result["search"]["transitions"], used + result["planner_search"]["transitions"])
        self.assertEqual(result["search"]["backend_calls"], len(backend.calls))
        self.assertGreater(len(backend.calls), 0)
        self.assertGreater(result["controller_wall_ns"], result["compute_gate"]["total_gate_wall_ns"])

    def test_gate_budget_failure_retains_cost_and_does_not_call_backend(self):
        for budget in (3, 4, 5):
            backend = RecordingBackend()
            with self.subTest(budget=budget), self.assertRaises(SearchBudgetExhausted) as caught:
                self.priced(backend=backend, forecast=0, budget=budget)
            error = caught.exception
            self.assertEqual(error.transitions, budget)
            self.assertGreater(error.controller_wall_ns, 0)
            self.assertFalse(error.cost_receipt["planner_attempted"])
            self.assertEqual(backend.calls, [])
            json.dumps(error.cost_receipt, allow_nan=False)

    def test_partial_planner_budget_failure_keeps_combined_denominator(self):
        # The linear gate spends 14 units at horizon 3. One remaining unit
        # cannot complete the actual full search; no partial result is returned.
        with self.assertRaises(SearchBudgetExhausted) as caught:
            self.priced(backend=RecordingBackend(), forecast=0, budget=15)
        error = caught.exception
        self.assertTrue(error.cost_receipt["planner_attempted"])
        self.assertEqual(error.transitions, 15)
        self.assertEqual(error.cost_receipt["search"]["gate_transitions"], 14)
        self.assertEqual(error.cost_receipt["search"]["planner_transitions"], 1)

    def test_native_fault_keeps_attempt_wall_and_spent_gate_budget(self):
        failure = RuntimeError("injected native refusal")
        backend = RecordingBackend(error=failure)
        with self.assertRaisesRegex(RuntimeError, "injected native refusal") as caught:
            self.priced(backend=backend, forecast=0)
        self.assertIs(caught.exception, failure)
        receipt = failure.cost_receipt
        self.assertEqual(receipt["phase"], "planner")
        self.assertEqual(receipt["search"]["backend_calls"], 1)
        self.assertGreater(receipt["planner_wall_ns"], 0)
        self.assertGreater(receipt["total_gate_wall_ns"], 0)
        self.assertEqual(failure.transitions, receipt["search"]["gate_transitions"] + receipt["search"]["planner_transitions"])
        json.dumps(receipt, allow_nan=False)

    def test_invalid_forecast_and_budget_inputs_have_serializable_failure_costs(self):
        for changes in ({"forecast": True}, {"forecast": -1}, {"forecast": 1.0},
                        {"forecast": float("nan")}, {"forecast": 10**13}, {"greedy_forecast": True},
                        {"budget": 0}, {"budget": True}, {"arm": "ordinary-mpc"}):
            with self.subTest(changes=changes), self.assertRaises(FeedbackError) as caught:
                self.priced(**changes)
            self.assertEqual(caught.exception.cost_receipt["phase"], "validation")
            self.assertEqual(caught.exception.transitions, 0)
            self.assertGreaterEqual(caught.exception.controller_wall_ns, 0)
            json.dumps(caught.exception.cost_receipt, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
