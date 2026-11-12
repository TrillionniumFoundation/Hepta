"""Independent finite-history controls for complete-policy NDU valuation.

The reference below reads Scenario fields directly. It does not use the
production forecast, preference, cost, rounding, oracle or policy evaluator.
These are small exhaustive controls, not another confirmation cohort.
"""
from collections import Counter
from copy import deepcopy
from dataclasses import astuple, replace
from fractions import Fraction
from functools import lru_cache
from itertools import product
import unittest

from experiments.hia_ndu_feedback_20261106.model import (
    Observation, Q32, Scenario, plan, preferences, scalar_backend,
)
from experiments.hia_ndu_feedback_20261106.policy_audit import build_graph, evaluate_policy


def _emissions(scenario, belief):
    rows = []
    for request, signal in product((0, 1), repeat=2):
        mass = []
        for regime in (0, 1):
            prior = belief if regime == 0 else 1 - belief
            demand = Fraction(getattr(scenario, f"request_p0_z{regime}_num"),
                              getattr(scenario, f"request_p0_z{regime}_den"))
            sensor = Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
            signal_zero = sensor if regime == 0 else 1 - sensor
            mass.append(prior * (demand if request == 0 else 1 - demand)
                        * (signal_zero if signal == 0 else 1 - signal_zero))
        probability = sum(mass, Fraction())
        if probability:
            rows.append((probability, request, signal, mass[0] / probability))
    return rows


def _cost(scenario, obs, action):
    return ((scenario.hot_cost if action == obs.request else scenario.direct_cost)
            + scenario.load_cost * int(action >= 0 and action != obs.resident)
            + scenario.retire_cost * int(obs.resident >= 0 and action != obs.resident)
            + scenario.holding_cost * int(action >= 0))


def _reference_graph(scenario):
    roots = []
    for probability, request, signal, belief in _emissions(
            scenario, Fraction(scenario.prior0_num, scenario.prior0_den)):
        roots.append((probability, Observation(0, request, signal, scenario.initial_resident,
            scenario.initial_budget, scenario.initial_deadline, belief.numerator, belief.denominator)))
    pending = [obs for _, obs in roots]
    nodes = {}
    while pending:
        obs = pending.pop()
        if obs in nodes:
            continue
        actions = {None: []}
        for action in (-1, 0, 1):
            cost = _cost(scenario, obs, action)
            if cost > min(obs.budget, obs.deadline):
                continue
            children = []
            if obs.step + 1 < scenario.horizon:
                for probability, request, signal, belief in _emissions(
                        scenario, Fraction(obs.belief_num, obs.belief_den)):
                    child = Observation(obs.step + 1, request, signal, action,
                        obs.budget - cost, obs.deadline - cost, belief.numerator, belief.denominator)
                    children.append((probability, child))
                    pending.append(child)
            actions[action] = children
        nodes[obs] = actions
    return {"roots": roots, "nodes": nodes,
            "edges": sum(len(children) for actions in nodes.values() for children in actions.values())}


def _backup(scenario, obs, action, continuation):
    remaining = scenario.horizon - obs.step
    if action is None:
        return -scenario.miss_penalty_q32 * remaining
    target = max(scenario.cost_unit, remaining * scenario.direct_cost)
    scarcity = (max(Fraction(), 1 - Fraction(min(obs.budget, obs.deadline), target))
                if scenario.dynamic_preferences else Fraction())
    price = round((1 + scarcity) * Q32)
    risk = min(Q32, scenario.risk_aversion_q32 + round(scarcity * Q32 / 4))
    mean = sum((p * value for p, value in continuation), Fraction())
    downside = sum((p * max(Fraction(), mean - value) for p, value in continuation), Fraction())
    ce = round(mean - Fraction(risk, Q32) * downside)
    cost_q32 = round(Fraction(_cost(scenario, obs, action) * Q32, scenario.cost_unit))
    instant = scenario.completion_reward_q32 - round(Fraction(price * cost_q32, Q32))
    return instant + round(Fraction(scenario.discount_q32 * ce, Q32))


def _reference_policy(scenario, graph, actions):
    @lru_cache(None)
    def visit(obs):
        action = actions[obs]
        if action is None:
            return _backup(scenario, obs, None, []), Fraction(), Fraction()
        children = [(p, visit(child)) for p, child in graph["nodes"][obs][action]]
        value = _backup(scenario, obs, action, [(p, result[0]) for p, result in children])
        delivered = 1 + sum((p * result[1] for p, result in children), Fraction())
        cost = _cost(scenario, obs, action) + sum((p * result[2] for p, result in children), Fraction())
        return value, delivered, cost

    state_values = {obs: visit(obs)[0] for obs in graph["nodes"]}
    roots = [(p, visit(obs)) for p, obs in graph["roots"]]
    return {"value_q32": round(sum((p * result[0] for p, result in roots), Fraction())),
            "state_values": state_values, "actions": actions,
            "expected_delivered": sum((p * result[1] for p, result in roots), Fraction()),
            "expected_cost": sum((p * result[2] for p, result in roots), Fraction())}


def _normalize(graph):
    return {"roots": dict((obs, p) for p, obs in graph["roots"]),
            "nodes": {obs: {action: dict((child, p) for p, child in children)
                            for action, children in actions.items()}
                      for obs, actions in graph["nodes"].items()}, "edges": graph["edges"]}


def _service_choice(scenario, graph, obs, preferred):
    if preferred in graph["nodes"][obs]:
        return preferred
    service = [a for a in graph["nodes"][obs] if a is not None]
    return min(service, key=lambda a: (_cost(scenario, obs, a), a)) if service else None


class PolicyAuditTests(unittest.TestCase):
    def test_graph_matches_every_legal_prefix_and_exact_bayesian_emission(self):
        for horizon, budget, deadline, sensor in product((1, 2), (3, 8), (4, 9), (1, 3)):
            scenario = Scenario("prefix", horizon=horizon, initial_budget=budget,
                initial_deadline=deadline, initial_resident=1, direct_cost=4,
                hot_cost=1, load_cost=2, retire_cost=1, holding_cost=1,
                request_p0_z0_num=3, request_p0_z0_den=4,
                request_p0_z1_num=1, request_p0_z1_den=4,
                signal_correct_num=sensor, signal_correct_den=4,
                prior0_num=2, prior0_den=3)
            with self.subTest(horizon=horizon, budget=budget, deadline=deadline, sensor=sensor):
                actual, expected = build_graph(scenario), _reference_graph(scenario)
                self.assertEqual(_normalize(actual), _normalize(expected))
                self.assertEqual(sum(p for p, _ in actual["roots"]), 1)
                self.assertEqual(len(actual["roots"]), len({obs for _, obs in actual["roots"]}))
                for obs, choices in actual["nodes"].items():
                    self.assertEqual(choices[None], [])
                    for action, children in choices.items():
                        self.assertTrue(all(type(p) is Fraction and p > 0 for p, _ in children))
                        self.assertEqual(len(children), len({child for _, child in children}))
                        if action is not None and obs.step + 1 < horizon:
                            self.assertEqual(sum(p for p, _ in children), 1)
                        else:
                            self.assertEqual(children, [])

    def test_different_legal_prefixes_keep_residency_and_resource_states(self):
        scenario = Scenario("all-actions", horizon=2, direct_cost=4, hot_cost=1,
                            load_cost=2, initial_budget=8, initial_deadline=8)
        graph = build_graph(scenario)
        _, root = graph["roots"][0]
        self.assertEqual(set(graph["nodes"][root]), {None, -1, 0, 1})
        suffixes = [graph["nodes"][root][a][0][1] for a in (-1, 0, 1)]
        self.assertEqual({s.resident for s in suffixes}, {-1, 0, 1})
        self.assertEqual(len(set(suffixes)), 3)
        self.assertEqual({s.budget for s in suffixes}, {2, 4, 5})
        self.assertTrue(all(s in graph["nodes"] for s in suffixes))

    def test_zero_probability_observations_and_illegal_actions_are_absent(self):
        scenario = Scenario("zero-support", horizon=2, prior0_num=1, prior0_den=1,
            request_p0_z0_num=1, request_p0_z0_den=1, signal_correct_num=0,
            signal_correct_den=1, initial_budget=1, initial_deadline=9,
            direct_cost=2, hot_cost=1, load_cost=1)
        graph = build_graph(scenario)
        self.assertEqual(_normalize(graph), _normalize(_reference_graph(scenario)))
        self.assertEqual(len(graph["roots"]), 1)
        probability, obs = graph["roots"][0]
        self.assertEqual((probability, obs.request, obs.signal, obs.belief_num, obs.belief_den),
                         (Fraction(1), 0, 1, 1, 1))
        self.assertEqual(graph["nodes"][obs], {None: []})
        result = evaluate_policy(scenario, graph, lambda current: None)
        self.assertEqual((result["value_q32"], result["expected_delivered"], result["expected_cost"]),
                         (-2 * scenario.miss_penalty_q32, Fraction(), Fraction()))

    def test_exhaustive_small_complete_policies_equal_independent_recursion(self):
        first = Scenario("one-step", horizon=1, prior0_num=1, prior0_den=1,
            request_p0_z0_num=1, request_p0_z0_den=2, signal_correct_num=1,
            signal_correct_den=1, initial_resident=0, initial_budget=3, initial_deadline=3,
            direct_cost=1, hot_cost=0, load_cost=1, cost_unit=3,
            completion_reward_q32=2 * Q32 + 1, discount_q32=Q32 // 2 + 1)
        second = replace(first, name="two-step", horizon=2,
                         request_p0_z0_den=1, initial_budget=2, initial_deadline=2)
        checked = []
        for scenario in (first, second):
            graph, reference = build_graph(scenario), _reference_graph(scenario)
            states = sorted(reference["nodes"], key=astuple)
            count = 0
            for selected in product(*(tuple(reference["nodes"][obs]) for obs in states)):
                actions = dict(zip(states, selected))
                expected = _reference_policy(scenario, reference, actions)
                actual = evaluate_policy(scenario, graph, actions.__getitem__)
                self.assertEqual({k: actual[k] for k in expected}, expected)
                self.assertIsInstance(actual["expected_delivered"], Fraction)
                self.assertIsInstance(actual["expected_cost"], Fraction)
                count += 1
            checked.append(count)
        self.assertEqual(checked, [16, 48])

    def test_uncertain_full_policies_use_true_law_and_state_dependent_external_objective(self):
        scenario = Scenario("uncertain", horizon=2, initial_resident=1,
            initial_budget=7, initial_deadline=7, direct_cost=4, hot_cost=1,
            load_cost=2, retire_cost=1, holding_cost=1, cost_unit=3,
            prior0_num=2, prior0_den=3, signal_correct_num=3, signal_correct_den=5,
            completion_reward_q32=17 * Q32 + 1, discount_q32=13 * Q32 // 16 + 1,
            risk_aversion_q32=Q32 // 3 + 1)
        graph, reference = build_graph(scenario), _reference_graph(scenario)
        for preferred in (-1, 0, 1):
            for delayed_stop in (False, True):
                actions = {obs: (None if delayed_stop and obs.step else
                           _service_choice(scenario, reference, obs, preferred))
                           for obs in reference["nodes"]}
                with self.subTest(preferred=preferred, delayed_stop=delayed_stop):
                    expected = _reference_policy(scenario, reference, actions)
                    actual = evaluate_policy(scenario, graph, actions.__getitem__)
                    self.assertEqual({k: actual[k] for k in expected}, expected)

    def test_nested_downside_is_applied_inside_history_not_again_before_root_reveal(self):
        scenario = Scenario("risk", horizon=2, initial_resident=0,
            initial_budget=100, initial_deadline=100, direct_cost=3, hot_cost=1,
            request_p0_z0_num=1, request_p0_z0_den=2,
            request_p0_z1_num=1, request_p0_z1_den=2,
            signal_correct_num=1, signal_correct_den=2,
            completion_reward_q32=10 * Q32, discount_q32=3 * Q32 // 4,
            risk_aversion_q32=Q32 // 2, dynamic_preferences=False)
        graph = build_graph(scenario)
        result = evaluate_policy(scenario, graph, lambda obs: 0)
        # Leaf rewards 9/7; conditional CE=7.75; root mean=8+0.75*7.75.
        self.assertEqual(result["value_q32"], 221 * Q32 // 16)
        self.assertEqual(result["expected_delivered"], Fraction(2))
        self.assertEqual(result["expected_cost"], Fraction(4))
        one = replace(scenario, horizon=1, risk_aversion_q32=Q32)
        self.assertEqual(evaluate_policy(one, build_graph(one), lambda obs: 0)["value_q32"], 8 * Q32)

    def test_ex_ante_root_rounding_is_exact_signed_ties_even(self):
        scenario = Scenario("root-rounding", horizon=1, initial_resident=0,
            initial_budget=2, initial_deadline=2, hot_cost=0, direct_cost=1,
            load_cost=0, cost_unit=Q32, dynamic_preferences=False,
            prior0_num=1, prior0_den=1, request_p0_z0_num=1, request_p0_z0_den=2,
            signal_correct_num=1, signal_correct_den=1, risk_aversion_q32=Q32)
        for reward, expected in ((0, 0), (1, 0), (2, 2), (-1, -2)):
            current = replace(scenario, completion_reward_q32=reward)
            with self.subTest(reward=reward):
                actual = evaluate_policy(current, build_graph(current), lambda obs: 0)
                self.assertEqual(actual["value_q32"], expected)
                self.assertEqual(actual["expected_cost"], Fraction(1, 2))

    def test_zero_first_action_regret_can_hide_strict_complete_policy_loss(self):
        scenario = Scenario("continuation", horizon=2, initial_resident=0,
            prior0_num=1, prior0_den=1, request_p0_z0_num=1, request_p0_z0_den=1,
            signal_correct_num=1, signal_correct_den=1,
            initial_budget=20, initial_deadline=20, dynamic_preferences=False)
        graph, reference = build_graph(scenario), _reference_graph(scenario)
        good_actions = {obs: 0 for obs in reference["nodes"]}
        bad_actions = {obs: 0 if obs.step == 0 else None for obs in reference["nodes"]}
        good = evaluate_policy(scenario, graph, good_actions.__getitem__)
        bad = evaluate_policy(scenario, graph, bad_actions.__getitem__)
        _, root = graph["roots"][0]
        self.assertEqual(good["actions"][root], bad["actions"][root])
        first_action_plus_optimal_continuation = _backup(scenario, root, 0,
            [(p, good["state_values"][child]) for p, child in reference["nodes"][root][0]])
        self.assertEqual(good["state_values"][root] - first_action_plus_optimal_continuation, 0)
        self.assertEqual(good["value_q32"], 589 * Q32 // 16)
        self.assertEqual(bad["value_q32"], -73 * Q32 // 8)
        self.assertGreater(good["value_q32"] - bad["value_q32"], 0)
        self.assertEqual((good["expected_delivered"], bad["expected_delivered"]), (Fraction(2), Fraction(1)))

    def test_same_dynamic_and_fixed_action_maps_have_same_complete_external_value(self):
        scenario = Scenario("same-actions", horizon=2, initial_budget=6, initial_deadline=6)
        graph = build_graph(scenario)
        # These callbacks exercise the two actual policy paths with an explicitly
        # scalar test backend. This test makes no original-native execution claim.
        dynamic_actions = {obs: plan(scenario, obs, "dynamic-ndu", backend=scalar_backend)["action"]
                           for obs in graph["nodes"]}
        fixed_actions = {obs: plan(scenario, obs, "fixed-preference-ndu", backend=scalar_backend)["action"]
                         for obs in graph["nodes"]}
        self.assertTrue(any(preferences(scenario, obs) != preferences(scenario, obs, fixed=True)
                            for obs in graph["nodes"]))
        self.assertEqual(dynamic_actions, fixed_actions)
        dynamic = evaluate_policy(scenario, graph, dynamic_actions.__getitem__)
        fixed = evaluate_policy(scenario, graph, fixed_actions.__getitem__)
        self.assertEqual(dynamic, fixed)
        expected = _reference_policy(scenario, _reference_graph(scenario), dynamic_actions)
        self.assertEqual({k: dynamic[k] for k in expected}, expected)

    def test_callback_observes_each_plain_current_state_exactly_once(self):
        scenario = Scenario("callback", horizon=2)
        graph = build_graph(scenario)
        calls = Counter()
        def choose(obs):
            self.assertIs(type(obs), Observation)
            self.assertFalse(hasattr(obs, "future"))
            self.assertFalse(hasattr(obs, "seed"))
            calls[obs] += 1
            return None
        result = evaluate_policy(scenario, graph, choose)
        self.assertEqual(calls, Counter({obs: 1 for obs in graph["nodes"]}))
        self.assertEqual(set(result["actions"]), set(graph["nodes"]))
        self.assertEqual(set(result["state_values"]), set(graph["nodes"]))

    def test_bad_choices_and_callback_failures_cannot_become_partial_results(self):
        scenario = Scenario("bad-choice", horizon=1, initial_budget=0, initial_deadline=0,
                            hot_cost=1, direct_cost=1)
        graph = build_graph(scenario)
        rich = replace(scenario, initial_budget=20, initial_deadline=20)
        rich_graph = build_graph(rich)
        for bad in (True, False, 0.0, "cache-0", 2):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                evaluate_policy(rich, rich_graph, lambda obs: bad)
        for bad in (-1, 0, 1):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                evaluate_policy(scenario, graph, lambda obs: bad)
        marker = RuntimeError("independent failing callback")
        def failure(obs):
            raise marker
        with self.assertRaises(RuntimeError) as caught:
            evaluate_policy(scenario, graph, failure)
        self.assertIs(caught.exception, marker)

    def test_caps_reject_truncation_and_accept_exact_complete_graph(self):
        scenario = Scenario("caps", horizon=2)
        expected = _reference_graph(scenario)
        count, edges = len(expected["nodes"]), expected["edges"]
        exact = build_graph(scenario, max_states=count, max_edges=edges)
        self.assertEqual(_normalize(exact), _normalize(expected))
        for args in ({"max_states": count - 1}, {"max_edges": edges - 1},
                     {"max_states": True}, {"max_edges": True},
                     {"max_states": 1.5}, {"max_edges": -1}):
            with self.subTest(args=args), self.assertRaises((ValueError, TypeError)):
                build_graph(scenario, **args)

    def test_omitted_or_reweighted_graph_evidence_is_rejected_before_policy(self):
        scenario = Scenario("graph-evidence", horizon=2)
        graph = build_graph(scenario)
        _, root = graph["roots"][0]
        incomplete_action, incomplete_child, reweighted, missing_root, bad_count = [deepcopy(graph) for _ in range(5)]
        del incomplete_action["nodes"][root][-1]
        incomplete_child["nodes"][root][-1].pop()
        branches = reweighted["nodes"][root][-1]
        probability, child = branches[0]
        branches[0] = (probability / 2, child)
        missing_root["roots"].pop()
        bad_count["edges"] -= 1
        for corrupted in (incomplete_action, incomplete_child, reweighted, missing_root, bad_count):
            calls = []
            with self.assertRaises((ValueError, TypeError)):
                evaluate_policy(scenario, corrupted, lambda obs: calls.append(obs))
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
