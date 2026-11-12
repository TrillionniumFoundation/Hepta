"""Causal, numerical and fair-control checks for the finite research model."""
from dataclasses import FrozenInstanceError, asdict, replace
from fractions import Fraction
import unittest

from experiments.hia_ndu_feedback_20261106.model import (
    ACTIONS, ARMS, Q32, SCENARIOS, FeedbackEnvironment, FeedbackError, Observation,
    Scenario, SearchBudgetExhausted, action_cost, certainty_equivalent,
    degeneration_probe, digest, forecast, independent_oracle, mul_q32, plan,
    posterior, preferences, q32, round_fraction, run_episode, scalar_backend, plan_gated,
    select_fixed, wiring_probes,
)


class RecordingBackend:
    def __init__(self):
        self.calls = []

    def evaluate(self, candidates, **kwargs):
        self.calls.append((candidates, kwargs))
        return scalar_backend(candidates, **kwargs)


class FeedbackTests(unittest.TestCase):
    def test_signed_fixed_point_rounds_each_product_ties_even(self):
        self.assertEqual(mul_q32(-3, Q32 // 2), -2)
        self.assertEqual(mul_q32(-1, Q32 // 2), 0)
        self.assertEqual(mul_q32(3, Q32 // 2), 2)
        self.assertEqual(mul_q32(1, Q32 // 2), 0)
        for n in range(-20, 21):
            self.assertEqual(round_fraction(Fraction(n, 2)), round(Fraction(n, 2)))

    def test_no_float_or_bool_probability_and_resource_ints(self):
        for change in ({"horizon": True}, {"direct_cost": 1.0}, {"prior0_den": 0},
                       {"signal_correct_num": 11, "signal_correct_den": 10},
                       {"hot_cost": 7}, {"horizon": 5}, {"cost_unit": 0}):
            with self.subTest(change=change), self.assertRaises(FeedbackError):
                Scenario("invalid", **change)

    def test_observation_is_immutable_and_contains_no_future_or_seed(self):
        obs = FeedbackEnvironment(SCENARIOS["adaptive"], 7).observe()
        self.assertEqual(set(asdict(obs)), {"step", "request", "signal", "resident", "budget", "deadline", "belief_num", "belief_den"})
        with self.assertRaises(FrozenInstanceError):
            obs.request = 1

    def test_same_history_same_decision_despite_future_rng_change(self):
        s = SCENARIOS["adaptive"]
        a, b = FeedbackEnvironment(s, 3), FeedbackEnvironment(s, 3)
        b._rng.seed(987654321)  # Change only future randomness, after observation.
        self.assertEqual(a.observe(), b.observe())
        pa, pb = plan(s, a.observe(), "same-objective"), plan(s, b.observe(), "same-objective")
        for key in ("action", "candidate_values_q32", "forecast", "preference", "state_digest"):
            self.assertEqual(pa[key], pb[key])

    def test_forecast_has_all_unrealized_outcomes_and_exact_mass(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 1).observe()
        branches = forecast(s, obs)
        self.assertEqual(len(branches), 4)
        self.assertEqual(sum(p for p, *_ in branches), 1)
        self.assertTrue(all(p > 0 for p, *_ in branches))
        self.assertEqual(sum(p*b for p, _, _, b in branches), obs.belief)

    def test_sensor_reliability_reverses_belief_when_signal_is_misleading(self):
        good, bad = SCENARIOS["adaptive"], SCENARIOS["misleading"]
        # Ambiguous current request plus signal: the calibrated anti-signal has
        # opposite evidence relative to the same current-request likelihood.
        pg = posterior(good, Fraction(1, 2), 0, 0)
        pb = posterior(bad, Fraction(1, 2), 0, 0)
        self.assertGreater(pg, Fraction(9, 10))
        self.assertLess(pb, Fraction(9, 10))

    def test_hand_computable_retention_and_numeric_reversals(self):
        result = wiring_probes()
        self.assertTrue(result["all_passed"])
        self.assertEqual([r["expected_action"] for r in result["retention"]], ["cache-1", "cache-0"])
        self.assertEqual([r["expected_action"] for r in result["numeric_preference"]], ["B", "A"])
        for r in result["retention"]:
            self.assertTrue(all(c["feasible"] for c in r["native"]["candidates"]))

    def test_native_callback_happens_before_choice_at_every_backup(self):
        s = SCENARIOS["adaptive"]
        backend = RecordingBackend()
        obs = FeedbackEnvironment(s, 3).observe()
        result = plan(s, obs, "dynamic-ndu", backend=backend)
        self.assertEqual(len(backend.calls), result["search"]["backups"])
        self.assertGreater(len(backend.calls), 1)
        self.assertEqual(result["search"]["backend_calls"], len(backend.calls))
        for candidates, _ in backend.calls:
            self.assertEqual({c["id"] for c in candidates}, {"direct", "cache-0", "cache-1", "abstain"})
        self.assertEqual(backend.calls[-1][1]["state_digest"], obs.state_digest)
        self.assertGreater(len({k["state_digest"] for _, k in backend.calls}), 1)

    def test_backend_values_actually_control_actions(self):
        s = replace(SCENARIOS["adaptive"], horizon=1)
        obs = Observation(0, 0, 0, -1, 20, 20, 1, 2)
        baseline = plan(s, obs, "dynamic-ndu", backend=scalar_backend)
        def prefer_other(candidates, **kwargs):
            r = scalar_backend(candidates, **kwargs)
            r["values"]["cache-1"] = 1000 * Q32
            r["winners"] = ["cache-1"]
            return r
        altered = plan(s, obs, "dynamic-ndu", backend=prefer_other)
        self.assertNotEqual(baseline["action"], altered["action"])
        self.assertEqual(altered["action"], 1)

    def test_backend_cannot_return_winner_inconsistent_with_values(self):
        s = replace(SCENARIOS["adaptive"], horizon=1)
        obs = Observation(0, 0, 0, -1, 20, 20, 1, 2)
        def corrupt(candidates, **kwargs):
            r = scalar_backend(candidates, **kwargs)
            r["winners"] = ["cache-1"]
            return r
        with self.assertRaises(FeedbackError):
            plan(s, obs, "dynamic-ndu", backend=corrupt)

    def test_native_arm_without_native_backend_is_not_silent_simulation(self):
        s = SCENARIOS["adaptive"]
        with self.assertRaises(FeedbackError):
            plan(s, FeedbackEnvironment(s, 1).observe(), "dynamic-ndu")

    def test_independent_oracle_matches_bellman_values_and_actions(self):
        for s in SCENARIOS.values():
            for seed in range(8):
                env = FeedbackEnvironment(s, seed)
                while not env.done:
                    obs = env.observe()
                    control = plan(s, obs, "same-objective")
                    oracle = independent_oracle(s, obs)
                    self.assertEqual(control["value_q32"], oracle["value_q32"], (s.name, seed, obs))
                    self.assertEqual(control["action"], oracle["action"])
                    for k, v in oracle["candidate_values_q32"].items():
                        self.assertEqual(control["candidate_values_q32"][k], v)
                    env.step(control["action"])

    def test_shared_single_slot_and_load_retire_costs(self):
        s = replace(SCENARIOS["adaptive"], retire_cost=2)
        obs = Observation(0, 0, 0, 1, 100, 100, 1, 2)
        self.assertEqual(action_cost(s, obs, 1)["total"], 6)
        changed = action_cost(s, obs, 0)
        self.assertEqual(changed["prepare"], 4)
        self.assertEqual(changed["retire"], 2)
        self.assertEqual(changed["total"], 7)
        self.assertEqual(action_cost(s, obs, -1)["retire"], 2)
        with self.assertRaises(FeedbackError):
            action_cost(s, obs, 3)

    def test_real_action_changes_next_feasible_space(self):
        s = replace(SCENARIOS["adaptive"], initial_budget=7, initial_deadline=7)
        a, b = FeedbackEnvironment(s, 3), FeedbackEnvironment(s, 3)
        target = a.observe().request
        a.step(target)
        b.step(-1)
        self.assertNotEqual(a.observe().resident, b.observe().resident)
        self.assertNotEqual(a.observe().budget, b.observe().budget)
        pa = plan(s, a.observe(), "state-greedy")
        pb = plan(s, b.observe(), "state-greedy")
        self.assertNotEqual([c["feasible"] for c in pa["candidates"]], [c["feasible"] for c in pb["candidates"]])

    def test_actual_feedback_changes_resources_not_frozen_forecast_costs(self):
        s = SCENARIOS["adaptive"]
        env = FeedbackEnvironment(s, 3)
        obs = env.observe()
        out = env.step(obs.request, actual_cost=7)
        self.assertEqual(out["predicted_cost"], 5)
        self.assertEqual(out["cost"], 7)
        self.assertEqual(env.observe().budget, 13)
        self.assertEqual(s.load_cost, 4)
        self.assertEqual(env.observe().resident, obs.request)

    def test_actual_overrun_retains_failure_and_full_denominator(self):
        s = SCENARIOS["adaptive"]
        result = run_episode(s, 3, "state-greedy", executor=lambda obs, action: 99)
        self.assertEqual(result["planned_requests"], 3)
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["actual_cost"], 99)
        self.assertEqual(result["steps"][0]["outcome"]["status"], "actual_budget_exceeded")

    def test_action_execution_identity_is_retained(self):
        s = SCENARIOS["adaptive"]
        r = run_episode(s, 7, "same-objective")
        for row in r["steps"]:
            self.assertEqual(row["decision"]["action"], row["outcome"]["executed_action"])
        self.assertEqual(r["authority"], "DENY_ALL")
        self.assertFalse(r["production_activation"])

    def test_resource_state_changes_numeric_price(self):
        s = SCENARIOS["adaptive"]
        rich = Observation(0, 0, 0, -1, 100, 100, 1, 2)
        poor = replace(rich, budget=8)
        self.assertNotEqual(preferences(s, rich)["price_q32"], preferences(s, poor)["price_q32"])
        self.assertEqual(preferences(s, rich, fixed=True)["price_q32"], preferences(s, poor, fixed=True)["price_q32"])

    def test_digest_only_change_cannot_change_values(self):
        c = [{"id": "A", "instant_q32": -5*Q32, "terminal_q32": 10*Q32,
              "discount_q32": 3*Q32//4, "feasible": True, "resource_q32": 0, "risk_q32": 0}]
        a = scalar_backend(c, state_digest=digest("s"), preference_digest=digest("a"), objective_digest=digest("o"))
        b = scalar_backend(c, state_digest=digest("s"), preference_digest=digest("b"), objective_digest=digest("o"))
        self.assertEqual(a["values"], b["values"])

    def test_unit_discount_linearity_is_preserved_as_negative_control(self):
        self.assertTrue(degeneration_probe()["all_passed"])

    def test_downside_risk_penalizes_same_mean_variability(self):
        stable = certainty_equivalent([(Fraction(1), 5*Q32)], Q32//2)
        risky = certainty_equivalent([(Fraction(1, 2), 0), (Fraction(1, 2), 10*Q32)], Q32//2)
        self.assertEqual(stable, 5*Q32)
        self.assertLess(risky, stable)
        self.assertEqual(certainty_equivalent([(Fraction(1, 2), 0), (Fraction(1, 2), 10*Q32)], 0), stable)

    def test_search_budget_does_not_return_a_partial_oracle(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 3).observe()
        for arm in ("same-objective", "exact-oracle"):
            with self.subTest(arm=arm), self.assertRaises(SearchBudgetExhausted):
                plan(s, obs, arm, max_transitions=3)

    def test_fixed_selection_charges_all_candidates_training_only(self):
        selected = select_fixed(SCENARIOS["fixed"], [1, 2, 3, 4])
        self.assertEqual(selected["action"], 0)
        self.assertEqual(len(selected["all_candidates"]), 3)
        self.assertFalse(selected["final_holdout_used"])
        self.assertTrue(all(r["training_search_transitions"] > 0 for r in selected["all_candidates"]))

    def test_all_controls_have_explicit_information_and_objective_roles(self):
        self.assertEqual(len(ARMS), 7)
        s = SCENARIOS["fixed"]
        obs = FeedbackEnvironment(s, 3).observe()
        ordinary = plan(s, obs, "ordinary-mpc")
        exact = plan(s, obs, "same-objective")
        self.assertEqual(ordinary["depth"], 3)
        self.assertTrue(ordinary["search_complete"])
        self.assertTrue(exact["search_complete"])
        self.assertNotEqual(ordinary["preference"]["discount_q32"], exact["preference"]["discount_q32"])

    def test_abstention_is_explicit_feasible_and_never_dispatches(self):
        s = replace(SCENARIOS["adaptive"], initial_budget=0, initial_deadline=0)
        o = FeedbackEnvironment(s, 3).observe()
        b = RecordingBackend()
        r = plan(s, o, "dynamic-ndu", backend=b)
        self.assertEqual(r["selected_action"], "abstain")
        self.assertIsNone(r["action"])
        self.assertEqual(r["candidate_values_q32"]["abstain"], -90*Q32)
        abstain = next(c for c in r["candidates"] if c["id"] == "abstain")
        self.assertTrue(abstain["feasible"])
        self.assertEqual(abstain["resource_q32"], 0)
        self.assertEqual(len(b.calls), 1)
        self.assertEqual(set(r["candidate_values_q32"]), {"direct", "cache-0", "cache-1", "abstain"})
        exact = independent_oracle(s, o)
        self.assertEqual(r["candidate_values_q32"], exact["candidate_values_q32"])
        with self.assertRaises(FeedbackError):
            action_cost(s, o, None)

    def test_abstention_retains_spent_controller_cost(self):
        s = SCENARIOS["adaptive"]
        env = FeedbackEnvironment(s, 3)
        o = env.step(None, actual_cost=7)
        self.assertEqual(o["cost"], 7)
        self.assertEqual(o["remaining_budget"], 13)
        self.assertEqual(o["remaining_deadline"], 13)
        self.assertEqual(o["reward_q32"], -97*Q32)
        self.assertIsNone(o["executed_action"])
        self.assertFalse(o["delivered"])

    def test_last_step_compute_gate_does_not_call_native(self):
        s = replace(SCENARIOS["adaptive"], horizon=1)
        obs = FeedbackEnvironment(s, 3).observe()
        def forbidden(*args, **kwargs):
            raise AssertionError("native must not start for certified zero-gap decision")
        decision = plan_gated(s, obs, backend=forbidden, fixed_action=0)
        oracle = independent_oracle(s, obs)
        self.assertFalse(decision["compute_gate"]["invoke"])
        self.assertEqual(decision["compute_gate"]["gross_gain_upper_q32"], 0)
        self.assertEqual(decision["value_q32"], oracle["value_q32"])
        self.assertEqual(decision["action"], oracle["action"])
        self.assertEqual(decision["search"]["backend_calls"], 0)
        self.assertGreater(decision["controller_wall_ns"], 0)
        self.assertEqual(decision["search"]["transitions"], decision["search"]["gate_transitions"])

    def test_fixed_deterministic_dominance_gate_has_exact_zero_gap(self):
        # An additional analytical gate fixture, distinct from registered 99%
        # fixed workload. It does not retroactively change that environment.
        s = replace(SCENARIOS["fixed"], request_p0_z0_num=100, request_p0_z1_num=100)
        obs = FeedbackEnvironment(s, 3).observe()
        d = plan_gated(s, obs)
        oracle = independent_oracle(s, obs)
        self.assertEqual(d["compute_gate"]["gross_gain_upper_q32"], 0)
        self.assertFalse(d["native_backend_used"])
        self.assertEqual(d["value_q32"], oracle["value_q32"])
        self.assertEqual(d["action"], oracle["action"])
        self.assertIn("full-horizon", d["value_scope"])

    def test_compute_gain_bound_contains_independent_finite_oracle(self):
        for s in SCENARIOS.values():
            for seed in range(8):
                obs = FeedbackEnvironment(s, seed).observe()
                # Large frozen price skips; the certificate itself must still
                # contain the independently encoded optimum.
                d = plan_gated(s, obs, compute_penalty_q32=1000*Q32)
                oracle = independent_oracle(s, obs)
                g = d["compute_gate"]
                self.assertLessEqual(g["incumbent_policy_value_q32"], oracle["value_q32"])
                self.assertLessEqual(oracle["value_q32"], g["optimal_value_upper_q32"])
                self.assertFalse(g["invoke"])
                self.assertFalse(g["cost_threshold_is_observed_guarantee"])

    def test_positive_compute_gap_invokes_original_callback(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 3).observe()
        backend = RecordingBackend()
        d = plan_gated(s, obs, backend=backend)
        self.assertTrue(d["compute_gate"]["invoke"])
        self.assertGreater(d["compute_gate"]["gross_gain_upper_q32"], 0)
        self.assertEqual(d["search"]["backend_calls"], len(backend.calls))
        self.assertGreater(len(backend.calls), 0)
        self.assertEqual(d["search"]["transitions"], d["search"]["gate_transitions"]+d["search"]["native_search_transitions"])
        self.assertEqual(d["value_q32"], independent_oracle(s, obs)["value_q32"])

    def test_gate_does_not_create_a_second_search_budget(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 3).observe()
        for limit in (4, 6, 10, 100):
            with self.subTest(limit=limit), self.assertRaises(SearchBudgetExhausted) as caught:
                plan_gated(s, obs, backend=RecordingBackend(), max_transitions=limit)
            self.assertEqual(caught.exception.transitions, limit)
            self.assertEqual(caught.exception.search_stats["transitions"], limit)

    def test_native_failures_preserve_already_spent_search_and_call_attempts(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 3).observe()
        calls = []
        def failed(candidates, **kwargs):
            calls.append(candidates)
            if len(calls) == 5:
                raise OSError("injected native transport failure")
            return scalar_backend(candidates, **kwargs)
        with self.assertRaises(OSError) as caught:
            plan(s, obs, "dynamic-ndu", backend=failed)
        self.assertEqual(caught.exception.search_stats["backend_calls"], 5)
        self.assertGreater(caught.exception.search_stats["transitions"], 0)
        self.assertEqual(caught.exception.transitions, caught.exception.search_stats["transitions"])
        self.assertGreater(caught.exception.controller_wall_ns, 0)

    def test_gated_native_failure_preserves_gate_and_search_cost(self):
        s = SCENARIOS["adaptive"]
        obs = FeedbackEnvironment(s, 3).observe()
        def failed(*args, **kwargs):
            raise OSError("injected gated native failure")
        with self.assertRaises(OSError) as caught:
            plan_gated(s, obs, backend=failed)
        stats = caught.exception.search_stats
        self.assertGreater(stats["gate_transitions"], 0)
        self.assertGreater(stats["transitions"], stats["gate_transitions"])
        self.assertEqual(stats["backend_calls"], 1)

    def test_no_actions_becomes_explicit_abstention(self):
        s = replace(SCENARIOS["adaptive"], initial_budget=0, initial_deadline=0)
        r = run_episode(s, 1, "same-objective")
        self.assertEqual(r["delivered"], 0)
        self.assertEqual(r["planned_requests"], 3)
        self.assertEqual(r["steps"][0]["outcome"]["status"], "abstained")
        self.assertLess(r["realized_discounted_utility_q32"], 0)


if __name__ == "__main__":
    unittest.main()
