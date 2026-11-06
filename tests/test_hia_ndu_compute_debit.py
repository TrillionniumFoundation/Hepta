"""Counterexamples for opt-in forecast and observed resource-time debits.

Clocks and callbacks below are deterministic controls, not native-performance
evidence. The explicit successor recurrence and frozen v1 primitives are
exercised; no alternative planner result is mocked into these checks.
"""
from dataclasses import FrozenInstanceError, asdict, replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import compute_debit as debit
from experiments.hia_ndu_feedback_20261106 import compute_plan, coverage, model
from experiments.hia_ndu_feedback_20261106.economical import priced_plan
from tools import qualify_hia_ndu_feedback as campaign


class Clock:
    def __init__(self, now=0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, elapsed):
        self.now += elapsed


def scenario(**changes):
    values = dict(horizon=2, request_p0_z0_num=1, request_p0_z0_den=1,
                  request_p0_z1_num=1, request_p0_z1_den=1,
                  signal_correct_num=1, signal_correct_den=1,
                  prior0_num=1, prior0_den=1, direct_cost=2, hot_cost=2,
                  load_cost=0, initial_resident=-1, initial_budget=100,
                  initial_deadline=100, discount_q32=model.Q32, risk_aversion_q32=0,
                  dynamic_preferences=False, cost_unit_label=debit.NANOSECOND_LABEL)
    values.update(changes)
    return model.Scenario("controlled-compute-debit", **values)


def profile(s, forecasts):
    return debit.ComputeDebitProfile(model.digest(asdict(s)),
        model.digest("controlled training-only fixture; no real calibration claim"), tuple(forecasts))


def choose(s, env, p, arm="same-objective", **kwargs):
    return compute_plan.plan(s, env.observe(), arm, compute_profile=p, **kwargs)


class ComputeDebitPlanningTests(unittest.TestCase):
    def test_v1_model_bytes_and_original_coverage_registration_remain_unchanged(self):
        # This is the concrete integration failure: the old coverage loader
        # rejects even behavior-compatible edits to the frozen v1 model bytes.
        original = coverage.load_protocol()
        model_hash = sha256(Path(model.__file__).read_bytes()).hexdigest()
        self.assertEqual(model_hash, original["base_model_sha256"])
        self.assertEqual(model_hash, compute_plan.BASE_MODEL_SHA256)
        contract = json.loads((Path(__file__).resolve().parents[1] /
            "benchmarks/hia_ndu_feedback/COMPUTE_DEBIT_PROTOCOL.json").read_text())
        self.assertEqual(contract["v1_compatibility"]["model_sha256"], model_hash)
        self.assertEqual(contract["planner_entrypoint"],
                         "experiments.hia_ndu_feedback_20261106.compute_plan.plan")
        s = scenario()
        env, p = model.FeedbackEnvironment(s, 1), profile(s, (1, 2))
        with self.assertRaises(TypeError):
            model.plan(s, env.observe(), "same-objective", compute_profile=p)
        self.assertEqual(choose(s, env, p)["schema"], debit.PLAN_SCHEMA)

    def test_future_compute_can_remove_service_from_the_existing_transition_graph(self):
        # Old model: two deliveries cost 3+3 <= 8. New model: the second
        # decision costs 3 first, leaving 2; a 3-unit service is infeasible.
        s = scenario(direct_cost=3, hot_cost=3, initial_budget=8, initial_deadline=8)
        env = model.FeedbackEnvironment(s, 1)
        old = model.plan(s, env.observe(), "same-objective")
        new = choose(s, env, profile(s, (3, 0)))
        self.assertEqual(old["value_q32"], 34 * model.Q32)
        self.assertEqual(new["value_q32"], -16 * model.Q32)  # 20-3 + (-30-3)
        futures = [r for r in new["search_trace"] if r["compute_debit"]["forecast_ns"] == 3]
        self.assertTrue(futures)
        self.assertTrue(all(r["eligible"] == ["abstain"] for r in futures))
        self.assertTrue(all((r["compute_debit"]["budget_before"], r["compute_debit"]["budget_after"])
                            == (5, 2) for r in futures))

    def test_each_forecast_is_charged_once_in_value_and_successor_resources(self):
        s = scenario()
        env = model.FeedbackEnvironment(s, 1)
        result = choose(s, env, profile(s, (5, 3)))
        # Exact, independently hand-computable value: 40 - (3+2) - (5+2).
        self.assertEqual(result["value_q32"], 28 * model.Q32)
        root = result["search_trace"][-1]["compute_debit"]
        self.assertEqual((root["budget_before"], root["budget_after"]), (100, 97))
        future = result["search_trace"][0]["compute_debit"]
        self.assertEqual((future["budget_before"], future["budget_after"]), (95, 90))
        self.assertEqual(env.observe().budget, 100, "Planning must not charge the real owner")

    def test_greedy_uses_full_remaining_depth_to_index_its_forecast(self):
        s = scenario()
        env = model.FeedbackEnvironment(s, 1)
        result = choose(s, env, profile(s, (5, 3)), arm="state-greedy")
        self.assertEqual(result["value_q32"], 15 * model.Q32)
        self.assertEqual(result["search_trace"][-1]["compute_debit"]["forecast_ns"], 3)

    def test_compute_exhaustion_blocks_zero_duration_work_and_prices_abstention(self):
        s = scenario(horizon=1, direct_cost=0, hot_cost=0, initial_budget=9, initial_deadline=9)
        env = model.FeedbackEnvironment(s, 1)
        result = choose(s, env, profile(s, (9,)))
        self.assertIsNone(result["action"])
        self.assertEqual(result["value_q32"], -39 * model.Q32)
        self.assertEqual(result["search_trace"][-1]["eligible"], ["abstain"])

    def test_budget_and_deadline_are_independent_constraints(self):
        for budget, deadline in ((4, 100), (100, 4)):
            with self.subTest(budget=budget, deadline=deadline):
                s = scenario(horizon=1, initial_budget=budget, initial_deadline=deadline)
                env = model.FeedbackEnvironment(s, 1)
                result = choose(s, env, profile(s, (3,)))
                self.assertIsNone(result["action"])

    def test_native_callback_is_bound_to_compute_objective_and_total_cost(self):
        s = scenario()
        p = profile(s, (5, 3))
        env = model.FeedbackEnvironment(s, 1)
        calls = []

        def recording_scalar(candidates, **kwargs):
            calls.append((candidates, kwargs))
            return model.scalar_backend(candidates, **kwargs)

        result = choose(s, env, p, arm="dynamic-ndu", backend=recording_scalar)
        ordinary = choose(s, env, p)
        self.assertEqual(result["candidate_values_q32"], ordinary["candidate_values_q32"])
        self.assertEqual(len(calls), result["search"]["backups"])
        self.assertTrue(all(c[1]["objective_digest"] == p.objective_digest(s) for c in calls))
        self.assertNotEqual(p.objective_digest(s), s.objective_digest)
        self.assertEqual(calls[-1][0][0]["resource_q32"], 5 * model.Q32)
        self.assertEqual(calls[0][0][0]["resource_q32"], 7 * model.Q32)

    def test_profile_rejects_wrong_units_identity_mutable_or_incomplete_forecasts(self):
        s = scenario()
        p = profile(s, (1, 2))
        with self.assertRaises(FrozenInstanceError):
            p.forecast_ns_by_remaining = (0, 0)
        for forecasts in ([1, 2], (True, 2), (-1, 2), (10**12 + 1, 2)):
            with self.subTest(forecasts=forecasts), self.assertRaises(model.FeedbackError):
                debit.ComputeDebitProfile(p.scenario_sha256, p.calibration_sha256, forecasts)
        for bad in (profile(s, (1,)), profile(replace(s, initial_budget=99), (1, 2))):
            with self.assertRaises(model.FeedbackError):
                choose(s, model.FeedbackEnvironment(s, 1), bad)
        raw = replace(s, cost_unit_label="declared model cost units")
        with self.assertRaisesRegex(model.FeedbackError, "nanoseconds"):
            choose(raw, model.FeedbackEnvironment(raw, 1), profile(raw, (1, 2)))

    def test_old_oracle_and_price_bounds_cannot_silently_claim_the_new_model(self):
        s = scenario()
        env, p = model.FeedbackEnvironment(s, 1), profile(s, (1, 2))
        with self.assertRaisesRegex(model.FeedbackError, "v1 independent oracle"):
            choose(s, env, p, arm="exact-oracle")
        with self.assertRaisesRegex(model.FeedbackError, "v1 price-only bounds") as caught:
            priced_plan(s, env.observe(), "same-objective", forecast_control_ns=1,
                        greedy_forecast_ns=1, compute_profile=p)
        self.assertEqual(caught.exception.cost_receipt["phase"], "validation")
        self.assertFalse(caught.exception.cost_receipt["planner_attempted"])
        with self.assertRaisesRegex(ValueError, "profile-aware independent audit"):
            campaign.audit_episode(s, {"steps": [{"decision": choose(s, env, p)}]}, 20000)


class ComputeDebitDispatchTests(unittest.TestCase):
    def dispatch(self, env, decision, p, clock, execute):
        return debit.dispatch_after_compute(env, decision, p, step_started_ns=0,
                                           execute=execute, clock_ns=clock)

    def test_actual_compute_wait_exhausts_deadline_before_any_action(self):
        for elapsed in (10, 11):
            with self.subTest(elapsed=elapsed):
                s = scenario(horizon=1, initial_budget=100, initial_deadline=10)
                env, p = model.FeedbackEnvironment(s, 1), profile(s, (0,))
                chosen = choose(s, env, p)
                self.assertIsNotNone(chosen["action"])
                calls = []
                result = self.dispatch(env, chosen, p, Clock(elapsed), lambda *_: calls.append(1))
                self.assertEqual(calls, [])
                self.assertEqual(result["outcome"]["status"], "controller_deadline_exceeded")
                self.assertEqual(result["outcome"]["cost"], elapsed)
                self.assertEqual(result["outcome"]["remaining_budget"], 100 - elapsed)
                self.assertEqual(result["outcome"]["remaining_deadline"], 0)
                self.assertTrue(result["selected_action_was_not_executed"])
                self.assertFalse(result["compute_debit"]["hard_realtime_guarantee"])

    def test_current_compute_leaves_insufficient_workload_budget_before_dispatch(self):
        # Old guard only compared elapsed > 10. At elapsed=9 it would run a
        # declared 2-unit service although only one unit remains.
        s = scenario(horizon=1, initial_budget=10, initial_deadline=100)
        env, p = model.FeedbackEnvironment(s, 1), profile(s, (0,))
        calls = []
        result = self.dispatch(env, choose(s, env, p), p, Clock(9), lambda *_: calls.append(1))
        self.assertEqual(calls, [])
        self.assertEqual(result["outcome"]["status"], "insufficient_resources_after_compute")
        self.assertEqual(result["compute_debit"]["after_compute"]["budget"], 1)
        self.assertEqual(result["outcome"]["cost"], 9)

    def test_observed_total_is_charged_once_without_adding_forecast_or_compute_again(self):
        s = scenario()
        env, p, clock = model.FeedbackEnvironment(s, 1), profile(s, (5, 5)), Clock(3)
        received = []

        def execute(remaining, action):
            received.append(remaining)
            clock.advance(4)
            return {"effect": "controlled completed action"}

        result = self.dispatch(env, choose(s, env, p), p, clock, execute)
        self.assertEqual(received[0].budget, 97)
        self.assertEqual(result["outcome"]["cost"], 7)
        self.assertEqual(env.observe().budget, 93)
        self.assertEqual(env.observe().deadline, 93)
        self.assertEqual(result["outcome"]["reward_q32"], 13 * model.Q32)
        self.assertEqual(result["compute_debit"]["actual_charged_ns"], 7)
        self.assertEqual(result["compute_debit"]["observed_after_gate_ns"], 4)

    def test_actual_workload_overrun_is_preserved_and_never_called_a_rollback(self):
        s = scenario()
        env, p, clock = model.FeedbackEnvironment(s, 1), profile(s, (0, 0)), Clock(3)
        calls = []

        def execute(*_):
            calls.append(1)
            clock.advance(101)
            return {"effect": "executed"}

        result = self.dispatch(env, choose(s, env, p), p, clock, execute)
        self.assertEqual(calls, [1])
        self.assertEqual(result["native_execution"], {"effect": "executed"})
        self.assertEqual(result["outcome"]["status"], "actual_budget_exceeded")
        self.assertEqual(result["outcome"]["cost"], 104)
        self.assertFalse(result["selected_action_was_not_executed"])

    def test_failed_callback_retains_unknown_effect_elapsed_cost_and_no_retry(self):
        s = scenario()
        env, p, clock = model.FeedbackEnvironment(s, 1), profile(s, (0, 0)), Clock(3)
        original = env.observe()
        calls = []

        def fail(*_):
            calls.append(1)
            clock.advance(4)
            raise RuntimeError("controlled failure after a possible effect")

        with self.assertRaises(RuntimeError) as caught:
            self.dispatch(env, choose(s, env, p), p, clock, fail)
        self.assertEqual(calls, [1])
        self.assertEqual(caught.exception.compute_debit_receipt["effect_outcome"], "UNKNOWN")
        self.assertEqual(caught.exception.compute_debit_receipt["observed_total_ns"], 7)
        self.assertEqual(env.observe(), original)
        self.assertEqual(env.outcomes, [])

    def test_stale_or_legacy_decision_is_rejected_before_workload(self):
        s = scenario()
        env, p = model.FeedbackEnvironment(s, 1), profile(s, (0, 0))
        chosen = choose(s, env, p)
        old = model.plan(s, env.observe(), "same-objective")
        for bad in (old, {**chosen, "state_digest": "0" * 64},
                    {**chosen, "compute_debit": {"profile_sha256": "0" * 64}}):
            with self.assertRaises(model.FeedbackError):
                self.dispatch(env, bad, p, Clock(0), lambda *_: self.fail("dispatched invalid plan"))

    def test_clock_regression_does_not_create_free_work_or_a_success(self):
        s = scenario()
        env, p = model.FeedbackEnvironment(s, 1), profile(s, (0, 0))
        with self.assertRaisesRegex(model.FeedbackError, "nonmonotonic dispatch clock"):
            self.dispatch(env, choose(s, env, p), p, Clock(-1), lambda *_: self.fail("work ran"))
        readings = iter((3, 2, 4))
        with self.assertRaisesRegex(model.FeedbackError, "nonmonotonic completion clock") as caught:
            self.dispatch(env, choose(s, env, p), p, lambda: next(readings), lambda *_: None)
        self.assertEqual(caught.exception.compute_debit_receipt["effect_outcome"], "UNKNOWN")
        self.assertEqual(env.outcomes, [])


class ComputeDebitEpisodeTests(unittest.TestCase):
    def run_control(self, s, p, *, decision_wait, workload_wait):
        clock, workers, observations = Clock(), [], []

        class ControlledWorker:
            def __init__(self, *_args, **_kwargs):
                self.resident, self.state_digest = -1, "controlled physical state"
                self.rows, self.startup_ns = [], 2
                clock.advance(self.startup_ns)
                workers.append(self)

            def execute(self, action, request, **kwargs):
                clock.advance(workload_wait)
                self.resident = action
                row = {"action": action, "request": request, "workload_wall_ns": workload_wait}
                self.rows.append(row)
                return row

            def close(self):
                clock.advance(1)
                return {"returncode": 0}

        def decision(sc, obs, arm, backend, fixed_action, allowance):
            observations.append(obs)
            result = compute_plan.plan(sc, obs, arm, fixed_action=fixed_action,
                                       max_transitions=allowance, compute_profile=p)
            clock.advance(decision_wait)
            return result

        clocks = SimpleNamespace(monotonic_ns=clock)
        with patch.object(campaign, "NativeCache", ControlledWorker), \
                patch.object(campaign, "time", clocks), patch.object(debit, "time", clocks):
            result = campaign.episode(s, 1, "same-objective", fixed_action=0,
                inputs={"workload_binary": {"path": "controlled-fixture"},
                        "workload_manifest": {"path": "controlled-fixture"}},
                output=Path("unused"), native=True, n=2, repeats=1, cap=20000,
                decision_function=decision, compute_profile=p)
        return result, workers, observations

    def test_actual_episode_consumes_compute_before_every_real_dispatch(self):
        s = scenario(horizon=1, initial_budget=10, initial_deadline=10)
        result, workers, _ = self.run_control(s, profile(s, (0,)), decision_wait=9, workload_wait=4)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(workers[0].rows, [])
        self.assertEqual(result["actual_cost"], 9)
        self.assertEqual(result["steps"][0]["outcome"]["status"], "insufficient_resources_after_compute")

    def test_successive_episode_observations_receive_single_actual_debits(self):
        s = scenario(initial_budget=50, initial_deadline=50)
        result, workers, observations = self.run_control(s, profile(s, (1, 1)), decision_wait=3, workload_wait=4)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["delivered"], 2)
        self.assertEqual([o.budget for o in observations], [50, 43])
        self.assertEqual([r["outcome"]["cost"] for r in result["steps"]], [7, 7])
        self.assertEqual(result["steps"][-1]["outcome"]["remaining_budget"], 36)
        self.assertEqual(result["actual_cost"], 14)
        self.assertEqual(result["episode_wall_ns"], 17)  # 2 startup + 14 online + 1 cleanup.
        self.assertEqual(len(workers[0].rows), 2)


if __name__ == "__main__":
    unittest.main()
