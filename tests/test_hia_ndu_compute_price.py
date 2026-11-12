"""Independent freeze, cost-ledger and failure attacks on the price cohort.

All timings and native identities in campaign doubles are controlled fixtures.
These tests do not provide measured native performance or positive net benefit.
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import model
from tests.test_hia_ndu_feedback_campaign import NoProcessBackend, record
from tools import qualify_hia_ndu_compute_price as priced
from tools import qualify_hia_ndu_feedback as common


class ComputePriceCampaignTests(unittest.TestCase):
    @staticmethod
    def protocol():
        return json.loads(priced.PROTOCOL.read_text())

    def make_case(self, directory):
        directory = Path(directory)
        previous = json.loads(common.PROTOCOL.read_text())
        p = self.protocol()
        p.update(holdout_seeds=[16001], repetitions=1)
        calibration = {
            "training_dimensions": [192, 640],
            "training_seeds": list(previous["training_seeds"]),
            "future_measurement_access": False, "repeats": p["kernel_repeats"],
            "models": {str(n): {"direct_ns": n*n*6, "packed_ns": n*n,
                                "prepare_ns": n*n*4, "retire_ns": 17}
                       for n in (192, 640)},
        }
        calibration_path = directory / "CALIBRATION.json"
        common.write(calibration_path, calibration)
        # A miniature fixture has its own explicitly pinned identity. The real
        # protocol continues to pin the independently audited original bytes.
        p["original_calibration_sha256"] = common.identity(calibration_path)["sha256"]
        protocol_path = directory / "COMPUTE_PRICE_PROTOCOL.json"
        common.write(protocol_path, p)
        inputs = {}
        for name in ("value_binary", "value_manifest", "workload_binary", "workload_manifest"):
            path = directory / name
            path.write_bytes(("controlled fixture: " + name).encode())
            inputs[name] = common.identity(path)
        prior = {"protocol": previous, "inputs": inputs}
        prior_path = directory / "PRIOR_REGISTRATION.json"
        common.write(prior_path, prior)
        registration_path = directory / "REGISTRATION.json"
        source = {"commit": "controlled test source", "tree": "controlled test tree"}
        with patch.object(priced, "PROTOCOL", protocol_path), patch.object(priced, "source", return_value=source):
            priced.freeze(SimpleNamespace(prior_registration=prior_path, calibration=calibration_path,
                                          output=registration_path))
        return SimpleNamespace(p=p, prior=prior, calibration=calibration,
            calibration_path=calibration_path, prior_path=prior_path,
            protocol_path=protocol_path, registration=registration_path,
            source=source, inputs=inputs, output=directory / "results")

    @staticmethod
    def fake_training(scenarios, p, inputs, output):
        trials = [{"environment": name, "arm": arm, "seed": p["training_seeds"][0],
                   "status": "completed", "wall_ns": 11, "search_transitions": 3}
                  for name in scenarios for arm in ("state-greedy", "same-objective", "dynamic-ndu")]
        result = {"status": "completed", "errors": [], "all_trials": trials,
                  "prices": {name: {arm: {str(depth): 1000 * (ai+1) + depth
                                           for depth in range(1, scenario.horizon+1)}
                                    for ai, arm in enumerate(("state-greedy", "same-objective", "dynamic-ndu"))}
                             for name, scenario in scenarios.items()},
                  "wall_ns": 777, "native_close": {"started": False},
                  "holdout_used": False, "price_is_physical_guarantee": False}
        common.write(output / "TRAINING_PRICES.json", result)
        return result

    @staticmethod
    def fake_episode(scenario, seed, arm, **kwargs):
        result = record(arm, family=scenario.name, seed=seed, dimension=kwargs["n"], wall=100)
        result["steps"] = [{"decision": {"compute_gate": {"invoke": True}},
                            "outcome": {"delivered": True}} for _ in range(scenario.horizon)]
        return result

    @staticmethod
    def fake_audit(scenario, row, cap):
        return {"rows": [{"same_objective_agrees": True} for _ in row["steps"]],
                "wall_ns": 7, "online_controller_access": False}

    def run_case(self, case, *, training=None, episode=None, audit=None, priced_plan=None):
        with ExitStack() as stack:
            stack.enter_context(patch.object(priced, "PROTOCOL", case.protocol_path))
            stack.enter_context(patch.object(priced, "source", return_value=case.source))
            stack.enter_context(patch.object(priced, "train_prices", side_effect=training or self.fake_training))
            stack.enter_context(patch.object(common, "episode", side_effect=episode or self.fake_episode))
            stack.enter_context(patch.object(common, "audit_episode", side_effect=audit or self.fake_audit))
            if priced_plan is not None:
                stack.enter_context(patch.object(priced, "priced_plan", side_effect=priced_plan))
            stack.enter_context(redirect_stdout(StringIO()))
            code = priced.run(SimpleNamespace(registration=case.registration, output=case.output))
        return code, json.loads((case.output / "RESULT.json").read_text())

    def test_default_plan_preserves_all_120_cells_and_360_requests(self):
        p = self.protocol()
        cells = priced.planned_cells(p)
        self.assertEqual(len(cells), 120)
        self.assertEqual(len(cells) * p["horizon"], 360)
        keys = {(c["environment"], c["seed"], c["repeat"], c["arm"]) for c in cells}
        expected = {(name, seed, repeat, arm) for name in p["environments"]
                    for seed in p["holdout_seeds"] for repeat in range(p["repetitions"])
                    for arm in p["arms"]}
        self.assertEqual(keys, expected)
        self.assertEqual(len(keys), len(cells))

    def test_split_and_original_calibration_scope_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            attacks = [
                ("prior final seed", {"holdout_seeds": [case.prior["protocol"]["holdout_seeds"][0]]}),
                ("training seed", {"holdout_seeds": [case.p["training_seeds"][0]]}),
                ("prior final dimension", {"dimension": case.prior["protocol"]["native_dimensions"][0]}),
                ("training dimension", {"dimension": 192}),
                ("changed training identity", {"training_seeds": [99991]}),
                ("unsupported horizon", {"horizon": 4}),
                ("boolean budget", {"episode_budget_ns": True}),
                ("missing control", {"arms": case.p["arms"][:-1]}),
            ]
            for label, changes in attacks:
                with self.subTest(attack=label), self.assertRaises(ValueError):
                    priced.validate_protocol({**case.p, **changes}, case.prior, case.calibration)
            altered = deepcopy(case.calibration)
            altered["future_measurement_access"] = True
            with self.assertRaises(ValueError):
                priced.validate_protocol(case.p, case.prior, altered)

    def test_freeze_rejects_repriced_training_bytes_despite_identical_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            altered = deepcopy(case.calibration)
            altered["models"]["192"]["direct_ns"] += 1
            case.calibration_path.write_text(json.dumps(altered))
            output = Path(directory) / "tampered-freeze.json"
            with patch.object(priced, "PROTOCOL", case.protocol_path), patch.object(priced, "source", return_value=case.source):
                with self.assertRaisesRegex(ValueError, "original training bytes"):
                    priced.freeze(SimpleNamespace(prior_registration=case.prior_path,
                        calibration=case.calibration_path, output=output))
            self.assertFalse(output.exists())

    def test_new_episode_budget_controls_derived_scenarios(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            p = {**case.p, "episode_budget_ns": 123456789}
            scenarios = priced.scenarios_from_training(p, case.prior, case.calibration)
            self.assertNotEqual(p["episode_budget_ns"], case.prior["protocol"]["native_episode_budget_ns"])
            for scenario in scenarios.values():
                self.assertEqual((scenario.initial_budget, scenario.initial_deadline),
                                 (p["episode_budget_ns"], p["episode_budget_ns"]))
                self.assertEqual(scenario.horizon, p["horizon"])

    def test_priced_native_hook_receives_a_real_backend_handle(self):
        seen = []

        def decision(scenario, observation, arm, backend, fixed_action, allowance):
            self.assertIsNotNone(backend, "A compute skip must not hide an unconnected native invoke path")
            result = model.plan(scenario, observation, "dynamic-ndu", backend=backend,
                                max_transitions=allowance)
            seen.append(backend)
            result["arm"] = arm
            return result

        with patch.object(common, "LazyBackend", NoProcessBackend):
            result = common.episode(model.SCENARIOS["adaptive"], 16001, "dynamic-ndu-priced",
                fixed_action=0, inputs={}, output=Path("unused"), native=False, n=0,
                repeats=4, cap=20000, decision_function=decision)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(seen), 3)
        self.assertEqual(len({id(b) for b in seen}), 1)
        self.assertGreater(result["backend_calls"], 0)

    def test_training_failure_preserves_partial_trial_cost_and_search_work(self):
        p = self.protocol()
        p["training_seeds"] = [211]
        calls = 0
        original = model.plan

        def fail_native(scenario, observation, arm, **kwargs):
            nonlocal calls
            calls += 1
            if arm == "dynamic-ndu":
                error = RuntimeError("injected partial native pricing failure")
                error.search_stats = {"transitions": 7, "backend_calls": 2}
                raise error
            return original(scenario, observation, arm, **kwargs)

        with tempfile.TemporaryDirectory() as directory, patch.object(common, "LazyBackend", NoProcessBackend), \
                patch.object(model, "plan", side_effect=fail_native):
            result = priced.train_prices({"adaptive": model.SCENARIOS["adaptive"]}, p, {}, Path(directory))
            stored = json.loads((Path(directory) / "TRAINING_PRICES.json").read_text())
        self.assertEqual(result, stored)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["all_trials"]), 3)
        failed = result["all_trials"][-1]
        self.assertEqual((failed["status"], failed["search_transitions"]), ("failed", 7))
        self.assertGreater(failed["wall_ns"], 0)
        self.assertGreaterEqual(result["wall_ns"], sum(r["wall_ns"] for r in result["all_trials"]))
        self.assertIsNotNone(result["native_close"])
        self.assertFalse(result["holdout_used"])

    def test_training_total_allowance_is_enforced_before_search_not_only_in_summary(self):
        p = self.protocol()
        p.update(training_seeds=[211], max_transitions_per_arm=4)
        with tempfile.TemporaryDirectory() as directory, patch.object(common, "LazyBackend", NoProcessBackend):
            result = priced.train_prices({"adaptive": model.SCENARIOS["adaptive"]}, p, {}, Path(directory))
        self.assertEqual(result["status"], "failed")
        for arm in ("state-greedy", "same-objective", "dynamic-ndu"):
            spent = sum(r["search_transitions"] for r in result["all_trials"] if r["arm"] == arm)
            self.assertLessEqual(spent, p["max_transitions_per_arm"],
                                 "Training executed work beyond the registered lifecycle allowance")

    def test_training_cleanup_failure_is_retained_and_blocks_price_admission(self):
        class FailedClose(NoProcessBackend):
            def close(self):
                raise RuntimeError("controlled training cleanup failure")

        p = self.protocol()
        p["training_seeds"] = [211]
        with tempfile.TemporaryDirectory() as directory, patch.object(common, "LazyBackend", FailedClose):
            result = priced.train_prices({"adaptive": model.SCENARIOS["adaptive"]}, p, {}, Path(directory))
            stored = json.loads((Path(directory) / "TRAINING_PRICES.json").read_text())
        self.assertEqual(result, stored)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["all_trials"]), 9)
        self.assertTrue(all(r["status"] == "completed" for r in result["all_trials"]))
        self.assertTrue(any(e.get("phase") == "native_close" for e in result["errors"]))
        self.assertGreaterEqual(result["wall_ns"], sum(r["wall_ns"] for r in result["all_trials"]))

    def test_training_observations_are_shared_and_medians_use_retained_trials_only(self):
        p = self.protocol()
        p["training_seeds"] = [211, 223]
        with tempfile.TemporaryDirectory() as directory, patch.object(common, "LazyBackend", NoProcessBackend):
            result = priced.train_prices({"adaptive": model.SCENARIOS["adaptive"]}, p, {}, Path(directory))
        self.assertEqual(result["status"], "completed")
        import statistics
        triples = {}
        for row in result["all_trials"]:
            self.assertIn(row["seed"], p["training_seeds"])
            self.assertNotIn(row["seed"], p["holdout_seeds"])
            triples.setdefault((row["seed"], row["observation"]["step"]), []).append(row)
        self.assertEqual(len(triples), 6)
        for rows in triples.values():
            self.assertEqual({r["arm"] for r in rows}, {"state-greedy", "same-objective", "dynamic-ndu"})
            self.assertTrue(all(r["observation"] == rows[0]["observation"] for r in rows))
        for arm, depths in result["prices"]["adaptive"].items():
            for depth, actual in depths.items():
                values = [r["wall_ns"] for r in result["all_trials"] if r["arm"] == arm
                          and 3-r["observation"]["step"] == int(depth)]
                self.assertEqual(actual, round(statistics.median(values)))

    def test_failed_training_retains_the_full_unrun_denominator(self):
        def failed_training(scenarios, p, inputs, output):
            result = self.fake_training(scenarios, p, inputs, output)
            result.update(status="failed", errors=[{"message": "controlled training failure"}])
            result["all_trials"][-1].update(status="failed", search_transitions=23)
            (output / "TRAINING_PRICES.json").write_text(json.dumps(result))
            return result

        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            code, result = self.run_case(case, training=failed_training,
                episode=lambda *a, **k: self.fail("Final execution began after failed training"))
            planned = json.loads((case.output / "PLANNED.json").read_text())
            self.assertEqual(code, 1)
            self.assertEqual(result["planned_episode_count"], len(planned))
            self.assertEqual(result["planned_request_count"], 3*len(planned))
            self.assertEqual(result["retained_episode_count"], 0)
            self.assertEqual(len(result["not_run_cells"]), len(planned))
            self.assertFalse(result["checks"]["all_requests_delivered"])
            self.assertFalse(result["checks"]["training_completed_and_frozen"])
            self.assertEqual(result["training_wall_ns"], 777)
            self.assertEqual(result["transition_ledgers"]["dynamic-ndu"], 29)
            self.assertEqual(result["transition_ledgers"]["dynamic-ndu-priced"], 29)

    def test_audit_error_does_not_remove_executed_cells_or_truncate_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            code, result = self.run_case(case,
                audit=lambda *a: (_ for _ in ()).throw(RuntimeError("injected offline audit failure")))
            self.assertEqual(code, 1)
            self.assertIsNone(result["fatal_error"])
            self.assertEqual(result["retained_episode_count"], result["planned_episode_count"])
            self.assertEqual(len(result["audit_errors"]), result["planned_episode_count"])
            self.assertEqual(result["not_run_cells"], [])
            self.assertFalse(result["checks"]["ordinary_and_native_same_objective_agree"])

    def test_completed_label_cannot_override_actual_missing_delivery(self):
        def mislabeled_episode(*args, **kwargs):
            row = self.fake_episode(*args, **kwargs)
            row["delivered"] = 0
            for step in row["steps"]:
                step["outcome"]["delivered"] = False
            return row

        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            code, result = self.run_case(case, episode=mislabeled_episode)
            self.assertEqual(result["delivered_request_count"], 0)
            self.assertFalse(result["checks"]["all_requests_delivered"],
                             "The success label overrode actual zero delivery")
            self.assertEqual(code, 1)

    def test_wrong_seed_cannot_fill_a_registered_cell(self):
        def rebound_episode(*args, **kwargs):
            row = self.fake_episode(*args, **kwargs)
            row["seed"] = 99999991
            return row

        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            code, result = self.run_case(case, episode=rebound_episode)
            self.assertEqual(result["retained_episode_count"], result["planned_episode_count"])
            self.assertFalse(result["checks"]["all_cells_retained"])
            self.assertFalse(result["checks"]["all_requests_delivered"])
            self.assertEqual(code, 1)

    def test_invoked_priced_planner_requires_exact_audit_but_greedy_skip_does_not(self):
        scenario = model.SCENARIOS["adaptive"]
        baseline = common.episode(scenario, 16001, "same-objective", fixed_action=0,
            inputs={}, output=Path("unused"), native=False, n=0, repeats=4, cap=20000)
        self.assertEqual(baseline["status"], "completed")
        for arm in ("same-objective-priced", "dynamic-ndu-priced"):
            for invoke in (False, True):
                with self.subTest(arm=arm, invoke=invoke):
                    result = deepcopy(baseline)
                    result["arm"] = arm
                    for step in result["steps"]:
                        step["decision"]["compute_gate"] = {"invoke": invoke}
                    result["steps"][0]["decision"]["value_q32"] += 1
                    audit = common.audit_episode(scenario, result, 20000)
                    actual = audit["rows"][0]["same_objective_agrees"]
                    self.assertIs(actual, False if invoke else None,
                        "Invoked exact planning and a deliberate immediate-value skip have different audit obligations")

    def test_postflight_rejects_calibration_prior_and_price_file_mutations(self):
        for attack in ("calibration", "prior", "training", "price_freeze"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                case = self.make_case(directory)
                mutated = False

                def mutate_after_freeze(*args, **kwargs):
                    nonlocal mutated
                    if not mutated:
                        path = {"calibration": case.calibration_path, "prior": case.prior_path,
                                "training": case.output / "TRAINING_PRICES.json",
                                "price_freeze": case.output / "PRICE_FREEZE.json"}[attack]
                        path.write_bytes(path.read_bytes() + b"\n ")
                        mutated = True
                    return self.fake_episode(*args, **kwargs)

                code, result = self.run_case(case, episode=mutate_after_freeze)
                self.assertEqual(code, 1)
                self.assertFalse(result["checks"]["source_and_binary_unchanged"])
                self.assertTrue(result["postflight_errors"])
                self.assertEqual(result["retained_episode_count"], result["planned_episode_count"])

    def test_prices_are_frozen_before_dispatch_and_only_training_prices_reach_gate(self):
        seen = []

        def gate(scenario, observation, arm, **kwargs):
            seen.append((scenario.name, arm, kwargs["forecast_control_ns"], kwargs["greedy_forecast_ns"]))
            return {"arm": arm + "-priced"}

        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)

            def inspect_freeze(scenario, seed, arm, **kwargs):
                frozen = json.loads((case.output / "PRICE_FREEZE.json").read_text())
                self.assertTrue(frozen["before_any_final_execution"])
                self.assertEqual(frozen["training"], common.identity(case.output / "TRAINING_PRICES.json"))
                if arm.endswith("-priced"):
                    obs = model.FeedbackEnvironment(scenario, seed).observe()
                    kwargs["decision_function"](scenario, obs, arm, None, 0, kwargs["cap"])
                # Widely different actual walls must not revise the frozen price.
                row = self.fake_episode(scenario, seed, arm, **kwargs)
                row["episode_wall_ns"] = 999999999 if arm.endswith("-priced") else 1
                return row

            code, result = self.run_case(case, episode=inspect_freeze, priced_plan=gate)
            self.assertEqual(code, 0)
            self.assertTrue(result["checks"]["training_completed_and_frozen"])
        self.assertEqual(len(seen), 6)
        for name, arm, forecast, greedy in seen:
            self.assertEqual(greedy, 1003)
            self.assertEqual(forecast, 2003 if arm == "same-objective" else 3003)


if __name__ == "__main__":
    unittest.main()
