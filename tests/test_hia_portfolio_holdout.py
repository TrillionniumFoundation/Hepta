"""Prospective-study accounting and model-information contracts, without timing."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_portfolio import digest, exact_portfolio
from tools.qualify_hia_portfolio_holdout import (ARMS, PROTOCOL_PATH, ROOT, cost_report,
    file_identity, finish_episode_evidence, native_build_cost, native_parity, portfolio_problem, verify_registration)


def bank():
    return {"bank_sha256": digest("development-only-bank"), "candidates": {
        name: {"setup_ns": setup, "artifact_bytes": size,
            "verification": {"status": "verified"}, "source_sha256": digest(name),
            "latency_ns": {"7": run, "9": run * 2}}
        for name, setup, size, run in (("base", 10, 3, 100), ("small", 20, 4, 60), ("wide", 30, 6, 40))}}


def episodes():
    return [{"arm": arm, "group": 0, "outer_wall_ns": 10,
        "status": "completed", "all_outputs_correct": True,
        "actual_budget_passed": True, "native_parity_checked": True} for arm in ARMS]


def build(outer=None):
    return {"inner_reported_wall_ns": 100, "outer_empty_target_wall_ns": outer,
            "complete_cold_build_scope_known": outer is not None}


class PortfolioStudyTests(unittest.TestCase):
    def test_episode_evidence_write_is_charged_to_its_arm_and_budget(self):
        row = {"status": "completed", "actual_budget_passed": True}
        with patch("tools.qualify_hia_portfolio_holdout.time.monotonic_ns", side_effect=[130, 180]), \
                patch("tools.qualify_hia_portfolio_holdout.save") as save:
            finish_episode_evidence(row, Path("unused"), started_ns=100, budget_ns=70)
        self.assertEqual(row["outer_wall_ns"], 80)
        self.assertEqual(row["outer_evidence_write_ns"], 50)
        self.assertFalse(row["actual_budget_passed"])
        self.assertEqual(save.call_args.args[1]["pre_outer_evidence_wall_ns"], 30)

    def test_failed_episode_evidence_write_is_retained_and_charged(self):
        row = {"status": "completed", "actual_budget_passed": True}
        with patch("tools.qualify_hia_portfolio_holdout.time.monotonic_ns", side_effect=[130, 150]), \
                patch("tools.qualify_hia_portfolio_holdout.save", side_effect=OSError("disk refusal")):
            finish_episode_evidence(row, Path("unused"), started_ns=100, budget_ns=70)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["outer_wall_ns"], 50)
        self.assertEqual(row["evidence_error"]["type"], "OSError")

    def test_registered_protocol_is_fixed_and_has_heldout_information_separation(self):
        cfg = json.loads(PROTOCOL_PATH.read_bytes())
        self.assertEqual(cfg["arms"], list(ARMS))
        self.assertEqual(len(cfg["batch_sizes"]), 12)
        self.assertEqual(cfg["groups"], len(cfg["holdout_seeds"]))
        self.assertNotIn(cfg["training_seed"], cfg["holdout_seeds"])
        self.assertFalse(cfg["previous_negative_results_replaced"])
        self.assertFalse(cfg["global_optimality_claim"])

    def test_registration_requires_exact_commit_before_any_process(self):
        for bad in ("main", "HEAD", "a" * 39, "A" * 40, None, "$(touch /tmp/not-run)"):
            with self.subTest(commit=bad), self.assertRaises(ValueError):
                verify_registration(bad)

    def test_common_setup_charged_once_per_standalone_not_divided_between_arms(self):
        controller = {arm: 0 for arm in ARMS}; controller["native-ndu"] = 7
        report = cost_report(episodes(), cfg={"groups": 1}, study_ns=100,
            controller_ns=controller, build=build(120), competition={"established": True})
        self.assertEqual(report["common_observed_preparation_ns"], 43)
        self.assertEqual(report["already_built_marginal_total_ns"]["exact-q32-dp"], 53)
        self.assertEqual(report["already_built_marginal_total_ns"]["native-ndu"], 60)
        self.assertEqual(report["standalone_with_original_outer_build_ns"]["native-ndu"], 180)
        self.assertEqual(report["native_cold_savings_against_controls_ns"]["exact-q32-dp"], -127)

    def test_unknown_build_is_never_zero_or_full_gain(self):
        report = cost_report(episodes(), cfg={"groups": 1}, study_ns=100,
            controller_ns={arm: 0 for arm in ARMS}, build=build(), competition={"established": True})
        self.assertIsNone(report["standalone_with_original_outer_build_ns"]["native-ndu"])
        self.assertIsNone(report["native_cold_savings_against_controls_ns"]["exact-q32-dp"])
        self.assertFalse(report["descriptive_measured_scope_net_gain"])
        self.assertFalse(report["complete_lifetime_net_gain_proved"])
        self.assertTrue(all(value is None for value in report["unknown_costs"].values()))

    def test_failed_episode_cost_remains_and_prevents_gain(self):
        rows = episodes(); rows[0].update(status="failed", all_outputs_correct=False, outer_wall_ns=90)
        report = cost_report(rows, cfg={"groups": 1}, study_ns=200,
            controller_ns={arm: 0 for arm in ARMS}, build=build(0), competition={"established": True})
        self.assertEqual(report["actual_episode_totals_ns"]["fixed-base"], 90)
        self.assertFalse(report["all_registered_execution_checks_passed"])
        self.assertFalse(report["descriptive_measured_scope_net_gain"])

    def test_missing_and_duplicate_episodes_cannot_complete_acceptance(self):
        kwargs = dict(cfg={"groups": 1}, study_ns=100, controller_ns={arm: 0 for arm in ARMS},
                      build=build(0), competition={"established": True})
        self.assertFalse(cost_report(episodes()[:-1], **kwargs)["all_registered_execution_checks_passed"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            cost_report(episodes() + [episodes()[0]], **kwargs)
        with self.assertRaisesRegex(ValueError, "negative|overlapping"):
            cost_report(episodes(), **dict(kwargs, study_ns=1))

    def test_model_uses_own_past_observations_and_preserves_paid_set(self):
        cfg = {"batch_sizes": [7, 9], "scratch_byte_limit": 40, "completion_value_ns": 10000}
        args = dict(remaining_indices=[1], initial_artifacts=["small"], observations=[],
                    remaining_ns=10000, retained_limit=10, generation=2)
        before = portfolio_problem(bank(), cfg, **args)
        after = portfolio_problem(bank(), cfg, **dict(args, observations=[
            {"status": "measured", "artifact": "small", "n": 7, "outer_wall_ns": 120}]))
        self.assertEqual(after["initial_artifacts"], ["small"])
        small = next(o for o in after["regions"][0]["options"] if o["artifact"] == "small")
        self.assertEqual(small["run_ns"], 240)
        self.assertNotEqual(before["snapshot_sha256"], after["snapshot_sha256"])
        self.assertEqual(before["objective_sha256"], after["objective_sha256"])
        self.assertNotEqual(digest(before), digest(after))

    def test_update_ratio_bounds_are_exact_and_do_not_rewrite_objective(self):
        cfg = {"batch_sizes": [7], "scratch_byte_limit": 40, "completion_value_ns": 10000}
        for wall, expected in ((0, 25), (100000, 400)):
            p = portfolio_problem(bank(), cfg, remaining_indices=[0], initial_artifacts=[],
                observations=[{"status": "measured", "artifact": "base", "n": 7, "outer_wall_ns": wall}],
                remaining_ns=10000, retained_limit=20, generation=1)
            self.assertEqual(next(o["run_ns"] for o in p["regions"][0]["options"] if o["artifact"] == "base"), expected)

    def test_native_parity_cannot_be_replaced_by_matching_candidate_id_only(self):
        cfg = {"batch_sizes": [7], "scratch_byte_limit": 40, "completion_value_ns": 10000}
        p = portfolio_problem(bank(), cfg, remaining_indices=[0], initial_artifacts=[], observations=[],
            remaining_ns=10000, retained_limit=20, generation=1)
        result = exact_portfolio(p)
        response = {"paths": [{"id": name, "values_q32": [value]} for name, value in result["values_q32"].items()],
            "pareto_candidate_ids": result["pareto_candidate_ids"], "advisory_candidate_id": result["advisory_candidate_id"]}
        native_parity(result, response)
        bad = deepcopy(response); bad["paths"][0]["values_q32"][0] += 1
        with self.assertRaises(ValueError):
            native_parity(result, bad)

    def test_outer_build_requires_exact_manifest_binary_source_and_real_cost(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); identity = root / "identity.json"; envelope = root / "outer.json"
            manifest = {"identity": {"source_commit": "a" * 40}, "binary_sha256": "b" * 64,
                "build_cost": {"wall_ns": 50, "target_cache": "empty"}}
            identity.write_text(json.dumps(manifest))
            self.assertFalse(native_build_cost(manifest, identity)["complete_cold_build_scope_known"])
            good = {"schema": "hepta.hia.ndu.outer-build-cost.v1", "identity_sha256": file_identity(identity)["sha256"],
                "status": "measured", "builder_sha256": file_identity(ROOT / "tools/build_hia_recursive_ndu_bridge.py")["sha256"],
                "binary_sha256": "b" * 64, "native_source_pin": "a" * 40, "returncode": 0,
                "source_unchanged": True, "target_cache": "empty", "wall_ns": 60,
                "authority": "DENY_ALL", "safety_certificate": False}
            envelope.write_text(json.dumps(good))
            self.assertEqual(native_build_cost(manifest, identity, envelope)["outer_empty_target_wall_ns"], 60)
            for changes in ({"wall_ns": 49}, {"source_unchanged": False}, {"identity_sha256": "c" * 64}, {"target_cache": "warm"},
                            {"status": "failed"}, {"builder_sha256": "d" * 64}):
                envelope.write_text(json.dumps({**good, **changes}))
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    native_build_cost(manifest, identity, envelope)


if __name__ == "__main__":
    unittest.main()
