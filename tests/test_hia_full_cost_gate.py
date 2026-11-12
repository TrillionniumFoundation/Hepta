"""Adversarial finite full-cost comparisons. No native build or NDU authority."""
import json
import unittest
from hepta.hia_full_cost_gate import FullCostRejected, SCHEMA, assess_full_cost

def fixture():
    d = lambda char: char * 64
    trials = [dict(id=f"task{i:02d}", input_digest=d("a"),
                   expected_result_digest=d("b")) for i in range(8)]
    arms = []
    for name, elapsed in {"baseline": 1000, "fixed": 910, "dp": 900, "ndu": 740}.items():
        costs = {key: 0 for key in ("toolchain", "dependencies", "controller_build",
            "candidate_build", "calibration", "search", "verification",
            "measurement", "publication", "switch", "rollback")}
        costs["controller_build"] = 10
        arms.append({"strategy": name, "core_digest": d("c"), "artifact_digest": d("d"),
            "toolchain_digest": d("e"), "observer_digest": d("f"),
            "candidate_bank_digest": d("1"), "one_time_ns": costs,
            "unknown_costs": [], "observations": [
                {"trial_id": trial["id"], "input_digest": trial["input_digest"],
                 "result_digest": trial["expected_result_digest"], "execution_ns": elapsed,
                 "controller_ns": 5, "failed_attempt_ns": 0, "peak_rss_bytes": 1024,
                 "p99_ns": elapsed, "completed": True} for trial in trials]})
    return {"schema": SCHEMA, "source_digest": d("2"), "objective_digest": d("3"),
        "hardware_digest": d("4"), "workload_digest": d("5"), "candidate_bank_digest": d("1"),
        "generation": 1, "registered_trials": trials, "minimum_gain_ppm": 50000,
        "minimum_gain_ns": 100, "maximum_peak_rss_bytes": 2048,
        "maximum_p99_ns": 1500, "arms": arms}

def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

class HIAFullCostGateTests(unittest.TestCase):
    def test_complete_positive_synthetic_observations_still_deny_authority(self):
        result = assess_full_cost(wire(fixture()))
        self.assertTrue(result["economic_scope_positive"])
        self.assertEqual(result["best_control"], "dp")
        self.assertEqual(result["ndu_full_cost_saving_ns"], 1280)
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertFalse(result["production_activation_allowed"])
        self.assertFalse(result["claims"]["input_observations_authenticated"])

    def test_unknown_cost_blocks_positive_claim(self):
        state = fixture()
        state["arms"][3]["unknown_costs"] = ["human_work_ns"]
        result = assess_full_cost(wire(state))
        self.assertFalse(result["economic_scope_positive"])
        self.assertIn("unaccounted_costs", result["reasons"])

    def test_complete_build_cost_reverses_apparent_gain(self):
        state = fixture()
        state["arms"][3]["one_time_ns"]["candidate_build"] = 2000
        result = assess_full_cost(wire(state))
        self.assertLess(result["ndu_full_cost_saving_ns"], 0)
        self.assertIn("no_absolute_full_cost_advantage", result["reasons"])

    def test_missing_or_forged_trial_or_control_fails_closed(self):
        mutations = (
            lambda x: x["arms"].pop(),
            lambda x: x["arms"][0].update(strategy="ndu"),
            lambda x: x["arms"][1].update(candidate_bank_digest="9"*64),
            lambda x: x["arms"][0]["observations"].pop(),
            lambda x: x["arms"][0]["observations"][1].update(trial_id="task00"),
            lambda x: x["arms"][0]["observations"][2].update(result_digest="9"*64),
            lambda x: x["arms"][0]["observations"][2].update(input_digest="9"*64),
            lambda x: x["arms"][0]["observations"][2].update(completed=False),
            lambda x: x["registered_trials"][2].update(id="task01"),
        )
        for mutation in mutations:
            with self.subTest(case=str(mutation)):
                state = fixture()
                mutation(state)
                with self.assertRaises(FullCostRejected):
                    assess_full_cost(wire(state))

    def test_mismatched_observer_invalidates_economic_claim(self):
        state = fixture()
        state["arms"][1]["observer_digest"] = "9" * 64
        result = assess_full_cost(wire(state))
        self.assertIn("different_observation_sources", result["reasons"])

    def test_absent_nonfinite_boolean_negative_and_overflow_cost_refuse(self):
        mutations = (
            lambda x: x["arms"][3]["one_time_ns"].pop("verification"),
            lambda x: x["arms"][3]["one_time_ns"].update(search=None),
            lambda x: x["arms"][3]["one_time_ns"].update(search=True),
            lambda x: x["arms"][3]["one_time_ns"].update(search=-1),
            lambda x: x["arms"][3]["one_time_ns"].update(search=1.5),
            lambda x: x["arms"][3]["one_time_ns"].update(search=10**30),
            lambda x: x["arms"][3]["observations"][0].update(execution_ns=0),
            lambda x: x.update(generation=True),
            lambda x: x.update(minimum_gain_ppm=0),
            lambda x: x["arms"][2].update(unknown_costs=["same", "same"]),
        )
        for mutation in mutations:
            with self.subTest(case=str(mutation)):
                state = fixture()
                mutation(state)
                with self.assertRaises(FullCostRejected):
                    assess_full_cost(wire(state))

    def test_limits_and_absolute_relative_thresholds(self):
        for mutation, reason in (
            (lambda x: x.update(maximum_peak_rss_bytes=512), "memory_limit_exceeded"),
            (lambda x: x.update(maximum_p99_ns=700), "p99_limit_exceeded"),
            (lambda x: x.update(minimum_gain_ns=2000), "no_absolute_full_cost_advantage"),
            (lambda x: x.update(minimum_gain_ppm=300000), "no_relative_full_cost_advantage"),
        ):
            state = fixture()
            mutation(state)
            result = assess_full_cost(wire(state))
            self.assertFalse(result["economic_scope_positive"])
            self.assertIn(reason, result["reasons"])

    def test_immutable_strict_wire(self):
        for bad in (fixture(), '{"x":1,"x":2}', '{"x":NaN}', b"\xff",
                    b" " * 262145):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(FullCostRejected):
                    assess_full_cost(bad)

if __name__ == "__main__":
    unittest.main()
