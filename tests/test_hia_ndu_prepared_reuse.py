"""Attribution and fairness gates for the prospective actual reuse experiment."""
from copy import deepcopy
import json
import unittest

from tools.qualify_hia_ndu_prepared_reuse import (
    MODULES, PROTOCOL_PATH, PROFILE, competition_attribution, complete_budget_dp,
    opportunity_analysis, totals, validate_protocol)


class PreparedReuseProtocolTests(unittest.TestCase):
    def protocol(self):
        return json.loads(PROTOCOL_PATH.read_bytes())

    def test_explicit_policy_and_equal_limits_are_bound_for_both_protocols(self):
        self.assertEqual(validate_protocol(self.protocol())["purpose"], "qualification")
        smoke = json.loads((PROFILE / "SMOKE_PROTOCOL_20261029.json").read_bytes())
        self.assertEqual(validate_protocol(smoke)["purpose"], "functional-smoke")
        for change in ("policy", "limits", "authority"):
            p = self.protocol()
            if change == "policy": p["proof_policy"]["timeout_ms"] -= 1
            if change == "limits": p["session_limits"]["max_entries"] += 1
            if change == "authority": p["authority"] = "ALLOW"
            with self.assertRaises(ValueError): validate_protocol(p)

    def test_historical_cost_never_becomes_a_new_cold_measurement(self):
        rows = [{"arm": "fixed", "wall_ns": 20}, {"arm": "dp", "wall_ns": 10},
                {"arm": "native-stream-sealed", "wall_ns": 9}]
        result = totals(rows, 100, 2, 1000)
        self.assertFalse(result["new_cold_controller_build_measured"])
        self.assertEqual(result["standalone_current_warm_ns"]["native-stream-sealed"], 111)
        self.assertEqual(result["current_warm_plus_historical_controller_build_ns"]["native-stream-sealed"], 1111)
        self.assertFalse(result["ndu_warm_observed_below_fixed_and_dp"])

    def test_actual_opportunity_requires_both_complete_admitted_pairs(self):
        targets = {module: "guard-wide" for module in MODULES}
        rows = [{"module_ids": [module], "arm": arm, "admitted": True, "wall_ns": cost}
            for module in MODULES for arm, cost in (("opportunity-base", 100), ("opportunity-candidate", 90))]
        self.assertTrue(opportunity_analysis(rows, targets)["two_observed_positive_amortized_opportunities"])
        rows[-1]["admitted"] = False
        self.assertFalse(opportunity_analysis(rows, targets)["two_observed_positive_amortized_opportunities"])
        self.assertFalse(opportunity_analysis(rows[:-1], targets)["two_observed_positive_amortized_opportunities"])

    def record(self):
        model = {"remaining_credits": 1, "modules": [
            [{"target": "base", "cost_ns": 100, "credits": 0, "verified": True},
             {"target": "guard-wide", "cost_ns": 40, "credits": 1, "verified": True}],
            [{"target": "base", "cost_ns": 110, "credits": 0, "verified": True},
             {"target": "guard-wide", "cost_ns": 80, "credits": 1, "verified": True}]]}
        return {"arm": "native-stream-sealed", "profile": "shared-budget", "group": 0,
            "admitted": True, "decisions": [{"epoch": 0, "model": model, "selected": complete_budget_dp(model)}],
            "compile_credit": {"attempts": [{"module": "byte_sum", "target": "guard-wide"}]},
            "observations": [{"module": "byte_sum", "state": "guard-wide", "status": "measured"}]}

    def test_competition_requires_exact_actual_target_build_output_and_inputs(self):
        targets = {module: "guard-wide" for module in MODULES}
        record = self.record()
        evidence = competition_attribution([record], targets)
        self.assertTrue(evidence[0]["two_exact_targets_competed_for_one_credit"])
        for case in ("group", "suffix", "build", "output", "second-gain", "different-plan"):
            bad = deepcopy(record)
            if case == "group": bad["group"] = 1
            if case == "suffix": bad["decisions"][0]["epoch"] = 1
            if case == "build": bad["compile_credit"]["attempts"] = []
            if case == "output": bad["observations"][0]["status"] = "wrong-output"
            if case == "second-gain": bad["decisions"][0]["model"]["modules"][1][1]["cost_ns"] = 111
            if case == "different-plan": bad["decisions"][0]["selected"]["targets"] = ["base", "guard-wide"]
            self.assertFalse(any(row["two_exact_targets_competed_for_one_credit"]
                for row in competition_attribution([bad], targets)), case)


if __name__ == "__main__":
    unittest.main()
