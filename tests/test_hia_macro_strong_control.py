"""Adversarial admissions for the ordinary full-budget comparison policy."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_agent_macro_policy import (MacroPolicyRejected, advise_ordinary,
    ordinary_plan_selection, ledger_totals, digest, wire)
from tests.test_hia_agent_macro_policy import state, entry


class StrongOrdinaryTests(unittest.TestCase):
    def candidate(self, identity, cost, *, tokens=0, actions=None, uncertainty=0):
        return {"id": identity, "actions": actions or ["evaluate", "stop"],
            "remaining_cost_ns": cost, "uncertainty_ns": uncertainty,
            "model_tokens": tokens, "support_sha256": digest(identity)}

    def test_considers_all_plans_and_retains_incumbent_on_ties(self):
        data = state()
        data["stop_remaining_ns"] = 1000
        data["plans"] = [self.candidate("first", 1200), self.candidate("best", 500)]
        self.assertEqual(ordinary_plan_selection(data)["selected_id"], "best")
        data["plans"].reverse()
        self.assertEqual(ordinary_plan_selection(data)["selected_id"], "best")
        data["stop_remaining_ns"] = 500
        self.assertEqual(ordinary_plan_selection(data)["selected_id"], "abstain")

    def test_budget_uses_all_sunk_costs_failed_timeouts_and_tokens(self):
        data = state()
        data["budget"] = {"wall_ns": 1000, "model_tokens": 100}
        data["ledger"] = [entry("failure", "search", 200, 0, "failed"),
            entry("timeout", "model", 300, 80, "timed_out")]
        data["stop_remaining_ns"] = 900
        data["plans"] = [self.candidate("fast_token_overrun", 1, tokens=21),
            self.candidate("wall_overrun", 501), self.candidate("fits", 499, tokens=20)]
        decision = ordinary_plan_selection(data)
        self.assertEqual(decision["selected_id"], "fits")
        self.assertEqual(decision["remaining_wall_ns"], 500)
        self.assertEqual(ledger_totals(data["ledger"])["failed_attempt_wall_ns"], 500)
        self.assertEqual(ordinary_plan_selection(data, elapsed_ns=2)["selected_id"], "abstain")

    def test_uncertainty_can_reverse_superficial_speed_gain(self):
        data = state()
        data["stop_remaining_ns"] = 1000
        data["plans"] = [self.candidate("looks_fast", 100, uncertainty=901),
            self.candidate("bounded", 900)]
        self.assertEqual(ordinary_plan_selection(data)["selected_id"], "bounded")

    def test_no_candidate_and_explicit_no_change_are_valid(self):
        data = state()
        data["plans"] = []
        decision = ordinary_plan_selection(data)
        self.assertEqual(decision["selected_id"], "abstain")
        self.assertEqual(decision["status"], "ADVISORY")
        for disposition in ("keep_existing", "no_adopt", "stop"):
            data["plans"] = [self.candidate("choice", 0,
                actions=[disposition, "use", "stop"] if disposition != "stop" else ["stop"])]
            decision = ordinary_plan_selection(data)
            self.assertEqual(decision["disposition"], disposition)

    def test_cannot_adopt_and_retain_same_candidate_plan(self):
        for actions in (["keep_existing", "adopt", "stop"], ["no_adopt", "adopt", "stop"],
                        ["keep_existing", "no_adopt", "stop"]):
            data = state()
            data["plans"] = [self.candidate("contradiction", 0, actions=actions)]
            with self.assertRaises(MacroPolicyRejected):
                ordinary_plan_selection(data)

    def test_unknown_cost_or_completion_blocks_control(self):
        data = state()
        for missing in ("wall_ns", "model_tokens", "receipt_sha256"):
            copy = deepcopy(data)
            copy["ledger"][0][missing] = None
            result = ordinary_plan_selection(copy)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason"], "unknown_observed_costs")
        data["ledger"][0]["status"] = "unknown"
        self.assertEqual(ordinary_plan_selection(data)["status"], "BLOCKED")

    def test_cancelled_cost_is_preserved_without_new_budget(self):
        data = state()
        data["ledger"].append(entry("cancelled", "search", 500, 0, "cancelled"))
        with patch("hepta.hia_agent_macro_policy.time.perf_counter_ns", side_effect=[0, 10, 23]):
            result = advise_ordinary(wire(data))
        self.assertEqual(result["next_state"]["budget"], data["budget"])
        self.assertEqual(result["observed_costs"]["observed_wall_ns"], 1523)
        self.assertEqual(result["observed_costs"]["failed_attempt_wall_ns"], 500)
        self.assertFalse(result["native_ndu_evaluated"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["ledger_entry"]["receipt_sha256"], digest({k:v for k,v in result.items()
            if k not in {"ledger_entry", "next_state", "observed_costs"}}))

    def test_repeated_advice_cannot_refund_controller_cost(self):
        data = state()
        with patch("hepta.hia_agent_macro_policy.time.perf_counter_ns", side_effect=[0, 10, 23, 100, 110, 125]):
            first = advise_ordinary(wire(data))
            second = advise_ordinary(wire(first["next_state"]))
        self.assertEqual(second["observed_costs"]["observed_wall_ns"], 1048)
        self.assertEqual(second["ledger_entry"]["id"], "controller.2")

    def test_native_campaign_ordinary_uses_all_budget_feasible_plans(self):
        from tools.qualify_hia_macro_campaign import _decision
        data = state()
        data["fixture_one_step_cost_ns"] = 10
        data["plans"] = [self.candidate("bad_first", 999999999), self.candidate("best", 10)]
        decision = _decision(data, "ordinary", None)
        self.assertEqual(decision["selected_id"], "best")
        self.assertEqual(decision["ordinary_advice"]["policy"], "full_budget_argmin")
        self.assertIsNone(decision["advice"])
        self.assertFalse(decision["ordinary_advice"]["native_ndu_evaluated"])

    def test_sixteen_plans_bound_and_unknown_parameters(self):
        data = state()
        data["plans"] = [self.candidate("p" + str(i), i) for i in range(17)]
        with self.assertRaises(MacroPolicyRejected):
            ordinary_plan_selection(data)
        data = state()
        data["prefer_fast"] = True
        with self.assertRaises(MacroPolicyRejected):
            ordinary_plan_selection(data)


if __name__ == '__main__':
    unittest.main()
