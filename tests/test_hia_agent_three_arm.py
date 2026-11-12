"""Adversarial controls for accounting and terminal feedback, not model scores."""
from __future__ import annotations

import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import qualify_hia_agent_three_arm as study


def usage():
    return {"input_tokens": 12, "cached_input_tokens": 2, "cache_write_input_tokens": 0,
            "output_tokens": 5, "reasoning_output_tokens": 3}


class ThreeArmProtocolTests(unittest.TestCase):
    def registration(self):
        return {"protocol": study.protocol(), "sources": {},
                "tools": {"clang": {"path": "clang"}, "rustc": {"path": "rustc"}}}

    def response(self, text="candidate"):
        return {"status": "completed", "text": text, "usage": usage(),
                "conservative_tokens": 20, "process": {"wall_ns": 10}}

    def observed(self, correct=True, unchanged=True):
        return {"status": "correct" if correct else "observable_wrong", "artifact_unchanged": unchanged,
                "cases": [[0, 0, 0]], "expected": [0], "actual": [0 if correct else 1]}

    def row(self, cell):
        return {**cell, "status": "correct", "correct": True, "identities_unchanged": True,
                "usage_complete": True, "attempts": [{"index": 0, "status": "public_passed", "usage": usage(), "conservative_tokens": 20}],
                "known_conservative_tokens": 20, "conservative_tokens": 20,
                "repair_rounds": 0, "cell_wall_ns": 10}

    def run_cell(self, directory):
        task = study.fixtures.make_fixtures()[0]
        # Mock identity acquisition only; the tested state machine is unchanged.
        with patch.object(study, "identity", side_effect=lambda path: {"path": path}):
            return study.run_cell(study.schedule()[0], task, Path(directory) / "cell", self.registration())

    def test_three_arms_share_canonical_starting_core_and_hidden_is_not_in_prompt(self):
        for task in study.fixtures.make_fixtures():
            for arm in study.ARMS:
                text = study.prompt(task, arm)
                self.assertIn(task["specification"], text)
                self.assertNotIn('"hidden_expected"', text)
                self.assertNotIn("The decoder constrains", text)
                study.evaluator.parse_files(task, arm, study.canonical({"files": task["correct_" + arm]}).decode())
        self.assertEqual(len(study.schedule()), 12)
        self.assertEqual(len({r["id"] for r in study.schedule()}), 12)

    def test_no_responses_means_unknown_delivery_and_usage_not_zero_failures(self):
        result = study.summarize([])
        self.assertFalse(result["eligible_comparison"])
        for group in result["groups"].values():
            self.assertEqual(group["scored_cells"], 0)
            self.assertIsNone(group["delivery_rate"])
            self.assertIsNone(group["cohort_delivery_rate"])
            self.assertIsNone(group["conservative_tokens"])

    def test_duplicate_missing_unknown_usage_and_forged_aggregate_block_gates(self):
        good = [self.row(c) for c in study.schedule()]
        self.assertTrue(study.summarize(good)["eligible_comparison"])
        cases = [good[:-1], good + [good[0]]]
        for key, value in (("correct", False), ("conservative_tokens", 0),
                           ("identities_unchanged", False), ("usage_complete", False)):
            changed = copy.deepcopy(good); changed[0][key] = value; cases.append(changed)
        changed = copy.deepcopy(good); changed[0]["attempts"][0]["usage"] = None; cases.append(changed)
        for rows in cases:
            result = study.summarize(rows)
            self.assertFalse(result["eligible_comparison"])
            self.assertFalse(any(result["descriptive_compact_advantage"].values()))
        self.assertFalse(study.summarize(good)["human_cost_advantage_qualified"])

    def test_infrastructure_attempt_cannot_be_relabelled_as_correct(self):
        rows = [self.row(c) for c in study.schedule()]
        rows[0]["attempts"][0]["status"] = "infrastructure_failure"
        self.assertFalse(study.summarize(rows)["eligible_comparison"])

    def test_public_failure_must_exhaust_registered_correction_before_scoring(self):
        row = self.row(study.schedule()[0])
        row.update(status="public_validation_failed", correct=False)
        row["attempts"][0]["status"] = "public_failed"
        self.assertFalse(study.valid_observation(row))
        second = copy.deepcopy(row["attempts"][0]); second["index"] = 1
        row["attempts"].append(second)
        row.update(known_conservative_tokens=40, conservative_tokens=40, repair_rounds=1)
        self.assertTrue(study.valid_observation(row))

    def test_provider_refusal_is_terminal_and_never_invokes_evaluator(self):
        failed = {"status": "infrastructure_failure", "usage": None, "process": {"wall_ns": 13}}
        with tempfile.TemporaryDirectory() as td, patch.object(study, "request", return_value=failed) as request, \
                patch.object(study.evaluator, "build") as build:
            row = self.run_cell(td)
        self.assertEqual(request.call_count, 1); build.assert_not_called()
        self.assertEqual(row["status"], "provider_or_transport_blocked")
        self.assertIsNone(row["correct"]); self.assertIsNone(row["conservative_tokens"])
        self.assertEqual(row["repair_rounds"], 0)

    def test_one_public_repair_and_no_hidden_feedback(self):
        rejected = {"status": "response_rejected", "native_built": False, "error": "bad public signature"}
        accepted = {"status": "compiled", "native_built": True}
        with tempfile.TemporaryDirectory() as td, patch.object(study, "request", side_effect=[self.response("first"), self.response("second")]) as request, \
                patch.object(study.evaluator, "build", side_effect=[rejected, accepted]), \
                patch.object(study.evaluator, "execute", side_effect=[self.observed(), self.observed(False)]):
            row = self.run_cell(td)
            retained = request.call_args_list[1].args[0]
        self.assertEqual(row["status"], "hidden_validation_failed")
        self.assertEqual(row["repair_rounds"], 1); self.assertEqual(request.call_count, 2)
        self.assertIn("bad public signature", str(retained))
        self.assertNotIn("hidden_expected", str(retained))
        self.assertTrue(study.valid_observation(row))

    def test_native_artifact_drift_invalidates_instead_of_scoring_a_wrong_answer(self):
        with tempfile.TemporaryDirectory() as td, patch.object(study, "request", return_value=self.response()), \
                patch.object(study.evaluator, "build", return_value={"status": "compiled", "native_built": True}), \
                patch.object(study.evaluator, "execute", return_value=self.observed(unchanged=False)):
            row = self.run_cell(td)
        self.assertEqual(row["status"], "native_infrastructure_failure")
        self.assertIsNone(row["correct"])
        self.assertFalse(study.valid_observation(row))

    def test_observed_over_budget_keeps_usage_and_does_not_score(self):
        response = self.response(); response["usage"]["input_tokens"] = 20001
        response["conservative_tokens"] = study.conservative_tokens(response["usage"])
        with tempfile.TemporaryDirectory() as td, patch.object(study, "request", return_value=response), \
                patch.object(study.evaluator, "build") as build:
            row = self.run_cell(td)
        build.assert_not_called()
        self.assertEqual(row["status"], "reported_token_budget_exceeded")
        self.assertEqual(row["conservative_tokens"], 20009)
        self.assertIsNone(row["correct"])


if __name__ == "__main__":
    unittest.main()
