"""Maintenance contracts, public/hidden separation and independent VM controls."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_agent_maintenance as study


class MaintenanceStudyTests(unittest.TestCase):
    def accounted_rows(self):
        """Synthetic receipt fixtures for the readout gate, never model results."""
        rows = []
        for model in study.protocol()["models"]:
            for task in study.TASKS:
                for language in ("hia", "rust"):
                    factor = 1 if language == "hia" else 2
                    usage = {"input_tokens": 10 * factor, "cached_input_tokens": 2 * factor,
                             "cache_write_input_tokens": 0, "output_tokens": 3 * factor,
                             "reasoning_output_tokens": 2 * factor}
                    request = {"index": 0, "usage": usage, "observed_usage": deepcopy(usage),
                               "unknown_usage": False, "actual_generation_observed": True,
                               "charged_tokens": 15 * factor,
                               "process": {"status": "exited", "cleanup_confirmed": True,
                                           "leader_reaped": True, "wall_ns": 5 * factor}}
                    rows.append({"model": model, "task": task["id"], "language": language,
                                 "correct": True, "complete_usage": True, "hidden_evaluated": True,
                                 "status": "correct", "human_answer_repairs": 0,
                                 "requests": [request], "charged_tokens": 15 * factor,
                                 "tool_calls": [{"name": "final", "public": {"accepted": True}}],
                                 "public_failed_checks": 0, "wall_ns": 50 * factor})
        return rows

    def test_exact_distinct_registered_tasks_are_required_for_each_model_and_language(self):
        good = self.accounted_rows()
        result = study.summary(good)
        self.assertTrue(result["exact_coverage"])
        self.assertTrue(result["eligible_comparison"])
        self.assertTrue(all(group["descriptive_hia_advantage_gate"]
                            for group in result["by_requested_model"].values()))
        duplicated = deepcopy(good)
        for row in duplicated:
            row["task"] = study.TASKS[0]["id"]
        unknown = deepcopy(good)
        unknown[0]["task"] = "unregistered-upgrade"
        other_model = deepcopy(good)
        other_model[0]["model"] = "unregistered-model"
        for rows in (duplicated, unknown, other_model, good[:-1], good + [good[0]]):
            result = study.summary(rows)
            self.assertFalse(result["exact_coverage"])
            self.assertFalse(result["eligible_comparison"])
            self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                                for group in result["by_requested_model"].values()))

    def test_reported_aggregate_cannot_hide_paid_failed_or_repair_requests(self):
        rows = self.accounted_rows()
        rows[0]["charged_tokens"] = 0
        result = study.summary(rows)
        self.assertFalse(result["eligible_comparison"])
        group = result["by_requested_model"][rows[0]["model"]]["groups"]["hia"]
        self.assertEqual(group["charged_tokens"], 45)
        self.assertIsNone(group["charged_tokens_per_correct_delivery"])
        rows = self.accounted_rows()
        extra = deepcopy(rows[0]["requests"][0]); extra["index"] = 1
        rows[0]["requests"].append(extra)
        rows[0]["charged_tokens"] += 15
        rows[0]["tool_calls"].insert(0, {"name": "check", "public": {"accepted": False}})
        rows[0]["public_failed_checks"] = 1
        result = study.summary(rows)
        self.assertTrue(result["eligible_comparison"])
        group = result["by_requested_model"][rows[0]["model"]]["groups"]["hia"]
        self.assertEqual(group["charged_tokens"], 60)
        self.assertEqual(group["charged_tokens_per_correct_delivery"], 20)

    def test_failed_task_costs_remain_in_per_success_numerator_and_zero_is_unavailable(self):
        rows = self.accounted_rows()
        model = rows[0]["model"]
        selected = [row for row in rows if row["model"] == model and row["language"] == "hia"]
        for row in selected[1:]:
            row.update(correct=False, status="hidden_failed")
        result = study.summary(rows)
        self.assertTrue(result["eligible_comparison"])
        group = result["by_requested_model"][model]["groups"]["hia"]
        self.assertEqual(group["correct"], 1)
        self.assertEqual(group["charged_tokens_per_correct_delivery"], 45)
        self.assertEqual(group["cell_wall_ns_per_correct_delivery"], 150)
        selected[0].update(correct=False, status="hidden_failed")
        group = study.summary(rows)["by_requested_model"][model]["groups"]["hia"]
        self.assertEqual(group["charged_tokens"], 45)
        self.assertEqual(group["correct"], 0)
        self.assertIsNone(group["charged_tokens_per_correct_delivery"])
        self.assertIsNone(group["cell_wall_ns_per_correct_delivery"])
        self.assertFalse(group["per_success_cost_available"])

    def test_inconsistent_request_usage_success_or_cleanup_blocks_readout(self):
        cases = []
        for key, value in (("charged_tokens", 0), ("unknown_usage", True), ("index", True),
                           ("actual_generation_observed", False), ("observed_usage", None)):
            rows = self.accounted_rows(); rows[0]["requests"][0][key] = value; cases.append(rows)
        for key, value in (("hidden_evaluated", False), ("public_failed_checks", 3),
                           ("wall_ns", 0), ("correct", 1)):
            rows = self.accounted_rows(); rows[0][key] = value; cases.append(rows)
        rows = self.accounted_rows(); rows[0]["requests"][0]["process"]["cleanup_confirmed"] = False; cases.append(rows)
        rows = self.accounted_rows(); rows[0]["requests"][0]["usage"]["input_tokens"] = True; cases.append(rows)
        for rows in cases:
            result = study.summary(rows)
            self.assertFalse(result["eligible_comparison"])
            self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                                for group in result["by_requested_model"].values()))

    def test_unknown_failure_usage_keeps_known_costs_without_a_full_cost_claim(self):
        rows = self.accounted_rows()
        rows[0]["complete_usage"] = False
        rows[0]["requests"][0]["unknown_usage"] = True
        rows[0]["requests"][0]["usage"] = None
        rows[0].update(status="terminal_runtime_or_protocol_failure", correct=False, hidden_evaluated=False)
        result = study.summary(rows)
        group = result["by_requested_model"][rows[0]["model"]]["groups"]["hia"]
        self.assertEqual(group["charged_tokens"], 45)
        self.assertFalse(result["eligible_comparison"])
        self.assertFalse(result["full_cost_advantage_proved"])
        self.assertFalse(result["human_cost_advantage_proved"])

    def test_boolean_observed_counter_cannot_alias_an_integer_and_understate_cost(self):
        rows = self.accounted_rows()
        request = rows[0]["requests"][0]
        request["usage"].update(input_tokens=1, cached_input_tokens=0)
        request["observed_usage"] = deepcopy(request["usage"])
        request["observed_usage"]["input_tokens"] = True
        request["charged_tokens"] = rows[0]["charged_tokens"] = 6
        self.assertFalse(study._valid_cell_accounting(rows[0], study.protocol()))
        result = study.summary(rows)
        self.assertFalse(result["eligible_comparison"])
        self.assertEqual(result["by_requested_model"][rows[0]["model"]]["groups"]["hia"]["charged_tokens"], 36)
        self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                            for group in result["by_requested_model"].values()))

    def test_inconsistent_valid_usage_retains_maximum_once_and_still_blocks_comparison(self):
        rows = self.accounted_rows()
        request = rows[0]["requests"][0]
        request["observed_usage"]["output_tokens"] += 10
        result = study.summary(rows)
        group = result["by_requested_model"][rows[0]["model"]]["groups"]["hia"]
        self.assertEqual(group["charged_tokens"], 55)  # max(15,25) + 15 + 15, not 70
        self.assertFalse(result["eligible_comparison"])
        self.assertIsNone(group["charged_tokens_per_correct_delivery"])
        self.assertFalse(result["full_cost_advantage_proved"])

    def test_every_author_repair_matches_independent_oracle_and_real_resource_witness(self):
        for task in study.TASKS:
            candidate = study.TASK_MODULE.reference(task["id"], "hia")
            verify_program(candidate)
            for values in study.TASK_MODULE.cases(task) + study.TASK_MODULE.cases(task, hidden=True):
                with self.subTest(task=task["id"], values=values):
                    observation = study.execute_hia_contract(candidate, task, values)
                    self.assertEqual(observation["result"], study.TASK_MODULE.oracle(task["id"], *values))
                    self.assertEqual(observation["resources"]["live_owners"], 0)
                    self.assertEqual(observation["resources"]["live_local_loans"], 0)

    def test_initial_programs_are_valid_and_require_actual_maintenance(self):
        for task in study.TASKS:
            initial = study.TASK_MODULE.initial(task["id"], "hia")
            verify_program(initial)
            changed = []
            for values in task["public"]:
                old = execute_program(initial, "target", values)["result"]
                changed.append(old != study.TASK_MODULE.oracle(task["id"], *values))
            self.assertTrue(any(changed), task["id"])
            self.assertNotEqual(initial, study.TASK_MODULE.reference(task["id"], "hia"))

    def test_public_prompt_contains_initial_code_but_never_reads_reference_or_hidden_cases(self):
        for task in study.TASKS:
            for language in ("hia", "rust"):
                with patch.object(study.TASK_MODULE, "reference", side_effect=AssertionError("private reference read")), \
                     patch.object(study.TASK_MODULE, "cases", side_effect=AssertionError("hidden generator read")):
                    prompt = study.public_prompt(task, language)
                self.assertEqual(prompt["initial_candidate"], study.TASK_MODULE.initial(task["id"], language))
                self.assertEqual([row["args"] for row in prompt["public_cases"]], task["public"])
                self.assertEqual(len(prompt["public_cases"]), 6)
                self.assertNotIn("hidden_cases", prompt)
                self.assertNotIn("reference", prompt)

    def test_hidden_feedback_is_terminal_and_cannot_enter_public_conversation(self):
        with self.assertRaisesRegex(ValueError, "terminal"):
            study.public_feedback({"hidden_evaluated": True, "accepted": False}, "0" * 64)
        result = {"hidden_evaluated": False, "accepted": False, "status": "cases_failed",
                  "private_secret": "not a public key"}
        self.assertNotIn("private_secret", study.public_feedback(result, "0" * 64))

    def test_removed_owner_drop_is_rejected_by_actual_core_verifier(self):
        task = next(t for t in study.TASKS if t["id"] == "buffer_resize")
        candidate = study.TASK_MODULE.reference(task["id"], "hia")
        body = candidate["functions"][0]["blocks"][0]
        body["ops"] = [op for op in body["ops"] if op["op"] != "owner.drop"]
        with self.assertRaises(ValueError):
            verify_program(candidate)

    def test_model_tiers_are_not_pooled_and_unknown_cost_never_claims_advantage(self):
        rows = []
        for model in study.protocol()["models"]:
            for task in study.TASKS:
                for language in ("hia", "rust"):
                    rows.append({"model": model, "task": task["id"], "language": language,
                                 "correct": True, "complete_usage": language == "rust",
                                 "requests": [{}], "charged_tokens": 1 if language == "hia" else 2,
                                 "public_failed_checks": 0, "wall_ns": 1 if language == "hia" else 2})
        result = study.summary(rows)
        self.assertEqual(set(result["by_requested_model"]), {"gpt-6.1-sol", "gpt-6-luna"})
        self.assertFalse(result["cross_model_pooling_used"])
        self.assertIsNone(result["human_review_time_ns"])
        self.assertFalse(result["human_cost_advantage_proved"])
        self.assertFalse(result["full_cost_advantage_proved"])
        self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                            for group in result["by_requested_model"].values()))

    def test_transport_limits_are_inherited_without_mutating_original_protocol(self):
        cfg = study.protocol()
        self.assertEqual(cfg["transport"], {"stdout_limit_bytes": 16777216,
                                          "stderr_limit_bytes": 4194304,
                                          "max_jsonl_line_bytes": 1048576})
        self.assertFalse(cfg["previous_negative_results_replaced"])

    def test_language_order_uses_stable_model_identity_when_iteration_order_reverses(self):
        cfg = study.protocol()
        self.assertEqual([study.language_order(i, "gpt-6.1-sol", cfg)[0] for i in range(3)],
                         ["hia", "rust", "hia"])
        self.assertEqual([study.language_order(i, "gpt-6-luna", cfg)[0] for i in range(3)],
                         ["rust", "hia", "rust"])


if __name__ == "__main__":
    unittest.main()
