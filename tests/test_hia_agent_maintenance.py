"""Maintenance contracts, public/hidden separation and independent VM controls."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_agent_maintenance as study


class MaintenanceStudyTests(unittest.TestCase):
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
