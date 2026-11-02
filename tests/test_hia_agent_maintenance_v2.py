"""Prospective campaign selection and actual authored maintenance semantics."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_agent_maintenance as study


class MaintenanceV2Tests(unittest.TestCase):
    def setUp(self):
        self.previous_campaign = study.CAMPAIGN
        study.select_campaign("maintenance-v2")

    def tearDown(self):
        study.select_campaign(self.previous_campaign)

    def test_separate_eight_cell_registration_keeps_models_and_cost_limits(self):
        cfg = study.protocol()
        self.assertEqual(cfg["campaign"], "maintenance-v2")
        self.assertEqual(cfg["models"], ["gpt-6.1-sol", "gpt-6-luna"])
        self.assertEqual(cfg["tasks"], ["cursor_api_v2", "owned_record_api_v2"])
        self.assertEqual(len(cfg["tasks"]) * len(cfg["models"]) * len(cfg["arms"]), 8)
        self.assertEqual(cfg["max_requests_per_cell"], 6)
        self.assertEqual(cfg["max_public_checks_per_cell"], 3)
        self.assertFalse(cfg["previous_negative_results_replaced"])
        self.assertEqual(study.HERE.name, "hia_agent_maintenance_v2")
        study.select_campaign("maintenance-v1")
        self.assertEqual(study.HERE.name, "hia_agent_maintenance")
        self.assertEqual(study.protocol()["tasks"], ["quota_reserve", "bitfield_revision", "buffer_resize"])
        with self.assertRaisesRegex(ValueError, "unknown source-owned"):
            study.select_campaign("../unregistered")

    def test_author_repairs_execute_all_public_and_hidden_oracles_and_lifetimes(self):
        for task in study.TASKS:
            candidate = study.TASK_MODULE.reference(task["id"], "hia")
            verify_program(candidate)
            for values in study.TASK_MODULE.cases(task) + study.TASK_MODULE.cases(task, hidden=True):
                with self.subTest(task=task["id"], values=values):
                    observed = study.execute_hia_contract(candidate, task, values)
                    self.assertEqual(observed["result"], study.TASK_MODULE.oracle(task["id"], *values))
                    self.assertEqual(observed["resources"]["live_owners"], 0)
                    self.assertEqual(observed["resources"]["live_local_loans"], 0)

    def test_initial_programs_are_legal_but_fail_the_changed_public_contract(self):
        for task in study.TASKS:
            original = study.TASK_MODULE.initial(task["id"], "hia")
            verify_program(original)
            self.assertTrue(any(execute_program(original, "target", pair)["result"]
                                != study.TASK_MODULE.oracle(task["id"], *pair)
                                for pair in task["public"]), task["id"])

    def test_public_prompts_do_not_call_author_reference_or_hidden_case_generator(self):
        for task in study.TASKS:
            for language in ("hia", "rust"):
                with patch.object(study.TASK_MODULE, "reference", side_effect=AssertionError("reference leaked")), \
                     patch.object(study.TASK_MODULE, "cases", side_effect=AssertionError("hidden leaked")):
                    prompt = study.public_prompt(task, language)
                self.assertEqual(prompt["initial_candidate"], study.TASK_MODULE.initial(task["id"], language))
                self.assertEqual(len(prompt["public_cases"]), 6)
                self.assertNotIn("hidden_cases", prompt)
                self.assertNotIn("reference", prompt)
                if study.buffer_task(task):
                    self.assertIn("resource_api", prompt)

    def test_buffer_syntactic_witness_cannot_replace_executed_lifecycle(self):
        task = study.task_for("owned_record_api_v2")
        candidate = study.TASK_MODULE.reference(task["id"], "hia")
        # Missing explicit release is rejected by the real ownership checker.
        ops = candidate["functions"][0]["blocks"][0]["ops"]
        candidate["functions"][0]["blocks"][0]["ops"] = [op for op in ops if op["op"] != "owner.drop"]
        with self.assertRaises(ValueError):
            verify_program(candidate)
        # A scalar implementation with the correct value has no resource witness.
        shortcut = study.TASK_MODULE.program([study.TASK_MODULE.block("entry", ["x", "y"],
            [study.TASK_MODULE.const("answer", study.TASK_MODULE.oracle(task["id"], 0, 0))],
            study.TASK_MODULE.ret("answer"))])
        with self.assertRaisesRegex(ValueError, "actually allocate"):
            study.execute_hia_contract(shortcut, task, [0, 0])

    def test_resource_oracle_validates_new_shape_separately_from_legacy_begin(self):
        task = study.task_for("owned_record_api_v2")
        expected = study.resource_expected(task, (18, 255))
        self.assertEqual(expected, {"length": 20, "index": (18 ^ 255) % 20,
                                    "byte": (18 + 255) % 256, "result": 10240 + 17})
        legacy = study.resource_expected({"id": "buffer_resize"}, (18, 255))
        self.assertEqual(legacy["length"], 19)
        self.assertEqual(legacy["index"], 255 % 19)
        self.assertEqual(legacy["byte"], 18 ^ 255)

    def test_summary_requires_exact_new_cohort_and_retains_unknown_human_cost(self):
        # Reuse receipt-shape author fixtures; these are never model successes.
        from tests.test_hia_agent_maintenance import MaintenanceStudyTests
        rows = MaintenanceStudyTests().accounted_rows()
        good = study.summary(rows)
        self.assertEqual(len(rows), 8)
        self.assertTrue(good["exact_coverage"])
        self.assertTrue(good["eligible_comparison"])
        self.assertIsNone(good["human_review_time_ns"])
        self.assertFalse(good["full_cost_advantage_proved"])
        bad = deepcopy(rows)
        bad[0]["task"] = "buffer_resize"
        self.assertFalse(study.summary(bad)["eligible_comparison"])
        bad = deepcopy(rows)
        bad[0]["requests"][0]["unknown_usage"] = True
        self.assertFalse(study.summary(bad)["eligible_comparison"])


if __name__ == "__main__":
    unittest.main()
