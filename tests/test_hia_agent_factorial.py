"""Scientific authority and source admission boundaries of the fresh study."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from experiments.hia_agent_factorial_v4_20261028 import calibration, evaluator, fixtures
from tools.provider_adapter.llama_cpp_engine import canonical
from tools import qualify_hia_agent_factorial as study


class FactorialStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = fixtures.make_fixtures()

    def test_same_edit_rights_and_closed_filenames_in_every_arm(self):
        for task in self.tasks:
            for language in ("hia", "rust"):
                for arm in (language + "_full", language + "_query"):
                    text = fixtures.prompt(task, arm)
                    for filename in fixtures.EDITABLE[language]:
                        self.assertIn(filename, text)
                    self.assertIn("Only these two files are editable in BOTH", text)
                good = {"files": copy.deepcopy(task["correct_" + language])}
                good["files"]["utility.hia.json" if language == "hia" else "utility.rs"] = {}
                with self.assertRaisesRegex(ValueError, "E_FACTORIAL_FILES"):
                    evaluator.parse_files(task, language, canonical(good).decode())

    def test_unbounded_methods_external_calls_and_arbitrary_rust_types_refused(self):
        task = next(t for t in self.tasks if t["provider"] == "touch")
        for forbidden in ("std::process::abort()", "Vec::with_capacity(3)", "buf.clone()", "core::mem::forget(buf)", "panic!()"):
            files = copy.deepcopy(task["correct_rust"])
            files["api.rs"] = "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { " + forbidden + "; buf }"
            with self.assertRaises(ValueError):
                evaluator.parse_files(task, "rust", canonical({"files": files}).decode())

    def test_hia_owner_cannot_drop_with_a_live_mutable_loan(self):
        task = next(t for t in self.tasks if t["provider"] == "touch")
        files = copy.deepcopy(task["correct_hia"])
        operations = files["api.hia.json"]["blocks"][0]["ops"]
        operations.insert(1, fixtures.op("owner.drop", ["buf"]))
        with self.assertRaises(Exception):
            evaluator.parse_files(task, "hia", canonical({"files": files}).decode())

    def test_hia_query_cannot_add_recursion_or_additional_functions(self):
        task = self.tasks[0]
        files = copy.deepcopy(task["correct_hia"])
        files["api.hia.json"]["blocks"][0]["ops"].insert(0, fixtures.call(task["provider"], ["a", "b"], [("recursive", "u32")]))
        with self.assertRaises(Exception):
            evaluator.parse_files(task, "hia", canonical({"files": files}).decode())

    def test_duplicate_response_keys_are_rejected(self):
        with self.assertRaises(Exception):
            evaluator.parse_files(self.tasks[0], "rust", '{"files":{},"files":{}}')

    def test_profile_exactly_matches_declared_rust_methods(self):
        task = self.tasks[0]
        for language in ("hia", "rust"):
            schema = fixtures.response_schema(language)
            text = canonical(schema).decode()
            for forbidden in ("saturating_add", "bit.xor", "wrapping_add", "owner.drop", "allowed_values"):
                self.assertNotIn(forbidden, text)
        for method in fixtures.RUST_METHODS:
            self.assertIn(method, fixtures.prompt(task, "rust_query"))

    def test_calibration_and_main_are_distinct_and_no_references_enter_prompts(self):
        main_ids = {t["id"] for t in self.tasks}
        self.assertTrue(main_ids.isdisjoint({t["id"] for t in calibration.problems()}))
        for task in self.tasks:
            for arm in study.protocol()["arms"]:
                text = fixtures.prompt(task, arm)
                self.assertNotIn('"hidden_cases"', text)
                self.assertNotIn('"correct_rust"', text)
                self.assertNotIn('"correct_hia"', text)
                self.assertNotIn('"allowed_values"', text)

    def test_missing_costs_or_unqualified_model_cannot_pass(self):
        rows = []
        for task in self.tasks:
            for arm in study.protocol()["arms"]:
                rows.append({"arm": arm, "correct": True, "attempts": [{"request_wall_ns": 1,
                    "usage": {"input_tokens": 2 if arm == "hia_query" else 5, "output_tokens": 2}}]})
        self.assertTrue(study.summarize(rows, {"eligible": True})["descriptive_advantage_gate"])
        self.assertFalse(study.summarize(rows, {"eligible": False})["descriptive_advantage_gate"])
        rows[0]["attempts"][0]["usage"] = None
        self.assertFalse(study.summarize(rows, {"eligible": True})["descriptive_advantage_gate"])
        self.assertIsNone(study.summarize(rows, {"eligible": True})["groups"][rows[0]["arm"]]["total_tokens"])

    def test_unqualified_calibrations_cannot_start_main_cohort(self):
        with tempfile.TemporaryDirectory(prefix="agent-calibration-gate-") as directory:
            paths = []
            for model in study.protocol()["model_selection"]["order"]:
                path = Path(directory) / (model + ".json")
                path.write_text(json.dumps({"stage": "calibration", "model": {"id": model},
                    "prompt_bindings": study.prompt_bindings(), "valid_observation": True,
                    "calibration_eligible": False}))
                paths.append(path)
            with self.assertRaisesRegex(ValueError, "E_FACTORIAL_BASELINE_CAPABILITY_UNQUALIFIED"):
                study._selection(study.protocol()["model_selection"]["order"][-1], paths)


if __name__ == "__main__":
    unittest.main()
