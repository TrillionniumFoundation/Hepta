"""Meaningful no-model controls for prospective study boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from experiments.hia_agent_factorial_v4_20261028 import calibration
from experiments.hia_agent_toolstudy_v8_20261029 import budget, prompts, support, validation
from experiments.hia_agent_toolstudy_v8_20261029.engine import response_schema
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity
from tools.qualify_hia_agent_toolstudy import summarize


class ToolStudyTests(unittest.TestCase):
    def test_all_nineteen_prompts_ignore_references_and_hidden_fields(self):
        count = 0
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                query = support.session_for(task, arm).query()
                original = prompts.prompt(task, arm, query)
                other = copy.deepcopy(task)
                for key in list(other):
                    if key.startswith(("hidden_", "correct_")) or key in {"cases", "expected"}:
                        other[key] = "SECRET_SENTINEL_NOT_PUBLIC"
                self.assertEqual(original, prompts.prompt(other, arm, query))
                self.assertNotIn("SECRET_SENTINEL_NOT_PUBLIC", original)
                self.assertIn("into", original) if arm.startswith("rust") or arm == "calibration" else None
                count += 1
        self.assertEqual(count, 19)

    def test_node_catalogue_discloses_rust_fields_roles_and_actual_binding_context(self):
        task = calibration.problems()[1]
        query = support.session_for(task, "calibration").query()
        text = prompts.prompt(task, "calibration", query)
        self.assertIn('changes:{"text":"complete replacement fragment"}', text)
        self.assertIn("parameter=a", text)
        self.assertIn("parameter=b", text)
        self.assertIn("Actual parsed interfaces", text)
        self.assertIn(task["original_rust"]["client.rs"], text)

    def test_node_decoder_accepts_only_edits_envelope_without_check_or_golden_ids(self):
        schema = response_schema("rust", "node")
        self.assertEqual(schema, response_schema("hia", "node"))
        self.assertEqual(schema["required"], ["edits"])
        self.assertEqual(schema["properties"]["edits"]["items"]["properties"]["node"], {"type": "string"})
        self.assertNotIn("check", canonical(schema).decode())
        self.assertEqual(response_schema("hia", "full")["required"], ["files"])

    def test_complete_previous_response_is_never_truncated(self):
        text = '{"edits":[{"node":"abc","changes":{"text":"x"}}]}'
        tokenize = lambda value: list(value)
        with self.assertRaisesRegex(budget.BudgetFailure, "PREVIOUS_BUDGET"):
            budget.repair_messages("initial", text, {}, tokenize, {"previous_response_tokens": 2, "feedback_tokens": 1024})
        messages, receipt = budget.repair_messages("initial", text, {"diagnostic": ""}, tokenize,
                                                   {"previous_response_tokens": 1024, "feedback_tokens": 1024})
        self.assertEqual(messages[1]["content"], text)
        self.assertFalse(receipt["previous_code_truncated"])
        self.assertIn("ENTIRE required edit set", messages[2]["content"])

    def test_diagnostic_clipping_preserves_every_public_case_and_resource_flag(self):
        feedback = {"diagnostic": "long diagnostic" * 400, "public_cases": [{"arguments": [3,9,5], "expected": 26}], "resource_ok": False}
        before = copy.deepcopy(feedback)
        messages, receipt = budget.repair_messages("initial", "previous", feedback, lambda value: list(value),
                                                   {"previous_response_tokens": 100, "feedback_tokens": 400})
        self.assertTrue(receipt["feedback"]["diagnostic_clipped"])
        self.assertEqual(receipt["feedback"]["public_cases"], feedback["public_cases"])
        self.assertIs(receipt["feedback"]["resource_ok"], False)
        self.assertEqual(before, feedback)
        self.assertIn("project's original source has NOT changed", messages[2]["content"])

    def test_feedback_overflow_never_drops_cases(self):
        with self.assertRaisesRegex(budget.BudgetFailure, "FEEDBACK_BUDGET"):
            budget.repair_messages("initial", "x", {"diagnostic": "", "public_cases": ["required" * 100]},
                                   lambda value: list(value), {"previous_response_tokens": 100, "feedback_tokens": 300})

    def test_node_wrapper_binds_captured_query_not_fresh_query(self):
        session = Mock()
        captured = {"source_revision": "old", "query_sha256": "oldquery"}
        session.response.return_value = {"captured": True}
        session.apply.return_value = {"accepted": False, "status": "response_rejected", "before_revision": "new", "after_revision": "new"}
        with tempfile.TemporaryDirectory() as tmp:
            validation.evaluate({}, "rust", "node", session, captured, '{"edits":[]}', Path(tmp), "unused", "unused")
        session.response.assert_called_once_with(captured, [])
        session.query.assert_not_called()

    def test_full_failed_compiler_identity_never_executes(self):
        task = calibration.problems()[0]
        session = support.session_for(task, "calibration")
        built = {"status": "infrastructure_failure", "native_built": True,
                 "error": {"message": "compiler changed"}}
        with tempfile.TemporaryDirectory() as tmp, patch.object(validation.evaluator, "build", return_value=built), patch.object(validation.evaluator, "execute") as execute:
            result = validation.evaluate(task, "rust", "full", session, session.query(),
                                         canonical({"files": task["correct_rust"]}).decode(), Path(tmp)/"case", "unused", "unused")
        execute.assert_not_called()
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "infrastructure_failure")

    def test_full_finite_parser_is_enforced_before_build(self):
        task = calibration.problems()[0]
        session = support.session_for(task, "calibration")
        with tempfile.TemporaryDirectory() as tmp, patch.object(validation.rust_syntax, "parse_function", side_effect=ValueError("finite parser rejection")), patch.object(validation.evaluator, "build") as build:
            result = validation.evaluate(task, "rust", "full", session, session.query(), canonical({"files": task["correct_rust"]}).decode(), Path(tmp)/"case", "unused", "unused")
        build.assert_not_called()
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "response_rejected")

    def test_old_qualification_is_not_v8_eligibility(self):
        with self.assertRaisesRegex(ValueError, "QUALIFICATION_BINDING"):
            support.validate_qualification({"schema": "hepta.agent.factorial-primitive-public-repair.v6", "calibration_eligible": True},
                                           tools={}, model={}, capacity_sha256="unused")

    def test_only_companion_runtime_change_invalidates_cross_stage_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("server", "tokenize", "clang", "rustc", "libllama.so"):
                (root / name).write_bytes(name.encode())
            paths = [str(root/name) for name in ("server", "tokenize", "clang", "rustc")]
            tools = support.tool_identities(*paths)
            row = {"passed": True, "reference_passed_all_gates": True, "capacity_passed": True,
                   "template_exact_match": True, "tokenizer_ids_match": True,
                   "complete_reference_output_tokens": 1, "allocated_worst_repair_plus_output_reserve": 1}
            record = {"schema": "hepta.agent.tool-capacity.v8", "source_bindings": support.bindings(),
                      "prompt_bindings": support.prompt_bindings(), "protocol_sha256": file_identity(support.HERE/"PROTOCOL.json")["sha256"],
                      "model": {}, "tools": tools, "rows": [{"id": key, **row} for key in support.prompt_bindings()],
                      "model_requests": 0, "engine_exited": True,
                      "complete": True, "source_unchanged": True, "tools_unchanged": True, "model_unchanged": True}
            support.validate_capacity(record, tools=tools, model={})
            (root / "libllama.so").write_bytes(b"changed companion; main binary unchanged")
            changed = support.tool_identities(*paths)
            self.assertEqual(tools["binary"], changed["binary"])
            with self.assertRaisesRegex(ValueError, "CAPACITY_BINDING"):
                support.validate_capacity(record, tools=changed, model={})

    def test_main_runner_does_not_import_control_references(self):
        path = support.ROOT / "tools/qualify_hia_agent_toolstudy.py"
        text = path.read_text()
        self.assertNotIn("import references", text)
        self.assertNotIn("qualify_hia_agent_tool_capacity", text)
        self.assertNotIn('task["correct_', text)

    def test_budget_failure_keeps_prior_request_cost_and_zero_new_requests(self):
        cell = {"arm": "hia_node", "correct": False, "status": "budget_failure", "cell_wall_ns": 99,
                "attempts": [{"actual_generation_requested": True, "usage": {"input_tokens": 100, "output_tokens": 1536}, "request_wall_ns": 70},
                             {"actual_generation_requested": False, "usage": None, "request_wall_ns": 2}]}
        summary = summarize([cell], None)["groups"]["hia_node"]
        self.assertEqual(summary["requests"], 1)
        self.assertEqual(summary["submissions"], 2)
        self.assertEqual(summary["total_tokens"], 1636)
        self.assertEqual(summary["unknown_usage_requests"], 0)
        self.assertEqual(summary["cell_wall_ns"], 99)


if __name__ == "__main__":
    unittest.main()
