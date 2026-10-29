"""Pure mock boundary checks; these never establish native reference success."""
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import qualify_hia_agent_tool_references as control


def observation(**changes):
    return {"status": "correct", "native_executed": True, "artifact_unchanged": True,
            "resource_contract_passed": True, "vm_contract_passed": True, **changes}


def public_result(**changes):
    return {"accepted": True, "status": "correct",
            "build": {"status": "compiled", "native_built": True},
            "public": observation(), **changes}


def task():
    return {"id": "mock", "public_cases": [[1, 2, 3]], "public_expected": [[4, 5]],
            "hidden_cases": [[6, 7, 8]], "hidden_expected": [[9, 10]],
            "correct_rust": {"api.rs": "REFERENCE_PROVIDER", "client.rs": "REFERENCE_CLIENT"}}


class ToolReferenceTests(unittest.TestCase):
    def test_registry_is_the_existing_nineteen_controls(self):
        cells = control.registered_cells()
        self.assertEqual(len(cells), 19)
        self.assertEqual(sum(stage == "calibration" for stage, _, _ in cells), 3)
        self.assertEqual([sum(stage == "main" and arm == name for stage, _, arm in cells)
                          for name in ("hia_full", "hia_node", "rust_full", "rust_node")], [4, 4, 4, 4])

    def test_missing_registered_cell_is_rejected(self):
        original = control.support.cells
        with patch.object(control.support, "cells", side_effect=lambda stage: original(stage)[:-1] if stage == "main" else original(stage)):
            with self.assertRaisesRegex(ValueError, "CELL_REGISTRY"):
                control.registered_cells()

    def evaluate_mock(self, *, arm="rust_node", public=None, hidden=None):
        value = task()
        session = Mock()
        query = {"source_revision": "original", "query_sha256": "captured-query"}
        session.query.return_value = query
        answer = {"edits": [{"node": "original-node", "changes": {"text": "explicit reference"}}]}
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            stack.enter_context(patch.object(control.support, "session_for", return_value=session))
            builder = stack.enter_context(patch.object(control.references, "reference", return_value=answer))
            validate = stack.enter_context(patch.object(control.validation, "evaluate", return_value=public_result() if public is None else public))
            execute = stack.enter_context(patch.object(control.evaluator, "execute", return_value=observation() if hidden is None else hidden))
            # Any accidental subprocess entry would fail, even in a mock test.
            process = stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no native/model/tokenizer process in mock controls")))
            result = control.evaluate_reference(value, arm, Path(tmp) / "case", "unused-clang", "unused-rustc")
            inputs = json.loads((Path(tmp) / "case" / "INPUT.json").read_text())
            process.assert_not_called()
            return result, inputs, value, session, query, answer, builder, validate, execute

    def test_node_reference_is_passed_verbatim_to_existing_validation(self):
        result, inputs, value, session, query, answer, builder, validate, execute = self.evaluate_mock()
        builder.assert_called_once_with(session, query, value)
        self.assertIs(validate.call_args.args[4], query)
        self.assertEqual(validate.call_args.args[5], control.evaluator.canonical(answer).decode())
        self.assertEqual(inputs["reference_response"], answer)
        self.assertEqual(inputs["terminal_hidden_cases_sha256"], control.digest([value["hidden_cases"], value["hidden_expected"]]))
        execute.assert_called_once_with(validate.return_value["build"], value, value["hidden_cases"], value["hidden_expected"])
        self.assertTrue(result["passed"])
        self.assertFalse(result["model_answer"])

    def test_full_reference_is_existing_complete_answer_without_rewriting(self):
        result, inputs, value, _, _, _, builder, validate, execute = self.evaluate_mock(arm="rust_full")
        builder.assert_not_called()
        self.assertEqual(inputs["reference_response"], {"files": value["correct_rust"]})
        self.assertEqual(validate.call_args.args[5], control.evaluator.canonical({"files": value["correct_rust"]}).decode())
        execute.assert_called_once()
        self.assertTrue(result["passed"])

    def test_failed_build_or_public_gate_never_executes_hidden(self):
        cases = [public_result(accepted=False), public_result(status="infrastructure_failure"),
                 public_result(build={"status": "infrastructure_failure", "native_built": True}),
                 public_result(build={"status": "compiled", "native_built": False})]
        for name in ("native_executed", "artifact_unchanged", "resource_contract_passed", "vm_contract_passed"):
            cases.append(public_result(public=observation(**{name: False})))
        for public in cases:
            with self.subTest(public=public):
                result, *_, execute = self.evaluate_mock(public=public)
                execute.assert_not_called()
                self.assertFalse(result["passed"])
                self.assertIsNone(result["terminal_hidden"])

    def test_hidden_failure_or_artifact_drift_cannot_pass(self):
        for hidden in (observation(status="wrong"), observation(artifact_unchanged=False), observation(resource_contract_passed=False)):
            with self.subTest(hidden=hidden):
                result, _, _, _, _, _, _, validate, execute = self.evaluate_mock(hidden=hidden)
                self.assertFalse(result["passed"])
                validate.assert_called_once()
                execute.assert_called_once()

    def run_mock(self, *, row_results=None, source_read=None, tools_read=None):
        cells = [("main", {"id": "mock" + str(index)}, "rust_node") for index in range(19)]
        source, tools = {"bound.py": "source"}, {"clang": {"sha256": "tool"}}
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            stack.enter_context(patch.object(control, "clean_source", return_value=("frozen-mock", source)))
            stack.enter_context(patch.object(control, "source_bindings", side_effect=source_read or (lambda: source)))
            stack.enter_context(patch.object(control, "tool_identities", side_effect=tools_read or (lambda *_: tools)))
            stack.enter_context(patch.object(control, "registered_cells", return_value=cells))
            stack.enter_context(patch.object(control.support, "snapshot"))
            evaluate = stack.enter_context(patch.object(control, "evaluate_reference", side_effect=row_results,
                                                        return_value={"passed": True, "mock_only": True}))
            process = stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no process in wrapper mock controls")))
            with redirect_stdout(io.StringIO()):
                result = control.run(output=Path(tmp) / "output", clang="unused-clang", rustc="unused-rustc")
            retained = json.loads((Path(tmp) / "output" / "REFERENCES.json").read_text())
            self.assertEqual(result, retained)
            process.assert_not_called()
            return result, evaluate

    def test_complete_mock_run_requires_all_nineteen_and_never_claims_qualification(self):
        result, evaluate = self.run_mock()
        self.assertEqual(evaluate.call_count, 19)
        self.assertTrue(result["complete"])
        self.assertEqual(result["passed"], 19)
        self.assertEqual(result["missing_ids"], [])
        self.assertEqual(result["model_requests"], 0)
        self.assertEqual(result["tokenizer_invocations"], 0)
        self.assertEqual(result["agent_successes"], 0)
        self.assertFalse(result["capacity_qualified"])
        self.assertFalse(result["model_qualified"])
        self.assertNotEqual(result["schema"], "hepta.agent.tool-capacity.v8")

    def test_one_failure_retains_all_rows_but_refuses_completion(self):
        rows = [{"passed": True}] * 7 + [{"passed": False, "mock_failure": "resource"}] + [{"passed": True}] * 11
        result, evaluate = self.run_mock(row_results=rows)
        self.assertEqual(evaluate.call_count, 19)
        self.assertEqual(result["passed"], 18)
        self.assertEqual(result["attempted_count"], 19)
        self.assertEqual(result["rows"][7]["mock_failure"], "resource")
        self.assertFalse(result["complete"])

    def test_row_exception_is_retained_and_cannot_be_a_skip(self):
        rows = [{"passed": True}] * 3 + [ValueError("reference rejected")] + [{"passed": True}] * 15
        result, _ = self.run_mock(row_results=rows)
        self.assertEqual(result["attempted_count"], 19)
        self.assertEqual(result["passed"], 18)
        self.assertIn("reference rejected", result["rows"][3]["error"]["message"])
        self.assertFalse(result["complete"])

    def test_source_drift_stops_before_further_native_work_and_lists_missing_rows(self):
        count = 0
        def source_read():
            nonlocal count
            count += 1
            return {"bound.py": "source" if count < 3 else "changed"}
        result, evaluate = self.run_mock(source_read=source_read)
        self.assertEqual(evaluate.call_count, 1)
        self.assertEqual(result["attempted_count"], 1)
        self.assertEqual(len(result["missing_ids"]), 18)
        self.assertFalse(result["source_unchanged"])
        self.assertFalse(result["complete"])

    def test_failed_post_row_identity_read_keeps_actual_row_and_stops(self):
        count = 0
        def tools_read(*_):
            nonlocal count
            count += 1
            if count >= 3:
                raise OSError("compiler file disappeared after evaluation")
            return {"clang": {"sha256": "tool"}}
        result, evaluate = self.run_mock(tools_read=tools_read)
        self.assertEqual(evaluate.call_count, 1)
        self.assertTrue(result["rows"][0]["mock_only"])
        self.assertIn("disappeared", result["rows"][0]["identity_errors"][0]["message"])
        self.assertEqual(result["passed"], 0)
        self.assertEqual(len(result["missing_ids"]), 18)
        self.assertFalse(result["complete"])

    def test_output_inside_checkout_is_rejected_before_work(self):
        with patch.object(control, "clean_source") as source:
            with self.assertRaisesRegex(ValueError, "OUTPUT"):
                control.run(output=control.ROOT / "artifacts" / "forbidden", clang="unused", rustc="unused")
        source.assert_not_called()


if __name__ == "__main__":
    unittest.main()
