"""One new model binding; unchanged tasks, budgets, source gates and costs."""
import copy
import ast
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_agent_toolstudy_v9_20261029 import prompts as old_prompts
from experiments.hia_agent_toolstudy_v9_20261029 import support as old_support
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine as OriginalEngine
from experiments.hia_agent_toolstudy_v11_20261030 import prompts, support
from experiments.hia_agent_toolstudy_v11_20261030.engine import ToolStudyEngine
from tools import qualify_hia_agent_toolstudy_v9 as old_runner
from tools import qualify_hia_agent_toolstudy_v11 as runner
from tools import qualify_hia_agent_tool_capacity_v11 as capacity


class ToolStudyV11Tests(unittest.TestCase):
    def test_all_19_visible_prompts_and_queries_are_unchanged(self):
        count = 0
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                query = support.session_for(task, arm).query()
                self.assertEqual(query, old_support.session_for(task, arm).query())
                text = prompts.prompt(task, arm, query)
                self.assertEqual(text, old_prompts.prompt(task, arm, query))
                self.assertEqual(prompts.messages(text), old_prompts.messages(text))
                count += 1
        self.assertEqual(count, 19)
        self.assertIs(prompts.prompt, old_prompts.prompt)
        self.assertIs(prompts.messages, old_prompts.messages)
        self.assertIs(runner.validation, old_runner.validation)
        self.assertIs(runner.budget, old_runner.budget)
        self.assertIs(ToolStudyEngine.generate, OriginalEngine.generate)

    def test_source_snapshots_do_not_import_reference_answers_into_generation(self):
        self.assertNotIn("import references", inspect.getsource(support))
        self.assertNotIn("import references", inspect.getsource(runner))
        self.assertEqual(support.protocol()["tokenizer_controls"]["independent_cli_calls"], 95)

    def test_model_and_budgets_are_pinned(self):
        new, old = support.protocol(), old_support.protocol()
        for key in ("runtime", "arms", "tasks", "generation", "history", "budget", "rust_conversion_profile",
                    "hidden_seed", "hidden_random_cases_per_task", "decoder", "advantage_gate", "capacity_gate"):
            self.assertEqual(new[key], old[key])
        self.assertEqual(new["model"], support.PINNED_MODEL)
        self.assertFalse(new["model_provenance"]["official_gguf"])
        self.assertFalse(new["model_provenance"]["quantization_reconstruction_verified"])
        self.assertFalse(new["prospective_amendment"]["public_preregistration_claimed"])
        self.assertIn("Do not tune prompts", new["prospective_amendment"]["stop_rule"])

    def test_condition_or_model_mutation_is_refused(self):
        actual = Path.read_text
        target = support.HERE / "PROTOCOL.json"
        for section, key, value in (("generation", "attempts_per_cell", 4), ("model", "revision", "0" * 40),
                                    ("model_template_options", "chat_template_kwargs", {"enable_thinking": True})):
            def changed(path, *args, **kwargs):
                text = actual(path, *args, **kwargs)
                if path == target:
                    item = json.loads(text); item[section][key] = value
                    return json.dumps(item)
                return text
            with self.subTest(section=section), patch.object(Path, "read_text", changed):
                with self.assertRaises(ValueError):
                    support.protocol()

    def test_official_and_quantized_templates_are_explicitly_distinct(self):
        record = prompts.official_template_binding()
        self.assertFalse(record["templates_identical"])
        self.assertNotEqual(record["chat_template_sha256"], record["gguf_chat_template_sha256"])
        self.assertEqual(record["chat_template_kwargs"], {"enable_thinking": False})
        self.assertFalse(record["whole_template_or_tokenizer_equivalence_claimed"])

    def test_plain_template_preserves_visible_contents_and_uses_fixed_suffix(self):
        items = [{"role": "user", "content": "initial"}, {"role": "assistant", "content": '{"edits":[]}'},
                 {"role": "user", "content": "feedback"}]
        original = copy.deepcopy(items)
        rendered = prompts.plain_qwen_template(items)
        self.assertEqual(items, original)
        self.assertEqual(rendered, '<|im_start|>user\ninitial<|im_end|>\n<|im_start|>assistant\n{"edits":[]}<|im_end|>\n'
                         '<|im_start|>user\nfeedback<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n')
        for bad in ([], [{"role": "system", "content": "x"}], [{"role": "user", "content": "x", "tools": []}],
                    [{"role": "user", "content": "x"}, {"role": "assistant", "content": "reason</think>answer"},
                     {"role": "user", "content": "retry"}]):
            with self.assertRaises(ValueError):
                prompts.plain_qwen_template(bad)

    def test_real_template_call_fixes_only_model_option_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = ToolStudyEngine.__new__(ToolStudyEngine)
            engine.output = Path(folder); engine.template_checks = 0
            payload = {"messages": [{"role": "user", "content": "fixed prompt"}]}
            original = copy.deepcopy(payload)
            expected = prompts.plain_qwen_template(payload["messages"])
            with patch.object(OriginalEngine, "request", return_value={"prompt": expected}) as request:
                self.assertEqual(engine.request("/apply-template", payload), {"prompt": expected})
                request.assert_called_once_with("/apply-template", {**payload, "chat_template_kwargs": {"enable_thinking": False}}, 10)
            self.assertEqual(payload, original)
            self.assertTrue(json.loads((Path(folder) / "template-001.json").read_text())["matched"])
            with patch.object(OriginalEngine, "request", return_value={"prompt": "wrong branch"}):
                with self.assertRaisesRegex(ValueError, "OFFICIAL_TEMPLATE_MISMATCH"):
                    engine.request("/apply-template", payload)
            self.assertFalse(json.loads((Path(folder) / "template-002.json").read_text())["matched"])

    def test_no_historical_eligibility_is_accepted(self):
        for version in ("v8", "v9", "v10"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ValueError, "CAPACITY_BINDING"):
                    support.validate_capacity({"schema": "hepta.agent.tool-capacity." + version, "complete": True}, tools={}, model={})
                with self.assertRaisesRegex(ValueError, "QUALIFICATION_BINDING"):
                    support.validate_qualification({"schema": "hepta.agent.real-node-toolstudy." + version, "calibration_eligible": True},
                                                   tools={}, model={}, capacity_sha256="unused")

    def test_v10_task_generation_validation_and_budget_calls_are_unchanged(self):
        # V11's reviewed deviations are runtime identity and failure-cost
        # retention. Check the calls that define the actual task experiment,
        # not byte equality of deliberately repaired finalization code.
        protected = {"validation.evaluate", "evaluator.execute", "engine.generate", "budget.repair_messages",
                     "prompts.prompt", "prompts.messages", "support.session_for", "session.query",
                     "support.validate_capacity", "support.validate_qualification", "range"}
        def calls(text):
            return [ast.dump(node, include_attributes=False) for node in ast.walk(ast.parse(text))
                    if isinstance(node, ast.Call) and ast.unparse(node.func) in protected]
        for baseline, current in (("V10_CAPACITY_SOURCE.py.txt", "qualify_hia_agent_tool_capacity_v11.py"),
                                  ("V10_STUDY_SOURCE.py.txt", "qualify_hia_agent_toolstudy_v11.py")):
            with self.subTest(source=current):
                self.assertEqual(calls((support.HERE / "provenance" / baseline).read_text()),
                                 calls((support.ROOT / "tools" / current).read_text()))

    def test_complete_usage_is_required_even_if_summary_claims_three_successes(self):
        model = support.PINNED_MODEL
        tasks = [task for task, _ in support.cells("calibration")]
        usage = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
        record = {"schema": support.protocol()["schema"], "stage": "calibration",
                  "protocol_sha256": support.file_identity(support.HERE / "PROTOCOL.json")["sha256"],
                  "source_bindings": {"test": "source"}, "prompt_bindings": {}, "model": model, "tools": {},
                  "capacity_sha256": "capacity", "valid_observation": True, "source_unchanged": True,
                  "model_unchanged": True, "tools_unchanged": True, "calibration_eligible": True,
                  "requests": 3, "responses": 3, "unknown_usage_requests": 0,
                  "known_input_tokens": 30, "known_output_tokens": 6, "total_tokens": 36,
                  "cells": [{"task": task["id"], "arm": "rust_node", "correct": True, "hidden_evaluated": True,
                             "status": "correct", "attempts": [{"usage": copy.deepcopy(usage), "actual_generation_requested": True}]}
                            for task in tasks]}
        with patch.object(support, "bindings", return_value={"test": "source"}), patch.object(support, "prompt_bindings", return_value={}):
            self.assertTrue(support.validate_qualification(record, tools={}, model=model, capacity_sha256="capacity")["eligible"])
            for key, bad in (("unknown_usage_requests", 1), ("total_tokens", None), ("responses", 2), ("known_output_tokens", 0)):
                changed = copy.deepcopy(record); changed[key] = bad
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "INCOMPLETE_USAGE"):
                    support.validate_qualification(changed, tools={}, model=model, capacity_sha256="capacity")


if __name__ == "__main__":
    unittest.main()
