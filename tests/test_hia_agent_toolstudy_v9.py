"""Minimal prospective amendment, unchanged gates, and no old qualification."""
import copy
import json
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch

from experiments.hia_agent_toolstudy_v8_20261029 import prompts as old_prompts
from experiments.hia_agent_toolstudy_v8_20261029 import support as old_support
from experiments.hia_agent_toolstudy_v9_20261029 import prompts, support
from tools import qualify_hia_agent_toolstudy as old_runner
from tools import qualify_hia_agent_toolstudy_v9 as runner
from tools import qualify_hia_agent_tool_capacity as old_capacity
from tools import qualify_hia_agent_tool_capacity_v9 as capacity


OLD_COMMON = "One to sixteen node edits; no whole files or whole functions."
NEW_COMMON = "One to sixteen node edits; every node ID appears at most once. No whole files or whole functions."
OLD_RUST = "Rust replacements are complete expression or type fragments. Preserve unselected syntax;"
NEW_RUST = "For a type node, text is only one allowed type expression; for an expression node, text is only one complete expression. Rust edit spans in the same file must be disjoint: choose a parent expression or its descendants, never both. Preserve unselected syntax;"


class ToolStudyV9Tests(unittest.TestCase):
    def test_every_prompt_diff_is_exactly_the_two_registered_generic_strings(self):
        count = 0
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                query = support.session_for(task, arm).query()
                self.assertEqual(query, old_support.session_for(task, arm).query())
                old = old_prompts.prompt(task, arm, query)
                new = prompts.prompt(task, arm, query)
                language, interface = support.language_interface(arm)
                if interface == "full":
                    self.assertEqual(old, new)
                else:
                    expected = old.replace(OLD_COMMON, NEW_COMMON)
                    if language == "rust":
                        expected = expected.replace(OLD_RUST, NEW_RUST)
                    self.assertEqual(new, expected)
                    self.assertIn("every node ID appears at most once", new)
                other = copy.deepcopy(task)
                for key in other:
                    if key.startswith(("hidden_", "correct_")) or key in {"cases", "expected"}:
                        other[key] = "NEVER_PUBLIC_REFERENCE_SENTINEL"
                self.assertEqual(query, support.session_for(other, arm).query())
                self.assertEqual(new, prompts.prompt(other, arm, query))
                count += 1
        self.assertEqual(count, 19)

    def test_old_prompt_helper_and_retry_history_are_unmodified(self):
        self.assertEqual(inspect.getsource(prompts.messages), inspect.getsource(old_prompts.messages))
        self.assertEqual(inspect.getsource(prompts.plain_qwen_template), inspect.getsource(old_prompts.plain_qwen_template))
        self.assertEqual(inspect.getsource(prompts.render_nodes), inspect.getsource(old_prompts.render_nodes))
        self.assertEqual(prompts.REPAIR, old_prompts.REPAIR)

    def test_model_budgets_tasks_history_and_qualification_gate_unchanged(self):
        new, old = support.protocol(), old_support.protocol()
        for key in ("model", "runtime", "arms", "tasks", "generation", "history", "budget",
                    "rust_conversion_profile", "hidden_seed", "hidden_random_cases_per_task"):
            self.assertEqual(new[key], old[key], key)
        self.assertEqual(new["qualification"]["tasks"], old["qualification"]["tasks"])
        self.assertTrue(new["qualification"]["main_forbidden_without_qualification"])
        self.assertFalse(new["prospective_amendment"]["accepted_programs_or_tool_authority_changed"])
        self.assertIn("do not tune prompts", new["prospective_amendment"]["stop_rule"])

    def test_prospective_protocol_refuses_even_one_changed_budget(self):
        actual = Path.read_text
        target = support.HERE / "PROTOCOL.json"
        def changed(path, *args, **kwargs):
            result = actual(path, *args, **kwargs)
            if path == target:
                value = json.loads(result)
                value["generation"]["attempts_per_cell"] = 4
                return json.dumps(value)
            return result
        with patch.object(Path, "read_text", changed):
            with self.assertRaisesRegex(ValueError, "UNAUTHORIZED_CONDITION_CHANGE"):
                support.protocol()

    def test_no_old_v8_capacity_or_qualification_can_be_inherited(self):
        with self.assertRaisesRegex(ValueError, "CAPACITY_BINDING"):
            support.validate_capacity({"schema": "hepta.agent.tool-capacity.v8", "complete": True}, tools={}, model={})
        with self.assertRaisesRegex(ValueError, "QUALIFICATION_BINDING"):
            support.validate_qualification({"schema": "hepta.agent.real-node-toolstudy.v8", "calibration_eligible": True},
                                           tools={}, model={}, capacity_sha256="unused")

    def test_acceptance_generation_budget_and_reference_implementations_are_shared_unchanged(self):
        self.assertIs(runner.validation, old_runner.validation)
        self.assertIs(runner.budget, old_runner.budget)
        self.assertIs(runner.ToolStudyEngine, old_runner.ToolStudyEngine)
        self.assertIs(capacity.references, old_capacity.references)
        self.assertIs(capacity.validation, old_capacity.validation)
        self.assertIs(capacity.ToolStudyEngine, old_capacity.ToolStudyEngine)

    def test_control_flow_copies_only_change_registered_module_and_schema_bindings(self):
        new = (support.ROOT / "tools/qualify_hia_agent_toolstudy_v9.py").read_text()
        expected = (support.ROOT / "tools/qualify_hia_agent_toolstudy.py").read_text().replace(
            "from experiments.hia_agent_toolstudy_v8_20261029 import budget, prompts, support, validation",
            "from experiments.hia_agent_toolstudy_v8_20261029 import budget, validation\nfrom experiments.hia_agent_toolstudy_v9_20261029 import prompts, support")
        self.assertEqual(new, expected)
        new = (support.ROOT / "tools/qualify_hia_agent_tool_capacity_v9.py").read_text()
        expected = (support.ROOT / "tools/qualify_hia_agent_tool_capacity.py").read_text().replace(
            "from experiments.hia_agent_toolstudy_v8_20261029 import budget, prompts, references, support, validation",
            "from experiments.hia_agent_toolstudy_v8_20261029 import budget, references, validation\nfrom experiments.hia_agent_toolstudy_v9_20261029 import prompts, support").replace(
            "hepta.agent.tool-capacity.v8", "hepta.agent.tool-capacity.v9")
        self.assertEqual(new, expected)


if __name__ == "__main__":
    unittest.main()
