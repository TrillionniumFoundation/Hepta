"""Frozen pilot controls and the safety of its restricted repair interface."""
import copy
import json
import unittest

from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from tools.qualify_hia_agent_pilot import (
    ARMS, expected_values, parse_candidate, reference_response, repaired_hia,
    semantic_template, task_fixtures,
)


class AgentPilotProtocolTests(unittest.TestCase):
    def test_independent_oracles_distinguish_all_four_buggy_programs(self):
        for task in task_fixtures():
            good = [execute_program(repaired_hia(task), "repair", args)["result"] for args in task["cases"]]
            self.assertEqual(good, expected_values(task))
            try:
                bad = [execute_program(task["hia"], "repair", args)["result"] for args in task["cases"]]
            except HIAProgramTrap:
                continue
            self.assertNotEqual(bad, expected_values(task))

    def test_every_arm_can_represent_the_correct_repair(self):
        for task in task_fixtures():
            for arm in ARMS:
                with self.subTest(task=task["id"], arm=arm):
                    candidate = parse_candidate(task, arm, reference_response(task, arm))
                    if arm.startswith("hia"):
                        self.assertEqual(candidate.as_dict(), repaired_hia(task))
                    else:
                        self.assertEqual(candidate, task["rust_template"].replace("@SLOT@", task["rust_good"]))

    def test_stale_structured_edits_are_rejected_for_both_languages(self):
        task = task_fixtures()[0]
        for arm in ("hia_semantic_patch", "rust_semantic_expression"):
            edit = semantic_template(task, arm, True)
            edit["expected_sha256"] = "0" * 64
            with self.subTest(arm=arm), self.assertRaises(ValueError):
                parse_candidate(task, arm, json.dumps(edit))

    def test_no_arbitrary_rust_statements_or_hia_context_changes(self):
        task = task_fixtures()[0]
        with self.assertRaises(ValueError):
            parse_candidate(task, "rust_full_function", "fn repair(i:u32,n:u32)->u32{std::process::exit(1)}")
        altered = repaired_hia(task)
        altered["module"] = "unrelated"
        with self.assertRaises(ValueError):
            parse_candidate(task, "hia_full_json", json.dumps(altered))
        edited = semantic_template(task, "rust_semantic_expression", True)
        edited["replacement"] = "std::process::exit(1)"
        with self.assertRaises(ValueError):
            parse_candidate(task, "rust_semantic_expression", json.dumps(edited))

    def test_duplicate_rust_edit_keys_reject(self):
        task = task_fixtures()[0]
        good = reference_response(task, "rust_semantic_expression")
        forged = '{"schema":"ignored",' + good[1:]
        with self.assertRaises(ValueError):
            parse_candidate(task, "rust_semantic_expression", forged)


if __name__ == "__main__":
    unittest.main()
