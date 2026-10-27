"""The multi-site study needs both fixes and must not score process failures."""
import copy
import unittest

from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from tools.qualify_hia_batch_study import (ARMS, canonical, classify, criteria, fixtures,
                                          parse_response, prompt, response_for)
from tools.qualify_hia_edit_study import summarize, preflight_matches


class AtomicMaintenanceStudyTests(unittest.TestCase):
    def test_preflight_does_not_equate_boolean_or_float_ids_with_integer_sites(self):
        wanted = '{"edits":[{"site":0},{"site":1}]}'
        self.assertTrue(preflight_matches(wanted, wanted))
        for observed in ('{"edits":[{"site":false},{"site":true}]}',
                         '{"edits":[{"site":0.0},{"site":1.0}]}',
                         '{"edits":[],"edits":[{"site":0},{"site":1}]}'):
            self.assertFalse(preflight_matches(observed, wanted))

    def test_two_repairs_are_necessary_and_sufficient_under_independent_oracle(self):
        for task in fixtures():
            for mask in range(4):
                with self.subTest(task=task["id"], mask=mask):
                    candidate = parse_response(task, "hia_edit_query", canonical(response_for(task, "hia", mask)).decode())
                    actual = []
                    for case in task["cases"]:
                        try:
                            actual.append(execute_program(candidate, "entrypoint", case)["result"])
                        except HIAProgramTrap as exc:
                            self.assertEqual(exc.code, "overflow")
                            actual.append("overflow")
                    self.assertEqual(actual == task["expected"], mask == 3)

    def test_prompts_contain_both_contracts_but_no_case_inventory(self):
        for task in fixtures():
            for arm in ARMS:
                text = prompt(task, arm)
                self.assertIn("part_0(", text)
                self.assertIn("part_1(", text)
                self.assertNotIn(canonical(task["cases"]).decode(), text)
                self.assertNotIn(canonical(task["expected"]).decode(), text)

    def test_invalid_batch_sites_types_and_fields_are_not_repaired(self):
        task = fixtures()[3]
        for arm in ("hia_edit_query", "rust_edit_query"):
            response = response_for(task, "hia" if arm.startswith("hia") else "rust", 3)
            for site in (True, 1.0, "0", -1, 2):
                altered = copy.deepcopy(response); altered["edits"][0]["site"] = site
                with self.subTest(site=site, arm=arm), self.assertRaises(ValueError):
                    parse_response(task, arm, canonical(altered).decode())
            with self.assertRaises(ValueError):
                parse_response(task, arm, '```json\n' + canonical(response).decode() + '\n```')
        wrong = response_for(task, "hia", 3)
        wrong["edits"][0]["changes"]["attrs"] = {"value": True}
        with self.assertRaises(ValueError):
            parse_response(task, "hia_edit_query", canonical(wrong).decode())

    def test_timeout_abort_and_loader_error_do_not_count_as_bug_detection(self):
        task = fixtures()[2]
        for code, stdout, stderr in ((-6, "", ""), (127, "", "loader failed"),
                                     (-9, "STUDY_READY\nSTUDY_CALL 0\n", "")):
            result = classify(task, "hia", code, stdout, stderr, 11)
            self.assertFalse(result["native_executed"])
            self.assertEqual(result["status"], "infrastructure_error")

    def test_exact_native_transcript_is_scored_without_accepting_extra_values(self):
        task = fixtures()[0]
        lines = ["STUDY_READY"]
        for i, value in enumerate(task["expected"]):
            lines.extend(["STUDY_CALL " + str(i), "STUDY_VALUE " + str(i) + " " + str(value)])
        lines.append("STUDY_DONE")
        self.assertTrue(classify(task, "hia", 0, "\n".join(lines), "", None)["ok"])
        self.assertFalse(classify(task, "hia", 0, "\n".join(lines + ["STUDY_VALUE 99 0"]), "", None)["native_executed"])

    def test_denominator_is_four_and_incomplete_study_cannot_claim_benefit(self):
        summary = summarize([], planned_tasks=4)
        self.assertTrue(all(value["planned_tasks"] == 4 for value in summary.values()))
        for value in summary.values():
            value.update(successes=4, input_tokens=10, output_tokens=2)
        summary["hia_full_context"]["input_tokens"] = 20
        self.assertEqual(criteria(summary, False), {"primary": False, "secondary": False})
        self.assertEqual(criteria(summary, True), {"primary": True, "secondary": True})


if __name__ == "__main__":
    unittest.main()
