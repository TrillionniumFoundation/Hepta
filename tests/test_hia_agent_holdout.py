"""Ensure the matched pilot's withheld input inventory cannot alter prompts."""
import unittest

from tools import qualify_hia_agent_holdout as q
from tools import qualify_hia_batch_study as batch
from tools.qualify_hia_edit_study import ARMS


class AgentWithheldInputsTests(unittest.TestCase):
    def test_withheld_cases_are_reproducible_and_absent_from_every_prompt(self):
        original = batch.fixtures()
        augmented = q.tasks()
        self.assertEqual(augmented, q.tasks())
        for before, after in zip(original, augmented):
            self.assertEqual(len(after["cases"]), len(before["cases"]) + 64)
            self.assertEqual(after["cases"][:len(before["cases"])], before["cases"])
            for arm in ARMS:
                self.assertEqual(batch.prompt(before, arm), batch.prompt(after, arm))
            first, second = (part["id"] for part in after["parts"])
            self.assertEqual(after["expected"], [(31 * batch.formula(first, x, y) + batch.formula(second, x, y)) % 2**32
                                                 for x, y in after["cases"]])

    def test_four_frozen_native_control_candidates_remain_valid_in_both_languages(self):
        for task in q.tasks():
            for language in ("hia", "rust"):
                for mask in range(4):
                    candidate = batch.parse_response(task, language + "_edit_query", q.canonical(batch.response_for(task, language, mask)).decode())
                    self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main()
