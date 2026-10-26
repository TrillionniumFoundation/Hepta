"""Qualification summaries must preserve failures and reject incomplete runs."""
import unittest

from tools.qualify_hia_unified import unittest_outcome


class UnifiedQualificationSummaryTests(unittest.TestCase):
    def test_completed_failure_keeps_denominator_and_counts(self):
        result = unittest_outcome(
            "diagnostic\nRan 1723 tests in 495.436s\n\n"
            "FAILED (failures=15, errors=1)\n", 1)
        self.assertEqual(result, {"tests_run": 1723, "skipped": 0,
                                  "failures": 15, "errors": 1, "passed": False})

    def test_only_completed_nonempty_zero_skip_success_passes(self):
        self.assertTrue(unittest_outcome("Ran 7 tests in 1.200s\n\nOK\n", 0)["passed"])
        for text, code in [
            ("Ran 7 tests in 1.200s\n\nOK (skipped=1)\n", 0),
            ("Ran 7 tests in 1.200s\n\nOK\n", 1),
            ("Ran 7 tests in 1.200s\n\nOK\nwrite failure\n", 0),
            ("Ran 7 tests in 1.200s\n", 0),
            ("Ran 0 tests in 0.000s\n\nOK\n", 0),
            ("Ran 7 tests in 1.200s\n\nOK (expected failures=1)\n", 0),
        ]:
            with self.subTest(text=text, code=code):
                self.assertFalse(unittest_outcome(text, code)["passed"])


if __name__ == "__main__":
    unittest.main()
