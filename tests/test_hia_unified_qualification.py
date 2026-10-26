"""Qualification summaries must preserve failures and reject incomplete runs."""
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected
from tools.qualify_hia_unified import _command, unittest_outcome


class UnifiedQualificationSummaryTests(unittest.TestCase):
    def test_timeout_preserves_bounded_partial_logs_without_a_success_code(self):
        error = CaptureRejected("E_CAPTURE_TIMEOUT", "deadline")
        error.capture = CaptureFailure(("compiler",), -9, b"partial output\n", b"partial error\n", 100, 200)
        with patch("tools.qualify_hia_unified.run_bounded", side_effect=error):
            result = _command(["compiler"])
        self.assertIsNone(result["returncode"])
        self.assertEqual(result["stdout"], "partial output\n")
        self.assertIn("partial error\n", result["stderr"])
        self.assertEqual(result["partial_capture"]["stdout_total_bytes"], 100)
        self.assertFalse(unittest_outcome(result["stderr"], result["returncode"])["passed"])

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
