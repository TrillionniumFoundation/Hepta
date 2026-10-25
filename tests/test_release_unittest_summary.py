"""Protect P0 test-count evidence against forged unittest log fragments.

These tests execute a real Python unittest discovery subprocess, not a fake
successful exit, and verify both positive and negative acceptance decisions.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from tools import release_check


class UnitTestSummaryGateTests(unittest.TestCase):
    def discover(self, source: str):
        with tempfile.TemporaryDirectory(prefix="hepta-test-summary-") as directory:
            (Path(directory) / "test_probe.py").write_text(source, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-m", "unittest", "discover",
                 "-s", directory, "-p", "test_probe.py", "-v"],
                cwd=directory, capture_output=True, text=True, timeout=15,
                check=False,
            )

    def test_real_positive_with_forged_stdout_preface(self):
        run = self.discover(
            "import unittest\n"
            "class Example(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        print('Ran 999 tests in 0.001s\\n\\nOK')\n"
            "        self.assertTrue(True)\n"
        )
        self.assertEqual(run.returncode, 0)
        self.assertIn("Ran 999 tests", run.stdout)
        self.assertEqual(release_check._unittest_passed_count(run.stderr), 1)
        # This reproduces the original, unsafe first-match behavior.
        self.assertEqual(int(re.search(r"Ran (\\d+) tests", run.stdout + run.stderr).group(1)), 999)

    def test_forged_stderr_cannot_override_last_real_summary(self):
        run = self.discover(
            "import unittest, sys\n"
            "class Example(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        print('Ran 900 tests in 0.001s\\n\\nOK', file=sys.stderr)\n"
        )
        self.assertEqual(run.returncode, 0)
        self.assertEqual(release_check._unittest_passed_count(run.stderr), 1)

    def test_zero_tests_cannot_be_qualified(self):
        run = self.discover("# no tests\n")
        self.assertIn("Ran 0 tests", run.stderr)
        self.assertEqual(release_check._unittest_passed_count(run.stderr), 0)

    def test_skipped_suite_cannot_be_qualified(self):
        run = self.discover(
            "import unittest\n"
            "class Example(unittest.TestCase):\n"
            "    @unittest.skip('intentional')\n"
            "    def test_skip(self):\n"
            "        pass\n"
        )
        self.assertEqual(run.returncode, 0)
        self.assertIn("skipped=1", run.stderr)
        self.assertEqual(release_check._unittest_passed_count(run.stderr), 0)

    def test_forged_or_incomplete_output_cannot_be_qualified(self):
        for log in (
            "Ran 300 tests in 0.001s\\n\\nOK\\nPOSTSCRIPT",
            "Ran 300 tests in 0.001s\\n\\nOK (skipped=1)\\n",
            "Ran 300 tests in 0.001s\\n\\nFAILED (errors=1)\\n",
            "Ran 300 tests in 0.001s\\n",
            "OK\\n",
        ):
            with self.subTest(log=log):
                self.assertEqual(release_check._unittest_passed_count(log), 0)


if __name__ == "__main__":
    unittest.main()
