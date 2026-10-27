"""Check that both Hepta C/Clang entry points share bounded capture.

These tests execute real Clang preprocessing and mock quota refusals; they do
not require rustc, native backend execution or any untrusted project input.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected
from hepta.c_migrate import MigrationRejected, _run
from hepta.c_project import invoke


class ClangCaptureIntegration(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang"), "Actual Clang executable required")
    def test_single_tu_and_project_use_real_bounded_preprocessing(self):
        compiler = shutil.which("clang")
        code = "#define ANSWER 12\nint value=ANSWER;\n"
        first = _run([compiler, "-std=c11", "-x", "c", "-E", "-"], input_text=code)
        with tempfile.TemporaryDirectory() as root:
            second = invoke([compiler, "-std=c11", "-x", "c", "-E", "-"],
                            Path(root), stdin=code)
        self.assertIn("int value=12;", first)
        self.assertEqual(first, second)

    def test_single_tu_output_budget_is_a_migration_rejection(self):
        with patch("hepta.c_migrate.run_bounded", side_effect=CaptureRejected(
                "E_CAPTURE_OUTPUT_SIZE", "fake Clang stdout exceeded budget")):
            with self.assertRaises(MigrationRejected) as rejected:
                _run(["clang", "--version"])
        self.assertEqual(rejected.exception.code, "E_CLANG_SIZE")

    def test_project_output_budget_is_a_migration_rejection(self):
        with patch("hepta.c_project.run_bounded", side_effect=CaptureRejected(
                "E_CAPTURE_OUTPUT_SIZE", "fake Clang stdout exceeded budget")):
            with self.assertRaises(MigrationRejected) as rejected:
                invoke(["clang", "--version"], Path("."))
        self.assertEqual(rejected.exception.code, "E_C_BUILD_SIZE")

    def test_timeout_does_not_become_frontend_success(self):
        with patch("hepta.c_migrate.run_bounded", side_effect=CaptureRejected(
                "E_CAPTURE_TIMEOUT", "fake Clang exceeded wall time")):
            with self.assertRaises(MigrationRejected) as rejected:
                _run(["clang", "--version"])
        self.assertEqual(rejected.exception.code, "E_CLANG_ENV")
        with patch("hepta.c_project.run_bounded", side_effect=CaptureRejected(
                "E_CAPTURE_TIMEOUT", "fake Clang exceeded wall time")):
            with self.assertRaises(MigrationRejected) as rejected:
                invoke(["clang", "--version"], Path("."))
        self.assertEqual(rejected.exception.code, "E_C_BUILD_TOOL")


if __name__ == "__main__":
    unittest.main()
