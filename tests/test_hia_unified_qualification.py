"""Qualification summaries must preserve failures and reject incomplete runs."""
from contextlib import redirect_stderr
import io
from pathlib import Path
import shutil
import subprocess
import textwrap
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected
from tools.qualify_hia_unified import _command, main, unittest_outcome


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


class UnifiedQualificationWorkflowTests(unittest.TestCase):
    def test_workflow_shell_passes_all_required_cli_arguments_before_any_execution(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/hepta-qualification.yml").read_text()
        marker = "      - name: Qualify the standalone HIA interpreter and direct native paths\n"
        self.assertEqual(workflow.count(marker), 1)
        step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        subprocess.run([bash, "--noprofile", "--norc", "-n"], input=script,
                       text=True, capture_output=True, check=True)
        workspace = "/tmp/hepta workflow workspace"
        # Capture the real shell-expanded command, including paths with spaces.
        # No Python process or qualification tool is executed by this shell.
        capture = subprocess.run(
            [bash, "--noprofile", "--norc", "-c",
             "python() { printf '%s\\0' \"$@\"; }\n" + script],
            env={"GITHUB_WORKSPACE": workspace, "PATH": "/nonexistent"},
            capture_output=True, check=True)
        argv = capture.stdout.decode().rstrip("\0").split("\0")
        self.assertEqual(argv[0], "tools/qualify_hia_unified.py")
        tools = workspace + "/../toolchains/"

        class ParsedWithoutExecution(Exception):
            pass

        with patch("sys.argv", argv), patch("tools.qualify_hia_unified.qualify",
                                             side_effect=ParsedWithoutExecution) as qualify:
            with self.assertRaises(ParsedWithoutExecution):
                main()
        qualify.assert_called_once_with(
            "artifacts/hia-unified", clang="/usr/lib/llvm-20/bin/clang",
            rustc=tools + "rust-1.90.0/bin/rustc",
            qemu_aarch64=tools + "qemu-8.2.2/qemu-aarch64-static",
            qemu_system_arm="/usr/bin/qemu-system-arm",
            linker=tools + "rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
            lean=tools + "lean-4.19.0/bin/lean")

        # Reproduce the CI omission against the actual parser: an exported
        # environment variable cannot supply this required command-line flag.
        index = argv.index("--lean")
        missing_lean = argv[:index] + argv[index + 2:]
        diagnostics = io.StringIO()
        with patch("sys.argv", missing_lean), patch("os.environ", {"LEAN": "present"}), \
                patch("tools.qualify_hia_unified.qualify") as qualify, redirect_stderr(diagnostics):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--lean", diagnostics.getvalue())
        qualify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
