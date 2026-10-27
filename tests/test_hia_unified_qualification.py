"""Qualification summaries must preserve failures and reject incomplete runs."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected
from tools.qualify_hia_unified import (_command, cargo_test_outcome, main,
                                      qualification_plan, qualify, unittest_outcome)


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

    def test_cargo_requires_nonempty_complete_zero_skip_test_execution(self):
        successful = ("running 2 tests\ntest positive ... ok\ntest negative ... ok\n"
                      "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; "
                      "0 filtered out; finished in 0.01s\n\n")
        empty_binary = ("running 0 tests\n"
                        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
                        "0 filtered out; finished in 0.00s\n")
        result = cargo_test_outcome(successful + empty_binary, 0)
        self.assertTrue(result["passed"])
        self.assertEqual(result["tests_run"], 2)
        self.assertEqual(result["test_binaries"], 2)
        for output, code in [
            ("", 0), (empty_binary, 0), (successful, 1),
            (successful.replace("0 ignored", "1 ignored"), 0),
            (successful.replace("0 filtered out", "1 filtered out"), 0),
            (successful.replace("0 measured", "1 measured"), 0),
            (successful.replace("ok. 2 passed; 0 failed", "FAILED. 1 passed; 1 failed"), 1),
            (successful + "running 3 tests\n", 0),
        ]:
            with self.subTest(output=output, code=code):
                self.assertFalse(cargo_test_outcome(output, code)["passed"])

    def test_candidate_executes_merged_paths_and_never_credits_missing_native_reports(self):
        selected = dict(clang="/tools/clang", rustc="/tools/rustc", cargo="/tools/cargo",
                        qemu_aarch64="/tools/qemu-aarch64", qemu_riscv64="/tools/qemu-riscv64",
                        qemu_system_arm="/tools/qemu-system-arm", linker="/tools/ld.lld",
                        lean="/tools/lean", cxx="/tools/g++")
        invocations = []

        def completed(argv, timeout=1800):
            argv = list(map(str, argv))
            invocations.append(argv)
            stdout, stderr = "", ""
            if "rev-parse" in argv:
                stdout = "a" * 40 + "\n"
            elif argv[0] == selected["cargo"]:
                stdout = ("test result: ok. 3 passed; 0 failed; 0 ignored; "
                          "0 measured; 0 filtered out; finished in 0.01s\n")
            elif "unittest" in argv:
                stderr = "Ran 2 tests in 0.010s\n\nOK\n"
            elif "tools/qualify_task_io.py" in argv:
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"ok": True, "status": "passed"}))
            return dict(argv=argv, returncode=0, stdout=stdout, stderr=stderr, seconds=0.01)

        # These are collector protocol controls, not native qualification.
        # A zero exit from a process cannot substitute for its missing report.
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {"CARGO_NET_OFFLINE": "original", "PYTHONDONTWRITEBYTECODE": "old"}), \
                patch("tools.qualify_hia_unified.snapshot", return_value={"sha256": "source"}), \
                patch("tools.qualify_hia_unified.compiler_hash", return_value="compiler"), \
                patch("tools.qualify_hia_unified._command", side_effect=completed), redirect_stdout(io.StringIO()):
            before = dict(os.environ)
            output = Path(directory) / "candidate"
            plan = qualification_plan(output, python="python", **selected)
            report = qualify(output, **selected)
            self.assertEqual(dict(os.environ), before)
        gates = {row["name"]: row for row in report["gates"]}
        self.assertEqual(len(gates), len(plan))
        self.assertEqual(report["completed_gates"], len(plan))
        self.assertEqual(len(invocations), len(plan) + 2)
        self.assertTrue(gates["rust_shadow_cargo"]["passed"])
        self.assertTrue(gates["rust_shadow_parity"]["passed"])
        for name in ("cpp_composed_implementation_llvm", "llvm_local_stored_views", "task_io_composition"):
            self.assertFalse(gates[name]["passed"])
            self.assertEqual(gates[name]["returncode"], 0)
        self.assertIn("evidence_error", gates["task_io_composition"])
        self.assertFalse(report["ok"])
        self.assertFalse(report["full_seven_deliverables_complete"])


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
            cargo=tools + "rust-1.90.0/bin/cargo",
            qemu_aarch64=tools + "qemu-8.2.2/qemu-aarch64-static",
            qemu_riscv64="/usr/bin/qemu-riscv64",
            qemu_system_arm="/usr/bin/qemu-system-arm",
            linker=tools + "rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
            lean=tools + "lean-4.19.0/bin/lean", cxx="/usr/bin/g++")

        # The unified v7 candidate adds an independently executed RV64 gate.
        # Keep its required emulator argument when integrating older workflow
        # improvements; successful shell parsing alone cannot catch this.
        self.assertIn("qemu-user", workflow)
        index = argv.index("--qemu-riscv64")
        missing_riscv = argv[:index] + argv[index + 2:]
        diagnostics = io.StringIO()
        with patch("sys.argv", missing_riscv), \
                patch("tools.qualify_hia_unified.qualify") as qualify, redirect_stderr(diagnostics):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--qemu-riscv64", diagnostics.getvalue())
        qualify.assert_not_called()

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
