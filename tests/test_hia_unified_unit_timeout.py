"""Explicit unit-gate budgets must not change the other integrated gates."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, CaptureResult
from tools import qualify_hia_unified as unified


TOOLS = {name: "/missing-hepta-test-tools/" + name for name in (
    "clang", "rustc", "qemu_aarch64", "qemu_riscv64", "qemu_system_arm", "linker", "lean", "cxx")}


class UnifiedUnitTimeoutTests(unittest.TestCase):
    def collect_without_commands(self, unit_timeout_seconds=None):
        calls = []

        def bounded(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == "git":
                return CaptureResult(0, "a" * 40 + "\n" if "rev-parse" in argv else "", "")
            stderr = "Ran 3 tests in 0.001s\n\nOK\n" if argv[1:4] == ["-m", "unittest", "discover"] else ""
            return CaptureResult(0, "", stderr)

        kwargs = {} if unit_timeout_seconds is None else {"unit_timeout_seconds": unit_timeout_seconds}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence"
            with patch.object(unified, "ROOT", root), patch.dict(os.environ), \
                    patch.object(unified, "snapshot", return_value={"sha256": "b" * 64}), \
                    patch.object(unified, "compiler_hash", return_value="c" * 64), \
                    patch.object(unified, "run_bounded", side_effect=bounded), \
                    contextlib.redirect_stdout(io.StringIO()):
                report = unified.qualify(output, **TOOLS, **kwargs)
            plan = json.loads((output / "plan.json").read_text())
            self.assertEqual(json.loads((output / "qualification.json").read_text()), report)
        return report, plan, calls

    def assert_budgets(self, report, plan, calls, unit_timeout):
        self.assertEqual(len(calls), 21)  # two Git identity probes, then every gate
        self.assertEqual([kwargs["timeout"] for _, kwargs in calls[:2]], [10, 10])
        self.assertEqual(len(report["gates"]), 19)
        self.assertEqual(len(plan["commands"]), 19)
        for declared, recorded, (argv, kwargs) in zip(plan["commands"], report["gates"], calls[2:]):
            expected = unit_timeout if declared["name"] == "unit_regression" else 1800
            self.assertEqual(recorded["name"], declared["name"])
            self.assertEqual(declared["timeout_seconds"], expected)
            self.assertEqual(recorded["timeout_seconds"], expected)
            self.assertEqual(kwargs["timeout"], expected)
            self.assertEqual(declared["argv"], argv)
            self.assertEqual(recorded["argv"], argv)
        for _, kwargs in calls:
            self.assertEqual(kwargs["stdin_limit"], 0)
            self.assertEqual(kwargs["stdout_limit"], 4 * 1024 * 1024)
            self.assertEqual(kwargs["stderr_limit"], 8 * 1024 * 1024)
        self.assertEqual(plan["commands"][0]["argv"],
                         [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"])
        self.assertTrue(report["gates"][0]["passed"])
        self.assertEqual(report["gates"][0]["tests_run"], 3)
        self.assertEqual(report["gates"][0]["skipped"], 0)

    def test_default_keeps_all_nineteen_gate_budgets(self):
        self.assert_budgets(*self.collect_without_commands(), 1800)

    def test_explicit_boundary_budgets_change_only_the_unit_gate(self):
        for timeout in (1, 3600):
            with self.subTest(timeout=timeout):
                self.assert_budgets(*self.collect_without_commands(timeout), timeout)

    def test_invalid_api_budget_rejects_before_output_or_any_command(self):
        class IntSubclass(int):
            pass

        for value in (True, False, 0, -1, 3601, 1800.0, "1800", None, [], {}, IntSubclass(1800)):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "must-not-exist"
                with patch.object(unified, "snapshot") as snapshot, \
                        patch.object(unified, "_command") as command, \
                        patch.object(Path, "mkdir") as mkdir:
                    with self.assertRaises(ValueError):
                        unified.qualify(output, **TOOLS, unit_timeout_seconds=value)
                    snapshot.assert_not_called()
                    command.assert_not_called()
                    mkdir.assert_not_called()
                self.assertFalse(output.exists())

    def cli(self, options):
        argv = ["qualify_hia_unified", "--output-directory", "/unused-output"]
        for name, value in TOOLS.items():
            argv.extend(["--" + name.replace("_", "-"), value])
        return patch.object(sys, "argv", argv + options)

    def test_cli_default_and_explicit_budget_reach_the_api(self):
        result = dict(ok=True, status="stub", passed_gates=19, completed_gates=19,
                      unchanged_source=True, full_seven_deliverables_complete=False)
        for options, expected in (([], 1800), (["--unit-timeout-seconds", "3600"], 3600)):
            with self.subTest(options=options), self.cli(options), \
                    patch.object(unified, "qualify", return_value=result) as qualify, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(unified.main(), 0)
                self.assertEqual(qualify.call_args.kwargs["unit_timeout_seconds"], expected)

    def test_invalid_cli_budget_rejects_before_qualification(self):
        for value in ("0", "-1", "3601", "1800.0", "true", "false"):
            with self.subTest(value=value), self.cli(["--unit-timeout-seconds", value]), \
                    patch.object(unified, "qualify") as qualify, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    unified.main()
                self.assertEqual(error.exception.code, 2)
                qualify.assert_not_called()

    def test_capture_failure_records_the_requested_budget_without_passing(self):
        with patch.object(unified, "run_bounded", side_effect=CaptureRejected("E_CAPTURE_TIMEOUT", "deadline")) as bounded:
            result = unified._command(["unit-command"], timeout=3600)
        self.assertEqual(result["timeout_seconds"], 3600)
        self.assertEqual(bounded.call_args.kwargs["timeout"], 3600)
        self.assertIsNone(result["returncode"])
        self.assertFalse(unified.unittest_outcome(result["stderr"], result["returncode"])["passed"])


if __name__ == "__main__":
    unittest.main()
