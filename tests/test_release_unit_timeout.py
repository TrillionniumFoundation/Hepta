"""Explicit release unit budgets retain every gate and its acceptance policy."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import release_check as release
from tests.test_hia_unified_workflow_cli import WORKFLOW, workflow_argv


class ReleaseUnitTimeoutTests(unittest.TestCase):
    def collect(self, options=(), *, real_unit=False, timeout_unit=False):
        calls = []
        actual_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="hepta-release-budget-") as directory:
            root = Path(directory)
            output = root / "evidence/candidate"
            (root / "tests").mkdir()
            (root / "tests/test_probe.py").write_text(
                "import unittest\n"
                "class Probe(unittest.TestCase):\n"
                "    def test_real_process(self):\n"
                "        self.assertEqual(2 + 3, 5)\n", encoding="utf-8")

            def run(argv, **kwargs):
                if argv[:2] == ["git", "rev-parse"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="budget-test-fixture\n", stderr="")
                calls.append((argv, kwargs))
                if argv[1:4] == ["-m", "unittest", "discover"]:
                    if timeout_unit:
                        raise subprocess.TimeoutExpired(argv, kwargs["timeout"],
                                                        output=b"partial stdout", stderr=b"partial stderr")
                    if real_unit:
                        return actual_run(argv, **kwargs)
                # All non-unit qualification is deliberately unqualified here.
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="budget-only fixture\n")

            args = ["--output-directory", str(output), *options]
            with patch.object(release, "ROOT", root), \
                    patch.object(release.subprocess, "run", side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = release.main(args)
            report = json.loads((output / "release-validation.json").read_text())
            unit_log = (output / "unit_and_integration.log").read_text()
            self.assertEqual(code, 1)  # This test never qualifies the release.
            self.assertEqual(report["status"], "failed")
        return report, calls, unit_log

    def test_default_and_explicit_budget_execute_real_unittest_discovery(self):
        for options, expected in (([], 600), (["--unit-timeout-seconds", "3600"], 3600)):
            with self.subTest(options=options):
                report, calls, log = self.collect(options, real_unit=True)
                self.assertEqual(report["unit_timeout_seconds"], expected)
                self.assertEqual(calls[0][0], [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
                self.assertEqual(calls[0][1]["timeout"], expected)
                gate = report["gates"][0]
                self.assertEqual(gate["timeout_seconds"], expected)
                self.assertEqual(gate["status"], "passed")
                self.assertEqual(gate["test_count"], 1)
                self.assertEqual(gate["skipped"], 0)
                self.assertIn("test_real_process", log)
                self.assertEqual(len(report["gates"]), 2)

    def test_explicit_boundaries_only_change_unit_gate_timeout(self):
        baseline, baseline_calls, _ = self.collect(["--continue-on-failure"])
        self.assertEqual(len(baseline_calls), len(baseline["planned_gates"]))
        self.assertGreater(len(baseline_calls), 40)
        original = {gate["name"]: gate["timeout_seconds"] for gate in baseline["gates"]}
        self.assertEqual(original["unit_and_integration"], 600)
        for selected in (1, 3600):
            with self.subTest(selected=selected):
                report, calls, _ = self.collect([
                    "--continue-on-failure", "--unit-timeout-seconds", str(selected)])
                self.assertEqual(report["planned_gates"], baseline["planned_gates"])
                self.assertEqual(len(calls), len(baseline_calls))
                for gate, (_, kwargs) in zip(report["gates"], calls):
                    expected = selected if gate["name"] == "unit_and_integration" else original[gate["name"]]
                    self.assertEqual(kwargs["timeout"], expected)
                    self.assertEqual(gate["timeout_seconds"], expected)

    def test_invalid_cli_budget_rejects_before_writing_or_running(self):
        for value in ("0", "-1", "3601", "600.0", "true", "false", ""):
            with self.subTest(value=value), tempfile.TemporaryDirectory(prefix="hepta-release-invalid-") as directory:
                output = Path(directory) / "absent"
                with patch.object(Path, "mkdir") as mkdir, \
                        patch.object(release, "snapshot") as snapshot, \
                        patch.object(release.subprocess, "run") as run, \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as rejected:
                        release.main(["--output-directory", str(output), "--unit-timeout-seconds", value])
                self.assertEqual(rejected.exception.code, 2)
                mkdir.assert_not_called()
                snapshot.assert_not_called()
                run.assert_not_called()
                self.assertFalse(output.exists())

    def test_timeout_receipt_retains_selected_budget_and_partial_output(self):
        report, calls, log = self.collect(["--unit-timeout-seconds", "3600"], timeout_unit=True)
        self.assertEqual(len(calls), 1)
        gate = report["gates"][0]
        self.assertEqual(gate["status"], "unknown_timeout")
        self.assertEqual(gate["timeout_seconds"], 3600)
        self.assertEqual(set(gate["partial_output"]), {"stdout", "stderr"})
        self.assertIn("partial stdout", log)
        self.assertIn("partial stderr", log)

    def test_workflow_declares_both_unit_budgets_and_complete_gate_collection(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        marker = "      - name: Run all current native and experiment qualification gates\n"
        self.assertEqual(text.count(marker), 1)
        step = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
        self.assertEqual(step.count("        run: >-\n"), 1)
        body = step.split("        run: >-\n", 1)[1]
        tokens = shlex.split(" ".join(line.strip() for line in body.splitlines()))
        self.assertEqual(tokens[:2], ["python", "tools/release_check.py"])
        args = tokens[2:]
        self.assertEqual(args[args.index("--output-directory") + 1], "artifacts/candidate")
        # collect() owns only the isolated output location; use every other
        # option from the actual workflow to drive the real main/parser loop.
        output_index = args.index("--output-directory")
        options = args[:output_index] + args[output_index + 2:]
        report, calls, _ = self.collect(options)
        self.assertEqual(report["unit_timeout_seconds"], 3600)
        self.assertEqual(calls[0][1]["timeout"], 3600)
        self.assertTrue(report["continue_on_failure"])
        self.assertEqual(len(report["gates"]), len(report["planned_gates"]))
        unified = workflow_argv(text, "/unexecuted/workflow-checkout")
        self.assertEqual(unified[unified.index("--unit-timeout-seconds") + 1], "3600")
        self.assertEqual([line for line in text.splitlines() if line.startswith("    timeout-minutes:")],
                         ["    timeout-minutes: 180"])


if __name__ == "__main__":
    unittest.main()
