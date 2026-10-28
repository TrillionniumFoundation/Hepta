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
from tools.qualify_hia_unified import (IMPORTED_QUALIFICATION_NAMES, _command, cargo_test_outcome, main,
                                      qualification_plan, qualify, unittest_outcome)


SELECTED_TOOLS = dict(clang="/tools/clang", cc="/tools/gcc", rustc="/tools/rustc", cargo="/tools/cargo",
                      qemu_aarch64="/tools/qemu-aarch64", qemu_riscv64="/tools/qemu-riscv64",
                      qemu_system_arm="/tools/qemu-system-arm", linker="/tools/ld.lld",
                      lean="/tools/lean", cxx="/tools/g++")


class UnifiedQualificationSummaryTests(unittest.TestCase):
    def test_interruption_retains_completed_gate_and_final_incomplete_report(self):
        def completed(argv, timeout=1800):
            argv = list(map(str, argv))
            if argv[0] == "interrupt-control":
                raise KeyboardInterrupt("intentional retention control")
            return {"argv": argv, "returncode": 0, "stdout": "a" * 40 + "\n" if "rev-parse" in argv else "",
                    "stderr": "Ran 1 test in 0.010s\n\nOK\n" if argv[0] == "completed-control" else "", "seconds": .01}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate"
            with patch("tools.qualify_hia_unified.qualification_plan", return_value=[
                    ("first", ["completed-control"], None), ("second", ["interrupt-control"], None)]), \
                    patch("tools.qualify_hia_unified.snapshot", return_value={"sha256": "source", "files": {}}), \
                    patch("tools.qualify_hia_unified.compiler_hash", return_value="compiler"), \
                    patch("tools.qualify_hia_unified._command", side_effect=completed), redirect_stdout(io.StringIO()):
                environment = dict(os.environ)
                with self.assertRaises(KeyboardInterrupt):
                    qualify(output, **SELECTED_TOOLS)
                self.assertEqual(dict(os.environ), environment)
            report = json.loads((output / "qualification.json").read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["completed_gates"], 1)
            self.assertEqual(report["passed_gates"], 1)
            self.assertEqual(report["interruption"]["type"], "KeyboardInterrupt")
            self.assertTrue((output / "started.json").is_file())
            self.assertTrue((output / "gate-01.json").is_file())
            self.assertFalse(report["full_seven_deliverables_complete"])

    def test_ignored_uncommitted_implementation_is_not_a_frozen_source(self):
        def completed(argv, timeout=1800):
            argv = list(map(str, argv))
            return {"argv": argv, "returncode": 0, "stdout": "a" * 40 + "\n" if "rev-parse" in argv else "",
                    "stderr": "", "seconds": .01}
        with tempfile.TemporaryDirectory() as temporary, \
                patch("tools.qualify_hia_unified.snapshot", return_value={"sha256": "source", "files": {"hepta/ignored.py": "a" * 64}}), \
                patch("tools.qualify_hia_unified._command", side_effect=completed):
            output = Path(temporary) / "candidate"
            with self.assertRaisesRegex(ValueError, "uncommitted implementation"):
                qualify(output, **SELECTED_TOOLS)
            self.assertFalse(output.exists())

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
        selected = SELECTED_TOOLS.copy()
        invocations = []
        success_flag_only = {
            "tools/qualify_task_io.py", "tools/validate_groups.py", "tools/validate_shared_runtime.py",
            "tools/validate_concurrent_ir.py", "tools/validate_task_tree.py", "tools/validate_io.py",
            "tools/validate_native_host.py", "tools/benchmark_applications.py", "tools/verify_memory.py",
            "tools/verify_formal.py",
        }

        def completed(argv, timeout=1800):
            argv = list(map(str, argv))
            invocations.append(argv)
            if argv[0] != "git":
                for key, value in {
                    "CC": selected["cc"], "HEPTA_LLD": selected["linker"],
                    "HEPTA_LLVM_READOBJ": "/tools/llvm-readobj",
                    "HEPTA_QEMU_AARCH64": selected["qemu_aarch64"],
                    "HEPTA_QEMU_RISCV64": selected["qemu_riscv64"],
                }.items():
                    self.assertEqual(os.environ.get(key), value)
            stdout, stderr = "", ""
            if "rev-parse" in argv:
                stdout = "a" * 40 + "\n"
            elif argv[0] == selected["cargo"]:
                stdout = ("test result: ok. 3 passed; 0 failed; 0 ignored; "
                          "0 measured; 0 filtered out; finished in 0.01s\n")
            elif "unittest" in argv:
                stderr = "Ran 2 tests in 0.010s\n\nOK\n"
            elif any(command in argv for command in success_flag_only):
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
        self.assertEqual(len(invocations), len(plan) + 3)
        self.assertTrue(gates["rust_shadow_cargo"]["passed"])
        self.assertTrue(gates["rust_shadow_parity"]["passed"])
        self.assertTrue(gates["agent_query_semantics"]["passed"])
        for name in IMPORTED_QUALIFICATION_NAMES:
            self.assertFalse(gates[name]["passed"])
            self.assertEqual(gates[name]["returncode"], 0)
        self.assertIn("evidence_error", gates["task_io_composition"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["schema"], "hepta.hia.unified-qualification.v4")
        self.assertFalse(report["full_seven_deliverables_complete"])

    def test_plan_keeps_hosted_denominators_compilers_and_timing_order_explicit(self):
        plan = qualification_plan(Path("/evidence"), python="python", **SELECTED_TOOLS)
        names = [name for name, _, _ in plan]
        self.assertEqual(len(plan), 35)
        self.assertEqual(len(set(names)), 35)
        self.assertEqual(names[-2:], ["application_performance", "standalone_performance"])
        commands = {name: list(map(str, argv)) for name, argv, _ in plan}
        reports = [str(path) for _, _, path in plan if path is not None]
        self.assertEqual(len(reports), len(set(reports)))
        self.assertIn("tests.test_hia_rust_owned_vm", commands["rust_shadow_parity"])
        self.assertIn("tests.test_hia_rust_owned_chain", commands["rust_shadow_parity"])
        self.assertEqual(commands["unit_regression"][1:4], ["tools/qualify_hia_unit.py", "--workers", "2"])
        for module in ("tests.test_hia_edit_query", "tests.test_hia_edit_batch",
                       "tests.test_hia_edit_control_context", "tests.test_hia_edit_batch_identity"):
            self.assertIn(module, commands["agent_query_semantics"])
        for name in ("bounded_concurrency", "shared_runtime", "structured_task_trees", "bounded_async_io"):
            argv = commands[name]
            self.assertEqual(argv[argv.index("--repeats") + 1], "3")
            self.assertEqual(IMPORTED_QUALIFICATION_NAMES[name], name)
        for name, compiler, family in (("native_host_gcc", "/tools/gcc", "gcc"),
                                       ("native_host_clang", "/tools/clang", "clang")):
            argv = commands[name]
            self.assertEqual(argv[argv.index("--cc") + 1], compiler)
            self.assertEqual(argv[argv.index("--cc-family") + 1], family)
            self.assertEqual(argv[argv.index("--expected-system") + 1], "Linux")
            self.assertEqual(argv[argv.index("--expected-machine") + 1], "x86_64")
            self.assertEqual(IMPORTED_QUALIFICATION_NAMES[name], "native_host_abi")
        application = commands["application_performance"]
        for flag, value in (("--trials", "3"), ("--requests", "96"), ("--warmups", "16")):
            self.assertEqual(application[application.index(flag) + 1], value)
        for name in ("cpp_composed_implementation_llvm", "llvm_local_stored_views", "task_io_composition",
                     "shared_runtime", "structured_task_trees", "bounded_async_io",
                     "legacy_executable_core", "application_performance"):
            argv = commands[name]
            self.assertEqual(argv[argv.index("--cc") + 1], "/tools/gcc")
        riscv = commands["standalone_riscv64_qemu"]
        self.assertEqual(riscv[riscv.index("--linker") + 1], SELECTED_TOOLS["linker"])
        self.assertEqual(riscv[riscv.index("--readobj") + 1], "/tools/llvm-readobj")

    def test_imported_success_convention_is_delegated_and_exit_status_still_required(self):
        # This isolates collector control flow, not producer qualification.
        # The preceding test uses the real validators to reject false reports.
        for returncode, rejected in ((0, False), (1, False), (0, True)):
            with self.subTest(returncode=returncode, validator_rejects=rejected), tempfile.TemporaryDirectory() as td:
                output = Path(td) / "candidate"
                evidence = output / "host.json"
                payload = {"status": "passed"}  # Existing hosted convention has no ok field.

                def completed(argv, timeout=1800):
                    argv = list(map(str, argv))
                    result = dict(argv=argv, returncode=0, stdout="", stderr="", seconds=0.01)
                    if "rev-parse" in argv:
                        result["stdout"] = "a" * 40 + "\n"
                    elif argv[0] == "producer-control":
                        evidence.write_text(json.dumps(payload))
                        result["returncode"] = returncode
                    return result

                with patch("tools.qualify_hia_unified.qualification_plan", return_value=[
                        ("native_host_gcc", ["producer-control"], evidence)]), \
                        patch("tools.qualify_hia_unified.snapshot", return_value={"sha256": "source"}), \
                        patch("tools.qualify_hia_unified.compiler_hash", return_value="compiler"), \
                        patch("tools.qualify_hia_unified._command", side_effect=completed), \
                        patch("tools.qualify_hia_unified.require_collected_qualification",
                              side_effect=ValueError("rejected") if rejected else None) as validator, \
                        redirect_stdout(io.StringIO()):
                    report = qualify(output, **SELECTED_TOOLS)
                validator.assert_called_once_with("native_host_abi", payload)
                self.assertIs(report["gates"][0]["passed"], returncode == 0 and not rejected)
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
            "artifacts/hia-unified", clang="/usr/lib/llvm-20/bin/clang", cc="/usr/bin/gcc",
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
