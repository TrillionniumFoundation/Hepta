"""Failed actual-host ABI evidence must retain its rejection trace, never pass."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected, CaptureResult
from tools import validate_native_host as module


CLANG_PROBE = ("HEPTA_CC_FAMILY clang\nHEPTA_CC_VERSION 20 1 8\n"
               "HEPTA_CC_SYSTEM Linux\nHEPTA_CC_MACHINE x86_64\nHEPTA_C_STANDARD 201112L\n")
MSVC_PROBE = ("HEPTA_CC_FAMILY msvc\nHEPTA_CC_VERSION 194435213 0\n"
              "HEPTA_CC_SYSTEM Windows\nHEPTA_CC_MACHINE x86_64\nHEPTA_C_STANDARD 201112L\n")


class NativeHostFailureEvidenceTests(TestCase):
    def test_host_subprocess_uses_bounded_capture_and_preserves_status(self):
        with patch.object(module, "run_bounded",
                          side_effect=[CaptureResult(0, "clang version 20.1.8\n", ""),
                                       CaptureResult(0, "x86_64-unknown-linux-gnu\n", ""),
                                       CaptureResult(0, CLANG_PROBE, "")]) as invoke:
            # The public run_host has a nested capture helper: exercise the
            # helper through its source path with a deliberately early mock
            # abort after version/target interrogation below.
            with (patch.object(module.shutil, "which", return_value=sys.executable),
                  patch.object(module.platform, "system", return_value="Linux"),
                  patch.object(module.platform, "machine", return_value="x86_64"),
                  patch.object(module, "Matrix") as matrix):
                matrix.side_effect = RuntimeError("stop after tool identity")
                with self.assertRaises(RuntimeError):
                    module.run_host(cc="clang", cc_family="clang")
            self.assertEqual(invoke.call_count, 3)
            for call in invoke.call_args_list:
                self.assertEqual(call.kwargs["timeout"], 120)
                self.assertEqual(call.kwargs["stdin_limit"], 0)
                self.assertEqual(call.kwargs["stdout_limit"], 128000)
                self.assertEqual(call.kwargs["stderr_limit"], 256000)

    def test_host_capture_rejection_does_not_claim_qualification(self):
        observations = {}
        rejection = CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "bounded")
        rejection.capture = CaptureFailure((sys.executable, "--version"), -9, b"partial", b"error", 200000, 5)
        with (patch.object(module.shutil, "which", return_value=sys.executable),
              patch.object(module, "run_bounded",
                           side_effect=rejection)):
            with self.assertRaisesRegex(ValueError, "E_NATIVE_HOST_CAPTURE"):
                module.run_host(cc="clang", observations=observations)
        entry = observations["commands"][0]
        self.assertEqual(entry["capture_rejection"], "E_CAPTURE_OUTPUT_SIZE")
        self.assertEqual(entry["stdout"], "partial")
        self.assertEqual(entry["stdout_total_bytes"], 200000)
        self.assertEqual(entry["returncode"], -9)

    def test_post_execution_validator_failure_keeps_raw_trace_and_fails(self):
        observed = {
            "schema": module.SCHEMA, "status": "passed",
            "commands": [{"argv": ["C:/clang.exe", "-c", "source.c"],
                          "returncode": 0, "stdout": "", "stderr": ""}],
            "c_compiler": {"path": "C:/clang.exe", "target": "x86_64-pc-windows-msvc"},
            "native_object": {"artifact": "C:/temp/matrix.obj"},
            "executions": [{"optimization": "-O0", "returncode": 0}],
            "negative_control": {"status": "rejected_as_expected"},
            "source_sha256": "ab" * 32,
        }
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "report.json"
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(dest)]),
                  patch.object(module, "run_host", return_value=observed),
                  patch.object(module, "validate_report", side_effect=ValueError(
                      "host compile/link/run trace differs: expected vs actual"))):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(), 1)
            report = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["claims"], {"cross_host_results_inferred": False})
            self.assertIn("trace differs", report["error"])
            self.assertEqual(report["unqualified_observations"]["commands"], observed["commands"])
            self.assertEqual(report["unqualified_observations"]["native_object_artifact"],
                             "C:/temp/matrix.obj")
            self.assertNotIn("frontend", report)
            self.assertNotIn("status", report["unqualified_observations"])

    def test_msvc_compile_failure_retains_all_prior_and_failing_commands(self):
        # An adapter unit test, not evidence that Microsoft cl.exe ran here.
        # The producer must retain a mid-compilation error even though it never
        # returns a candidate report to the post-execution validator.
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "report.json"
            with (patch.object(sys, "argv", ["validate_native_host.py", "--cc", "cl", "--cc-family", "msvc", "--output", str(dest)]),
                  patch.object(module.shutil, "which", return_value=sys.executable),
                  patch.object(module.platform, "system", return_value="Windows"),
                  patch.object(module.platform, "machine", return_value="AMD64"),
                  patch.object(module, "run_bounded", side_effect=[CaptureResult(0, MSVC_PROBE, ""),
                         CaptureResult(2, "matrix.c\nerror C2143: deliberate compile failure\n", "")]),
                  patch.object(module, "analyze", return_value=SimpleNamespace(report={"ok": True}, program=None, rust="")),
                  patch.object(module, "emit_header", return_value="/* unit fixture */\n"),
                  patch.object(module, "compile_rust", return_value={"ok": True})):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(), 1)
            report = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertNotIn("actual_reported_host_executed", report["claims"])
            trace = report["unqualified_observations"]
            self.assertEqual(trace["c_compiler"]["family"], "msvc")
            self.assertEqual(len(trace["commands"]), 2)
            self.assertIn("/Od", trace["commands"][-1]["argv"])
            self.assertEqual(trace["commands"][-1]["returncode"], 2)
            self.assertIn("deliberate compile failure", trace["commands"][-1]["stdout"])


    def test_real_temp_directory_canonicalizes_like_native_artifact(self):
        # On Windows GitHub Runners the default temp path may use 8.3 aliases.
        # Canonicalizing before emitting clang commands must give the same
        # spelling used by compile_rust(Path(...).resolve()).
        import tempfile
        with tempfile.TemporaryDirectory(prefix="hepta-path-") as tmp:
            directory = Path(tmp).resolve(strict=True)
            object_file = directory / ("matrix.obj" if sys.platform == "win32" else "matrix.o")
            object_file.write_bytes(b"\x00")
            self.assertEqual(str(object_file), str(object_file.resolve(strict=True)))

    def test_execution_failure_without_returned_report_is_still_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "report.json"
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(dest)]),
                  patch.object(module, "run_host", side_effect=ValueError("no native host compiler"))):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(), 1)
            report = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertNotIn("unqualified_observations", report)


class NativeHostCompilerDriverTests(TestCase):
    def test_clang_windows_macros_cannot_qualify_as_msvc(self):
        observations = {}
        with (patch.object(module.shutil, "which", return_value=sys.executable),
              patch.object(module.platform, "system", return_value="Windows"),
              patch.object(module.platform, "machine", return_value="AMD64"),
              patch.object(module, "run_bounded", return_value=CaptureResult(0, CLANG_PROBE.replace("Linux", "Windows"), ""))):
            with self.assertRaisesRegex(ValueError, "implementation differs"):
                module.run_host(cc="clang-cl", cc_family="msvc", observations=observations)
        self.assertEqual(len(observations["commands"]), 1)

    def test_requested_gcc_is_checked_against_actual_clang_macros(self):
        with (patch.object(module.shutil, "which", return_value=sys.executable),
              patch.object(module.platform, "system", return_value="Linux"),
              patch.object(module.platform, "machine", return_value="x86_64"),
              patch.object(module, "run_bounded", side_effect=[CaptureResult(0, "clang version 20.1.8", ""),
                   CaptureResult(0, "x86_64-unknown-linux-gnu", ""), CaptureResult(0, CLANG_PROBE, "")])):
            with self.assertRaisesRegex(ValueError, "differs from --cc-family"):
                module.run_host(cc="cc", cc_family="gcc")

    def test_identity_probe_requires_unique_markers_c11_and_matching_version(self):
        for wrong in (CLANG_PROBE + "HEPTA_CC_FAMILY gcc\n", CLANG_PROBE.replace("201112L", "201710L"),
                      CLANG_PROBE.replace("20 1 8", "20 1"), CLANG_PROBE.replace("HEPTA_CC_MACHINE", "IGNORED_MACHINE")):
            with self.subTest(probe=wrong), self.assertRaises(ValueError):
                module.parse_compiler_probe(wrong)
        with self.assertRaisesRegex(ValueError, "version differs"):
            module.check_compiler_version(module.parse_compiler_probe(CLANG_PROBE), "clang version 19.1.8")

    def test_msvc_driver_keeps_c_and_rust_objects_separate_with_spaces(self):
        directory = PureWindowsPath("C:/Temp Folder/native")
        source, rust_object, executable = (directory / name for name in ("matrix.c", "matrix.obj", "host-matrix-O0.exe"))
        command = module.c_compile_command("C:/VS/bin/cl.exe", "msvc", source, executable,
                                           profile="O0", rust_object=rust_object)
        self.assertEqual(command[1:8], ["/nologo", "/std:c11", "/Od", "/W4", "/WX", "/MD", "/DABI_LAYOUT"])
        self.assertIn("/Tc" + str(source), command)
        self.assertIn(str(rust_object), command)
        self.assertIn("/Fo" + str(directory / "host-matrix-O0.c.obj"), command)
        self.assertNotIn("/Fo" + str(rust_object), command)
        self.assertIn("/Fe" + str(executable), command)
        self.assertEqual(command[-2:], ["/link", "/INCREMENTAL:NO"])
        self.assertNotIn("-std=c11", command)

    def test_msvc_type_control_compiles_without_linking(self):
        directory = PureWindowsPath("C:/Temp Folder/native")
        output = directory / "type-array_extent.obj"
        command = module.c_compile_command("cl.exe", "msvc", directory / "matrix.c", output)
        self.assertIn("/O2", command)
        self.assertEqual(command[-2:], ["/c", "/Fo" + str(output)])
        self.assertNotIn("/link", command)
        self.assertFalse(any(arg.startswith("/Fe") for arg in command))
