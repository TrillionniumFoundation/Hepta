"""Failed actual-host ABI evidence must retain its rejection trace, never pass."""
from __future__ import annotations

import contextlib
from copy import deepcopy
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


def _captured(code, stdout="", stderr=""):
    return CaptureResult(code, stdout, stderr, stdout.encode(), stderr.encode())


class NativeHostFailureEvidenceTests(TestCase):
    def test_host_subprocess_uses_bounded_capture_and_preserves_status(self):
        with patch.object(module, "run_bounded",
                          side_effect=[_captured(0, "clang version 20.1.8\n", ""),
                                       _captured(0, "x86_64-unknown-linux-gnu\n", ""),
                                       _captured(0, CLANG_PROBE, "")]) as invoke:
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
        root, _ = module._validate_retained_files(observations["retained_evidence"])
        self.assertIs(entry["retained_streams"]["complete"], False)
        self.assertEqual((root / "streams/00.stdout").read_bytes(), b"partial")
        self.assertEqual((root / "streams/00.stderr").read_bytes(), b"error")

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
                  patch.object(module, "run_bounded", side_effect=[_captured(0, MSVC_PROBE, ""),
                         _captured(2, "matrix.c\nerror C2143: deliberate compile failure\n", "")]),
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
              patch.object(module, "run_bounded", return_value=_captured(0, CLANG_PROBE.replace("Linux", "Windows"), ""))):
            with self.assertRaisesRegex(ValueError, "implementation differs"):
                module.run_host(cc="clang-cl", cc_family="msvc", observations=observations)
        self.assertEqual(len(observations["commands"]), 1)

    def test_requested_gcc_is_checked_against_actual_clang_macros(self):
        with (patch.object(module.shutil, "which", return_value=sys.executable),
              patch.object(module.platform, "system", return_value="Linux"),
              patch.object(module.platform, "machine", return_value="x86_64"),
              patch.object(module, "run_bounded", side_effect=[_captured(0, "clang version 20.1.8", ""),
                   _captured(0, "x86_64-unknown-linux-gnu", ""), _captured(0, CLANG_PROBE, "")])):
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


class NativeHostRetainedEvidenceTests(TestCase):
    def native_names(self):
        extension = ".exe" if sys.platform == "win32" else ""
        return ("matrix.obj" if sys.platform == "win32" else "matrix.o",
                "host-matrix-O0" + extension, "host-matrix-O2" + extension, "wrong" + extension)

    @contextlib.contextmanager
    def archive(self):
        """Synthetic bytes exercise archive admission, not native execution."""
        with tempfile.TemporaryDirectory() as temporary:
            observations, commands = {}, []
            evidence = module._RetainedEvidence(Path(temporary) / "archive", observations)
            with module._retained_workdir(evidence, commands) as work:
                inputs = {"compiler-identity.c": module.COMPILER_PROBE.encode(),
                          "matrix.hepta": b"unit Hepta source", "matrix.c": b"positive C source",
                          "matrix.h": b"positive header", "matrix.rs": b"complete Rust input",
                          "layout-probes.rs": b"layout probes", "wrong.c": b"wrong C source"}
                for name, raw in inputs.items():
                    evidence.save("inputs/" + name, raw)
                object_name, o0, o2, wrong = self.native_names()
                native = {object_name: b"unit native object", o0: b"unit O0 executable",
                          o2: b"unit O2 executable", wrong: b"unit wrong executable"}
                for name, raw in {**native, "compiler-identity.c": inputs["compiler-identity.c"],
                                  "matrix.c": inputs["wrong.c"], "matrix.h": inputs["matrix.h"]}.items():
                    (work / name).write_bytes(raw)
                controls = []
                for name in ("function_parameter", "array_extent", "nested_pointer_const"):
                    raw = ("changed header " + name).encode()
                    evidence.save("inputs/type-" + name + ".h", raw)
                    controls.append({"name": name, "header_sha256": module.sha(raw)})
                commands.append({"argv": [str(work / o0)], "returncode": 0,
                                 "seconds": 0, "stdout": "unit observation\n", "stderr": "",
                                 "retained_streams": evidence.streams(0, b"unit observation\r\n", b"", complete=True)})
                report = {"host": {"system": module.platform.system()}, "retained_evidence": evidence.receipt,
                          "source_sha256": module.sha(inputs["matrix.hepta"]),
                          "harness_sha256": module.sha(inputs["matrix.c"]),
                          "header_sha256": module.sha(inputs["matrix.h"]),
                          "layout_probes_sha256": module.sha(inputs["layout-probes.rs"]),
                          "native_object": {"artifact": str(work / object_name), "artifact_bytes": len(native[object_name]),
                                            "artifact_sha256": module.sha(native[object_name]),
                                            "rust_sha256": module.sha(inputs["matrix.rs"])},
                          "executable_sha256s": [module.sha(native[name]) for name in (o0, o2)],
                          "negative_control": {"source_sha256": module.sha(inputs["wrong.c"]),
                                               "artifact_sha256": module.sha(native[wrong])},
                          "type_negative_controls": controls, "commands": commands}
                evidence.save("native-build.json", (json.dumps(report["native_object"], sort_keys=True) + "\n").encode())
            self.assertFalse(work.exists())
            yield report, evidence.directory

    def reseal(self, report, root):
        receipt = report["retained_evidence"]
        for name in receipt["files"]:
            raw = (root / name).read_bytes()
            receipt["files"][name] = {"bytes": len(raw), "sha256": module.sha(raw)}
        raw = (json.dumps({k: v for k, v in receipt.items() if k != "manifest"}, sort_keys=True) + "\n").encode()
        (root / "manifest.json").write_bytes(raw)
        receipt["manifest"] = {"bytes": len(raw), "sha256": module.sha(raw)}

    def test_originals_survive_temp_cleanup_with_raw_crlf_and_create_only_archive(self):
        with self.archive() as (report, root):
            module._validate_retained_bindings(report)
            self.assertEqual((root / "streams/00.stdout").read_bytes(), b"unit observation\r\n")
            self.assertNotEqual((root / "inputs/matrix.c").read_bytes(), (root / "work/matrix.c").read_bytes())
            before = (root / "manifest.json").read_bytes()
            with self.assertRaises(FileExistsError):
                module._RetainedEvidence(root, {})
            self.assertEqual((root / "manifest.json").read_bytes(), before)

    def test_missing_truncated_or_changed_originals_cannot_qualify(self):
        with self.archive() as (report, root):
            for name in tuple("work/" + name for name in self.native_names()) + (
                         "inputs/matrix.c", "inputs/type-array_extent.h", "streams/00.stdout"):
                path = root / name; original = path.read_bytes()
                for change in ("missing", "truncated", "changed"):
                    with self.subTest(name=name, change=change):
                        if change == "missing":
                            path.unlink()
                        else:
                            path.write_bytes(original[:1] if change == "truncated" else b"X" * len(original))
                        with self.assertRaises(ValueError):
                            module._validate_retained_bindings(report)
                        path.write_bytes(original)
            module._validate_retained_bindings(report)

    def test_resealed_manifest_cannot_replace_native_roles_or_original_output(self):
        for name in tuple("work/" + name for name in self.native_names()) + (
                     "inputs/matrix.c", "inputs/wrong.c", "streams/00.stdout"):
            with self.subTest(name=name), self.archive() as (report, root):
                (root / name).write_bytes(b"different retained bytes")
                self.reseal(report, root)
                with self.assertRaises(ValueError):
                    module._validate_retained_bindings(report)
        with self.archive() as (report, root):
            changed = deepcopy(report)
            changed["commands"][0]["argv"] = ["different-executable"]
            with self.assertRaisesRegex(ValueError, "commands differ"):
                module._validate_retained_bindings(changed)

    def test_legacy_receipt_extra_files_aliases_and_symlinks_refuse(self):
        with self.assertRaisesRegex(ValueError, "receipt-only"):
            module._validate_retained_bindings({"schema": "hepta.native-host.v2"})
        for name in ("../escape", "/absolute", "C:/drive", "\\\\server\\file", "work/../alias", "work\\alias", "work//alias"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module._archive_name(name)
        with self.archive() as (report, root):
            (root / "extra").write_bytes(b"unlisted")
            with self.assertRaisesRegex(ValueError, "file set"):
                module._validate_retained_bindings(report)
            (root / "extra").unlink()
            # Exercise this guard on Windows without requiring OS symlink privileges.
            with patch.object(Path, "is_symlink", autospec=True, side_effect=lambda p: p.name == self.native_names()[0]):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    module._validate_retained_bindings(report)

    def test_second_profile_failure_retains_first_profile_and_partial_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "report.json"
            def compile_object(source, **kwargs):
                Path(kwargs["output"]).write_bytes(b"unit Rust object")
                return {"ok": True}
            def invoke(argv, **kwargs):
                if argv[-1] == "--version": return _captured(0, "clang version 20.1.8\n")
                if argv[-1] == "-dumpmachine": return _captured(0, "x86_64-unknown-linux-gnu\n")
                if "-E" in argv: return _captured(0, CLANG_PROBE)
                if "-o" in argv:
                    output = Path(argv[argv.index("-o") + 1]); output.write_bytes(b"unit " + output.name.encode())
                    return _captured(2, "deliberate O2 failure\n") if "-O2" in argv else _captured(0)
                return _captured(0, json.dumps({"status": "passed", "foreign_calls": 181}) + "\n")
            with (patch.object(sys, "argv", ["validate_native_host.py", "--cc", "clang", "--output", str(target)]),
                  patch.object(module.shutil, "which", return_value=sys.executable),
                  patch.object(module.platform, "system", return_value="Linux"),
                  patch.object(module.platform, "machine", return_value="x86_64"),
                  patch.object(module, "run_bounded", side_effect=invoke),
                  patch.object(module, "analyze", return_value=SimpleNamespace(report={"ok": True}, program=None, rust="unit Rust source")),
                  patch.object(module, "emit_header", return_value="unit header"),
                  patch.object(module, "compile_rust", side_effect=compile_object),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(module.main(), 1)
            report = json.loads(target.read_bytes())
            self.assertEqual(report["status"], "failed")
            observed = report["unqualified_observations"]
            receipt = observed["retained_evidence"]
            root, files = module._validate_retained_files(receipt)
            self.assertFalse(Path(receipt["original_temporary_directory"]).exists())
            self.assertEqual(len(observed["executions"]), 1)
            self.assertEqual(observed["commands"][-1]["returncode"], 2)
            for name in ("work/matrix.o", "work/host-matrix-O0", "work/host-matrix-O2"):
                self.assertIn(name, files)
            self.assertEqual((root / "streams/05.stdout").read_bytes(), b"deliberate O2 failure\n")
            with self.assertRaises(ValueError):
                module.validate_report(report)

    def test_retention_failure_cannot_hide_original_failure_or_admit_success(self):
        for original_failure in (False, True):
            with self.subTest(original_failure=original_failure), tempfile.TemporaryDirectory() as temporary:
                evidence = module._RetainedEvidence(Path(temporary) / "archive", {})
                with patch.object(evidence, "finish", side_effect=OSError("archive unavailable")):
                    expected = RuntimeError if original_failure else OSError
                    with self.assertRaisesRegex(expected, "original native failure" if original_failure else "archive unavailable"):
                        with module._retained_workdir(evidence, []):
                            if original_failure:
                                raise RuntimeError("original native failure")
                self.assertEqual(evidence.receipt["retention_error"]["type"], "OSError")
                self.assertEqual("execution_failure" in evidence.receipt, original_failure)
                if original_failure:
                    self.assertEqual(evidence.receipt["execution_failure"]["message"], "original native failure")
