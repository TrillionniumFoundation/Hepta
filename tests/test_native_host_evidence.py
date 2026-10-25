"""Failed actual-host ABI evidence must retain its rejection trace, never pass."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from tools import validate_native_host as module


class NativeHostFailureEvidenceTests(TestCase):
    def test_post_execution_validator_failure_keeps_raw_trace_and_fails(self):
        observed = {
            "schema": "hepta.native-host.v1", "status": "passed",
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
