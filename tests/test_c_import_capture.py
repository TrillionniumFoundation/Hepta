"""P3 C importer uses bounded native compiler/probe output capture."""
from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.clang_capture import CaptureRejected, CaptureResult
from hepta.c_import import _native_process


class HeaderProbeBudgetTests(unittest.TestCase):
    def test_capture_limits_not_silently_disabled(self):
        with patch("hepta.c_import.run_bounded",
                   return_value=CaptureResult(0, "checked", "")) as capture:
            out = _native_process(["gcc", "-dumpmachine"], timeout=30)
            self.assertEqual(out.stdout, "checked")
            capture.assert_called_once_with(
                ["gcc", "-dumpmachine"], timeout=30,
                stdin_limit=0, stdout_limit=64000, stderr_limit=512000)

    def test_probe_runtime_has_larger_but_finite_stdout_cap(self):
        with patch("hepta.c_import.run_bounded",
                   return_value=CaptureResult(0, "P|int|4|4|1\n", "")) as capture:
            out = _native_process(["/tmp/native-probe"], timeout=30,
                                  stdout_limit=4_000_000)
            self.assertEqual(out.returncode, 0)
            self.assertEqual(capture.call_args.kwargs["stdout_limit"], 4_000_000)

    def test_timeout_and_overrun_fail_closed(self):
        for reason in ("E_CAPTURE_TIMEOUT", "E_CAPTURE_OUTPUT_SIZE",
                       "E_CAPTURE_ENCODING"):
            with self.subTest(reason=reason):
                with patch("hepta.c_import.run_bounded",
                           side_effect=CaptureRejected(reason, "rejected")):
                    with self.assertRaises(HeptaError) as error:
                        _native_process(["gcc", "--version"], timeout=30)
                self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE_CAPTURE")
                self.assertIn(reason, str(error.exception))

    @unittest.skipUnless(shutil.which("gcc"), "Real GCC native C probe required")
    def test_real_c_compiler_and_probe_execution(self):
        gcc = shutil.which("gcc")
        with tempfile.TemporaryDirectory(prefix="hepta-c-probe-budget-") as td:
            root = Path(td)
            source, executable = root/"probe.c", root/"probe"
            source.write_text(
                "#include <stdio.h>\n"
                "int main(void) { printf(\"P|int|%zu|%zu|1\\n\","
                "sizeof(int),_Alignof(int));return 0;}\n",
                encoding="utf-8")
            self.assertEqual(_native_process(
                [gcc, "-std=c11", "-Werror", str(source), "-o", str(executable)],
                timeout=120).returncode, 0)
            actual = _native_process([str(executable)], timeout=30,
                                     stdout_limit=4_000_000)
            self.assertEqual(actual.returncode, 0)
            self.assertEqual(actual.stdout, f"P|int|{ctypes.sizeof(ctypes.c_int)}|{ctypes.alignment(ctypes.c_int)}|1\\n")


if __name__ == "__main__":
    unittest.main()
