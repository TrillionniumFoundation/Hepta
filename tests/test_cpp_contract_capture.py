"""P4 C++ contract native compiler entry uses file-backed bounded capture."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, CaptureResult
from hepta.cpp_contracts import _command
from hepta.c_migrate import MigrationRejected


class CppContractCompilerCaptureTests(unittest.TestCase):
    def test_compiler_capture_has_explicit_time_and_byte_budgets(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   return_value=CaptureResult(0, "ok", "")) as run:
            result = _command(["c++", "--version"], timeout=11)
            self.assertEqual(result.stdout, "ok")
            run.assert_called_once_with(
                ["c++", "--version"], timeout=11, stdin_limit=0,
                stdout_limit=64000, stderr_limit=256000)

    def test_output_overrun_never_counts_as_native_success(self):
        for reason in ("E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_ENCODING"):
            with self.subTest(reason=reason):
                with patch("hepta.cpp_contracts.run_bounded",
                           side_effect=CaptureRejected(reason, "rejected")):
                    with self.assertRaises(MigrationRejected) as error:
                        _command(["c++", "-c", "bridge.cpp"])
                self.assertEqual(error.exception.code, "E_CPP_CAPTURE")

    def test_timeout_maps_to_environment_error(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   side_effect=CaptureRejected("E_CAPTURE_TIMEOUT", "timeout")):
            with self.assertRaises(MigrationRejected) as error:
                _command(["c++", "--version"])
        self.assertEqual(error.exception.code, "E_CPP_ENV")

    def test_nonzero_status_remains_native_rejection(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   return_value=CaptureResult(7, "", "invalid C++")):
            with self.assertRaises(MigrationRejected) as error:
                _command(["c++", "-c", "bridge.cpp"])
        self.assertEqual(error.exception.code, "E_CPP_NATIVE")

    @unittest.skipUnless(shutil.which("clang++"), "Real Clang++ required")
    def test_native_cxx20_standard_library_object_compiled(self):
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-capture-") as tmp:
            src, target = Path(tmp)/"bridge.cpp", Path(tmp)/"bridge.o"
            src.write_text(
                '#include <vector>\n'
                'extern "C" int vector_size() { std::vector<int> v{1,2,3};'
                'return static_cast<int>(v.size()); }\n',
                encoding="utf-8")
            result = _command([shutil.which("clang++"), "-std=c++20", "-O2",
                               "-fPIC", "-pthread", "-Werror", "-c",
                               str(src), "-o", str(target)])
            self.assertEqual(result.returncode, 0)
            self.assertGreater(target.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
