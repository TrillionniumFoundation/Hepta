"""P2/P4 strict compiler budget regression: real Clang and adverse children.

These tests exercise bounded capture and the shared strict C/C++ _run adapter.
They do not attest compiler sandboxing or general C++ migration correctness.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.c_migrate import MigrationRejected, _run


class CaptureBudgets(unittest.TestCase):
    def test_utf8_text_stdin_and_stderr(self):
        code = 'import sys; print("stdin=" + sys.stdin.read()); print("stderr", file=sys.stderr)'
        result = run_bounded([sys.executable, "-c", code], input_text="abc", timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "stdin=abc\n")
        self.assertEqual(result.stderr, "stderr\n")

    @unittest.skipUnless(shutil.which("clang"), "Native Clang required")
    def test_real_clang_preprocessing_and_migration_adapter(self):
        compiler = shutil.which("clang")
        argv = [compiler, "-x", "c", "-std=c11", "-E", "-P", "-"]
        input_text = "#define OFFSET 7\nint demo = OFFSET;\n"
        r = run_bounded(argv, input_text=input_text, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("int demo = 7;", r.stdout)
        self.assertIn("int demo = 7;", _run(argv, input_text=input_text))

    @unittest.skipUnless(shutil.which("clang"), "Native Clang required")
    def test_project_capture_uses_real_cwd_and_clang(self):
        from hepta.c_project import invoke
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / "meaning.h").write_text("#define MEANING 42\n")
            (directory / "project.c").write_text('#include "meaning.h"\nint f(void){return MEANING;}\n')
            text = invoke([shutil.which("clang"), "-std=c11", "-E", "-P", "project.c"],
                          directory)
            self.assertIn("return 42;", text)

    def test_project_capture_preserves_errors_and_quota_codes(self):
        from hepta import c_project
        with tempfile.TemporaryDirectory() as root:
            for capture_code, expected in (
                ("E_CAPTURE_OUTPUT_SIZE", "E_C_BUILD_SIZE"),
                ("E_CAPTURE_INPUT_SIZE", "E_C_BUILD_SIZE"),
                ("E_CAPTURE_TIMEOUT", "E_C_BUILD_TOOL"),
                ("E_CAPTURE_ENCODING", "E_C_BUILD_TOOL"),
            ):
                with self.subTest(code=capture_code):
                    with patch.object(c_project, "run_bounded",
                                      side_effect=CaptureRejected(capture_code, "limited")):
                        with self.assertRaises(MigrationRejected) as caught:
                            c_project.invoke(["clang", "-dumpmachine"], Path(root))
                        self.assertEqual(caught.exception.code, expected)
            with self.assertRaises(MigrationRejected) as caught:
                c_project.invoke([sys.executable, "-c", "import sys; sys.exit(7)"], Path(root))
            self.assertEqual(caught.exception.code, "E_C_BUILD_TOOL")

    def test_c_header_probe_capture_real_process_and_rejection(self):
        from hepta import c_import
        ok = c_import._native_capture([sys.executable, "-c", 'print("probe")'],
                                      timeout=3, phase="PROBE")
        self.assertEqual(ok.stdout, "probe\n")
        for code in ("E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_TIMEOUT"):
            with self.subTest(code=code):
                with patch.object(c_import, "run_bounded",
                                  side_effect=CaptureRejected(code, "limited")):
                    with self.assertRaisesRegex(Exception, "limited") as captured:
                        c_import._native_capture(["fake"], timeout=3, phase="PROBE")
                    self.assertEqual(captured.exception.diagnostic.code, "E_C_IMPORT_PROBE")

    def test_cpp_contract_native_capture_real_process_and_rejection(self):
        from hepta import cpp_contracts
        ok = cpp_contracts._command([sys.executable, "-c", 'print("cpp")'], timeout=3)
        self.assertEqual(ok.stdout, "cpp\n")
        for code in ("E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_TIMEOUT"):
            with self.subTest(code=code):
                with patch.object(cpp_contracts, "run_bounded",
                                  side_effect=CaptureRejected(code, "limited")):
                    with self.assertRaises(MigrationRejected) as captured:
                        cpp_contracts._command(["fake"], timeout=3)
                    self.assertEqual(captured.exception.code, "E_CPP_ENV")

    @unittest.skipUnless(shutil.which("clang"), "LLVM-capable Clang required")
    def test_bounded_llvm_tool_emits_real_native_object(self):
        from hepta.llvm_ssa_backend import run_llvm_tool
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / "function.ll"
            output = directory / "function.o"
            source.write_text("define i32 @hepta_test(i32 %x) {\n"
                              "entry:\n  %y = add i32 %x, 1\n  ret i32 %y\n}\n")
            result = run_llvm_tool([shutil.which("clang"), "-x", "ir", "-O2",
                                    "-c", str(source), "-o", str(output)], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(output.stat().st_size, 32)

    def test_llvm_capture_error_is_not_a_backend_success(self):
        from hepta import llvm_ssa_backend
        with patch.object(llvm_ssa_backend, "run_bounded",
                          side_effect=CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "budget")):
            with self.assertRaisesRegex(llvm_ssa_backend.LLVMSSARejected,
                                        "E_LLVM_SSA_TOOL_BOUND"):
                llvm_ssa_backend.run_llvm_tool(["clang", "-dumpmachine"], timeout=1)

    def test_child_nonzero_exit_is_never_success(self):
        r = run_bounded([sys.executable, "-c", "import sys; sys.exit(7)"], timeout=3)
        self.assertEqual(r.returncode, 7)
        with self.assertRaises(MigrationRejected) as caught:
            _run([sys.executable, "-c", 'import sys;sys.stderr.write("failed");sys.exit(7)'])
        self.assertEqual(caught.exception.code, "E_CLANG_REJECT")

    def test_stdout_byte_quota(self):
        with self.assertRaises(CaptureRejected) as caught:
            run_bounded([sys.executable, "-c", 'print("x"*1000000)'],
                        timeout=3, stdout_limit=4096)
        self.assertEqual(caught.exception.code, "E_CAPTURE_OUTPUT_SIZE")

    def test_stderr_byte_quota(self):
        with self.assertRaises(CaptureRejected) as caught:
            run_bounded([sys.executable, "-c", 'import sys;sys.stderr.write("x"*1000000)'],
                        timeout=3, stderr_limit=4096)
        self.assertEqual(caught.exception.code, "E_CAPTURE_OUTPUT_SIZE")

    def test_wall_timeout(self):
        started = time.monotonic()
        with self.assertRaises(CaptureRejected) as caught:
            run_bounded([sys.executable, "-c", "import time;time.sleep(10)"], timeout=.15)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT")
        self.assertLess(time.monotonic() - started, 2)

    def test_oversize_stdin_rejected_before_process_launch(self):
        with self.assertRaises(CaptureRejected) as caught:
            run_bounded([sys.executable, "-c", "print(1)"],
                        input_text="x"*100, stdin_limit=64)
        self.assertEqual(caught.exception.code, "E_CAPTURE_INPUT_SIZE")

    def test_invalid_utf8_stdout(self):
        with self.assertRaises(CaptureRejected) as caught:
            run_bounded([sys.executable, "-c", 'import os;os.write(1,b"\xff")'],
                        timeout=3)
        self.assertEqual(caught.exception.code, "E_CAPTURE_ENCODING")

    @unittest.skipUnless(os.name == "posix", "POSIX process group cleanup only")
    def test_descendant_terminated_after_compiler_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "survived.txt"
            grandchild = ("import time,pathlib;time.sleep(.7);"
                          + f"pathlib.Path({str(path)!r}).write_text('survived')")
            parent = ("import subprocess,sys;"
                      + f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]);"
                      + "print('parent finished')")
            r = run_bounded([sys.executable, "-c", parent], timeout=2)
            self.assertEqual(r.returncode, 0)
            time.sleep(.9)
            self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX descendant cleanup only")
    def test_oversize_output_cannot_leave_child_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "survived-after-overflow.txt"
            grandchild = ("import time,pathlib;time.sleep(.6);"
                          + f"pathlib.Path({str(marker)!r}).write_text('survived')")
            parent = ("import subprocess,sys;"
                      + f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]);"
                      + "sys.stdout.write('X'*1000000)")
            with self.assertRaises(CaptureRejected) as caught:
                run_bounded([sys.executable, "-c", parent],
                            timeout=3, stdout_limit=4096)
            self.assertEqual(caught.exception.code, "E_CAPTURE_OUTPUT_SIZE")
            time.sleep(.8)
            self.assertFalse(marker.exists(), "Compiler descendant escaped after quota rejection")

    def test_migration_rejection_codes_preserve_budgets(self):
        from hepta import c_migrate
        for capture_code, expected in (
            ("E_CAPTURE_OUTPUT_SIZE", "E_CLANG_SIZE"),
            ("E_CAPTURE_INPUT_SIZE", "E_CLANG_SIZE"),
            ("E_CAPTURE_TIMEOUT", "E_CLANG_ENV"),
            ("E_CAPTURE_ENCODING", "E_CLANG_ENV"),
        ):
            with self.subTest(capture_code=capture_code):
                with patch.object(c_migrate, "run_bounded",
                                  side_effect=CaptureRejected(capture_code, "bounded")):
                    with self.assertRaises(MigrationRejected) as caught:
                        c_migrate._run(["clang", "-dumpmachine"])
                    self.assertEqual(caught.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
