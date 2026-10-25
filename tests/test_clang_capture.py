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
