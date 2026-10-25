"""Scoped real-process and Clang capture budget regression tests."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
from unittest.mock import patch
import sys
import tempfile
import time
import unittest

from hepta.clang_capture import CaptureRejected, run_bounded


class CaptureBudgets(unittest.TestCase):
    def test_success_preserves_text_and_input(self):
        c = 'import sys; print("stdin=" + sys.stdin.read()); print("stderr", file=sys.stderr)'
        result = run_bounded([sys.executable, '-c', c], input_text='abc', timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'stdin=abc\n')
        self.assertEqual(result.stderr, 'stderr\n')

    @unittest.skipUnless(shutil.which('clang'), 'Clang required')
    def test_real_clang_c_preprocess(self):
        compiler = shutil.which('clang')
        result = run_bounded([compiler, '-x', 'c', '-std=c11', '-E', '-'],
                             input_text='#define OFFSET 7\nint demo = OFFSET;\n', timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('int demo = 7;', result.stdout)

    def test_child_exit_failure_does_not_turn_into_success(self):
        p = run_bounded([sys.executable, '-c', 'import sys; sys.exit(7)'], timeout=3)
        self.assertEqual(p.returncode, 7)

    def test_stdout_limit(self):
        with self.assertRaises(CaptureRejected) as e:
            run_bounded([sys.executable, '-c', 'print("x"*1000000)'],
                        timeout=3, stdout_limit=4096)
        self.assertEqual(e.exception.code, 'E_CAPTURE_OUTPUT_SIZE')

    def test_stderr_limit(self):
        with self.assertRaises(CaptureRejected) as e:
            run_bounded([sys.executable, '-c', 'import sys;sys.stderr.write("x"*1000000)'],
                        timeout=3, stderr_limit=4096)
        self.assertEqual(e.exception.code, 'E_CAPTURE_OUTPUT_SIZE')

    def test_wall_timeout(self):
        start = time.monotonic()
        with self.assertRaises(CaptureRejected) as e:
            run_bounded([sys.executable, '-c', 'import time;time.sleep(10)'], timeout=.15)
        self.assertEqual(e.exception.code, 'E_CAPTURE_TIMEOUT')
        self.assertLess(time.monotonic() - start, 2)

    def test_invalid_timeout_budgets_reject_before_launch(self):
        for invalid in (float("nan"), float("inf"), float("-inf"),
                        "45", True, 0, -1, 3601):
            with self.subTest(timeout=repr(invalid)):
                with patch("hepta.clang_capture.subprocess.Popen") as launch:
                    with self.assertRaises(CaptureRejected) as caught:
                        run_bounded([sys.executable, "-c", "print(1)"], timeout=invalid)
                    self.assertEqual(caught.exception.code, "E_CAPTURE_BUDGET")
                    launch.assert_not_called()

    def test_invalid_byte_limits_reject_before_launch(self):
        for key in ("stdout_limit", "stderr_limit", "stdin_limit"):
            for invalid in (float("nan"), float("inf"), -1, True, None, "4096", 4.5):
                with self.subTest(budget=key, invalid=repr(invalid)):
                    with patch("hepta.clang_capture.subprocess.Popen") as launch:
                        with self.assertRaises(CaptureRejected) as caught:
                            run_bounded([sys.executable, "-c", "print(1)"], **{key: invalid})
                        self.assertEqual(caught.exception.code, "E_CAPTURE_BUDGET")
                        launch.assert_not_called()

    def test_oversize_stdin_without_process_launch(self):
        with self.assertRaises(CaptureRejected) as e:
            run_bounded([sys.executable, '-c', 'print(1)'],
                        input_text='x'*100, stdin_limit=64)
        self.assertEqual(e.exception.code, 'E_CAPTURE_INPUT_SIZE')

    def test_bad_utf8_stdout_is_rejected(self):
        with self.assertRaises(CaptureRejected) as e:
            run_bounded([sys.executable, '-c', 'import os;os.write(1,b"\\xff")'], timeout=3)
        self.assertEqual(e.exception.code, 'E_CAPTURE_ENCODING')

    @unittest.skipUnless(os.name == 'posix', 'POSIX session descendants only')
    def test_descendant_cancelled_even_when_parent_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            signal_path = Path(tmp) / 'survived.txt'
            grandchild = ("import time,pathlib;time.sleep(0.6);"
                          + f"pathlib.Path({str(signal_path)!r}).write_text('survived')")
            child = ("import subprocess,sys;" +
                     f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]);" +
                     "print('parent finished')")
            result = run_bounded([sys.executable, '-c', child], timeout=2)
            self.assertEqual(result.returncode, 0)
            time.sleep(.9)
            self.assertFalse(signal_path.exists(), 'compiler orphan survived parent completion')


if __name__ == '__main__':
    unittest.main()
