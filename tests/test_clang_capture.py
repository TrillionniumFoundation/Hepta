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

from hepta.clang_capture import (CaptureRejected, run_bounded,
                                 scoped_capture_deadline)


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

    def test_elapsed_scope_does_not_preempt_python_or_launch_another_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "unexpected-child"
            with scoped_capture_deadline(.02) as deadline:
                time.sleep(.04)
                # No signal interrupts arbitrary Python; the next tool check
                # observes expiry before constructing a child process.
                reached_boundary = True
                with self.assertRaises(CaptureRejected) as caught:
                    run_bounded([sys.executable, "-c",
                                 f"from pathlib import Path; Path({str(marker)!r}).touch()"])
            self.assertTrue(reached_boundary)
            self.assertTrue(deadline.expired)
            self.assertEqual(caught.exception.code, "E_CAPTURE_TOTAL_DEADLINE")
            self.assertIsNone(caught.exception.capture)
            self.assertFalse(marker.exists())
        # The expired context is gone; it cannot poison a subsequent caller.
        result = run_bounded([sys.executable, "-c", "print('restored')"], timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, "restored\n"))

    def test_nested_disabled_or_later_deadline_cannot_extend_outer_scope(self):
        for inner_seconds in (None, 10):
            with self.subTest(inner_seconds=inner_seconds):
                with scoped_capture_deadline(.25) as outer:
                    with scoped_capture_deadline(inner_seconds) as inner:
                        with self.assertRaises(CaptureRejected) as caught:
                            run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=5)
                self.assertTrue(outer.expired)
                self.assertFalse(inner.expired)
                self.assertEqual(caught.exception.code, "E_CAPTURE_TOTAL_DEADLINE")
                self.assertIsNotNone(caught.exception.capture)
                self.assertIsNotNone(caught.exception.capture.returncode)

    def test_scope_exit_records_unpolled_expiry_and_restores_outer_scope(self):
        with scoped_capture_deadline(3) as outer:
            with scoped_capture_deadline(.02) as inner:
                time.sleep(.04)
            self.assertTrue(inner.expired)
            result = run_bounded([sys.executable, "-c", "print('outer remains active')"], timeout=2)
            self.assertEqual(result.returncode, 0)
        self.assertFalse(outer.expired)

    def test_invalid_scoped_deadline_does_not_replace_context(self):
        for invalid in (float("nan"), float("inf"), float("-inf"), True, 0, -1, 3601, "1"):
            with self.subTest(seconds=repr(invalid)), self.assertRaises(ValueError):
                with scoped_capture_deadline(invalid):
                    self.fail("invalid deadline entered a scope")

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
