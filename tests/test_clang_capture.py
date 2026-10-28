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

    def test_real_exit_status_and_streams_are_preserved(self):
        # ExitProcess accepts an actual unsigned DWORD. SystemExit in the test
        # child would reproduce the launcher's conversion before we could test
        # its propagation. POSIX exercises its real ordinary exit-code contract
        # here; that branch does not qualify Windows high-bit statuses.
        codes = ((0, 7, 0x7fffffff, 0x80000000, 0xc0000409, 0xc0000005, 0xffffffff)
                 if os.name == 'nt' else (0, 7, 127, 128, 255))
        command = (
            "import os, sys\n"
            "code = int(sys.argv[1])\n"
            "print(f'stdout-before-exit:{code}', flush=True)\n"
            "print(f'stderr-before-exit:{code}', file=sys.stderr, flush=True)\n"
            "if os.name == 'nt':\n"
            "    import ctypes\n"
            "    exit_process = ctypes.WinDLL('kernel32', use_last_error=True).ExitProcess\n"
            "    exit_process.argtypes = [ctypes.c_uint32]\n"
            "    exit_process.restype = None\n"
            "    exit_process(code)\n"
            "    raise AssertionError('ExitProcess unexpectedly returned')\n"
            "os._exit(code)\n"
        )
        for code in codes:
            with self.subTest(platform=os.name, exit_code=f'0x{code:08x}'):
                result = run_bounded([sys.executable, '-c', command, str(code)], timeout=5)
                self.assertIs(type(result.returncode), int)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, f'stdout-before-exit:{code}\n')
                self.assertEqual(result.stderr, f'stderr-before-exit:{code}\n')

    def test_launch_failure_cannot_start_the_requested_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'must-not-start.txt'
            command = [sys.executable, '-c',
                       f'import pathlib; pathlib.Path({str(marker)!r}).write_text("started")']
            # Windows starts the real gated launcher but denies actual job
            # assignment. POSIX rejects process creation at the existing seam.
            target = ('hepta.windows_capture.WindowsJob.assign' if os.name == 'nt'
                      else 'hepta.clang_capture.subprocess.Popen')
            with patch(target, side_effect=OSError('injected launch/assignment failure')):
                with self.assertRaises(CaptureRejected) as caught:
                    run_bounded(command, timeout=3)
            self.assertEqual(caught.exception.code, 'E_CAPTURE_EXEC')
            time.sleep(.4)
            self.assertFalse(marker.exists(), 'requested compiler ran after failed admission')

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

    def _descendant_cleanup(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            signal_path = Path(tmp) / 'survived.txt'
            started_path = Path(tmp) / 'started.txt'
            grandchild = ("import time,pathlib;"
                          + f"pathlib.Path({str(started_path)!r}).write_text('started');"
                          + "time.sleep(3);"
                          + f"pathlib.Path({str(signal_path)!r}).write_text('survived')")
            child = ("import subprocess,sys,pathlib,time\n"
                     + f"subprocess.Popen([sys.executable,'-c',{grandchild!r}])\n"
                     + f"started = pathlib.Path({str(started_path)!r})\n"
                     + "while not started.exists(): time.sleep(.005)\n"
                     + "print('descendant started', flush=True)\n")
            if mode == 'timeout':
                child += "time.sleep(10)\n"
            elif mode == 'output':
                child += "print('x' * 100000, flush=True)\ntime.sleep(10)\n"
            elif mode == 'nonzero':
                child += "sys.exit(7)\n"
            if mode in ('timeout', 'output'):
                with self.assertRaises(CaptureRejected) as caught:
                    run_bounded([sys.executable, '-c', child], timeout=2,
                                stdout_limit=4096)
                expected = 'E_CAPTURE_TIMEOUT' if mode == 'timeout' else 'E_CAPTURE_OUTPUT_SIZE'
                self.assertEqual(caught.exception.code, expected)
                self.assertIsNotNone(caught.exception.capture)
                self.assertIn(b'descendant started', caught.exception.capture.stdout)
            else:
                result = run_bounded([sys.executable, '-c', child], timeout=3)
                self.assertEqual(result.returncode, 7 if mode == 'nonzero' else 0)
            self.assertTrue(started_path.exists(), 'descendant must really run before cleanup')
            time.sleep(3.2)
            self.assertFalse(signal_path.exists(), 'compiler descendant survived capture cleanup')

    def test_descendant_cancelled_even_when_parent_succeeds(self):
        self._descendant_cleanup('success')

    def test_descendant_cancelled_when_parent_fails(self):
        self._descendant_cleanup('nonzero')

    def test_descendant_cancelled_on_wall_timeout(self):
        self._descendant_cleanup('timeout')

    def test_descendant_cancelled_on_output_limit(self):
        self._descendant_cleanup('output')


if __name__ == '__main__':
    unittest.main()
