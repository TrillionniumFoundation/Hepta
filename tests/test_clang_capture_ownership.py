"""Actual private children plus controlled ownership/read-race fault seams.

The fault controls do not claim to reproduce an uninterruptible kernel task,
PID reuse, or synchronous termination of every process-group descendant.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import clang_capture as capture


POSIX_WAITID = (os.name == "posix" and callable(getattr(os, "waitid", None))
               and all(hasattr(os, name) for name in
                       ("P_PID", "WEXITED", "WNOWAIT", "WNOHANG")))


@unittest.skipUnless(POSIX_WAITID, "actual POSIX waitid(WNOWAIT) required")
class CaptureOwnershipTests(unittest.TestCase):
    def test_actual_group_signal_retains_unreaped_leader_and_original_exit_status(self):
        real_killpg = os.killpg
        for code in (0, 7, 127, 128, 255):
            observations = []

            def group_signal(pid, sig):
                try:
                    info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    observations.append((True, None if info is None else info.si_status))
                except ChildProcessError:
                    observations.append((False, None))
                return real_killpg(pid, sig)

            with self.subTest(exit_code=code), patch.object(capture.os, "killpg", group_signal):
                result = capture.run_bounded([sys.executable, "-c",
                    "import sys;print('owned',flush=True);sys.exit(int(sys.argv[1]))", str(code)],
                    timeout=3)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, "owned\n")
                # Darwin retains a living private guardian, whose status is
                # distinct from the compiler's private exit-status frame.
                self.assertEqual(observations, [(True, None if capture._DARWIN else code)])

    def test_unconfirmed_wait_refuses_instead_of_returning_success(self):
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            children.append((proc, proc.wait))
            proc.wait = lambda *a, **k: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(proc.args, k.get("timeout", 3)))
            return proc

        try:
            with patch.object(capture.subprocess, "Popen", side_effect=launch):
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c", "print('complete',flush=True)"],
                                        timeout=3)
            self.assertEqual(caught.exception.code, "E_CAPTURE_CLEANUP")
        finally:
            for proc, real_wait in children:
                proc.wait = real_wait
                real_wait(timeout=3)

    def test_growth_after_final_stat_is_refused_with_bounded_failure_prefixes(self):
        real_temporary_file = tempfile.TemporaryFile
        for growing_stream in (1, 2):
            files, read_sizes = [], []

            class GrowingFile:
                def __init__(self, raw, index):
                    self.raw, self.index, self.grown = raw, index, False

                def __getattr__(self, name):
                    return getattr(self.raw, name)

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.raw.__exit__(*args)

                def read(self, size=-1):
                    read_sizes.append((self.index, size))
                    if self.index == growing_stream and not self.grown:
                        # A deterministic writer-scheduling seam after fstat.
                        # Do not rely on SIGKILL making a file snapshot stable.
                        self.grown = True
                        position = self.raw.tell()
                        self.raw.seek(0, os.SEEK_END)
                        self.raw.write(b"late" * 32)
                        self.raw.flush()
                        self.raw.seek(position)
                    return self.raw.read(size)

            def make_file(*args, **kwargs):
                proxy = GrowingFile(real_temporary_file(*args, **kwargs), len(files))
                files.append(proxy)
                return proxy

            with self.subTest(stream=growing_stream), \
                    patch.object(capture.tempfile, "TemporaryFile", side_effect=make_file):
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c",
                        "import os;os.write(1,b'12345678');os.write(2,b'abcdefgh')"],
                        timeout=3, stdout_limit=8, stderr_limit=8)
                self.assertEqual(caught.exception.code, "E_CAPTURE_OUTPUT_SIZE")
                evidence = caught.exception.capture
                self.assertIsNotNone(evidence)
                self.assertLessEqual(len(evidence.stdout), 8)
                self.assertLessEqual(len(evidence.stderr), 8)
                self.assertTrue(all(0 <= size <= 9 for _, size in read_sizes), read_sizes)

    def test_reap_error_after_effect_cannot_repeat_numeric_group_signal(self):
        real_popen, real_killpg = subprocess.Popen, os.killpg
        children, group_signals = [], []

        def launch(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            real_wait = proc.wait
            children.append((proc, real_wait))

            def interrupted_wait(*a, **k):
                real_wait(*a, **k)
                raise OSError("injected failure after actual leader reap")

            proc.wait = interrupted_wait
            return proc

        def group_signal(pid, sig):
            group_signals.append(pid)
            return real_killpg(pid, sig)

        try:
            with patch.object(capture.subprocess, "Popen", side_effect=launch), \
                    patch.object(capture.os, "killpg", group_signal):
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c", "raise SystemExit(7)"], timeout=3)
            self.assertEqual(caught.exception.code, "E_CAPTURE_CLEANUP")
            self.assertEqual(group_signals, [children[0][0].pid])
            self.assertEqual(children[0][0].returncode, -signal.SIGKILL if capture._DARWIN else 7)
        finally:
            for proc, real_wait in children:
                proc.wait = real_wait
                real_wait(timeout=3)

    def test_external_reaper_is_refused_without_signalling_lost_group_identity(self):
        real_terminate = capture._terminate
        signals = []

        def stolen_leader(proc, job=None):
            if capture._DARWIN:
                proc.kill()
            proc.wait(timeout=3)
            return real_terminate(proc, job)

        with patch.object(capture, "_terminate", side_effect=stolen_leader), \
                patch.object(capture.os, "killpg", side_effect=lambda *args: signals.append(args)):
            with self.assertRaises(capture.CaptureRejected) as caught:
                capture.run_bounded([sys.executable, "-c", "pass"], timeout=3)
        self.assertEqual(caught.exception.code, "E_CAPTURE_OWNERSHIP")
        self.assertEqual(signals, [])

    def test_primary_rejection_retains_failed_cleanup_without_a_second_attempt(self):
        real_terminate = capture._terminate
        attempts = []

        def cleanup_then_error(proc, job=None):
            attempts.append(proc.pid)
            real_terminate(proc, job)
            raise capture.CaptureRejected("E_CAPTURE_CLEANUP", "failure after actual cleanup")

        with patch.object(capture, "_terminate", side_effect=cleanup_then_error):
            with self.assertRaises(capture.CaptureRejected) as caught:
                capture.run_bounded([sys.executable, "-c", "import time;time.sleep(3)"],
                                    timeout=.05)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT")
        self.assertIn("E_CAPTURE_CLEANUP: failure after actual cleanup",
                      caught.exception.capture_error)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(caught.exception.capture.returncode, None if capture._DARWIN else -signal.SIGKILL)

    def test_missing_waitid_or_nondefault_sigchld_refuses_before_spawn(self):
        for target, replacement in ((capture.os, None), (capture.signal, signal.SIG_IGN)):
            name = "waitid" if target is capture.os else "getsignal"
            options = {"new": replacement} if name == "waitid" else {"return_value": replacement}
            with self.subTest(interface=name), patch.object(target, name, **options), \
                    patch.object(capture.subprocess, "Popen") as launch:
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c", "pass"], timeout=3)
                self.assertEqual(caught.exception.code, "E_CAPTURE_OWNERSHIP")
                launch.assert_not_called()

    def test_stopped_child_is_not_accepted_as_a_completed_capture(self):
        with self.assertRaises(capture.CaptureRejected) as caught:
            capture.run_bounded([sys.executable, "-c",
                "import os,signal;os.kill(os.getpid(),signal.SIGSTOP)"], timeout=.15)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT")
        self.assertEqual(caught.exception.capture.returncode, None if capture._DARWIN else -signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
