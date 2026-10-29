"""Adversarial Clang wrapper child-process termination regressions (POSIX only).

These tests cover children that remain in the compiler's own process group.
They do not certify a full cgroup, container or detached-daemon sandbox.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import clang_capture
from tools.c2hepta import UnsupportedC, _run_bounded_ast


@unittest.skipUnless(os.name == "posix", "POSIX process-group contract")
class ClangProcessGroupTermination(unittest.TestCase):
    def _check_descendant(self, *, overflow: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="hepta-clang-process-group-") as temp:
            root = Path(temp)
            ready = root / "child-ready"
            release = root / "release"
            survived = root / "child-survived"
            # The shell stays in the same process group as its compiler wrapper.
            # It can write only after the parent was terminated and the fixture
            # releases its barrier. This distinguishes kill(parent) from killpg.
            shell = (
                f"printf ready > {shlex.quote(str(ready))}; "
                f"while [ ! -e {shlex.quote(str(release))} ]; do sleep 0.05; done; "
                f"printf survived > {shlex.quote(str(survived))}"
            )
            wrapper = (
                "import pathlib, subprocess, sys, time\n"
                f"subprocess.Popen(['/bin/sh', '-c', {shell!r}], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
                "stderr=subprocess.DEVNULL)\n"
                "deadline = time.monotonic() + 3\n"
                f"while not pathlib.Path({str(ready)!r}).exists() and time.monotonic() < deadline:\n"
                "    time.sleep(0.01)\n"
                + (
                    "sys.stdout.buffer.write(b'x' * 131072)\n"
                    "sys.stdout.buffer.flush()\n"
                    "time.sleep(60)\n"
                    if overflow else "time.sleep(60)\n"
                )
            )
            try:
                if overflow:
                    with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_OUTPUT_SIZE"):
                        _run_bounded_ast(
                            [sys.executable, "-c", wrapper],
                            context="probe", max_stdout_bytes=64, timeout=5,
                        )
                else:
                    with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_TIMEOUT"):
                        _run_bounded_ast(
                            [sys.executable, "-c", wrapper],
                            context="probe", max_stdout_bytes=64, timeout=3,
                        )
                self.assertTrue(ready.is_file(), "compiler child never initialized")
            finally:
                # Release any leaked child so the regression fails without
                # leaving a waiting shell behind on a broken implementation.
                release.touch()
                time.sleep(0.6)
            self.assertFalse(survived.exists(), "compiler descendant survived termination")

    def test_stdout_overflow_kills_compiler_descendants(self):
        self._check_descendant(overflow=True)

    def test_timeout_kills_compiler_descendants(self):
        self._check_descendant(overflow=False)

    def test_normal_short_output_is_preserved(self):
        result = _run_bounded_ast(
            [sys.executable, "-c", "print('ok')"],
            context="probe", max_stdout_bytes=64, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b"ok")


    def test_exited_wrapper_cannot_leave_descendant_holding_capture_pipes(self):
        # The wrapper exits cleanly, but its child inherits the capture
        # handles. Shared file-backed capture may return successfully only
        # after group cleanup; it must retain the exact bounded input/output
        # and prevent the child from writing after we release its barrier.
        with tempfile.TemporaryDirectory(prefix="hepta-clang-orphan-pipes-") as temp:
            root = Path(temp)
            ready = root / "child-ready"
            release = root / "release"
            parent_id = root / "wrapper-pid"
            survived = root / "child-survived"
            shell = (
                f"printf '%s' \"$$\" > {shlex.quote(str(ready))}; "
                f"while [ ! -e {shlex.quote(str(release))} ]; do sleep 0.01; done; "
                f"printf survived > {shlex.quote(str(survived))}; printf late-output"
            )
            wrapper = (
                "import os, pathlib, subprocess, sys, time\n"
                f"pathlib.Path({str(parent_id)!r}).write_text(str(os.getpid()))\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stdout.buffer.flush()\n"
                f"subprocess.Popen(['/bin/sh', '-c', {shell!r}], stdin=subprocess.DEVNULL)\n"
                "deadline = time.monotonic() + 3\n"
                f"while not pathlib.Path({str(ready)!r}).exists() and time.monotonic() < deadline:\n"
                "    time.sleep(0.01)\n"
            )
            try:
                result = _run_bounded_ast(
                    [sys.executable, "-c", wrapper], context="probe",
                    max_stdout_bytes=64, timeout=5, input_text="admitted\r\n",
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"admitted\r\n")
                self.assertEqual(result.stderr, b"")
                self.assertTrue(ready.is_file(), "compiler child never initialized")
                if Path("/proc").is_dir():
                    self.assertFalse((Path("/proc") / parent_id.read_text()).exists(),
                                     "capture leader was not reaped")
                    child_status = Path("/proc") / ready.read_text() / "status"
                    deadline = time.monotonic() + 1
                    child_state = None
                    while time.monotonic() < deadline:
                        try:
                            state = next(line for line in child_status.read_text().splitlines()
                                         if line.startswith("State:"))
                        except FileNotFoundError:
                            child_state = None
                            break
                        child_state = state.split()[1]
                        if child_state in {"Z", "X"}:
                            break
                        time.sleep(.01)
                    if child_state is not None:
                        self.assertIn(child_state, {"Z", "X"},
                                      "compiler descendant still runs after capture returned")
            finally:
                # A broken implementation gets a finite chance to reveal a
                # surviving writer, without leaving a waiting orphan behind.
                release.touch()
                time.sleep(.6)
            self.assertFalse(survived.exists(), "exited wrapper left a live compiler child")

    def test_cleanup_failure_never_becomes_a_successful_capture(self):
        # The real parent has exited but is deliberately still waitable under
        # WNOWAIT. This injection performs no cleanup: retain its real owner
        # and reap it in finally so the fixture cannot leave an orphan. The
        # test checks error propagation, not detection of every OS failure.
        real_terminate = clang_capture._terminate
        owner = {}

        def refuse_cleanup(proc, job=None):
            owner.update(process=proc, job=job)
            raise clang_capture.CaptureRejected("E_CAPTURE_CLEANUP", "injected cleanup failure")

        try:
            with patch.object(clang_capture, "_terminate", side_effect=refuse_cleanup):
                with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_CLEANUP"):
                    _run_bounded_ast([sys.executable, "-c", "print('ok')"], timeout=5)
        finally:
            if owner:
                real_terminate(owner["process"], owner["job"])
        self.assertTrue(owner, "the injected cleanup path must actually run")
        self.assertIsNotNone(owner["process"].returncode, "fixture child was not reaped")


if __name__ == "__main__":
    unittest.main()
