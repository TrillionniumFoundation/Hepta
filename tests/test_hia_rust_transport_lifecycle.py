"""Real process-group ownership tests for both Rust shadow protocols.

Each fixture runs in a separate Linux child subreaper, so the test can
observe and reap the producer's orphaned child without changing the test
runner's process-wide child disposition. No Rust claims are mocked here.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_rust_crosscheck import HIARustCrosscheckRejected, _run_bounded_shadow


_PRODUCER = r'''
import json
import os
from pathlib import Path
import sys
import time

mode, record = sys.argv[1:]
sys.stdin.buffer.read()
ready_r, ready_w = os.pipe()
child = os.fork()
if child == 0:
    os.close(ready_r)
    if mode != "inherited_pipe":
        for fd in (0, 1, 2):
            os.close(fd)
    os.write(ready_w, b"1")
    os.close(ready_w)
    time.sleep(30)
    os._exit(0)
os.close(ready_w)
assert os.read(ready_r, 1) == b"1"
os.close(ready_r)
Path(record).write_text(json.dumps({"leader": os.getpid(), "child": child,
                                  "group": os.getpgrp()}))
if mode == "timeout":
    time.sleep(30)
elif mode == "closed_pipe_timeout":
    os.close(1)
    os.close(2)
    time.sleep(30)
elif mode == "oversize":
    os.write(1, b"x" * 131072)
elif mode == "stderr":
    os.write(2, b"unexpected diagnostic\n")
else:
    os.write(1, b"ok\n")
os._exit(7 if mode == "failure" else 0)
'''


_OBSERVER = r'''
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch

from hepta.hia_rust_crosscheck import _run_bounded_shadow

# PR_SET_CHILD_SUBREAPER is process-local to this isolated observer. It
# gives the test waitpid evidence instead of mistaking a zombie for a
# still-running descendant or depending on the container's PID 1 reaper.
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "test child subreaper unavailable")
producer, mode, record, cleanup_failure = sys.argv[1:]
real_killpg, real_wait = os.killpg, subprocess.Popen.wait
signals = []

def kill_owned_group(pgid, sig):
    # A reaped leader would raise ECHILD here. Inspecting the real child
    # with WNOWAIT demonstrates that killpg cannot target a reused ID.
    status = os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
    signals.append({"group": pgid, "signal": sig,
                    "exited_unreaped_leader": status is not None})
    result = real_killpg(pgid, sig)
    if cleanup_failure == "signal":
        raise ProcessLookupError("group signal completion is unconfirmed")
    return result

def uncertain_reap(process, timeout=None):
    real_wait(process, timeout=timeout)
    # Simulate a failure reported after the actual wait consumed the PID.
    # No cleanup retry may signal that numeric group after this point.
    raise subprocess.TimeoutExpired(process.args, timeout)

started = time.monotonic()
observed = {}
try:
    with patch("hepta.hia_rust_crosscheck.os.killpg", side_effect=kill_owned_group):
        with patch.object(subprocess.Popen, "wait",
                          uncertain_reap if cleanup_failure == "reap" else real_wait):
            stdout, stderr, returncode = _run_bounded_shadow(
                [sys.executable, producer, mode, record], b"request", 0.4,
                maximum_output=1024)
            observed.update(stdout=stdout.decode(), stderr=stderr.decode(),
                            returncode=returncode)
except Exception as error:
    observed.update(error_type=type(error).__name__, error=str(error))
observed.update(elapsed_seconds=time.monotonic() - started, signals=signals)
identity = json.loads(Path(record).read_text())
observed.update(identity)
try:
    os.waitpid(identity["leader"], os.WNOHANG)
    observed["leader_reaped"] = False
except ChildProcessError:
    observed["leader_reaped"] = True

deadline = time.monotonic() + 2
observed["descendant_survived"] = True
while time.monotonic() < deadline:
    pid, status = os.waitpid(identity["child"], os.WNOHANG)
    if pid:
        observed["descendant_survived"] = False
        observed["descendant_returncode"] = os.waitstatus_to_exitcode(status)
        break
    time.sleep(0.005)
if observed["descendant_survived"]:
    # Teardown for the regression's pre-fix failure also kills and reaps
    # the known still-owned direct child; the test must leave no sleeper.
    os.kill(identity["child"], signal.SIGKILL)
    os.waitpid(identity["child"], 0)
print(json.dumps(observed, sort_keys=True))
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "waitid"),
                     "Real shadow process ownership requires Linux waitid; NOT qualified")
class RustShadowTransportLifecycle(unittest.TestCase):
    def observe(self, mode, *, cleanup_failure="none"):
        with tempfile.TemporaryDirectory(prefix="hepta-shadow-lifecycle-") as temporary:
            root = Path(temporary)
            producer = root / "producer.py"
            producer.write_text(_PRODUCER)
            run = subprocess.run(
                [sys.executable, "-c", _OBSERVER, str(producer), mode,
                 str(root / "identity.json"), cleanup_failure],
                cwd=Path(__file__).resolve().parents[1], capture_output=True,
                text=True, timeout=10, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, "")
            result = json.loads(run.stdout)
        self.assertEqual(result["leader"], result["group"], result)
        self.assertTrue(result["leader_reaped"], result)
        self.assertFalse(result["descendant_survived"], result)
        self.assertEqual(result["descendant_returncode"], -signal.SIGKILL, result)
        self.assertEqual(len(result["signals"]), 1, result)
        self.assertEqual(result["signals"][0]["group"], result["group"], result)
        self.assertEqual(result["signals"][0]["signal"], signal.SIGKILL, result)
        self.assertLess(result["elapsed_seconds"], 3, result)
        return result

    def test_exited_leader_with_inherited_pipe_reaps_descendant_on_deadline(self):
        result = self.observe("inherited_pipe")
        self.assertEqual(result["error_type"], "HIARustCrosscheckRejected")
        self.assertIn("deadline", result["error"])
        self.assertTrue(result["signals"][0]["exited_unreaped_leader"])

    def test_success_nonzero_and_stderr_reap_descendant_before_returning(self):
        for mode in ("success", "failure", "stderr"):
            with self.subTest(mode=mode):
                result = self.observe(mode)
                self.assertNotIn("error", result)
                self.assertEqual(result["returncode"], 7 if mode == "failure" else 0)
                self.assertEqual(result["stdout"], "" if mode == "stderr" else "ok\n")
                self.assertEqual(result["stderr"],
                                 "unexpected diagnostic\n" if mode == "stderr" else "")
                self.assertTrue(result["signals"][0]["exited_unreaped_leader"])

    def test_live_leader_deadline_with_open_or_closed_pipes_reaps_descendant(self):
        for mode in ("timeout", "closed_pipe_timeout"):
            with self.subTest(mode=mode):
                result = self.observe(mode)
                self.assertEqual(result["error_type"], "HIARustCrosscheckRejected")
                self.assertIn("deadline", result["error"])
                self.assertFalse(result["signals"][0]["exited_unreaped_leader"])

    def test_output_budget_violation_reaps_descendant(self):
        result = self.observe("oversize")
        self.assertEqual(result["error_type"], "HIARustCrosscheckRejected")
        self.assertIn("bounded output budget", result["error"])

    def test_unconfirmed_reap_never_qualifies_or_resignals_group(self):
        result = self.observe("success", cleanup_failure="reap")
        self.assertEqual(result["error_type"], "HIARustCrosscheckRejected")
        self.assertIn("cleanup", result["error"])
        self.assertTrue(result["signals"][0]["exited_unreaped_leader"])

    def test_unconfirmed_group_signal_never_qualifies_or_retries(self):
        result = self.observe("success", cleanup_failure="signal")
        self.assertEqual(result["error_type"], "HIARustCrosscheckRejected")
        self.assertIn("cleanup", result["error"])
        self.assertTrue(result["signals"][0]["exited_unreaped_leader"])

    def test_missing_wnowait_capability_rejects_before_spawn(self):
        with patch("hepta.hia_rust_crosscheck.os.waitid", None), \
                patch("hepta.hia_rust_crosscheck.subprocess.Popen") as launch:
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "WNOWAIT"):
                _run_bounded_shadow(["unused"], b"", 0.1)
            launch.assert_not_called()

    def test_unavailable_waitid_syscall_rejects_before_spawn(self):
        with patch("hepta.hia_rust_crosscheck.os.waitid",
                   side_effect=OSError(errno.ENOSYS, "not available")), \
                patch("hepta.hia_rust_crosscheck.subprocess.Popen") as launch:
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "WNOWAIT"):
                _run_bounded_shadow(["unused"], b"", 0.1)
            launch.assert_not_called()

    def test_external_sigchld_reaper_rejects_before_spawn(self):
        with patch("hepta.hia_rust_crosscheck.signal.getsignal", return_value=signal.SIG_IGN), \
                patch("hepta.hia_rust_crosscheck.subprocess.Popen") as launch:
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "SIGCHLD"):
                _run_bounded_shadow(["unused"], b"", 0.1)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
