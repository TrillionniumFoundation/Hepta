"""Actual guardian children on every supported POSIX test host.

Linux exercises the same Darwin owner implementation through its private host
dispatch seam. These runs do not claim macOS execution, synchronous descendant
reaping, or reproduction of Darwin's zombie-only process-group errno.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import clang_capture as capture
from hepta import darwin_capture as darwin


_POSIX_WAITID = (os.name == "posix" and callable(getattr(os, "waitid", None))
                 and all(hasattr(os, name) for name in
                         ("P_PID", "WEXITED", "WNOWAIT", "WNOHANG")))


@unittest.skipUnless(_POSIX_WAITID, "actual POSIX private process ownership required")
class DarwinGuardianTests(unittest.TestCase):
    def setUp(self):
        self.dispatch = patch.object(capture, "_DARWIN", True)
        self.dispatch.start()
        self.addCleanup(self.dispatch.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-darwin-guardian-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _helper(self, body: str) -> Path:
        path = self.root / "injected_guardian.py"
        path.write_text("import os,signal,sys,time\nfd=int(sys.argv[1])\n" + body)
        return path

    def test_live_guardian_and_actual_compiler_exit_status_are_distinct(self):
        real_launch, real_killpg = darwin.launch, os.killpg
        for code in (0, 7, 127, 128, 255, -signal.SIGTERM):
            owners, signals = [], []

            def launch(*args, **kwargs):
                pair = real_launch(*args, **kwargs)
                owners.append(pair)
                return pair

            def group_signal(pid, sig):
                # The direct child still runs; it is not the exited compiler.
                info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                signals.append((pid, sig, info, os.getpgid(pid)))
                return real_killpg(pid, sig)

            command = [sys.executable, "-c",
                       "import os,signal,sys;os.write(1,b'compiler\\r\\n');"
                       "code=int(sys.argv[1]);"
                       "os.kill(os.getpid(),-code) if code<0 else sys.exit(code)", str(code)]
            with self.subTest(code=code), patch.object(darwin, "launch", side_effect=launch), \
                    patch.object(capture.os, "killpg", side_effect=group_signal):
                result = capture.run_bounded(command, timeout=5)
            proc, owner = owners[0]
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.raw_stdout, b"compiler\r\n")
            self.assertEqual(signals, [(proc.pid, signal.SIGKILL, None, proc.pid)])
            self.assertEqual(proc.returncode, -signal.SIGKILL)
            self.assertEqual(owner.returncode, code)
            self.assertEqual(owner._status_fd, -1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(proc.pid, os.WNOHANG)

    def test_compiler_cannot_inherit_the_private_status_descriptor(self):
        real_popen = subprocess.Popen
        private_descriptors = []

        def launch(argv, **kwargs):
            descriptor, = kwargs["pass_fds"]
            private_descriptors.append(descriptor)
            argv = [str(descriptor) if part == "PRIVATE_STATUS_FD" else part for part in argv]
            return real_popen(argv, **kwargs)

        command = [sys.executable, "-c",
                   "import os,sys\ntry: os.fstat(int(sys.argv[1]))\n"
                   "except OSError: print('closed')\nelse: print('inherited')\n", "PRIVATE_STATUS_FD"]
        with patch.object(darwin.subprocess, "Popen", side_effect=launch):
            result = capture.run_bounded(command, timeout=5)
        self.assertEqual(len(private_descriptors), 1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "closed\n")

    def test_stream_readers_reach_eof_while_guardian_remains_alive(self):
        capture._require_posix_ownership()
        proc, owner = darwin.launch(
            [sys.executable, "-c", "import os;os.write(1,b'out');os.write(2,b'err')"],
            cwd=None, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        buffers, ended = [bytearray(), bytearray()], [False, False]
        try:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
            deadline = time.monotonic() + 2
            complete = False
            while time.monotonic() < deadline:
                complete = capture._child_exited(proc, owner)
                for index, stream in enumerate((proc.stdout, proc.stderr)):
                    if ended[index]:
                        continue
                    try:
                        chunk = os.read(stream.fileno(), 64)
                    except BlockingIOError:
                        continue
                    if chunk:
                        buffers[index].extend(chunk)
                    else:
                        ended[index] = True
                if complete and all(ended):
                    break
                time.sleep(.005)
            self.assertTrue(complete, "compiler did not provide a complete status frame")
            self.assertEqual(ended, [True, True], "guardian retained a standard-stream writer")
            self.assertEqual(buffers, [b"out", b"err"])
            self.assertIsNone(os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG))
            self.assertEqual(owner.returncode, 0)
        finally:
            capture._terminate(proc, owner)
            owner.close()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, -signal.SIGKILL)

    def test_compiler_can_close_stdout_before_its_exit_status_is_ready(self):
        capture._require_posix_ownership()
        marker = self.root / "compiler-closed-stdout"
        pending_marker = self.root / "compiler-closed-stdout.tmp"
        command = ("import os,pathlib,time;os.write(1,b'prefix');os.close(1);"
                   f"pathlib.Path({str(pending_marker)!r}).write_text(str(os.getpid()));"
                   f"os.replace({str(pending_marker)!r},{str(marker)!r});time.sleep(30)")
        proc, owner = darwin.launch([sys.executable, "-c", command], cwd=None,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        payload, ended = bytearray(), False
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    chunk = os.read(proc.stdout.fileno(), 64)
                except BlockingIOError:
                    time.sleep(.005)
                    continue
                if chunk:
                    payload.extend(chunk)
                else:
                    ended = True
                    if marker.exists():
                        break
                    time.sleep(.005)
            self.assertTrue(marker.exists(), "actual compiler never closed its stdout")
            self.assertTrue(ended, "guardian masked a running compiler's real stdout EOF")
            self.assertEqual(payload, b"prefix")
            self.assertEqual(os.getpgid(int(marker.read_text())), proc.pid)
            self.assertFalse(capture._child_exited(proc, owner))
            self.assertIsNone(owner.returncode)
            self.assertIsNone(os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG))
        finally:
            capture._terminate(proc, owner)
            owner.close()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, -signal.SIGKILL)

    def test_actual_compiler_launch_errno_is_retained(self):
        with self.assertRaises(capture.CaptureRejected) as caught:
            capture.run_bounded([str(self.root / "missing-compiler")], timeout=5)
        self.assertEqual(caught.exception.code, "E_CAPTURE_EXEC")
        self.assertEqual(caught.exception.__cause__.errno, errno.ENOENT)
        self.assertIn(f"[Errno {errno.ENOENT}]", str(caught.exception))
        self.assertIsNone(caught.exception.capture.returncode)

    def test_malformed_extra_and_forged_status_frames_refuse(self):
        valid = darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 0, 0, 0, 0)
        frames = [valid[:7], valid + b"extra", b"BAD!" + valid[4:],
                  darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 1, 0, 0, 0),
                  darwin._FRAME.pack(darwin._MAGIC, 99, 0, 0, 0, 0),
                  darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 0, 0, 256, 0),
                  darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 0, 0, 0, errno.EIO)]
        for frame in frames:
            helper = self._helper(f"os.write(fd,{frame!r});os.close(fd)\nwhile True: signal.pause()\n")
            with self.subTest(frame=frame), patch.object(darwin, "_GUARDIAN_SCRIPT", helper):
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c", "pass"], timeout=5)
            self.assertEqual(caught.exception.code, "E_CAPTURE_GUARDIAN")
            self.assertIsNone(caught.exception.capture.returncode)

    def test_complete_frame_without_writer_eof_cannot_complete_capture(self):
        frame = darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 0, 0, 7, 0)
        helper = self._helper(f"os.write(fd,{frame!r})\nwhile True: signal.pause()\n")
        with patch.object(darwin, "_GUARDIAN_SCRIPT", helper):
            with self.assertRaises(capture.CaptureRejected) as caught:
                capture.run_bounded([sys.executable, "-c", "pass"], timeout=.3)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT")
        self.assertIsNone(caught.exception.capture.returncode)

    def test_unexpected_guardian_exit_is_refused_even_with_a_complete_frame(self):
        real_child_exited = capture._child_exited

        def observe_after_exit(proc, job):
            deadline = time.monotonic() + 3
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                if time.monotonic() >= deadline:
                    self.fail("injected guardian did not actually exit")
                time.sleep(.001)
            return real_child_exited(proc, job)

        frame = darwin._FRAME.pack(darwin._MAGIC, darwin._EXIT, 0, 0, 0, 0)
        for payload in (b"", frame):
            helper = self._helper(f"os.write(fd,{payload!r});os.close(fd);os._exit(0)\n")
            with self.subTest(payload=payload), patch.object(darwin, "_GUARDIAN_SCRIPT", helper), \
                    patch.object(capture, "_child_exited", side_effect=observe_after_exit):
                with self.assertRaises(capture.CaptureRejected) as caught:
                    capture.run_bounded([sys.executable, "-c", "pass"], timeout=5)
            self.assertEqual(caught.exception.code, "E_CAPTURE_GUARDIAN")
            self.assertIsNone(caught.exception.capture.returncode)

    def test_writer_close_error_after_spawn_keeps_real_guardian_owned(self):
        real_popen, real_close, real_killpg = subprocess.Popen, os.close, os.killpg
        cases = [(OSError(errno.EINTR, "injected close error after actual close"), False),
                 (KeyboardInterrupt("interrupted writer close"), False),
                 (SystemExit(23), False),
                 (KeyboardInterrupt("interrupted close with cleanup refusal"), True)]
        for injected, deny_cleanup in cases:
            children, descriptor, close_attempts, group_signals = [], [], [], []
            armed = False

            def launch(argv, **kwargs):
                nonlocal armed
                descriptor[:] = list(kwargs["pass_fds"])
                proc = real_popen(argv, **kwargs)
                children.append(proc)
                armed = True
                return proc

            def close(fd):
                nonlocal armed
                if descriptor and fd == descriptor[0] and armed:
                    close_attempts.append(fd)
                    armed = False
                    real_close(fd)
                    raise injected
                return real_close(fd)

            def group_signal(pid, sig):
                group_signals.append(pid)
                if deny_cleanup:
                    raise PermissionError(errno.EPERM, "injected cleanup denial")
                return real_killpg(pid, sig)

            expected = capture.CaptureRejected if isinstance(injected, OSError) else type(injected)
            with self.subTest(interruption=type(injected).__name__, cleanup_denied=deny_cleanup), \
                    patch.object(darwin.subprocess, "Popen", side_effect=launch), \
                    patch.object(darwin.os, "close", side_effect=close), \
                    patch.object(capture.os, "killpg", side_effect=group_signal):
                with self.assertRaises(expected) as caught:
                    capture.run_bounded([sys.executable, "-c", "pass"], timeout=5)
            if isinstance(injected, OSError):
                self.assertEqual(caught.exception.code, "E_CAPTURE_GUARDIAN")
                self.assertIn("status writer close failed", str(caught.exception))
            else:
                self.assertIs(caught.exception, injected)
            if deny_cleanup:
                notes = "\n".join(caught.exception.__notes__)
                self.assertIn("E_CAPTURE_CLEANUP", notes)
                self.assertIn(f"errno={errno.EPERM}", notes)
            self.assertEqual(close_attempts, descriptor)
            self.assertEqual(group_signals, [children[0].pid])
            self.assertEqual(children[0].returncode, -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)

    def test_group_permission_error_keeps_errno_and_never_retries(self):
        with patch.object(capture.os, "killpg", side_effect=PermissionError(errno.EPERM, "injected group denial")) as kill_group:
            with self.assertRaises(capture.CaptureRejected) as caught:
                capture.run_bounded([sys.executable, "-c", "pass"], timeout=5)
        self.assertEqual(caught.exception.code, "E_CAPTURE_CLEANUP")
        self.assertEqual(caught.exception.__cause__.errno, errno.EPERM)
        self.assertIn(f"errno={errno.EPERM}", str(caught.exception))
        self.assertEqual(kill_group.call_count, 1)
        self.assertEqual(caught.exception.capture.returncode, 0)

    def test_timeout_and_overflow_terminate_the_owned_descendant_group(self):
        for mode in ("timeout", "overflow"):
            ready, release, survived = (self.root / f"{mode}-{part}" for part in ("ready", "release", "survived"))
            child = ("import pathlib,time\n" f"pathlib.Path({str(ready)!r}).write_text('ready')\n"
                     "deadline=time.monotonic()+5\n" f"while not pathlib.Path({str(release)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                     f"if pathlib.Path({str(release)!r}).exists(): pathlib.Path({str(survived)!r}).write_text('alive')\n")
            compiler = ("import pathlib,subprocess,sys,time\n"
                        f"subprocess.Popen([sys.executable,'-c',{child!r}],stdin=subprocess.DEVNULL)\n"
                        "deadline=time.monotonic()+3\n" f"while not pathlib.Path({str(ready)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                        + ("print('x'*64,flush=True)\n" if mode == "overflow" else "") + "time.sleep(5)\n")
            try:
                with self.subTest(mode=mode):
                    with self.assertRaises(capture.CaptureRejected) as caught:
                        capture.run_bounded([sys.executable, "-c", compiler],
                                            timeout=1.5 if mode == "timeout" else 4, stdout_limit=8)
                    self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT" if mode == "timeout" else "E_CAPTURE_OUTPUT_SIZE")
                    self.assertIsNone(caught.exception.capture.returncode)
                    self.assertTrue(ready.exists(), "actual compiler descendant did not start")
            finally:
                release.touch()
                time.sleep(.3)
            self.assertFalse(survived.exists(), "a same-group descendant wrote after its barrier was released")


if __name__ == "__main__":
    unittest.main()
