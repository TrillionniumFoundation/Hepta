"""Complete streamed AST framing must never accept an omitted suffix."""
import json
from hashlib import sha256
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import clang_capture, cpp_unique_capture, darwin_capture
from hepta.clang_capture import CaptureRejected
from hepta.cpp_unique_capture import _Objects, stream_ast


class UniqueCaptureTests(unittest.TestCase):
    def parse(self, raw, width):
        framing, nodes = _Objects(), []
        for offset in range(0, len(raw), width):
            nodes.extend(framing.feed(raw[offset:offset + width]))
        framing.close()
        return nodes

    def test_every_chunk_boundary_preserves_escaped_fields_and_full_census(self):
        nodes = [{"kind": "VarDecl", "name": 'quote\\"[]{}λ', "value": 7},
                 {"kind": "NamespaceDecl", "inner": [{"kind": "FunctionDecl", "name": "later"}]}]
        raw = json.dumps({"id": "0x1", "kind": "TranslationUnitDecl", "loc": {}, "range": {}, "inner": nodes}).encode()
        for width in range(1, len(raw) + 1):
            self.assertEqual(self.parse(raw, width), nodes)

    def test_truncation_extra_suffix_and_extra_array_separator_reject(self):
        raw = b'{"id":"0x1","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl"}]}'
        for bad in (raw[:-1], raw[:-2], raw + b'{}', raw.replace(b'}]}', b'},]}'),
                    raw.replace(b'}]}', b'}{"kind":"VarDecl"}]}')):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                self.parse(bad, 3)

    def test_duplicate_field_unknown_root_and_nonfinite_value_reject(self):
        for raw in (b'{"id":"x","kind":"TranslationUnitDecl","kind":"TranslationUnitDecl","inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","unaccounted":1,"inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","kind":"FunctionDecl"}]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","x":1e999}]}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw, 5)

    def test_oversized_header_and_nonfinite_metadata_reject(self):
        for bad in (b'{"id":"' + b"x" * 65536 + b'","kind":"TranslationUnitDecl","inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","loc":{"offset":1e999},"inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","loc":{"offset":NaN},"inner":[]}'):
            for width in (11, len(bad)):
                with self.subTest(width=width), self.assertRaises(ValueError):
                    self.parse(bad, width)

    def test_total_value_and_subtree_budgets_fail_closed(self):
        raw = b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"X","name":"a"},{"kind":"Y","name":"b"}]}'
        with patch("hepta.cpp_unique_capture.MAX_AST_VALUES", 4), self.assertRaisesRegex(ValueError, "value/depth"):
            self.parse(raw, 8)
        with patch("hepta.cpp_unique_capture.MAX_OBJECT_BYTES", 10), self.assertRaisesRegex(ValueError, "subtree"):
            self.parse(raw, 8)

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "fork") and hasattr(os, "pidfd_open"),
                         "Actual Linux pidfd/process-group cleanup required")
    def test_timeout_cleans_descendant_after_parent_exits(self):
        script = '''import os, sys, time
from pathlib import Path
child = os.fork()
if child == 0:
    Path("child.pid").write_text(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
while not Path("child.pid").exists():
    time.sleep(0.001)
sys.stdout.write('{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","name":"probe"}]}')
sys.stdout.flush()
Path("parent-exited").write_text("yes")
os._exit(0)
'''
        with tempfile.TemporaryDirectory(prefix="hepta-ast-child-") as directory:
            receipt, handles = {}, []
            try:
                with patch("hepta.cpp_unique_capture.MAX_AST_SECONDS", 1), self.assertRaisesRegex(ValueError, "timeout"):
                    for node in stream_ast([sys.executable, "-c", script], cwd=directory, source=None, receipt=receipt):
                        self.assertEqual(node["name"], "probe")
                        child = int((Path(directory) / "child.pid").read_text())
                        handles.append(os.pidfd_open(child))
                self.assertEqual(receipt, {})
                self.assertTrue((Path(directory) / "parent-exited").exists())
                self.assertEqual(len(handles), 1)
                # A pidfd observes this exact namespace-local child even when
                # /proc is mounted from a different PID namespace. Readability
                # indicates termination regardless of asynchronous reaping.
                poller = select.poll()
                poller.register(handles[0], select.POLLIN)
                self.assertTrue(poller.poll(2000), "Owned capture descendant remains live")
            finally:
                for handle in handles:
                    os.close(handle)


@unittest.skipUnless(os.name == "posix", "Streaming capture requires a POSIX process owner")
class UniqueCaptureResourceTests(unittest.TestCase):
    """Real streams exercise caller ownership independently of AST grammar."""

    raw = b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","name":"probe"}]}'

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hepta-ast-owner-")
        self.addCleanup(directory.cleanup)
        self.directory = directory.name
        self.receipt = {}
        deadline = patch.object(cpp_unique_capture, "MAX_AST_SECONDS", 5)
        deadline.start()
        self.addCleanup(deadline.stop)

    def stream(self, suffix="", *, raw=None):
        payload = self.raw if raw is None else raw
        script = ("import os, sys, time\nfrom pathlib import Path\n"
                  f"sys.stdout.buffer.write({payload!r})\nsys.stdout.flush()\n" + suffix)
        return stream_ast([sys.executable, "-c", script], cwd=self.directory,
                          source=None, receipt=self.receipt)

    def track_cleanup(self, *, after=None):
        original = cpp_unique_capture._terminate
        calls = []

        def terminate(process, owner=None):
            calls.append((process, owner))
            self.assertIsNone(process.returncode, "Leader was reaped before its group signal")
            self.assertEqual(self.receipt, {}, "Receipt was published before cleanup")
            original(process, owner)
            if after is not None:
                raise after

        return calls, patch.object(cpp_unique_capture, "_terminate", side_effect=terminate)

    def assert_compiler_status(self, calls, status):
        self.assertEqual(len(calls), 1)
        process, owner = calls[0]
        if owner is None:
            self.assertEqual(process.returncode, status)
        else:
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertEqual(owner.returncode, status)

    def test_complete_stream_keeps_leader_owned_until_cleanup_and_receipt_follows(self):
        calls, cleanup = self.track_cleanup()
        with cleanup:
            self.assertEqual(list(self.stream()), [{"kind": "VarDecl", "name": "probe"}])
        self.assert_compiler_status(calls, 0)
        process, owner = calls[0]
        self.assertTrue(process.stdout.closed)
        self.assertEqual(self.receipt["sha256"], sha256(self.raw).hexdigest())
        self.assertEqual(self.receipt["bytes"], len(self.raw))
        self.assertEqual(self.receipt["top_level_objects"], 1)
        self.assertTrue(self.receipt["complete_stream"])
        self.assertFalse(self.receipt["raw_ast_retained"])

    def test_stdout_eof_does_not_substitute_for_compiler_completion(self):
        calls, cleanup = self.track_cleanup()
        suffix = 'os.close(1)\ntime.sleep(0.05)\nPath("completed").write_text("yes")\nos._exit(0)\n'
        with cleanup:
            list(self.stream(suffix))
        self.assert_compiler_status(calls, 0)
        self.assertEqual((Path(self.directory) / "completed").read_text(), "yes")
        self.assertTrue(self.receipt["complete_stream"])

    def test_eof_exit_deadline_remains_separate_from_total_capture_budget(self):
        calls, cleanup = self.track_cleanup()
        # Both process owners must expose compiler EOF before its exit status.
        # A short seam tests the original five-second phase limit without a
        # slow test or replacing the real producer/owner with a process mock.
        with (cleanup,
              patch.object(cpp_unique_capture, "_EXIT_WAIT_SECONDS", 0.05),
              self.assertRaisesRegex(ValueError, "Compiler exit timeout after complete AST EOF")):
            list(self.stream("os.close(1)\ntime.sleep(60)\n"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
        self.assertTrue(calls[0][0].stdout.closed)
        self.assertEqual(self.receipt, {})

    def test_nonzero_compiler_exit_rejects_after_cleanup_without_receipt(self):
        calls, cleanup = self.track_cleanup()
        with cleanup, self.assertRaisesRegex(ValueError, "Clang returned 7: compiler failed"):
            list(self.stream('sys.stderr.write("compiler failed")\nsys.stderr.flush()\nos._exit(7)\n'))
        self.assert_compiler_status(calls, 7)
        self.assertEqual(self.receipt, {})

    def test_truncated_stream_rejects_with_one_cleanup_and_no_receipt(self):
        calls, cleanup = self.track_cleanup()
        with cleanup, self.assertRaisesRegex(ValueError, "Truncated or trailing"):
            list(self.stream(raw=self.raw[:-1]))
        self.assert_compiler_status(calls, 0)
        self.assertEqual(self.receipt, {})

    def test_post_effect_cleanup_failure_never_retries_or_publishes_receipt(self):
        refused = CaptureRejected("E_CAPTURE_CLEANUP", "post-effect cleanup refusal")
        calls, cleanup = self.track_cleanup(after=refused)
        with cleanup, self.assertRaises(CaptureRejected) as caught:
            list(self.stream())
        self.assertIs(caught.exception, refused)
        self.assert_compiler_status(calls, 0)
        self.assertTrue(calls[0][0].stdout.closed)
        self.assertEqual(self.receipt, {})

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "fork") and hasattr(os, "pidfd_open"),
                         "Actual Linux pidfd/process-group cleanup required")
    def test_generator_close_terminates_live_leader_and_descendant_without_receipt(self):
        script = '''import os, sys, time
from pathlib import Path
child = os.fork()
if child == 0:
    Path("child.pid").write_text(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
while not Path("child.pid").exists():
    time.sleep(0.001)
sys.stdout.write('{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","name":"probe"}]}')
sys.stdout.flush()
time.sleep(60)
'''
        calls, cleanup = self.track_cleanup()
        iterator = stream_ast([sys.executable, "-c", script], cwd=self.directory,
                              source=None, receipt=self.receipt)
        handle = None
        try:
            with cleanup:
                self.assertEqual(next(iterator)["name"], "probe")
                child = int((Path(self.directory) / "child.pid").read_text())
                handle = os.pidfd_open(child)
                iterator.close()
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
            self.assertTrue(calls[0][0].stdout.closed)
            self.assertEqual(self.receipt, {})
            poller = select.poll()
            poller.register(handle, select.POLLIN)
            self.assertTrue(poller.poll(2000), "Early-close capture descendant remains live")
        finally:
            iterator.close()
            if handle is not None:
                os.close(handle)

    def test_generator_close_surfaces_post_effect_cleanup_failure(self):
        refused = CaptureRejected("E_CAPTURE_CLEANUP", "early-close cleanup refusal")
        calls, cleanup = self.track_cleanup(after=refused)
        iterator = self.stream("time.sleep(60)\n")
        try:
            with cleanup:
                self.assertEqual(next(iterator)["name"], "probe")
                with self.assertRaises(CaptureRejected) as caught:
                    iterator.close()
            self.assertIs(caught.exception, refused)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
            self.assertEqual(self.receipt, {})
        finally:
            iterator.close()

    def test_original_interruption_survives_cleanup_failure_with_note(self):
        interruption = KeyboardInterrupt("caller interruption")
        refused = CaptureRejected("E_CAPTURE_CLEANUP", "interrupted cleanup refusal")
        calls, cleanup = self.track_cleanup(after=refused)
        iterator = self.stream("time.sleep(60)\n")
        try:
            with cleanup:
                self.assertEqual(next(iterator)["name"], "probe")
                with self.assertRaises(KeyboardInterrupt) as caught:
                    iterator.throw(interruption)
            self.assertIs(caught.exception, interruption)
            self.assertTrue(any("interrupted cleanup refusal" in note for note in interruption.__notes__))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
            self.assertEqual(self.receipt, {})
        finally:
            iterator.close()

    def test_real_guardian_pipe_eof_preserves_compiler_status(self):
        # Exercise the actual guardian on this POSIX host. This is a mechanism
        # test, not a claim of execution on macOS when the host is Linux.
        for status in (0, 7):
            with self.subTest(status=status):
                self.receipt.clear()
                calls, cleanup = self.track_cleanup()
                with patch.object(clang_capture, "_DARWIN", True), cleanup:
                    if status:
                        with self.assertRaisesRegex(ValueError, "Clang returned 7"):
                            list(self.stream(f"os._exit({status})\n"))
                    else:
                        list(self.stream("os._exit(0)\n"))
                self.assertEqual(len(calls), 1)
                process, owner = calls[0]
                self.assertEqual(process.returncode, -signal.SIGKILL)
                self.assertEqual(owner.returncode, status)
                self.assertEqual(owner._status_fd, -1)
                self.assertTrue(process.stdout.closed)
                self.assertEqual(bool(self.receipt), status == 0)

    def test_guardian_status_close_failure_prevents_receipt(self):
        original_close = darwin_capture.GuardianOwner.close
        refused = OSError("post-effect status close refusal")

        def close(owner):
            original_close(owner)
            raise refused

        calls, cleanup = self.track_cleanup()
        with (patch.object(clang_capture, "_DARWIN", True), cleanup,
              patch.object(darwin_capture.GuardianOwner, "close", close),
              self.assertRaises(OSError) as caught):
            list(self.stream())
        self.assertIs(caught.exception, refused)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
        self.assertEqual(calls[0][1]._status_fd, -1)
        self.assertEqual(self.receipt, {})

    def test_guardian_startup_interruption_is_inside_owned_cleanup(self):
        original_launch = darwin_capture.launch
        interruption = KeyboardInterrupt("post-spawn handoff interruption")

        def launch(*args, **kwargs):
            process, owner = original_launch(*args, **kwargs)
            owner.startup_error = interruption
            return process, owner

        calls, cleanup = self.track_cleanup()
        with (patch.object(clang_capture, "_DARWIN", True), cleanup,
              patch.object(darwin_capture, "launch", side_effect=launch),
              self.assertRaises(KeyboardInterrupt) as caught):
            list(self.stream())
        self.assertIs(caught.exception, interruption)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].returncode, -signal.SIGKILL)
        self.assertEqual(calls[0][1]._status_fd, -1)
        self.assertEqual(self.receipt, {})

    def test_missing_nonreaping_ownership_rejects_before_spawn(self):
        refused = CaptureRejected("E_CAPTURE_OWNERSHIP", "non-reaping observation unavailable")
        with (patch.object(clang_capture, "_require_posix_ownership", side_effect=refused),
              patch.object(cpp_unique_capture.subprocess, "Popen") as spawn,
              self.assertRaises(CaptureRejected) as caught):
            list(self.stream())
        self.assertIs(caught.exception, refused)
        spawn.assert_not_called()
        self.assertEqual(self.receipt, {})


if __name__ == "__main__":
    unittest.main()
