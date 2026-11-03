"""JSONL admission must depend on line bytes, not pipe read batching."""
import sys
import os
import selectors
from contextlib import ExitStack
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import hia_agent_codex_transport as transport


class JsonlFramingTests(unittest.TestCase):
    def run_wire(self, wire, limit=32, *, fragment=None, drain_only=False):
        seen = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration = {"transport": {"stdout_limit_bytes": 4096,
                "stderr_limit_bytes": 4096, "max_jsonl_line_bytes": limit}}
            with ExitStack() as stack:
                stack.enter_context(patch.object(transport, "protocol", return_value=configuration))
                if fragment is not None:
                    original_read = os.read
                    stack.enter_context(patch.object(transport.os, "read",
                        side_effect=lambda fd, count: original_read(fd, min(count, fragment))))
                if drain_only:
                    # Force the first poll to observe leader exit before any
                    # bytes are read; all framing then occurs in final drain.
                    original_selector = selectors.DefaultSelector
                    selector = original_selector()
                    original_select = selector.select
                    first = [True]
                    def select(timeout=None):
                        if first.pop() if first else False:
                            return []
                        return original_select(timeout)
                    stack.enter_context(patch.object(selector, "select", side_effect=select))
                    stack.enter_context(patch.object(transport.selectors, "DefaultSelector", return_value=selector))
                    original_waitid = os.waitid
                    stack.enter_context(patch.object(transport.os, "waitid", side_effect=lambda kind, pid, flags:
                        original_waitid(kind, pid, flags if pid == os.getpid() else flags & ~os.WNOHANG)))
                result = transport.run_owned(
                    [sys.executable, "-c", "import os; os.write(1," + repr(wire) + ")"],
                    root, root / "transport", wall_seconds=3, on_line=seen.append)
            self.assertTrue(result["cleanup_confirmed"], result)
            self.assertEqual((root / "transport/stdout.raw").read_bytes(), wire)
        return result, seen

    def test_batched_short_lines_are_not_one_oversized_line(self):
        wire = (b'"' + b'a' * 20 + b'"\n') * 3
        result, seen = self.run_wire(wire)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(seen, wire.splitlines())

    def test_fragmented_line_and_newline_in_separate_reads(self):
        wire = (b'"' + b'a' * 30 + b'"\n') * 2
        result, seen = self.run_wire(wire, fragment=1)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(seen, wire.splitlines())

    def test_final_drain_batches_are_framed_identically(self):
        wire = (b'"' + b'a' * 20 + b'"\n') * 3
        result, seen = self.run_wire(wire, drain_only=True)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(seen, wire.splitlines())

    def test_exact_limit_with_newline_is_accepted(self):
        wire = b'"' + b'a' * 30 + b'"\n'
        result, seen = self.run_wire(wire)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(seen, wire.splitlines())

    def test_oversized_complete_line_is_rejected(self):
        result, seen = self.run_wire(b'a' * 33 + b'\n')
        self.assertEqual(result["status"], "jsonl_line_limit")
        self.assertEqual(seen, [])

    def test_oversized_unterminated_line_is_rejected(self):
        result, seen = self.run_wire(b'a' * 33)
        self.assertEqual(result["status"], "jsonl_line_limit")
        self.assertEqual(seen, [])

    def test_short_unterminated_tail_after_batched_lines_is_accepted(self):
        wire = (b'"' + b'a' * 20 + b'"\n') * 3 + b'"tail"'
        result, seen = self.run_wire(wire)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(seen, wire.splitlines())

    def test_oversized_tail_keeps_preceding_valid_line(self):
        result, seen = self.run_wire(b'"ok"\n' + b'a' * 33)
        self.assertEqual(result["status"], "jsonl_line_limit")
        self.assertEqual(seen, [b'"ok"'])

    def test_empty_line_still_rejected(self):
        result, seen = self.run_wire(b'"ok"\n\n')
        self.assertEqual(result["status"], "protocol_violation")
        self.assertEqual(result["event_error"], "E_PILOT_EMPTY_EVENT_LINE")
        self.assertEqual(seen, [b'"ok"'])


if __name__ == "__main__":
    unittest.main()
