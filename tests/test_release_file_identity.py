"""Fail-closed local evidence-file identity regressions for the unified release.

These are file-boundary checks only, not native compiler or P0-P7 qualification.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import release_check


class ReleaseEvidenceIdentityTests(unittest.TestCase):
    def test_fresh_regular_file_is_read_from_one_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            payload = b'{"status":"passed","samples":1}'
            path.write_bytes(payload)
            read, state = release_check._read_regular_evidence(path)
            self.assertEqual(read, payload)
            self.assertEqual(state, release_check._evidence_state(path))

    def test_replaced_report_has_new_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_bytes(b'{"status":"passed","old":true}')
            previous = release_check._evidence_state(path)
            replacement = Path(directory) / "replacement.json"
            replacement.write_bytes(b'{"status":"passed","new":true}')
            os.replace(replacement, path)
            payload, current = release_check._read_regular_evidence(path)
            self.assertNotEqual(current, previous)
            self.assertIn(b'"new":true', payload)

    def test_untouched_old_result_remains_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_bytes(b'{"status":"passed"}')
            previous = release_check._evidence_state(path)
            _, current = release_check._read_regular_evidence(path)
            self.assertEqual(previous, current)

    def test_missing_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-created.json"
            self.assertIsNone(release_check._evidence_state(path))
            with self.assertRaisesRegex(ValueError, "E_MISSING_GATE_EVIDENCE"):
                release_check._read_regular_evidence(path)

    def test_symlinked_old_result_never_qualifies_as_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "old.json"
            target.write_bytes(b'{"status":"passed"}')
            path = Path(directory) / "current.json"
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "E_UNSAFE_GATE_EVIDENCE"):
                release_check._read_regular_evidence(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_named_pipe_does_not_block_evidence_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "E_UNSAFE_GATE_EVIDENCE"):
                release_check._read_regular_evidence(path)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "POSIX nonblocking FIFO required")
    def test_regular_evidence_fifo_swap_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            previous = Path(directory) / "original.json"
            path.write_bytes(b'{"status":"passed"}')
            original_open = os.open
            opened = []
            def swap(name, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                opened.append(flags)
                path.rename(previous)
                os.mkfifo(path)
                return original_open(name, flags, *args, **kwargs)
            with patch.object(release_check.os, "open", side_effect=swap):
                with self.assertRaisesRegex(ValueError, "E_UNSAFE_GATE_EVIDENCE"):
                    release_check._read_regular_evidence(path)
            self.assertEqual(len(opened), 1)
            self.assertEqual(previous.read_bytes(), b'{"status":"passed"}')

    def test_oversize_sparse_json_refused_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.json"
            with path.open("wb") as stream:
                stream.truncate(release_check.MAX_RELEASE_EVIDENCE_BYTES + 1)
            with patch.object(release_check.os, "open",
                              side_effect=AssertionError("oversize input was opened")):
                with self.assertRaisesRegex(ValueError, "E_OVERSIZED_GATE_EVIDENCE"):
                    release_check._read_regular_evidence(path)

    def test_empty_evidence_is_not_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "E_OVERSIZED_GATE_EVIDENCE"):
                release_check._read_regular_evidence(path)

    def test_path_substitution_between_check_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current.json"
            target = Path(directory) / "old.json"
            path.write_bytes(b'{"status":"passed","new":true}')
            target.write_bytes(b'{"status":"passed","old":true}')
            original_open = os.open

            def substitute(name, flags, *args, **kwargs):
                path.unlink()
                path.symlink_to(target)
                return original_open(name, flags, *args, **kwargs)

            with patch.object(release_check.os, "open", side_effect=substitute):
                with self.assertRaises((OSError, ValueError)):
                    release_check._read_regular_evidence(path)


if __name__ == "__main__":
    unittest.main()
