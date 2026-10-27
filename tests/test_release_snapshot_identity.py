"""P7 release-source snapshot uses exact pinned ordinary file descriptors.

These exercise only the local snapshot contract, never compilation, native
toolchain execution, or whole-project P0–P7 release eligibility.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import release_check


class SourceSnapshotIdentityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hia-snapshot-source-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_regular_and_empty_source_are_streamed_and_deterministic(self):
        (self.root / "src").mkdir()
        data = b"safe" * 300_123
        (self.root / "src/module.py").write_bytes(data)
        (self.root / "empty.hepta").write_bytes(b"")
        with patch.object(release_check, "ROOT", self.root), patch.object(
            Path, "read_bytes", side_effect=AssertionError("unbounded read_bytes")
        ):
            first = release_check.snapshot()
            second = release_check.snapshot()
        self.assertEqual(first, second)
        self.assertEqual(first["files"]["src/module.py"], sha256(data).hexdigest())
        self.assertEqual(first["files"]["empty.hepta"], sha256(b"").hexdigest())
        self.assertEqual(len(first["files"]), 2)

    def test_special_source_paths_are_never_ignored(self):
        target = self.root / "regular.hepta"
        target.write_bytes(b"record")
        (self.root / "link.hepta").symlink_to(target)
        with patch.object(release_check, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "E_SOURCE_SNAPSHOT_UNSAFE"):
                release_check.snapshot()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipe")
    def test_fifo_in_source_tree_is_refused_without_open(self):
        path = self.root / "fifo.hepta"
        os.mkfifo(path)
        with patch.object(release_check, "ROOT", self.root), patch.object(
            release_check.os, "open", side_effect=AssertionError("FIFO must not open")
        ):
            with self.assertRaisesRegex(ValueError, "E_SOURCE_SNAPSHOT_UNSAFE"):
                release_check.snapshot()

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "requires POSIX nonblocking FIFO")
    def test_regular_source_fifo_swap_cannot_block_on_open(self):
        path = self.root / "source.hepta"
        previous = self.root / "saved.hepta"
        path.write_bytes(b"original")
        original_open = os.open
        captured = []

        def replace(name, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)
            captured.append(flags)
            path.rename(previous)
            os.mkfifo(path)
            return original_open(name, flags, *args, **kwargs)

        with patch.object(release_check.os, "open", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "E_SOURCE_SNAPSHOT_RACE"):
                release_check._stable_source_digest(path)
        self.assertEqual(len(captured), 1)
        self.assertEqual(previous.read_bytes(), b"original")
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_sparse_oversized_source_refused_before_open(self):
        path = self.root / "large.bin"
        with path.open("wb") as stream:
            stream.truncate(release_check.MAX_SOURCE_SNAPSHOT_FILE_BYTES + 1)
        with patch.object(release_check.os, "open",
                          side_effect=AssertionError("oversized file was opened")):
            with self.assertRaisesRegex(ValueError, "E_SOURCE_SNAPSHOT_UNSAFE"):
                release_check._stable_source_digest(path)

    def test_post_check_symlink_swap_is_rejected(self):
        path = self.root / "source.hepta"
        other = self.root / "other.hepta"
        path.write_bytes(b"trusted")
        other.write_bytes(b"replacement")
        original_open = os.open

        def substitute(name, flags, *args, **kwargs):
            path.unlink()
            path.symlink_to(other)
            return original_open(name, flags, *args, **kwargs)

        with patch.object(release_check.os, "open", side_effect=substitute):
            with self.assertRaises((OSError, ValueError)):
                release_check._stable_source_digest(path)


if __name__ == "__main__":
    unittest.main()
