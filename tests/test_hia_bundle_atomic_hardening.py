"""Precommit filesystem race regressions for the existing atomic HIA publisher."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_bundle_atomic import AtomicBundleRejected, publish_hia_bundle


@unittest.skipUnless(sys.platform == "linux", "Linux renameat2 required")
class BundleFileRaceTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="hia-atomic-races-")
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        self.stage = self.root / ".staged"
        self.stage.mkdir()
        self.dest = self.root / "published"
        self.data = {"candidate.hepta": b"source\n",
                     "candidate.so": b"actual native bytes\0",
                     "migration-hia.json": b'{"ok":true}\n'}
        for name, data in self.data.items():
            (self.stage / name).write_bytes(data)

    def publish(self):
        return publish_hia_bundle(self.stage, self.dest, self.data, lambda: True)

    def test_fifo_swap_after_lstat_cannot_block_and_cannot_publish(self):
        original = os.open
        observed = []
        def fifo_swap(path, flags, *args, **kwargs):
            if path == "candidate.so" and not observed:
                observed.append(flags)
                (self.stage / "candidate.so").unlink()
                os.mkfifo(self.stage / "candidate.so")
            return original(path, flags, *args, **kwargs)
        with patch("hepta.hia_bundle_atomic.os.open", side_effect=fifo_swap):
            with self.assertRaisesRegex(AtomicBundleRejected, "changed while opening"):
                self.publish()
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0] & os.O_NONBLOCK)
        self.assertFalse(self.dest.exists())
        self.assertTrue(self.stage.is_dir())

    def test_same_inode_same_size_mutation_after_digest_fails_precommit(self):
        original = os.fsync
        target = self.stage / "candidate.so"
        inode = target.stat().st_ino
        fired = []
        def write_between_read_and_fstat(fd):
            if os.fstat(fd).st_ino == inode and not fired:
                fired.append(True)
                before = target.stat()
                target.write_bytes(b"!" * len(self.data["candidate.so"]))
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            return original(fd)
        with patch("hepta.hia_bundle_atomic.os.fsync", side_effect=write_between_read_and_fstat):
            with self.assertRaisesRegex(AtomicBundleRejected, "changed after byte verification"):
                self.publish()
        self.assertEqual(fired, [True])
        self.assertTrue(self.stage.is_dir())
        self.assertFalse(self.dest.exists(), "corrupt bytes must never be published")

    def test_growing_file_during_hash_is_bounded_and_rejected(self):
        original = os.read
        target = self.stage / "candidate.so"
        inode = target.stat().st_ino
        counts = []
        fired = []
        def append_during_read(fd, count):
            if os.fstat(fd).st_ino == inode:
                counts.append(count)
                if not fired:
                    fired.append(True)
                    with target.open("ab") as stream:
                        stream.write(b"+extra")
            return original(fd, count)
        with patch("hepta.hia_bundle_atomic.os.read", side_effect=append_during_read):
            with self.assertRaisesRegex(AtomicBundleRejected, "staged size/bytes"):
                self.publish()
        self.assertEqual(fired, [True])
        self.assertLessEqual(sum(counts), len(self.data["candidate.so"]) + 1)
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()
