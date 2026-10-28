"""C migration must bound source reads at admission and identity recheck."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


class C2HeptaBoundedSource(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-c2hepta-bounded-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "module.c"
        self.output = self.root / "module.hepta"
        self.report = self.root / "migration.json"

    def test_maximum_read_size_and_prefix_is_not_a_source_identity(self):
        # A sparse 32 MiB file represents an untrusted oversized input without
        # allocating it in the test process. The reader may retain <=256001 B.
        with self.source.open("wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        self.assertEqual(len(c2hepta._read_bounded_source(self.source)),
                         c2hepta._MAX_SOURCE_BYTES + 1)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report,
                                     clang="/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("256 KB", result["reason"])
        self.assertIsNone(result["source_sha256"],
                          "digest of an incomplete prefix must never claim full source identity")
        self.assertFalse(self.output.exists())
        self.assertTrue(self.report.exists())

    def test_exact_boundary_has_full_digest(self):
        data = b" " * c2hepta._MAX_SOURCE_BYTES
        self.source.write_bytes(data)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report,
                                     clang="/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("clang executable unavailable", result["reason"])
        self.assertEqual(result["source_sha256"], hashlib.sha256(data).hexdigest())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.source)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("regular file", result["reason"])
        self.assertFalse(self.output.exists())
        self.assertTrue(self.report.exists())

    @unittest.skipUnless(shutil.which("clang"), "Clang is needed for actual migration")
    def test_valid_conversion_uses_bounded_read_on_both_paths(self):
        self.source.write_text("int identity(int x) { return x; }\n", encoding="utf-8")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "converted", result)
        self.assertTrue(self.output.exists())
        self.assertEqual(result["source_sha256"],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())

    @unittest.skipUnless(shutil.which("clang"), "Clang is needed for source-race probe")
    def test_growth_before_identity_recheck_is_rejected(self):
        self.source.write_text("int identity(int x) { return x; }\n", encoding="utf-8")
        real_hash = c2hepta.function_hash

        def change_source(fn):
            digest = real_hash(fn)
            with self.source.open("wb") as handle:
                handle.truncate(32 * 1024 * 1024)
            return digest

        with patch.object(c2hepta, "function_hash", side_effect=change_source):
            with patch.object(Path, "read_bytes",
                              side_effect=AssertionError("unbounded source recheck")):
                result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("source changed during conversion", result["reason"])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
