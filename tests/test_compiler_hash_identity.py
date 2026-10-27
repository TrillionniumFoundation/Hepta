"""P0 secure raw-byte compiler hash: no full compiler/native qualification."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hepta import pipeline
from hepta.native_tool_identity import digest_executable, ToolIdentityRejected


class CompilerSourceHashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def hash_sources(self):
        with patch.object(pipeline, "__file__", str(self.root / "pipeline.py")):
            return pipeline.compiler_hash()

    def test_historical_raw_bytes_and_empty_file(self):
        (self.root / "a.py").write_bytes(b"xyz" * 500001)
        (self.root / "b.py").write_bytes(b"")
        old = hashlib.sha256()
        for path in sorted(self.root.glob("*.py")):
            old.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
        with patch.object(Path, "read_bytes",
                          side_effect=AssertionError("unbounded whole file")):
            self.assertEqual(self.hash_sources(), old.hexdigest())

    def test_no_symlink_or_special_source(self):
        src = self.root / "a.py"
        src.write_bytes(b"safe")
        (self.root / "alias.py").symlink_to(src)
        with self.assertRaises(ToolIdentityRejected):
            self.hash_sources()
        (self.root / "alias.py").unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo.py")
            with self.assertRaises(ToolIdentityRejected):
                self.hash_sources()

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "POSIX FIFO required")
    def test_regular_to_fifo_race_is_bounded(self):
        src = self.root / "a.py"
        saved = self.root / "saved"
        src.write_bytes(b"safe")
        original_open = os.open
        def replace(name, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            src.rename(saved)
            os.mkfifo(src)
            return original_open(name, flags, *args, **kwargs)
        with patch("hepta.native_tool_identity.os.open", side_effect=replace):
            with self.assertRaises(ToolIdentityRejected):
                self.hash_sources()
        self.assertEqual(saved.read_bytes(), b"safe")

    def test_oversized_sparse_source_is_rejected_before_open(self):
        source = self.root / "huge.py"
        with source.open("wb") as out:
            out.truncate(64 * 1024 * 1024 + 1)
        with patch("hepta.native_tool_identity.os.open",
                   side_effect=AssertionError("oversize file opened")):
            with self.assertRaises(ToolIdentityRejected):
                self.hash_sources()

    def test_original_compiler_binary_digest_and_nonempty_rule(self):
        program = self.root / "compiler"
        program.write_bytes(b"EXE\x00" * 321)
        self.assertEqual(digest_executable(program),
                         hashlib.sha256(program.read_bytes()).hexdigest())
        program.write_bytes(b"")
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(program)


if __name__ == "__main__":
    unittest.main()
