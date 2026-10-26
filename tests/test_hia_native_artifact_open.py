"""Native HIA artifact read: real Linux FIFO-swap lstat/open regression.

No Clang or Rust required. This validates the exact native-object reader
before code signing/publication; it does not qualify the LLVM compiler.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_llvm import HIAProgramLLVMRejected, _read_artifact


class HIANativeArtifactOpenTests(unittest.TestCase):
    def test_ordinary_bounded_native_bytes_accepted(self):
        with tempfile.TemporaryDirectory(prefix="hia-native-open-") as temporary:
            artifact = Path(temporary) / "native.o"
            artifact.write_bytes(b"real bytes, not a qualified native object")
            self.assertEqual(_read_artifact(artifact), artifact.read_bytes())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_regular_file_swapped_to_fifo_before_open_is_nonblocking(self):
        with tempfile.TemporaryDirectory(prefix="hia-native-open-") as temporary:
            artifact = Path(temporary) / "native.o"
            artifact.write_bytes(b"real candidate bytes")
            original = os.open
            flags_seen = []
            def swap(path, flags, *args, **kwargs):
                if Path(path) == artifact and not flags_seen:
                    flags_seen.append(flags)
                    artifact.unlink()
                    os.mkfifo(artifact)
                return original(path, flags, *args, **kwargs)
            with patch("hepta.hia_program_llvm.os.open", side_effect=swap):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "changed before reading"):
                    _read_artifact(artifact)
            self.assertEqual(len(flags_seen), 1)
            self.assertTrue(flags_seen[0] & os.O_NONBLOCK)
            self.assertTrue(flags_seen[0] & os.O_CLOEXEC)
            self.assertTrue(artifact.exists())

    def test_same_inode_modified_between_lstat_and_open_rejected(self):
        with tempfile.TemporaryDirectory(prefix="hia-native-open-") as temporary:
            artifact = Path(temporary) / "native.o"
            artifact.write_bytes(b"legitimate byte payload")
            original = os.open
            changed = []
            def swap_bytes(path, flags, *args, **kwargs):
                if Path(path) == artifact and not changed:
                    changed.append(True)
                    previous = artifact.stat()
                    artifact.write_bytes(b"!" * len(b"legitimate byte payload"))
                    os.utime(artifact, ns=(previous.st_atime_ns,
                                           previous.st_mtime_ns + 1_000_000_000))
                return original(path, flags, *args, **kwargs)
            with patch("hepta.hia_program_llvm.os.open", side_effect=swap_bytes):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "changed before reading"):
                    _read_artifact(artifact)
            self.assertEqual(changed, [True])


if __name__ == "__main__":
    unittest.main()
