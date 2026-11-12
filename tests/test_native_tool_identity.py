"""P5/P7: identical compiler bytes, bounded memory and fail-closed path races."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.native_tool_identity import (
    MAX_EXECUTABLE_BYTES, ToolIdentityRejected, digest_executable,
)


class NativeToolIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_small_exact_sha_no_read_bytes(self):
        raw = b"\x7fELF" + b"deterministic-executable-binary" * 1024
        path = self.root / "compiler"
        path.write_bytes(raw)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read forbidden")):
            self.assertEqual(digest_executable(path), hashlib.sha256(raw).hexdigest())

    def test_empty_and_missing(self):
        path = self.root / "empty"
        path.write_bytes(b"")
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(path)
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(self.root / "absent")

    @unittest.skipIf(os.name == "nt", "POSIX path semantics")
    def test_symlink_fails_closed(self):
        base = self.root / "compiler"
        base.write_bytes(b"clang")
        alias = self.root / "alias"
        alias.symlink_to(base)
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(alias)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_fails_without_open(self):
        fifo = self.root / "named-pipe"
        os.mkfifo(fifo)
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(fifo)

    def test_oversize_sparse_file_without_reading(self):
        path = self.root / "huge"
        with path.open("wb") as handle:
            handle.truncate(MAX_EXECUTABLE_BYTES + 1)
        with self.assertRaises(ToolIdentityRejected):
            digest_executable(path)

    @unittest.skipIf(os.name == "nt", "POSIX open-inode mutation semantics")
    def test_in_place_mutation_after_open(self):
        path = self.root / "mutable"
        path.write_bytes(b"a" * 4096)
        original_open = os.open

        def mutate_after_open(candidate, flags, *args, **kwargs):
            fd = original_open(candidate, flags, *args, **kwargs)
            if Path(candidate) == path:
                os.truncate(path, 1)
            return fd

        with patch("hepta.native_tool_identity.os.open", side_effect=mutate_after_open):
            with self.assertRaises(ToolIdentityRejected):
                digest_executable(path)

    @unittest.skipIf(os.name == "nt", "POSIX open-inode replacement semantics")
    def test_path_retarget_after_open(self):
        path = self.root / "clang"
        path.write_bytes(b"a" * 4096)
        replacement = self.root / "replacement"
        replacement.write_bytes(b"b" * 4096)
        original_open = os.open

        def replace_after_open(candidate, flags, *args, **kwargs):
            fd = original_open(candidate, flags, *args, **kwargs)
            if Path(candidate) == path:
                os.replace(replacement, path)
            return fd

        with patch("hepta.native_tool_identity.os.open", side_effect=replace_after_open):
            with self.assertRaises(ToolIdentityRejected):
                digest_executable(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_regular_compiler_swapped_to_fifo_before_open_never_blocks(self):
        path = self.root / "clang"
        path.write_bytes(b"compiled file bytes")
        real_open = os.open
        observed = []

        def swap_to_fifo(candidate, flags, *args, **kwargs):
            if Path(candidate) == path and not observed:
                observed.append(flags)
                path.unlink()
                os.mkfifo(path)
            return real_open(candidate, flags, *args, **kwargs)

        with patch("hepta.native_tool_identity.os.open", side_effect=swap_to_fifo):
            with self.assertRaises(ToolIdentityRejected):
                digest_executable(path)
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0] & os.O_NONBLOCK)

    def test_file_growth_after_open_is_not_silently_accepted(self):
        path = self.root / "clang"
        path.write_bytes(b"A" * 4096)
        real_fstat = os.fstat
        observed = []
        def modify_after_first_fd_stat(fd):
            st = real_fstat(fd)
            if st.st_ino == path.stat().st_ino and not observed:
                observed.append(True)
                with path.open("ab") as stream:
                    stream.write(b"B" * 10)
            return st
        with patch("hepta.native_tool_identity.os.fstat", side_effect=modify_after_first_fd_stat):
            with self.assertRaises(ToolIdentityRejected):
                digest_executable(path)
        self.assertEqual(observed, [True])

    @unittest.skipUnless(shutil.which("clang"), "A real Clang executable is required")
    def test_real_clang_identity(self):
        actual = Path(shutil.which("clang")).resolve()
        self.assertEqual(digest_executable(actual),
                         hashlib.sha256(actual.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
