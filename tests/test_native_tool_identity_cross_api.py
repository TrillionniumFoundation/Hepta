"""Portable controls for Windows lstat/fstat timestamp semantics and stable reads."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hepta import native_tool_identity as identity, pipeline


class CrossApiToolIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = b"compiler image\x00\r\n" * 17
        self.path = self.root / "compiler"
        self.path.write_bytes(self.raw)

    def snapshot(self, **changes):
        values = dict(st_mode=stat.S_IFREG | 0o600, st_dev=3, st_ino=41,
                      st_size=len(self.raw), st_mtime_ns=100,
                      st_ctime_ns=200, st_birthtime_ns=200)
        values.update(changes)
        return SimpleNamespace(**values)

    def hash_snapshots(self, *, before=None, initial=None, after=None,
                       final=None):
        before = before if before is not None else self.snapshot()
        initial = initial if initial is not None else self.snapshot(st_ctime_ns=300)
        after = after if after is not None else initial
        final = final if final is not None else before
        # Replace this module's os binding, not the process-wide os.name used
        # by pathlib. The actual descriptor still supplies the bytes.
        native_os = SimpleNamespace(**(vars(os) | {
            "name": "nt", "fstat": Mock(side_effect=[initial, after]),
        }))
        with patch.object(identity, "os", native_os), \
                patch.object(Path, "lstat", side_effect=[before, final]):
            return identity.digest_executable(self.path)

    def test_windows_distinct_creation_and_change_times_are_accepted(self):
        self.assertEqual(self.hash_snapshots(), hashlib.sha256(self.raw).hexdigest())

    def test_windows_311_without_birthtime_keeps_creation_time_check(self):
        before = self.snapshot()
        del before.st_birthtime_ns
        self.assertEqual(self.hash_snapshots(before=before, initial=before),
                         hashlib.sha256(self.raw).hexdigest())
        changed = SimpleNamespace(**(vars(before) | {"st_ctime_ns": 201}))
        with self.assertRaisesRegex(identity.ToolIdentityRejected, "before read"):
            self.hash_snapshots(before=before, initial=changed)

    def test_posix_cross_api_ctime_is_still_required_even_with_birthtime(self):
        # Exercise the POSIX key directly: the Windows host does not provide
        # the POSIX-only open flags needed to simulate the entire reader.
        with patch.object(identity, "os", SimpleNamespace(name="posix")):
            self.assertNotEqual(identity._identity(self.snapshot(), cross_api=True),
                                identity._identity(self.snapshot(st_ctime_ns=300), cross_api=True))

    def test_each_comparable_field_mismatch_is_rejected_before_read(self):
        changes = {"st_dev": 4, "st_ino": 42, "st_size": len(self.raw) + 1,
                   "st_mtime_ns": 101, "st_birthtime_ns": 201,
                   "st_mode": stat.S_IFDIR | 0o700}
        for field, value in changes.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(identity.ToolIdentityRejected, "before read"):
                    self.hash_snapshots(initial=self.snapshot(st_ctime_ns=300, **{field: value}))

    def test_each_handle_identity_change_during_read_is_rejected(self):
        changes = {"st_dev": 4, "st_ino": 42, "st_size": len(self.raw) + 1,
                   "st_mtime_ns": 101, "st_ctime_ns": 301}
        for field, value in changes.items():
            with self.subTest(field=field):
                after = self.snapshot(**({"st_ctime_ns": 300} | {field: value}))
                with self.assertRaisesRegex(identity.ToolIdentityRejected, "during read"):
                    self.hash_snapshots(after=after)

    def test_each_path_identity_change_after_read_is_rejected(self):
        changes = {"st_dev": 4, "st_ino": 42, "st_size": len(self.raw) + 1,
                   "st_mtime_ns": 101, "st_ctime_ns": 201,
                   "st_mode": stat.S_IFLNK | 0o777}
        for field, value in changes.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(identity.ToolIdentityRejected, "path replaced"):
                    self.hash_snapshots(final=self.snapshot(**{field: value}))

    def test_real_rewritten_file_preserves_exact_bytes(self):
        # Force metadata changes after creation, like checkout followed by
        # setting file times. CPython 3.12+ Windows then exposes different
        # lstat/fstat ctimes even though the file remains untouched in the read.
        time.sleep(0.02)
        raw = self.raw[::-1]
        self.path.write_bytes(raw)
        os.utime(self.path, ns=(1_600_000_000_000_000_000,) * 2)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole file read")):
            self.assertEqual(identity.digest_executable(self.path), hashlib.sha256(raw).hexdigest())

    def test_real_compiler_source_envelope_after_metadata_change(self):
        sources = {"a.py": b"source\r\n\x00", "empty.py": b"", "z.py": b"last\n"}
        expected = hashlib.sha256()
        for name, raw in sources.items():
            source = self.root / name
            source.write_bytes(raw)
            os.utime(source, ns=(1_600_000_000_000_000_000,) * 2)
            expected.update(name.encode() + b"\0" + raw + b"\0")
        with patch.object(pipeline, "__file__", str(self.root / "pipeline.py")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("whole file read")):
            self.assertEqual(pipeline.compiler_hash(), expected.hexdigest())

    def test_real_checkout_compiler_hash_matches_original_envelope(self):
        expected = hashlib.sha256()
        for path in sorted(Path(pipeline.__file__).parent.glob("*.py")):
            expected.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
        self.assertEqual(pipeline.compiler_hash(), expected.hexdigest())


if __name__ == "__main__":
    unittest.main()
