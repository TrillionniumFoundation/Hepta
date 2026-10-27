"""P3/P4 bounded source and native staging intake regression tests."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_migrate import (
    HIAMigrationRejected, MAX_L1_SOURCE_BYTES, MAX_L1_HEPTA_BYTES,
    _read_snapshot, migrate_scalar_to_hia,
)


class L1SnapshotTests(unittest.TestCase):
    def test_regular_source_and_exact_identity(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "test.c"
            p.write_bytes(b"int f(int x) { return x; }\n")
            self.assertEqual(_read_snapshot(p, MAX_L1_SOURCE_BYTES), p.read_bytes())

    def test_symlink_source_not_a_direct_regular_file(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "test.c"
            alias = Path(root) / "link.c"
            p.write_bytes(b"int f(void) { return 7; }")
            alias.symlink_to(p)
            with self.assertRaisesRegex(HIAMigrationRejected, "bounded ordinary"):
                _read_snapshot(alias, MAX_L1_SOURCE_BYTES)

    def test_sparse_source_refuses_before_open(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "large.c"
            with p.open("wb") as stream:
                stream.truncate(MAX_L1_SOURCE_BYTES + 1)
            with patch("hepta.hia_migrate.os.open",
                       side_effect=AssertionError("unbounded source open")):
                with self.assertRaisesRegex(HIAMigrationRejected, "bounded ordinary"):
                    _read_snapshot(p, MAX_L1_SOURCE_BYTES)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "POSIX nonblocking FIFO required")
    def test_fifo_swap_between_lstat_and_open_fails_without_hanging(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "input.c"
            previous = Path(root) / "previous.c"
            p.write_bytes(b"int f(void) { return 1; }")
            original = os.open
            calls = []
            def replace_with_fifo(name, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                calls.append(flags)
                p.rename(previous)
                os.mkfifo(p)
                return original(name, flags, *args, **kwargs)
            with patch("hepta.hia_migrate.os.open", side_effect=replace_with_fifo):
                with self.assertRaisesRegex(HIAMigrationRejected, "inode changed"):
                    _read_snapshot(p, MAX_L1_SOURCE_BYTES)
            self.assertEqual(len(calls), 1)
            self.assertTrue(previous.is_file())

    def test_cross_phase_same_bytes_different_inode_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "input.c"
            previous = Path(root) / "previous.c"
            payload = b"int f(int x) { return x; }\n"
            p.write_bytes(payload)
            observed, identity = _read_snapshot(
                p, MAX_L1_SOURCE_BYTES, capture_identity=True)
            self.assertEqual(observed, payload)
            p.rename(previous)
            p.write_bytes(payload)
            self.assertEqual(_read_snapshot(p, MAX_L1_SOURCE_BYTES), payload)
            with self.assertRaisesRegex(HIAMigrationRejected, "identity changed between phases"):
                _read_snapshot(p, MAX_L1_SOURCE_BYTES, expected_identity=identity)

    def test_source_rebind_with_identical_bytes_blocks_native_builder(self):
        from tests.test_hia_migrate import fake_migrate
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "input.c"
            previous = Path(root) / "previous.c"
            output = Path(root) / "converted"
            p.write_bytes(b"int f(int x) { return x; }\n")
            def migrate_then_rebind(path, dst, **kwargs):
                receipt = fake_migrate(path, dst, **kwargs)
                p.rename(previous)
                p.write_bytes(previous.read_bytes())
                return receipt
            with (patch("hepta.hia_migrate.migrate_c", side_effect=migrate_then_rebind),
                  patch("hepta.hia_migrate.build_checked_hepta_hia_native",
                        side_effect=AssertionError("rebound source reached native build"))):
                result = migrate_scalar_to_hia(p, output, language="c")
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "rejected")
            self.assertFalse(output.exists())
            self.assertIn("identity changed between phases", str(result["diagnostics"]))

    def test_candidate_sparse_output_refused_before_native_build(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "input.c"
            out = Path(root) / "output"
            p.write_bytes(b"int f(int x) { return x; }\n")
            def huge_migrate(source, output, **kwargs):
                with Path(output).open("wb") as stream:
                    stream.truncate(MAX_L1_HEPTA_BYTES + 1)
                return {
                    "ok": True, "status": "frontend_checked_not_native_qualified",
                    "native_validation": "not_run",
                    "source_sha256": sha256(Path(source).read_bytes()).hexdigest(),
                    "source_equivalence_proved": False,
                }
            with (patch("hepta.hia_migrate.migrate_c", side_effect=huge_migrate),
                  patch("hepta.hia_migrate.build_checked_hepta_hia_native",
                        side_effect=AssertionError("oversized candidate reached native"))):
                outcome = migrate_scalar_to_hia(p, out, language="c")
            self.assertFalse(outcome["ok"])
            self.assertEqual(outcome["status"], "rejected")
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
