"""Actual-Clang controls for bounded strict C source reads and staged cleanup."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import hepta.c_migrate as migration
from hepta.checker import check as actual_check


SOURCE = b"int pure(int x) { return x; }\n"


class BoundedCSourceReads(unittest.TestCase):
    def setUp(self):
        self.clang = os.environ.get("CLANG", "clang")
        self.assertIsNotNone(shutil.which(self.clang), "Actual Clang is required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-bounded-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"
        self.source.write_bytes(SOURCE)
        self.actual_open = Path.open
        self.actual_run = migration._run
        self.armed = False
        self.read_sizes = []

    def migrate(self):
        return migration.migrate_c(self.source, self.output, clang=self.clang)

    def assert_refused_cleanly(self, result, code):
        self.assertFalse(result["ok"], result)
        self.assertIn(code, [x["code"] for x in result["rejected"]], result)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])

    def guarded_open(self, path, mode="r", *args, **kwargs):
        stream = self.actual_open(path, mode, *args, **kwargs)
        if path != self.source or mode != "rb":
            return stream
        owner = self

        class SourceRead:
            def __enter__(self):
                stream.__enter__()
                return self

            def __exit__(self, *exc):
                return stream.__exit__(*exc)

            def read(self, size=-1):
                owner.read_sizes.append(size)
                if owner.armed:
                    owner.assertGreaterEqual(size, 0, "unbounded source read")
                    owner.assertLessEqual(size, 256_001, "source read exceeded one-byte sentinel")
                return stream.read(size)

        return SourceRead()

    def failing_open(self, path, mode="r", *args, **kwargs):
        if self.armed and path == self.source and mode == "rb":
            raise PermissionError("controlled source-read denial")
        return self.actual_open(path, mode, *args, **kwargs)

    def after_clang(self, argv, **kwargs):
        value = self.actual_run(argv, **kwargs)
        if "-ast-dump=json" in argv:
            self.armed = True
            if self.grow:
                self.source.write_bytes(SOURCE + b" " * (256_001 - len(SOURCE)))
        return value

    def after_frontend(self, program):
        checked = actual_check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        self.armed = True
        if self.grow:
            self.source.write_bytes(SOURCE + b" " * (256_001 - len(SOURCE)))
        return checked

    def test_initial_oversize_rejects_before_unbounded_read_or_clang(self):
        self.source.write_bytes(SOURCE + b" " * (256_001 - len(SOURCE)))
        self.armed = True
        with patch.object(Path, "open", autospec=True, side_effect=self.guarded_open), \
                patch.object(migration, "_run", side_effect=AssertionError("oversize input must not launch Clang")):
            result = self.migrate()
        self.assert_refused_cleanly(result, "E_C_SIZE")
        self.assertEqual(self.read_sizes, [256_001])

    def test_initial_read_error_is_controlled_before_clang(self):
        self.armed = True
        with patch.object(Path, "open", autospec=True, side_effect=self.failing_open), \
                patch.object(migration, "_run", side_effect=AssertionError("unreadable input must not launch Clang")):
            result = self.migrate()
        self.assert_refused_cleanly(result, "E_C_SOURCE_RACE")

    def test_growth_after_actual_clang_uses_bounded_recheck(self):
        self.grow = True
        with patch.object(Path, "open", autospec=True, side_effect=self.guarded_open), \
                patch.object(migration, "_run", side_effect=self.after_clang):
            result = self.migrate()
        self.assertTrue(self.armed)
        self.assert_refused_cleanly(result, "E_C_SOURCE_RACE")
        self.assertEqual(self.read_sizes, [256_001, 256_001])

    def test_growth_after_actual_frontend_cleans_staged_output(self):
        self.grow = True
        with patch.object(Path, "open", autospec=True, side_effect=self.guarded_open), \
                patch("hepta.checker.check", side_effect=self.after_frontend):
            result = self.migrate()
        self.assertTrue(self.armed)
        self.assert_refused_cleanly(result, "E_C_SOURCE_RACE")
        self.assertEqual(self.read_sizes, [256_001, 256_001, 256_001])

    def test_read_error_after_actual_clang_is_controlled(self):
        self.grow = False
        with patch.object(Path, "open", autospec=True, side_effect=self.failing_open), \
                patch.object(migration, "_run", side_effect=self.after_clang):
            result = self.migrate()
        self.assertTrue(self.armed)
        self.assert_refused_cleanly(result, "E_C_SOURCE_RACE")

    def test_read_error_after_actual_frontend_cleans_staged_output(self):
        self.grow = False
        with patch.object(Path, "open", autospec=True, side_effect=self.failing_open), \
                patch("hepta.checker.check", side_effect=self.after_frontend):
            result = self.migrate()
        self.assertTrue(self.armed)
        self.assert_refused_cleanly(result, "E_C_SOURCE_RACE")

    def test_unchanged_eligible_source_retains_frontend_and_digest_contract(self):
        result = self.migrate()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "frontend_checked_not_native_qualified")
        self.assertEqual(result["source_sha256"], hashlib.sha256(SOURCE).hexdigest())
        self.assertEqual(result["output_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertFalse(result["source_equivalence_proved"])
        self.assertEqual(result["native_validation"], "not_run")
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


if __name__ == "__main__":
    unittest.main()
