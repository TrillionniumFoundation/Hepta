"""Adversarial P3 migration gates: completeness and atomic publication."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import migrate_c


class CMigrationAdversarial(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-migrate-adversarial-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.output = self.root / "translated.hepta"

    def migrate(self, text: str) -> dict:
        self.source.write_text(text, encoding="utf-8")
        return migrate_c(self.source, self.output)

    def reject(self, text: str, code: str):
        result = self.migrate(text)
        self.assertFalse(result["ok"], result)
        self.assertFalse(self.output.exists())
        self.assertIn(code, [item["code"] for item in result["rejected"]], result)
        if code == "E_C_TOPLEVEL":
            self.assertEqual(result["status"], "unsupported_source", result)

    def test_unused_global_must_not_be_silently_dropped(self):
        self.reject("int hidden = 7; int pure(int x){ return x + 1; }", "E_C_TOPLEVEL")

    def test_global_following_translated_function_is_rejected(self):
        self.reject("int pure(int x){return x;} int hidden = 7;", "E_C_TOPLEVEL")

    def test_extra_c_prototype_cannot_disappear(self):
        self.reject("int legacy(int x); int pure(int x){return x;}", "E_C_TOPLEVEL")

    def test_user_typedef_cannot_disappear(self):
        self.reject("typedef int Custom; int pure(int x){return x;}", "E_C_TOPLEVEL")

    def test_builtin_stdint_header_does_not_trigger_false_rejection(self):
        result = self.migrate("#include <stdint.h>\nint32_t add(int32_t x, int32_t y){return x+y;}")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.write_text("old")
        self.source.write_text("int f(int x){return x;}")
        result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"])
        self.assertEqual(self.output.read_text(), "old")

    def test_dangling_symlink_output_is_rejected(self):
        dangling = self.root / "absent.hepta"
        self.output.symlink_to(dangling)
        self.source.write_text("int f(int x){return x;}")
        result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertFalse(dangling.exists())
        self.assertTrue(self.output.is_symlink())

    def test_frontend_mutation_of_equal_size_source_is_rejected(self):
        # Changes after Clang and the first digest check must not produce
        # a successfully published artifact labeled with the old source hash.
        before = "int f(int x){return x;}\n"
        after = "int f(int x){return 0;}\n"
        self.assertEqual(len(before), len(after))
        self.source.write_text(before, encoding="utf-8")
        from hepta.checker import check as actual_check

        def check_and_replace(*args, **kwargs):
            result = actual_check(*args, **kwargs)
            self.source.write_text(after, encoding="utf-8")
            return result

        with patch("hepta.checker.check", side_effect=check_and_replace):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])

    def test_unchanged_source_keeps_successful_frontend_gate(self):
        result = self.migrate("int f(int x){return x;}\n")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "frontend_checked_not_native_qualified")
        self.assertTrue(self.output.is_file())

    def test_atomic_publish_failure_leaves_no_partial_output(self):
        self.source.write_text("int f(int x){return x;}")
        with patch("hepta.c_migrate.os.link", side_effect=OSError("simulated filesystem failure")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_PUBLISH", [item["code"] for item in result["rejected"]])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


    def test_oversized_source_rejected_before_unbounded_read(self):
        # A caller may point the converter at an arbitrarily large file.
        # Do not load the entire file merely to discover it exceeds 256 KB.
        self.source.write_bytes(b"x" * 256_001)
        with patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SIZE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())

    def test_source_read_error_is_controlled_rejection(self):
        # Revalidate read access at use; a file may become unreadable
        # after is_file(), and the public API must not leak an OSError.
        self.source.write_text("int f(int x){return x;}\\n", encoding="utf-8")
        with patch("hepta.c_migrate.Path.open",
                   side_effect=PermissionError("simulated read denial")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())


    def test_source_growth_during_clang_does_not_trigger_unbounded_reread(self):
        # Clang already parsed the original file when a noncooperating writer
        # replaces it with an oversize source. Rechecks must be size-bounded.
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")
        from hepta.c_migrate import _run as actual_run

        def run_then_grow(args, **kwargs):
            result = actual_run(args, **kwargs)
            if "-ast-dump=json" in args:
                self.source.write_bytes(b"x" * 256_001)
            return result

        with patch("hepta.c_migrate._run", side_effect=run_then_grow), \
             patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded post-Clang source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE", [x["code"] for x in result["rejected"]], result)
        self.assertFalse(self.output.exists())

    def test_source_growth_during_frontend_does_not_trigger_unbounded_reread(self):
        # This exercises the second (prepublication) freshness check.
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")
        from hepta.checker import check as actual_check

        def check_then_grow(*args, **kwargs):
            result = actual_check(*args, **kwargs)
            self.source.write_bytes(b"x" * 256_001)
            return result

        with patch("hepta.checker.check", side_effect=check_then_grow), \
             patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded prepublication source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE", [x["code"] for x in result["rejected"]], result)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


if __name__ == "__main__":
    unittest.main()
