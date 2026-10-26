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

    def test_macro_generated_main_globals_must_be_in_inventory(self):
        for source in (
            "int pure(int x){return x;}\n#define G int hidden=7;\nG\n",
            "#define G int hidden=7;\nG\nint pure(int x){return x;}\n",
            "int pure(int x){return x;}\n#define G(n) int n=7;\nG(hidden)\n",
        ):
            with self.subTest(source=source):
                self.reject(source, "E_C_TOPLEVEL")

    def test_macro_generated_prototypes_must_not_disappear(self):
        self.reject("int pure(int x){return x;}\n#define P int legacy(int);\nP\n", "E_C_TOPLEVEL")

    def test_header_macro_expansion_belongs_to_main_c_file(self):
        (self.root / "defs.h").write_text("#define G int hidden=7;\n", encoding="utf-8")
        self.reject('#include "defs.h"\nint pure(int x){return x;}\nG\n', "E_C_TOPLEVEL")

    def test_macro_defined_function_is_not_certified_by_missing_offset(self):
        self.reject("#define F int pure(int x){return x;}\nF\n", "E_C_TOPLEVEL")

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

    def test_atomic_publish_failure_leaves_no_partial_output(self):
        self.source.write_text("int f(int x){return x;}")
        with patch("hepta.c_migrate.os.link", side_effect=OSError("simulated filesystem failure")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_PUBLISH", [item["code"] for item in result["rejected"]])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


if __name__ == "__main__":
    unittest.main()
