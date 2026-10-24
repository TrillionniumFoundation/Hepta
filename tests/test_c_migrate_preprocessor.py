"""Strict P3 C preprocessor evidence: reject unpinned macro/header inputs."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c


class PreprocessorScopeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Real Clang is required")
        self.work = tempfile.TemporaryDirectory(prefix="hepta-preprocess-")
        self.addCleanup(self.work.cleanup)
        self.src = Path(self.work.name) / "input.c"
        self.out = Path(self.work.name) / "input.hepta"

    def convert(self, source: str) -> dict:
        self.src.write_text(source, encoding="utf-8")
        return migrate_c(self.src, self.out)

    def reject(self, source: str):
        result = self.convert(source)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["converted"], [])
        self.assertFalse(self.out.exists())
        self.assertIn("E_C_PREPROCESSOR", [d["code"] for d in result["rejected"]], result)

    def test_pure_function_positive(self):
        result = self.convert("int f(int x){return x+1;}\n")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.out.is_file())

    def test_literal_stdint_header_positive(self):
        result = self.convert("#include <stdint.h>\nint32_t f(int32_t x){return x+1;}\n")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.out.is_file())

    def test_macro_expansion_hidden_global_cannot_disappear(self):
        self.reject("int f(int x){return x;}\n"
                    "#define GLOBAL int hidden = 7;\nGLOBAL\n"
                    "int g(int x){return x+1;}\n")

    def test_macro_expansion_in_function_is_rejected(self):
        self.reject("#define INC(x) ((x)+1)\nint f(int x){return INC(x);}\n")

    def test_local_header_input_is_rejected(self):
        (self.src.parent / "local.h").write_text("int hidden = 7;\n", encoding="utf-8")
        self.reject('#include "local.h"\nint f(int x){return x;}\n')

    def test_conditional_compilation_cannot_change_scope(self):
        self.reject("#if defined(RELEASE)\nint hidden=7;\n#endif\n"
                    "int f(int x){return x;}\n")

    def test_digraph_and_trigraph_directives_rejected(self):
        for directive in ("%:define H 7\n", "??=define H 7\n"):
            with self.subTest(directive=directive):
                self.reject(directive + "int f(int x){return x;}\n")

    def test_spliced_directive_rejected(self):
        self.reject("int f(int x){return x;}\n#\\\ndefine H 7\n")

    def test_comment_with_hash_fail_closed_conservatively(self):
        self.reject("/* # external preprocessing cannot be certified */\n"
                    "int f(int x){return x;}\n")


if __name__ == "__main__":
    unittest.main()
