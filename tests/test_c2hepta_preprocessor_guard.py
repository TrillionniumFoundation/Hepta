"""Strict migration excludes actual C preprocessing, including builtin macros.

The scalar importer has no macro provenance model. These regressions use the
actual Clang frontend; no mocked AST can establish which source spellings the
C implementation expands. Rejection must retain an existing output and report
the precise rejected source, while ordinary scalar conversion remains usable.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.c2hepta import migrate


class C2HeptaPreprocessorGuardTests(unittest.TestCase):
    def setUp(self):
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.assertTrue(self.clang, "Actual Clang is required for migration conformance")
        self.temporary = tempfile.TemporaryDirectory(prefix="c2hepta-preprocessor-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"
        self.report = self.root / "report.json"

    def convert(self, source):
        self.source.write_bytes(source)
        return migrate(self.source, self.output, self.report, clang=self.clang)

    def assert_rejected(self, source, *, compiler_ran):
        previous = b"previous admitted artifact\n"
        self.output.write_bytes(previous)
        result = self.convert(source)
        self.assertEqual(result["status"], "rejected", result)
        self.assertEqual(result["safety"], "not_qualified")
        self.assertEqual(result["source_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(self.output.read_bytes(), previous)
        self.assertEqual(json.loads(self.report.read_text()), result)
        self.assertEqual(result["clang"] != "not_run", compiler_ran)
        self.assertNotIn("output_sha256", result)
        self.assertIn("source model", result["reason"])

    def test_c11_directive_spellings_reject_before_clang(self):
        sources = (
            b"#define STEP 1\nint step(int x){return x+STEP;}\n",
            b"%:define STEP 1\nint step(int x){return x+STEP;}\n",
            b"/*prefix*/ %:define STEP 1\nint step(int x){return x+STEP;}\n",
            b"/*prefix*/ #define STEP 1\nint step(int x){return x+STEP;}\n",
            b"%\\\n:define STEP 1\nint step(int x){return x+STEP;}\n",
            b"??=define STEP 1\nint step(int x){return x+STEP;}\n",
            b"int step(int x){return x + \\\n1;}\n",
            b"int step(int x){return x + \\\r\n1;}\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_rejected(source, compiler_ran=False)

    def test_builtin_macro_expansions_reject_after_actual_clang_ast(self):
        # No directive is present in these inputs, so spelling checks alone
        # cannot enforce the no-macro subset. Clang reports expansion locations.
        for macro in (b"__LINE__", b"__STDC__", b"__SIZEOF_INT__"):
            with self.subTest(macro=macro):
                self.assert_rejected(b"int value(void){return " + macro + b";}\n",
                                     compiler_ran=True)

    def test_macro_free_scalar_still_converts(self):
        result = self.convert(b"/* ordinary source */\nint step(int x){return x+1;}\n")
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertEqual(result["backend_validation"], "not_run")
        self.assertEqual(result["output_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertIn("export \"C\" fn step", self.output.read_text())


if __name__ == "__main__":
    unittest.main()
