"""Fail-closed C preprocessing rejection, including alternative C11 spellings.

This importer translates an unpreprocessed, strict scalar C slice.  Clang
accepts digraph `%:` as a directive marker, including after a C comment,
and phase-two line splicing can construct one across physical lines.
Such input must not become qualified migration output without recording
and verifying the preprocessing environment.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.c2hepta import migrate


class ClangPreprocessingEscapes(unittest.TestCase):
    def test_preprocessor_directive_spellings_are_rejected_before_clang(self):
        self.assertIsNotNone(shutil.which("clang"), "real Clang required")
        cases = {
            "digraph": "%:define ID(x) (x)\nint identity(int x) { return ID(x); }\n",
            "comment_prefixed_digraph":
                "/* permitted comment */%:define ID(x) (x)\n"
                "int identity(int x) { return ID(x); }\n",
            "spliced_digraph":
                "%\\\n:define ID(x) (x)\nint identity(int x) { return ID(x); }\n",
            "comment_prefixed_hash":
                "/* permitted comment */#define ID(x) (x)\n"
                "int identity(int x) { return ID(x); }\n",
            "ordinary_hash":
                "#define ID(x) (x)\nint identity(int x) { return ID(x); }\n",
        }
        for label, code in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix="hepta-preprocessor-"
            ) as temp:
                root = Path(temp)
                source, output, report = root / "in.c", root / "out.hepta", root / "report.json"
                source.write_text(code, encoding="utf-8")
                result = migrate(source, output, report, clang="clang")
                self.assertEqual(result["status"], "rejected", result)
                self.assertIn("preprocessor directives/macros", result["reason"])
                self.assertFalse(output.exists())
                self.assertEqual(json.loads(report.read_text())["status"], "rejected")

    def test_predefined_compiler_macros_are_not_accepted_as_plain_scalar_c(self):
        # No #define or other directive is needed for these compiler-provided
        # names to expand. They must not silently enter a no-preprocessing
        # source subset through a Clang AST that contains only integer nodes.
        self.assertIsNotNone(shutil.which("clang"), "real Clang required")
        for macro in ("__LINE__", "__STDC__", "__COUNTER__", "__SIZEOF_INT__"):
            with self.subTest(macro=macro), tempfile.TemporaryDirectory(
                prefix="hepta-predefined-macro-"
            ) as temp:
                root = Path(temp)
                source, output, report = root / "in.c", root / "out.hepta", root / "report.json"
                source.write_text(
                    f"int identity(int x) {{ return x + {macro}; }}\\n", encoding="utf-8")
                result = migrate(source, output, report, clang="clang")
                self.assertEqual(result["status"], "rejected", result)
                self.assertIn("predefined compiler identifiers", result["reason"])
                self.assertFalse(output.exists())
                self.assertEqual(json.loads(report.read_text())["status"], "rejected")

    def test_internal_underscores_without_predefined_identifiers_remain_valid(self):
        self.assertIsNotNone(shutil.which("clang"), "real Clang required")
        with tempfile.TemporaryDirectory(prefix="hepta-predefined-positive-") as temp:
            root = Path(temp)
            source, output, report = root / "in.c", root / "out.hepta", root / "report.json"
            source.write_text(
                "int add_one(int user_value) { return user_value + 1; }\\n", encoding="utf-8")
            result = migrate(source, output, report, clang="clang")
            self.assertEqual(result["status"], "converted", result)
            self.assertIn('export "C" fn add_one', output.read_text())
            self.assertEqual(json.loads(report.read_text())["status"], "converted")

    def test_normal_scalar_function_and_comments_remain_supported(self):
        self.assertIsNotNone(shutil.which("clang"), "real Clang required")
        with tempfile.TemporaryDirectory(prefix="hepta-preprocessor-positive-") as temp:
            root = Path(temp)
            source, output, report = root / "in.c", root / "out.hepta", root / "report.json"
            source.write_text("/* ordinary C comment */\nint identity(int x) { return x; }\n")
            result = migrate(source, output, report, clang="clang")
            self.assertEqual(result["status"], "converted", result)
            self.assertIn('export "C" fn identity', output.read_text())
            self.assertEqual(json.loads(report.read_text())["status"], "converted")


if __name__ == "__main__":
    unittest.main()
