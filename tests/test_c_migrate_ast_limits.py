"""Fail closed on oversized/malformed/reentrant Clang JSON AST intake."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected, _load_bounded_clang_ast


class ClangASTIntakeTests(unittest.TestCase):
    def test_exact_transcript_structure(self):
        example = {"kind": "TranslationUnitDecl",
                   "inner": [{"kind": "FunctionDecl", "name": "sample", "inner": []}]}
        self.assertEqual(_load_bounded_clang_ast(json.dumps(example)), example)
        for raw in ("[]", "null", '{"kind":"NotTranslationUnitDecl"}', "{"):
            with self.subTest(raw=raw), self.assertRaises(MigrationRejected):
                _load_bounded_clang_ast(raw)

    def test_nonfinite_values_rejected(self):
        inputs = (
            '{"kind":"TranslationUnitDecl","x":NaN}',
            '{"kind":"TranslationUnitDecl","x":Infinity}',
            '{"kind":"TranslationUnitDecl","x":1e9999}',
        )
        for raw in inputs:
            with self.subTest(raw=raw), self.assertRaises(MigrationRejected):
                _load_bounded_clang_ast(raw)

    def test_byte_node_and_depth_limits(self):
        raw = json.dumps({"kind": "TranslationUnitDecl", "x": "a" * 300})
        with self.assertRaisesRegex(MigrationRejected, "E_CLANG_AST_LIMIT"):
            _load_bounded_clang_ast(raw, max_bytes=100)
        raw = json.dumps({"kind": "TranslationUnitDecl",
                          "inner": [{"kind": "IntegerLiteral", "value": i} for i in range(80)]})
        with self.assertRaisesRegex(MigrationRejected, "E_CLANG_AST_LIMIT"):
            _load_bounded_clang_ast(raw, max_nodes=30)
        value = {"kind": "TranslationUnitDecl"}
        branch = value
        for _ in range(100):
            branch["nested"] = {}
            branch = branch["nested"]
        with self.assertRaisesRegex(MigrationRejected, "E_CLANG_AST_LIMIT"):
            _load_bounded_clang_ast(json.dumps(value), max_depth=20)

    def test_python_json_recursion_is_structured_failure(self):
        raw = '{"kind":"TranslationUnitDecl","child":' + "[" * 1600 + "null" + "]" * 1600 + "}"
        with self.assertRaises(MigrationRejected):
            _load_bounded_clang_ast(raw)

    def test_boolean_or_unsupported_quota_rejected(self):
        for kwargs in ({"max_depth": True}, {"max_nodes": 0},
                       {"max_bytes": -1}, {"max_depth": 1.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(MigrationRejected):
                _load_bounded_clang_ast("{}", **kwargs)

    @unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"),
                         "Real Clang frontends required")
    def test_real_c11_and_cpp20_clang_ast(self):
        for compiler, standard, suffix, source in (
            ("clang", "-std=c11", ".c", "int f(int n){return n + 1;}"),
            ("clang++", "-std=c++20", ".cc",
             "int f(int n) noexcept {int x=0;while(x<n){x=x+1;}return x;}"),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / ("sample" + suffix)
                path.write_text(source)
                result = subprocess.run(
                    [compiler, standard, "-Werror", "-fsyntax-only",
                     "-Xclang", "-ast-dump=json", str(path)],
                    capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                ast = _load_bounded_clang_ast(result.stdout)
                self.assertTrue(any(item.get("kind") == "FunctionDecl"
                                    for item in ast.get("inner", [])))


if __name__ == "__main__":
    unittest.main()
