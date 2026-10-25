"""P2/P7: bounded C/C++ Clang JSON admission before recursive scalar lowering."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected, _load_bounded_clang_ast, migrate_c
from hepta.cpp2hepta import migrate_cpp
from hepta import c_migrate, cpp2hepta


class BoundedClangASTTests(unittest.TestCase):
    def test_valid_structural_translation_unit(self):
        original = {"kind": "TranslationUnitDecl", "inner": [
            {"kind": "FunctionDecl", "name": "sum", "inner": []}]}
        self.assertEqual(_load_bounded_clang_ast(json.dumps(original)), original)

    def test_malformed_nonfinite_and_wrong_root_rejected(self):
        sources = (
            "{", "null", "[]", '{"kind":"WrongRoot"}',
            '{"kind":"TranslationUnitDecl","inner":[NaN]}',
            '{"kind":"TranslationUnitDecl","number":1e9999}',
        )
        for source in sources:
            with self.subTest(source=source):
                with self.assertRaises(MigrationRejected) as exc:
                    _load_bounded_clang_ast(source)
                self.assertEqual(exc.exception.code, "E_CLANG_AST_FORMAT")

    def test_deep_and_large_node_inventory_reject(self):
        deep = ('{"kind":"TranslationUnitDecl","child":' +
                '{"child":' * 45 + "null" + "}" * 45 + "}")
        with self.assertRaises(MigrationRejected) as exc:
            _load_bounded_clang_ast(deep, max_depth=12)
        self.assertEqual(exc.exception.code, "E_CLANG_AST_LIMIT")
        huge = json.dumps({"kind": "TranslationUnitDecl", "inner": [
            {"kind": "IntegerLiteral", "value": n} for n in range(90)]})
        with self.assertRaises(MigrationRejected) as exc:
            _load_bounded_clang_ast(huge, max_nodes=20)
        self.assertEqual(exc.exception.code, "E_CLANG_AST_LIMIT")

    def test_decoder_recursion_raises_structured_rejection(self):
        deep = ('{"kind":"TranslationUnitDecl","body":' +
                "[ " * 1200 + "null" + "]" * 1200 + "}")
        with self.assertRaises(MigrationRejected) as exc:
            _load_bounded_clang_ast(deep)
        self.assertIn(exc.exception.code, {"E_CLANG_AST_FORMAT", "E_CLANG_AST_LIMIT"})

    def test_byte_quota_and_invalid_budget_types_rejected(self):
        data = json.dumps({"kind": "TranslationUnitDecl", "x": "x" * 300})
        with self.assertRaises(MigrationRejected) as exc:
            _load_bounded_clang_ast(data, max_bytes=80)
        self.assertEqual(exc.exception.code, "E_CLANG_AST_LIMIT")
        for kwargs in ({"max_depth": True}, {"max_depth": 1.2},
                       {"max_nodes": 0}, {"max_bytes": -1}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(MigrationRejected):
                    _load_bounded_clang_ast(data, **kwargs)

    @unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"),
                         "Real Clang AST admission requires Clang and Clang++")
    def test_real_clang_c11_and_cpp20_ast_both_admitted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for target, compiler, flags, src in (
                ("c", "clang", ["-std=c11"],
                 "int add(int a,int b){ return a+b; }"),
                ("cpp", "clang++", ["-std=c++20"],
                 "int add(int a,int b) noexcept {return a+b;}"),
            ):
                with self.subTest(target=target):
                    path = root / ("unit.c" if target == "c" else "unit.cc")
                    path.write_text(src, encoding="utf-8")
                    done = subprocess.run([compiler, *flags, "-Werror", "-fsyntax-only",
                                           "-Xclang", "-ast-dump=json", str(path)],
                                          capture_output=True, text=True, timeout=20)
                    self.assertEqual(done.returncode, 0, done.stderr)
                    tree = _load_bounded_clang_ast(done.stdout)
                    self.assertEqual(tree["kind"], "TranslationUnitDecl")
                    self.assertTrue(any(n.get("kind") == "FunctionDecl"
                                        for n in tree["inner"]))

    @unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"),
                         "Migration fail-closed checks require native Clang")
    def test_both_migrators_reject_forged_deep_ast_without_output(self):
        deep = ('{"kind":"TranslationUnitDecl","body":' +
                '{"child":' * 48 + "null" + "}" * 48 + "}")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for language in ("c", "cpp"):
                with self.subTest(language=language):
                    src = root / ("input.c" if language == "c" else "input.cc")
                    out = root / ("migrated_" + language + ".hepta")
                    src.write_text("int f(int x){return x;}" if language == "c"
                                   else "int f(int x) noexcept {return x;}")
                    module = c_migrate if language == "c" else cpp2hepta
                    real_run = module._run

                    def substituted(argv, **kwargs):
                        if "-ast-dump=json" in argv:
                            return deep
                        return real_run(argv, **kwargs)

                    with patch.object(module, "_run", side_effect=substituted):
                        report = (migrate_c(src, out) if language == "c"
                                  else migrate_cpp(src, out))
                    self.assertFalse(report["ok"], report)
                    self.assertFalse(out.exists())
                    self.assertIn("E_CLANG_AST_LIMIT",
                                  [e["code"] for e in report["rejected"]])


if __name__ == "__main__":
    unittest.main()
