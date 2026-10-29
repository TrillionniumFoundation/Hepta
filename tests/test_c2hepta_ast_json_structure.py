"""Adversarial JSON-structure gates for bounded C-to-Hepta Clang AST output."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.c2hepta import migrate


class ClangAstJsonStructure(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-clang-json-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sample.c"
        self.output = self.root / "sample.hepta"
        self.report = self.root / "sample.json"
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")

    def import_mock_ast(self, payload: bytes):
        def probe(args, *, label, max_stdout_bytes=16_384):
            if label == "version":
                return b"clang version fixture\n"
            if label == "target":
                return b"x86_64-unknown-linux-gnu\n"
            if label == "predefined macros":
                return b"#define __SIZEOF_INT__ 4\n#define __CHAR_BIT__ 8\n"
            self.fail("unexpected Clang probe " + label)

        def capture(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, payload, b"")

        # The configured compiler must be executable, but all three identity
        # probes and its AST pipe are deterministic, separately mocked inputs.
        with patch("tools.c2hepta._probe_clang", side_effect=probe), \
             patch("tools.c2hepta._run_bounded_ast", side_effect=capture):
            return migrate(self.source, self.output, self.report, clang=sys.executable)

    def assert_rejected_without_output(self, payload: bytes, message: str):
        result = self.import_mock_ast(payload)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn(message, result["reason"])
        self.assertFalse(self.output.exists(), "a malformed AST must not publish Hepta")
        self.assertTrue(self.report.is_file())
        self.assertEqual(json.loads(self.report.read_text())["status"], "rejected")
        self.assertEqual(result["source_sha256"],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_deep_json_decoder_failure_returns_rejection_report(self):
        payload = (b'{"kind":"TranslationUnitDecl","inner":['
                   + b"[" * 1600 + b"0" + b"]" * 1600 + b"]}")
        self.assert_rejected_without_output(payload, "Clang AST JSON malformed or excessively nested")

    def test_valid_json_with_deep_unused_subtree_is_rejected_before_lowering(self):
        deep = {"leaf": 1}
        for _ in range(150):
            deep = {"nested": deep}
        payload = json.dumps({
            "kind": "TranslationUnitDecl",
            "inner": [{"kind": "FunctionDecl", "loc": {"offset": 0}, "extra": deep}],
        }).encode()
        self.assert_rejected_without_output(payload, "Clang AST JSON structural budget exceeded")

    def test_duplicate_json_keys_cannot_overwrite_ast_identity(self):
        self.assert_rejected_without_output(
            b'{"kind":"TranslationUnitDecl","inner":[],"inner":[{}]}',
            "Clang AST JSON contains duplicate keys")

    def test_unexpected_json_types_fail_closed(self):
        inputs = (
            (b'[]', "translation unit has invalid shape"),
            (b'{"kind":"TranslationUnitDecl","inner":{}}',
             "translation unit has invalid shape"),
            (b'{"kind":"TranslationUnitDecl","inner":[1]}',
             "top-level child has invalid shape"),
            (b'{"kind":"TranslationUnitDecl","inner":[{"kind":"FunctionDecl","loc":[]}]}',
             "source location has invalid shape"),
            (b'{"kind":"TranslationUnitDecl","inner":[{"kind":"FunctionDecl","loc":{"offset":0},"inner":{}}]}',
             "child array has invalid shape"),
        )
        for payload, reason in inputs:
            with self.subTest(payload=payload):
                self.assert_rejected_without_output(payload, reason)

    def test_invalid_utf8_json_fails_with_report(self):
        self.assert_rejected_without_output(bytes([0xff]), "Clang AST JSON malformed or excessively nested")

    def test_real_clang_scalar_positive_control(self):
        self.assertIsNotNone(shutil.which("clang"), "real Clang required for migration acceptance")
        result = migrate(self.source, self.output, self.report, clang="clang")
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertTrue(self.output.is_file())
        self.assertIn('export "C" fn f', self.output.read_text())


if __name__ == "__main__":
    unittest.main()
