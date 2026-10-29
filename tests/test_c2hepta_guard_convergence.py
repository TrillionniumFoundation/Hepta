"""Exercise captured input and directory capabilities together on real POSIX I/O.

The executable fixture emits a fixed Clang-shaped AST; it is not a C compiler.
These tests qualify the importer/capture/publication interaction. The existing
real-Clang and generated-native controls remain separate mandatory tests.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureResult
from tools import c2hepta


@unittest.skipUnless(os.name == "posix", "actual POSIX directory-fd publication")
class C2HeptaGuardConvergence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-guard-convergence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"
        self.report = self.root / "audit.json"
        self.original = b"/* \xc3\xa9 */ int identity(int x) { return x; }\r\n"
        self.changed = b"int identity(int x) { return x + 1; }\n"
        self.source.write_bytes(self.original)
        self.previous = b"previous accepted artifact\n"
        self.output.write_bytes(self.previous)
        self.observed_input = self.root / "actual-stdin.bin"
        self.safe = self.root / "safe"
        self.safe.mkdir()
        self.parked = self.root / "original-safe"
        self.compiler = self.root / "ast-fixture"
        ast = {"kind": "TranslationUnitDecl", "inner": [{
            "kind": "FunctionDecl", "loc": {"offset": 13}, "name": "identity",
            "type": {"qualType": "int (int)"}, "inner": [
                {"kind": "ParmVarDecl", "name": "x", "type": {"qualType": "int"}},
                {"kind": "CompoundStmt", "inner": [{"kind": "ReturnStmt", "inner": [{
                    "kind": "DeclRefExpr", "type": {"qualType": "int"},
                    "referencedDecl": {"kind": "ParmVarDecl", "name": "x"},
                }]}]},
            ],
        }]}
        ast_bytes = json.dumps(ast).encode() + b"\r\n"
        self.compiler.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys\n"
            "args = sys.argv[1:]\n"
            "if '--version' in args: sys.stdout.buffer.write(b'clang-shaped fixture\\r\\n')\n"
            "elif '-dumpmachine' in args: print('x86_64-unknown-linux-gnu')\n"
            "elif '-dM' in args:\n"
            "    sys.stdout.buffer.write(b'#define __SIZEOF_INT__ 4\\r\\n#define __CHAR_BIT__ 8\\r\\n')\n"
            "elif '-ast-dump=json' in args:\n"
            "    if args[-1] != '-': sys.exit(31)\n"
            f"    Path({str(self.observed_input)!r}).write_bytes(sys.stdin.buffer.read())\n"
            f"    sys.stdout.buffer.write({ast_bytes!r})\n"
            "else: sys.exit(32)\n",
            encoding="utf-8",
        )
        self.compiler.chmod(0o700)

    def convert(self, output=None, report=None):
        return c2hepta.migrate(self.source, output or self.output,
                                report or self.report, clang=str(self.compiler))

    def test_live_source_aba_keeps_exact_utf8_and_crlf_compiler_input(self):
        actual = c2hepta.run_bounded
        observations = []

        def capture(argv, **kwargs):
            if "-ast-dump=json" not in argv:
                return actual(argv, **kwargs)
            self.source.write_bytes(self.changed)
            observations.append(self.source.read_bytes())
            try:
                return actual(argv, **kwargs)
            finally:
                self.source.write_bytes(self.original)

        with patch.object(c2hepta, "run_bounded", side_effect=capture):
            result = self.convert()
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertEqual(observations, [self.changed])
        self.assertEqual(self.observed_input.read_bytes(), self.original)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(result["clang_input"], {
            "transport": "captured_source_stdin", "bytes": len(self.original),
            "sha256": hashlib.sha256(self.original).hexdigest(),
        })

    def test_source_aba_and_report_parent_rebind_do_not_clobber_source(self):
        alias = self.root / "alias"
        alias.symlink_to(self.safe, target_is_directory=True)
        report = alias / self.source.name
        actual = c2hepta.run_bounded
        changed = []

        def capture(argv, **kwargs):
            if "-ast-dump=json" not in argv:
                return actual(argv, **kwargs)
            self.source.write_bytes(self.changed)
            alias.unlink()
            alias.symlink_to(self.root, target_is_directory=True)
            changed.append(True)
            try:
                return actual(argv, **kwargs)
            finally:
                self.source.write_bytes(self.original)

        with patch.object(c2hepta, "run_bounded", side_effect=capture):
            result = self.convert(report=report)
        self.assertEqual(changed, [True])
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("path binding changed", result["reason"])
        self.assertEqual(self.observed_input.read_bytes(), self.original)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.output.read_bytes(), self.previous)
        saved = json.loads((self.safe / self.source.name).read_text())
        self.assertEqual(saved["status"], "rejected")
        self.assertEqual(saved["source_sha256"], hashlib.sha256(self.original).hexdigest())

    def canonical_swap(self, *, at_report):
        output = self.safe / ("translated.hepta" if at_report else self.source.name)
        report = self.safe / (self.source.name if at_report else "audit.json")
        trigger = report if at_report else output
        actual = c2hepta._atomic_write
        swaps = []

        def publication(path, content, **kwargs):
            if path == trigger and not swaps:
                self.safe.rename(self.parked)
                self.safe.symlink_to(self.root, target_is_directory=True)
                swaps.append(True)
            return actual(path, content, **kwargs)

        with patch.object(c2hepta, "_atomic_write", side_effect=publication):
            result = self.convert(output=output, report=report)
        self.assertEqual(swaps, [True])
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertTrue((self.parked / output.name).read_text().startswith("module c2hepta_generated;"))
        self.assertEqual(json.loads((self.parked / report.name).read_text())["status"], "converted")
        self.assertEqual(self.observed_input.read_bytes(), self.original)

    def test_output_publication_uses_admitted_directory_after_canonical_swap(self):
        self.canonical_swap(at_report=False)

    def test_report_publication_uses_admitted_directory_after_canonical_swap(self):
        self.canonical_swap(at_report=True)

    def test_missing_raw_capture_is_not_reconstructed_from_normalized_text(self):
        with patch.object(c2hepta, "run_bounded", return_value=CaptureResult(0, "clang\n", "")):
            result = self.convert()
        self.assertEqual(result["status"], "rejected")
        self.assertIn("exact raw streams", result["reason"])
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(self.source.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
