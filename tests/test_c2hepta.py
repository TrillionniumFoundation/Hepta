"""Bounded Clang-AST migration tests; never treats compilation as an equivalence proof."""
from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c2hepta import MigrationRejected, convert_c, main
from hepta.parser import parse
from hepta.checker import check


CLANG = shutil.which("clang")


@unittest.skipUnless(CLANG, "Clang is needed to construct a real C AST")
class C2HeptaTests(unittest.TestCase):
    SOURCE = """int add(int a, int b) { return a + b; }
int bigger(int a, int b) {
    if (a > b) { return a; } else { return b; }
}
int accumulate(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) { total += i; }
    return total;
}
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def convert(self, source=None):
        src = self.root / "input.c"
        src.write_text(self.SOURCE if source is None else source)
        return convert_c(src, clang=CLANG)

    def test_real_ast_emits_parseable_checked_hepta(self):
        result = self.convert()
        self.assertEqual(result.report["migration_tier"], "L1")
        self.assertEqual(result.report["status"], "candidate_unverified")
        self.assertFalse(result.report["abi_qualified"])
        self.assertFalse(result.report["semantic_equivalence_proved"])
        self.assertFalse(result.report["memory_safety_proved"])
        self.assertIn('export "C" fn accumulate(n: i32)', result.source)
        self.assertIn("while (i < n)", result.source)
        self.assertIn("total = (total + i)", result.source)
        program = parse(result.source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        self.assertEqual(result.source, self.convert().source)

    def test_if_raw_integer_condition_and_while(self):
        with self.assertRaises(MigrationRejected):
            self.convert("int keep(int n) { int i = 0; while(n) { i = i + 1; n = n - 1; } return i; }")
        # Parameter reassignment is deliberately refused; no silent mutability relaxation.

    def test_if_integer_condition_is_normalized(self):
        result = self.convert("int sign(int a) { if (a) return 1; else return 0; }")
        self.assertIn("if (a != 0)", result.source)
        checked = check(parse(result.source))
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])

    def test_no_silent_unsafe_or_partial_translations(self):
        bad = (
            "int *take(int *p) { return p; }",
            "unsigned int f(unsigned int x) { return x + 1; }",
            "int global; int f(int x) { return x; }",
            "#define X 1\nint f(int x) { return x + X; }",
            "int f(int x) { return x ? 1 : 2; }",
            "int f(int x) { return x << 1; }",
            "static int f(int x) { return x; }",
            "int f(int x) { return (x < 2) + 4; }",  # unsupported implicit boolean arithmetic
            "int f(int x) { int y; return x + y; }",
            "int f(int x) { return f(x); }",  # call contracts unsupported
            "int f(int x) { goto end; end: return x; }",
            "int f(int x __attribute__((unused))) { return 1; }",
        )
        for src in bad:
            with self.subTest(src=src):
                with self.assertRaises(MigrationRejected):
                    self.convert(src)

    def test_dangling_output_symlink_cannot_redirect_generated_source(self):
        src = self.root / 'input.c'
        src.write_text('int f(int a) { return a; }')
        output = self.root / 'alias.hepta'
        redirected = self.root / 'unintended.hepta'
        output.symlink_to(redirected)
        self.assertEqual(main([str(src), '-o', str(output), '--clang', CLANG]), 1)
        self.assertTrue(output.is_symlink())
        self.assertFalse(redirected.exists())

    def test_cli_does_not_overwrite_existing_target(self):
        src = self.root / "input.c"
        src.write_text("int f(int a) { return a; }")
        target = self.root / "out.hepta"
        target.write_text("sentinel")
        self.assertEqual(main([str(src), "-o", str(target), "--clang", CLANG]), 1)
        self.assertEqual(target.read_text(), "sentinel")

    def test_optional_native_c_vs_hepta_abi_differential(self):
        from hepta.ast import HeptaError
        from hepta.backend import find_rustc, compile_rust
        from hepta.pipeline import analyze
        try:
            rustc = find_rustc()
        except HeptaError:
            self.skipTest("pinned rustc is not available")
        migrated = self.convert()
        checked = analyze(migrated.source, path=str(self.root / "migrated.hepta"),
                          rustc=rustc, crate_type="cdylib")
        self.assertTrue(checked.report["ok"], checked.report["diagnostics"])
        hepta_so = self.root / "libmigrated.so"
        c_so = self.root / "liboriginal.so"
        hepta_report = compile_rust(checked.rust, rustc=rustc, crate_type="cdylib", output=hepta_so)
        self.assertTrue(hepta_report["ok"], hepta_report["diagnostics"])
        subprocess.run([CLANG, "-shared", "-fPIC", "-O2", str(self.root / "input.c"),
                        "-o", str(c_so)], check=True, capture_output=True, timeout=30)
        original = ctypes.CDLL(str(c_so))
        candidate = ctypes.CDLL(str(hepta_so))
        for name, arity, samples in (
            ("add", 2, [(1, 2), (-10, 11), (2_000_000, -900_000)]),
            ("bigger", 2, [(-5, -2), (200, 200), (17, -33)]),
            ("accumulate", 1, [(0,), (1,), (12,), (100,), (1000,)]),
        ):
            left, right = getattr(original, name), getattr(candidate, name)
            for fn in (left, right):
                fn.restype = ctypes.c_int32
                fn.argtypes = [ctypes.c_int32] * arity
            for args in samples:
                with self.subTest(name=name, args=args):
                    self.assertEqual(left(*args), right(*args))


if __name__ == "__main__":
    unittest.main()
