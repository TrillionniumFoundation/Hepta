"""C/C++ int/bool ABI migrations: real AST conversion, strict negative cases."""
from __future__ import annotations

import ctypes
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from hepta.c2hepta import MigrationRejected, convert_c
from hepta.cpp2hepta import convert_cpp

C_SOURCE = """int compare(int a, int b) { return a < b; }
int logic(int a, int b) { int flag = a != 0; flag = a && b; return flag; }
int negate(int a) { return !a; }
"""
CPP_SOURCE = C_SOURCE.replace(") {", ") noexcept {")


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"), "requires Clang and Clang++")
class BooleanIntegerMigrationTests(unittest.TestCase):
    def test_real_ast_and_explicit_zero_one_lowering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for language, source, converter, suffix in (
                ("c", C_SOURCE, convert_c, ".c"),
                ("cpp", CPP_SOURCE, convert_cpp, ".cc"),
            ):
                original = root / ("source" + suffix)
                original.write_text(source)
                translated = converter(original)
                with self.subTest(language=language):
                    self.assertEqual(translated.report["status"], "candidate_unverified")
                    self.assertFalse(translated.report["semantic_equivalence_proved"])
                    self.assertFalse(translated.report["memory_safety_proved"])
                    self.assertIn("if (a < b) {\n        return 1;", translated.source)
                    self.assertIn("let mut flag: i32 = 0;", translated.source)
                    self.assertIn("if ((a != 0) && (b != 0))", translated.source)
                    self.assertIn("if (!(a != 0)) {", translated.source)
                    self.assertEqual(translated.source, converter(original).source)

    def test_unsupported_implicit_arithmetic_still_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "original.cc"
            for candidate in (
                "int f(bool x) noexcept {return x;}",
                "int f(int x) noexcept {return (unsigned int)x;}",
                "int f(int x) noexcept {return (x < 0) + 4;}",
            ):
                source.write_text(candidate)
                with self.subTest(candidate=candidate):
                    with self.assertRaises(MigrationRejected):
                        convert_cpp(source)

    def test_native_original_c_and_cpp_return_0_or_1(self):
        # Original-program oracles; native migrated Hepta equivalence is a
        # *separate* opt-in real rustc gate, never inferred from this test.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for language, src, compiler, suffix in (
                ("c", C_SOURCE, "clang", ".c"),
                ("cpp", CPP_SOURCE, "clang++", ".cc"),
            ):
                source = root / ("ref" + suffix)
                if language == "cpp":
                    src = 'extern "C" {\n' + src + '\n}\n'
                source.write_text(src)
                obj = root / (language + ".so")
                subprocess.run([compiler, "-std=c++20" if language == "cpp" else "-std=c11",
                                "-O2", "-fPIC", "-shared", str(source), "-o", str(obj)],
                               check=True, capture_output=True, timeout=20)
                lib = ctypes.CDLL(str(obj))
                rng = random.Random(83201)
                inputs = [(0, 0), (0, 7), (7, 0), (-17, -8), (-(2**31), 2**31-1)]
                inputs += [(rng.randrange(-10000,10000), rng.randrange(-10000,10000))
                           for _ in range(100)]
                for name in ("compare", "logic", "negate"):
                    fn = getattr(lib, name)
                    fn.restype = ctypes.c_int32
                    fn.argtypes = [ctypes.c_int32] * (1 if name == "negate" else 2)
                    for a, b in inputs:
                        value = fn(a) if name == "negate" else fn(a,b)
                        expected = (int(a < b) if name == "compare" else
                                    int(bool(a) and bool(b)) if name == "logic" else int(a == 0))
                        self.assertEqual(value, expected)

    def test_optional_hepta_native_differential(self):
        try:
            from hepta.ast import HeptaError
            from hepta.backend import find_rustc, compile_rust
            from hepta.pipeline import analyze
            from hepta.cpp_bridge import generate_cpp_bridge
        except ModuleNotFoundError:
            self.skipTest("Complete Hepta frontend not available")
        try:
            rustc = find_rustc()
        except HeptaError:
            self.skipTest("Pinned Rust compiler not available")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for language, src, converter, compiler, suffix in (
                ("c", C_SOURCE, convert_c, "clang", ".c"),
                ("cpp", CPP_SOURCE, convert_cpp, "clang++", ".cc"),
            ):
                original = root / ("original" + suffix)
                original.write_text(src)
                translated = converter(original)
                checked = analyze(translated.source, path=str(root / (language + ".hepta")),
                                  rustc=rustc, crate_type="cdylib")
                self.assertTrue(checked.report["ok"], checked.report["diagnostics"])
                target = root / (language + "_hepta.so")
                result = compile_rust(checked.rust, rustc=rustc, crate_type="cdylib", output=target)
                self.assertTrue(result["ok"], result["diagnostics"])
                other = root / (language + "_original.so")
                original_sources = [str(original)]
                symbol_prefix = ""
                if language == "cpp":
                    wrapper = root / "bridge.cc"
                    wrapper.write_text(generate_cpp_bridge(original).source)
                    original_sources.append(str(wrapper))
                    symbol_prefix = "hepta_cxx_"
                subprocess.run([compiler, "-O2", "-shared", "-fPIC", *original_sources,
                                "-o", str(other)], check=True, capture_output=True, timeout=20)
                ref = ctypes.CDLL(str(other))
                hepta = ctypes.CDLL(str(target))
                for name in ("compare", "logic", "negate"):
                    lhs, rhs = getattr(ref, symbol_prefix + name), getattr(hepta, name)
                    for f in (lhs, rhs):
                        f.restype = ctypes.c_int32
                        f.argtypes = [ctypes.c_int32] * (1 if name == "negate" else 2)
                    for a, b in [(0, 0), (4, 7), (0, -8), (-1000, 999), (65535, 0)]:
                        params = (a,) if name == "negate" else (a,b)
                        self.assertEqual(lhs(*params), rhs(*params))


if __name__ == "__main__":
    unittest.main()
