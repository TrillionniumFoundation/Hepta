"""C++20 L1 strictly reuses the C scalar lowering authority."""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.cpp2hepta import migrate_cpp
from hepta.pipeline import analyze


@unittest.skipUnless(shutil.which("clang++"), "Clang++ is required for exact C++ AST")
class CppStrictL1Tests(unittest.TestCase):
    _GOOD = """
int add(int a, int b) noexcept { return a + b; }
int clamp(int x) noexcept {
    if (x < 0) { return 0; }
    return x;
}
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "project.cc"
        self.dst = self.root / "migrated.hepta"

    def test_strict_cpp_ast_reuses_c_expression_lowering(self):
        self.src.write_text(self._GOOD)
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["tier"], "L1")
        self.assertFalse(report["cpp_abi_preserved"])
        self.assertFalse(report["behavioral_equivalence_proved"])
        self.assertEqual(report["native_validation"], "not_run")
        source = self.dst.read_text()
        self.assertIn('export "C" fn add(', source)
        self.assertIn('export "C" fn clamp(', source)
        self.assertEqual(analyze(source, str(self.dst), native=False).report["status"], "frontend_only")
        first_hash = report["output_sha256"]
        self.dst.unlink()
        self.assertEqual(first_hash, migrate_cpp(self.src, self.dst)["output_sha256"])

    def test_unsafe_cpp_constructs_never_partially_publish(self):
        negative = [
            'class Foo { public: int x; }; int f(int a) noexcept {return a;}',
            'int *f(int *p) noexcept {return p;}',
            'int f(int a) {return a;}',
            'int f(int a) noexcept {return a;} int f(int a,int b) noexcept {return a+b;}',
            'int f(int a=1) noexcept {return a;}',
            '#define FLAG 1\nint f(int a) noexcept {return a+FLAG;}',
            'int shared=4; int f(int a) noexcept{return a+shared;}',
            'template<typename T> T f(T x) noexcept {return x;}',
            'int f(int a) noexcept { return a; } int g(int a) noexcept { int x = a; return x; }',
        ]
        for text in negative:
            with self.subTest(text=text):
                self.src.write_text(text)
                result = migrate_cpp(self.src, self.dst)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["converted"], [])
                self.assertFalse(self.dst.exists())
        self.assertTrue(len(negative) >= 9)

    def test_hidden_preprocessor_forms_never_publish(self):
        sources = [
            '%:define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
            '/*comment*/ #define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
            '%\\' + '\n:define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.src.write_text(source)
                report = migrate_cpp(self.src, self.dst)
                self.assertFalse(report["ok"], report)
                self.assertEqual(report["rejected"][0]["code"], "E_CPP2HEPTA_PREPROCESSOR")
                self.assertFalse(self.dst.exists())

    def test_dangling_output_alias_and_existing_source_are_not_replaced(self):
        self.src.write_text(self._GOOD)
        target = self.root / "redirected.hepta"
        self.dst.symlink_to(target)
        report = migrate_cpp(self.src, self.dst)
        self.assertFalse(report["ok"])
        self.assertTrue(self.dst.is_symlink())
        self.assertFalse(target.exists())

    @unittest.skipUnless(shutil.which("gcc"), "C native differential runner requires GCC")
    def test_defined_cpp_vs_hepta_native_c_abi_differential(self):
        self.src.write_text(self._GOOD)
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        # Test C++ original through an explicit C ABI wrapper: NEVER infer
        # preservation of C++ mangled ABI from the generated Hepta exports.
        wrap = self.root / "wrapped.cc"
        wrap.write_text("""
int add(int, int) noexcept;
int clamp(int) noexcept;
extern "C" int cpp_add(int a,int b) { return add(a,b); }
extern "C" int cpp_clamp(int x) { return clamp(x); }
""")
        reference = self.root / "libreference.so"
        build_original = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                         str(self.src), str(wrap), "-o", str(reference)],
                                        capture_output=True, text=True, timeout=50)
        self.assertEqual(build_original.returncode, 0, build_original.stderr)
        translated = self.root / "libhepta.so"
        build_hepta = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                      "--backend", "c", "--crate-type", "cdylib", "-o", str(translated)],
                                      capture_output=True, text=True, timeout=90)
        self.assertEqual(build_hepta.returncode, 0, build_hepta.stderr+build_hepta.stdout)
        cpp, hepta = ctypes.CDLL(str(reference)), ctypes.CDLL(str(translated))
        cases = {"add": [(0, 0), (2, 3), (-12, 55), (129, -22)],
                 "clamp": [(-3,), (-1,), (0,), (40,)]}
        for name, vals in cases.items():
            original_fn, converted_fn = getattr(cpp, "cpp_"+name), getattr(hepta, name)
            for fn in (original_fn, converted_fn):
                fn.restype = ctypes.c_int32
                fn.argtypes = [ctypes.c_int32] * len(vals[0])
            for args in vals:
                with self.subTest(function=name,args=args):
                    self.assertEqual(original_fn(*args), converted_fn(*args))
