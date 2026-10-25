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
            'int f(int a) noexcept { return a; } int g(int a) noexcept { int x; return a; }',
            'int f(int a) noexcept { int x = a; int x = 1; return x; }',
            'int f(int a) noexcept { if (a > 0) { int y = a; return y; } return a; }',
            'int f(int a) noexcept { int x = a; x += 1; return x; }',
            'int f(int a) noexcept { static int x = 0; x = x + a; return x; }',
            'int f(int a) noexcept { static thread_local int x = 0; x = x + a; return x; }',
        ]
        for text in negative:
            with self.subTest(text=text):
                self.src.write_text(text)
                result = migrate_cpp(self.src, self.dst)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["converted"], [])
                self.assertFalse(self.dst.exists())
        self.assertTrue(len(negative) >= 9)

    def test_checked_stateful_locals_and_while_translate(self):
        self.src.write_text("""
int sum_to(int n) noexcept {
    int total = 0;
    int i = 0;
    while (i < n) { total = total + i; i = i + 1; }
    return total;
}
int clamp_local(int x) noexcept {
    int y = x;
    if (y < 0) { y = 0; }
    return y;
}
""")
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["tier"], "L1")
        self.assertFalse(report["behavioral_equivalence_proved"])
        self.assertEqual(report["native_validation"], "not_run")
        generated = self.dst.read_text()
        self.assertIn("let mut total: i32 = 0;", generated)
        self.assertIn("resources {heap_allocations=0;may_block=false;", generated)
        self.assertIn("may_suspend=false;may_spawn=false;}", generated)
        self.assertIn("while (i < n)", generated)
        self.assertIn("y = 0;", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"], "frontend_only")

    @unittest.skipUnless(shutil.which("gcc"), "GCC is needed for C ABI native differential")
    def test_stateful_cpp_vs_hepta_native_differential(self):
        self.src.write_text("""
int sum_to(int n) noexcept {
    int total = 0;
    int i = 0;
    while (i < n) { total = total + i; i = i + 1; }
    return total;
}
int clamp_local(int x) noexcept {
    int y = x;
    if (y < 0) { y = 0; }
    return y;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        wrapper = self.root / "wrapped.cc"
        wrapper.write_text("""
int sum_to(int) noexcept;
int clamp_local(int) noexcept;
extern "C" int cpp_sum_to(int n) { return sum_to(n); }
extern "C" int cpp_clamp_local(int x) { return clamp_local(x); }
""")
        original = self.root / "liboriginal.so"
        result = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                 str(self.src), str(wrapper), "-o", str(original)],
                                capture_output=True, text=True, timeout=50)
        self.assertEqual(result.returncode, 0, result.stderr)
        translated = self.root / "libhepta.so"
        result = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                 "--backend", "c", "--crate-type", "cdylib", "-o",
                                 str(translated)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        cpp, hepta = ctypes.CDLL(str(original)), ctypes.CDLL(str(translated))
        cases = {"sum_to": [(-10,), (0,), (1,), (2,), (7,), (100,), (1000,)],
                 "clamp_local": [(-100,), (-1,), (0,), (1,), (1234,)]}
        for name, args_list in cases.items():
            left, right = getattr(cpp, "cpp_" + name), getattr(hepta, name)
            for fn in (left, right):
                fn.restype = ctypes.c_int32
                fn.argtypes = [ctypes.c_int32]
            for args in args_list:
                with self.subTest(name=name, args=args):
                    self.assertEqual(left(*args), right(*args))

    def test_cpp_counted_for_original_vs_hepta_native(self):
        self.src.write_text("""
int sum_for(int n) noexcept {
    int total = 0;
    int i = 0;
    for (i = 0; i < n; ++i) { total = total + i; }
    return total;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        self.assertFalse(migrated["cpp_abi_preserved"])
        generated = self.dst.read_text()
        self.assertIn("while (i < n)", generated)
        self.assertIn("i = (i + 1);", generated)
        wrapper = self.root / "for_wrapper.cc"
        wrapper.write_text("""
int sum_for(int) noexcept;
extern "C" int cpp_sum_for(int n) { return sum_for(n); }
""")
        original_so = self.root / "for_original.so"
        hepta_so = self.root / "for_hepta.so"
        original = subprocess.run(["clang++", "-std=c++20", "-O2", "-shared",
                                   "-fPIC", str(self.src), str(wrapper),
                                   "-o", str(original_so)],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(original.returncode, 0, original.stdout + original.stderr)
        native = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                 "--backend", "c", "--crate-type", "cdylib",
                                 "-o", str(hepta_so)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
        cpp = ctypes.CDLL(str(original_so)).cpp_sum_for
        hp = ctypes.CDLL(str(hepta_so)).sum_for
        for fn in (cpp, hp):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-8, 0, 1, 2, 9, 100, 1000):
            self.assertEqual(cpp(n), hp(n), n)


    def test_declared_for_shadowed_parameters_nested_and_repeated(self):
        # Clang source identities, not textual names, determine every reference.
        import re
        source = """
int twice(int n) noexcept {
    int total = 0;
    for (int i=0; i<n; ++i) { total = total + i; }
    for (int i=0; i<n; ++i) { total = total + i; }
    return total;
}
int nested(int n) noexcept {
    int total = 0;
    for (int i=0; i<n; ++i) {
        for (int i=0; i<2; ++i) { total = total + 1; }
    }
    return total;
}
int shadow(int i) noexcept {
    int total = 0;
    for (int i=0; i<4; ++i) { total = total + i; }
    return total + i;
}
"""
        self.src.write_text(source)
        result = migrate_cpp(self.src, self.dst)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["behavioral_equivalence_proved"])
        hepta = self.dst.read_text()
        names = re.findall(r"let mut (hepta_for_\d+_i): i32 = 0;", hepta)
        self.assertEqual(len(names), 5)
        self.assertEqual(len(set(names)), 5)
        self.assertIn("return (total + i);", hepta)  # function parameter, not for-local
        self.assertEqual(analyze(hepta, str(self.dst), native=False).report["status"], "frontend_only")
        previous_sha = result["output_sha256"]
        self.dst.unlink()
        self.assertEqual(previous_sha, migrate_cpp(self.src, self.dst)["output_sha256"])

    @unittest.skipUnless(shutil.which("gcc"), "GCC needed for C++ native differential")
    def test_declared_for_native_cpp_vs_hepta_c(self):
        self.src.write_text("""
int twice(int n) noexcept { int t=0;
    for(int i=0; i<n; ++i){t=t+i;}
    for(int i=0; i<n; ++i){t=t+i;}
    return t;
}
int nested(int n) noexcept { int t=0;
    for(int i=0; i<n; ++i){for(int i=0; i<2; ++i){t=t+1;}}
    return t;
}
int shadow(int i) noexcept { int t=0;
    for(int i=0; i<4; ++i){t=t+i;}
    return t+i;
}
""")
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        wrapper = self.root / "declared-for-wrap.cc"
        wrapper.write_text("""
int twice(int) noexcept; int nested(int) noexcept; int shadow(int) noexcept;
extern "C" int cpp_twice(int n){return twice(n);}
extern "C" int cpp_nested(int n){return nested(n);}
extern "C" int cpp_shadow(int n){return shadow(n);}
""")
        original = self.root / "original-declared-for.so"
        compiled = subprocess.run(["clang++", "-std=c++20", "-O2", "-shared", "-fPIC",
                                   str(self.src), str(wrapper), "-o", str(original)],
                                  capture_output=True, text=True, timeout=45)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        result_so = self.root / "hepta-declared-for.so"
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(result_so)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        cpp, hp = ctypes.CDLL(str(original)), ctypes.CDLL(str(result_so))
        cases = [-8, -1, 0, 1, 2, 7, 50, 500]
        for name in ("twice", "nested", "shadow"):
            ref_fn, new_fn = getattr(cpp, "cpp_" + name), getattr(hp, name)
            for fn in (ref_fn, new_fn):
                fn.argtypes = [ctypes.c_int32]
                fn.restype = ctypes.c_int32
            for n in cases:
                with self.subTest(name=name, n=n):
                    self.assertEqual(ref_fn(n), new_fn(n))

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
