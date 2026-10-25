"""C++20 L1 strictly reuses the C scalar lowering authority."""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
from unittest.mock import patch
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.cpp2hepta import _model, migrate_cpp
from hepta.c_migrate import MigrationRejected
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

    def test_rejects_wrong_cpp_host_model_and_foreign_target(self):
        from hepta import cpp2hepta
        from hepta.c_migrate import _run as native_run
        compiler = shutil.which("clang++")
        normal = _model(compiler)
        self.assertEqual(normal["sizeof_pointer"], 8)
        for mode in ("pointer", "target"):
            with self.subTest(mode=mode):
                def replace_capture(argv, **kwargs):
                    result = native_run(argv, **kwargs)
                    if mode == "pointer" and "-dM" in argv:
                        import re
                        result = re.sub(r"(?m)^#define __SIZEOF_POINTER__ 8$",
                                        "#define __SIZEOF_POINTER__ 4", result)
                    if mode == "target" and "-dumpmachine" in argv:
                        result = "riscv64-unknown-linux-gnu"
                    return result
                with patch.object(cpp2hepta, "_run", side_effect=replace_capture):
                    with self.assertRaises(MigrationRejected) as rejected:
                        _model(compiler)
                    self.assertEqual(rejected.exception.code,
                                     "E_CPP2HEPTA_MODEL" if mode == "pointer" else "E_CPP2HEPTA_TARGET")

    def test_strict_cpp_ast_reuses_c_expression_lowering(self):
        self.src.write_text(self._GOOD)
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["tier"], "L1")
        self.assertFalse(report["cpp_abi_preserved"])
        self.assertFalse(report["behavioral_equivalence_proved"])
        self.assertEqual(report["native_validation"], "not_run")
        self.assertRegex(report["target_model"]["compiler_sha256"], r"^[a-f0-9]{64}$")
        source = self.dst.read_text()
        self.assertIn('export "C" fn add(', source)
        self.assertIn('export "C" fn clamp(', source)
        self.assertEqual(analyze(source, str(self.dst), native=False).report["status"], "frontend_only")
        first_hash = report["output_sha256"]
        self.dst.unlink()
        self.assertEqual(first_hash, migrate_cpp(self.src, self.dst)["output_sha256"])

    @unittest.skipUnless(shutil.which("gcc"), "GCC needed for Hepta/C native differential")
    def test_cpp20_unsigned_unary_modular_operations(self):
        self.src.write_text("""
unsigned int uneg(unsigned int x) noexcept { return -x; }
unsigned long long unot(unsigned long long x) noexcept { return ~x; }
""")
        result = migrate_cpp(self.src, self.dst)
        self.assertTrue(result["ok"], result)
        generated = self.dst.read_text()
        self.assertIn("wrapping_sub(0, x)", generated)
        self.assertIn("(!x)", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"], "frontend_only")
        bridge = self.root / "unary_bridge.cc"
        bridge.write_text("""
unsigned int uneg(unsigned int) noexcept;
unsigned long long unot(unsigned long long) noexcept;
extern "C" unsigned int original_uneg(unsigned int x){return uneg(x);}
extern "C" unsigned long long original_unot(unsigned long long x){return unot(x);}
""")
        original, native = self.root / "unary_cpp.so", self.root / "unary_hepta.so"
        a = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                            str(self.src), str(bridge), "-o", str(original)],
                           capture_output=True, text=True, timeout=45)
        self.assertEqual(a.returncode, 0, a.stderr)
        b = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                            "--backend", "c", "--crate-type", "cdylib", "-o", str(native)],
                           capture_output=True, text=True, timeout=90)
        self.assertEqual(b.returncode, 0, b.stdout + b.stderr)
        old, converted = ctypes.CDLL(str(original)), ctypes.CDLL(str(native))
        for source_name, name, typ, inputs in (
            ("original_uneg", "uneg", ctypes.c_uint32, (0, 1, 2**31, 2**32-1)),
            ("original_unot", "unot", ctypes.c_uint64, (0, 1, 2**63, 2**64-1))):
            left, right = getattr(old, source_name), getattr(converted, name)
            for fn in (left, right):
                fn.argtypes, fn.restype = [typ], typ
            for x in inputs:
                with self.subTest(fn=name, x=x):
                    self.assertEqual(left(x), right(x))

    @unittest.skipUnless(shutil.which("gcc"), "GCC needed for Hepta/C native differential")
    def test_cpp20_divmod_shortcircuit_original_vs_hepta_native(self):
        self.src.write_text("""
int cpp_div(int a,int b) noexcept { return a / b; }
unsigned long long cpp_mod(unsigned long long a,unsigned long long b) noexcept { return a % b; }
int cpp_guard(int a,int b) noexcept {
    if (b != 0 && a / b > 2) { return 11; }
    if (b == 0 || a % b == 0) { return 9; }
    return 3;
}
""")
        converted = migrate_cpp(self.src, self.dst)
        self.assertTrue(converted["ok"], converted)
        self.assertEqual(converted["tier"], "L1")
        generated = self.dst.read_text()
        self.assertIn("&&", generated)
        self.assertIn("||", generated)
        self.assertIn("a / b", generated)
        self.assertIn("a % b", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"], "frontend_only")
        wrapper = self.root / "divmod_wrapper.cc"
        wrapper.write_text("""
int cpp_div(int,int) noexcept;
unsigned long long cpp_mod(unsigned long long,unsigned long long) noexcept;
int cpp_guard(int,int) noexcept;
extern "C" int abi_div(int a,int b){return cpp_div(a,b);}
extern "C" unsigned long long abi_mod(unsigned long long a,unsigned long long b){return cpp_mod(a,b);}
extern "C" int abi_guard(int a,int b){return cpp_guard(a,b);}
""")
        original, generated_so = self.root / "original_div.so", self.root / "hepta_div.so"
        c = subprocess.run(["clang++", "-std=c++20", "-O2", "-shared", "-fPIC",
                            str(self.src), str(wrapper), "-o", str(original)],
                           capture_output=True, text=True, timeout=45)
        self.assertEqual(c.returncode, 0, c.stderr)
        build = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(generated_so)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        original_lib, migrated_lib = ctypes.CDLL(str(original)), ctypes.CDLL(str(generated_so))
        for src, dst, typ, cases in (
            ("abi_div", "cpp_div", ctypes.c_int32,
             ((-100, -7), (-100, 7), (100, -7), (100, 7), (-(2**31), 1))),
            ("abi_mod", "cpp_mod", ctypes.c_uint64,
             ((2**64 - 1, 9), (2**63, 3), (0, 1), (123456789, 17))),
            ("abi_guard", "cpp_guard", ctypes.c_int32,
             ((-100, -7), (100, 7), (0, 7), (42, 0), (-(2**31), 1)))):
            left, right = getattr(original_lib, src), getattr(migrated_lib, dst)
            for fn in (left, right):
                fn.argtypes, fn.restype = [typ, typ], typ
            for args in cases:
                with self.subTest(function=dst, args=args):
                    self.assertEqual(left(*args), right(*args))

    @unittest.skipUnless(shutil.which("gcc"), "GCC required for C ABI differential")
    def test_wide_cpp_signatures_native_original_vs_hepta_c(self):
        # Defined inputs only for signed arithmetic; unsigned wrap is exact.
        self.src.write_text("""
unsigned int u32_add(unsigned int a, unsigned int b) noexcept { return a + b; }
unsigned long long u64_mix(unsigned long long a, unsigned long long b) noexcept { return a * b + 3ULL; }
long long i64_add(long long a, long long b) noexcept { return a + b; }
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        self.assertEqual(migrated["tier"], "L1")
        self.assertFalse(migrated["cpp_abi_preserved"])
        self.assertFalse(migrated["behavioral_equivalence_proved"])
        generated = self.dst.read_text()
        for signature in ("fn u32_add(a: u32, b: u32) -> u32",
                          "fn u64_mix(a: u64, b: u64) -> u64",
                          "fn i64_add(a: i64, b: i64) -> i64"):
            self.assertIn(signature, generated)
        self.assertIn("wrapping_add", generated)
        self.assertIn("wrapping_mul", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"], "frontend_only")
        wrapper = self.root / "wide_wrapper.cc"
        wrapper.write_text("""
unsigned int u32_add(unsigned int,unsigned int) noexcept;
unsigned long long u64_mix(unsigned long long,unsigned long long) noexcept;
long long i64_add(long long,long long) noexcept;
extern "C" unsigned int cpp_u32_add(unsigned int a,unsigned int b){return u32_add(a,b);}
extern "C" unsigned long long cpp_u64_mix(unsigned long long a,unsigned long long b){return u64_mix(a,b);}
extern "C" long long cpp_i64_add(long long a,long long b){return i64_add(a,b);}
""")
        original, native = self.root / "wide-cpp.so", self.root / "wide-hepta.so"
        built = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                str(self.src), str(wrapper), "-o", str(original)],
                               capture_output=True, text=True, timeout=45)
        self.assertEqual(built.returncode, 0, built.stderr)
        translated = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                     "--backend", "c", "--crate-type", "cdylib", "-o", str(native)],
                                    capture_output=True, text=True, timeout=90)
        self.assertEqual(translated.returncode, 0, translated.stderr + translated.stdout)
        cpp, hepta = ctypes.CDLL(str(original)), ctypes.CDLL(str(native))
        cases = {
            "u32_add": (ctypes.c_uint32, [(0, 0), (2**32-1, 1), (2**31, 2**31), (12345, 67890)]),
            "u64_mix": (ctypes.c_uint64, [(0, 0), (2**64-1, 1), (2**63, 2), (123456789, 987654321)]),
            "i64_add": (ctypes.c_int64, [(-100, 20), (2**63-1, 0), (-(2**63), 0), (-1234567, 7654321)]),
        }
        for name, (typ, inputs) in cases.items():
            left, right = getattr(cpp, "cpp_" + name), getattr(hepta, name)
            for fn in (left, right):
                fn.argtypes, fn.restype = [typ, typ], typ
            for args in inputs:
                with self.subTest(name=name, args=args):
                    self.assertEqual(left(*args), right(*args))

    @unittest.skipUnless(shutil.which("gcc"), "GCC needed for Hepta/C native differential")
    def test_cpp20_unsigned_shifts_original_vs_hepta_native(self):
        self.src.write_text("""
unsigned int left32(unsigned int value, unsigned int bits) noexcept { return value << bits; }
unsigned long long right64(unsigned long long value, unsigned long long bits) noexcept { return value >> bits; }
""")
        converted = migrate_cpp(self.src, self.dst)
        self.assertTrue(converted["ok"], converted)
        self.assertFalse(converted["cpp_abi_preserved"])
        hepta_source = self.dst.read_text()
        self.assertIn("value << bits", hepta_source)
        self.assertIn("value >> bits", hepta_source)
        self.assertEqual(analyze(hepta_source, str(self.dst), native=False).report["status"], "frontend_only")
        wrapper = self.root / "shifts_cpp_wrapper.cc"
        wrapper.write_text("""
unsigned int left32(unsigned int,unsigned int) noexcept;
unsigned long long right64(unsigned long long,unsigned long long) noexcept;
extern "C" unsigned int cpp_left32(unsigned int v,unsigned int b){return left32(v,b);}
extern "C" unsigned long long cpp_right64(unsigned long long v,unsigned long long b){return right64(v,b);}
""")
        original, result_so = self.root / "shifts_cpp.so", self.root / "shifts_hepta.so"
        built = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                str(self.src), str(wrapper), "-o", str(original)],
                               capture_output=True, text=True, timeout=45)
        self.assertEqual(built.returncode, 0, built.stderr)
        native = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                 "--backend", "c", "--crate-type", "cdylib", "-o", str(result_so)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(native.returncode, 0, native.stderr + native.stdout)
        old, hp = ctypes.CDLL(str(original)), ctypes.CDLL(str(result_so))
        for name, typ, width, samples in (
                ("left32", ctypes.c_uint32, 32, (0, 1, 2**31, 2**32-1)),
                ("right64", ctypes.c_uint64, 64, (0, 1, 2**63, 2**64-1))):
            lhs, rhs = getattr(old, "cpp_" + name), getattr(hp, name)
            for fn in (lhs, rhs):
                fn.argtypes = [typ, typ]
                fn.restype = typ
            for value in samples:
                for bits in (0, 1, 7, width - 1):
                    with self.subTest(name=name, value=value, bits=bits):
                        self.assertEqual(lhs(value, bits), rhs(value, bits))

    def test_cpp20_independent_shift_rhs_native_differential(self):
        self.src.write_text("""
unsigned int left_s32(unsigned int value,int bits) noexcept {return value << bits;}
unsigned int right_u64(unsigned int value,unsigned long long bits) noexcept {return value >> bits;}
unsigned long long left_s32_wide(unsigned long long value,int bits) noexcept {return value << bits;}
unsigned long long right_literal(unsigned long long value) noexcept {return value >> 7;}
""")
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["cpp_abi_preserved"])
        translated = self.dst.read_text()
        self.assertIn("value << (bits as u32)", translated)
        self.assertIn("value >> (bits as u32)", translated)
        self.assertIn("value << (bits as u64)", translated)
        self.assertIn("value >> (7 as u64)", translated)
        self.assertEqual(analyze(translated, str(self.dst), native=False).report["status"], "frontend_only")
        wrapper = self.root / "mixed-shift-wrap.cc"
        wrapper.write_text("""
unsigned int left_s32(unsigned int,int) noexcept;
unsigned int right_u64(unsigned int,unsigned long long) noexcept;
unsigned long long left_s32_wide(unsigned long long,int) noexcept;
unsigned long long right_literal(unsigned long long) noexcept;
extern "C" unsigned int cpp_left_s32(unsigned int a,int b){return left_s32(a,b);}
extern "C" unsigned int cpp_right_u64(unsigned int a,unsigned long long b){return right_u64(a,b);}
extern "C" unsigned long long cpp_left_s32_wide(unsigned long long a,int b){return left_s32_wide(a,b);}
extern "C" unsigned long long cpp_right_literal(unsigned long long a){return right_literal(a);}
""")
        original, hepta = self.root / "mixed-shift-original.so", self.root / "mixed-shift-hepta.so"
        old_build = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                    str(self.src), str(wrapper), "-o", str(original)],
                                   capture_output=True, text=True, timeout=45)
        self.assertEqual(old_build.returncode, 0, old_build.stderr)
        new_build = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                    "--backend", "c", "--crate-type", "cdylib", "-o", str(hepta)],
                                   capture_output=True, text=True, timeout=90)
        self.assertEqual(new_build.returncode, 0, new_build.stdout + new_build.stderr)
        old, new = ctypes.CDLL(str(original)), ctypes.CDLL(str(hepta))
        for name, ret, count_type, values, counts in (
                ("left_s32", ctypes.c_uint32, ctypes.c_int32, (0, 1, 2**31, 2**32-1), (0, 1, 7, 31)),
                ("right_u64", ctypes.c_uint32, ctypes.c_uint64, (0, 1, 2**31, 2**32-1), (0, 1, 7, 31)),
                ("left_s32_wide", ctypes.c_uint64, ctypes.c_int32, (0, 1, 2**63, 2**64-1), (0, 1, 7, 63)),
                ("right_literal", ctypes.c_uint64, None, (0, 1, 2**63, 2**64-1), (0,))):
            lhs, rhs = getattr(old, "cpp_" + name), getattr(new, name)
            for fn in (lhs, rhs):
                fn.argtypes = [ret] + ([count_type] if count_type is not None else [])
                fn.restype = ret
            for value in values:
                for count in counts:
                    args = (value, count) if count_type is not None else (value,)
                    with self.subTest(name=name, args=args):
                        self.assertEqual(lhs(*args), rhs(*args))

    def test_signed_cpp_shift_rejected(self):
        self.src.write_text("int bad(int x,int b) noexcept {return x << b;}")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertFalse(migrated["ok"], migrated)
        self.assertEqual(migrated["rejected"][0]["code"], "E_C_SHIFT_SIGNED")
        self.assertFalse(self.dst.exists())

    def test_wide_cpp_rejects_unmodeled_abi_types(self):
        for source in ("long double f(long double x) noexcept { return x; }",
                       "bool f(bool x) noexcept { return x; }",
                       "unsigned int *f(unsigned int *x) noexcept { return x; }"):
            with self.subTest(source=source):
                self.src.write_text(source)
                result = migrate_cpp(self.src, self.dst)
                self.assertFalse(result["ok"], result)
                self.assertFalse(self.dst.exists())

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


    def test_do_while_cpp20_native_differential(self):
        self.src.write_text("""
int do_sum(int n) noexcept {
    int total=0; int i=0;
    do { total=total+i; i=i+1; } while(i<n);
    return total;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        generated = self.dst.read_text()
        self.assertIn("while (i < n)", generated)
        self.assertEqual(generated.count("total = (total + i);"), 2)
        self.assertFalse(migrated["cpp_abi_preserved"])
        wrapper = self.root / "do-wrapper.cc"
        wrapper.write_text("""
int do_sum(int) noexcept;
extern "C" int cpp_do_sum(int n){return do_sum(n);}
""")
        reference = self.root / "do-original.so"
        output = self.root / "do-hepta.so"
        compiled = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                   str(self.src), str(wrapper), "-o", str(reference)],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(output)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        cpp, hepta = ctypes.CDLL(str(reference)).cpp_do_sum, ctypes.CDLL(str(output)).do_sum
        for fn in (cpp, hepta):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-10, -1, 0, 1, 2, 7, 50, 500):
            self.assertEqual(cpp(n), hepta(n), n)


    def test_ternary_cpp20_return_and_assignment_native(self):
        self.src.write_text("""
int choose(int x, int y) noexcept { return x > y ? x : y; }
int clamp(int x) noexcept { int y=0; y = x > 0 ? x : 0; return y; }
""")
        translated = migrate_cpp(self.src, self.dst)
        self.assertTrue(translated["ok"], translated)
        self.assertFalse(translated["cpp_abi_preserved"])
        generated = self.dst.read_text()
        self.assertIn("if (x > y)", generated)
        self.assertIn("y = 0;", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"],
                         "frontend_only")
        wrapper = self.root / "ternary_wrapper.cc"
        wrapper.write_text("""
int choose(int, int) noexcept; int clamp(int) noexcept;
extern "C" int cpp_choose(int x,int y){return choose(x,y);}
extern "C" int cpp_clamp(int x){return clamp(x);}
""")
        original, hepta = self.root / "ternary_orig.so", self.root / "ternary_hepta.so"
        native = subprocess.run(["clang++", "-std=c++20", "-O2", "-shared", "-fPIC",
                                 str(self.src), str(wrapper), "-o", str(original)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(native.returncode, 0, native.stderr)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(hepta)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        cpp, hp = ctypes.CDLL(str(original)), ctypes.CDLL(str(hepta))
        for name, rows in (
                ("choose", [(-20, -50), (0, 1), (7, 5), (2**31-1, -1)]),
                ("clamp", [(-2**31,), (-7,), (0,), (1,), (555,)])):
            left, right = getattr(cpp, "cpp_" + name), getattr(hp, name)
            for fn in (left, right):
                fn.argtypes = [ctypes.c_int32] * len(rows[0])
                fn.restype = ctypes.c_int32
            for row in rows:
                self.assertEqual(left(*row), right(*row), (name, row))

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
