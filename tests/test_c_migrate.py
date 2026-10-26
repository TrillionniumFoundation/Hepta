"""Clang-backed C->Hepta strict scalar pilot: positive and negative gates."""
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hepta.c_migrate as strict_migrator
from hepta.c_migrate import migrate_c
from hepta.pipeline import analyze


C_SOURCE = """
#include <stdint.h>
int32_t add(int32_t x, int32_t y) { return x + y; }
uint64_t xor_mask(uint64_t x, uint64_t y) { return x ^ y; }
uint64_t add_wrap(uint64_t x, uint64_t y) { return x + y; }
int32_t clamp_positive(int32_t x) {
    if (x < 0) { return 0; }
    return x;
}
"""


class ClangMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.c = self.directory / "input.c"
        self.hepta = self.directory / "translated.hepta"
        self.c.write_text(C_SOURCE, encoding="utf-8")
        self.assertIsNotNone(shutil.which("clang"), "Clang is mandatory for this migration qualification")

    def test_three_functions_migrate_and_frontend_check(self):
        result = migrate_c(self.c, self.hepta)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "frontend_checked_not_native_qualified")
        self.assertEqual(len(result["converted"]), 4)
        self.assertEqual(result["target_model"]["sizeof_int"], 4)
        self.assertFalse(result["source_equivalence_proved"])
        self.assertEqual(result["native_validation"], "not_run")
        source = self.hepta.read_text(encoding="utf-8")
        checked = analyze(source, str(self.hepta), native=False)
        self.assertTrue(checked.report["ok"], checked.report)
        self.assertIn('export "C" fn add', source)
        self.assertIn('export "C" fn clamp_positive', source)
        self.assertIn("wrapping_add(x, y)", source)

    def test_unsigned_unary_modular_and_complement_vs_native_c(self):
        self.c.write_text("""
unsigned int neg32(unsigned int x) { return -x; }
unsigned int bitnot32(unsigned int x) { return ~x; }
unsigned long long neg64(unsigned long long x) { return -x; }
unsigned long long bitnot64(unsigned long long x) { return ~x; }
""")
        migrated = migrate_c(self.c, self.hepta)
        self.assertTrue(migrated["ok"], migrated)
        source = self.hepta.read_text()
        self.assertIn("wrapping_sub(0, x)", source)
        self.assertIn("(!x)", source)
        self.assertEqual(analyze(source, str(self.hepta), native=False).report["status"], "frontend_only")
        original, native = self.directory / "unary-original.so", self.directory / "unary-hepta.so"
        a = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", str(self.c), "-o", str(original)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(a.returncode, 0, a.stderr)
        b = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                            "--backend", "c", "--crate-type", "cdylib", "-o", str(native)],
                           capture_output=True, text=True, timeout=90)
        self.assertEqual(b.returncode, 0, b.stdout + b.stderr)
        old, translated = ctypes.CDLL(str(original)), ctypes.CDLL(str(native))
        for name, typ, cases in (
            ("neg32", ctypes.c_uint32, (0, 1, 2**31, 2**32-1)),
            ("bitnot32", ctypes.c_uint32, (0, 1, 2**31, 2**32-1)),
            ("neg64", ctypes.c_uint64, (0, 1, 2**63, 2**64-1)),
            ("bitnot64", ctypes.c_uint64, (0, 1, 2**63, 2**64-1))):
            left, right = getattr(old, name), getattr(translated, name)
            for fn in (left, right):
                fn.argtypes, fn.restype = [typ], typ
            for x in cases:
                with self.subTest(fn=name, x=x):
                    self.assertEqual(left(x), right(x))

    def test_signed_bitwise_complement_stays_rejected(self):
        self.c.write_text("int unsafe_bits(int x){return ~x;}")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_BITWISE", [entry["code"] for entry in result["rejected"]])
        self.assertFalse(self.hepta.exists())

    def test_divmod_shortcircuit_c11_vs_hepta_c_defined_domain(self):
        self.c.write_text("""
int safe_div(int a,int b) { return a / b; }
int safe_mod(int a,int b) { return a % b; }
unsigned long long unsigned_mod(unsigned long long a,unsigned long long b) { return a % b; }
int safe_guard(int a,int b) {
    if (b != 0 && a / b > 1) { return 7; }
    if (b == 0 || a % b == 0) { return 9; }
    if (!(a < 0)) { return 4; }
    return 2;
}
""")
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["source_equivalence_proved"])
        source = self.hepta.read_text()
        self.assertIn("a / b", source)
        self.assertIn("a % b", source)
        self.assertIn("&&", source)
        self.assertIn("||", source)
        self.assertIn("!(", source)
        self.assertEqual(analyze(source, str(self.hepta), native=False).report["status"], "frontend_only")
        original, hepta_native = self.directory / "div-original.so", self.directory / "div-hepta.so"
        original_run = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                                       str(self.c), "-o", str(original)],
                                      capture_output=True, text=True, timeout=30)
        self.assertEqual(original_run.returncode, 0, original_run.stderr)
        native_run = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                     "--backend", "c", "--crate-type", "cdylib", "-o", str(hepta_native)],
                                    capture_output=True, text=True, timeout=90)
        self.assertEqual(native_run.returncode, 0, native_run.stdout + native_run.stderr)
        old, new = ctypes.CDLL(str(original)), ctypes.CDLL(str(hepta_native))
        for name in ("safe_div", "safe_mod", "safe_guard", "unsigned_mod"):
            a, b = getattr(old, name), getattr(new, name)
            typ = ctypes.c_uint64 if name == "unsigned_mod" else ctypes.c_int32
            for fn in (a, b):
                fn.argtypes, fn.restype = [typ, typ], typ
            samples = (((2**64-1, 3), (0, 1), (2**63, 7), (0x1234567890abcdef, 11))
                       if name == "unsigned_mod" else
                       ((-99, -7), (-99, 7), (99, -7), (99, 7), (0, 3),
                        (-(2**31), 1), (2**31-1, -1), (5, 0)))
            for x, y in samples:
                if y == 0 and name != "safe_guard":
                    continue  # C zero divisor is undefined
                with self.subTest(name=name, args=(x, y)):
                    self.assertEqual(a(x, y), b(x, y))

    def test_divmod_nontrivial_promotions_and_truthiness_reject(self):
        for source, code in (
            ("int f(int a,unsigned int b){return a / b;}", "E_C_DIVMOD_PROMOTION"),
            ("int f(int a,int b){if(a && b){return 1;}return 0;}", "E_C_PROMOTION"),
            ("int f(int a){if(!a){return 1;}return 0;}", "E_C_PROMOTION"),
        ):
            with self.subTest(source=source):
                self.c.write_text(source)
                result = migrate_c(self.c, self.hepta)
                self.assertFalse(result["ok"], result)
                self.assertIn(code, [entry["code"] for entry in result["rejected"]])
                self.assertFalse(self.hepta.exists())

    def test_unsigned_shift_c11_vs_hepta_c_native_defined_domain(self):
        self.c.write_text("""
unsigned int shl32(unsigned int value, unsigned int bits) { return value << bits; }
unsigned int shr32(unsigned int value, unsigned int bits) { return value >> bits; }
unsigned long long shl64(unsigned long long value, unsigned long long bits) { return value << bits; }
""")
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["source_equivalence_proved"])
        text = self.hepta.read_text()
        self.assertIn("value << bits", text)
        self.assertIn("value >> bits", text)
        self.assertEqual(analyze(text, str(self.hepta), native=False).report["status"], "frontend_only")
        original, converted = self.directory / "shifts-original.so", self.directory / "shifts-hepta.so"
        compile_c = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", str(self.c),
                                    "-o", str(original)], capture_output=True, text=True, timeout=30)
        self.assertEqual(compile_c.returncode, 0, compile_c.stderr)
        compiled = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                   "--backend", "c", "--crate-type", "cdylib", "-o", str(converted)],
                                  capture_output=True, text=True, timeout=90)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        left, right = ctypes.CDLL(str(original)), ctypes.CDLL(str(converted))
        profiles = {
            "shl32": (ctypes.c_uint32, 32, (0, 1, 2**31, 2**32-1)),
            "shr32": (ctypes.c_uint32, 32, (0, 1, 2**31, 2**32-1)),
            "shl64": (ctypes.c_uint64, 64, (0, 1, 2**63, 2**64-1)),
        }
        for name, (typ, width, values) in profiles.items():
            lhs, rhs = getattr(left, name), getattr(right, name)
            for fn in (lhs, rhs):
                fn.argtypes = [typ, typ]
                fn.restype = typ
            for bits in (0, 1, 7, width - 1):
                for value in values:
                    with self.subTest(name=name, value=value, bits=bits):
                        self.assertEqual(lhs(value, bits), rhs(value, bits))

    def test_unsigned_shift_independent_rhs_types_original_c_vs_hepta_native(self):
        # Shift result follows the promoted lhs, while the C count type is
        # independent. Retain exact behavior only for defined counts.
        self.c.write_text("""
unsigned int left_s32(unsigned int value,int bits) {return value << bits;}
unsigned int right_u64(unsigned int value,unsigned long long bits) {return value >> bits;}
unsigned long long left_s32_wide(unsigned long long value,int bits) {return value << bits;}
unsigned long long right_literal(unsigned long long value) {return value >> 7;}
""")
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        source = self.hepta.read_text()
        self.assertIn("value << (bits as u32)", source)
        self.assertIn("value >> (bits as u32)", source)
        self.assertIn("value << (bits as u64)", source)
        self.assertIn("value >> (7 as u64)", source)
        self.assertEqual(analyze(source, str(self.hepta), native=False).report["status"], "frontend_only")
        original = self.directory / "rhs-original.so"
        converted = self.directory / "rhs-hepta.so"
        ref_build = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                                    str(self.c), "-o", str(original)],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(ref_build.returncode, 0, ref_build.stderr)
        hp_build = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                   "--backend", "c", "--crate-type", "cdylib", "-o", str(converted)],
                                  capture_output=True, text=True, timeout=90)
        self.assertEqual(hp_build.returncode, 0, hp_build.stdout + hp_build.stderr)
        old, new = ctypes.CDLL(str(original)), ctypes.CDLL(str(converted))
        for name, ret, count_type, values, counts in (
                ("left_s32", ctypes.c_uint32, ctypes.c_int32, (0, 1, 2**31, 2**32-1), (0, 1, 7, 31)),
                ("right_u64", ctypes.c_uint32, ctypes.c_uint64, (0, 1, 2**31, 2**32-1), (0, 1, 7, 31)),
                ("left_s32_wide", ctypes.c_uint64, ctypes.c_int32, (0, 1, 2**63, 2**64-1), (0, 1, 7, 63)),
                ("right_literal", ctypes.c_uint64, None, (0, 1, 2**63, 2**64-1), (0,))):
            lhs, rhs = getattr(old, name), getattr(new, name)
            for fn in (lhs, rhs):
                fn.argtypes = [ret] + ([count_type] if count_type is not None else [])
                fn.restype = ret
            for value in values:
                for count in counts:
                    args = (value, count) if count_type is not None else (value,)
                    with self.subTest(name=name, args=args):
                        self.assertEqual(lhs(*args), rhs(*args))

    def test_signed_shift_is_still_rejected_without_publication(self):
        self.c.write_text("int unsafe_shift(int value, int bits) { return value << bits; }")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SHIFT_SIGNED", [d["code"] for d in result["rejected"]])
        self.assertFalse(self.hepta.exists())

    def test_pointer_function_refuses_entire_input(self):
        self.c.write_text(C_SOURCE + "\nint32_t pointer(int32_t* p) {return *p;}\n")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["status"], "unsupported_source")
        self.assertEqual(result["converted"], [])
        self.assertFalse(self.hepta.exists())

    def test_global_access_does_not_look_like_local_parameter(self):
        self.c.write_text("int shared = 7; int f(int x) {return x + shared;}\n")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_TOPLEVEL", [x["code"] for x in result["rejected"]])
        self.assertFalse(self.hepta.exists())

    def test_strict_c_scalar_state_and_while(self):
        self.c.write_text("""
int sum_to(int n) {
    int total = 0;
    int i = 0;
    while (i < n) { total = total + i; i = i + 1; }
    return total;
}
""")
        result = migrate_c(self.c, self.hepta)
        self.assertTrue(result["ok"], result)
        self.assertIn("let mut total: i32 = 0;", self.hepta.read_text())
        self.assertIn("resources {heap_allocations=0;may_block=false;", self.hepta.read_text())
        self.assertIn("while (i < n)", self.hepta.read_text())
        original = self.directory / "liboriginal.so"
        output = self.directory / "libhepta.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                        str(self.c), "-o", str(original)], check=True, capture_output=True)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(output)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        old = ctypes.CDLL(str(original)).sum_to
        new = ctypes.CDLL(str(output)).sum_to
        for func in (old, new):
            func.argtypes = [ctypes.c_int32]
            func.restype = ctypes.c_int32
        for n in (-4, 0, 1, 2, 5, 40, 100):
            self.assertEqual(old(n), new(n), n)

    def test_for_condition_variable_slot_forgery_stays_rejected(self):
        # Clang uses {} for an *absent* ForStmt condition-variable slot.
        # A populated slot must never be silently dropped during lowering.
        fake = {"kind": "ForStmt", "inner": [
            {"kind": "DeclStmt"}, {"kind": "VarDecl", "name": "hidden"},
            {"kind": "BinaryOperator"}, {"kind": "UnaryOperator"},
            {"kind": "CompoundStmt"},
        ]}
        with self.assertRaisesRegex(strict_migrator.MigrationRejected,
                                    "For requires explicit init"):
            strict_migrator._stmt(fake, {}, {}, "i32")
        self.assertFalse(self.hepta.exists())

    def test_counted_for_original_c_vs_hepta_native(self):
        self.c.write_text("""
int sum_for(int n) {
    int total = 0;
    int i = 0;
    for (i = 0; i < n; i++) { total = total + i; }
    return total;
}
""")
        migrated = migrate_c(self.c, self.hepta)
        self.assertTrue(migrated["ok"], migrated)
        self.assertEqual(migrated["native_validation"], "not_run")
        generated = self.hepta.read_text()
        self.assertIn("while (i < n)", generated)
        self.assertIn("i = (i + 1);", generated)
        native_c = self.directory / "for_original.so"
        native_hepta = self.directory / "for_hepta.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                        str(self.c), "-o", str(native_c)], check=True, capture_output=True)
        result = subprocess.run([sys.executable, "-m", "hepta", "build",
                                 str(self.hepta), "--backend", "c", "--crate-type",
                                 "cdylib", "-o", str(native_hepta)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        old = ctypes.CDLL(str(native_c)).sum_for
        new = ctypes.CDLL(str(native_hepta)).sum_for
        for fn in (old, new):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-8, -1, 0, 1, 2, 17, 100, 1000):
            self.assertEqual(old(n), new(n), n)

    def test_unsupported_for_syntax_rejected_without_output(self):
        sources = [
            "int f(int n){int x=0;for(int i=0;i<n;i++){x=x+i;}return x;}",
            "int f(int n){int i=0;for(i=0;i<n;i+=1){i=i+1;}return i;}",
            "int f(int n){int i=0;for(i=0;;i=i+1){if(i>3)return i;}return i;}",
            "int f(int n){int i=0;for(i=0;i<n;i=i+1)i=i+1;return i;}",
            "int f(int n){int i=0;for(i=0;i<n;i=i+1){continue;}return i;}",
        ]
        for src in sources:
            with self.subTest(src=src):
                self.c.write_text(src)
                result = migrate_c(self.c, self.hepta)
                self.assertFalse(result["ok"], result)
                self.assertFalse(self.hepta.exists())


    def test_declared_for_unsigned_and_repeated_scoped_names(self):
        import re
        self.c.write_text("""
unsigned int sum_unsigned(unsigned int n) {
    unsigned int total=0;
    for(unsigned int i=0; i<n; ++i){ total=total+i; }
    return total;
}
int twice(int n) {
    int total=0;
    for(int i=0; i<n; ++i){ total=total+i; }
    for(int i=0; i<n; ++i){ total=total+i; }
    return total;
}
""")
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        generated = self.hepta.read_text()
        self.assertRegex(generated, r"let mut hepta_for_\d+_i: u32 = 0;")
        names = re.findall(r"let mut (hepta_for_\d+_i): i32 = 0;", generated)
        self.assertEqual(len(names), 2)
        self.assertNotEqual(names[0], names[1])
        self.assertIn("wrapping_add(", generated)
        self.assertEqual(analyze(generated, str(self.hepta), native=False).report["status"],
                         "frontend_only")
        old = self.directory / "declared-original.so"
        new = self.directory / "declared-hepta.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                        str(self.c), "-o", str(old)], check=True, capture_output=True)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(new)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        original, converted = ctypes.CDLL(str(old)), ctypes.CDLL(str(new))
        for name, signature, cases in (
                ("sum_unsigned", ctypes.c_uint32, [0, 1, 2, 7, 100, 500]),
                ("twice", ctypes.c_int32, [-50, -1, 0, 1, 2, 7, 100, 500])):
            left, right = getattr(original, name), getattr(converted, name)
            for fn in (left, right):
                fn.restype = signature
                fn.argtypes = [signature]
            for n in cases:
                with self.subTest(name=name, n=n):
                    self.assertEqual(left(n), right(n))

    def test_for_with_unsupported_declarations_still_rejects(self):
        cases = [
            "int f(int n){int r=0;for(int i; i<n; ++i){r=r+i;}return r;}",
            "int f(int n){int r=0;for(int i=0,j=0; i<n; ++i){r=r+i;}return r;}",
            "int f(int n){int r=0;for(static int i=0; i<n; ++i){r=r+i;}return r;}",
            "int f(int n){int r=0;for(int i=0; i<n; i+=1){r=r+i;}return r;}",
            "int f(int n){int r=0;for(int i=0; i<n; ++i){continue;}return r;}",
        ]
        for code in cases:
            with self.subTest(code=code):
                self.c.write_text(code)
                report = migrate_c(self.c, self.hepta)
                self.assertFalse(report["ok"], report)
                self.assertFalse(self.hepta.exists())


    def test_do_while_clang_defined_semantics_vs_native_hepta(self):
        self.c.write_text("""
int do_sum(int n) {
    int total=0; int i=0;
    do { total=total+i; i=i+1; } while(i<n);
    return total;
}
""")
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        generated = self.hepta.read_text()
        self.assertIn("while (i < n)", generated)
        self.assertEqual(generated.count("total = (total + i);"), 2)
        self.assertEqual(analyze(generated, str(self.hepta), native=False).report["status"],
                         "frontend_only")
        reference = self.directory / "do-ref.so"
        output = self.directory / "do-hepta.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC",
                        str(self.c), "-o", str(reference)], check=True, capture_output=True)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(output)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        old, new = ctypes.CDLL(str(reference)).do_sum, ctypes.CDLL(str(output)).do_sum
        for fn in (old, new):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-20, -1, 0, 1, 2, 3, 17, 100, 500):
            self.assertEqual(old(n), new(n), n)

    def test_do_while_unsupported_scopes_reject(self):
        cases = [
            "int f(int n){int i=0;do i=i+1;while(i<n);return i;}",
            "int f(int n){int i=0;do {int j=0;i=i+j;}while(i<n);return i;}",
            "int f(int n){int i=0;do {i=i+1;continue;}while(i<n);return i;}",
            "int f(int n){int i=0;do {i=i+1;break;}while(i<n);return i;}",
            "int f(int n){int i=0;do {return i;}while(i<n);}",
            "int f(int n){int i=0;do {do{i=i+1;}while(i<n);}while(i<n);return i;}",
        ]
        for code in cases:
            with self.subTest(code=code):
                self.c.write_text(code)
                self.hepta.unlink(missing_ok=True)
                report = migrate_c(self.c, self.hepta)
                self.assertFalse(report["ok"], report)
                self.assertFalse(self.hepta.exists())


    def test_scalar_ternary_return_and_assignment_native_differential(self):
        self.c.write_text("""
int choose(int x, int y) { return x > y ? x : y; }
int clamp(int x) { int y=0; y = x > 0 ? x : 0; return y; }
""")
        result = migrate_c(self.c, self.hepta)
        self.assertTrue(result["ok"], result)
        generated = self.hepta.read_text()
        self.assertIn("if (x > y)", generated)
        self.assertIn("return x;", generated)
        self.assertIn("y = 0;", generated)
        self.assertEqual(analyze(generated, str(self.hepta), native=False).report["status"],
                         "frontend_only")
        reference, migrated = self.directory / "ternary-original.so", self.directory / "ternary-hepta.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                        str(self.c), "-o", str(reference)], check=True, capture_output=True)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                "--backend", "c", "--crate-type", "cdylib", "-o", str(migrated)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        old, new = ctypes.CDLL(str(reference)), ctypes.CDLL(str(migrated))
        for name, args in (
                ("choose", [(1, 0), (-3, -8), (0, 0), (123, 222), (2**31 - 1, -1)]),
                ("clamp", [(-2**31,), (-10,), (-1,), (0,), (1,), (2**31 - 1,)])):
            left, right = getattr(old, name), getattr(new, name)
            for fn in (left, right):
                fn.argtypes = [ctypes.c_int32] * len(args[0])
                fn.restype = ctypes.c_int32
            for row in args:
                self.assertEqual(left(*row), right(*row), (name, row))

    def test_side_effecting_ternary_rejected_without_output(self):
        cases = [
            "int f(int x){return x>0 ? ++x : x;}",
            "int f(int x){int y=0; y=x>0 ? (y=1) : x; return y;}",
            "int f(int x){return x>0 ? x++ : 0;}",
            "int f(int x){return x ?: 0;}",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.hepta.unlink(missing_ok=True)
                self.c.write_text(source)
                report = migrate_c(self.c, self.hepta)
                self.assertFalse(report["ok"], report)
                self.assertFalse(self.hepta.exists())

    def test_unsupported_scalar_local_shapes_do_not_publish(self):
        cases = [
            "int f(int n) { int x; return n; }",
            "int f(int n) { int x=0; if (n>0) { int y=n; x=y; } return x; }",
            "int f(int n) { int x=0; x += 1; return x; }",
            "int f(int n) { int x=0; x++; return x; }",
            "int f(int n) { int x=n, y=n; return x; }",
            "int f(int n) { int x=0; x=n; int y=x; return y; }",
            "int f(int n) { static int x=0; x=x+n; return x; }",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.c.write_text(source)
                report = migrate_c(self.c, self.hepta)
                self.assertFalse(report["ok"], report)
                self.assertFalse(self.hepta.exists())
                self.assertTrue(report["rejected"])

    def test_unsupported_cast_rejected_without_writing(self):
        self.c.write_text("unsigned long long f(unsigned long long x) {return (unsigned int)x;}\n")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"])
        self.assertFalse(self.hepta.exists())

    def test_exotic_char_bit_model_rejected_before_ast_capture(self):
        original = strict_migrator._run

        def forged_non_octet_model(argv, **kwargs):
            raw = original(argv, **kwargs)
            if "-dM" in argv and "-E" in argv:
                self.assertIn("#define __CHAR_BIT__ 8", raw)
                return raw.replace("#define __CHAR_BIT__ 8", "#define __CHAR_BIT__ 16")
            return raw

        with patch.object(strict_migrator, "_run", side_effect=forged_non_octet_model):
            with self.assertRaisesRegex(strict_migrator.MigrationRejected, "E_C_DATA_MODEL"):
                strict_migrator._data_model("clang")

    def test_header_macro_preprocessing_is_source_bound(self):
        header = self.directory / "values.h"
        header.write_text("#define DELTA 3\n")
        self.c.write_text('#include "values.h"\nint shifted(int x) { return x + DELTA; }\n')
        report = migrate_c(self.c, self.hepta)
        self.assertTrue(report["ok"], report)
        self.assertRegex(report["preprocessed_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("shifted", self.hepta.read_text())

    def test_header_mutation_between_clang_capture_and_publication_rejected(self):
        header = self.directory / "values.h"
        header.write_text("#define DELTA 3\n")
        self.c.write_text('#include "values.h"\nint shifted(int x) { return x + DELTA; }\n')
        original_run = strict_migrator._run
        counts = {"preprocess": 0}

        def mutate_after_preprocessing(argv, **kwargs):
            output = original_run(argv, **kwargs)
            if "-E" in argv and "-P" in argv and "-std=c11" in argv:
                counts["preprocess"] += 1
                if counts["preprocess"] == 1:
                    header.write_text("#define DELTA 4\n")
            return output

        with patch.object(strict_migrator, "_run", side_effect=mutate_after_preprocessing):
            report = migrate_c(self.c, self.hepta)
        self.assertFalse(report["ok"], report)
        self.assertFalse(self.hepta.exists())
        self.assertEqual(counts["preprocess"], 2)
        self.assertIn("E_C_PREPROCESS_RACE", [x["code"] for x in report["rejected"]])

    def test_preexisting_output_is_not_overwritten(self):
        self.hepta.write_text("keep untouched", encoding="utf-8")
        result = migrate_c(self.c, self.hepta)
        self.assertFalse(result["ok"])
        self.assertEqual(self.hepta.read_text(), "keep untouched")
        self.assertIn("E_C_EXISTS", [x["code"] for x in result["rejected"]])

    def test_cli_exposes_machine_readable_evidence(self):
        process = subprocess.run([sys.executable, "-m", "hepta", "migrate-c",
                                  str(self.c), "-o", str(self.hepta)],
                                 capture_output=True, text=True, timeout=40)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"],
                         "frontend_checked_not_native_qualified")

    def test_differential_native_calls_on_defined_inputs(self):
        self.assertIsNotNone(shutil.which("gcc"), "GCC is mandatory for native ABI tests")
        migrated = migrate_c(self.c, self.hepta)
        self.assertTrue(migrated["ok"], migrated)
        original_so = self.directory / "liboriginal.so"
        translated_so = self.directory / "libtranslated.so"
        compile_c = subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared", str(self.c),
                                    "-o", str(original_so)], capture_output=True, text=True)
        self.assertEqual(compile_c.returncode, 0, compile_c.stderr)
        compile_h = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                                    "--backend", "c", "--crate-type", "cdylib",
                                    "-o", str(translated_so)], capture_output=True, text=True, timeout=60)
        self.assertEqual(compile_h.returncode, 0, compile_h.stdout + compile_h.stderr)
        c_lib = ctypes.CDLL(str(original_so))
        h_lib = ctypes.CDLL(str(translated_so))
        cases = {
            "add": (ctypes.c_int32, [ctypes.c_int32, ctypes.c_int32],
                    [(1, 2), (-32, 12), (0, 0), (200, 321)]),
            "xor_mask": (ctypes.c_uint64, [ctypes.c_uint64, ctypes.c_uint64],
                         [(0, 0), (15, 7), (2**64 - 1, 0xA5A5), (2**63, 2**63-1)]),
            "clamp_positive": (ctypes.c_int32, [ctypes.c_int32], [(-100,), (-1,), (0,), (10,)]),
            "add_wrap": (ctypes.c_uint64, [ctypes.c_uint64, ctypes.c_uint64],
                         [(0, 0), (2**64 - 1, 1), (2**63, 2**63)]),
        }
        for name, (restype, argtypes, rows) in cases.items():
            cfn, hfn = getattr(c_lib, name), getattr(h_lib, name)
            for fn in (cfn, hfn):
                fn.restype = restype
                fn.argtypes = argtypes
            for row in rows:
                self.assertEqual(cfn(*row), hfn(*row), (name, row))


if __name__ == "__main__":
    unittest.main()
