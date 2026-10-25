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

    def test_for_scoped_init_repeated_name_native_abi(self):
        self.c.write_text("""
int twice(int n) {
    int sum = 0;
    for (int i = 0; i < n; ++i) { sum = sum + i; }
    for (int i = 0; i < n; i = i + 1) { sum = sum + i; }
    return sum;
}
""")
        result = migrate_c(self.c, self.hepta)
        self.assertTrue(result["ok"], result)
        generated = self.hepta.read_text()
        self.assertEqual(len(set(__import__("re").findall(r"let mut (hepta_for_\\d+_i)", generated))), 2)
        self.assertNotIn("let mut i:", generated)
        original = self.directory / "c_original.so"
        migrated = self.directory / "hepta_migrated.so"
        built = subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                                str(self.c), "-o", str(original)],
                               capture_output=True, text=True, timeout=50)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        out = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.hepta),
                              "--backend", "c", "--crate-type", "cdylib",
                              "-o", str(migrated)], capture_output=True, text=True, timeout=90)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        left = ctypes.CDLL(str(original)).twice
        right = ctypes.CDLL(str(migrated)).twice
        for fn in (left, right):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-30, -1, 0, 1, 2, 3, 17, 100, 1000):
            with self.subTest(n=n):
                self.assertEqual(left(n), right(n))

    def test_unsupported_for_syntax_rejected_without_output(self):
        sources = [
            "int f(int n){int x=0;for(int i=0,j=0;i<n;i++){x=x+i;}return x;}",
            "int f(int n){int x=0;for(int i;i<n;i++){x=x+i;}return x;}",
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
