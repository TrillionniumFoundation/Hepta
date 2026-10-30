"""Conformance/rejection checks for the first Clang-driven migration slice."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hepta.migration_ir import Expr, Function, IRValidationError, Stmt, check_function, emit_function
from tools.c2hepta import migrate


class HsirSafety(unittest.TestCase):
    def test_unbound_variable_rejected(self):
        fn = Function("f", (("x", "i32"),), "i32", (Stmt("return", Expr("var", "i32", "y")),))
        with self.assertRaises(IRValidationError):
            emit_function(fn)

    def test_mismatched_return_rejected(self):
        fn = Function("f", (), "i32", (Stmt("return", Expr("literal", "u32", "1")),))
        with self.assertRaises(IRValidationError):
            check_function(fn)

    def test_missing_else_rejected(self):
        fn = Function("f", (("x", "i32"),), "i32", (
            Stmt("if", Expr("compare", "bool", ">", (Expr("var", "i32", "x"), Expr("literal", "i32", "0"))),
                 (Stmt("return", Expr("literal", "i32", "1")),), ()),))
        with self.assertRaises(IRValidationError):
            check_function(fn)

    def test_unsigned_arithmetic_has_no_panic_effect(self):
        fn = Function("mix", (("a", "u32"),), "u32", (
            Stmt("return", Expr("arith", "u32", "+", (Expr("var", "u32", "a"), Expr("literal", "u32", "1")))),))
        self.assertEqual(check_function(fn), frozenset())
        self.assertIn("wrapping_add", emit_function(fn))


class C2HeptaImport(unittest.TestCase):
    def setUp(self):
        self.assertTrue(shutil.which("clang"), "Clang is required for this migration test")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c2hepta-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.src = self.path / "module.c"
        self.out = self.path / "module.hepta"
        self.report = self.path / "migration.json"

    def convert(self, text):
        self.src.write_text(text, encoding="utf-8")
        return migrate(self.src, self.out, self.report)

    def test_scalar_abi_and_unsigned_wrapping(self):
        result = self.convert("""int add(int a,int b){return a+b;}
            unsigned int mul(unsigned int a,unsigned int b){return a*b;}
            int choose(int a,int b){if(a>=b){return a;}else{return b;}}
        """)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(len(result["functions"]), 3)
        self.assertEqual(result["functions"][0]["effects"], ["panic"])
        self.assertEqual(result["functions"][1]["effects"], [])
        self.assertIn("wrapping_mul(a, b)", self.out.read_text())
        self.assertIn('export "C" fn choose', self.out.read_text())
        self.assertEqual(result["backend_validation"], "not_run")

    def test_rejects_pointer_and_global_without_partial_output(self):
        for code in ("int get(int *p){return *p;}",
                     "int global=1; int read(void){return global;}",
                     "int call(int x){return other(x);}",
                     "int a(int x){return x;} int b(int *p){return *p;}"):
            with self.subTest(code=code):
                self.out.unlink(missing_ok=True)
                result = self.convert(code)
                self.assertEqual(result["status"], "rejected")
                self.assertFalse(self.out.exists())
                self.assertTrue(self.report.exists())

    def test_rejects_macro_preprocessor_and_implicit_promotions(self):
        for code in ("#define VALUE 4\nint answer(void){return VALUE;}",
                     "int f(unsigned int x){return x;}",
                     "int f(int a){return a << 1;}",
                     "int f(int a){return a / 2;}",
                     "int f(int x){if(x)return 1;else return 0;}"):
            with self.subTest(code=code):
                self.assertEqual(self.convert(code)["status"], "rejected")

    def test_deterministic_ir_and_fail_closed_stale_output(self):
        a = self.convert("int increment(int x){return x + 1;}")
        self.assertEqual(a["status"], "converted")
        first = self.out.read_bytes()
        b = self.convert("int increment(int x){return x + 1;}")
        self.assertEqual(a["output_sha256"], b["output_sha256"])
        self.assertEqual(first, self.out.read_bytes())
        self.assertEqual(self.convert("int f(int *x){return *x;}")["status"], "rejected")
        self.assertEqual(first, self.out.read_bytes(), "failed conversion must not replace a previous artifact")

    def test_nonexistent_source_has_explicit_rejection_report(self):
        result = migrate(self.path / "missing.c", self.out, self.report)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("cannot read C input", result["reason"])
        self.assertIsNone(result["source_sha256"])
        self.assertTrue(self.report.exists())
        self.assertFalse(self.out.exists())

    def test_large_input_and_output_symlink_reject(self):
        self.assertEqual(self.convert(" " * 256001)["status"], "rejected")
        self.out.symlink_to(self.path / "missing.hepta")
        self.assertEqual(self.convert("int f(int x){return x;} ")["status"], "rejected")
        self.assertTrue(self.out.is_symlink())
        self.assertFalse((self.path / "missing.hepta").exists())

    def test_oversized_sparse_input_rejected_before_unbounded_read(self):
        # A regular 1 GiB sparse file must not be materialized in Python
        # memory merely to discover it exceeds the 256 KB source budget.
        with self.src.open("wb") as stream:
            stream.truncate(1 << 30)
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError(
                "unbounded Path.read_bytes must never run on this input")):
            result = migrate(self.src, self.out, self.report)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("input limit", result["reason"])
        self.assertFalse(self.out.exists())
        self.assertTrue(self.report.exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"),
                         "POSIX named pipes required")
    def test_fifo_input_is_rejected_without_blocking_for_writer(self):
        fifo = self.path / "untrusted.c"
        os.mkfifo(fifo)
        code = (
            "import json, sys\n"
            "from pathlib import Path\n"
            "from tools.c2hepta import migrate\n"
            "result = migrate(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))\n"
            "print(json.dumps(result))\n"
        )
        run = subprocess.run(
            [sys.executable, "-c", code, str(fifo), str(self.out), str(self.report)],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
            timeout=3, check=True)
        result = json.loads(run.stdout)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("regular file", result["reason"])
        self.assertFalse(self.out.exists())
        self.assertTrue(self.report.exists())

    def test_clang_must_compile_hash_bound_source_snapshot(self):
        # Model a path swap during Clang's AST invocation, followed by a
        # restore before the importer's final source-digest recheck.
        # Compiling the path would accept attacker's code while attributing
        # its output to the original source hash.
        original = "int safe(int x){return x;}\n"
        replacement = "int evil(int x){return x+1;}\n"
        self.src.write_text(original, encoding="utf-8")
        actual_run = subprocess.run

        def swap_during_ast(command, *args, **kwargs):
            if "-ast-dump=json" not in command:
                return actual_run(command, *args, **kwargs)
            self.src.write_text(replacement, encoding="utf-8")
            try:
                return actual_run(command, *args, **kwargs)
            finally:
                self.src.write_text(original, encoding="utf-8")

        with mock.patch("tools.c2hepta.subprocess.run", side_effect=swap_during_ast):
            result = migrate(self.src, self.out, self.report)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual([item["name"] for item in result["functions"]], ["safe"])
        self.assertIn("fn safe(", self.out.read_text())
        self.assertNotIn("fn evil(", self.out.read_text())
        self.assertEqual(result["source_sha256"], hashlib.sha256(original.encode()).hexdigest())

    def test_clang_ast_capture_stops_oversized_producer_early(self):
        # A bounded source does NOT bound the emitted Clang AST.  The real
        # producer must be stopped before it emits 16 MiB, not merely rejected
        # after subprocess.run has captured the entire output in memory.
        self.src.write_text("int safe(int x){return x;}\n", encoding="utf-8")
        marker = self.path / "clang-finished-oversized-output"
        fake_clang = self.path / "clang-spam"
        fake_clang.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys, time\n"
            "args = sys.argv[1:]\n"
            "if '--version' in args:\n"
            "    print('clang version 19.0.0')\n"
            "elif '-dumpmachine' in args:\n"
            "    print('x86_64-unknown-linux-gnu')\n"
            "elif '-dM' in args:\n"
            "    print('#define __SIZEOF_INT__ 4')\n"
            "    print('#define __CHAR_BIT__ 8')\n"
            "elif '-ast-dump=json' in args:\n"
            "    for _ in range(256):\n"
            "        sys.stdout.buffer.write(b'X' * 65536)\n"
            "        sys.stdout.buffer.flush()\n"
            "        time.sleep(0.005)\n"
            f"    pathlib.Path({str(marker)!r}).write_text('producer not stopped')\n"
            "else:\n"
            "    sys.exit(2)\n",
            encoding="utf-8",
        )
        fake_clang.chmod(0o700)
        result = migrate(self.src, self.out, self.report, clang=str(fake_clang))
        self.assertEqual(result["status"], "rejected", result)
        self.assertFalse(marker.exists(), "unbounded Clang output producer was allowed to finish")
        self.assertFalse(self.out.exists())
        self.assertTrue(self.report.exists())

    def test_native_gate_without_frontend_fails_closed(self):
        self.src.write_text("int f(int x){return x;}", encoding="utf-8")
        result = migrate(self.src, self.out, self.report, verify_native=True, rustc="/no/such/rustc")
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(self.out.exists())

    def test_differential_c_defined_scalar_domain(self):
        if not shutil.which("gcc"):
            self.fail("GCC required for C differential check")
        source = """int add(int a,int b){return a+b;}
        unsigned int mul(unsigned int a,unsigned int b){return a*b;}
        int choose(int a,int b){if(a>=b)return a;else return b;}
        """
        result = self.convert(source)
        self.assertEqual(result["status"], "converted", result)
        lib_path = self.path / "module.so"
        subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                        str(self.src), "-o", str(lib_path)], check=True, capture_output=True)
        lib = ctypes.CDLL(str(lib_path))
        lib.add.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.add.restype = ctypes.c_int
        lib.mul.argtypes = [ctypes.c_uint, ctypes.c_uint]
        lib.mul.restype = ctypes.c_uint
        lib.choose.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.choose.restype = ctypes.c_int
        for x in range(-100, 101, 7):
            for y in range(-100, 101, 13):
                self.assertEqual(lib.add(x, y), x+y)
                self.assertEqual(lib.choose(x, y), max(x, y))
        for x in (0, 1, 255, 2**31, 2**32-1):
            for y in (0, 1, 17, 2**32-1):
                self.assertEqual(lib.mul(x, y), (x*y) % 2**32)
        # This differential test compares C to HSIR's intended arithmetic,
        # not actual generated Hepta machine code (requires native gate).


if __name__ == "__main__":
    unittest.main()
