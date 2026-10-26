"""Boundary cases discovered by independent source/native differential audit."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project
from hepta.c_translation import CTranslator
from hepta.checker import check
from hepta.hia_program import execute_program
from hepta.hia_program_source import lower_c_multi_owner, lower_source
from hepta.parser import parse

CLANG = os.environ.get("CLANG") or shutil.which("clang")
GCC = shutil.which("gcc")
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


SHORT_CIRCUIT_LOOPS = '''
fn tick(x:mut u64)->bool effects{write,panic}{x=x+1;return x<5;}
export "C" fn conjunction(start:u64)->u64 effects{write,panic}{
    let mut n=start;while n<3 && tick(mut n){}return n;
}
export "C" fn disjunction(start:u64)->u64 effects{write,panic}{
    let mut n=start;while n<2 || tick(mut n){n=n+1;}return n;
}
export "C" fn nested(start:u64)->u64 effects{write,panic}{
    let mut n=start;while (n<3 && tick(mut n)) || (n<5 && tick(mut n)){}return n;
}
export "C" fn early(start:u64)->u64 effects{write,panic}{
    let mut n=start;while n<3 && tick(mut n){if n==2{return n+100;}}return n;
}
'''


def loop_expected(name, start):
    n = start
    def tick():
        nonlocal n
        n += 1
        return n < 5
    if name == "conjunction":
        while n < 3 and tick():
            pass
    elif name == "disjunction":
        while n < 2 or tick():
            n += 1
    elif name == "nested":
        while (n < 3 and tick()) or (n < 5 and tick()):
            pass
    else:
        while n < 3 and tick():
            if n == 2:
                return n + 100
    return n


def database(directory, source):
    path = directory / "input.c"
    path.write_text(source)
    db = directory / "compile_commands.json"
    db.write_text(json.dumps([{"directory": str(directory), "file": "input.c",
        "arguments": [CLANG, "-std=c11", "-c", "input.c", "-o", "input.o"]}]))
    return db


class HIAShortCircuitLoopTests(unittest.TestCase):
    def test_short_circuit_conditions_preserve_the_loop_header_interface(self):
        self.assertTrue(check(parse(SHORT_CIRCUIT_LOOPS)).ok)
        core = lower_source(SHORT_CIRCUIT_LOOPS)
        for name in ("conjunction", "disjunction", "nested", "early"):
            for start in (0, 1, 2, 3, 4, 8):
                with self.subTest(function=name, start=start):
                    self.assertEqual(execute_program(core, name, [start])["result"], loop_expected(name, start))

    @unittest.skipUnless(CLANG and RUSTC, "native LLVM and pinned Rust reference required")
    def test_short_circuit_loop_results_match_actual_rust_and_hia_native(self):
        from hepta.backend import compile_rust, emit_rust
        from hepta.hia_program_llvm import build_program_native
        source = parse(SHORT_CIRCUIT_LOOPS)
        checked = check(source)
        core = lower_source(SHORT_CIRCUIT_LOOPS)
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            rust_library, hia_library = directory / "rust.so", directory / "hia.so"
            receipt = compile_rust(emit_rust(source, checked, crate_type="cdylib"),
                                   rustc=RUSTC, crate_type="cdylib", output=rust_library)
            self.assertTrue(receipt["ok"], receipt.get("diagnostics"))
            build_program_native(core, hia_library, clang=CLANG)
            for path in (rust_library, hia_library):
                library = ctypes.CDLL(str(path))
                for name in ("conjunction", "disjunction", "nested", "early"):
                    function = getattr(library, name)
                    function.argtypes, function.restype = [ctypes.c_uint64], ctypes.c_uint64
                    for start in (0, 1, 2, 3, 4, 8):
                        with self.subTest(library=path.name, function=name, start=start):
                            self.assertEqual(function(start), loop_expected(name, start))


@unittest.skipUnless(CLANG and GCC, "Clang capture and GCC native reference required")
class CIntegerPromotionMigrationTests(unittest.TestCase):
    def test_small_signed_increments_reject_in_both_project_frontends(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            for typ in ("signed char", "short"):
                for operator in ("++", "--"):
                    with self.subTest(type=typ, operator=operator):
                        source = f"int step({typ} input){{{typ} x=input;x{operator};return x;}}\n"
                        db = database(directory, source)
                        capture = capture_project(db, clang=CLANG)
                        with self.assertRaises(MigrationRejected) as old:
                            CTranslator(capture).emit()
                        self.assertEqual(old.exception.code, "E_C_SIGNED_CONVERSION")
                        with self.assertRaises(MigrationRejected) as new:
                            lower_c_multi_owner(db, clang=CLANG)
                        self.assertEqual(new.exception.code, "E_C_SIGNED_CONVERSION")

    def test_c_boundary_observations_and_defined_unsigned_wrapping_remain_distinct(self):
        original = '''
int signed_up(signed char input){signed char x=input;x++;return x;}
int signed_down(signed char input){signed char x=input;x--;return x;}
int short_up(short input){short x=input;x++;return x;}
int short_down(short input){short x=input;x--;return x;}
unsigned int unsigned_up(unsigned char input){unsigned char x=input;x++;return x;}
unsigned int unsigned_down(unsigned char input){unsigned char x=input;x--;return x;}
unsigned int unsigned_literal(void){unsigned char x=255;x++;return x;}
'''
        # The signed results record these real compilers' target behavior;
        # the migrator rejects them instead of declaring that behavior portable.
        cases = [("signed_up", ctypes.c_int8, 127, -128),
                 ("signed_down", ctypes.c_int8, -128, 127),
                 ("short_up", ctypes.c_int16, 32767, -32768),
                 ("short_down", ctypes.c_int16, -32768, 32767),
                 ("unsigned_up", ctypes.c_uint8, 255, 0),
                 ("unsigned_down", ctypes.c_uint8, 0, 255)]
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            source = directory / "original.c"; source.write_text(original)
            for index, compiler in enumerate((CLANG, GCC)):
                output = directory / f"original-{index}.so"
                subprocess.run([compiler, "-std=c11", "-O2", "-fPIC", "-shared", str(source),
                                "-o", str(output)], check=True, capture_output=True, text=True)
                library = ctypes.CDLL(str(output))
                for name, argument_type, argument, expected in cases:
                    function = getattr(library, name)
                    function.argtypes, function.restype = [argument_type], ctypes.c_int32
                    with self.subTest(compiler=compiler, function=name):
                        self.assertEqual(function(argument), expected)
                library.unsigned_literal.argtypes = []
                library.unsigned_literal.restype = ctypes.c_uint32
                self.assertEqual(library.unsigned_literal(), 0)
            unsigned = "\n".join(line for line in original.splitlines() if line.startswith("unsigned"))
            db = database(directory, unsigned)
            old_source, _, _ = CTranslator(capture_project(db, clang=CLANG)).emit()
            cores = [lower_source(old_source), lower_c_multi_owner(db, clang=CLANG)["program"]]
            for core in cores:
                self.assertEqual(execute_program(core, "c_unsigned_up", [255])["result"], 0)
                self.assertEqual(execute_program(core, "c_unsigned_down", [0])["result"], 255)
                self.assertEqual(execute_program(core, "c_unsigned_literal", [])["result"], 0)


if __name__ == "__main__":
    unittest.main()
