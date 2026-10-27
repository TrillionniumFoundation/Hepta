"""Execute the same checked scalar source through pinned Rust and native LLVM.

These finite differential cases qualify observed behavior, not universal
equivalence, memory-model soundness or execution on cross-object targets.
"""
from __future__ import annotations

import ctypes
import itertools
import operator
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.backend import compile_rust
from hepta.cfg import lower_hsir_cfg
from hepta.hsir import lower_checked_program
from hepta.llvm_ssa_backend import compile_scalar_ssa_llvm, emit_scalar_ssa_llvm
from hepta.pipeline import analyze
from hepta.ssa import lower_cfg_scalar_ssa


ARITHMETIC = {"+": ("add", operator.add), "-": ("sub", operator.sub),
              "*": ("mul", operator.mul)}
COMPARISONS = {"==": ("eq", operator.eq), "!=": ("ne", operator.ne),
               "<": ("lt", operator.lt), "<=": ("le", operator.le),
               ">": ("gt", operator.gt), ">=": ("ge", operator.ge)}


def source():
    parts = ["module llvm_rust_differential;"]
    for word in ("i32", "u32"):
        for op, (name, _) in ARITHMETIC.items():
            parts.append(f"""export "C" fn {word}_{name}(a: {word}, b: {word}) -> {word} effects {{panic}} {{
    return a {op} b;
}}""")
        for op, (name, _) in COMPARISONS.items():
            parts.append(f"""export "C" fn {word}_{name}(a: {word}, b: {word}) -> {word} effects {{}} {{
    if a {op} b {{ return 1; }} else {{ return 0; }}
}}""")
    parts.append("""export "C" fn i32_neg(a: i32) -> i32 effects {panic} {
    return -a;
}
export "C" fn u32_loop(n: u32) -> u32 effects {panic} {
    let mut i: u32 = 0;
    let mut total: u32 = 0;
    while i < n {
        if i < 5 { total = total + i; }
        else { total = total + 2; }
        i = i + 1;
    }
    return total;
}""")
    return "\n".join(parts) + "\n"


@unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                     "Real Clang and pinned Rust are required")
class LLVMRustNativeDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hepta-llvm-rust-differential-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        checked = analyze(source(), "llvm_rust_differential.hepta", native=True,
                          rustc=os.environ.get("RUSTC"), crate_type="cdylib")
        if not checked.report["ok"]:
            raise AssertionError(checked.report)
        if checked.report["checks"]["rust_borrows_types"] != "rustc_checked":
            raise AssertionError("Native Rust reference validation was not performed")
        cls.rust_output = cls.root / "rust_reference.so"
        reference = compile_rust(checked.rust, rustc=os.environ.get("RUSTC"),
                                 crate_type="cdylib", output=cls.rust_output)
        if reference["ok"] is not True:
            raise AssertionError(reference)
        cfg = lower_hsir_cfg(lower_checked_program(checked.program, checked.checked))
        ssa = lower_cfg_scalar_ssa(cfg)
        ir = emit_scalar_ssa_llvm(ssa, cfg)
        cls.llvm_output = cls.root / "llvm_candidate.so"
        cls.receipt = compile_scalar_ssa_llvm(ir, output=cls.llvm_output, ssa=ssa, cfg=cfg)
        cls.libraries = [ctypes.CDLL(str(path)) for path in (cls.rust_output, cls.llvm_output)]

    def function(self, library, word, name, arity=2):
        ctype = ctypes.c_int32 if word == "i32" else ctypes.c_uint32
        fn = getattr(library, f"{word}_{name}")
        fn.argtypes, fn.restype = [ctype] * arity, ctype
        return fn

    def test_signed_unsigned_arithmetic_comparisons_and_phi_execution(self):
        rng = random.Random(20261025)
        cases = 0
        for word, edges in (
            ("i32", [-2**31, -2**31 + 1, -65536, -1, 0, 1, 65536, 2**31 - 2, 2**31 - 1]),
            ("u32", [0, 1, 2, 65535, 65536, 2**31 - 1, 2**31, 2**32 - 2, 2**32 - 1]),
        ):
            pairs = list(itertools.product(edges, repeat=2))
            pairs += [(rng.randrange(-10000, 10000), rng.randrange(-10000, 10000))
                      if word == "i32" else (rng.randrange(10000), rng.randrange(10000))
                      for _ in range(64)]
            low, high = (-2**31, 2**31 - 1) if word == "i32" else (0, 2**32 - 1)
            for _, (name, operation) in {**ARITHMETIC, **COMPARISONS}.items():
                functions = [self.function(lib, word, name) for lib in self.libraries]
                for a, b in pairs:
                    expected = int(operation(a, b))
                    if not low <= expected <= high:
                        continue  # Overflow is tested in isolated child processes below.
                    with self.subTest(word=word, operation=name, a=a, b=b):
                        actual = [fn(a, b) for fn in functions]
                        self.assertEqual(actual, [expected, expected])
                    cases += 1
        negations = [self.function(lib, "i32", "neg", 1) for lib in self.libraries]
        for value in (-2**31 + 1, -1, 0, 1, 2**31 - 1):
            self.assertEqual([fn(value) for fn in negations], [-value, -value])
            cases += 1
        loops = [self.function(lib, "u32", "loop", 1) for lib in self.libraries]
        for n in (0, 1, 4, 5, 6, 10, 31, 100):
            expected = sum(i if i < 5 else 2 for i in range(n))
            self.assertEqual([fn(n) for fn in loops], [expected, expected])
            cases += 1
        self.assertGreater(cases, 2000)
        self.assertTrue(self.receipt["claims"]["ssa_cfg_origin_rechecked"])
        self.assertFalse(self.receipt["claims"]["backend_refinement_proven"])

    def test_every_checked_arithmetic_operation_aborts_on_overflow(self):
        child = """import ctypes, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
lib = ctypes.CDLL(sys.argv[1])
fn = getattr(lib, sys.argv[2])
ty = ctypes.c_uint32 if sys.argv[2].startswith("u32_") else ctypes.c_int32
values = [int(x) for x in sys.argv[3:]]
fn.argtypes, fn.restype = [ty] * len(values), ty
fn(*values)
sys.exit(19)
"""
        failures = (
            ("i32_add", 2**31 - 1, 1),
            ("i32_sub", -2**31, 1),
            ("i32_mul", 2**30, 2),
            ("u32_add", 2**32 - 1, 1),
            ("u32_sub", 0, 1),
            ("u32_mul", 2**31, 2),
            ("i32_neg", -2**31),
        )
        for artifact in (self.rust_output, self.llvm_output):
            for name, *values in failures:
                with self.subTest(backend=artifact.name, operation=name):
                    result = subprocess.run([sys.executable, "-c", child, str(artifact),
                                             name, *map(str, values)],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, -signal.SIGABRT, result.stderr)


if __name__ == "__main__":
    unittest.main()
