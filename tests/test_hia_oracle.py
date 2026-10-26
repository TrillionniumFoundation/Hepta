"""HIA scalar SSA execution oracle tests against the actual canonical compiler.

Value oracle checks are separate from native qualification and are not formal
source/backend refinement or a general ownership proof.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.checker import check
from hepta.cfg import lower_hsir_cfg
from hepta.hia_core import seal_hia_scalar_core
from hepta.hia_oracle import (HIAOracleBudgetExceeded, HIAOracleRejected,
                               HIAOracleTrap, prepare_scalar_oracle)
from hepta.hsir import lower_checked_program
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source
from hepta.native_resource_gate import qualify_native_resource_source
from hepta.parser import parse
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa

_PROJECT = "d" * 64
_LOOP = '''module hia_oracle;
export "C" fn count(n: i32) -> i32 effects {panic} {
    let mut x: i32 = 0;
    while x < n { x = x + 1; }
    return x;
}
'''
_UNSIGNED = '''module hia_unsigned;
export "C" fn maximum(a: u32, b: u32) -> u32 effects {} {
    if a < b { return b; } else { return a; }
}
'''
_ADD = '''module hia_overflow;
export "C" fn add(a: i32, b: i32) -> i32 effects {panic} {
    return a + b;
}
'''
_ZERO = '''module hia_constant;
export "C" fn value() -> i32 effects {} { return 7; }
'''


def fixture(source):
    program = parse(source, "hia_oracle.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([x.to_dict() for x in checked.diagnostics])
    hsir = lower_checked_program(program, checked)
    cfg = lower_hsir_cfg(hsir)
    ssa = lower_cfg_scalar_ssa(cfg)
    verification = verify_scalar_ssa(ssa, cfg)
    gate = qualify_native_resource_source(
        program, checked,
        canonical_hsir_sha256=hsir.as_dict()["source_semantic_sha256"],
        project_sha256=_PROJECT)
    core = seal_hia_scalar_core(hsir, cfg, ssa, verification,
                                gate, project_sha256=_PROJECT)
    oracle = prepare_scalar_oracle(core, program, checked,
                                   project_sha256=_PROJECT)
    return program, checked, core, oracle


class HIAScalarOracleTests(unittest.TestCase):
    def test_checked_source_loop_phi_and_budget(self):
        _, _, core, oracle = fixture(_LOOP)
        self.assertEqual(oracle.core_sha256, core.sha256)
        for n in (-8, -1, 0, 1, 2, 3, 10, 100):
            with self.subTest(n=n):
                self.assertEqual(oracle.run("count", [n]), max(0, n))
        with self.assertRaises(HIAOracleBudgetExceeded):
            oracle.run("count", [100], max_steps=20)
        for bad in ([True], [-2147483649], [2147483648], [1, 2], []):
            with self.subTest(bad=bad):
                with self.assertRaises(HIAOracleRejected):
                    oracle.run("count", bad)

    def test_unsigned_branch_order(self):
        _, _, _, oracle = fixture(_UNSIGNED)
        for a, b in ((0, 4294967295), (4294967295, 0),
                     (1, 2), (2, 1), (100, 100)):
            with self.subTest(a=a, b=b):
                self.assertEqual(oracle.run("maximum", [a, b]), max(a, b))
        with self.assertRaises(HIAOracleRejected):
            oracle.run("maximum", [-1, 0])

    def test_overflow_is_a_trap_not_unbounded_execution(self):
        _, _, _, oracle = fixture(_ADD)
        for a, b in ((0, 0), (2, 5), (-10, 2), (-2147483648, 0)):
            self.assertEqual(oracle.run("add", [a, b]), a + b)
        for a, b in ((2147483647, 1), (-2147483648, -1)):
            with self.subTest(a=a, b=b):
                with self.assertRaises(HIAOracleTrap):
                    oracle.run("add", [a, b])

    def test_zero_argument_export(self):
        _, _, _, oracle = fixture(_ZERO)
        self.assertEqual(oracle.run("value", []), 7)

    def test_stale_core_cannot_prepare_oracle(self):
        program, checked, core, _ = fixture(_LOOP)
        changed, changed_checked, _, _ = fixture(
            _LOOP.replace("x + 1", "x + 2"))
        with self.assertRaisesRegex(ValueError, "E_HIA_CORE"):
            prepare_scalar_oracle(core, changed, changed_checked,
                                  project_sha256=_PROJECT)
        with self.assertRaisesRegex(ValueError, "E_HIA_CORE"):
            prepare_scalar_oracle(core, program, checked,
                                  project_sha256="e" * 64)

    @unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "native Clang and pinned Rust required")
    def test_real_native_llvm_matches_hia_value_oracle(self):
        # Real test builds from an actual file through full pinned-rustc,
        # Source/Core replay, SSA emitter, Clang and ELF validation.
        # No trap cases are sent through ctypes: native abort is process-fatal.
        with tempfile.TemporaryDirectory(prefix="hia-oracle-native-") as temp:
            src, obj = Path(temp) / "program.hepta", Path(temp) / "native.so"
            src.write_text(_LOOP, encoding="utf-8")
            _, _, _, oracle = fixture(_LOOP)
            built = build_llvm_ssa_source(src, obj, rustc=os.environ.get("RUSTC"))
            self.assertTrue(built["ok"], built)
            self.assertTrue(built["claims"]["hia_scalar_core_source_replayed"])
            count = ctypes.CDLL(str(obj)).count
            count.argtypes = [ctypes.c_int32]
            count.restype = ctypes.c_int32
            for n in (-8, -1, 0, 1, 2, 3, 10, 99, 100):
                self.assertEqual(count(n), oracle.run("count", [n]))


if __name__ == "__main__":
    unittest.main()
