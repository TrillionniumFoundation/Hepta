"""Pinned-rustc Hepta source -> verified scalar LLVM object -> GCC-native ABI.

A source-level i32 scalar subset is linked and executed on Linux x86_64.
This is not full C ABI, cross-platform execution or semantic refinement proof.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.pipeline import analyze
from hepta.hsir import lower_checked_program
from hepta.cfg import lower_hsir_cfg
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa
from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm
from hepta.llvm_ssa_target import compile_ssa_target_object

_SOURCE = """module abi_native;
export "C" fn hepta_accumulate(n: i32) -> i32 effects {panic} {
    let mut total: i32 = 0;
    let mut i: i32 = 0;
    while i < n {
        if i < 4 { total = total + i; }
        else { total = total + 1; }
        i = i + 1;
    }
    return total;
}
"""

_DRIVER = """#include <stdint.h>
extern int32_t hepta_accumulate(int32_t n);
int main(void) {
    for (int32_t n = -16; n <= 400; ++n) {
        int32_t expected = 0;
        for (int32_t i = 0; i < n; ++i) {
            expected += (i < 4) ? i : 1;
        }
        if (hepta_accumulate(n) != expected) return 17;
    }
    return 0;
}
"""

_BAD = """#include <stdint.h>
int32_t hepta_accumulate(int32_t n) {
    return n + 1;
}
"""


def _run(argv: list[str], *, timeout: int = 30):
    return run_bounded(argv, timeout=timeout, input_text=None,
                       stdout_limit=64 * 1024, stderr_limit=256 * 1024,
                       stdin_limit=0)


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
    and shutil.which("clang") and shutil.which("gcc"),
    "Requires real Linux x86_64 Clang/GCC native compilers",
)
class HeptaSourceToCABI(unittest.TestCase):
    def test_native_checked_source_to_gcc_linked_c_caller(self):
        # No frontend-only or unpinned reference substitute is accepted.
        checked = analyze(_SOURCE, "hepta_abi_linux.hepta", native=True,
                          rustc=os.environ.get("RUSTC"), crate_type="rlib")
        self.assertTrue(checked.report["ok"], checked.report)
        self.assertEqual(checked.report["checks"]["rust_borrows_types"], "rustc_checked")

        hsir = lower_checked_program(checked.program, checked.checked)
        cfg = lower_hsir_cfg(hsir)
        ssa = lower_cfg_scalar_ssa(cfg)
        verification = verify_scalar_ssa(ssa, cfg)
        self.assertTrue(verification.as_dict()["claims"]["single_assignment_checked"])
        ir = emit_scalar_ssa_llvm(ssa, cfg)
        self.assertEqual(ir.verification_sha256, verification.sha256)
        self.assertEqual(ir.functions, ("hepta_accumulate",))

        with tempfile.TemporaryDirectory(prefix="hepta-full-llvm-gcc-") as tmp:
            root = Path(tmp)
            obj = root / "hepta.o"
            native = compile_ssa_target_object(
                ir, target="x86_64-unknown-linux-gnu", output=obj)
            self.assertEqual(native["verified_defined_exports"], ["hepta_accumulate"])
            self.assertGreater(native["artifact_bytes"], 0)
            self.assertFalse(native["claims"]["foreign_c_abi_qualified"])

            caller = root / "driver.c"
            caller.write_text(_DRIVER, encoding="utf-8")
            wrong = root / "wrong.c"
            wrong.write_text(_BAD, encoding="utf-8")
            for gcc_opt in ("O0", "O2"):
                with self.subTest(gcc_opt=gcc_opt):
                    linked = root / ("linked-" + gcc_opt)
                    good_build = _run(
                        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                         "-" + gcc_opt, str(caller), str(obj), "-o", str(linked)])
                    self.assertEqual(good_build.returncode, 0, good_build.stderr)
                    actual = _run([str(linked)])
                    self.assertEqual(actual.returncode, 0, actual.stderr)

                    # An independently compiled deliberately wrong function
                    # must be rejected by the same executable source oracle.
                    mutated = root / ("mutated-" + gcc_opt)
                    bad_build = _run(
                        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                         "-" + gcc_opt, str(caller), str(wrong),
                         "-o", str(mutated)])
                    self.assertEqual(bad_build.returncode, 0, bad_build.stderr)
                    failed = _run([str(mutated)])
                    self.assertEqual(failed.returncode, 17)


if __name__ == "__main__":
    unittest.main()
