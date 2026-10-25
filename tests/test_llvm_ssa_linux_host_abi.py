"""Native Linux x86_64 Clang-object/GCC-caller ABI with wrong-code control.

The input is explicit bounded LLVM IR, not general Hepta source. A successful
runtime call does not qualify Windows/macOS/ARM64, C++ ABIs or compiler soundness.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.llvm_ssa_backend import SSA_LLVM_IR
from hepta.llvm_ssa_target import (
    _defined_exports, _qualified_header, compile_ssa_target_object,
)

_GOOD = """define i32 @hepta_scalar(i32 %x) {
entry:
  %triple = mul i32 %x, 3
  %answer = add i32 %triple, 1
  ret i32 %answer
}
"""
_BAD = _GOOD.replace("%triple, 1", "%triple, 2")
_CALLER = """#include <stdint.h>
extern int32_t hepta_scalar(int32_t);
int main(void) {
    for (int32_t x = -1000; x <= 1000; ++x) {
        if (hepta_scalar(x) != 3*x + 1) return 17;
    }
    return 0;
}
"""


def _run(argv, timeout=30):
    return run_bounded(argv, timeout=timeout, stdout_limit=65536,
                       stderr_limit=262144, stdin_limit=0)


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
    and shutil.which("clang") and shutil.which("gcc"),
    "Requires real Linux x86_64 with Clang and GCC",
)
class LLVMHostABI(unittest.TestCase):
    def test_real_target_backend_object_linked_into_gcc_c_caller(self):
        with tempfile.TemporaryDirectory(prefix="hepta-llvm-gcc-") as tmp:
            root = Path(tmp)
            driver = root / "driver.c"
            driver.write_text(_CALLER, encoding="utf-8")
            output = root / "hepta.o"
            ir = SSA_LLVM_IR(
                _GOOD, sha256(_GOOD.encode()).hexdigest(),
                ("hepta_scalar",), "a" * 64, "b" * 64,
            )
            ir.check_identity()
            receipt = compile_ssa_target_object(
                ir, target="x86_64-unknown-linux-gnu", output=output,
            )
            self.assertEqual(receipt["status"], "cross_object_only_not_executed")
            self.assertEqual(receipt["verified_defined_exports"], ["hepta_scalar"])
            self.assertFalse(receipt["claims"]["foreign_c_abi_qualified"])
            self.assertTrue(_qualified_header(output.read_bytes(),
                                               "x86_64-unknown-linux-gnu"))
            self.assertIn("hepta_scalar", _defined_exports(
                output.read_bytes(), "x86_64-unknown-linux-gnu"))
            # Separate GCC driver compilation and actual on-host execution.
            for gcc_opt in ("O0", "O2"):
                with self.subTest(gcc_opt=gcc_opt):
                    program = root / ("runner-" + gcc_opt)
                    linker = _run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                   "-" + gcc_opt, str(driver), str(output),
                                   "-o", str(program)])
                    self.assertEqual(linker.returncode, 0, linker.stderr)
                    executed = _run([str(program)])
                    self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_independent_two_by_two_compilers_and_wrong_code_control(self):
        with tempfile.TemporaryDirectory(prefix="hepta-llvm-native-matrix-") as tmp:
            root = Path(tmp)
            driver = root / "driver.c"
            driver.write_text(_CALLER, encoding="utf-8")
            correct, rejected = 0, 0
            for implementation, source in (("correct", _GOOD), ("wrong", _BAD)):
                ll = root / (implementation + ".ll")
                ll.write_text(source, encoding="utf-8")
                for clang_opt in ("O0", "O2"):
                    object_path = root / (implementation + "-" + clang_opt + ".o")
                    compiled = _run(
                        ["clang", "--target=x86_64-unknown-linux-gnu", "-x", "ir",
                         "-" + clang_opt, "-c", str(ll), "-o", str(object_path)])
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    self.assertIn("hepta_scalar", _defined_exports(
                        object_path.read_bytes(), "x86_64-unknown-linux-gnu"))
                    for gcc_opt in ("O0", "O2"):
                        with self.subTest(implementation=implementation,
                                          clang_opt=clang_opt, gcc_opt=gcc_opt):
                            exe = root / (implementation + "-" + clang_opt + "-" + gcc_opt)
                            linked = _run(
                                ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                 "-" + gcc_opt, str(driver), str(object_path),
                                 "-o", str(exe)])
                            self.assertEqual(linked.returncode, 0, linked.stderr)
                            executed = _run([str(exe)])
                            expected_exit = 0 if implementation == "correct" else 17
                            self.assertEqual(executed.returncode, expected_exit)
                            if expected_exit == 0:
                                correct += 1
                            else:
                                rejected += 1
            self.assertEqual((correct, rejected), (4, 4))


if __name__ == "__main__":
    unittest.main()
