"""P3/P5: actual GCC/Clang C consumers linking direct Hepta SSA LLVM machine code.

This uses the independently checked scalar SSA fixture, not a whole-language
Hepta source or foreign object ABI proof. Deliberately incorrect compiled code
must be detected, not merely a Python-side negative fixture.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.llvm_ssa_backend import compile_scalar_ssa_llvm, emit_scalar_ssa_llvm
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_llvm_ssa_backend import LLVMSSATests
from tests.test_ssa_differential import execute_source


@unittest.skipUnless(
    sys.platform.startswith("linux") and shutil.which("clang") and shutil.which("gcc"),
    "Actual Linux host GCC + Clang C ABI toolchains required",
)
class ScalarSSAHostCABITests(unittest.TestCase):
    def test_native_bidirectional_compiler_abi_and_wrong_code_controls(self):
        # The source SSA/CFG is structurally checked by the actual emitter.
        helper = LLVMSSATests("test_true_loop_phi_and_checked_arithmetic_ir")
        cfg = helper.fixture()
        ssa = lower_cfg_scalar_ssa(cfg)
        native_ir = emit_scalar_ssa_llvm(ssa, cfg)
        self.assertEqual(native_ir.functions, ("f",))
        origin = json.loads(cfg.canonical_json)["functions"][0]
        inputs = (-10, -1, 0, 1, 2, 4, 5, 8, 12, 19, 40, 70)
        expected = [execute_source(origin, {"bound": x}) for x in inputs]
        self.assertTrue(any(x != -12345 for x in expected))

        with tempfile.TemporaryDirectory(prefix="hepta-ssa-host-abi-") as td:
            root = Path(td)
            correct = root / "libhepta_ssa.so"
            evidence = compile_scalar_ssa_llvm(native_ir, output=correct)
            self.assertEqual(evidence["status"], "native_host_compiled_unqualified")
            self.assertFalse(evidence["claims"]["cross_target_abi_qualified"])

            wrong_src = root / "wrong.c"
            wrong_src.write_text(
                "#include <stdint.h>\n"
                "int32_t f(int32_t bound) { (void)bound; return -12345; }\n"
            )
            wrong = root / "libhepta_wrong.so"
            wrong_build = subprocess.run(
                ["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                 str(wrong_src), "-o", str(wrong)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(wrong_build.returncode, 0, wrong_build.stderr)

            original_c = root / "native_consumer.c"
            original_c.write_text(
                "#include <stdint.h>\n"
                "extern int32_t f(int32_t);\n"
                "static const int32_t inputs[] = {"
                + ", ".join(str(x) for x in inputs) + "};\n"
                "static const int32_t expected[] = {"
                + ", ".join(str(x) for x in expected) + "};\n"
                "int main(void) {\n"
                "  for (unsigned i=0; i<sizeof(inputs)/sizeof(inputs[0]); ++i)\n"
                "    if (f(inputs[i]) != expected[i]) return 23;\n"
                "  return 0;\n"
                "}\n"
            )
            # Native callers compiled by both independent C compiler families,
            # at both -O0 and -O2, exercise actual link/run, not ctypes/libffi.
            for compiler in ("gcc", "clang"):
                for optimization in ("-O0", "-O2"):
                    for label, linked, exit_code in (
                        ("correct", correct, 0), ("wrong", wrong, 23)
                    ):
                        with self.subTest(compiler=compiler, optimization=optimization,
                                          implementation=label):
                            program = root / (compiler + optimization + label)
                            command = [
                                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                optimization, str(original_c), str(linked),
                                "-Wl,-rpath," + str(root), "-o", str(program),
                            ]
                            compiled = subprocess.run(command, capture_output=True,
                                                      text=True, timeout=45)
                            self.assertEqual(compiled.returncode, 0, compiled.stderr)
                            executed = subprocess.run([str(program)],
                                                      capture_output=True, text=True, timeout=8)
                            self.assertEqual(executed.returncode, exit_code, executed.stderr)


if __name__ == "__main__":
    unittest.main()
