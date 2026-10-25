"""Strict SSA/PHI-to-LLVM host execution, differential and fault controls."""
from __future__ import annotations

import ctypes
import json
import random
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.cfg import CFGSnapshot
from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm, compile_scalar_ssa_llvm
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_ssa_differential import nested_loop_fixture, execute_source
from tests.test_ssa_scalar import snapshot, block, i, n, expr


def exported(cfg, effects=("panic",)):
    data = json.loads(cfg.canonical_json)
    for fn in data["functions"]:
        fn.update(abi="C", direction="export", declared_effects=list(effects))
    data["external_assumptions"] = []
    src = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return CFGSnapshot("hepta.cfg.v0", src, sha256(src.encode()).hexdigest())


class LLVMSSATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def fixture(self):
        return exported(nested_loop_fixture())

    def test_true_loop_phi_and_checked_arithmetic_ir(self):
        cfg = self.fixture()
        ssa = lower_cfg_scalar_ssa(cfg)
        ir = emit_scalar_ssa_llvm(ssa, cfg)
        self.assertEqual(ir.profile, "hepta.llvm-ssa-i32.v0")
        self.assertEqual(ir.sha256, emit_scalar_ssa_llvm(ssa, cfg).sha256)
        self.assertEqual(ir.source_ssa_sha256, ssa.sha256)
        self.assertGreaterEqual(ir.text.count(" phi i32 "), 2)
        self.assertIn("@llvm.sadd.with.overflow.i32", ir.text)
        self.assertIn("call void @abort()", ir.text)
        self.assertIn("br i1 ", ir.text)
        self.assertIn("define i32 @f(", ir.text)
        self.assertNotIn("alloca ", ir.text)

    @unittest.skipUnless(shutil.which("clang"), "clang required for host native qualification")
    def test_native_vs_source_cfg_differential(self):
        cfg = self.fixture()
        ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg)
        report = compile_scalar_ssa_llvm(ir, output=self.root / "candidate.so")
        self.assertEqual(report["status"], "native_host_compiled_unqualified")
        self.assertFalse(report["claims"]["backend_refinement_proven"])
        fn = ctypes.CDLL(report["output"]).f
        fn.argtypes = [ctypes.c_int32]
        fn.restype = ctypes.c_int32
        original = json.loads(cfg.canonical_json)["functions"][0]
        rng = random.Random(20261024)
        inputs = list(range(-5, 40)) + [rng.randrange(-10, 60) for _ in range(64)]
        for value in inputs:
            with self.subTest(bound=value):
                self.assertEqual(fn(value), execute_source(original, {"bound": value}))
        with self.assertRaisesRegex(LLVMSSARejected, "OUTPUT"):
            compile_scalar_ssa_llvm(ir, output=report["output"])

    @unittest.skipUnless(shutil.which("clang"), "clang required for host output-path qualification")
    def test_dangling_output_symlink_cannot_redirect_native_library(self):
        cfg = self.fixture()
        ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg)
        unintended_dir = self.root / "unintended"
        unintended_dir.mkdir()
        unintended = unintended_dir / "misrouted.so"
        alias = self.root / "requested.so"
        alias.symlink_to(unintended)
        self.assertTrue(alias.is_symlink())
        self.assertFalse(unintended.exists())
        with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_OUTPUT"):
            compile_scalar_ssa_llvm(ir, output=alias)
        self.assertTrue(alias.is_symlink())
        self.assertFalse(unintended.exists())

        normal = self.root / "normal.so"
        report = compile_scalar_ssa_llvm(ir, output=normal)
        self.assertEqual(report["artifact_bytes"], normal.stat().st_size)
        self.assertEqual(report["artifact_sha256"], sha256(normal.read_bytes()).hexdigest())
        with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_OUTPUT"):
            compile_scalar_ssa_llvm(ir, output=normal)

    @unittest.skipUnless(shutil.which("clang"), "clang required for overflow negative control")
    def test_native_overflow_abort_negative(self):
        cfg = exported(snapshot([
            block(0, kind="return", value=expr("binary", "+", "i32", n("a"), n("b")))
        ], params=[("a", "i32"), ("b", "i32")]))
        artifact = self.root / "checked.so"
        compile_scalar_ssa_llvm(emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg),
                                output=artifact)
        code = ("import ctypes,sys\n"
                "lib=ctypes.CDLL(sys.argv[1]);f=lib.f\n"
                "f.argtypes=[ctypes.c_int32,ctypes.c_int32];f.restype=ctypes.c_int32\n"
                "sys.exit(0 if f(int(sys.argv[2]),int(sys.argv[3])) == int(sys.argv[4]) else 7)\n")
        good = subprocess.run([sys.executable, "-c", code, str(artifact),
                               "1", "2", "3"], timeout=8)
        bad = subprocess.run([sys.executable, "-c", code, str(artifact),
                              str(2**31-1), "1", "0"], timeout=8)
        self.assertEqual(good.returncode, 0)
        self.assertNotEqual(bad.returncode, 0)
        self.assertNotEqual(bad.returncode, 7)

    def test_rehashed_llvm_escape_cannot_reach_native_compilers(self):
        from dataclasses import replace
        ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(self.fixture()), self.fixture())
        # A digest is an integrity label, not a license to compile arbitrary
        # LLVM memory operations or unexpected imports.
        variants = [
            ir.text.replace("define i32 @", "declare i32 @puts(ptr)\ndefine i32 @", 1),
            ir.text.replace("define i32 @", "@malicious = global i32 1\ndefine i32 @", 1),
            ir.text.replace("  ret i32 ", "  store i32 2, ptr null\n  ret i32 ", 1),
            ir.text.replace("  ret i32 ", "  %t999 = call i32 @puts(ptr null)\n  ret i32 ", 1),
            ir.text.replace("  ret i32 ", "  call void asm sideeffect \"\", \"\"()\n  ret i32 ", 1),
        ]
        for text in variants:
            with self.subTest(change=text[:75]):
                forged = replace(ir, text=text, sha256=sha256(text.encode()).hexdigest())
                with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
                    forged.check_identity()

    def test_abi_and_effect_rejected(self):
        cfg = nested_loop_fixture()
        with self.assertRaisesRegex(LLVMSSARejected, "ABI"):
            emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg)
        cfg = exported(nested_loop_fixture(), effects=())
        with self.assertRaisesRegex(LLVMSSARejected, "EFFECT"):
            emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg)

    def test_foreign_assumptions_and_forged_ssa_rejected(self):
        cfg = self.fixture()
        obj = json.loads(cfg.canonical_json)
        obj["external_assumptions"] = [{"unverified": "foreign"}]
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        bad = CFGSnapshot("hepta.cfg.v0", canonical, sha256(canonical.encode()).hexdigest())
        with self.assertRaisesRegex(LLVMSSARejected, "FFI"):
            emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(bad), bad)
        ssa = lower_cfg_scalar_ssa(cfg)
        tampered = type(ssa)(ssa.schema, ssa.canonical_json, "0" * 64)
        with self.assertRaises(ValueError):
            emit_scalar_ssa_llvm(tampered, cfg)


if __name__ == "__main__":
    unittest.main()
