"""Cross-target i32 SSA/PHI object is not cross-target execution or ABI proof."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm
from hepta.llvm_ssa_target import compile_ssa_target_object, _qualified_header
from hepta.ssa import lower_cfg_scalar_ssa
from test_llvm_ssa_backend import LLVMSSATests


@unittest.skipUnless(shutil.which("clang"), "Clang backend required")
class LLVMSSATargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        helper = LLVMSSATests("test_true_loop_phi_and_checked_arithmetic_ir")
        self.graph = helper.fixture()
        self.ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(self.graph), self.graph)

    def test_validated_elf_and_coff_cross_objects(self):
        for target, machine in (("x86_64-unknown-linux-gnu", 62),
                                ("aarch64-unknown-linux-gnu", 183),
                                ("x86_64-pc-windows-msvc", 0x8664)):
            with self.subTest(target=target):
                output = self.root / (target + ".o")
                evidence = compile_ssa_target_object(self.ir, target=target, output=output)
                self.assertEqual(evidence["schema"], "hepta.llvm-ssa-object.v0")
                self.assertEqual(evidence["target"], target)
                self.assertEqual(evidence["machine"], machine)
                self.assertGreater(evidence["artifact_bytes"], 0)
                self.assertEqual(evidence["status"], "cross_object_only_not_executed")
                self.assertTrue(_qualified_header(output.read_bytes(), target))
                self.assertFalse(evidence["claims"]["target_program_executed"])
                self.assertFalse(evidence["claims"]["foreign_c_abi_qualified"])

    def test_wrong_target_unknown_or_overwrite_rejects(self):
        path = self.root / "object.o"
        with self.assertRaisesRegex(LLVMSSARejected, "TARGET"):
            compile_ssa_target_object(self.ir, target="thumbv7em-none-eabi", output=path)
        self.assertFalse(path.exists())
        path.write_bytes(b"untouched")
        with self.assertRaisesRegex(LLVMSSARejected, "OUTPUT"):
            compile_ssa_target_object(self.ir, target="x86_64-unknown-linux-gnu", output=path)
        self.assertEqual(path.read_bytes(), b"untouched")

    def test_dangling_output_symlink_cannot_redirect_publication(self):
        unintended_dir = self.root / "unintended"
        unintended_dir.mkdir()
        unintended = unintended_dir / "object.o"
        alias = self.root / "requested.o"
        alias.symlink_to(unintended)
        self.assertTrue(alias.is_symlink())
        self.assertFalse(unintended.exists())
        with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_OUTPUT"):
            compile_ssa_target_object(self.ir, target="x86_64-unknown-linux-gnu",
                                      output=alias)
        self.assertTrue(alias.is_symlink())
        self.assertFalse(unintended.exists())
        regular = self.root / "regular.o"
        evidence = compile_ssa_target_object(self.ir, target="x86_64-unknown-linux-gnu",
                                             output=regular)
        self.assertEqual(evidence["artifact_bytes"], regular.stat().st_size)
        self.assertTrue(_qualified_header(regular.read_bytes(), "x86_64-unknown-linux-gnu"))

    def test_modified_ir_fails_before_compilation(self):
        from dataclasses import replace
        forged = replace(self.ir, sha256="0"*64)
        with self.assertRaisesRegex(LLVMSSARejected, "IDENTITY"):
            compile_ssa_target_object(forged, target="aarch64-unknown-linux-gnu",
                                      output=self.root / "forged.o")
        self.assertFalse((self.root / "forged.o").exists())


if __name__ == "__main__":
    unittest.main()
