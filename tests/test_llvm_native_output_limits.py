"""Native SSA host/cross target output must be size-bounded before publication.

This integration gate imports the real Hepta LLVM emitter and backends. It is
not part of the standalone helper-only local qualification.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta import llvm_ssa_backend as host
from hepta import llvm_ssa_target as cross
from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_llvm_ssa_backend import LLVMSSATests


class NativeOutputLimits(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = LLVMSSATests("test_true_loop_phi_and_checked_arithmetic_ir")
        self.cfg = fixture.fixture()
        self.ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(self.cfg), self.cfg)
        self.fake_compiler = self.root / "fake-clang"
        self.fake_compiler.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.fake_compiler.chmod(0o755)

    def fake_tool(self, kind):
        def command(argv, *, timeout):
            if "--version" in argv:
                return SimpleNamespace(returncode=0, stdout="clang fake 1\n", stderr="")
            dst = Path(argv[argv.index("-o") + 1])
            if kind == "large":
                with dst.open("wb") as stream:
                    stream.truncate(64 * 1024 * 1024 + 1)
            elif kind == "symlink":
                other = self.root / "external-binary"
                other.write_bytes(b"not a compiler output")
                dst.symlink_to(other)
            elif kind == "empty":
                dst.touch()
            else:
                raise AssertionError(kind)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return command

    def test_host_rejects_oversized_symlink_and_empty_native_artifacts(self):
        for kind in ("large", "symlink", "empty"):
            with self.subTest(kind=kind):
                output = self.root / (kind + ".so")
                with (patch.object(host.shutil, "which", return_value=str(self.fake_compiler)),
                      patch.object(host, "_clang_run", side_effect=self.fake_tool(kind))):
                    with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_NATIVE_ARTIFACT"):
                        host.compile_scalar_ssa_llvm(self.ir, output=output)
                self.assertFalse(output.exists())
                self.assertFalse(output.is_symlink())

    def test_cross_target_rejects_before_object_decoder_or_publication(self):
        for kind in ("large", "symlink", "empty"):
            with self.subTest(kind=kind):
                output = self.root / (kind + ".o")
                with (patch.object(cross.shutil, "which", return_value=str(self.fake_compiler)),
                      patch.object(cross, "_clang_run", side_effect=self.fake_tool(kind))):
                    with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_TARGET_OUTPUT"):
                        cross.compile_ssa_target_object(
                            self.ir, target="x86_64-unknown-linux-gnu", output=output)
                self.assertFalse(output.exists())
                self.assertFalse(output.is_symlink())


if __name__ == "__main__":
    unittest.main()
