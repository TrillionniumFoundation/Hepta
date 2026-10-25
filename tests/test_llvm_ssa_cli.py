"""Command-level Rust reference + scalar HSIR/SSA/LLVM native qualification.

No passing test grants full backend refinement or memory-model proof.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source


SOURCE = """module llvm_command;
export "C" fn sum(n: i32) -> i32 effects {panic} {
    let mut i: i32 = 0;
    let mut total: i32 = 0;
    while i < n {
        total = total + i;
        i = i + 1;
    }
    return total;
}
"""


class LLVMSSASourceCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-llvm-command-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "program.hepta"
        self.source.write_text(SOURCE, encoding="utf-8")
        self.output = self.root / "compiled.so"

    def test_invalid_target_and_existing_output_reject_without_side_effect(self):
        wrong = build_llvm_ssa_source(self.source, self.output, target="unknown-cpu")
        self.assertFalse(wrong["ok"])
        self.assertFalse(self.output.exists())
        self.output.write_bytes(b"do not overwrite")
        outcome = build_llvm_ssa_source(self.source, self.output)
        self.assertFalse(outcome["ok"])
        self.assertEqual(self.output.read_bytes(), b"do not overwrite")

    def test_dangling_output_symlink_rejected(self):
        other = self.root / "unexpected.so"
        self.output.symlink_to(other)
        report = build_llvm_ssa_source(self.source, self.output)
        self.assertFalse(report["ok"])
        self.assertTrue(self.output.is_symlink())
        self.assertFalse(other.exists())

    def test_missing_native_rust_gate_cannot_publish(self):
        report = build_llvm_ssa_source(self.source, self.output, rustc="/missing/hepta-rustc")
        self.assertFalse(report["ok"])
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "Native Clang and pinned Rust are required")
    def test_corrupt_native_digest_does_not_publish_any_artifact(self):
        def fake_native(ir, *, clang, output, ssa, cfg):
            Path(output).write_bytes(b"wrong compiled artifact")
            return {"status": "native_host_compiled_unqualified",
                    "artifact_sha256": "0" * 64,
                    "artifact_bytes": len(b"wrong compiled artifact"),
                    "llvm_ir_sha256": ir.sha256,
                    "llvm_source_profile": ir.profile,
                    "ssa_sha256": ssa.sha256,
                    "ssa_verification_sha256": ir.verification_sha256,
                    "claims": {"backend_refinement_proven": False,
                               "ssa_cfg_origin_rechecked": True}}
        with patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm", side_effect=fake_native):
            outcome = build_llvm_ssa_source(self.source, self.output,
                                            rustc=os.environ.get("RUSTC"))
        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("E_LLVM_SSA_ARTIFACT", outcome["diagnostics"][0]["code"])
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "Native Clang and pinned Rust are required")
    def test_forged_native_status_or_proof_scope_never_publishes(self):
        def fake_native(ir, *, clang, output, ssa, cfg):
            payload = b"plausible but unqualified object"
            Path(output).write_bytes(payload)
            return {"status": "native_host_compiled_unqualified",
                    "artifact_sha256": sha256(payload).hexdigest(),
                    "artifact_bytes": len(payload),
                    "llvm_ir_sha256": ir.sha256,
                    "llvm_source_profile": ir.profile,
                    "ssa_sha256": ir.source_ssa_sha256,
                    "ssa_verification_sha256": ir.verification_sha256,
                    "claims": {"backend_refinement_proven": True,
                               "ssa_cfg_origin_rechecked": True}}
        with patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm", side_effect=fake_native):
            report = build_llvm_ssa_source(self.source, self.output,
                                           rustc=os.environ.get("RUSTC"))
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_LLVM_SSA_RECEIPT")
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "Native Clang and pinned Rust are required")
    def test_rehashed_emitter_result_cannot_pass_source_bound_build(self):
        from dataclasses import replace
        import re
        from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm

        def changed_module(ssa, cfg):
            original = emit_scalar_ssa_llvm(ssa, cfg)
            text = re.sub(r"(?m)^  ret i32 [^\n]+$", "  ret i32 12345",
                          original.text, count=1)
            self.assertNotEqual(text, original.text)
            return replace(original, text=text, sha256=sha256(text.encode()).hexdigest())

        with patch("hepta.llvm_ssa_pipeline.emit_scalar_ssa_llvm", side_effect=changed_module):
            report = build_llvm_ssa_source(self.source, self.output,
                                           rustc=os.environ.get("RUSTC"))
        self.assertFalse(report["ok"])
        self.assertEqual(report["reference_validation"]["checks"]["rust_borrows_types"],
                         "rustc_checked")
        self.assertEqual(report["diagnostics"][0]["code"], "E_LLVM_SSA_ORIGIN")
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which("clang") and (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "Native Clang and pinned Rust are required")
    def test_exact_checked_source_to_native_llvm_and_cli(self):
        report = build_llvm_ssa_source(self.source, self.output, rustc=os.environ.get("RUSTC"))
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["reference_validation"]["checks"]["rust_borrows_types"],
                         "rustc_checked")
        self.assertEqual(report["status"], "native_host_compiled_unqualified")
        self.assertTrue(report["claims"]["independent_scalar_ssa_structure_checked"])
        self.assertTrue(report["claims"]["ssa_cfg_origin_rechecked"])
        self.assertTrue(report["native_backend"]["claims"]["ssa_cfg_origin_rechecked"])
        self.assertFalse(report["claims"]["backend_refinement_proved"])
        native = ctypes.CDLL(str(self.output)).sum
        native.argtypes = [ctypes.c_int32]
        native.restype = ctypes.c_int32
        for n in (-8, -1, 0, 1, 2, 4, 7, 10, 31, 100):
            with self.subTest(n=n):
                self.assertEqual(native(n), (n * (n - 1) // 2 if n > 0 else 0))
        # The CLI must expose JSON and reject attempts to overwrite the artifact.
        from contextlib import redirect_stdout
        import io
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main(["build-llvm-ssa", str(self.source), "--output", str(self.output)])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(stream.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
