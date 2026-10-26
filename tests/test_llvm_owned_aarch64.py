"""Native AArch64 Owned LLVM *object-only* positive and refusal controls.

These tests do not use QEMU, claim platform ABI equivalence, or run an AArch64
executable. They verify actual Clang-produced relocatable ELF bytes.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.llvm_owned_aarch64 import (
    TARGET_AARCH64, build_owned_aarch64_source, compile_owned_aarch64_object,
    inspect_owned_aarch64_object, retarget_owned_llvm,
)
from hepta.llvm_owned_backend import LLVMOwnedRejected, emit_owned_llvm
from hepta.pipeline import analyze


SOURCE = """
export "C" fn checked_owner_length(n:usize)->u64 effects {alloc,block,panic} {
    let bytes=buffer(n);
    let length=len(bytes) as u64;
    drop(move bytes);
    return length;
}
"""


@unittest.skipUnless(shutil.which("clang"), "actual native target Clang is needed")
class OwnedAArch64ObjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-owned-aarch64-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checked_source = analyze(SOURCE, str(self.root / "source.hepta"), native=False)
        self.assertTrue(self.checked_source.report["ok"], self.checked_source.report)
        self.ir = emit_owned_llvm(self.checked_source.program, self.checked_source.checked)

    def compile(self, ir=None, name="native.o"):
        return compile_owned_aarch64_object(
            ir if ir is not None else self.ir, program=self.checked_source.program,
            checked=self.checked_source.checked, output=self.root / name)

    def test_exact_checked_source_builds_real_aarch64_elf_and_receipt(self):
        receipt = self.compile()
        object_bytes = (self.root / "native.o").read_bytes()
        self.assertEqual(object_bytes[:6], b"\x7fELF\x02\x01")
        self.assertEqual(int.from_bytes(object_bytes[18:20], "little"), 183)
        self.assertEqual(receipt["status"], "cross_object_only_not_executed")
        self.assertEqual(receipt["artifact_sha256"], sha256(object_bytes).hexdigest())
        self.assertEqual(receipt["artifact_bytes"], len(object_bytes))
        self.assertEqual(receipt["target"], TARGET_AARCH64)
        self.assertEqual(receipt["symbols"]["exports"], ["checked_owner_length"])
        layout = receipt["target_layout_probe"]
        self.assertEqual(layout["target"], TARGET_AARCH64)
        self.assertEqual(layout["bound_llvm_sha256"], receipt["target_llvm_sha256"])
        self.assertEqual(layout["status"], "target_c_static_assertions_compiled_not_executed")
        self.assertEqual(layout["observed_requirements"]["buffer_alignment"], 8)
        self.assertTrue(receipt["claims"]["target_c_layout_compiled"])
        self.assertIs(layout["llvm_layout_equivalence_proved"], False)
        self.assertTrue(receipt["claims"]["source_and_resource_origin_regenerated"])
        for flag in ("target_object_executed", "target_link_succeeded",
                     "foreign_abi_qualified", "physical_hardware_tested",
                     "whole_language_memory_safety_proved"):
            self.assertIs(receipt["claims"][flag], False)

    def test_only_target_triple_is_rewritten_and_untrusted_ir_rejected(self):
        text, digest = retarget_owned_llvm(self.ir, TARGET_AARCH64)
        self.assertEqual(digest, sha256(text.encode()).hexdigest())
        self.assertEqual(text.replace('target triple = "aarch64-unknown-linux-gnu"',
                                      'target triple = "x86_64-unknown-linux-gnu"'),
                         self.ir.text)
        with self.assertRaisesRegex(LLVMOwnedRejected, "TARGET"):
            retarget_owned_llvm(self.ir, "x86_64-pc-windows-msvc")
        tampered = replace(self.ir, text=self.ir.text.replace("target triple",
                         "target datalayout", 1))
        tampered = replace(tampered, sha256=sha256(tampered.text.encode()).hexdigest())
        with self.assertRaisesRegex(LLVMOwnedRejected, "(TARGET|SOURCE)"):
            self.compile(tampered, "forged.o")
        self.assertFalse((self.root / "forged.o").exists())

    def test_rehashed_foreign_source_emission_is_not_trusted(self):
        poisoned = replace(self.ir, semantic_sha256="0" * 64)
        with self.assertRaisesRegex(LLVMOwnedRejected, "SOURCE"):
            self.compile(poisoned, "wrong-semantic.o")
        self.assertFalse((self.root / "wrong-semantic.o").exists())

    def test_unknown_dynamic_dependency_is_refused_from_real_aarch64_elf(self):
        ll = self.root / "unknown.ll"
        obj = self.root / "unknown.o"
        ll.write_text('target triple = "aarch64-unknown-linux-gnu"\n'
                      'declare i32 @getpid()\n'
                      'define i32 @checked_owner_length() {\n'
                      'entry:\n'
                      '  %v = call i32 @getpid()\n'
                      '  ret i32 %v\n'
                      '}\n')
        subprocess.run(["clang", "--target=" + TARGET_AARCH64,
                        "-x", "ir", "-O2", "-c", str(ll), "-o", str(obj)],
                       check=True, capture_output=True, timeout=30)
        with self.assertRaisesRegex(LLVMOwnedRejected, "IMPORT"):
            inspect_owned_aarch64_object(obj.read_bytes(), ("checked_owner_length",))
        with self.assertRaisesRegex(LLVMOwnedRejected, "EXPORT"):
            inspect_owned_aarch64_object(obj.read_bytes(), ("wrong_name",))

    def test_other_target_bytes_cannot_claim_aarch64(self):
        with self.assertRaisesRegex(LLVMOwnedRejected, "OBJECT"):
            inspect_owned_aarch64_object(b"not-elf", ("checked_owner_length",))

    def test_existing_or_symlink_output_cannot_be_published(self):
        old = self.root / "old.o"
        old.write_bytes(b"preserve")
        with self.assertRaisesRegex(LLVMOwnedRejected, "OUTPUT"):
            self.compile(name="old.o")
        self.assertEqual(old.read_bytes(), b"preserve")
        alias = self.root / "alias.o"
        alias.symlink_to(self.root / "not-here.o")
        with self.assertRaisesRegex(LLVMOwnedRejected, "OUTPUT"):
            self.compile(name="alias.o")
        self.assertTrue(alias.is_symlink())


class OwnedAArch64ReferenceGateTests(unittest.TestCase):
    def test_frontend_only_cannot_publish_a_target_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "arm64.o"
            unsupported = SimpleNamespace(
                report={"ok": True, "checks": {"rust_borrows_types": "not_run"},
                        "assumptions": []},
                program=object(), checked=object(), project=object(),
            )
            with patch("hepta.llvm_owned_aarch64.analyze_project",
                       return_value=unsupported):
                report = build_owned_aarch64_source(root / "input.hepta", target)
            self.assertFalse(report["ok"])
            self.assertFalse(target.exists())
            self.assertEqual(report["diagnostics"][0]["code"],
                             "E_LLVM_OWNED_TARGET_REFERENCE")


if __name__ == "__main__":
    unittest.main()
