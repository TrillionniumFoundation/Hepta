"""Finite CPU data-model checks for the Owned LLVM pointer/length ABI.

These compile actual C11 target objects without libc or runtime execution.
They do not prove the LLVM backend's language refinement or target hardware.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from hepta.owned_target_layout import (
    OwnedTargetLayoutRejected, _SOURCE, probe_owned_target_layout,
)


def llvm(target):
    return (f'; hepta profile\ntarget triple = "{target}"\n'
            '%hepta.bytes = type { ptr, i64 }\n')


@unittest.skipUnless(shutil.which("clang"), "real Clang target object compiler required")
class OwnedTargetLayoutTests(unittest.TestCase):
    def setUp(self):
        self.clang = str(Path(shutil.which("clang")).resolve())

    def test_actual_x86_and_aarch64_static_model_assertions(self):
        for target, machine in (("x86_64-unknown-linux-gnu", 62),
                                ("aarch64-unknown-linux-gnu", 183)):
            with self.subTest(target=target):
                report = probe_owned_target_layout(self.clang, target, llvm(target))
                self.assertEqual(report["status"], "target_c_static_assertions_compiled_not_executed")
                self.assertEqual(report["machine"], machine)
                self.assertGreater(report["probe_object_bytes"], 0)
                self.assertTrue(report["compiler_checked"])
                self.assertEqual(report["observed_requirements"]["buffer_bytes"], 16)
                self.assertEqual(report["observed_requirements"]["len_offset"], 8)
                for claim in ("llvm_layout_equivalence_proved",
                              "native_abi_execution_qualified", "physical_target_executed"):
                    self.assertIs(report[claim], False)

    def test_mismatched_llvm_memory_layout_rejects_before_compiler(self):
        target = "aarch64-unknown-linux-gnu"
        with patch("hepta.owned_target_layout._clang_run",
                   side_effect=AssertionError("malformed model must not invoke native tools")):
            for value in (llvm(target).replace("ptr, i64", "i64, ptr"),
                          llvm(target).replace("aarch64-unknown-linux-gnu",
                                               "x86_64-unknown-linux-gnu"),
                          llvm(target) + 'target datalayout = "malicious"\n'):
                with self.subTest(llvm=value), self.assertRaisesRegex(
                        OwnedTargetLayoutRejected, "(SOURCE|TARGET)"):
                    probe_owned_target_layout(self.clang, target, value)

    def test_unsupported_or_type_confused_target_rejected(self):
        for target in ("x86_64-pc-windows-msvc", "aarch64-apple-darwin", True, None):
            with self.subTest(target=target), self.assertRaisesRegex(
                    OwnedTargetLayoutRejected, "TARGET"):
                probe_owned_target_layout(self.clang, target, llvm("aarch64-unknown-linux-gnu"))

    def test_forged_c_model_assertion_stops_native_artifact(self):
        target = "aarch64-unknown-linux-gnu"
        forged = _SOURCE.replace(
            'sizeof(struct hepta_owned_bytes) == 16',
            'sizeof(struct hepta_owned_bytes) == 24')
        self.assertNotEqual(forged, _SOURCE)
        with patch("hepta.owned_target_layout._SOURCE", forged):
            with self.assertRaisesRegex(OwnedTargetLayoutRejected, "E_OWNED_LAYOUT_ASSERT"):
                probe_owned_target_layout(self.clang, target, llvm(target))

    def test_unreviewed_external_import_never_qualifies_as_layout_probe(self):
        target = "aarch64-unknown-linux-gnu"
        forged = _SOURCE.replace(
            "int hepta_owned_layout_probe(void) { return (int)sizeof(struct hepta_owned_bytes); }",
            "extern int getpid(void);\nint hepta_owned_layout_probe(void) { return getpid(); }")
        self.assertNotEqual(forged, _SOURCE)
        with patch("hepta.owned_target_layout._SOURCE", forged):
            with self.assertRaisesRegex(OwnedTargetLayoutRejected, "E_OWNED_LAYOUT_OBJECT"):
                probe_owned_target_layout(self.clang, target, llvm(target))


if __name__ == "__main__":
    unittest.main()
