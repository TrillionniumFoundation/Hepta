"""Native ARM64 synthetic freestanding linkability is NOT runtime qualification."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.owned_aarch64_link import (
    OwnedAArch64LinkRejected, inspect_synthetic_aarch64_elf,
    probe_owned_aarch64_freestanding_link,
)


LL = """\
target triple = "aarch64-unknown-linux-gnu"
declare ptr @malloc(i64)
declare void @free(ptr)
define i64 @hepta_owner_test(i64 %n) {
entry:
  %ptr = call ptr @malloc(i64 %n)
  %failed = icmp eq ptr %ptr, null
  br i1 %failed, label %bad, label %ok
ok:
  call void @free(ptr %ptr)
  ret i64 %n
bad:
  ret i64 1
}
"""


@unittest.skipUnless(shutil.which("clang") and shutil.which("ld.lld"),
                     "real cross Clang and lld required; no target runtime execution")
class AArch64LinkProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-link-probe-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.compiler = shutil.which("clang")
        self.path = self.root / "owner.o"
        self.compile(self.path, LL)

    def compile(self, path, source):
        ir = path.with_suffix(".ll")
        ir.write_text(source)
        result = subprocess.run(
            [self.compiler, "--target=aarch64-unknown-linux-gnu", "-x", "ir",
             "-O2", "-c", str(ir), "-o", str(path)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_aarch64_static_link_resolution(self):
        report = probe_owned_aarch64_freestanding_link(
            self.path.read_bytes(), ("hepta_owner_test",), clang=self.compiler)
        self.assertEqual(report["status"], "synthetic_freestanding_link_only_not_executed")
        self.assertEqual(report["target"], "aarch64-unknown-linux-gnu")
        self.assertGreater(report["linked_bytes"], 0)
        self.assertTrue(report["symbols"]["no_unresolved_symbols"])
        self.assertIn("hepta_owner_test", report["symbols"]["external_functions"])
        self.assertTrue(report["relocations_linked_with_dummy_shims"])
        for key in ("real_allocator_linked", "linux_runtime_qualified",
                    "c_abi_execution_qualified", "physical_hardware_executed"):
            self.assertIs(report[key], False)

    def test_missing_or_wrong_export_refuses_source_claim(self):
        with self.assertRaisesRegex(ValueError, "(EXPORT|LINK)"):
            probe_owned_aarch64_freestanding_link(
                self.path.read_bytes(), ("other_export",), clang=self.compiler)

    def test_actual_unreviewed_import_rejected_before_linker(self):
        foreign = LL.replace(
            "define i64 @hepta_owner_test",
            "declare i32 @getpid()\ndefine i64 @hepta_owner_test")
        foreign = foreign.replace(
            "  %ptr = call ptr @malloc(i64 %n)",
            "  %unreviewed = call i32 @getpid()\n  %ptr = call ptr @malloc(i64 %n)")
        file = self.root / "unreviewed.o"
        self.compile(file, foreign)
        with self.assertRaisesRegex(ValueError, "(IMPORT|LINK)"):
            probe_owned_aarch64_freestanding_link(
                file.read_bytes(), ("hepta_owner_test",), clang=self.compiler)

    def test_linked_image_rejects_writable_executable_load_and_exec_stack(self):
        # Capture the real Clang/lld linked bytes before the synthetic probe
        # discards them. Only the ELF reader is called with mutated bytes;
        # no dummy-allocator image is ever executed.
        import hepta.owned_aarch64_link as module
        original = module.inspect_synthetic_aarch64_elf
        captured = []

        def retain(payload, exports):
            captured.append(payload)
            return original(payload, exports)

        with patch.object(module, "inspect_synthetic_aarch64_elf", side_effect=retain):
            report = module.probe_owned_aarch64_freestanding_link(
                self.path.read_bytes(), ("hepta_owner_test",), clang=self.compiler)
        self.assertTrue(report["symbols"]["no_unresolved_symbols"])
        linked = captured[-1]
        phoff = int.from_bytes(linked[32:40], "little")
        count = int.from_bytes(linked[56:58], "little")
        load = []
        stack = []
        for index in range(count):
            at = phoff + 56 * index
            kind = int.from_bytes(linked[at:at+4], "little")
            if kind == 1:
                load.append(at)
            if kind == 0x6474e551:
                stack.append(at)
        self.assertTrue(load)
        for label, positions in (("rwx_load", load[:1]), ("exec_stack", stack[:1])):
            if not positions:
                continue
            with self.subTest(case=label):
                corrupted = bytearray(linked)
                at = positions[0]
                original_flags = int.from_bytes(corrupted[at+4:at+8], "little")
                corrupted[at+4:at+8] = (original_flags | (3 if label == "rwx_load" else 1)).to_bytes(4, "little")
                with self.assertRaisesRegex(OwnedAArch64LinkRejected,
                                            "executable stack or writable executable"):
                    original(bytes(corrupted), ("hepta_owner_test",))

    def test_link_receipt_cannot_use_changed_native_compiler(self):
        import hepta.owned_aarch64_link as module
        with patch.object(module, "digest_executable",
                          side_effect=["a" * 64, "b" * 64]) as digest:
            with self.assertRaisesRegex(OwnedAArch64LinkRejected,
                                        "compiler changed during synthetic link"):
                probe_owned_aarch64_freestanding_link(
                    self.path.read_bytes(), ("hepta_owner_test",),
                    clang=self.compiler)
        self.assertEqual(digest.call_count, 2)

    def test_linked_image_negative_header_controls(self):
        # Unit-level header refusal applies without executing foreign code.
        bad = bytearray(b"\x7fELF" + b"\x02\x01" + b"\0" * 600)
        with self.assertRaisesRegex(OwnedAArch64LinkRejected, "LINK"):
            inspect_synthetic_aarch64_elf(bytes(bad), ("hepta_owner_test",))
        bad[18:20] = (62).to_bytes(2, "little")
        with self.assertRaisesRegex(OwnedAArch64LinkRejected, "LINK"):
            inspect_synthetic_aarch64_elf(bytes(bad), ("hepta_owner_test",))


if __name__ == "__main__":
    unittest.main()
