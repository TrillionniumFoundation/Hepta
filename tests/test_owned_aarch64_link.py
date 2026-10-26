"""Native ARM64 synthetic freestanding linkability is NOT runtime qualification."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.owned_aarch64_link import (
    OwnedAArch64LinkRejected, inspect_synthetic_aarch64_elf,
    probe_owned_aarch64_freestanding_link, _SHIM,
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

    def test_real_linked_elf_rejects_unbacked_executable_functions(self):
        # Build the same finite nonfunctional shim without running it. A
        # correctly linked image is a positive control for both mutations.
        shim = self.root / "link-shim.c"
        shim_object = self.root / "link-shim.o"
        target = self.root / "link-only.elf"
        shim.write_text(_SHIM, encoding="ascii")
        compiler = subprocess.run(
            [self.compiler, "--target=aarch64-unknown-linux-gnu", "-x", "c",
             "-std=c11", "-ffreestanding", "-nostdinc", "-fno-builtin",
             "-fno-stack-protector", "-O0", "-Wall", "-Wextra", "-Werror",
             "-c", str(shim), "-o", str(shim_object)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(compiler.returncode, 0, compiler.stderr)
        linker = subprocess.run(
            [self.compiler, "--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld", "-nostdlib", "-static", "-Wl,-e,_start",
             str(self.path), str(shim_object), "-o", str(target)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(linker.returncode, 0, linker.stderr)
        original = target.read_bytes()
        functions = ("hepta_owner_test",)
        self.assertTrue(inspect_synthetic_aarch64_elf(
            original, functions)["no_unresolved_symbols"])

        # SHT_NOBITS has no actual text bytes, even if its flags claim
        # executable+allocated. A forged section header cannot pass.
        no_bits = bytearray(original)
        shoff = int.from_bytes(no_bits[40:48], "little")
        shnum = int.from_bytes(no_bits[60:62], "little")
        executable_sections = [
            shoff + 64 * index
            for index in range(shnum)
            if int.from_bytes(no_bits[shoff + 64 * index + 4:
                                     shoff + 64 * index + 8], "little") == 1
            and int.from_bytes(no_bits[shoff + 64 * index + 8:
                                       shoff + 64 * index + 16], "little") & 6 == 6
        ]
        self.assertTrue(executable_sections)
        at = executable_sections[0]
        no_bits[at + 4:at + 8] = (8).to_bytes(4, "little")
        with self.assertRaisesRegex(OwnedAArch64LinkRejected, "LINK"):
            inspect_synthetic_aarch64_elf(bytes(no_bits), functions)

        # Keep the entrypoint just inside a file-backed RX PT_LOAD but
        # truncate its mapped size so _start's remaining bytes are absent.
        short = bytearray(original)
        entry = int.from_bytes(short[24:32], "little")
        phoff = int.from_bytes(short[32:40], "little")
        phnum = int.from_bytes(short[56:58], "little")
        patched = False
        for i in range(phnum):
            at = phoff + i * 56
            if (int.from_bytes(short[at:at + 4], "little") == 1
                    and int.from_bytes(short[at + 4:at + 8], "little") & 1):
                addr = int.from_bytes(short[at + 16:at + 24], "little")
                size = int.from_bytes(short[at + 32:at + 40], "little")
                if addr <= entry < addr + size and entry + 1 - addr < size:
                    short[at + 32:at + 40] = (entry + 1 - addr).to_bytes(8, "little")
                    patched = True
                    break
        self.assertTrue(patched)
        with self.assertRaisesRegex(OwnedAArch64LinkRejected, "LINK"):
            inspect_synthetic_aarch64_elf(bytes(short), functions)

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
