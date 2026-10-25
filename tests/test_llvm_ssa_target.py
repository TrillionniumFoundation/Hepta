"""Cross-target i32 SSA/PHI object is not cross-target execution or ABI proof."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm
from hepta.llvm_ssa_target import compile_ssa_target_object, _qualified_header
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_llvm_ssa_backend import exported
from tests.test_ssa_differential import nested_loop_fixture


@unittest.skipUnless(shutil.which("clang"), "Clang backend required")
class LLVMSSATargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.graph = exported(nested_loop_fixture())
        self.ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(self.graph), self.graph)

    def test_validated_elf_coff_and_macho_cross_objects(self):
        for target, machine in (("x86_64-unknown-linux-gnu", 62),
                                ("aarch64-unknown-linux-gnu", 183),
                                ("x86_64-pc-windows-msvc", 0x8664),
                                ("x86_64-apple-darwin", 0x01000007),
                                ("aarch64-apple-darwin", 0x0100000c)):
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

    def test_reject_macho_wrong_machine_or_wrong_file_type(self):
        # Accept only Mach-O 64-bit MH_OBJECT for the exact requested CPU.
        header = (b"\xcf\xfa\xed\xfe" + (0x01000007).to_bytes(4, "little")
                  + (3).to_bytes(4, "little") + (1).to_bytes(4, "little")
                  + b"\x00" * 16)
        # A 32-byte Mach-O header without load commands and sections is not
        # a complete object; the former positive expectation was incorrect.
        self.assertFalse(_qualified_header(header, "x86_64-apple-darwin"))
        self.assertFalse(_qualified_header(header, "aarch64-apple-darwin"))
        linked = header[:12] + (2).to_bytes(4, "little") + header[16:]
        self.assertFalse(_qualified_header(linked, "x86_64-apple-darwin"))
        self.assertFalse(_qualified_header(header[:16], "x86_64-apple-darwin"))
        big_endian = b"\xfe\xed\xfa\xcf" + header[4:]
        self.assertFalse(_qualified_header(big_endian, "x86_64-apple-darwin"))

    def test_reject_out_of_file_section_payloads_on_real_target_objects(self):
        # A correct machine tag plus valid section-table bounds must not let
        # truncated/fabricated payload references masquerade as a native build.
        for target in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                       "aarch64-apple-darwin"):
            with self.subTest(target=target):
                output = self.root / ("sections-" + target + ".o")
                compile_ssa_target_object(self.ir, target=target, output=output)
                original = output.read_bytes()
                self.assertTrue(_qualified_header(original, target))
                data = bytearray(original)
                if "linux" in target:
                    table = int.from_bytes(data[40:48], "little")
                    count = int.from_bytes(data[60:62], "little")
                    candidates = [
                        table + 64 * index
                        for index in range(count)
                        if int.from_bytes(data[table + 64 * index + 32:table + 64 * index + 40], "little")
                        and int.from_bytes(data[table + 64 * index + 4:table + 64 * index + 8], "little") != 8
                    ]
                    self.assertTrue(candidates)
                    start = candidates[0] + 32
                    data[start:start + 8] = (len(data) + 1024).to_bytes(8, "little")
                elif "windows" in target:
                    self.assertGreater(int.from_bytes(data[20 + 16:20 + 20], "little"), 0)
                    data[20 + 16:20 + 20] = (len(data) + 1024).to_bytes(4, "little")
                else:
                    # First Clang object command is LC_SEGMENT_64 with __text.
                    self.assertEqual(int.from_bytes(data[32:36], "little"), 0x19)
                    self.assertGreater(int.from_bytes(data[32 + 64:32 + 68], "little"), 0)
                    data[32 + 72 + 40:32 + 72 + 48] = (len(data) + 1024).to_bytes(8, "little")
                self.assertFalse(_qualified_header(bytes(data), target))

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
