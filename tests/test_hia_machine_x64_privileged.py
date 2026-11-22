"""Independent GNU as byte oracle for staged x86-64 privileged encodings.

These tests assemble/disassemble but NEVER execute privileged instructions.
No Core effect, verifier, native selfhost lowering or QEMU execution is claimed.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, PrivilegedCode, MachineEncodingError


REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
DISPLACEMENTS = (0, 1, -1, 127, -128, 128, -129,
                 4096, -4096, (1 << 31) - 1, -(1 << 31))


class PrivilegedEncodingTests(unittest.TestCase):
    def test_malformed_operands_fail_closed_without_emitting(self):
        for invalid in ("eax", "cr3", "xmm0", "rip", None, True, 1, []):
            for method in ("read_cr3", "write_cr3", "invlpg"):
                with self.subTest(method=method, invalid=repr(invalid)):
                    code = PrivilegedCode()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, method)(invalid)
                    self.assertEqual(code.finalize(), (b"", []))
        for invalid in (True, None, "0", 1 << 31, -(1 << 31) - 1, 1.5):
            with self.subTest(disp=repr(invalid)):
                code = PrivilegedCode()
                with self.assertRaises(MachineEncodingError):
                    code.invlpg("rax", invalid)
                self.assertEqual(code.finalize(), (b"", []))

    def test_default_code_remains_unprivileged_and_subclass_is_explicit(self):
        reference = Code()
        self.assertIs(type(reference), Code)
        for name in ("read_cr3", "write_cr3", "invlpg", "iretq"):
            self.assertFalse(hasattr(reference, name))
            self.assertTrue(hasattr(PrivilegedCode(), name))
        self.assertIs(type(PrivilegedCode()), PrivilegedCode)

    def test_staged_encoder_does_not_grant_core_privilege_effect(self):
        # No effect inference, HIA Core IR operation, selfhost emission or
        # privileged execution authority has been integrated at this stage.
        from hepta.hia_opcodes import EFFECTS, OPCODES
        self.assertEqual(EFFECTS, {"alloc", "read", "write", "trap"})
        for name in ("x86.read_cr3", "x86.write_cr3", "x86.invlpg", "x86.iretq"):
            self.assertNotIn(name, OPCODES)

    @unittest.skipUnless(shutil.which("as") and shutil.which("objcopy") and
                         shutil.which("objdump"), "independent GNU binutils required")
    def test_every_register_and_boundary_displacement_matches_gnu_as(self):
        code = PrivilegedCode()
        source = [".text", ".globl privileged_oracle", "privileged_oracle:"]
        for reg in REGISTERS:
            code.read_cr3(reg)
            source.append(f"  mov %cr3,%{reg}")
            code.write_cr3(reg)
            source.append(f"  mov %{reg},%cr3")
        for reg in REGISTERS:
            for disp in DISPLACEMENTS:
                code.invlpg(reg, disp)
                source.append(f"  invlpg {disp}(%{reg})")
        code.iretq()
        source.append("  iretq")
        machine, relocations = code.finalize()
        self.assertEqual(relocations, [])
        self.assertEqual(code.finalize(), (machine, []))
        with tempfile.TemporaryDirectory(prefix="hia-privileged-encode-") as directory:
            root = Path(directory)
            (root / "oracle.s").write_text("\n".join(source) + "\n")
            subprocess.run(["as", "--64", "-o", str(root / "oracle.o"),
                            str(root / "oracle.s")], check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(root / "oracle.o"), str(root / "oracle.bin")],
                           check=True, capture_output=True)
            expected = (root / "oracle.bin").read_bytes()
            self.assertEqual(len(source) - 3, 32 + 16 * len(DISPLACEMENTS) + 1)
            self.assertEqual(machine, expected)
            disassembly = subprocess.run(["objdump", "-d", "-M", "intel",
                                          str(root / "oracle.o")],
                                         check=True, capture_output=True, text=True).stdout
            self.assertEqual(disassembly.count("invlpg"), 16 * len(DISPLACEMENTS))
            self.assertIn("cr3", disassembly)
            self.assertIn("iretq", disassembly)
            self.assertNotIn("(bad)", disassembly)

    def test_scratch_register_renaming_is_respected(self):
        code = PrivilegedCode(scratch_registers={"r10": "r11", "r11": "r10"})
        code.read_cr3("r10")
        code.write_cr3("r11")
        code.invlpg("r10")
        encoded, relocations = code.finalize()
        self.assertEqual(encoded, bytes.fromhex("410f20db410f22da410f013b"))
        self.assertEqual(relocations, [])


if __name__ == "__main__":
    unittest.main()
