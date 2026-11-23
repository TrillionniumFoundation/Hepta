"""Independent GNU-as oracle for unpromoted x86-64 LIDT and LTR encodings."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError, PrivilegedCode
from hepta.hia_x86_kernel_descriptor import KernelDescriptorCode

REGISTERS = (
    ("rax", "ax"), ("rcx", "cx"), ("rdx", "dx"), ("rbx", "bx"),
    ("rsp", "sp"), ("rbp", "bp"), ("rsi", "si"), ("rdi", "di"),
    ("r8", "r8w"), ("r9", "r9w"), ("r10", "r10w"), ("r11", "r11w"),
    ("r12", "r12w"), ("r13", "r13w"), ("r14", "r14w"), ("r15", "r15w"),
)
DISPLACEMENTS = (0, 1, -1, 127, -128, 128, -129, 4096,
                 -4096, (1 << 31) - 1, -(1 << 31))


class DescriptorStageTests(unittest.TestCase):
    def test_scope_keeps_original_core_and_default_code_closed(self):
        from hepta.hia_opcodes import EFFECTS, OPCODES
        self.assertEqual(EFFECTS, {"alloc", "read", "write", "trap"})
        for name in ("lidt", "ltr"):
            self.assertFalse(hasattr(Code(), name))
            self.assertFalse(hasattr(PrivilegedCode(), name))
            self.assertTrue(hasattr(KernelDescriptorCode(), name))
            self.assertNotIn("x86." + name, OPCODES)

    def test_exact_short_vectors_and_repeatability(self):
        machine = KernelDescriptorCode()
        machine.lidt("r10")
        machine.lidt("r13", 0)
        machine.ltr("rax")
        machine.ltr("r8")
        expected = bytes.fromhex("410f011a410f015d000f00d8410f00d8")
        self.assertEqual(machine.finalize(), (expected, []))
        self.assertEqual(machine.finalize(), (expected, []))

    def test_operand_refusal_never_emits_partial_bytes(self):
        for bad in ("eax", "xmm0", "cr3", "rip", None, True, 7, []):
            for op in ("lidt", "ltr"):
                with self.subTest(op=op, bad=repr(bad)):
                    code = KernelDescriptorCode()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, op)(bad)
                    self.assertEqual(code.finalize(), (b"", []))
        for bad in (None, True, "0", 1.5, 1 << 31, -(1 << 31) - 1):
            with self.subTest(disp=repr(bad)):
                code = KernelDescriptorCode()
                with self.assertRaises(MachineEncodingError):
                    code.lidt("r10", bad)
                self.assertEqual(code.finalize(), (b"", []))
        for wrong in ((), ("rax", "rdx"), ("rax", 0, 1)):
            with self.subTest(args=wrong):
                code = KernelDescriptorCode()
                with self.assertRaises(TypeError):
                    code.ltr(*wrong)
                self.assertEqual(code.finalize(), (b"", []))

    def test_dishonest_noop_has_different_bytes(self):
        expected = KernelDescriptorCode()
        expected.lidt("r10")
        expected.ret()
        dishonest = KernelDescriptorCode()
        dishonest.ret()
        self.assertNotEqual(expected.finalize()[0], dishonest.finalize()[0])
        self.assertEqual(expected.finalize()[0], bytes.fromhex("410f011ac3"))

    @unittest.skipUnless(all(shutil.which(x) for x in ("as", "objcopy", "objdump")),
                         "independent GNU assembler/disassembler required")
    def test_all_registers_and_disp_boundaries_match_gnu_assembler(self):
        code = KernelDescriptorCode()
        asm = [".text", ".global descriptor_oracle", "descriptor_oracle:"]
        for reg, reg16 in REGISTERS:
            for disp in DISPLACEMENTS:
                code.lidt(reg, disp)
                asm.append(f"  lidt {disp}(%{reg})")
            code.ltr(reg)
            asm.append(f"  ltr %{reg16}")
        emitted, relocations = code.finalize()
        self.assertEqual(relocations, [])
        self.assertEqual(len(asm) - 3, 16 * (len(DISPLACEMENTS) + 1))
        with tempfile.TemporaryDirectory(prefix="hia-x86-descriptor-oracle-") as temp:
            root = Path(temp)
            (root / "oracle.s").write_text("\n".join(asm) + "\n")
            subprocess.run(["as", "--64", "-o", str(root / "oracle.o"),
                            str(root / "oracle.s")], check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(root / "oracle.o"), str(root / "oracle.bin")],
                           check=True, capture_output=True)
            self.assertEqual(emitted, (root / "oracle.bin").read_bytes())
            disassembly = subprocess.run(["objdump", "-d", "-M", "intel",
                                          str(root / "oracle.o")],
                                         check=True, capture_output=True, text=True).stdout
            self.assertEqual(disassembly.count("lidt "), 16 * len(DISPLACEMENTS))
            self.assertEqual(disassembly.count("ltr "), 16)
            self.assertNotIn("(bad)", disassembly)


if __name__ == "__main__":
    unittest.main()
