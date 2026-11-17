"""Byte-level x86-64 kernel instruction checks; never execute privileged code.

This is a staging test of the direct encoder only. It is not HIA Core
verifier support, not the native self-hosted compiler, and not a QEMU test.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_opcodes import OpcodeRejected, opcode_spec


class KernelEncodingTests(unittest.TestCase):
    CASES = (
        ("read_rax", "read_cr3", ("rax",), "0f20d8", r"\bmov\s+%cr3,%rax"),
        ("read_r15", "read_cr3", ("r15",), "410f20df", r"\bmov\s+%cr3,%r15"),
        ("write_rax", "write_cr3", ("rax",), "0f22d8", r"\bmov\s+%rax,%cr3"),
        ("write_r12", "write_cr3", ("r12",), "410f22dc", r"\bmov\s+%r12,%cr3"),
        ("invalidate_rax", "invlpg", ("rax", 0),
         "0f01b800000000", r"\binvlpg\s+0x0\(%rax\)"),
        ("invalidate_rsp", "invlpg", ("rsp", 64),
         "0f01bc2440000000", r"\binvlpg\s+0x40\(%rsp\)"),
        ("invalidate_r12", "invlpg", ("r12", -16),
         "410f01bc24f0ffffff", r"\binvlpg\s+-0x10\(%r12\)"),
        ("invalidate_r13", "invlpg", ("r13", 4096),
         "410f01bd00100000", r"\binvlpg\s+0x1000\(%r13\)"),
    )

    def test_unprivileged_core_v8_still_refuses_kernel_instructions(self):
        # Adding a machine encoder helper must not silently extend ordinary
        # HIA opcode admission. A later kernel profile needs typed effects.
        for op in ("x86.read_cr3", "x86.write_cr3", "x86.invlpg"):
            with self.subTest(opcode=op):
                with self.assertRaises(OpcodeRejected):
                    opcode_spec(op, "hepta.hia.program.v8")

    def test_independent_exact_instruction_vectors(self):
        for name, method, args, expected, _ in self.CASES:
            with self.subTest(name=name):
                code = Code()
                getattr(code, method)(*args)
                image, relocations = code.finalize()
                self.assertEqual(image, bytes.fromhex(expected))
                self.assertEqual(relocations, [])
                self.assertEqual(code.finalize(), (image, []))

    def test_all_integer_registers_admitted_and_no_implicit_relocations(self):
        regs = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        for reg in regs:
            for method in ("read_cr3", "write_cr3", "invlpg"):
                with self.subTest(register=reg, method=method):
                    code = Code()
                    getattr(code, method)(reg)
                    image, relocations = code.finalize()
                    self.assertGreaterEqual(len(image), 3)
                    self.assertEqual(relocations, [])

    def test_invalid_inputs_reject_atomically_without_emitting(self):
        for method in ("read_cr3", "write_cr3", "invlpg"):
            for bad in ("eax", "cr3", "rip", "[rax]", 0, None, True):
                with self.subTest(method=method, invalid=repr(bad)):
                    code = Code()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, method)(bad)
                    self.assertEqual(code.finalize(), (b"", []))
        for bad in (True, None, 1.0, 1 << 31, -(1 << 31) - 1):
            with self.subTest(displacement=repr(bad)):
                code = Code()
                with self.assertRaises(MachineEncodingError):
                    code.invlpg("rax", bad)
                self.assertEqual(code.finalize(), (b"", []))

    @unittest.skipUnless(shutil.which("objdump"), "GNU binutils disassembly required")
    def test_independent_objdump_decodes_every_privileged_instruction(self):
        with tempfile.TemporaryDirectory(prefix="hia-kernel-encoding-") as tmp:
            for name, method, args, expected, opcode in self.CASES:
                with self.subTest(name=name):
                    code = Code()
                    getattr(code, method)(*args)
                    binary = Path(tmp) / (name + ".bin")
                    binary.write_bytes(code.finalize()[0])
                    decoded = subprocess.run(
                        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                         str(binary)],
                        check=True, capture_output=True, text=True,
                        env={**os.environ, "LC_ALL": "C"}).stdout
                    self.assertRegex(decoded, opcode)
                    self.assertNotIn("(bad)", decoded)
                    self.assertEqual(binary.read_bytes(), bytes.fromhex(expected))


if __name__ == "__main__":
    unittest.main()
