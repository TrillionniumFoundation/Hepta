"""Independent x86 control-register and port-I/O encoder staging.

Never execute these privileged instructions in a host user process. Byte
identity and binutils decoding alone do not establish effect safety or HIA
source/selfhost support. Tests preserve the ordinary Core admission boundary.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_machine_x64_kernel import KernelCode
from hepta.hia_opcodes import OpcodeRejected, opcode_spec


GPRS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


class KernelControlAndIOVectors(unittest.TestCase):
    CASES = (
        ("read_cr0", ("rax",), "0f20c0", r"\bmov\s+%cr0,%rax\b"),
        ("read_cr0", ("r8",), "410f20c0", r"\bmov\s+%cr0,%r8\b"),
        ("write_cr0", ("r13",), "410f22c5", r"\bmov\s+%r13,%cr0\b"),
        ("read_cr2", ("r12",), "410f20d4", r"\bmov\s+%cr2,%r12\b"),
        ("read_cr4", ("rax",), "0f20e0", r"\bmov\s+%cr4,%rax\b"),
        ("write_cr4", ("r15",), "410f22e7", r"\bmov\s+%r15,%cr4\b"),
        ("in_port", (8, "dx"), "ec", r"\bin\s+\(%dx\),%al\b"),
        ("in_port", (16, "dx"), "66ed", r"\bin\s+\(%dx\),%ax\b"),
        ("in_port", (32, "dx"), "ed", r"\bin\s+\(%dx\),%eax\b"),
        ("in_port", (8, 255), "e4ff", r"\bin\s+\$0xff,%al\b"),
        ("in_port", (16, 128), "66e580", r"\bin\s+\$0x80,%ax\b"),
        ("in_port", (32, 128), "e580", r"\bin\s+\$0x80,%eax\b"),
        ("out_port", (8, "dx"), "ee", r"\bout\s+%al,\(%dx\)"),
        ("out_port", (16, "dx"), "66ef", r"\bout\s+%ax,\(%dx\)"),
        ("out_port", (32, "dx"), "ef", r"\bout\s+%eax,\(%dx\)"),
        ("out_port", (8, 255), "e6ff", r"\bout\s+%al,\$0xff"),
        ("out_port", (16, 128), "66e780", r"\bout\s+%ax,\$0x80"),
        ("out_port", (32, 128), "e780", r"\bout\s+%eax,\$0x80"),
    )

    def test_18_literal_vectors_and_independent_binutils(self):
        with tempfile.TemporaryDirectory(prefix="hia-cr-io-") as root:
            for i, (name, args, expected, mnemonic) in enumerate(self.CASES):
                with self.subTest(name=name, args=args):
                    code = KernelCode()
                    getattr(code, name)(*args)
                    raw, reloc = code.finalize()
                    self.assertEqual(raw.hex(), expected)
                    self.assertEqual(reloc, [])
                    path = Path(root) / f"{i}.bin"
                    path.write_bytes(raw)
                    output = subprocess.run(
                        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(path)],
                        capture_output=True, text=True, check=True,
                        env={**os.environ, "LC_ALL": "C"}).stdout
                    self.assertRegex(output, mnemonic)
                    self.assertNotIn("(bad)", output)

    def test_cr0_cr2_cr4_all_16_gprs_and_implicit_operand_position(self):
        for name, index, opcode in (("read_cr0", 0, 0x20),
                                    ("write_cr0", 0, 0x22),
                                    ("read_cr2", 2, 0x20),
                                    ("read_cr4", 4, 0x20),
                                    ("write_cr4", 4, 0x22)):
            for regnum, register in enumerate(GPRS):
                with self.subTest(name=name, register=register):
                    code = KernelCode()
                    getattr(code, name)(register)
                    raw, reloc = code.finalize()
                    expected = (b"\x41" if regnum >= 8 else b"") + bytes(
                        (0x0f, opcode, 0xc0 | (index << 3) | (regnum & 7)))
                    self.assertEqual(raw, expected)
                    self.assertEqual(reloc, [])

    def test_all_reviewed_io_forms_and_immediate_boundaries(self):
        for method in ("in_port", "out_port"):
            for width in (8, 16, 32):
                for port in ("dx", 0, 1, 128, 255):
                    with self.subTest(method=method, width=width, port=port):
                        code = KernelCode()
                        getattr(code, method)(width, port)
                        raw, reloc = code.finalize()
                        self.assertEqual(len(raw), (1 if width == 16 else 0) +
                                         1 + (0 if port == "dx" else 1))
                        self.assertEqual(raw[:1], b"\x66" if width == 16 else raw[:1])
                        self.assertEqual(reloc, [])

    def test_invalid_register_width_port_and_internal_controls_are_atomic(self):
        for name in ("read_cr0", "write_cr0", "read_cr2", "read_cr4", "write_cr4"):
            for bad in ("cr0", "eax", "rip", "[rax]", None, True, 0, []):
                with self.subTest(method=name, bad=repr(bad)):
                    code = KernelCode()
                    code.mfence()
                    before = code.finalize()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, name)(bad)
                    self.assertEqual(code.finalize(), before)
        for name in ("in_port", "out_port"):
            for bad_width in (True, None, 0, 1, 24, 64, "8", 8.0):
                code = KernelCode()
                code.lfence()
                before = code.finalize()
                with self.assertRaises(MachineEncodingError):
                    getattr(code, name)(bad_width)
                self.assertEqual(code.finalize(), before)
            for bad_port in (True, -1, 256, 65535, 8.0, "al", "DX", "rax", None, []):
                code = KernelCode()
                code.sfence()
                before = code.finalize()
                with self.assertRaises(MachineEncodingError):
                    getattr(code, name)(8, bad_port)
                self.assertEqual(code.finalize(), before)
        for args in ((0x22, "rax", 2), (0x21, "rax", 3), (0x20, "rax", 8)):
            code = KernelCode()
            with self.assertRaises(MachineEncodingError):
                code._mov_control(*args)
            self.assertEqual(code.finalize(), (b"", []))

    def test_core_opcode_and_ordinary_machine_class_remain_closed(self):
        names = ("read_cr0", "write_cr0", "read_cr2", "read_cr4",
                 "write_cr4", "in_port", "out_port")
        for method in names:
            self.assertFalse(hasattr(Code, method))
            self.assertTrue(hasattr(KernelCode, method))
        for opcode in ("x86.read_cr0", "x86.read_cr2", "x86.read_cr4",
                       "x86.write_cr0", "x86.write_cr4", "x86.in", "x86.out"):
            with self.subTest(opcode=opcode):
                with self.assertRaises(OpcodeRejected):
                    opcode_spec(opcode, "hepta.hia.program.v8")


if __name__ == "__main__":
    unittest.main()
