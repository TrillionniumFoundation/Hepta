"""Independent x86-64 MSR/interrupt instruction encoding, not an HIA backend.

The experimental KernelCode helper emits literal architectural encodings only.
Never execute privileged instructions in the host test runner. Feature/authority,
MSR policies and interrupt atomicity require a future typed kernel HIA profile.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code
from hepta.hia_machine_x64_kernel import KernelCode
from hepta.hia_opcodes import OpcodeRejected, opcode_spec


class KernelMsrInterruptStaging(unittest.TestCase):
    CASES = (
        ("cli", "fa", r"\bcli\b"),
        ("sti", "fb", r"\bsti\b"),
        ("rdmsr", "0f32", r"\brdmsr\b"),
        ("wrmsr", "0f30", r"\bwrmsr\b"),
        ("swapgs", "0f01f8", r"\bswapgs\b"),
        ("cpuid", "0fa2", r"\bcpuid\b"),
    )

    def test_exact_bytes_and_no_relocations(self):
        for method, expected, _ in self.CASES:
            with self.subTest(method=method):
                code = KernelCode()
                getattr(code, method)()
                actual, relocations = code.finalize()
                self.assertEqual(actual.hex(), expected)
                self.assertEqual(relocations, [])
                self.assertEqual(code.finalize(), (actual, []))

    @unittest.skipUnless(shutil.which("objdump"), "GNU objdump required")
    def test_independent_disassembly(self):
        with tempfile.TemporaryDirectory(prefix="hia-kernel-msr-") as tmp:
            for method, expected, mnemonic in self.CASES:
                with self.subTest(method=method):
                    code = KernelCode()
                    getattr(code, method)()
                    path = Path(tmp) / (method + ".bin")
                    path.write_bytes(code.finalize()[0])
                    self.assertEqual(path.read_bytes(), bytes.fromhex(expected))
                    decoded = subprocess.run(
                        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                         str(path)],
                        check=True, capture_output=True, text=True,
                        env={**os.environ, "LC_ALL": "C"}).stdout
                    self.assertRegex(decoded, mnemonic)
                    self.assertNotIn("(bad)", decoded)

    def test_composition_preserves_instruction_boundaries(self):
        code = KernelCode()
        code.cli()
        code.rdmsr()
        code.cpuid()
        code.wrmsr()
        code.swapgs()
        code.sti()
        self.assertEqual(code.finalize(), (bytes.fromhex(
            "fa0f320fa20f300f01f8fb"), []))

    def test_ordinary_code_and_v8_opcodes_remain_closed(self):
        for method, _, _ in self.CASES:
            with self.subTest(method=method):
                self.assertFalse(hasattr(Code, method))
                self.assertTrue(hasattr(KernelCode, method))
                with self.assertRaises(OpcodeRejected):
                    opcode_spec("x86." + method, "hepta.hia.program.v8")


if __name__ == "__main__":
    unittest.main()
