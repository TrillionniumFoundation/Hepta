"""Staged SYSCALL/SYSRETQ and SMAP/HLT x86 encodings; never execute on host.

Literal instruction bytes are compared to an independent GNU objdump decoder.
This is a KernelCode-only byte-encoder extension, not the HIA v8 verifier,
selfhost native emitter, valid CPU state or a Linux syscall implementation.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code
from hepta.hia_machine_x64_kernel import KernelCode
from hepta.hia_opcodes import OpcodeRejected, opcode_spec


class KernelSyscallSmapStaging(unittest.TestCase):
    CASES = (
        ("syscall", "0f05", r"\bsyscall\b"),
        ("sysretq", "480f07", r"\bsysretq\b"),
        ("stac", "0f01cb", r"\bstac\b"),
        ("clac", "0f01ca", r"\bclac\b"),
        ("hlt", "f4", r"\bhlt\b"),
    )

    def test_literal_bytes_and_empty_relocations(self):
        for method, expected, _ in self.CASES:
            with self.subTest(method=method):
                code = KernelCode()
                getattr(code, method)()
                image, relocations = code.finalize()
                self.assertEqual(image, bytes.fromhex(expected))
                self.assertEqual(relocations, [])
                self.assertEqual(code.finalize(), (image, []))

    @unittest.skipUnless(shutil.which("objdump"), "independent GNU objdump required")
    def test_disassembly_exact_mnemonics_and_instruction_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="hia-kernel-syscall-") as tmp:
            for method, expected, mnemonic in self.CASES:
                with self.subTest(method=method):
                    code = KernelCode()
                    getattr(code, method)()
                    blob = Path(tmp) / (method + ".bin")
                    blob.write_bytes(code.finalize()[0])
                    self.assertEqual(blob.read_bytes(), bytes.fromhex(expected))
                    decoded = subprocess.run(
                        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                         str(blob)], check=True, capture_output=True,
                        text=True, env={**os.environ, "LC_ALL": "C"}).stdout
                    ins = [line for line in decoded.splitlines()
                           if re.match(r"\s*[0-9a-f]+:", line)]
                    self.assertEqual(len(ins), 1, decoded)
                    self.assertRegex(decoded, mnemonic)
                    self.assertNotIn("(bad)", decoded)

    def test_composition_and_non_partial_refusal(self):
        code = KernelCode()
        code.stac()
        code.clac()
        code.syscall()
        code.sysretq()
        code.hlt()
        expected = bytes.fromhex("0f01cb0f01ca0f05480f07f4")
        self.assertEqual(code.finalize(), (expected, []))
        for method, _, _ in self.CASES:
            with self.subTest(method=method):
                before = code.finalize()
                with self.assertRaises(TypeError):
                    getattr(code, method)(None)
                self.assertEqual(code.finalize(), before)

    def test_unprivileged_code_and_core_opcodes_remain_closed(self):
        for method, _, _ in self.CASES:
            with self.subTest(method=method):
                self.assertFalse(hasattr(Code, method))
                self.assertTrue(hasattr(KernelCode, method))
                with self.assertRaises(OpcodeRejected):
                    opcode_spec("x86." + method, "hepta.hia.program.v8")


if __name__ == "__main__":
    unittest.main()
