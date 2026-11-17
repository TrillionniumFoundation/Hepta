"""Independent, non-executing x86-64 privileged opcode staging checks."""
import os
import subprocess
import tempfile
from pathlib import Path
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_machine_x64_kernel import KernelCode


class KernelPrivilegeExtendedVectors(unittest.TestCase):
    CASES = (
        ('lidt_rax', 'lidt', ('rax', 0), '0f019800000000', r'\blidt\s+0x0\(%rax\)'),
        ('lidt_rsp', 'lidt', ('rsp', 64), '0f019c2440000000', r'\blidt\s+0x40\(%rsp\)'),
        ('lidt_r12', 'lidt', ('r12', -16), '410f019c24f0ffffff', r'\blidt\s+-0x10\(%r12\)'),
        ('lidt_r13', 'lidt', ('r13', 4096), '410f019d00100000', r'\blidt\s+0x1000\(%r13\)'),
        ('ltr_rax', 'ltr', ('rax',), '0f00d8', r'\bltr\s+%eax'),
        ('ltr_r15', 'ltr', ('r15',), '410f00df', r'\bltr\s+%r15d'),
        ('iretq', 'iretq', (), '48cf', r'\biretq'),
    )

    def test_vectors_disassembled(self):
        for name, method, args, expected, pattern in self.CASES:
            with self.subTest(name=name):
                c = KernelCode()
                getattr(c, method)(*args)
                encoded, relocs = c.finalize()
                self.assertEqual(encoded.hex(), expected)
                self.assertEqual(relocs, [])
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / 'code.bin'
                    path.write_bytes(encoded)
                    result = subprocess.run(
                        ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', str(path)],
                        text=True, capture_output=True, check=True,
                        env={**os.environ, 'LC_ALL': 'C'})
                    self.assertRegex(result.stdout, pattern)

    def test_invalid_operands_preserve_bytes(self):
        for method in ('lidt', 'ltr'):
            for bad in ('eax', 'rip', 'cr3', '[rax]', True, 1, None):
                with self.subTest(method=method, bad=repr(bad)):
                    code = KernelCode()
                    code.iretq()
                    before = code.finalize()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, method)(bad)
                    self.assertEqual(code.finalize(), before)
        for bad in (True, None, 1.0, 1 << 31, -(1 << 31) - 1):
            code = KernelCode()
            with self.assertRaises(MachineEncodingError):
                code.lidt('rax', bad)
            self.assertEqual(code.finalize(), (b'', []))

    def test_unmodified_unprivileged_code(self):
        for name in ('lidt', 'ltr', 'iretq'):
            self.assertFalse(hasattr(Code, name))
            self.assertTrue(hasattr(KernelCode, name))

    def test_all_gprs_instruction_shapes(self):
        regs = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
        for reg in regs:
            code = KernelCode()
            code.lidt(reg, -1)
            image, relocs = code.finalize()
            self.assertEqual(image[-4:], b'\xff' * 4)
            self.assertEqual(relocs, [])
            code = KernelCode()
            code.ltr(reg)
            image, relocs = code.finalize()
            self.assertIn(len(image), (3, 4))
            self.assertEqual(relocs, [])


if __name__ == '__main__':
    unittest.main()
