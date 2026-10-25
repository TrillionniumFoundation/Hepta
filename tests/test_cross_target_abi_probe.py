"""Actual Clang cross-target *object* ABI evidence; never assert execution."""
from __future__ import annotations

import shutil
import unittest

from tools.cross_target_abi_probe import _object_matches, run_probe, TARGET_MACHINE


@unittest.skipUnless(shutil.which('clang'), 'Clang required for target object compilation')
class CrossTargetABITests(unittest.TestCase):
    def test_actual_cross_target_object_and_negative_assertions(self):
        report = run_probe()
        self.assertEqual(report['status'], 'passed')
        self.assertEqual({x['target'] for x in report['cases']}, set(TARGET_MACHINE))
        for case in report['cases']:
            self.assertEqual(case['status'], 'passed')
            self.assertTrue(case['layout_static_asserts_compiled'])
            self.assertTrue(case['deliberate_layout_fault_rejected'])
            self.assertFalse(case['executed_on_target'])
            self.assertFalse(case['independent_foreign_compiler_verified'])
        self.assertFalse(report['claims']['hepta_abi_equivalence_verified'])
        self.assertFalse(report['claims']['whole_p2_gate_closed'])

    def test_wrong_machine_rejected(self):
        elf_x64 = bytearray(24)
        elf_x64[:5] = b'\x7fELF\x02'
        elf_x64[5] = 1
        elf_x64[18:20] = (62).to_bytes(2, 'little')
        self.assertTrue(_object_matches(elf_x64, 'elf_x86_64'))
        self.assertFalse(_object_matches(elf_x64, 'elf_aarch64'))
        self.assertFalse(_object_matches(elf_x64, 'coff_x86_64'))
        self.assertFalse(_object_matches(b'', 'elf_x86_64'))


if __name__ == '__main__':
    unittest.main()
