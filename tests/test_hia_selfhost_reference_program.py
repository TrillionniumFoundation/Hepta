"""Same-case Core handoff retains every ordinary VM observation and recheck."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from hepta import hia_agent_assembly as assembly
from hepta.hia_program import VerifiedProgram, verify_program
from tools.hia_selfhost_owned_elf_cases import cases, reference


class SelfhostReferenceProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = {case['id']: case for case in cases()}

    def test_return_trap_and_original_budget_reports_are_unchanged(self):
        for label in ('new-8', 'new-allocation-trap-1',
                      'try-failure-4611686018427387904'):
            with self.subTest(case=label):
                case = self.inputs[label]
                expected = reference(case)
                with patch.object(assembly, 'assemble_program',
                                  wraps=assembly.assemble_program) as assemble:
                    checked, observed = reference(case, include_program=True)
                self.assertEqual(assemble.call_count, 1)
                self.assertEqual(observed, expected)
                self.assertIs(type(checked), VerifiedProgram)
                independently_checked = assembly.assemble_program(case['source'])
                self.assertEqual(checked.canonical_bytes,
                                 independently_checked.canonical_bytes)
                self.assertEqual(checked.input_sha256,
                                 independently_checked.input_sha256)
                self.assertEqual(verify_program(checked), independently_checked)
                with self.assertRaises(FrozenInstanceError):
                    checked.canonical_bytes = b'{}'

    def test_repeated_and_changed_cases_execute_fresh_assembly_and_vm(self):
        small, large = self.inputs['new-1'], self.inputs['new-8']
        with patch.object(assembly, 'assemble_program',
                          wraps=assembly.assemble_program) as assemble:
            first, first_report = reference(small, include_program=True)
            repeated, repeated_report = reference(small, include_program=True)
            changed, changed_report = reference(large, include_program=True)
        self.assertEqual(assemble.call_count, 3)
        self.assertIsNot(first, repeated)
        self.assertIsNot(first_report, repeated_report)
        self.assertEqual(first_report, repeated_report)
        self.assertNotEqual(first.canonical_bytes, changed.canonical_bytes)
        self.assertEqual(first_report['result'], 1)
        self.assertEqual(changed_report['result'], 8)
        self.assertNotEqual(first_report['external_output_hex'],
                            changed_report['external_output_hex'])

    def test_changed_invalid_source_never_reuses_prior_admission(self):
        valid = self.inputs['new-8']
        reference(valid, include_program=True)
        invalid = {**valid, 'source': valid['source'].replace(
            '  ret(', '  unknown_instruction(', 1)}
        with self.assertRaises(assembly.HIAAssemblyRejected):
            reference(invalid, include_program=True)


if __name__ == '__main__':
    unittest.main()
