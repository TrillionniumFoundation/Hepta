"""General function spelling never substitutes for Core identity or semantics."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_names import (cases, independent_reference, name_hash,
    refusals, renamed_source)


class SelfhostFunctionNameTests(unittest.TestCase):
    def test_equal_hash_names_have_distinct_runtime_functions_and_results(self):
        self.assertEqual(name_hash('aaB'), name_hash('aba'))
        rows = [r for r in cases() if r['program'] == 'equal-hash-distinct-functions']
        self.assertEqual(len(rows), 3)
        for row in rows:
            program = assemble_program(row['source'].encode()).as_dict()
            self.assertEqual([f['name'] for f in program['functions']], ['entry', 'aaB', 'aba'])
            self.assertEqual(row['expected_hex'], bytes([(4 * bytes.fromhex(row['source_hex'])[0] + 124) & 255]).hex())

    def test_independent_vm_inputs_preserve_resource_and_byte_results(self):
        report = independent_reference()
        self.assertTrue(report['before_B0'])
        self.assertFalse(report['all_input_correctness_proved'])
        self.assertFalse(report['whole_stack_rewrite_complete'])
        self.assertEqual(len(report['cases']), 34)
        self.assertEqual(len({r['program'] for r in report['cases']}), 12)
        for row in report['cases']:
            self.assertEqual(row['reference']['values'], [row['expected_result']])
            self.assertEqual(row['reference']['resources']['live_owners'], 0)
            self.assertEqual(row['reference']['resources']['live_local_loans'], 0)
        maximum = next(r for r in report['cases'] if r['program'] == 'named-128-functions')
        self.assertEqual(len(assemble_program(maximum['source'].encode()).as_dict()['functions']), 128)

    def test_core_reserved_duplicate_long_and_invalid_names_are_not_profile_aliases(self):
        for row in refusals():
            with self.subTest(case=row['id']), self.assertRaises(HIAProgramRejected):
                assemble_program(row['source'].encode())

    def test_whole_compiler_alpha_renaming_preserves_every_call_target(self):
        from tools.generate_hia_selfhost import document
        from tools.qualify_hia_selfhost import SOURCE, mutate_compiler
        _, names = document()
        mapping = {number: name for name, number in names.items()}
        for canonical in (SOURCE.read_bytes(), mutate_compiler(SOURCE.read_bytes())):
            renamed = renamed_source(canonical, mapping)
            original = assemble_program(canonical)
            restored = renamed_source(renamed, names)
            self.assertNotEqual(renamed, canonical)
            self.assertEqual(assemble_program(restored).sha256, original.sha256)
            self.assertEqual(assemble_program(renamed).as_dict()['functions'][0]['name'], 'compile')


if __name__ == '__main__':
    unittest.main()
