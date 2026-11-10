"""General function spelling never substitutes for Core identity or semantics."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_names import (cases, independent_reference, name_hash,
    refusals, renamed_source, value_cases, value_refusals, renamed_values, block_cases, block_refusals, renamed_blocks)


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
        self.assertEqual(len(report['cases']), 86)
        self.assertEqual(len({r['program'] for r in report['cases']}), 36)
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

    def test_ssa_contextual_names_full_intern_table_and_capacity_refusal_stay_distinct(self):
        rows = value_cases()
        self.assertEqual(len(rows), 28)
        self.assertEqual(len({r['program'] for r in rows}), 10)
        maximum = assemble_program(rows[-1]['source']).as_dict()['functions'][0]
        self.assertEqual(sum(len(b['params']) + sum(len(o['out']) for o in b['ops'])
                             for b in maximum['blocks']), 2048)
        for row in value_refusals():
            with self.subTest(case=row['id']):
                if row['general_core_expected'] == 'accepted':
                    assemble_program(row['source'])
                else:
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(row['source'])
        from tools.generate_hia_selfhost import document
        doc, _ = document()
        source = __import__('hepta.hia_agent_assembly', fromlist=['render_assembly']).render_assembly(doc).encode()
        changed = renamed_values(source)
        self.assertNotEqual(changed, source)
        checked = assemble_program(changed).as_dict()
        self.assertEqual(sum(len(f['blocks']) for f in checked['functions']),
                         sum(len(f['blocks']) for f in doc['functions']))

    def test_block_names_preserve_collisions_forward_cfg_full_tables_and_entry_boundary(self):
        rows = block_cases()
        self.assertEqual(len(rows), 24)
        self.assertEqual(len({r['program'] for r in rows}), 14)
        counts = [sum(len(fn['blocks']) for fn in assemble_program(r['source']).as_dict()['functions'])
                  for r in rows]
        self.assertIn(256, counts)
        self.assertIn(1536, counts)
        for row in block_refusals():
            with self.subTest(case=row['id']):
                if row['general_core_expected'] == 'accepted':
                    assemble_program(row['source'])
                else:
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(row['source'])
        changed = renamed_blocks(rows[0]['source'].encode())
        doc = assemble_program(changed).as_dict()
        for fn in doc['functions']:
            self.assertEqual(fn['entry'], fn['blocks'][0]['id'])


if __name__ == '__main__':
    unittest.main()
