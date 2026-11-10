"""General function spelling never substitutes for Core identity or semantics."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_names import (cases, independent_reference, name_hash,
    refusals, renamed_source, value_cases, value_refusals, renamed_values, block_cases, block_refusals, renamed_blocks,
    entry_order_cases, entry_order_refusals, reordered_blocks, nonfirst_entry_source,
    renamed_compiler_source)


class SelfhostComposedNameTests(unittest.TestCase):
    @staticmethod
    def serial(source, mapping):
        return renamed_blocks(renamed_values(renamed_source(source, mapping)))

    def test_composition_preserves_exact_serial_text_for_names_loans_and_cfgs(self):
        wanted = {'equal-hash-distinct-functions-0', 'named-loan-mut-cfg-0',
            'named-loan-mut-tail-0', 'named-128-functions-0', 'ssa-spellings-4-00',
            'ssa-intern-table-full-2048', 'named-reverse-1536-six-functions',
            'named-late-matching-parent-join', 'entry-last-loan-read-tail-0',
            'entry-last-parallel-scalar-tail'}
        rows = [r for r in [*cases(), *value_cases(), *block_cases(), *entry_order_cases()]
                if r['id'] in wanted]
        self.assertEqual({r['id'] for r in rows}, wanted)
        for row in rows:
            mapping = {fn['name']: 'function_' + str(i)
                for i, fn in enumerate(assemble_program(row['source']).as_dict()['functions'])}
            with self.subTest(case=row['id']):
                self.assertEqual(renamed_compiler_source(row['source'], mapping),
                                 self.serial(row['source'], mapping))

    def test_every_intermediate_still_rejects_schema_cfg_and_loan_corruption(self):
        from unittest.mock import patch
        import tools.hia_selfhost_names as names
        source = next(r['source'] for r in cases() if r['id'] == 'named-loan-mut-cfg-0')
        mapping = {'lease_0': 'entry', 'lease_1': 'helper'}
        mutations = (
            ('_rename_functions', '_rename_values', 'E_HIA_SCHEMA',
             lambda doc: doc.update(schema='unsupported')),
            ('_rename_values', '_rename_blocks', 'E_HIA_CFG',
             lambda doc: doc['functions'][1]['blocks'][0]['term'].update(target='missing')),
            ('_rename_values', '_rename_blocks', 'E_HIA_LOAN',
             lambda doc: doc['functions'][1].update(return_loans=[None])),
        )
        for stage, later, code, corrupt in mutations:
            original = getattr(names, stage)
            def transformed(doc, *args):
                original(doc, *args)
                corrupt(doc)
            with self.subTest(stage=stage, code=code), \
                    patch.object(names, stage, side_effect=transformed), \
                    patch.object(names, later) as never_reached:
                with self.assertRaises(HIAProgramRejected) as refused:
                    renamed_compiler_source(source, mapping)
                self.assertEqual(refused.exception.code, code)
                never_reached.assert_not_called()

    def test_intermediate_text_limit_cannot_be_hidden_by_later_shorter_ssa_names(self):
        from unittest.mock import patch
        import hepta.hia_agent_assembly as assembly
        value = 'x' * 128
        source = ('hia-asm.v1 hepta.hia.program.v8 unit\n'
            + 'fn f0(' + value + ':u32) -> (u32) effects() entry(b0)\n'
            + 'block b0(' + value + ':u32)\n  ret(' + value + ')\nend\n')
        mapping = {'f0': 'f' * 128}
        intermediate = renamed_source(source, mapping)
        final = self.serial(source, mapping)
        line_limit = max(len(line) for text in (source.encode(), final) for line in text.split(b'\n'))
        self.assertGreater(max(map(len, intermediate.split(b'\n'))), line_limit)
        with patch.object(assembly, 'MAX_LINE_BYTES', line_limit):
            # Both endpoints fit. Only the first intermediate representation
            # exceeds this budget, so skipping its round trip would admit it.
            assemble_program(source)
            assemble_program(final)
            errors = []
            for rename in (self.serial, renamed_compiler_source):
                with self.assertRaises(assembly.HIAAssemblyRejected) as refused:
                    rename(source, mapping)
                errors.append((refused.exception.code, str(refused.exception), refused.exception.line))
            self.assertEqual(errors[0], errors[1])
            self.assertEqual(errors[1][0], 'E_HIA_ASSEMBLY_LIMIT')

    def test_invalid_input_still_has_exact_schema_cfg_and_loan_refusals(self):
        for row in entry_order_refusals():
            errors = []
            for rename in (self.serial, renamed_compiler_source):
                with self.subTest(case=row['id'], rename=rename.__name__), \
                        self.assertRaises(HIAProgramRejected) as refused:
                    rename(row['source'], {})
                errors.append((refused.exception.code, str(refused.exception)))
            self.assertEqual(errors[0], errors[1])


class SelfhostNameSeedTests(unittest.TestCase):
    def test_refusal_sources_keep_preoptimization_bytes_without_unrelated_fixtures(self):
        from hashlib import sha256
        import json
        from unittest.mock import patch
        import tools.hia_selfhost_names as names
        # Canonical digests of the complete existing negative fixture records,
        # captured before extracting their seeds, including source text/order.
        expected = (
            (value_refusals, 10, '81618ca2cc4edb95ce7c597d3477e49eb6acc05fbfecd59667bc949bbbcc6160'),
            (block_refusals, 9, '6740abddc19e0c970251d6cf04cf3b312edfb431095f6a1b376eed38742db828'),
        )
        with patch.object(names, 'cases', side_effect=AssertionError('unrelated function fixtures')), \
                patch.object(names, 'value_cases', side_effect=AssertionError('unrelated SSA fixtures')), \
                patch.object(names, 'block_cases', side_effect=AssertionError('unrelated CFG fixtures')):
            for builder, count, digest in expected:
                with self.subTest(builder=builder.__name__):
                    rows = builder()
                    self.assertEqual(len(rows), count)
                    self.assertEqual(sha256(json.dumps(rows, sort_keys=True,
                        separators=(',', ':')).encode()).hexdigest(), digest)
                    rows[0]['source'] = 'caller mutation'
                    self.assertEqual(sha256(json.dumps(builder(), sort_keys=True,
                        separators=(',', ':')).encode()).hexdigest(), digest)


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
        self.assertEqual(len(report['cases']), 106)
        self.assertEqual(len({r['program'] for r in report['cases']}), 52)
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

    def test_nonfirst_entries_keep_formals_tail_origins_and_complete_block_boundaries(self):
        from hashlib import sha256
        rows = entry_order_cases()
        self.assertEqual(len(rows), 20)
        self.assertEqual(len({r['program'] for r in rows}), 16)
        retained = rows[0]
        self.assertEqual(retained['source'], nonfirst_entry_source())
        self.assertTrue(retained['retained_former_profile_refusal'])
        # An independently retained v27 negative-control source is now positive.
        self.assertEqual(sha256(retained['source'].encode()).hexdigest(),
                         '84e2246c1c442d37c38ad441a4d8603de6ed817bcbe2f2fdc2540ff3a5828abd')
        maximum = []
        for row in rows:
            doc = assemble_program(row['source']).as_dict()
            for fn in doc['functions']:
                entry = next(b for b in fn['blocks'] if b['id'] == fn['entry'])
                at = len(fn['blocks']) // 2 if row['id'].startswith('entry-middle-') else len(fn['blocks']) - 1
                self.assertEqual(fn['entry'], fn['blocks'][at]['id'])
                self.assertEqual(fn['params'], entry['params'])
                maximum.append(len(fn['blocks']))
        self.assertIn(256, maximum)
        for row in entry_order_refusals():
            with self.subTest(row=row['id']):
                with self.assertRaises(HIAProgramRejected) as refused:
                    assemble_program(row['source'])
                expected = 'E_HIA_LOAN' if row['id'].endswith(('return-origin', 'join-roots')) else 'E_HIA_CFG'
                self.assertEqual(refused.exception.code, expected)
        from tools.generate_hia_selfhost import document
        from hepta.hia_agent_assembly import render_assembly
        doc, _ = document()
        changed = assemble_program(reordered_blocks(render_assembly(doc))).as_dict()
        for before, after in zip(doc['functions'], changed['functions'], strict=True):
            self.assertEqual(before['entry'], after['entry'])
            self.assertEqual({b['id']: b for b in before['blocks']}, {b['id']: b for b in after['blocks']})


if __name__ == '__main__':
    unittest.main()
