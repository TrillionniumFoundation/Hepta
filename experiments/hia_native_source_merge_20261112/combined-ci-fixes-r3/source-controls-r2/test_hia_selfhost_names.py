"""General function spelling never substitutes for Core identity or semantics."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_names import (cases, independent_reference, name_hash,
    refusals, renamed_source, value_cases, value_refusals, renamed_values, block_cases, block_refusals, renamed_blocks,
    entry_order_cases, entry_order_refusals, reordered_blocks, nonfirst_entry_source)


class SelfhostFunctionNameTests(unittest.TestCase):
    def test_all_case_compilation_originals_survive_later_same_name_calls(self):
        # Exercise the real qualification driver with inert file-writing
        # transports. This verifies evidence custody, not native semantics.
        import json
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        from tools import qualify_hia_selfhost as native
        from tools import qualify_hia_selfhost_cli as cli
        from tools.hia_selfhost_names import qualify
        rows=cases()+value_cases()+block_cases()+entry_order_cases()
        self.assertEqual(len(rows),106)
        self.assertEqual(len({row['program'] for row in rows}),52)
        executions={'original-'+row['id']+'-'+kind:row for row in rows for kind in ('flat','elf')}
        written={}
        def original(directory,label,stage):
            value={'case':label,'stage':stage}
            raw=(json.dumps(value,sort_keys=True)+'\n').encode()
            for suffix in ('.request.json','.input.bin','.output.bin','.receipt.json'):
                path=directory/(label+suffix)
                with path.open('xb') as stream:stream.write(raw)
                written[path]=raw
            return value
        def compile_stage(directory,label,compiler,source,output_extension='.image.bin'):
            receipt=original(directory,label,'compile')
            image=directory/(label+output_extension)
            image.write_bytes(Path(compiler).read_bytes())
            return image,receipt
        def invoke(directory,label,image,source,**kwargs):
            original(directory,label,'invoke')
            row=executions[label]
            return {'status':'returned','abi_status':0,'core_u32':row['expected_result'],
                    'source_unchanged':True},bytes.fromhex(row['expected_hex'])
        def link(directory,label,tool,arguments):
            original(directory,label,'link')
            Path(arguments[-1]).write_bytes(b'inert shared image')
            return {'returncode':0}
        def execute(directory,label,image,source):
            original(directory,label,'execute')
            return {'status':'OWNED_PROCESS_COMPLETED','returncode':0,
                    'cleanup':{'complete':True},'stderr_hex':''},image.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            compiler=directory/'compiler.bin'
            compiler.write_bytes(b'inert compiler image, not executable')
            reference={'cases':rows,'refusals':[],
                       'alpha_compiler':{'original':{'source':native.SOURCE.read_text()}}}
            checks={}
            with patch.object(native,'compile_stage',side_effect=compile_stage), \
                    patch.object(native,'invoke',side_effect=invoke), \
                    patch.object(native,'observe_native_tool',side_effect=link), \
                    patch.object(native,'inspect_selfhost_object',return_value={}), \
                    patch.object(cli,'inspect_executable',return_value={}), \
                    patch.object(cli,'execute',side_effect=execute):
                observations=qualify(directory,compiler,checks,reference,'original')
            self.assertTrue(checks and all(checks.values()))
            self.assertEqual(len(executions),212)
            compile_records=[row for row in observations if row.get('stage')=='compile']
            self.assertEqual(len(compile_records),109)
            self.assertTrue(all(path.read_bytes()==raw for path,raw in written.items()))

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
