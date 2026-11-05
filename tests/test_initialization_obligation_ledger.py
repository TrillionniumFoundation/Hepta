"""Read-only obligation transport controls; no semantic proof or elision authority."""
from copy import deepcopy
import json
import re
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from tests.test_hia_initialization import initialized_program
from tests.test_hia_program import b, f, i, ret
from tests import test_initialization_frontier_checker as fixtures
from tools import extract_initialization_obligations as ledger


class InitializationObligationLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.InitializationFrontierCheckerTests.setUpClass()
        cls.cores = {name: arms['deferred'] for name, arms in
                     fixtures.InitializationFrontierCheckerTests.cores.items()}

    def assert_denied(self, report):
        self.assertEqual(report['authority'], 'DENY_ALL')
        for key, value in ledger.DENY.items():
            self.assertEqual(report[key], value)
            if isinstance(value, bool):
                self.assertIs(report[key], False)
        self.assertIs(report['actual_core_bridge_proved'], False)

    def extract(self, program):
        report = ledger.extract_obligations(program)
        self.assertEqual(report['status'], 'extracted', report)
        self.assert_denied(report)
        self.assertIs(report['model_replayed'], False)
        self.assertIs(report['output_equivalence_proved'], False)
        return report

    def mismatch(self, program, proposed):
        result = ledger.check_obligation_transport(program, proposed)
        self.assertEqual(result['status'], 'rejected', result)
        self.assert_denied(result)

    def test_actual_deferred_hashes_and_all_obligations_remain_unproved(self):
        expected = {'environment_phi', 'dynamic_owner', 'allocation_extent',
                    'finite_integer', 'direct_body_seed', 'store_write_frame',
                    'value_schedule', 'normal_completion', 'empty_extent',
                    'trace_edge_cut', 'post_completion_frame', 'observational_boundary'}
        for name, program in self.cores.items():
            with self.subTest(workload=name):
                report = self.extract(program)
                self.assertEqual(report['core_sha256'], fixtures.DEFERRED_HASHES[name])
                for function in report['functions']:
                    self.assertEqual({o['id'] for o in function['obligations']}, expected)
                    self.assertEqual(len(function['obligations']), len(expected))
                    self.assertTrue(all(o['status'] == 'unproved' for o in function['obligations']))

    def test_model_references_and_source_closure_are_existing_not_new_proofs(self):
        report = self.extract(initialized_program())
        paths = report['source_sha256']
        for path in ('tools/extract_initialization_obligations.py',
                     'tools/check_initialization_frontiers.py', 'hepta/hia_program.py',
                     'hepta/hia_program_runtime.py', 'formal/HiaInitializationPrefix.lean',
                     'formal/toolchain-lock.json', 'formal/proof-dependencies.txt',
                     'tools/qualify_hia_initialization_prefix.py', 'tools/qualify_hia_selected_formal.py'):
            self.assertIn(path, paths)
        source = (ledger.ROOT / 'formal/HiaInitializationPrefix.lean').read_text()
        declarations = set(re.findall(r'(?:def|abbrev|theorem)\s+(\w+)', source))
        for obligation in report['functions'][0]['obligations']:
            for symbol in obligation['candidate_model_symbols']:
                self.assertTrue(symbol.startswith('HiaInitializationPrefix.'))
                self.assertIn(symbol.split('.')[-1], declarations)
            self.assertEqual(obligation['status'], 'unproved')

    def test_every_ordered_phi_binding_matches_actual_core(self):
        for program in self.cores.values():
            report = self.extract(program)
            for actual, row in zip(verify_program(program).as_dict()['functions'], report['functions']):
                mapping = {block['id']: block for block in actual['blocks']}
                expected = []
                for block in actual['blocks']:
                    term = block['term']
                    arms = [('jump', term)] if term['op'] == 'jump' else (
                        [('then', term['then']), ('else', term['else'])] if term['op'] == 'branch' else [])
                    for arm, edge in arms:
                        expected.append({'source': block['id'], 'arm': arm, 'target': edge['target'],
                            'bindings': [{'slot': slot, 'parameter': param, 'operand': edge['args'][slot]}
                                         for slot, param in enumerate(mapping[edge['target']]['params'])]})
                self.assertEqual(row['edges'], expected)
                self.assertTrue(any(e['source'] == 'dg_guard_0' for e in row['edges']))

    def test_operations_definitions_and_value_dependencies_are_actual(self):
        for program in self.cores.values():
            report = self.extract(program)
            for actual, row in zip(verify_program(program).as_dict()['functions'], report['functions']):
                self.assertEqual(row['exact_function'], actual)
                operations, definitions = [], []
                for block in actual['blocks']:
                    definitions.extend({'value': p['name'], 'type': p['type'], 'block': block['id'],
                                        'parameter_slot': slot} for slot, p in enumerate(block['params']))
                    for ordinal, op in enumerate(block['ops']):
                        operations.append({'block': block['id'], 'ordinal': ordinal, 'operation': op})
                        definitions.extend({'value': out['name'], 'type': out['type'], 'block': block['id'],
                            'ordinal': ordinal, 'output_slot': slot, 'direct_dependencies': op['args']}
                            for slot, out in enumerate(op['out']))
                self.assertEqual(row['operations'], operations)
                self.assertEqual(row['definitions'], definitions)
                self.assertEqual(row['allocations'], [op for op in operations
                    if op['operation']['op'] in {'buffer.new', 'buffer.try_new'}])
                self.assertEqual([{k: load[k] for k in ('block', 'ordinal', 'operation')}
                                  for load in row['loads']],
                                 [op for op in operations if op['operation']['op'] == 'buffer.load'])
                self.assertTrue(row['loads'])
                for load in row['loads']:
                    self.assertTrue(load['candidate_cuts'])
                    for cut in load['candidate_cuts']:
                        self.assertEqual(cut['load_root_connection'], 'unproved')
                        self.assertIs(cut['load_block_reachable'], False)

    def test_parallel_arms_are_distinct_and_each_is_authenticated(self):
        program = fixtures.duplicate_header_ingress()
        report = self.extract(program)
        edges = [e for e in report['functions'][0]['edges'] if e['source'] == 'entry']
        self.assertEqual([e['arm'] for e in edges], ['then', 'else'])
        self.assertEqual(edges[0]['target'], edges[1]['target'])
        self.assertEqual(edges[0]['bindings'], edges[1]['bindings'])
        for arm in ('then', 'else'):
            mutant = deepcopy(report)
            edge = next(e for e in mutant['functions'][0]['edges'] if e['source'] == 'entry' and e['arm'] == arm)
            edge['bindings'][1]['operand'] = 'probe'
            self.mismatch(program, mutant)
        for kwargs in ({'bad_extent': True}, {'bad_seed': True}):
            self.assertEqual(ledger.extract_obligations(fixtures.duplicate_header_ingress(**kwargs))['status'], 'rejected')

    def test_alpha_rename_and_block_shuffle_extract_but_old_transport_is_stale(self):
        for program in self.cores.values():
            report = self.extract(program)
            renamed = fixtures.alpha_rename_and_shuffle(program)
            changed = self.extract(renamed)
            self.assertNotEqual(changed['core_sha256'], report['core_sha256'])
            self.mismatch(renamed, report)
            self.assertEqual(ledger.check_obligation_transport(renamed, changed)['status'], 'matched')

    def test_exact_json_roundtrip_matches_without_granting_authority(self):
        program = self.cores['linear']
        report = self.extract(program)
        result = ledger.check_obligation_transport(program, json.loads(json.dumps(report)))
        self.assertEqual(result['status'], 'matched')
        self.assert_denied(result)

    def test_mutated_transport_fields_reject(self):
        program = self.cores['linear']
        report = self.extract(program)
        paths = [('schema',), ('core_sha256',), ('source_sha256',),
                 ('functions', 0, 'exact_function'), ('functions', 0, 'definitions'),
                 ('functions', 0, 'operations'), ('functions', 0, 'allocations'),
                 ('functions', 0, 'loads'), ('functions', 0, 'structure_certificates'),
                 ('functions', 0, 'edges'), ('functions', 0, 'obligations')]
        for path in paths:
            with self.subTest(path=path):
                mutant = deepcopy(report)
                target = mutant
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = None
                self.mismatch(program, mutant)
        mutant = deepcopy(report)
        mutant['invented_proof'] = True
        self.mismatch(program, mutant)

    def test_proof_and_authority_flags_cannot_be_promoted(self):
        program = self.cores['linear']
        report = self.extract(program)
        for field in ('actual_core_bridge_proved', 'model_replayed', 'output_equivalence_proved', *ledger.DENY):
            with self.subTest(field=field):
                mutant = deepcopy(report)
                mutant[field] = True if field != 'authority' else 'ALLOW_ALL'
                self.mismatch(program, mutant)
        mutant = deepcopy(report)
        mutant['functions'][0]['obligations'][0]['status'] = 'proved'
        self.mismatch(program, mutant)

    def test_bool_integer_substitutions_are_not_equal_transport(self):
        program = self.cores['linear']
        report = self.extract(program)
        mutant = deepcopy(report)
        mutant['actual_core_bridge_proved'] = 0
        self.assertEqual(mutant, report)  # Python equality is insufficient.
        self.mismatch(program, mutant)
        mutant = deepcopy(report)
        definition = next(d for d in mutant['functions'][0]['definitions'] if d.get('parameter_slot') == 0)
        definition['parameter_slot'] = False
        self.assertEqual(mutant, report)
        self.mismatch(program, mutant)

    def test_repeated_dynamic_root_and_unsupported_call_fail_closed(self):
        repeated = initialized_program()
        fixtures.blocks(repeated)['body']['ops'][:0] = [
            i('buffer.new', ['bn'], [('dynamic_owner', 'buffer')]), i('owner.drop', ['dynamic_owner'])]
        unsupported = initialized_program()
        fixtures.blocks(unsupported)['body']['ops'].insert(1,
            i('call', ['value'], [('called', 'u8')], function='identity'))
        unsupported['functions'].append(f('identity', [('input', 'u8')], ['u8'], [], [
            b('entry', [('input', 'u8')], [], ret('input'))]))
        for program in (repeated, unsupported, initialized_program(wrong_owner=True), initialized_program(skip=True)):
            verify_program(program)
            report = ledger.extract_obligations(program)
            self.assertEqual(report['status'], 'rejected', report)
            self.assert_denied(report)
            self.mismatch(program, report)

    def test_same_target_empty_cut_does_not_cover_other_branch_arm(self):
        program = fixtures.body_seed_program()
        mapping = fixtures.blocks(program)
        mapping['entry']['term']['then']['target'] = 'exit'
        program['functions'][0]['blocks'] = [mapping['entry'], mapping['exit']]
        verify_program(program)
        result = ledger.extract_obligations(program)
        self.assertEqual(result['status'], 'rejected')
        self.assert_denied(result)

    def test_changed_store_value_requires_new_transport_but_is_not_a_proof(self):
        program = initialized_program()
        original = self.extract(program)
        mutant = deepcopy(program)
        value = next(op for op in fixtures.blocks(mutant)['body']['ops']
                     if op['op'] == 'const' and op['out'][0]['type'] == 'u8')
        value['attrs']['value'] = (value['attrs']['value'] + 1) % 256
        changed = self.extract(mutant)
        self.assertNotEqual(changed['core_sha256'], original['core_sha256'])
        self.assertNotEqual(changed['functions'][0]['operations'], original['functions'][0]['operations'])
        self.mismatch(mutant, original)
        schedule = next(o for o in changed['functions'][0]['obligations'] if o['id'] == 'value_schedule')
        self.assertEqual(schedule['status'], 'unproved')

    def test_actual_extent_phi_mutation_fails_closed(self):
        for program in self.cores.values():
            mutant = deepcopy(program)
            entry = fixtures.blocks(mutant)['dg_shared_1']
            zero = next(op['out'][0]['name'] for op in entry['ops'] if op['op'] == 'const' and op['attrs']['value'] == 0)
            entry['term']['args'][3] = zero
            verify_program(mutant)
            report = ledger.extract_obligations(mutant)
            self.assertEqual(report['status'], 'rejected')
            self.assert_denied(report)

    def test_stale_source_hash_and_source_change_fail_closed(self):
        program = initialized_program()
        report = self.extract(program)
        changed = dict(report['source_sha256'])
        changed[next(iter(changed))] = '0' * 64
        with patch.object(ledger, 'source_identity', return_value=changed):
            self.mismatch(program, report)
        with patch.object(ledger, 'source_identity', side_effect=[report['source_sha256'], changed]):
            result = ledger.extract_obligations(program)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['functions'], [])
        self.assert_denied(result)

    def test_malformed_oversized_and_unexpected_failure_fail_closed(self):
        for program in (None, {}, {'status': 'extracted'}):
            report = ledger.extract_obligations(program)
            self.assertEqual(report['status'], 'rejected')
            self.assert_denied(report)
        with patch.object(ledger, 'MAX_JSON_BYTES', 1):
            self.assertEqual(ledger.extract_obligations(initialized_program())['status'], 'rejected')
        with patch.object(ledger, 'source_identity', side_effect=OSError('unavailable')):
            result = ledger.extract_obligations(initialized_program())
        self.assertEqual(result['status'], 'unknown')
        self.assert_denied(result)

    def test_extraction_is_read_only_and_does_not_run_vm_or_emitter(self):
        from hepta import hia_program_llvm, hia_program_runtime
        program = deepcopy(self.cores['linear'])
        original = deepcopy(program)
        with patch.object(hia_program_llvm, 'emit_program_llvm', side_effect=AssertionError('no emission')) as emitter, \
             patch.object(hia_program_llvm, 'compile_program_llvm', side_effect=AssertionError('no compiler')) as compiler, \
             patch.object(hia_program_runtime, 'execute_program', side_effect=AssertionError('no VM')) as vm:
            report = self.extract(program)
            self.assertEqual(ledger.check_obligation_transport(program, report)['status'], 'matched')
        self.assertEqual(program, original)
        emitter.assert_not_called()
        compiler.assert_not_called()
        vm.assert_not_called()


if __name__ == '__main__':
    unittest.main()
