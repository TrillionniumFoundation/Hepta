"""Finite actual-VM step controls, never a loop theorem or admission authority.

Fixtures are ordinary verified Core. No native execution, Lean, installation,
publication, or zero-initialization changes are involved.
"""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline
from hepta import hia_program_runtime as vm
from tests.test_hia_program import b, c, f, i, m, ret, branch
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS
from tools import check_dynamic_unsigned_step as checker

ROOT = Path(__file__).resolve().parents[1]
MAX_USIZE = 2**64 - 1


def step_program(*, compare='compare.lt', step=1, phi='index',
                 mode='wrap', typ='usize'):
    # Kept self-contained: the exploratory script has import-time execution.
    params = [('index', typ), ('extent', typ)]
    return m(f('step', params, [typ], ['trap'] if mode == 'checked' else [], [
        b('entry', params,
          [i(compare, ['index', 'extent'], [('condition', 'bool')])],
          branch('condition', ('body', phi, 'extent'), ('done', 'index'))),
        b('body', [('body_index', typ), ('body_extent', typ)],
          [c('one', typ, step),
           i('int.add.' + mode, ['body_index', 'one'], [('next', typ)])],
          ret('next')),
        b('done', [('unchanged', typ)], [], ret('unchanged'))]))


def ordinary_outcome(program, arguments, function='step', **limits):
    try:
        return vm.execute_program(program, function, arguments, **limits)
    except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
        return error.report


def alpha_rename(program):
    """Rename SSA values and CFG labels without touching opcodes or types."""
    result = deepcopy(program)
    for fn in result['functions']:
        fn['entry'] = 'renamed_' + fn['entry']
        for param in fn['params']:
            param['name'] = 'renamed_' + param['name']
        for block in fn['blocks']:
            block['id'] = 'renamed_' + block['id']
            for param in block['params']:
                param['name'] = 'renamed_' + param['name']
            for op in block['ops']:
                op['args'] = ['renamed_' + name for name in op['args']]
                for out in op['out']:
                    out['name'] = 'renamed_' + out['name']
            term = block['term']
            if term['op'] == 'ret':
                term['values'] = ['renamed_' + name for name in term['values']]
            elif term['op'] == 'branch':
                term['cond'] = 'renamed_' + term['cond']
                for side in ('then', 'else'):
                    term[side]['target'] = 'renamed_' + term[side]['target']
                    term[side]['args'] = ['renamed_' + name for name in term[side]['args']]
            elif term['op'] == 'jump':
                term['target'] = 'renamed_' + term['target']
                term['args'] = ['renamed_' + name for name in term['args']]
    return result


class DynamicUnsignedStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deferred = {}
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / 'benchmarks/hia_reduction_release' /
                                 (workload + '.hepta')).read_text())
            proposal = propose_reduction_pipeline(base, include_induction=True)
            cls.deferred[workload] = propose_deferred_guard(base, proposal)['candidate_core']

    def observe(self, program, arguments, *, function='step', **kwargs):
        result = checker.observe_unsigned_steps(program, arguments, function=function, **kwargs)
        for key, value in DENY.items():
            self.assertEqual(result[key], value)
        self.assertFalse(result['actual_core_bridge_proved'])
        self.assertFalse(result['whole_loop_proved'])
        self.assertFalse(result['all_entries_step_safe'])
        self.assertEqual(result['obligations'],
                         [{'id': name, 'status': 'unproved'} for name, _ in OBLIGATIONS])
        limits = {key: value for key, value in kwargs.items() if key != 'max_events'}
        self.assertEqual(result['vm_outcome'], ordinary_outcome(program, arguments, function, **limits))
        for event in result['events']:
            self.assertEqual(event['arm'], 'then')
            self.assertTrue(event['simultaneous_phi_matches'])
            self.assertEqual(event['outcome'], 'success')
            self.assertEqual(event['result'], event['index'] + 1)
            self.assertLessEqual(event['result'], event['extent'])
            self.assertLessEqual(event['extent'], MAX_USIZE)
        return result

    def test_replay_metadata_preserves_inputs_and_observation_limit(self):
        arguments = [3, 7]
        report = checker.observe_unsigned_steps(self.deferred['linear'], arguments,
            function='calculate', max_events=7, max_steps=1000, max_heap_bytes=4096)
        self.assertEqual(report['function'], 'calculate')
        self.assertEqual(report['arguments'], [3, 7])
        self.assertEqual(report['limits'], {'max_steps': 1000, 'max_heap_bytes': 4096})
        self.assertEqual(report['event_limit'], 7)
        arguments[0] = 999
        self.assertEqual(report['arguments'], [3, 7])

    def test_real_deferred_loops_finite_inputs(self):
        for workload, program in self.deferred.items():
            extraction = checker.extract_step_slices(program)
            self.assertEqual(extraction['status'], 'extracted', extraction)
            self.assertTrue(extraction['slices'])
            for length in (0, 1, 2, 4, 17):
                for seed in (0, 5471, 2**32 - 1):
                    with self.subTest(workload=workload, length=length, seed=seed):
                        report = self.observe(program, [length, seed], function='calculate')
                        self.assertEqual(report['finite_step_matches'], length > 0, report)
                        # Initial fill enters the body directly, outside this true-edge slice.
                        self.assertEqual(len(report['events']), max(0, 2 * length - 1))
                        self.assertEqual(report['extraction']['core_sha256'], verify_program(program).sha256)

    def test_checked_and_wrap_unit_step_at_unsigned_maximum(self):
        for mode in ('checked', 'wrap'):
            program = step_program(mode=mode)
            extraction = checker.extract_step_slices(program)
            self.assertEqual(extraction['status'], 'extracted', extraction)
            report = self.observe(program, [MAX_USIZE - 1, MAX_USIZE])
            self.assertTrue(report['finite_step_matches'])
            self.assertEqual(len(report['events']), 1)
            self.assertEqual(report['vm_outcome']['values'], [MAX_USIZE])

    def test_all_small_guarded_steps(self):
        for extent in range(6):
            for index in range(extent + 1):
                report = self.observe(step_program(), [index, extent])
                self.assertEqual(report['finite_step_matches'], index < extent)
                self.assertEqual(len(report['events']), int(index < extent))

    def test_inclusive_compare_stride_two_wrong_phi_and_signed_rejected(self):
        for kwargs in ({'compare': 'compare.le'}, {'step': 2},
                       {'phi': 'extent'}, {'typ': 'i64'}):
            with self.subTest(kwargs=kwargs):
                program = step_program(**kwargs)
                verify_program(program)
                report = checker.extract_step_slices(program)
                self.assertEqual(report['status'], 'rejected', report)
                self.assertEqual(report['slices'], [])

    def test_false_edge_with_identical_target_is_not_true_arm_evidence(self):
        program = step_program()
        program['functions'][0]['blocks'][0]['term']['else'] = {
            'target': 'body', 'args': ['index', 'extent']}
        # Remove unreachable block so this is ordinary valid Core.
        program['functions'][0]['blocks'].pop()
        verify_program(program)
        true = self.observe(program, [0, 1])
        self.assertEqual(len(true['events']), 1)
        false = self.observe(program, [1, 1])
        self.assertEqual(false['events'], [])
        self.assertEqual(false['vm_outcome']['values'], [2])

    def test_branch_must_use_comparison_result(self):
        program = step_program()
        fn = program['functions'][0]
        fn['params'].append({'name': 'other_condition', 'type': 'bool'})
        fn['blocks'][0]['params'].append({'name': 'other_condition', 'type': 'bool'})
        fn['blocks'][0]['term']['cond'] = 'other_condition'
        verify_program(program)
        result = checker.extract_step_slices(program)
        self.assertEqual(result['status'], 'rejected', result)
        observation = checker.observe_unsigned_steps(program, [0, 1, True], function='step')
        self.assertEqual(observation['events'], [])
        self.assertFalse(observation['finite_step_matches'])

    def test_budget_before_add_cannot_manufacture_result(self):
        for budget in (1, 2, 3, 4):
            report = self.observe(step_program(), [0, 1], max_steps=budget)
            self.assertEqual(report['vm_outcome']['status'], 'budget_exceeded')
            self.assertFalse(any(event.get('outcome') == 'success' for event in report['events']))
            self.assertEqual(report['events'], [])

    def test_trap_before_add_cannot_manufacture_result(self):
        program = step_program(mode='checked')
        body = program['functions'][0]['blocks'][1]
        body['ops'][0:0] = [c('zero', 'usize', 0),
                            i('int.div.checked', ['body_index', 'zero'], [('quotient', 'usize')])]
        verify_program(program)
        report = self.observe(program, [0, 1])
        self.assertEqual(report['vm_outcome']['status'], 'trapped')
        self.assertEqual(report['events'], [])

    def test_alpha_renaming_preserves_steps(self):
        for program, arguments, function in ((step_program(), [4, 5], 'step'),
                                             (self.deferred['linear'], [4, 7], 'calculate')):
            renamed = alpha_rename(program)
            self.assertNotEqual(verify_program(program).sha256, verify_program(renamed).sha256)
            report = self.observe(renamed, arguments, function=function)
            original = self.observe(program, arguments, function=function)
            self.assertTrue(report['finite_step_matches'])
            self.assertEqual(len(report['events']), len(original['events']))
            self.assertEqual(report['vm_outcome']['values'], original['vm_outcome']['values'])

    def test_event_bound_exhaustion_fails_closed_without_changing_vm(self):
        for maximum in (0, 1):
            report = self.observe(self.deferred['linear'], [4, 7],
                                  function='calculate', max_events=maximum)
            self.assertLessEqual(len(report['events']), maximum)
            self.assertFalse(report['observation_complete'])
            self.assertFalse(report['finite_step_matches'])

    def test_exact_event_bound_does_not_count_false_exit_guard(self):
        report = self.observe(self.deferred['linear'], [1, 7],
                              function='calculate', max_events=1)
        self.assertEqual(len(report['events']), 1)
        self.assertTrue(report['observation_complete'])
        self.assertTrue(report['finite_step_matches'])

    def test_invalid_event_bounds_are_rejected(self):
        for maximum in (-1, True, 1.5, '1', 2**64):
            with self.subTest(maximum=maximum), self.assertRaises((ValueError, HIAProgramRejected)):
                checker.observe_unsigned_steps(step_program(), [0, 1], function='step', max_events=maximum)

    def test_source_change_invalidates_finite_observation(self):
        original = checker.source_identity()
        changed = dict(original)
        changed['test_source_change'] = 'changed'
        with patch.object(checker, 'source_identity', side_effect=[original, original, changed]):
            report = self.observe(step_program(), [0, 1])
        self.assertFalse(report['sources_unchanged'])
        self.assertFalse(report['observation_complete'])
        self.assertFalse(report['finite_step_matches'])

    def test_invalid_typed_scalars_never_become_step_evidence(self):
        for arguments in ([True, 1], [-1, 1], [0, 2**64], [0, False], [0.0, 1]):
            with self.subTest(arguments=arguments), self.assertRaises(HIAProgramRejected):
                checker.observe_unsigned_steps(step_program(), arguments, function='step')

    def test_reordered_phi_parameters_are_matched_by_position(self):
        program = step_program()
        entry, body, _ = program['functions'][0]['blocks']
        entry['term']['then']['args'] = ['extent', 'index']
        body['params'].reverse()
        verify_program(program)
        report = self.observe(program, [4, 9])
        event, = report['events']
        self.assertEqual((event['index'], event['extent'], event['result']), (4, 9, 5))
        self.assertTrue(event['simultaneous_phi_matches'])
        self.assertEqual(event['phi_bindings_checked'], 2)

    def test_all_incoming_phi_bindings_are_checked(self):
        program = step_program()
        fn = program['functions'][0]
        entry, body, _ = fn['blocks']
        fn['params'].append({'name': 'payload', 'type': 'u32'})
        entry['params'].append({'name': 'payload', 'type': 'u32'})
        entry['term']['then']['args'].append('payload')
        body['params'].append({'name': 'body_payload', 'type': 'u32'})
        report = self.observe(program, [4, 9, 123456])
        event, = report['events']
        self.assertEqual(event['phi_bindings_checked'], 3)
        self.assertTrue(event['finite_step_matches'])

    def test_extraction_source_change_fails_closed(self):
        original = checker.source_identity()
        changed = dict(original, changed='different')
        with patch.object(checker, 'source_identity', side_effect=[original, changed]):
            report = checker.extract_step_slices(step_program())
        self.assertEqual(report['status'], 'unknown')
        self.assertEqual(report['slices'], [])

    def test_extraction_operation_bound_fails_closed(self):
        program = step_program()
        body = program['functions'][0]['blocks'][1]
        body['ops'] += [c('unused_' + str(n), 'usize', n) for n in range(2048)]
        verify_program(program)
        report = checker.extract_step_slices(program)
        self.assertEqual(report['status'], 'rejected')
        self.assertEqual(report['slices'], [])

    def test_malformed_core_is_not_extracted(self):
        program = step_program()
        program['functions'][0]['blocks'][1]['ops'][0]['attrs']['value'] = True
        report = checker.extract_step_slices(program)
        self.assertIn(report['status'], ('rejected', 'unknown'))
        self.assertEqual(report['slices'], [])


if __name__ == '__main__':
    unittest.main()
