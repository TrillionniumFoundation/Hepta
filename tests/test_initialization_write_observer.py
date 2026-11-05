"""Real Core/VM controls; zero initialization is never disabled."""
from copy import deepcopy
from pathlib import Path
import unittest
from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools.research_initialization_writes import observe_explicit_writes

ROOT = Path(__file__).resolve().parents[1]


class ExplicitWriteObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.programs = {}
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
            proposal = propose_reduction_pipeline(base, include_induction=True)
            cls.programs[workload] = propose_deferred_guard(base, proposal)['candidate_core']

    def test_actual_deferred_cores_finite_loads_follow_explicit_stores(self):
        for workload, program in self.programs.items():
            for n in (0, 1, 2, 4, 17):
                for seed in (0, 5471, 2**32-1):
                    with self.subTest(workload=workload, n=n, seed=seed):
                        report = observe_explicit_writes(program, [n, seed])
                        self.assertEqual(report['missing_program_writes'], [])
                        self.assertEqual(len(report['loads']), n)
                        self.assertEqual(len(report['stores']), n)
                        self.assertEqual(report['authority'], 'DENY_ALL')
                        self.assertTrue(report['ordinary_zero_initialization_retained'])
                        self.assertFalse(report['initialization_elision_authorized'])

    def test_deleted_store_is_core_valid_but_zero_initialization_is_needed(self):
        for workload, source in self.programs.items():
            mutant = deepcopy(source)
            for block in mutant['functions'][0]['blocks']:
                block['ops'] = [op for op in block['ops'] if op['op'] != 'buffer.store']
            verify_program(mutant)
            report = observe_explicit_writes(mutant, [2, 5])
            self.assertEqual([row['index'] for row in report['missing_program_writes']], [0, 1])
            self.assertEqual(report['stores'], [])
            self.assertTrue(report['ordinary_zero_initialization_retained'])

    def test_repeated_index_zero_does_not_cover_later_reads(self):
        for workload, source in self.programs.items():
            mutant = deepcopy(source)
            counter = 0
            for block in mutant['functions'][0]['blocks']:
                stores = [op for op in block['ops'] if op['op'] == 'buffer.store']
                for store in stores:
                    name = 'observer_mutation_zero_' + str(counter)
                    counter += 1
                    block['ops'].insert(0, {'op': 'const', 'args': [], 'attrs': {'value': 0},
                                           'out': [{'name': name, 'type': 'usize'}]})
                    store['args'][1] = name
            verify_program(mutant)
            report = observe_explicit_writes(mutant, [3, 5])
            self.assertEqual([row['index'] for row in report['missing_program_writes']], [1, 2])
            self.assertEqual([row['index'] for row in report['stores']], [0, 0, 0])

    def test_start_stride_predicate_and_extent_counterexamples_keep_zero_init(self):
        from hepta.hia_initialization import verify_initialization_coverage
        for workload, source in self.programs.items():
            for mutation, expected in (('start_one', [0]), ('stride_two', [1, 3]),
                                       ('wrong_predicate', [0, 1, 2, 3]), ('short_extent', [3])):
                with self.subTest(workload=workload, mutation=mutation):
                    mutant = deepcopy(source)
                    blocks = {block['id']: block for block in mutant['functions'][0]['blocks']}
                    if mutation == 'start_one':
                        next(op for op in blocks['dg_shared_1']['ops'] if op['op'] == 'const')['attrs']['value'] = 1
                    elif mutation == 'stride_two':
                        for side in ('fast', 'slow'):
                            next(op for op in blocks['dg_' + side + '_1']['ops']
                                 if op['op'] == 'const' and op['out'][0]['type'] == 'usize')['attrs']['value'] = 2
                    elif mutation == 'wrong_predicate':
                        blocks['dg_shared_3']['ops'][0]['op'] = 'compare.eq'
                    else:
                        block = blocks['dg_shared_1']
                        block['ops'] += [
                            {'op': 'const', 'args': [], 'out': [{'name': 'extent_one', 'type': 'usize'}], 'attrs': {'value': 1}},
                            {'op': 'int.sub.checked', 'args': ['dg_v_3', 'extent_one'],
                             'out': [{'name': 'short_extent', 'type': 'usize'}], 'attrs': {}}]
                        block['term']['args'][3] = 'short_extent'
                    checked = verify_program(mutant)
                    self.assertFalse(verify_initialization_coverage(checked)['functions'][0]['eligible'])
                    report = observe_explicit_writes(checked, [4, 7], max_steps=10000, max_heap_bytes=4096)
                    self.assertEqual([row['index'] for row in report['missing_program_writes']], expected)
                    self.assertTrue(report['ordinary_zero_initialization_retained'])

    def test_other_owner_stores_cannot_cover_this_owners_load(self):
        from tests.test_hia_initialization import initialized_program
        checked = verify_program(initialized_program(wrong_owner=True))
        report = observe_explicit_writes(checked, [4, 3], function='initialized')
        self.assertEqual([row['index'] for row in report['missing_program_writes']], [3])
        self.assertNotIn(report['loads'][0]['owner'], {row['owner'] for row in report['stores']})

    def test_generated_positive_cores_equal_real_compile_only_ci_inputs(self):
        expected = {'linear': 'c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3',
                    'affine': '91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861'}
        for workload, source in self.programs.items():
            self.assertEqual(verify_program(source).sha256, expected[workload])

    def test_extent_phi_zero_keeps_cfg_and_root_but_misses_all_program_writes(self):
        from hepta.hia_initialization import verify_initialization_coverage
        for source in self.programs.values():
            mutant = deepcopy(source)
            block = next(b for b in mutant['functions'][0]['blocks'] if b['id'] == 'dg_shared_1')
            zero = next(op['out'][0]['name'] for op in block['ops'] if op['op'] == 'const'
                        and op['out'][0]['type'] == 'usize' and op['attrs']['value'] == 0)
            block['term']['args'][3] = zero
            checked = verify_program(mutant)
            self.assertFalse(verify_initialization_coverage(checked)['functions'][0]['eligible'])
            report = observe_explicit_writes(checked, [4, 7])
            self.assertEqual([row['index'] for row in report['missing_program_writes']], [0, 1, 2, 3])

    def test_explicit_threshold_zero_variant_exercises_slow_finitely_only(self):
        # This variant is not the original huge-threshold CI program or a proof
        # about all its slow inputs. It makes small n>0 take the slow clone.
        from hepta.hia_program_runtime import execute_program
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
            proposal = propose_reduction_pipeline(base, maximum=0, include_induction=True)
            variant = verify_program(propose_deferred_guard(base, proposal)['candidate_core'])
            self.assertNotEqual(variant.sha256, verify_program(self.programs[workload]).sha256)
            for n in (0, 1, 2, 4, 17):
                for seed in (0, 5471, 2**32-1):
                    report = observe_explicit_writes(variant, [n, seed])
                    self.assertEqual(report['missing_program_writes'], [])
                    self.assertEqual(len(report['stores']), n)
                    self.assertEqual(len(report['loads']), n)
                    self.assertEqual(report['vm_outcome'], execute_program(variant, 'calculate', [n, seed]))

    def test_checked_initialization_structure_does_not_prove_output_equivalence(self):
        from tools.check_initialization_frontiers import check_initialization_frontiers
        for source in self.programs.values():
            mutant = deepcopy(source)
            for number, block in enumerate(mutant['functions'][0]['blocks']):
                for store in [op for op in block['ops'] if op['op'] == 'buffer.store']:
                    name = 'different_output_byte_' + str(number)
                    block['ops'].insert(0, {'op': 'const', 'args': [], 'attrs': {'value': 0},
                                           'out': [{'name': name, 'type': 'u8'}]})
                    store['args'][2] = name
            checked = verify_program(mutant)
            report = check_initialization_frontiers(checked)
            self.assertEqual(report['status'], 'checked')
            self.assertFalse(report['initialization_elision_authorized'])
            observed = observe_explicit_writes(checked, [2, 5])
            self.assertEqual(observed['missing_program_writes'], [])
            self.assertNotEqual(observed['vm_outcome']['result'],
                                observe_explicit_writes(source, [2, 5])['vm_outcome']['result'])

    def test_allocation_refusal_and_vm_budget_remain_ordinary_vm_outcomes(self):
        from hepta.hia_program_runtime import execute_program, HIAProgramBudgetExceeded
        for source in self.programs.values():
            checked = verify_program(source)
            for limits in ({'allocation_fail_at': 1}, {'max_heap_bytes': 1}, {'max_steps': 1}):
                report = observe_explicit_writes(checked, [4, 7], **limits)
                try:
                    expected = execute_program(checked, 'calculate', [4, 7], **limits)
                except HIAProgramBudgetExceeded as error:
                    expected = error.report
                self.assertEqual(report['vm_outcome'], expected)
                self.assertEqual(report['loads'], [])
                self.assertEqual(report['stores'], [])
                self.assertTrue(report['ordinary_zero_initialization_retained'])

    def test_observer_does_not_change_vm_result_or_resource_counters(self):
        from hepta.hia_program_runtime import execute_program
        for source in self.programs.values():
            checked = verify_program(source)
            report = observe_explicit_writes(checked, [3, 5])
            self.assertEqual(report['vm_outcome'], execute_program(checked, 'calculate', [3, 5]))


if __name__ == '__main__':
    unittest.main()
