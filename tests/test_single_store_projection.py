"""Finite ordinary-VM observations, not a proof or zero-elision authority.

Adversarial private runtime-object tests are explicitly boundary probes, not
verified Core examples. No native, Lean, installation or publication is used.
"""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline
from hepta import hia_program_runtime as vm
from tests.test_hia_program import b, c, f, i, m, ret
from tests.test_hia_initialization import initialized_program
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS
from tools.observe_single_store_projection import audit_store_event, observe_single_stores

ROOT = Path(__file__).resolve().parents[1]


def store_program(*, writes=1, other=False, epochs=1):
    params = [('n', 'usize'), ('index', 'usize'), ('value', 'u8')]
    ops = []
    if other:
        ops += [i('buffer.new', ['n'], [('other', 'buffer')]),
                i('borrow.mut', ['other'], [('other_view', 'mutbuf')]),
                c('other_value', 'u8', 199),
                i('buffer.store', ['other_view', 'index', 'other_value']),
                i('loan.end', ['other_view'])]
    for epoch in range(epochs):
        owner, view = 'owner_' + str(epoch), 'view_' + str(epoch)
        ops += [i('buffer.new', ['n'], [(owner, 'buffer')]),
                i('borrow.mut', [owner], [(view, 'mutbuf')])]
        ops += [i('buffer.store', [view, 'index', 'value']) for _ in range(writes)]
        ops += [i('loan.end', [view]), i('owner.drop', [owner])]
    if other:
        ops.append(i('owner.drop', ['other']))
    return m(f('calculate', params, ['u8'], ['alloc', 'write', 'trap'],
               [b('entry', params, ops, ret('value'))]))


def ordinary_outcome(program, arguments, function='calculate', **limits):
    try:
        return vm.execute_program(program, function, arguments, **limits)
    except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
        return error.report


class SingleStoreProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deferred = {}
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / 'benchmarks/hia_reduction_release' /
                                 (workload + '.hepta')).read_text())
            proposal = propose_reduction_pipeline(base, include_induction=True)
            cls.deferred[workload] = propose_deferred_guard(base, proposal)['candidate_core']

    def observe(self, program, arguments, **kwargs):
        report = observe_single_stores(program, arguments, **kwargs)
        for key, value in DENY.items():
            self.assertEqual(report[key], value)
        self.assertIs(report['actual_core_bridge_proved'], False)
        self.assertIs(report['finite_observation_only'], True)
        self.assertIs(report['all_program_loads_covered_claim'], False)
        self.assertEqual(report['observed_successful_store_count'],
                         sum(e['outcome'] == 'success' for e in report['events']))
        self.assertIs(report['ordinary_zero_initialization_retained'], True)
        self.assertEqual(len(report['obligations']), 12)
        self.assertEqual(report['obligations'],
                         [{'id': name, 'status': 'unproved'} for name, _ in OBLIGATIONS])
        vm_kwargs = {key: value for key, value in kwargs.items()
                     if not key.startswith('max_observed') and key != 'max_events'}
        self.assertEqual(report['vm_outcome'], ordinary_outcome(program, arguments, **vm_kwargs))
        return report

    def test_real_deferred_finite_lengths_seeds_and_every_byte_frame(self):
        hashes = {'linear': 'c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3',
                  'affine': '91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861'}
        for workload, program in self.deferred.items():
            for n in (0, 1, 2, 4, 17):
                for seed in (0, 5471, 2**32 - 1):
                    with self.subTest(workload=workload, n=n, seed=seed):
                        report = self.observe(program, [n, seed])
                        self.assertEqual(report['core_sha256'], hashes[workload])
                        self.assertTrue(report['finite_frame_matches'])
                        self.assertEqual(report['observed_store_count'], n)
                        for event in report['events']:
                            self.assertTrue(audit_store_event(event))
                            self.assertEqual(event['resources_before'], event['resources_after'])
                            row = event['after'][event['owner_epoch']]
                            self.assertEqual(row['written'], list(range(event['index'] + 1)))

    def test_all_small_indices_representative_bytes_and_same_value_overwrite(self):
        program = store_program(writes=2)
        for n in (1, 2, 4):
            for index in range(n):
                for value in (0, 1, 127, 128, 255):
                    with self.subTest(n=n, index=index, value=value):
                        report = self.observe(program, [n, index, value])
                        self.assertTrue(report['finite_frame_matches'])
                        first, second = report['events']
                        root = first['owner_epoch']
                        self.assertEqual(first['before'][root]['bytes'], [0] * n)
                        self.assertEqual(first['before'][root]['written'], [])
                        self.assertEqual(first['after'][root]['written'], [index])
                        self.assertEqual(first['after'], second['before'])
                        self.assertEqual(second['before'], second['after'])

    def test_explicit_zero_is_distinct_from_allocator_zero_and_absent_store(self):
        zero = self.observe(store_program(), [3, 1, 0])['events'][0]
        root = zero['owner_epoch']
        self.assertEqual(zero['before'][root]['bytes'], zero['after'][root]['bytes'])
        self.assertEqual(zero['before'][root]['written'], [])
        self.assertEqual(zero['after'][root]['written'], [1])
        no_write = self.observe(store_program(writes=0), [3, 1, 0])
        self.assertEqual(no_write['events'], [])
        self.assertEqual(no_write['owner_epochs_seen'], 1)

    def test_bounds_failures_have_no_w_update(self):
        for n, index in ((0, 0), (1, 1), (3, 3), (3, 2**64 - 1)):
            report = self.observe(store_program(), [n, index, 23])
            self.assertEqual(report['vm_outcome']['status'], 'trapped')
            event, = report['events']
            self.assertEqual(event['outcome'], 'failure')
            self.assertEqual(event['before'], event['after'])
            self.assertEqual(event['after'][event['owner_epoch']]['written'], [])
            self.assertTrue(audit_store_event(event))

    def test_budget_before_store_never_fabricates_success(self):
        complete = self.observe(store_program(), [2, 0, 9])
        step = complete['events'][0]['step']
        report = self.observe(store_program(), [2, 0, 9], max_steps=step - 1)
        self.assertEqual(report['vm_outcome']['status'], 'budget_exceeded')
        self.assertEqual(report['events'], [])

    def test_allocation_refusal_heap_and_step_budgets_equal_ordinary_vm(self):
        for program in self.deferred.values():
            for limits in ({'allocation_fail_at': 1}, {'max_heap_bytes': 1}, {'max_steps': 1}):
                report = self.observe(program, [4, 7], **limits)
                self.assertEqual(report['events'], [])

    def test_observation_limits_refuse_claim_without_changing_execution(self):
        for limits in ({'max_events': 0}, {'max_events': 1}, {'max_observed_bytes': 1}):
            report = self.observe(store_program(writes=2), [3, 1, 11], **limits)
            self.assertFalse(report['observation_complete'])
            self.assertFalse(report['finite_frame_matches'])
        for bound in ('max_events', 'max_observed_bytes'):
            for invalid in (-1, True, 0.5, None, 65537):
                with self.subTest(bound=bound, invalid=invalid):
                    with self.assertRaises(ValueError):
                        observe_single_stores(store_program(), [2, 0, 9], **{bound: invalid})

    def test_dropped_owner_new_allocations_have_fresh_epochs(self):
        report = self.observe(store_program(epochs=4), [3, 1, 44])
        self.assertEqual(report['owner_epochs_seen'], 4)
        roots = [event['owner_epoch'] for event in report['events']]
        self.assertEqual(len(set(roots)), 4)
        for event in report['events']:
            root = event['owner_epoch']
            self.assertEqual(event['before'][root]['written'], [])
            self.assertEqual(event['before'][root]['bytes'], [0, 0, 0])
            self.assertEqual(event['after'][root]['written'], [1])

    def test_repeated_dynamic_allocation_site_does_not_reuse_w(self):
        program = initialized_program()
        ops = program['functions'][0]['blocks'][2]['ops']
        ops[:0] = [i('buffer.new', ['bn'], [('temp', 'buffer')]),
                   i('borrow.mut', ['temp'], [('temp_view', 'mutbuf')]),
                   c('temp_value', 'u8', 41),
                   i('buffer.store', ['temp_view', 'bi', 'temp_value']),
                   i('loan.end', ['temp_view']), i('owner.drop', ['temp'])]
        report = self.observe(program, [4, 3], function='initialized')
        temporary = report['events'][::2]
        self.assertEqual(len({e['owner_epoch'] for e in temporary}), 4)
        for event in temporary:
            self.assertEqual(event['before'][event['owner_epoch']]['written'], [])

    def test_another_live_equal_sized_owner_preserves_distinct_bytes_and_w(self):
        report = self.observe(store_program(other=True), [3, 1, 7])
        first, second = report['events']
        other, root = first['owner_epoch'], second['owner_epoch']
        self.assertNotEqual(other, root)
        self.assertEqual(second['before'][other]['bytes'], [0, 199, 0])
        self.assertEqual(second['before'][other], second['after'][other])
        self.assertEqual(second['before'][root]['written'], [])
        self.assertEqual(second['after'][root]['bytes'], [0, 7, 0])

    def test_tampered_target_other_byte_length_root_value_w_and_resources_reject(self):
        event = self.observe(store_program(other=True), [3, 1, 7])['events'][1]
        root = event['owner_epoch']
        other = next(key for key in event['before'] if key != root)
        mutations = [
            lambda e: e['after'][root]['bytes'].__setitem__(0, 66),
            lambda e: e['after'][root]['bytes'].__setitem__(1, 8),
            lambda e: e['after'][root]['bytes'].append(0),
            lambda e: e['after'][other]['bytes'].__setitem__(0, 66),
            lambda e: e.__setitem__('owner_epoch', other),
            lambda e: e.__setitem__('owner_epoch', 999),
            lambda e: e.__setitem__('value', 8),
            lambda e: e['after'][root].__setitem__('written', []),
            lambda e: e['after'][root].__setitem__('written', [0, 1]),
            lambda e: e['after'][other].__setitem__('written', []),
            lambda e: e['resources_after'].__setitem__('live_bytes', 999),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                changed = deepcopy(event)
                mutate(changed)
                self.assertFalse(audit_store_event(changed))

    def test_bad_scalar_inputs_are_rejected_at_public_typed_boundary(self):
        program = store_program()
        for arguments in ([2, -1, 1], [2, True, 1], [2, 2**64, 1],
                          [2, 0, -1], [2, 0, 256], [2, 0, True]):
            with self.subTest(arguments=arguments), self.assertRaises(HIAProgramRejected):
                observe_single_stores(program, arguments)

    def test_wrong_operand_order_is_rejected_by_core_not_private_vm(self):
        program = store_program()
        op = next(op for op in program['functions'][0]['blocks'][0]['ops']
                  if op['op'] == 'buffer.store')
        op['args'][1:] = reversed(op['args'][1:])
        with self.assertRaises(HIAProgramRejected):
            observe_single_stores(program, [2, 0, 1])

    def test_captured_locators_resolve_to_exact_core_operation(self):
        for program in (*self.deferred.values(), store_program(writes=2)):
            arguments = [3, 7] if program in self.deferred.values() else [3, 1, 7]
            report = self.observe(program, arguments)
            document = verify_program(program).as_dict()
            for event in report['events']:
                locator = event['locator']
                function = next(f for f in document['functions'] if f['name'] == locator['function'])
                block = next(b for b in function['blocks'] if b['id'] == locator['block'])
                self.assertEqual(block['ops'][locator['ordinal']], event['operation'])
        # Two structurally equal stores have distinct instruction ordinals.
        report = self.observe(store_program(writes=2), [3, 1, 7])
        self.assertEqual(report['events'][0]['operation'], report['events'][1]['operation'])
        self.assertNotEqual(report['events'][0]['locator'], report['events'][1]['locator'])

    def test_frame_audit_explicitly_does_not_authenticate_locator_transport(self):
        event = self.observe(store_program(), [3, 1, 7])['events'][0]
        event['locator']['ordinal'] = 999
        # This API checks concrete bytes/W only. Authentication against Core,
        # ordered environment and phi transport remains an unproved obligation.
        self.assertTrue(audit_store_event(event))

    def test_total_snapshot_byte_bound_stops_recording_not_vm(self):
        report = self.observe(store_program(writes=33), [4096, 1, 7])
        self.assertEqual(report['observed_store_count'], 32)
        self.assertFalse(report['observation_complete'])
        self.assertFalse(report['finite_frame_matches'])
        self.assertEqual(sum(2 * sum(len(row['bytes']) for row in e['before'].values())
                             for e in report['events']), 262144)

    def test_zero_sized_owners_count_toward_total_snapshot_row_budget(self):
        from tools import observe_single_store_projection as observer
        program = store_program(writes=3)
        ops = program['functions'][0]['blocks'][0]['ops']
        ops[:0] = [c('zero', 'usize', 0)] + [
            i('buffer.new', ['zero'], [('empty_' + str(n), 'buffer')]) for n in range(3)]
        ops.extend(i('owner.drop', ['empty_' + str(n)]) for n in range(3))
        with patch.object(observer, 'MAX_SNAPSHOT_OWNER_ROWS', 16):
            report = self.observe(program, [1, 0, 7])
        self.assertEqual(report['observed_store_count'], 2)
        self.assertEqual(sum(2 * len(e['before']) for e in report['events']), 16)
        self.assertEqual(sum(2 * sum(len(r['bytes']) for r in e['before'].values())
                             for e in report['events']), 4)
        self.assertFalse(report['observation_complete'])
        self.assertFalse(report['finite_frame_matches'])
        self.assertEqual(report['observation_bounds']['total_snapshot_owner_rows'], 16)

    def test_source_identity_change_disables_finite_claim(self):
        from tools import observe_single_store_projection as observer
        identity = observer.source_identity()
        self.assertIn('tools/observe_single_store_projection.py', identity)
        changed = dict(identity)
        changed['tools/observe_single_store_projection.py'] = '0' * 64
        with patch.object(observer, 'source_identity', side_effect=[identity, changed]):
            report = self.observe(store_program(), [3, 1, 7])
        self.assertFalse(report['sources_unchanged'])
        self.assertFalse(report['observation_complete'])
        self.assertFalse(report['finite_frame_matches'])

    def test_invalid_w_domains_and_non_bytes_reject_even_unchanged_failure_frames(self):
        event = self.observe(store_program(), [3, 3, 7])['events'][0]
        root = event['owner_epoch']
        for field, invalid in (('written', [-1]), ('written', [3]),
                               ('written', [False]), ('written', [1, 1]),
                               ('written', [2, 1]), ('bytes', [0, 256, 0]),
                               ('bytes', [0, True, 0])):
            with self.subTest(field=field, invalid=invalid):
                changed = deepcopy(event)
                for side in ('before', 'after'):
                    changed[side][root][field] = invalid
                self.assertFalse(audit_store_event(changed))

    def test_private_boundary_probes_reject_invalid_view_graphs_without_writing(self):
        # Deliberately fabricated objects: NOT verified Core counterexamples.
        owner = vm._Owner(1, bytearray([0, 0]))
        expired_owner = vm._Owner(2, bytearray([0, 0]), active=False)
        expired_view = vm._View(owner, True, active=False)
        cyclic = vm._View(owner, True)
        cyclic.parent = cyclic
        views = [vm._View(owner, False), expired_view,
                 vm._View(expired_view, True), vm._View(expired_owner, True), cyclic]
        machine = vm._Machine(verify_program(store_program()), 100, 100, None, 10)
        for view in views:
            with self.subTest(view_type=type(view).__name__):
                with self.assertRaises(HIAProgramRejected):
                    machine.operation(i('buffer.store', ['view', 'index', 'value']),
                                      {'view': view, 'index': 0, 'value': 7}, 0)
                self.assertEqual(owner.data, bytearray([0, 0]))
                self.assertEqual(expired_owner.data, bytearray([0, 0]))


if __name__ == '__main__':
    unittest.main()
