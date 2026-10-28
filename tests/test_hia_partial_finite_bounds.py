"""Real canonical/VM regressions for finite v7 partial-record resource bounds."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hepta.hia_heap_bound import (HIAHeapBoundRejected, analyze_constant_live_heap,
                                  qualify_finite_entry_live_heap_budget)
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests.test_hia_static_budget import cyclic_calls, cyclic_control_flow
from tools.qualify_hia_partial_records import budget_cases, cases, independent_spec, program


def v7(*functions):
    result = m(*functions)
    result['schema'] = 'hepta.hia.program.v7'
    result['exports'] = ['entry']
    return result


def nested_owned():
    inner = f('inner', [('incoming', 'buffer')], ['buffer'], ['alloc', 'trap'], [
        b('start', [('incoming', 'buffer')], [
            c('five', 'usize', 5), i('buffer.new', ['five'], [('scratch', 'buffer')]),
            i('owner.drop', ['scratch'])], ret('incoming'))])
    middle = f('middle', [('owned', 'buffer')], ['buffer', 'buffer'], ['alloc', 'trap'], [
        b('start', [('owned', 'buffer')], [
            i('call', ['owned'], [('again', 'buffer')], function='inner'),
            c('six', 'usize', 6), i('buffer.new', ['six'], [('extra', 'buffer')]),
        ], ret('again', 'extra'))])
    entry = f('entry', [], ['usize'], ['alloc', 'trap'], [
        b('start', [], [
            c('four', 'usize', 4), i('buffer.new', ['four'], [('kept', 'buffer')]),
            c('nine', 'usize', 9), i('buffer.new', ['nine'], [('passed', 'buffer')]),
            i('call', ['passed'], [('first', 'buffer'), ('second', 'buffer')], function='middle'),
            i('owner.drop', ['second']), i('owner.drop', ['first']), i('owner.drop', ['kept']),
        ], ret('nine'))])
    return v7(inner, middle, entry)


def borrowed_owned():
    child = f('child', [('left', 'readbuf'), ('right', 'readbuf'), ('owned', 'buffer')],
              ['buffer'], ['alloc', 'read', 'trap'], [
        b('start', [('left', 'readbuf'), ('right', 'readbuf'), ('owned', 'buffer')], [
            i('buffer.len', ['left'], [('ignored', 'usize')]),
            c('five', 'usize', 5), i('buffer.new', ['five'], [('scratch', 'buffer')]),
            i('owner.drop', ['scratch'])], ret('owned'))])
    entry = f('entry', [], [], ['alloc', 'read', 'trap'], [
        b('start', [], [
            c('nine', 'usize', 9), i('buffer.new', ['nine'], [('kept', 'buffer')]),
            c('four', 'usize', 4), i('buffer.new', ['four'], [('passed', 'buffer')]),
            i('borrow.read', ['kept'], [('view', 'readbuf')]),
            i('call', ['view', 'view', 'passed'], [('returned', 'buffer')], function='child'),
            i('owner.drop', ['returned']), i('loan.end', ['view']), i('owner.drop', ['kept']),
        ], ret())])
    return v7(child, entry)


class PartialFiniteBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nominal = verify_core(program())

    def bound(self, core, function, arguments, limit=1024):
        return qualify_finite_entry_live_heap_budget(
            core, function, arguments, max_live_heap_bytes=limit)

    def assert_observation(self, bound, observed):
        resources = observed['resources']
        self.assertLessEqual(resources['peak_bytes'], bound['peak_bound_bytes'])
        self.assertLessEqual(observed['steps'], bound['max_vm_ticks'])
        self.assertLessEqual(resources['allocation_attempts'] + resources['frees'],
                             bound['max_allocator_interactions'])

    def test_real_partial_normalization_gets_separate_versioned_bounds(self):
        checked = self.nominal
        self.assertEqual(checked.as_dict()['schema'], 'hepta.hia.program.v7')
        static = analyze_static_budget(checked)
        self.assertEqual(static['schema'], 'hepta.hia.static-budget.v3')
        self.assertEqual(static['profile'], 'acyclic-byte-owner-v7')
        for function in ('partial_case', 'partial_task', 'partial_pair_task'):
            row = next(row for row in cases() if row['function'] == function
                       and row['arguments'][1] == 7 and row['fail_at'] == 0)
            with self.subTest(function=function):
                certificate = self.bound(checked, function, row['arguments'])
                self.assertEqual(certificate['schema'], 'hepta.hia.finite-entry-live-heap-admission.v1')
                self.assertEqual(certificate['core_sha256'], checked.sha256)
                self.assertEqual(certificate['input_sha256'], checked.input_sha256)
                self.assertEqual(certificate['static_budget_sha256'], static['sha256'])
                self.assertEqual(certificate['arguments'], row['arguments'])
                self.assertFalse(certificate['claims']['all_function_input_extents_bounded'])
                actual = execute_program(checked, function, row['arguments'])
                self.assertEqual(actual['values'], [independent_spec(row)['result']])
                self.assert_observation(certificate, actual)

    def test_all_function_heap_meaning_is_not_replaced_by_exact_invocations(self):
        with self.assertRaises(HIAHeapBoundRejected):
            analyze_constant_live_heap(self.nominal)
        certificate = self.bound(self.nominal, 'partial_case', [0, 7, 73], limit=14)
        self.assertEqual(certificate['peak_bound_bytes'], 14)
        with self.assertRaisesRegex(HIAHeapBoundRejected, 'E_HIA_BUDGET_EXCEEDED'):
            self.bound(self.nominal, 'partial_case', [0, 7, 73], limit=13)

    def test_zero_byte_partial_tokens_remain_logical_owners(self):
        certificate = self.bound(self.nominal, 'partial_case', [0, 0, 73], limit=0)
        observed = execute_program(self.nominal, 'partial_case', [0, 0, 73])
        self.assertEqual(certificate['peak_bound_bytes'], 0)
        self.assertEqual(observed['resources']['owners_created'], 5)
        self.assertEqual(observed['resources']['owners_dropped'], 5)
        for key in ('allocation_attempts', 'allocations', 'frees', 'live_bytes', 'peak_bytes'):
            self.assertEqual(observed['resources'][key], 0)
        self.assert_observation(certificate, observed)

    def test_existing_oversize_cases_keep_failed_empty_logical_owners(self):
        rows = [row for row in cases() if row['arguments'][1] > (1 << 63) - 1]
        self.assertEqual(len(rows), 4)
        for row in rows:
            with self.subTest(arguments=row['arguments']):
                certificate = self.bound(self.nominal, row['function'], row['arguments'], limit=0)
                self.assertEqual(certificate['peak_bound_bytes'], 0)
                actual = execute_program(self.nominal, row['function'], row['arguments'])
                self.assertEqual(actual['values'], [100])
                self.assertEqual(actual['values'], [independent_spec(row)['result']])
                self.assertEqual(actual['resources']['owners_created'], 2)
                self.assertEqual(actual['resources']['owners_dropped'], 2)
                for key in ('allocation_attempts', 'allocations', 'frees', 'live_bytes', 'peak_bytes'):
                    self.assertEqual(actual['resources'][key], 0)
                self.assert_observation(certificate, actual)

    def test_infallible_oversize_allocation_preserves_trap_and_stop_prefixes(self):
        for extent in (1 << 63, (1 << 64) - 1):
            with self.subTest(extent=extent):
                entry = f('entry', [], [], ['alloc', 'trap'], [b('start', [], [
                    c('four', 'usize', 4), i('buffer.new', ['four'], [('held', 'buffer')]),
                    c('huge', 'usize', extent), i('buffer.new', ['huge'], [('never_created', 'buffer')]),
                    i('owner.drop', ['never_created']), i('owner.drop', ['held'])], ret())])
                core = verify_core(v7(entry))
                certificate = self.bound(core, 'entry', [], limit=4)
                self.assertEqual(certificate['peak_bound_bytes'], 4)
                with self.assertRaises(HIAProgramTrap) as failure:
                    execute_program(core, 'entry', [])
                observed = failure.exception.report
                self.assertEqual(observed['error']['code'], 'allocation')
                self.assertEqual(observed['resources']['owners_created'], 1)
                self.assertEqual(observed['resources']['owners_dropped'], 0)
                self.assertEqual(observed['resources']['allocation_attempts'], 1)
                self.assertEqual(observed['resources']['live_bytes'], 4)
                self.assert_observation(certificate, observed)
                with self.assertRaises(HIAProgramBudgetExceeded) as stop:
                    execute_program(core, 'entry', [], max_steps=3)
                self.assertEqual(stop.exception.report['resources']['live_bytes'], 4)
                self.assert_observation(certificate, stop.exception.report)

    def test_crossing_object_limit_and_exact_checked_overflow_remain_unknown(self):
        crossing = f('entry', [], [], ['alloc', 'read', 'trap'], [b('start', [], [
            c('one', 'usize', 1), i('buffer.try_new', ['one'], [('held', 'buffer'), ('ok', 'bool')]),
            i('buffer.len', ['held'], [('length', 'usize')]),
            c('maximum', 'usize', (1 << 63) - 1),
            i('int.add.checked', ['maximum', 'length'], [('request', 'usize')]),
            i('buffer.try_new', ['request'], [('other', 'buffer'), ('other_ok', 'bool')]),
            i('owner.drop', ['other']), i('owner.drop', ['held'])], ret())])
        # The actual allocator might fail, but that cannot justify a zero
        # byte certificate for an interval that includes the maximum request.
        with self.assertRaisesRegex(HIAHeapBoundRejected, 'allocator extent'):
            self.bound(verify_core(v7(crossing)), 'entry', [])
        overflowing = f('entry', [], [], ['alloc', 'trap'], [b('start', [], [
            c('maximum', 'usize', (1 << 64) - 1), c('one', 'usize', 1),
            i('int.add.checked', ['maximum', 'one'], [('request', 'usize')]),
            i('buffer.try_new', ['request'], [('other', 'buffer'), ('ok', 'bool')]),
            i('owner.drop', ['other'])], ret())])
        # This transfer has no independently audited arithmetic trap summary.
        # Preserve UNKNOWN instead of treating a failed abstract fold as zero.
        with self.assertRaisesRegex(HIAHeapBoundRejected, 'checked constant arithmetic'):
            self.bound(verify_core(v7(overflowing)), 'entry', [])

    def test_all_existing_budget_prefixes_are_bounded_without_implicit_cleanup(self):
        certificate = self.bound(self.nominal, 'partial_case', [0, 7, 73], limit=14)
        stopped, returned, live_prefixes = 0, 0, 0
        for options in budget_cases():
            with self.subTest(options=options):
                try:
                    observed = execute_program(self.nominal, 'partial_case', [0, 7, 73], **options)
                    returned += 1
                except HIAProgramBudgetExceeded as error:
                    observed = error.report
                    stopped += 1
                    live_prefixes += observed['resources']['live_bytes'] > 0
                self.assert_observation(certificate, observed)
        self.assertEqual((stopped, returned), (10, 1))
        self.assertGreater(live_prefixes, 0)
        self.assertFalse(certificate['claims']['cleanup_after_trap_or_budget_stop_proved'])

    def test_nested_owned_calls_and_multiple_returns_count_each_live_payload_once(self):
        core = verify_core(nested_owned())
        certificate = self.bound(core, 'entry', [], limit=19)
        self.assertEqual(certificate['peak_bound_bytes'], 19)
        normal = execute_program(core, 'entry', [])
        self.assertEqual(normal['values'], [9])
        self.assertEqual(normal['resources']['peak_bytes'], 19)
        self.assertEqual(normal['resources']['allocations'], 4)
        self.assertEqual(normal['resources']['frees'], 4)
        self.assert_observation(certificate, normal)
        for fail_at, expected_peak in enumerate((0, 4, 13, 18), start=1):
            with self.subTest(fail_at=fail_at):
                with self.assertRaises(HIAProgramTrap) as failure:
                    execute_program(core, 'entry', [], allocation_fail_at=fail_at)
                observed = failure.exception.report
                self.assertEqual(observed['resources']['peak_bytes'], expected_peak)
                self.assert_observation(certificate, observed)
        self.assertGreater(observed['resources']['live_bytes'], 0)

    def test_returned_length_interval_covers_fallible_empty_owner(self):
        consume = f('consume', [('owned', 'buffer')], ['usize'], ['alloc', 'read'], [
            b('start', [('owned', 'buffer')], [
                i('buffer.len', ['owned'], [('size', 'usize')]), i('owner.drop', ['owned'])], ret('size'))])
        entry = f('entry', [], [], ['alloc', 'read', 'trap'], [
            b('start', [], [c('eight', 'usize', 8),
                i('buffer.try_new', ['eight'], [('owned', 'buffer'), ('ok', 'bool')]),
                i('call', ['owned'], [('length', 'usize')], function='consume'),
                c('hundred', 'usize', 100), i('int.sub.checked', ['hundred', 'length'], [('next', 'usize')]),
                i('buffer.try_new', ['next'], [('later', 'buffer'), ('later_ok', 'bool')]),
                i('owner.drop', ['later'])], ret())])
        core = verify_core(v7(consume, entry))
        certificate = self.bound(core, 'entry', [], limit=100)
        self.assertEqual(certificate['peak_bound_bytes'], 100)
        for failure, expected_peak in ((None, 92), (1, 100)):
            with self.subTest(failure=failure):
                observed = execute_program(core, 'entry', [], allocation_fail_at=failure)
                self.assertEqual(observed['resources']['peak_bytes'], expected_peak)
                self.assert_observation(certificate, observed)

    def test_scalar_call_result_bounds_are_specialized_to_exact_entry_values(self):
        child = f('plus_one', [('n', 'usize')], ['usize'], ['trap'], [
            b('start', [('n', 'usize')], [c('one', 'usize', 1),
                i('int.add.checked', ['n', 'one'], [('result', 'usize')])], ret('result'))])
        entry = f('entry', [('n', 'usize')], [], ['alloc', 'trap'], [
            b('start', [('n', 'usize')], [i('call', ['n'], [('size', 'usize')], function='plus_one'),
                i('buffer.new', ['size'], [('owner', 'buffer')]), i('owner.drop', ['owner'])], ret())])
        core = verify_core(v7(child, entry))
        digests = set()
        for value in (0, 7, 15):
            certificate = self.bound(core, 'entry', [value])
            self.assertEqual(certificate['peak_bound_bytes'], value + 1)
            self.assertEqual(certificate['arguments'], [value])
            digests.add(certificate['sha256'])
            self.assert_observation(certificate, execute_program(core, 'entry', [value]))
        self.assertEqual(len(digests), 3)

    def test_shared_borrowed_actuals_and_owned_actual_do_not_double_count(self):
        core = verify_core(borrowed_owned())
        certificate = self.bound(core, 'entry', [], limit=18)
        self.assertEqual(certificate['peak_bound_bytes'], 18)
        observed = execute_program(core, 'entry', [])
        self.assertEqual(observed['resources']['peak_bytes'], 18)
        self.assertEqual(observed['resources']['live_bytes'], 0)
        self.assert_observation(certificate, observed)

    def test_borrowed_unknown_extent_never_becomes_zero_or_caller_promise(self):
        raw = borrowed_owned()
        child_ops = raw['functions'][0]['blocks'][0]['ops']
        child_ops[2]['args'] = ['ignored']  # allocation depends on external borrowed len
        core = verify_core(raw)
        with self.assertRaisesRegex(HIAHeapBoundRejected, 'allocator extent'):
            self.bound(core, 'entry', [])

    def test_return_join_keeps_largest_owner_extent(self):
        child = f('choose', [('flag', 'bool')], ['buffer'], ['alloc', 'trap'], [
            b('start', [('flag', 'bool')], [], branch('flag', ('small',), ('large',))),
            b('small', [], [c('two', 'usize', 2), i('buffer.new', ['two'], [('a', 'buffer')])], ret('a')),
            b('large', [], [c('nine', 'usize', 9), i('buffer.new', ['nine'], [('z', 'buffer')])], ret('z'))])
        entry = f('entry', [('flag', 'bool')], [], ['alloc', 'trap'], [
            b('start', [('flag', 'bool')], [c('three', 'usize', 3),
                i('buffer.new', ['three'], [('kept', 'buffer')]),
                i('call', ['flag'], [('selected', 'buffer')], function='choose'),
                i('owner.drop', ['selected']), i('owner.drop', ['kept'])], ret())])
        core = verify_core(v7(child, entry))
        for flag, actual_peak in ((True, 5), (False, 12)):
            certificate = self.bound(core, 'entry', [flag], limit=12)
            self.assertEqual(certificate['peak_bound_bytes'], 12)
            actual = execute_program(core, 'entry', [flag])
            self.assertEqual(actual['resources']['peak_bytes'], actual_peak)
            self.assert_observation(certificate, actual)

    def test_callee_without_normal_return_preserves_its_live_trap_prefix(self):
        child = f('stop', [], [], ['alloc', 'trap'], [b('start', [], [
            c('four', 'usize', 4), i('buffer.new', ['four'], [('held', 'buffer')])],
            {'op': 'trap', 'code': 'user'})])
        entry = f('entry', [], [], ['alloc', 'trap'], [b('start', [], [
            c('two', 'usize', 2), i('buffer.new', ['two'], [('kept', 'buffer')]),
            i('call', [], [], function='stop'), c('hundred', 'usize', 100),
            i('buffer.new', ['hundred'], [('unreached', 'buffer')]),
            i('owner.drop', ['unreached']), i('owner.drop', ['kept'])], ret())])
        core = verify_core(v7(child, entry))
        certificate = self.bound(core, 'entry', [], limit=6)
        self.assertEqual(certificate['peak_bound_bytes'], 6)
        with self.assertRaises(HIAProgramTrap) as failure:
            execute_program(core, 'entry', [])
        self.assertEqual(failure.exception.report['resources']['live_bytes'], 6)
        self.assert_observation(certificate, failure.exception.report)

    def test_chain_and_all_module_cycles_remain_structured_unknown(self):
        chain = nested_owned()
        chain['functions'].append(f('unused_chain', [('root', 'chain')], [], ['alloc'], [
            b('start', [('root', 'chain')], [i('owner.drop', ['root'])], ret())]))
        raw_cases = [(chain, 'entry', [], 'E_HIA_BUDGET_PROFILE')]
        for document, name, arguments in ((cyclic_control_flow(), 'cycle', [False, 1]),
                                           (cyclic_calls(), 'one', [1])):
            document['schema'] = 'hepta.hia.program.v7'
            raw_cases.append((document, name, arguments, 'E_HIA_BUDGET_UNBOUNDED'))
        for document, name, arguments, code in raw_cases:
            with self.subTest(function=name, code=code):
                checked = verify_core(document)
                with self.assertRaisesRegex(HIAHeapBoundRejected, code):
                    self.bound(checked, name, arguments)
                with self.assertRaisesRegex(HIAStaticBudgetRejected, code):
                    analyze_static_budget(checked)

    def test_canonical_alias_refusal_still_precedes_resource_estimation(self):
        raw = nested_owned()
        entry = raw['functions'][-1]
        entry['effects'].append('read')
        entry['blocks'][0]['ops'].insert(4, i('borrow.read', ['passed'], [('live', 'readbuf')]))
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_LOAN'):
            self.bound(raw, 'entry', [])

    def test_argument_policy_and_context_work_limits_fail_closed(self):
        for arguments in ([True, 7, 73], [0, -1, 73], [0, 7.0, 73], [0, 7, 256], [0], 'not-args'):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(HIAHeapBoundRejected, 'E_HIA_BUDGET_INPUT'):
                    self.bound(self.nominal, 'partial_case', arguments)
        for limit in (True, -1, 1.0, None):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(HIAHeapBoundRejected, 'E_HIA_BUDGET_POLICY'):
                    self.bound(self.nominal, 'partial_case', [0, 7, 73], limit=limit)
        core = verify_core(nested_owned())
        for variable in ('_FINITE_MAX_CONTEXTS', '_FINITE_MAX_TRANSFER_STEPS', '_FINITE_MAX_ANALYSIS_DEPTH'):
            with self.subTest(variable=variable), patch('hepta.hia_heap_bound.' + variable, 1):
                with self.assertRaisesRegex(HIAHeapBoundRejected, 'E_HIA_BUDGET_LIMIT'):
                    self.bound(core, 'entry', [])

    def test_caller_mutation_cannot_rebind_analyzed_argument_snapshot(self):
        from hepta.hia_heap_bound import _FiniteInvocationAnalysis

        entry = f('entry', [('n', 'usize')], [], ['alloc', 'trap'], [
            b('start', [('n', 'usize')], [i('buffer.new', ['n'], [('owned', 'buffer')]),
                i('owner.drop', ['owned'])], ret())])
        core = verify_core(v7(entry))
        arguments = [7]
        consumed_arguments = []
        original_invoke = _FiniteInvocationAnalysis.invoke

        def mutate_caller_before_analysis(analysis, function, bounds):
            # Deterministic simulation of the caller modifying its own list
            # after admission captures the values, while analysis is active.
            arguments[0] = 100
            consumed_arguments.append(bounds)
            return original_invoke(analysis, function, bounds)

        with patch.object(_FiniteInvocationAnalysis, 'invoke', mutate_caller_before_analysis):
            certificate = self.bound(core, 'entry', arguments, limit=7)
        self.assertEqual(arguments, [100])
        self.assertEqual(consumed_arguments, [(7,)])
        self.assertEqual(certificate['arguments'], [7])
        self.assertEqual(certificate['peak_bound_bytes'], 7)
        actual = execute_program(core, 'entry', certificate['arguments'])
        self.assertEqual(actual['resources']['peak_bytes'], 7)
        self.assert_observation(certificate, actual)


if __name__ == '__main__':
    unittest.main()
