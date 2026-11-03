"""Actual-Core positive and well-typed adversarial deferred-guard checks."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_reduction import propose_reduction_pipeline
from hepta.hia_guarded_optimization import propose_guarded_reduction
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools import check_deferred_guard_candidate as checker

try:
    import z3
except ImportError:
    z3 = None

ROOT = Path(__file__).resolve().parents[1]


def block_for(proposal, namespace, source):
    row = next(row for row in proposal['layout'][namespace] if row['source_block'] == source)
    return next(block for block in proposal['candidate_core']['functions'][0]['blocks']
                if block['id'] == row['candidate_block'])


def guard_for(proposal, source='b4'):
    row = next(row for row in proposal['layout']['guards'] if row['source_block'] == source)
    return next(block for block in proposal['candidate_core']['functions'][0]['blocks']
                if block['id'] == row['candidate_block'])


class CheckerFixture:
    @classmethod
    def setUpClass(cls):
        cls.base = lower_source((ROOT / 'benchmarks/hia_reduction_release/linear.hepta').read_text())
        cls.reduction = propose_reduction_pipeline(cls.base, maximum=4, include_induction=True)
        # Only test-fixture construction uses the untrusted proposer. The
        # checker must not import or call it or its plan helpers.
        cls.proposal = propose_deferred_guard(cls.base, cls.reduction)

    def reject(self, proposal, *, typed=True, reason=None):
        if typed:
            verify_program(proposal['candidate_core'])
        result = checker.check_deferred_guard(self.base, proposal)
        self.assertEqual(result['status'], 'rejected', result)
        self.assertEqual(result['authority'], 'DENY_ALL')
        self.assertFalse(result['production_admission'])
        self.assertFalse(result['native_admission'])
        if reason is not None:
            self.assertIn(reason, result['reason'])
        return result


class StructuralCheckerTests(CheckerFixture, unittest.TestCase):
    def test_wrong_snapshot_phi_operand_is_well_typed_but_rejected(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'shared', 'b2')
        b['term']['args'][-1] = b['ops'][-1]['out'][0]['name']  # zero, not original input
        self.reject(p, reason='snapshot propagation')

    def test_frontier_snapshot_cannot_use_current_loop_value(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'shared', 'b4')
        b['term']['then']['args'][-1] = b['params'][-2]['name']
        self.reject(p, reason='snapshot propagation')

    def test_original_shared_phi_operands_cannot_be_reordered(self):
        p = deepcopy(self.proposal)
        args = block_for(p, 'shared', 'b2')['term']['args']
        args[0], args[4] = args[4], args[0]  # two usize values, identical type signature
        self.reject(p, reason='phi operand order')

    def test_guard_must_route_original_ordered_parameters(self):
        p = deepcopy(self.proposal)
        args = guard_for(p)['term']['then']['args']
        args[0], args[4] = args[4], args[0]
        self.reject(p, reason='original parameter routing')

    def test_guard_side_reversal_is_not_a_type_error(self):
        p = deepcopy(self.proposal)
        term = guard_for(p)['term']
        term['then'], term['else'] = term['else'], term['then']
        self.reject(p, reason='guard side')

    def test_guard_cannot_skip_target_or_repeat_loop_header(self):
        p = deepcopy(self.proposal)
        guard_for(p)['term']['then']['target'] = block_for(p, 'fast', 'b4')['id']
        self.reject(p, reason='guard side')

    def test_suffix_cannot_cross_to_other_version(self):
        p = deepcopy(self.proposal)
        block_for(p, 'fast', 'b8')['term']['target'] = block_for(p, 'slow', 'b7')['id']
        self.reject(p, reason='terminator')

    def test_suffix_cannot_reenter_shared_prefix_and_reselect(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b8')
        b['term']['target'] = block_for(p, 'shared', 'b7')['id']
        b['term']['args'].append(b['params'][0]['name'])
        self.reject(p, reason='terminator')

    def test_suffix_phi_mutation_is_checked_too(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b8')
        b['term']['args'][-1] = b['params'][-1]['name']
        self.reject(p, reason='phi operand order')

    def test_missing_second_cut_is_rejected(self):
        p = deepcopy(self.proposal)
        p['layout']['guards'].pop()
        self.reject(p, reason='complete cut set')

    def test_duplicate_source_and_duplicate_destination_maps_rejected(self):
        for field in ('source_block', 'candidate_block'):
            with self.subTest(field=field):
                p = deepcopy(self.proposal)
                p['layout']['shared'][1][field] = p['layout']['shared'][0][field]
                self.reject(p)

    def test_wrong_source_claim_is_not_used_as_a_proof(self):
        p = deepcopy(self.proposal)
        a, b = p['layout']['fast'][0], p['layout']['fast'][2]
        a['candidate_block'], b['candidate_block'] = b['candidate_block'], a['candidate_block']
        self.reject(p)

    def test_missing_suffix_loop_header_is_rejected(self):
        p = deepcopy(self.proposal)
        p['layout']['fast'].pop(0)
        self.reject(p, reason='inventory length')

    def test_unaccounted_actual_block_is_rejected(self):
        p = deepcopy(self.proposal)
        p['layout']['shared'].pop()
        self.reject(p, reason='inventory length')

    def test_wrong_comparison_constant_operand_and_operator(self):
        for mutation in (
            lambda b: b['ops'][0]['attrs'].update(value=5),
            lambda b: b['ops'][1].update(op='compare.lt'),
            lambda b: b['ops'][1]['args'].reverse(),
            lambda b: b['ops'][1]['args'].__setitem__(0, b['params'][-2]['name']),
        ):
            p = deepcopy(self.proposal)
            mutation(guard_for(p))
            self.reject(p)

    def test_signed_guard_with_explicit_cast_is_well_typed_but_rejected(self):
        p = deepcopy(self.proposal)
        b = guard_for(p)
        b['ops'][0]['out'][0]['type'] = 'isize'
        b['ops'].insert(1, {'op': 'int.cast', 'args': [b['params'][-1]['name']],
                            'out': [{'name': 'signed_snapshot', 'type': 'isize'}],
                            'attrs': {'mode': 'wrap'}})
        b['ops'][2]['args'][0] = 'signed_snapshot'
        self.reject(p, reason='only const and compare.le')

    def test_shared_attributes_cannot_change(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'shared', 'b3')
        next(op for op in b['ops'] if op['op'] == 'const')['attrs']['value'] += 1
        self.reject(p, reason='attribute or effect changed')

    def test_suffix_cast_attributes_cannot_change(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b5')
        next(op for op in b['ops'] if op['op'] == 'int.cast')['attrs']['mode'] = 'checked'
        self.reject(p, reason='attribute or effect changed')

    def test_resource_operation_actual_index_must_match(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b5')
        next(op for op in b['ops'] if op['op'] == 'buffer.store')['args'][1] = b['params'][0]['name']
        self.reject(p, reason='attribute or effect changed')

    def test_resource_effect_cannot_be_deleted_even_when_lifetime_remains_valid(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b5')
        b['ops'] = [op for op in b['ops'] if op['op'] != 'buffer.store']
        self.reject(p, reason='operation count')

    def test_real_core_verifier_rejects_broken_loan_lifetime(self):
        p = deepcopy(self.proposal)
        b = block_for(p, 'fast', 'b5')
        b['ops'] = [op for op in b['ops'] if op['op'] != 'loan.end']
        result = self.reject(p, typed=False)
        self.assertIn('E_HIA_', result['reason'])

    def test_module_and_function_interface_cannot_change(self):
        for mutate in (
            lambda p: p['candidate_core'].update(module='other_module'),
            lambda p: p['candidate_core']['functions'][0]['effects'].reverse(),
        ):
            p = deepcopy(self.proposal); mutate(p)
            self.reject(p, reason='interface changed')

    def test_actual_source_and_proof_identities_are_bound(self):
        for target in ('proposal', 'reduction', 'guarded'):
            p = deepcopy(self.proposal)
            part = p if target == 'proposal' else p['reduction'] if target == 'reduction' else p['reduction']['guarded']
            part['base_sha256'] = '0' * 64
            self.reject(p)
        base = self.base.as_dict(); base['module'] = 'stale_source'
        result = checker.check_deferred_guard(base, self.proposal)
        self.assertEqual(result['status'], 'rejected', result)

    def test_receipt_or_extra_claim_cannot_substitute_for_checking(self):
        p = deepcopy(self.proposal)
        p['verification'] = {'status': 'checked', 'checker_sha256': checker.deferred_guard_checker_identity()}
        self.reject(p, reason='exact fields')

    def test_claimed_change_list_cannot_hide_actual_difference(self):
        p = deepcopy(self.proposal)
        p['reduction']['guarded']['changes'].pop()
        self.reject(p, reason='changed-operation inventory')

    def test_wire_subclasses_cycles_and_extra_layout_fields_fail_closed(self):
        class Forged(dict):
            pass
        self.assertEqual(checker.check_deferred_guard(self.base, Forged(self.proposal))['status'], 'rejected')
        p = deepcopy(self.proposal); p['layout']['claim'] = p
        self.assertEqual(checker.check_deferred_guard(self.base, p)['status'], 'rejected')
        p = deepcopy(self.proposal); p['layout']['proof'] = True
        self.reject(p, reason='exact fields')

    def test_guard_other_than_original_usize_parameter_rejected(self):
        p = deepcopy(self.proposal)
        p['reduction']['guarded']['guards'][0]['argument'] = self.base.as_dict()['functions'][0]['params'][1]['name']
        self.reject(p, reason='original immutable usize')

    def test_missing_solver_and_unexpected_proof_failure_are_unknown(self):
        with patch.dict('sys.modules', {'z3': None}):
            result = checker.check_deferred_guard(self.base, self.proposal)
        self.assertEqual(result['status'], 'unknown', result)
        self.assertFalse(result['claims']['fresh_reduction_proofs_checked'])
        with patch.object(checker, '_verify_frozen', side_effect=RuntimeError('test solver failure')):
            result = checker.check_deferred_guard(self.base, self.proposal)
        self.assertEqual(result['status'], 'unknown', result)
        self.assertEqual(result['authority'], 'DENY_ALL')

    def test_first_profile_shape_limits_fail_closed(self):
        slow = self.reduction['narrowed_core']['functions'][0]
        fast = self.reduction['guarded']['fast_core']['functions'][0]
        guard = self.reduction['guarded']['guards'][0]
        with self.assertRaisesRegex(ValueError, 'no actual block differences'):
            checker._derive_regions(slow, slow, guard)
        divergent = deepcopy(fast)
        divergent['blocks'][0]['ops'][0]['attrs']['unsupported'] = True
        with self.assertRaisesRegex(ValueError, 'entry-divergent'):
            checker._derive_regions(slow, divergent, guard)
        calls = deepcopy(slow); calls['blocks'][0]['ops'][0]['op'] = 'call'
        with self.assertRaisesRegex(ValueError, 'calls and recursion'):
            checker._derive_regions(calls, fast, guard)
        many = deepcopy(slow); many['blocks'] *= 15
        with self.assertRaisesRegex(ValueError, 'at most 128'):
            checker._derive_regions(many, fast, guard)


@unittest.skipUnless(z3 is not None and z3.get_version_string() == '4.15.4', 'pinned Z3 4.15.4 required')
class FreshProofTests(CheckerFixture, unittest.TestCase):
    def test_real_linear_and_affine_candidates_checked_with_denials(self):
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / ('benchmarks/hia_reduction_release/' + workload + '.hepta')).read_text())
            proposal = propose_deferred_guard(base, propose_reduction_pipeline(base, maximum=4, include_induction=True))
            report = checker.check_deferred_guard(base, proposal)
            self.assertEqual(report['status'], 'checked', report)
            self.assertEqual(report['structure']['candidate_blocks'], 21)
            self.assertEqual(report['structure']['cut_set'], [['b4', 'then', 'b5'], ['b7', 'then', 'b8']])
            self.assertEqual(report['candidate_sha256'], verify_program(proposal['candidate_core']).sha256)
            self.assertEqual(report['checker_sha256'], checker.deferred_guard_checker_identity())
            self.assertTrue(report['claims']['fresh_reduction_proofs_checked'])
            for flag in ('native_admission', 'production_admission', 'performance_qualified',
                         'vm_steps_preserved', 'quota_equivalence'):
                self.assertFalse(report[flag])
            self.assertEqual(report['authority'], 'DENY_ALL')

    def test_alpha_renaming_is_reconstructed_without_proposer_or_planner(self):
        p = deepcopy(self.proposal)
        fn = p['candidate_core']['functions'][0]
        keep = {param['name'] for param in fn['params']}
        definitions = [param['name'] for b in fn['blocks'] for param in b['params']]
        definitions += [out['name'] for b in fn['blocks'] for op in b['ops'] for out in op['out']]
        values = {name: name if name in keep else 'totally_new_' + str(i)
                  for i, name in enumerate(reversed(definitions))}
        bids = {b['id']: 'renamed_block_' + str(i) for i, b in enumerate(reversed(fn['blocks']))}
        for b in fn['blocks']:
            b['id'] = bids[b['id']]
            for param in b['params']: param['name'] = values[param['name']]
            for op in b['ops']:
                op['args'] = [values[a] for a in op['args']]
                for out in op['out']: out['name'] = values[out['name']]
            term = b['term']
            if term['op'] == 'ret': term['values'] = [values[a] for a in term['values']]
            if term['op'] == 'branch': term['cond'] = values[term['cond']]
            edges = [term] if term['op'] == 'jump' else [term['then'], term['else']] if term['op'] == 'branch' else []
            for edge in edges:
                edge['target'] = bids[edge['target']]
                edge['args'] = [values[a] for a in edge['args']]
        fn['entry'] = bids[fn['entry']]; fn['blocks'].reverse()
        for namespace in ('shared', 'fast', 'slow', 'guards'):
            for row in p['layout'][namespace]: row['candidate_block'] = bids[row['candidate_block']]
            p['layout'][namespace].reverse()
        verify_program(p['candidate_core'])
        with patch('tools.experimental_deferred_guard_proposer.propose_deferred_guard', side_effect=AssertionError('untrusted proposer called')), \
             patch('tools.research_deferred_guard_model.frontier', side_effect=AssertionError('design planner called')):
            report = checker.check_deferred_guard(self.base, p)
        self.assertEqual(report['status'], 'checked', report)

    def test_every_call_rechecks_actual_candidate_and_both_proof_stages(self):
        with patch.object(checker, '_verify_frozen', wraps=checker._verify_frozen) as proofs, \
             patch.object(checker, 'verify_program', wraps=verify_program) as core:
            for _ in range(2):
                self.assertEqual(checker.check_deferred_guard(self.base, self.proposal)['status'], 'checked')
            self.assertEqual(proofs.call_count, 2)
            self.assertEqual(core.call_count, 2)

    def test_valid_structure_does_not_substitute_for_scalar_proof(self):
        reduction = deepcopy(self.reduction)
        narrowed = reduction['narrowed_core']
        b = next(b for b in narrowed['functions'][0]['blocks'] if b['id'] == 'b3')
        next(op for op in b['ops'] if op['op'] == 'const')['attrs']['value'] += 1
        reduction['guarded'] = propose_guarded_reduction(narrowed, maximum=4, include_induction=True)
        proposal = propose_deferred_guard(self.base, reduction)
        result = self.reject(proposal, reason='fresh reduction proof')
        self.assertTrue(result['claims']['actual_core_structure_checked'])
        self.assertFalse(result['claims']['fresh_reduction_proofs_checked'])

    def test_valid_structure_does_not_substitute_for_guarded_induction(self):
        reduction = deepcopy(self.reduction)
        reduction['guarded']['guards'][0]['maximum'] = 2**64 - 1
        for blocks in reduction['guarded']['invariants'].values():
            for constraints in blocks.values():
                for constraint in constraints:
                    if constraint['op'] == 'le_const': constraint['limit'] = 2**64 - 1
        proposal = propose_deferred_guard(self.base, reduction)
        result = self.reject(proposal, reason='fresh reduction proof')
        self.assertTrue(result['claims']['actual_core_structure_checked'])
        self.assertFalse(result['claims']['fresh_reduction_proofs_checked'])

    def test_shared_prefix_loop_propagates_snapshot_on_every_backedge(self):
        source = (ROOT / 'benchmarks/hia_reduction_release/linear.hepta').read_text()
        source = source.replace('    match try_buffer(size)',
                                '    for prefix in 0..(3 as usize) { let ignored:u32=seed; }\n    match try_buffer(size)')
        base = lower_source(source)
        proposal = propose_deferred_guard(base, propose_reduction_pipeline(base, maximum=4, include_induction=True))
        result = checker.check_deferred_guard(base, proposal)
        self.assertEqual(result['status'], 'checked', result)
        backedge = block_for(proposal, 'shared', 'b3')
        backedge['term']['args'][-1] = backedge['params'][-2]['name']
        verify_program(proposal['candidate_core'])
        result = checker.check_deferred_guard(base, proposal)
        self.assertEqual(result['status'], 'rejected', result)
        self.assertIn('snapshot propagation', result['reason'])

    def test_caller_mutation_cannot_change_frozen_candidate_under_check(self):
        proposal = deepcopy(self.proposal)
        before = verify_program(proposal['candidate_core']).sha256
        freeze = checker._freeze_pipeline
        def mutate_caller(base, reduction):
            guard_for(proposal)['ops'][0]['attrs']['value'] = 999
            return freeze(base, reduction)
        with patch.object(checker, '_freeze_pipeline', side_effect=mutate_caller):
            result = checker.check_deferred_guard(self.base, proposal)
        self.assertEqual(result['status'], 'checked', result)
        self.assertEqual(result['candidate_sha256'], before)
        self.assertNotEqual(verify_program(proposal['candidate_core']).sha256, before)
        self.assertEqual(checker.check_deferred_guard(self.base, proposal)['status'], 'rejected')

    def test_stale_checker_identity_cannot_report_checked(self):
        with patch.object(checker, 'deferred_guard_checker_identity', side_effect=['a' * 64, 'b' * 64]):
            report = checker.check_deferred_guard(self.base, self.proposal)
        self.assertEqual(report['status'], 'unknown', report)
        self.assertIn('implementation changed', report['reason'])
        self.assertFalse(report['claims']['fresh_reduction_proofs_checked'])

    def test_timeout_is_unknown_and_no_backend_or_admission_runs(self):
        with patch('hepta.hia_program_llvm.build_program_native') as compiler, \
             patch('hepta.hia_reduction._admit') as admission:
            result = checker.check_deferred_guard(self.base, self.proposal,
                                                 policy={**DEFAULT_POLICY, 'timeout_ms': 0})
            compiler.assert_not_called(); admission.assert_not_called()
        self.assertEqual(result['status'], 'unknown', result)
        self.assertFalse(result['claims']['fresh_reduction_proofs_checked'])


if __name__ == '__main__':
    unittest.main()
