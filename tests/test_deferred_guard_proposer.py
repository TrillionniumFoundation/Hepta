"""Actual Core/VM exploratory tests; never a native or quota qualification."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program
from hepta import hia_program_runtime as vm
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools.research_deferred_guard_model import ROOT


def observed_run(program, arguments, **limits):
    trace = []
    operation = vm._Machine.operation
    def snapshot(value):
        if isinstance(value, vm._Owner):
            return ('owner', value.ident, bytes(value.data), value.active)
        if isinstance(value, vm._View):
            return ('view', snapshot(value.parent), value.mutable, value.active)
        return value
    def observed(machine, ins, env, depth):
        tracked = ins['op'].startswith(('buffer.', 'borrow.', 'loan.', 'owner.'))
        event = None
        if tracked:
            event = {'op': ins['op'], 'attrs': deepcopy(ins['attrs']),
                     'before': [snapshot(env[name]) for name in ins['args']]}
            trace.append(event)
        try:
            result = operation(machine, ins, env, depth)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            if event is not None:
                event['failure'] = (type(error).__name__, error.code)
            raise
        if event is not None:
            event['after'] = [snapshot(env[out['name']]) for out in ins['out']]
            event['resources'] = machine.resources()
        return result
    with patch.object(vm._Machine, 'operation', observed):
        try:
            return vm.execute_program(program, 'calculate', arguments, **limits), trace
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            return error.report, trace


class DeferredProposerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {}
        for workload in ('linear', 'affine'):
            base = lower_source((ROOT / ('benchmarks/hia_reduction_release/' + workload + '.hepta')).read_text())
            reduction = propose_reduction_pipeline(base, maximum=4, include_induction=True)
            proposal = propose_deferred_guard(base, reduction)
            cls.cases[workload] = (base, reduction, proposal, reduction_program(base, reduction))

    def test_actual_candidates_pass_resource_and_ssa_verifier_with_closed_frontier(self):
        for base, reduction, proposal, old in self.cases.values():
            candidate = verify_program(proposal['candidate_core'])
            self.assertNotEqual(candidate.sha256, old.sha256)
            self.assertEqual(len(candidate.as_dict()['functions'][0]['blocks']), 21)
            self.assertEqual({(g['source_block'], g['target_block']) for g in proposal['layout']['guards']},
                             {('b4', 'b5'), ('b7', 'b8')})
            self.assertEqual(candidate.as_dict()['functions'][0]['params'], base.as_dict()['functions'][0]['params'])

    def test_actual_fast_slow_loops_refusals_and_ordered_resource_trace(self):
        count = 0
        for workload, (_, _, proposal, old) in self.cases.items():
            for n in (0, 1, 4, 5, 17):
                for seed in (0, 5471, 2**32 - 1):
                    for fail in (None, 1):
                        a, trace_a = observed_run(old, [n, seed], allocation_fail_at=fail)
                        b, trace_b = observed_run(proposal['candidate_core'], [n, seed], allocation_fail_at=fail)
                        self.assertEqual((a['status'], a['values'], a['resources']),
                                         (b['status'], b['values'], b['resources']), (workload, n, seed, fail))
                        self.assertEqual(trace_a, trace_b, (workload, n, seed, fail))
                        count += 1
        self.assertEqual(count, 60)

    def test_real_machine_range_refusal_and_heap_budget_keep_resource_trace(self):
        for _, _, proposal, old in self.cases.values():
            for n in (2**63, 2**64 - 1):
                a, ta = observed_run(old, [n, 7])
                b, tb = observed_run(proposal['candidate_core'], [n, 7])
                self.assertEqual((a['values'], a['resources'], ta), (b['values'], b['resources'], tb))
            a, ta = observed_run(old, [17, 7], max_heap_bytes=4)
            b, tb = observed_run(proposal['candidate_core'], [17, 7], max_heap_bytes=4)
            self.assertEqual(a['status'], 'budget_exceeded')
            self.assertEqual((a['status'], a['resources'], ta), (b['status'], b['resources'], tb))

    def test_real_shared_prefix_trap_is_not_skipped_by_empty_path(self):
        source = (ROOT / 'benchmarks/hia_reduction_release/linear.hepta').read_text()
        source = source.replace('    match try_buffer(size)',
                                '    let probe:u32=1/seed;\n    match try_buffer(size)')
        base = lower_source(source)
        reduction = propose_reduction_pipeline(base, maximum=4, include_induction=True)
        old = reduction_program(base, reduction)
        candidate = propose_deferred_guard(base, reduction)
        for n in (0, 1, 5):
            a, ta = observed_run(old, [n, 0])
            b, tb = observed_run(candidate['candidate_core'], [n, 0])
            self.assertEqual(a['status'], 'trapped')
            self.assertEqual(a['error']['code'], 'division_by_zero')
            self.assertEqual((a['status'], a['error'], a['resources'], ta),
                             (b['status'], b['error'], b['resources'], tb))

    def test_real_step_quota_counterexample_prevents_quota_equivalence_claim(self):
        for _, _, proposal, old in self.cases.values():
            a = vm.execute_program(old, 'calculate', [0, 7])
            b = vm.execute_program(proposal['candidate_core'], 'calculate', [0, 7])
            self.assertLess(b['steps'], a['steps'])
            vm.execute_program(proposal['candidate_core'], 'calculate', [0, 7], max_steps=b['steps'])
            with self.assertRaises(vm.HIAProgramBudgetExceeded):
                vm.execute_program(old, 'calculate', [0, 7], max_steps=b['steps'])

if __name__ == '__main__': unittest.main()
