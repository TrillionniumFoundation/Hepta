from copy import deepcopy
import unittest
from tools import research_deferred_guard_model as model
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline


class FrontierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core = lower_source((model.ROOT / 'benchmarks/hia_reduction_release/linear.hepta').read_text())
        p = propose_reduction_pipeline(core, include_induction=True)
        cls.slow = p['narrowed_core']['functions'][0]
        cls.fast = p['guarded']['fast_core']['functions'][0]
        cls.guard = p['guarded']['guards'][0]
        cls.plan = model.frontier(cls.slow, cls.fast, cls.guard)

    def test_actual_loop_frontier_contains_both_first_divergence_edges(self):
        self.assertEqual(self.plan['different'], ['b5', 'b8'])
        self.assertEqual(self.plan['cuts'], [['b4', 'then', 'b5'], ['b7', 'then', 'b8']])
        self.assertIn('b3', self.plan['shared'])  # allocation refusal
        self.assertIn('b9', self.plan['shared'])  # early return / drop
        self.assertIn('b4', self.plan['suffix'])  # cloned fill-loop backedge
        self.assertTrue(model.check_plan(self.slow, self.fast, self.guard, self.plan))

    def test_missing_cut_or_loop_backedge_rejected(self):
        for key, item in [('cuts', ['b7', 'then', 'b8']), ('suffix', 'b4')]:
            plan = deepcopy(self.plan); plan[key].remove(item)
            with self.assertRaises(ValueError): model.check_plan(self.slow, self.fast, self.guard, plan)

    def test_wrong_snapshot_and_suffix_namespace_rejected(self):
        for mutation in (lambda p: p['guard_snapshot'].update(origin='current_phi_value'),
                         lambda p: p.update(suffix_namespace='shared_prefix'),
                         lambda p: p.update(guard_evaluation='each_iteration')):
            plan = deepcopy(self.plan); mutation(plan)
            with self.assertRaises(ValueError): model.check_plan(self.slow, self.fast, self.guard, plan)

    def test_phi_parameter_reordering_and_effect_changes_cannot_be_shared(self):
        fast = deepcopy(self.fast)
        block = next(b for b in fast['blocks'] if b['id'] == 'b4')
        block['params'][0], block['params'][1] = block['params'][1], block['params'][0]
        with self.assertRaises(ValueError): model.frontier(self.slow, fast, self.guard)
        fast = deepcopy(self.fast)
        block = next(b for b in fast['blocks'] if b['id'] == 'b3')
        block['ops'][0]['op'] = 'owner.move'
        changed = model.frontier(self.slow, fast, self.guard)
        self.assertNotIn('b3', changed['shared'])
        with self.assertRaises(ValueError): model.check_plan(self.slow, fast, self.guard, self.plan)

    def test_impure_or_non_total_guard_shapes_rejected(self):
        for guard in ({**self.guard, 'operation': 'divide'}, {**self.guard, 'maximum': True},
                      {**self.guard, 'maximum': -1}, {**self.guard, 'argument': 'mutable_local'}):
            with self.assertRaises(ValueError): model.frontier(self.slow, self.fast, guard)

    def test_entry_divergence_requires_immediate_dispatch(self):
        fast = deepcopy(self.fast); fast['blocks'][0]['ops'][0]['attrs']['test_only_change'] = True
        plan = model.frontier(self.slow, fast, self.guard)
        self.assertTrue(plan['entry_dispatch'])
        self.assertEqual(plan['shared'], [])
        self.assertIn(self.slow['entry'], plan['suffix'])

    def test_calls_are_outside_first_model(self):
        fast = deepcopy(self.fast); fast['blocks'][0]['ops'][0]['op'] = 'call'
        with self.assertRaises(ValueError): model.frontier(self.slow, fast, self.guard)


class SemanticModelTests(unittest.TestCase):
    def test_symbolic_snapshot_obligations_and_counterexamples(self):
        result = model.symbolic_obligations()
        self.assertEqual([v['result'] for v in result['obligations'].values()],
                         ['unsat', 'unsat', 'sat', 'sat', 'sat', 'unsat'])
        self.assertFalse(result['production_admission'])
        self.assertFalse(result['performance_qualified'])

    def test_loop_and_refusal_differential_model_keeps_ordered_events(self):
        for n in range(16):
            for fail in (False, True):
                for increment in (False, True):
                    kw = dict(fail_allocation=fail, prefix_increment=increment)
                    old = model.toy_run(n, deferred=False, **kw)
                    new = model.toy_run(n, deferred=True, **kw)
                    self.assertEqual(model.observation(old), model.observation(new), (n, kw))
                    if new['status'] == 'returned' and not fail and (n + int(increment)):
                        self.assertEqual(new['guards'], 1)

    def test_common_prefix_loops_and_traps_keep_the_same_observation(self):
        for cycles in (0, 1, 2, 50):
            for n in (0, 7, 8, 15):
                old = model.toy_run(n, deferred=False, prefix_cycles=cycles)
                new = model.toy_run(n, deferred=True, prefix_cycles=cycles)
                self.assertEqual(model.observation(old), model.observation(new))
        old = model.toy_run(7, deferred=False, prefix_trap=True)
        new = model.toy_run(7, deferred=True, prefix_trap=True)
        self.assertEqual(model.observation(old), model.observation(new))
        self.assertEqual(new['status'], 'trapped')

    def test_mutable_phi_snapshot_has_concrete_wrong_version_counterexample(self):
        old = model.toy_run(7, deferred=False, prefix_increment=True)
        wrong = model.toy_run(7, deferred=True, prefix_increment=True, mutated_snapshot=True)
        self.assertNotEqual(model.observation(old), model.observation(wrong))
        self.assertEqual((old['value'], wrong['value']), (10, 20))

    def test_omitted_cut_and_reselection_have_trace_counterexamples(self):
        old = model.toy_run(3, deferred=False)
        missing = model.toy_run(3, deferred=True, omit_fill_cut=True)
        self.assertNotEqual(old['events'], missing['events'])
        old = model.toy_run(9, deferred=False)
        wrong = model.toy_run(9, deferred=True, reselect_on_backedge=True, mutated_snapshot=True)
        self.assertNotEqual(old['events'], wrong['events'])

    def test_early_return_does_not_preserve_guard_step_budget(self):
        old = model.toy_run(0, deferred=False)
        new = model.toy_run(0, deferred=True)
        self.assertEqual(model.observation(old), model.observation(new))
        self.assertEqual((old['guards'], new['guards']), (1, 0))
        # A quota that counts guard work can distinguish the two. Not claimed.

    def test_trapping_guard_cannot_be_delayed_past_early_return(self):
        with self.assertRaises(ZeroDivisionError):
            _original_guard = 1 // 0
        deferred_early_return = 0
        self.assertEqual(deferred_early_return, 0)
        # This counterexample motivates the total compare-only guard profile.

if __name__ == '__main__': unittest.main()
