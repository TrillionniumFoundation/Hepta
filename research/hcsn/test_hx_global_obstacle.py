"""Independent and adverse checks for full-state original-HX certificates."""
from dataclasses import replace
import unittest

try:
    from .hx_original import HXParams
    from .hx_global_obstacle import global_obstacle_enclosure, cashflow_tail_enclosure
    from .hx_interval_domain import boundary_domain_enclosure
    from .p0_global_obstacle_evidence import IndependentMPReference, independent_cell_checks
except ImportError:
    from hx_original import HXParams
    from hx_global_obstacle import global_obstacle_enclosure, cashflow_tail_enclosure
    from hx_interval_domain import boundary_domain_enclosure
    from p0_global_obstacle_evidence import IndependentMPReference, independent_cell_checks


NEGATIVE_Q0 = HXParams(r=.1, delta=.075, sigma=.2, alpha=.4,
    tax=.3999077379072307, xi=4., k=.2, maturity=3., coupon_total=5., face_total=20.)
POSITIVE_Q0 = replace(NEGATIVE_Q0, tax=.39990773048821086)
OVERFLOW = HXParams(r=.30, delta=.001, sigma=.03, xi=0.)
PASS = 'CERTIFIED_SINGLE_CROSSING_FIXED_DEBT_OBSTACLE'


class HXGlobalObstacleTests(unittest.TestCase):
    def assertContinuousProof(self, result):
        self.assertEqual(result['status'], PASS)
        self.assertTrue(result['complete_continuous_cover'])
        self.assertFalse(result['production_activation'])
        self.assertFalse(result['general_hx_parameter_domain_closed'])
        self.assertLess(result['base_domain']['local_cashflow']['upper'], 0)
        self.assertEqual(result['cells'][0]['lower'], 0.)
        self.assertEqual(result['cells'][-1]['upper'], result['tail']['start'])
        for first, second in zip(result['cells'], result['cells'][1:]):
            self.assertEqual(first['upper'], second['lower'])
        for cell in result['cells']:
            self.assertLess(cell['lower'], cell['upper'])
            if cell['kind'] == 'POSITIVE_SLOPE':
                self.assertGreater(cell['enclosure']['lower'], 0)
            else:
                self.assertEqual(cell['kind'], 'NEGATIVE_CASHFLOW')
                self.assertLess(cell['enclosure']['upper'], 0)
        self.assertGreater(result['tail']['qprime_uniform_lower_bound'], 0)

    def test_both_original_unresolved_points_gain_continuous_proofs(self):
        for p in (NEGATIVE_Q0, OVERFLOW):
            with self.subTest(p=p):
                self.assertEqual(boundary_domain_enclosure(p)['status'],
                                 'UNRESOLVED_OUTSIDE_SUFFICIENT_DOMAIN')
                self.assertContinuousProof(global_obstacle_enclosure(p))

    def test_cashflow_may_decrease_initially_without_invalidating_theorem(self):
        ref = IndependentMPReference(NEGATIVE_Q0)
        self.assertLess(ref.cashflow(ref.c.mpf(0)), 0)
        self.assertLess(ref.c.diff(ref.cashflow, ref.c.mpf(0)), -20)
        result = global_obstacle_enclosure(NEGATIVE_Q0)
        self.assertContinuousProof(result)
        self.assertEqual(result['cells'][0]['kind'], 'NEGATIVE_CASHFLOW')
        self.assertTrue(any(cell['kind'] == 'POSITIVE_SLOPE' for cell in result['cells']))

    def test_independent_differentiated_debt_checks_every_cell(self):
        for p in (HXParams(), NEGATIVE_Q0, OVERFLOW):
            with self.subTest(p=p):
                certificate = global_obstacle_enclosure(p)
                self.assertContinuousProof(certificate)
                checks = independent_cell_checks(certificate, p)
                self.assertTrue(all(row['contained'] for row in checks['cell_checks']))
                self.assertTrue(all(row['within_tail_bounds'] for row in checks['tail_checks']))

    def test_whole_quantization_boxes_keep_original_parameter_semantics(self):
        for dtype in ('fp32', 'bf16'):
            with self.subTest(dtype=dtype):
                certificate = global_obstacle_enclosure(OVERFLOW, dtype=dtype)
                self.assertContinuousProof(certificate)
                box = certificate['base_domain']['input_box']
                for side in ('lower', 'upper'):
                    corner = HXParams(**{name: item[side] for name, item in box.items()})
                    independent_cell_checks(certificate, corner)

    def test_same_encoded_opposite_local_sign_pair_stays_unresolved(self):
        self.assertEqual(global_obstacle_enclosure(POSITIVE_Q0)['status'],
                         'REFUTED_LOCAL_OBSTACLE')
        for dtype in ('fp32', 'bf16'):
            a = global_obstacle_enclosure(NEGATIVE_Q0, dtype=dtype)
            b = global_obstacle_enclosure(POSITIVE_Q0, dtype=dtype)
            self.assertEqual(a['base_domain']['input_box'], b['base_domain']['input_box'])
            for result in (a, b):
                self.assertEqual(result['status'], 'UNRESOLVED_LOCAL_SIGN')
                self.assertFalse(result['complete_continuous_cover'])

    def test_nonpositive_candidate_does_not_enter_positive_state_problem(self):
        p = HXParams(tax=.99, coupon_total=500., face_total=.0001)
        for dtype in (None, 'fp32', 'bf16'):
            result = global_obstacle_enclosure(p, dtype=dtype)
            self.assertEqual(result['status'], 'NO_POSITIVE_EQ12_CANDIDATE')
            self.assertFalse(result['complete_continuous_cover'])

    def test_budget_failures_are_unresolved_not_success_or_invalidity(self):
        for options, expected in (
            ({'max_cells': 1}, 'UNRESOLVED_CELL_BUDGET'),
            ({'max_depth': 0}, 'UNRESOLVED_CELL_DEPTH'),
        ):
            with self.subTest(options=options):
                result = global_obstacle_enclosure(NEGATIVE_Q0, **options)
                self.assertEqual(result['status'], expected)
                self.assertFalse(result['complete_continuous_cover'])
        result = global_obstacle_enclosure(HXParams(maturity=10., sigma=.75), max_tail=1.)
        self.assertEqual(result['status'], 'UNRESOLVED_TAIL_BUDGET')
        self.assertFalse(result['complete_continuous_cover'])

    def test_tail_assumptions_and_malformed_inputs_are_refused(self):
        with self.assertRaisesRegex(ArithmeticError, 'Mills-tail'):
            cashflow_tail_enclosure(HXParams(), .0001)
        for opts in ({'max_cells': True}, {'max_cells': 0}, {'max_depth': -1},
                     {'max_depth': True}, {'max_tail': float('inf')},
                     {'max_tail': 100.}, {'dtype': 'fp16'}, {'digits': 60}):
            with self.subTest(options=opts), self.assertRaises((ValueError, TypeError)):
                global_obstacle_enclosure(HXParams(), **opts)


if __name__ == '__main__':
    unittest.main()
