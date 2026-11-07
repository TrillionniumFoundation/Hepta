"""Independent exact-parameter collision regression for P0 low precision."""
from __future__ import annotations
import math
from types import SimpleNamespace
import unittest
import mpmath as mp
import numpy as np

try:
    from .hx_fp32_local_sign_collision import collision_evidence,FinancialPoint
    from .hx_local_obstacle_mp_reference import mp_first_passage_sign
except ImportError:
    from hx_fp32_local_sign_collision import collision_evidence,FinancialPoint
    from hx_local_obstacle_mp_reference import mp_first_passage_sign


class OriginalHXFP32Collision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=collision_evidence(digits=50)

    def test_two_distinct_original_inputs_quantize_to_same_float32_tax(self):
        a=self.d['positive_net_negative_curvature'];b=self.d['negative_net_positive_curvature']
        self.assertNotEqual(a['tax'],b['tax'])
        self.assertEqual(a['tax_fp32_hex'],b['tax_fp32_hex'])
        self.assertGreater(mp.mpf(self.d['tax_pair_separation']),0)

    def test_float32_boundary_is_indistinguishable_too(self):
        a=self.d['positive_net_negative_curvature'];b=self.d['negative_net_positive_curvature']
        self.assertEqual(a['boundary_fp32_hex'],b['boundary_fp32_hex'])
        self.assertGreater(mp.mpf(a['boundary']),mp.mpf(b['boundary']))

    def test_high_precision_local_cashflow_opposite_signed(self):
        a=self.d['positive_net_negative_curvature'];b=self.d['negative_net_positive_curvature']
        self.assertGreater(mp.mpf(a['net_cashflow']),mp.mpf('1e-10'))
        self.assertLess(mp.mpf(b['net_cashflow']),-mp.mpf('1e-10'))
        self.assertLess(mp.mpf(a['local_log_curvature']),0)
        self.assertGreater(mp.mpf(b['local_log_curvature']),0)

    def test_independent_mp50_first_hit_integration_reproduces_each_sign(self):
        p=FinancialPoint()
        for label,expected_sign in [('positive_net_negative_curvature',1),('negative_net_positive_curvature',-1)]:
            a=self.d[label]
            kwargs={k:float(v) for k,v in vars(p).items()}
            kwargs['tax']=float(a['tax'])
            reference=mp_first_passage_sign(SimpleNamespace(**kwargs),decimal_digits=50)
            actual=mp.mpf(reference['boundary_cashflow'])
            expected=mp.mpf(a['net_cashflow'])
            self.assertEqual(1 if actual>0 else -1,expected_sign)
            self.assertLess(abs(actual-expected),mp.mpf('4e-13'))
            self.assertLess(abs(mp.mpf(reference['boundary'])-mp.mpf(a['boundary'])),mp.mpf('4e-12'))

    def test_liquidation_recovery_stays_below_face_for_both(self):
        for label in ('positive_net_negative_curvature','negative_net_positive_curvature'):
            self.assertTrue(0<mp.mpf(self.d[label]['recovery_over_face'])<1)

    def test_full_input_vector_loses_tax_difference(self):
        p=vars(FinancialPoint())
        a=self.d['positive_net_negative_curvature'];b=self.d['negative_net_positive_curvature']
        def frozen_f32(rec):
            return tuple(np.float32(float(rec['tax'] if k=='tax' else v)).tobytes().hex()
                         for k,v in p.items())
        self.assertEqual(frozen_f32(a),frozen_f32(b))

    def test_70_digit_independent_recalculation_preserves_root(self):
        higher=collision_evidence(digits=70)
        self.assertLess(abs(mp.mpf(higher['tax_zero_cashflow'])-mp.mpf(self.d['tax_zero_cashflow'])), mp.mpf('1e-46'))
        self.assertTrue(higher['same_fp32_inputs'])
        self.assertTrue(higher['same_fp32_boundary'])

    def test_no_scientific_admission_from_unquantized_reference(self):
        self.assertFalse(self.d['original_hx_full_domain_certified'])
        self.assertFalse(self.d['outward_rounded_certificate'])
        self.assertFalse(self.d['production_activation'])
        self.assertTrue(all(v=='OPEN' for v in self.d['p0_p6_scientific_gates'].values()))

    def test_reject_invalid_precision_budget(self):
        for bad in (20,44,91,True):
            with self.assertRaises(ValueError):collision_evidence(digits=bad)

if __name__=='__main__':unittest.main()
