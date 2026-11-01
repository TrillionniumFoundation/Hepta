"""P0 one-axis input quantization and Eq12 gradients; NOT all-domain proof."""
from dataclasses import replace
from fractions import Fraction
import math
import struct
import unittest
import mpmath as mp
try:
    from .hx_original import HXParams, closed_boundary
    from .hx_local_obstacle_mp_reference import mp_first_passage_sign
    from .p0_tax_cell_sensitivity import audit_tax_cell, _tax_rounding_cell
except ImportError:
    from hx_original import HXParams, closed_boundary
    from hx_local_obstacle_mp_reference import mp_first_passage_sign
    from p0_tax_cell_sensitivity import audit_tax_cell, _tax_rounding_cell


class TaxCellTests(unittest.TestCase):
    def test_fp32_collision_spans_opposing_local_signs(self):
        fixed=dict(r=.10,delta=.075,sigma=.20,alpha=.40,xi=4,k=.20,
                   maturity=3,coupon_total=5,face_total=20)
        a,b=.39990773048821087,.3999077379072307
        self.assertEqual(struct.pack('!f',a),struct.pack('!f',b))
        z=audit_tax_cell(HXParams(**fixed,tax=a),digits=40)
        self.assertEqual(z['float32_tax_word'],'0x3eccc0b5')
        self.assertEqual(z['classification'],'TAX_CELL_LOCAL_SIGN_AMBIGUITY')
        self.assertLess(Fraction(z['tax_cell_lower_exact']),a)
        self.assertLess(b,Fraction(z['tax_cell_upper_exact']))
        self.assertLess(mp.mpf(z['boundary_cashflow_min']),0)
        self.assertGreater(mp.mpf(z['boundary_cashflow_max']),0)
        self.assertEqual(z['p0_scientific_gate'],'OPEN')
        self.assertFalse(z['production_activation'])

    def test_entire_cell_numerical_local_obstruction(self):
        p=HXParams(r=.10,delta=.075,sigma=.20,alpha=.40,tax=.27,xi=4,
                   k=.20,maturity=3,coupon_total=5,face_total=100)
        z=audit_tax_cell(p,digits=35)
        self.assertEqual(z['classification'],'REJECT_LOCAL_EQUITY_FOR_ENTIRE_TAX_CELL')
        self.assertGreater(mp.mpf(z['boundary_cashflow_min']),0)
        self.assertFalse(z['global_equity_obstacle_certified'])

    def test_baseline_is_never_global_admission(self):
        z=audit_tax_cell(HXParams(),digits=35)
        self.assertEqual(z['classification'],'ONE_AXIS_ONLY_NO_LOCAL_SIGN_OBSTRUCTION')
        self.assertLess(mp.mpf(z['boundary_cashflow_max']),0)
        for key in ('full_fp32_input_box_certified','global_equity_obstacle_certified',
                    'regenerative_qvi_certified','production_activation'):
            self.assertFalse(z[key])
        self.assertTrue(z['mp_quadrature_not_outward_rounded'])

    def test_zero_liquidity_degenerate_limit(self):
        z=audit_tax_cell(HXParams(k=0.,xi=0.),digits=35)
        self.assertEqual(z['classification'],'ONE_AXIS_ONLY_NO_LOCAL_SIGN_OBSTRUCTION')
        self.assertLess(float(z['d_boundary_d_tax']),0.)

    def test_four_gradients_vs_independent_fp64_laplace_fd(self):
        for p in (HXParams(),HXParams(k=0.,xi=0.)):
            z=audit_tax_cell(p,digits=35)
            for name,key,h in (
                ('tax','d_boundary_d_tax',1e-5),
                ('alpha','d_boundary_d_alpha',1e-5),
                ('coupon_total','d_boundary_d_coupon_total',1e-4),
                ('face_total','d_boundary_d_face_total',1e-4)):
                plus=closed_boundary(replace(p,**{name:getattr(p,name)+h}))
                minus=closed_boundary(replace(p,**{name:getattr(p,name)-h}))
                observed=(plus-minus)/(2*h)
                expected=float(z[key])
                self.assertLess(abs(observed-expected),3e-5*max(1,abs(expected)),
                                msg=f'{name},k={p.k}')

    def test_tax_midpoints_are_exact_binary_rationals(self):
        word,lo,hi=_tax_rounding_cell(.27)
        prev,mid,nxt=map(lambda n:Fraction.from_float(
            struct.unpack('!f',struct.pack('!I',n))[0]),(word-1,word,word+1))
        self.assertEqual(lo,(prev+mid)/2)
        self.assertEqual(hi,(mid+nxt)/2)
        self.assertTrue(lo<mid<hi)

    def test_gradient_vs_separate_mp_first_passage_roots(self):
        p=HXParams()
        z=audit_tax_cell(p,digits=35)
        h=2e-5
        plus=mp_first_passage_sign(replace(p,tax=p.tax+h),decimal_digits=35)
        minus=mp_first_passage_sign(replace(p,tax=p.tax-h),decimal_digits=35)
        derivative=(mp.mpf(plus['boundary'])-mp.mpf(minus['boundary']))/(2*h)
        self.assertLess(abs(float(derivative)-float(z['d_boundary_d_tax'])),1e-9)

    def test_fail_closed_bad_inputs_and_precision(self):
        with self.assertRaises(TypeError):audit_tax_cell({'tax':.27})
        for digits in (34,91,True,45.0):
            with self.assertRaises(ValueError):audit_tax_cell(HXParams(),digits=digits)
        for tax in (0.,math.nextafter(1.,0.)):
            with self.assertRaises(ValueError):audit_tax_cell(HXParams(tax=tax))
        for tax in (True,float('nan'),float('inf'),-1.):
            with self.assertRaises(ValueError):_tax_rounding_cell(tax)

if __name__=='__main__':unittest.main()
