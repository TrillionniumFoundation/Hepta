"""P0 regression: necessary local obstacle and no-clipping fail-closed reference.

This is an exact local necessary-condition guard, NOT an all-domain HX proof.
"""
from __future__ import annotations
from dataclasses import replace
import unittest
from unittest.mock import patch

import numpy as np

try:
    from .hx_original import HXParams,closed_boundary
    from . import hx_uniform
except ImportError:
    from hx_original import HXParams,closed_boundary
    import hx_uniform

HIGH_LIQUIDITY=HXParams(r=.10,delta=.075,sigma=.20,alpha=.40,
    tax=.27,xi=4.,k=.20,maturity=3.,coupon_total=5.,face_total=100.)

NEAR_THRESHOLD=HXParams(r=.10,delta=.075,sigma=.20,alpha=.40,
    tax=.3999077341977208,xi=4.,k=.20,maturity=3.,coupon_total=5.,face_total=20.)


class HXUniformFailClosed(unittest.TestCase):
    def test_baseline_no_local_obstruction_does_not_imply_admission(self):
        p=HXParams()
        b=closed_boundary(p)
        for x in (-.1,0.,1e-7,1e-4,1e-3):
            got=hx_uniform.equity_logmargin(x,p,boundary=b)
            self.assertGreaterEqual(got.equity,0.)
            self.assertFalse(got.global_obstacle_certified)
            self.assertFalse(got.production_activation)
            self.assertTrue(got.fp64_reference_only)

    def test_invalid_smooth_fit_candidate_is_refused_at_all_distances(self):
        # Prior implementation silently projected some tiny negative equity
        # to zero if below an arbitrary -1e-7*boundary threshold.
        p=HIGH_LIQUIDITY
        for x in (-.02,0.,1e-8,1e-6,1e-4,5e-4):
            with self.subTest(x=x),self.assertRaisesRegex(ArithmeticError,'local sign'):
                hx_uniform.equity_logmargin(x,p)

    def test_supplied_boundary_cannot_bypass_eq12(self):
        p=HXParams()
        root=closed_boundary(p)
        for other in (root*1.02,root*.98,0.,float('nan'),float('inf'),True):
            with self.subTest(other=other),self.assertRaises(ValueError):
                hx_uniform.equity_logmargin(.0001,p,boundary=other)

    def test_near_threshold_unresolved_sign_fails_closed_in_both_directions(self):
        p=NEAR_THRESHOLD
        minus=replace(p,tax=.3999077304882109)
        plus=replace(p,tax=.3999077379072307)
        self.assertEqual(np.float32(minus.tax).tobytes(),np.float32(plus.tax).tobytes())
        self.assertNotEqual(minus.tax,plus.tax)
        for near in (minus,plus,replace(p,tax=float(np.float32(p.tax)))):
            with self.subTest(tax=near.tax),self.assertRaisesRegex(ArithmeticError,'local sign'):
                hx_uniform.equity_logmargin(1e-6,near)

    def test_negative_continuation_never_projected_to_zero(self):
        p=HXParams()
        with patch.object(hx_uniform,'equity_near_boundary',return_value=-1e-18):
            with self.assertRaisesRegex(ArithmeticError,'no silent clipping'):
                hx_uniform.equity_logmargin(1e-5,p)

    def test_parameter_type_and_numeric_guards(self):
        p=HXParams()
        with self.assertRaises(TypeError):hx_uniform.equity_logmargin(1e-4,dict(vars(p)))
        for x in (float('nan'),float('inf'),-2.5,9.):
            with self.assertRaises(ValueError):hx_uniform.equity_logmargin(x,p)
        with self.assertRaises(ValueError):hx_uniform.equity_logmargin(.01,p,singular_tol=-1.)


if __name__=='__main__':unittest.main()
