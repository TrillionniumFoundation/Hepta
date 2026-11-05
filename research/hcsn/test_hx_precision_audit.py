"""P0 deterministic adversarial MP80 Eq12 consistency audit (not full proof)."""
from __future__ import annotations
import math
import unittest

try:
    from .hx_original import HXParams, closed_boundary
    from .hx_uniform import equity_logmargin
    from .hx_precision_audit import (audit_boundary,high_precision_boundary,
                                     require_consistent_boundary)
except ImportError:
    from hx_original import HXParams, closed_boundary
    from hx_uniform import equity_logmargin
    from hx_precision_audit import (audit_boundary,high_precision_boundary,
                                    require_consistent_boundary)

# Both parameter tuples lie in the declared bounded exploratory HX domain.
# FP64 Eq12 has reproduced >1e-7 relative MP80 discrepancy on both.
WITNESSES = (
    HXParams(r=.008865616291825792,delta=.08525496331127541,
        sigma=.18494437417965617,alpha=.18630843521961182,
        tax=.2532366506796759,xi=.13338214919934874,
        k=1.6891755491255562e-05,maturity=.12736911541646764,
        coupon_total=27.577137854035556,face_total=2.738040065111361),
    HXParams(r=.05221966966205526,delta=.09497827526915133,
        sigma=.060131790099257586,alpha=.032834590917326545,
        tax=.5952256792256638,xi=.00010254624685183584,
        k=.05014256520358495,maturity=.09416257725950261,
        coupon_total=.0010869997734354265,face_total=.00011543223527937419),
)

class HXPrecisionAuditTests(unittest.TestCase):
    def test_paper_baseline_passes_precision_guard_without_production_certificate(self):
        p=HXParams()
        check=require_consistent_boundary(p,closed_boundary(p))
        self.assertLess(check.relative_difference,1e-10)
        self.assertFalse(check.global_obstacle_certified)
        self.assertFalse(check.production_activation)

    def test_legitimate_fp64_path_has_adversarial_relative_drift(self):
        for p in WITNESSES:
            with self.subTest(p=p):
                check=audit_boundary(p)
                self.assertGreater(check.relative_difference,1e-8)
                self.assertTrue(math.isfinite(check.fp64_boundary))
                self.assertTrue(math.isfinite(check.mp80_boundary))
                with self.assertRaisesRegex(ArithmeticError,'Unverified FP64'):
                    require_consistent_boundary(p,check.fp64_boundary)

    def test_uniform_entry_guard_blocks_locally_passable_witnesses(self):
        # The older Eq11 local curvature screen would *not* reject these.
        for p in WITNESSES:
            b=closed_boundary(p)
            q=p.delta*b-(1-p.tax)*p.coupon_total+p.alpha*b/p.maturity-p.p
            scale=max(1.,abs(p.delta*b),abs((1-p.tax)*p.coupon_total),
                      abs(p.alpha*b/p.maturity),abs(p.p))
            self.assertLess(q,-1e-9*scale)
            with self.subTest(p=p),self.assertRaisesRegex(ArithmeticError,'MP80'):
                equity_logmargin(0.,p)
        self.assertEqual(equity_logmargin(0.,HXParams()).equity,0.)

    def test_precision_dps_invariance_independent_construction(self):
        for p in (HXParams(),*WITNESSES):
            with self.subTest(p=p):
                sixty=high_precision_boundary(p,digits=60)
                hundred=high_precision_boundary(p,digits=100)
                self.assertLess(abs(float(sixty/hundred)-1),1e-13)

    def test_zero_liquidity_limit_and_extreme_tiny_shock(self):
        p=HXParams(xi=0.,k=.25)
        q=HXParams(xi=1e-20,k=1e-15)
        root0=high_precision_boundary(p)
        root1=high_precision_boundary(q)
        self.assertLess(abs(float(root1/root0)-1),1e-12)
        self.assertLess(audit_boundary(p).relative_difference,1e-10)

    def test_wrong_boundary_and_invalid_precision_rejected(self):
        p=HXParams()
        for bad in (float('nan'),float('inf'),0.,-1.,True):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                require_consistent_boundary(p,bad)
        for digits in (0,59,161,80.,True):
            with self.subTest(digits=digits),self.assertRaises(ValueError):
                high_precision_boundary(p,digits=digits)
        with self.assertRaisesRegex(ArithmeticError,'wrong candidate'):
            require_consistent_boundary(p,closed_boundary(p)*1.01)

    def test_global_mpmath_precision_unchanged(self):
        import mpmath as mp
        saved=mp.mp.dps
        high_precision_boundary(HXParams(), digits=120)
        self.assertEqual(mp.mp.dps,saved)

if __name__=='__main__': unittest.main()
