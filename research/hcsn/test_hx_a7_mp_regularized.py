"""Regression for the high-precision removable A7 limit."""
import unittest
try:
    from .hx_a7_mp_regularized import equity_a7_mp
    from .hx_original import HXParams, closed_boundary, equity_green
except ImportError:
    from hx_a7_mp_regularized import equity_a7_mp
    from hx_original import HXParams, closed_boundary, equity_green

class A7HighPrecisionTests(unittest.TestCase):
    def test_zero_hazard_matches_independent_equity_green(self):
        for kwargs in ({"k":0.0}, {"xi":0.0,"k":0.025}):
            p=HXParams(**kwargs)
            b=closed_boundary(p)
            for ratio in (1.02,1.2,2.0,4.0):
                v=b*ratio
                actual=equity_a7_mp(v,p,b)
                target=equity_green(v,b,p)
                self.assertAlmostEqual(actual,target,delta=5e-8*max(1.,abs(target)))

    def test_positive_hazard_continuity(self):
        p0=HXParams(k=0.)
        b0=closed_boundary(p0)
        reference=equity_a7_mp(b0*1.4,p0,b0)
        for hazard in (1e-8,1e-11,1e-14):
            p=HXParams(k=hazard)
            b=closed_boundary(p)
            self.assertAlmostEqual(equity_a7_mp(b*1.4,p,b),reference,delta=5e-5)

    def test_bad_state_and_precision_fail_closed(self):
        p=HXParams()
        b=closed_boundary(p)
        with self.assertRaises(ValueError):
            equity_a7_mp(float("nan"),p,b)
        with self.assertRaises(ValueError):
            equity_a7_mp(b*1.4,p,b,dps=8)
