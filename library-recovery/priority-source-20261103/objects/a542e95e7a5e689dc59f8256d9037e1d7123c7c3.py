import math
import unittest
try:
 from .hx_a7_mp_regularized import equity_a7_mp
 from .hx_a7 import equity_a7
 from .hx_original import HXParams,closed_boundary,equity_green
except ImportError:
 from hx_a7_mp_regularized import equity_a7_mp
 from hx_a7 import equity_a7
 from hx_original import HXParams,closed_boundary,equity_green

class HXA7MPLimitTests(unittest.TestCase):
 def test_zero_liquidity_hazard_does_not_raise(self):
    p=HXParams(k=0,xi=2.);b=closed_boundary(p)
    with self.assertRaises(ValueError):equity_a7(b*1.2,p,b)
    for ratio in (1.02,1.2,2.,4.):
        v=b*ratio
        mpval=equity_a7_mp(v,p,b)
        green=equity_green(v,b,p)
        self.assertAlmostEqual(mpval,green,delta=5e-8*max(1,abs(green)))
 def test_continuity_to_zero_from_small_positive_hazard(self):
    p0=HXParams(k=0.);b0=closed_boundary(p0)
    v=b0*1.4
    ref=equity_a7_mp(v,p0,b0)
    for k in (1e-8,1e-11,1e-14):
        p=HXParams(k=k)
        b=closed_boundary(p)
        # Keep V/B constant; compare to the k=0 limiting financial model.
        got=equity_a7_mp(b*1.4,p,b)
        self.assertAlmostEqual(got,ref,delta=5e-5)
 def test_reference_admissibility_rejects_invalid(self):
    p=HXParams();b=closed_boundary(p)
    with self.assertRaises(ValueError):equity_a7_mp(b*1.1,p,b,dps=8)
    with self.assertRaises(ValueError):equity_a7_mp(float('nan'),p,b)

if __name__=='__main__':unittest.main()
