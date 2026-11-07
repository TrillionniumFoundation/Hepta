"""Direct paper Appendix A5/A7 vs independently solved Eq11 Green integral."""
import math
import random
import unittest
try:
 from .hx_original import HXParams,closed_boundary,equity_green
 from .hx_a7 import equity_a7
except ImportError:
 from hx_original import HXParams,closed_boundary,equity_green
 from hx_a7 import equity_a7

class A7Tests(unittest.TestCase):
    def test_literal_a7_matches_independent_green_and_boundary(self):
        p=HXParams();b=closed_boundary(p)
        for x in (1e-6,1e-4,.01,.03,.2,.5,1.,2.,3.):
            v=b*math.exp(x)
            want=equity_green(v,b,p)
            got=equity_a7(v,p,b)
            self.assertAlmostEqual(got,want,delta=5e-8*max(1.,abs(want)))
            self.assertGreaterEqual(got,-1e-8)

    def test_holdout_parameter_sweep(self):
        rng=random.Random(20261031)
        passed=0
        for i in range(16):
            p=HXParams(r=rng.uniform(.04,.11),delta=rng.uniform(.01,.05),
                sigma=rng.uniform(.12,.35),alpha=rng.uniform(.4,.85),
                tax=rng.uniform(.1,.35),xi=rng.uniform(.5,4),k=rng.uniform(.005,.05),
                maturity=rng.uniform(.5,4),coupon_total=rng.uniform(3,12),
                face_total=rng.uniform(40,95))
            try:b=closed_boundary(p)
            except ValueError:continue
            for x in (.03,.1,.5,1.1):
                v=b*math.exp(x)
                self.assertAlmostEqual(equity_a7(v,p,b),equity_green(v,b,p),
                    delta=2e-6*max(1.,v))
            passed+=1
        self.assertGreaterEqual(passed,10)

    def test_a7_rejects_near_zero_liquidity_singularity(self):
        p=HXParams(xi=0.,k=0.)
        b=closed_boundary(p)
        with self.assertRaises(ValueError):equity_a7(b*1.3,p,b)

if __name__=='__main__':unittest.main(verbosity=2)
