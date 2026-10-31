"""Precision, boundary, independent FD, limit and invalid-domain probes."""
import math
import random
import unittest
try:
    from .math_kernel import (PhysicalParameters,beta_and_boundary,values,
        stationary_pde_residual,independent_finite_difference)
except ImportError:
    from math_kernel import (PhysicalParameters,beta_and_boundary,values,
        stationary_pde_residual,independent_finite_difference)

class MathTests(unittest.TestCase):
    def test_value_matching_smooth_fit_and_call_put_identity(self):
        rng=random.Random(44)
        for _ in range(400):
            p=PhysicalParameters(r=rng.uniform(.01,.2),delta=rng.uniform(.01,.16),
                                 sigma=rng.uniform(.06,.7),k=rng.uniform(.2,5))
            beta,b=beta_and_boundary(p)
            self.assertGreater(beta,0)
            self.assertEqual(values(b,p)[0],0.)
            for ratio in (.6,.99,1,1+1e-7,1.01,1.2,2,5):
                v=b*ratio
                c,put,m,bb,g,rg=values(v,p)
                self.assertGreaterEqual(c,-1e-9)
                self.assertAlmostEqual(c-(v-p.k+put),0,delta=max(1.,v)*2e-11)
                self.assertAlmostEqual(g+rg,1.,places=13)
                self.assertTrue(0<=g<=1)
            eps=1e-5
            derivative=(values(b*(1+eps),p)[0]-values(b,p)[0])/(b*eps)
            self.assertLess(derivative,eps*(1+beta)*1.1)

    def test_pde_sweep(self):
        rng=random.Random(8)
        worst=0.
        for _ in range(400):
            p=PhysicalParameters(r=rng.uniform(.01,.2),delta=rng.uniform(.01,.16),
                                 sigma=rng.uniform(.04,.7),k=rng.uniform(.3,4))
            b=beta_and_boundary(p)[1]
            for ratio in (1.001,1.1,2.,5.):
                e=abs(stationary_pde_residual(b*ratio,p))
                worst=max(worst,e)
                self.assertLess(e,5e-11*max(1.,b*ratio))

    def test_boundary_nearby_taylor_no_negative_roundoff(self):
        p=PhysicalParameters()
        beta,b=beta_and_boundary(p)
        for m in (1e-11,1e-10,1e-8,1e-6,1e-5,1e-4,1e-3):
            c=values(b*math.exp(m),p)[0]
            expected=.5*b*(1+beta)*m*m
            self.assertGreaterEqual(c,0)
            if m<1e-5:self.assertAlmostEqual(c/expected,1.,delta=1e-4)

    def test_independent_fd_refinement(self):
        p=PhysicalParameters(r=.05,delta=.03,sigma=.2,k=1.)
        low=independent_finite_difference(p,steps=256,xmax=8.)
        mid=independent_finite_difference(p,steps=512,xmax=8.)
        high=independent_finite_difference(p,steps=1024,xmax=8.)
        self.assertLess(mid['max_abs_error'],low['max_abs_error']*.35)
        self.assertLess(high['max_abs_error'],mid['max_abs_error']*.35)
        # Original absolute threshold at n=512 FAILS; retain this numerical fact.
        self.assertGreater(mid['max_abs_error'],.002)
        self.assertLess(high['max_abs_error'],.002)
        self.assertGreaterEqual(high['min_fd_value'],-1e-9)

    def test_high_precision_adversarial_tiny_call(self):
        import mpmath as mp
        mp.mp.dps=75
        rng=random.Random(20261031)
        for _ in range(250):
            p=PhysicalParameters(r=10**rng.uniform(-3,-.6),
                delta=10**rng.uniform(-3,-.8),sigma=10**rng.uniform(-2,0),
                k=10**rng.uniform(-1,1))
            beta,b=beta_and_boundary(p)
            m=10**rng.uniform(-12,-3)
            # Evaluate the exact algebra using a high-precision reference;
            # beta and b are held to the *same f64 parameters* to isolate
            # cancellation in the final C operator, not root conditioning.
            bm=mp.mpf(beta);bb=mp.mpf(b);mm=mp.mpf(m)
            high=bb*(mp.expm1(mm)+mp.expm1(-bm*mm)/bm)
            got=values(b*math.exp(m),p)[0]
            self.assertGreaterEqual(got,0)
            # At 1e-12 the f64 input v already loses part of the margin;
            # compare against actual representable log(v/b), not ideal m.
            actual=math.log((b*math.exp(m))/b)
            ref=float(bb*(mp.expm1(mp.mpf(actual))+mp.expm1(-bm*mp.mpf(actual))/bm))
            if ref>1e-25 and beta*actual<100:
                self.assertAlmostEqual(got/ref,1.,delta=5e-5)

    def test_native_fp32_is_not_certified(self):
        import numpy as np
        p=PhysicalParameters()
        beta,b=beta_and_boundary(p)
        m=1e-6
        v=np.float32(b*math.exp(m));k=np.float32(p.k)
        bf=np.float32(b);be=np.float32(beta)
        naive=np.float32(v-k+(k-bf)*np.float32((bf/v)**be))
        true=values(b*math.exp(m),p)[0]
        self.assertGreater(abs(float(naive)-true),10*true)
        # This is a documented counterexample, NOT a passing FP32 kernel.

    def test_parameter_and_state_guard(self):
        for args in [(0,.03,.2,1),(.05,0,.2,1),(.05,.03,0,1),
                     (.05,.03,.2,math.inf),(.4,.03,.2,1)]:
            with self.assertRaises(ValueError):PhysicalParameters(*args)
        for v in (0.,-1.,math.nan,math.inf):
            with self.assertRaises(ValueError):values(v,PhysicalParameters())

if __name__=='__main__':unittest.main(verbosity=2)
