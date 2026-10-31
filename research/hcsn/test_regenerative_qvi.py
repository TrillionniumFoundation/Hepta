"""Exact regenerative QVI verification and reset-point-process tests."""
import math
import unittest
import numpy as np
try:
 from .regenerative_qvi import (RegenerativeParams,reset_boundary,regenerative_value,
    regenerative_residuals,first_passage_cdf,sample_exact_first_passage,simulate_regenerative_events)
except ImportError:
 from regenerative_qvi import (RegenerativeParams,reset_boundary,regenerative_value,
    regenerative_residuals,first_passage_cdf,sample_exact_first_passage,simulate_regenerative_events)

class QVITests(unittest.TestCase):
    def test_smooth_pasting_value_matching_global_qvi(self):
        for p in (RegenerativeParams(),RegenerativeParams(sigma=.4,delta=.06),
                  RegenerativeParams(r=.06,delta=.02,sigma=.3,reset_value=1.3,reset_cost=.12)):
            b=reset_boundary(p);R=p.reset_value
            self.assertLess(b,R-p.reset_cost)
            vleft=regenerative_value(b*(1-1e-8),p)
            self.assertAlmostEqual(vleft,regenerative_value(R,p)-p.reset_cost,places=9)
            eps=1e-5
            derivative=(regenerative_value(b*(1+eps),p)-regenerative_value(b,p))/(b*eps)
            self.assertLess(abs(derivative),eps*(p.gamma+1)*2)
            for ratio in (.01,.25,.75,.9999,1,1.0001,1.03,1.5,2,4,10):
                v=b*ratio
                c,imp,u=regenerative_residuals(v,p)
                self.assertLessEqual(c,1e-10*max(1,u)+1e-10)
                self.assertLessEqual(imp,1e-10*max(1,u)+1e-10)
                self.assertAlmostEqual(max(c,imp),0.,delta=3e-10*max(1,abs(u)))

    def test_first_passage_probability_mc(self):
        # Use a positive log drift to test nonhit mass, conditional IG law.
        p=RegenerativeParams(r=.08,delta=.015,sigma=.2)
        b=reset_boundary(p);x=math.log(p.reset_value/b)
        horizon=60.
        target=first_passage_cdf(x,horizon,p)
        rng=np.random.default_rng(123)
        n=2500
        draws=[sample_exact_first_passage(p.reset_value,b,p,rng) for _ in range(n)]
        estimate=sum(t<=horizon for t in draws)/n
        self.assertAlmostEqual(estimate,target,delta=.045)
        self.assertLessEqual(target,1)
        self.assertEqual(first_passage_cdf(x,0.,p),0.)

    def test_multiple_exact_cycles_replay_and_cost(self):
        p=RegenerativeParams(r=.05,delta=.04,sigma=.34,reset_value=1.4,reset_cost=.12)
        a=simulate_regenerative_events(.1,500.,p,seed=47)
        b=simulate_regenerative_events(.1,500.,p,seed=47)
        self.assertEqual(a,b)
        self.assertGreaterEqual(a['events'],4)
        self.assertEqual(a['times'][0],0.)
        self.assertTrue(all(a['times'][i]<a['times'][i+1] for i in range(len(a['times'])-1)))
        self.assertTrue(all(0<=x<=500 for x in a['times']))
        with self.assertRaises(ValueError):RegenerativeParams(reset_cost=2.)
        with self.assertRaises(ValueError):sample_exact_first_passage(1.,2.,p,np.random.default_rng(1))

if __name__=='__main__':unittest.main(verbosity=2)
