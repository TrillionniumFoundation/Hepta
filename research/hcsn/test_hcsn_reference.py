"""Portable original-paper HX and new regenerative QVI math reference tests."""
import math
import random
import unittest
import numpy as np
try:
    from .hx_original import (HXParams,closed_boundary,independent_boundary,
        bond_price_from_log,hitting_and_discounted_hitting,equity_green,
        equity_smooth_derivative_at_boundary,equity_pde_residual_fd)
    from .hx_a7 import equity_a7
    from .regenerative_qvi import (RegenerativeParams,reset_boundary,regenerative_value,
        regenerative_residuals,first_passage_cdf,sample_exact_first_passage,
        simulate_regenerative_events)
except ImportError:
    from hx_original import (HXParams,closed_boundary,independent_boundary,
        bond_price_from_log,hitting_and_discounted_hitting,equity_green,
        equity_smooth_derivative_at_boundary,equity_pde_residual_fd)
    from hx_a7 import equity_a7
    from regenerative_qvi import (RegenerativeParams,reset_boundary,regenerative_value,
        regenerative_residuals,first_passage_cdf,sample_exact_first_passage,
        simulate_regenerative_events)

class HXReferenceTests(unittest.TestCase):
    def test_paper_baseline_a7_independent_equity(self):
        p=HXParams();b=closed_boundary(p)
        self.assertAlmostEqual(b,67.44151539060374,delta=1e-8)
        self.assertAlmostEqual(independent_boundary(p),b,delta=5e-7)
        self.assertLess(abs(equity_smooth_derivative_at_boundary(b,p)),1e-8)
        for x in (1e-4,.01,.05,.1,.4,1.,2.,3.):
            v=b*math.exp(x)
            self.assertAlmostEqual(equity_a7(v,p,b),equity_green(v,b,p),
                                   delta=5e-7*max(1,v))
            self.assertGreater(equity_a7(v,p,b),0)

    def test_bond_terminal_default_probabilities(self):
        p=HXParams();b=closed_boundary(p)
        for tau in (.01,.25,1.):
            self.assertAlmostEqual(bond_price_from_log(0.,tau,b,p),p.alpha*b/p.maturity)
        for x in (.01,.1,2.,5.):
            self.assertAlmostEqual(bond_price_from_log(x,0.,b,p),p.p)
        for x in (.001,.01,.1,1.,4.):
            for tau in (.01,.2,1.):
                f,g=hitting_and_discounted_hitting(x,tau,p)
                self.assertTrue(0<=g<=f<=1)

    def test_eq11_fd_and_adversarial_params(self):
        p=HXParams();b=closed_boundary(p)
        for x in (.05,.15,.8):
            coarse=abs(equity_pde_residual_fd(x,b,p,step=.004))
            fine=abs(equity_pde_residual_fd(x,b,p,step=.002))
            self.assertLess(fine,coarse*.35+1e-6)
        rng=random.Random(20261031)
        for _ in range(10):
            p=HXParams(r=rng.uniform(.05,.12),delta=rng.uniform(.01,.05),
                       sigma=rng.uniform(.14,.36),xi=rng.uniform(.3,3.),
                       k=rng.uniform(.004,.05),maturity=rng.uniform(.5,2.5))
            b=closed_boundary(p)
            self.assertAlmostEqual(b,independent_boundary(p),delta=1e-4*max(1,b))
        for kwargs in ({'r':0},{'sigma':0},{'alpha':-1},{'tax':1}):
            with self.assertRaises(ValueError):HXParams(**kwargs)
        with self.assertRaises(ValueError):
            equity_a7(closed_boundary(HXParams(xi=0,k=0))*1.1,HXParams(xi=0,k=0))

    def test_global_regenerative_qvi_and_events(self):
        p=RegenerativeParams();b=reset_boundary(p)
        self.assertTrue(0<b<p.reset_value-p.reset_cost)
        self.assertAlmostEqual(regenerative_value(b,p),
                               regenerative_value(p.reset_value,p)-p.reset_cost,places=10)
        for v in (b*.1,b*.8,b,b*1.0001,b*1.2,b*3.,b*10):
            cont,imp,u=regenerative_residuals(v,p)
            self.assertLessEqual(cont,1e-9)
            self.assertLessEqual(imp,1e-9)
            self.assertAlmostEqual(max(cont,imp),0,delta=3e-9)
        q=RegenerativeParams(r=.05,delta=.04,sigma=.34,reset_value=1.4,reset_cost=.12)
        e=simulate_regenerative_events(.1,500.,q,seed=47)
        self.assertGreater(e['events'],4)
        self.assertEqual(e,simulate_regenerative_events(.1,500.,q,seed=47))
        self.assertTrue(all(s<t for s,t in zip(e['times'],e['times'][1:])))

    def test_exact_first_passage_sampler_consistent_with_cdf(self):
        p=RegenerativeParams(r=.08,delta=.015,sigma=.2)
        b=reset_boundary(p);x=math.log(p.reset_value/b)
        target=first_passage_cdf(x,60.,p)
        rng=np.random.default_rng(123)
        draw=sum(sample_exact_first_passage(p.reset_value,b,p,rng)<=60 for _ in range(2500))/2500
        self.assertAlmostEqual(draw,target,delta=.045)

if __name__=='__main__':unittest.main(verbosity=2)
