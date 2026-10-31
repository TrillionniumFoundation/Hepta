"""Independent density integral cross-check on finite seeded HX parameter domains."""
import math
import unittest
import numpy as np
try:
    from .hx_original import HXParams,hitting_and_discounted_hitting,bond_price_from_log
    from .first_passage_quad import hitting_density_quadrature
except ImportError:
    from hx_original import HXParams,hitting_and_discounted_hitting,bond_price_from_log
    from first_passage_quad import hitting_density_quadrature

class FirstPassageQuadratureTests(unittest.TestCase):
    def test_500_broad_parameters_including_log_margins_down_to_1e_minus_9(self):
        rng=np.random.default_rng(1111)
        max_error=0.;compared=0
        for _ in range(500):
            p=HXParams(r=rng.uniform(.005,.3),delta=rng.uniform(.001,.2),
                       sigma=rng.uniform(.03,.75),xi=rng.uniform(0,10),
                       k=rng.uniform(0,.25),maturity=rng.uniform(.05,10))
            x=10**rng.uniform(-9,1.08)
            tau=p.maturity*10**rng.uniform(-2,0)
            expected=hitting_and_discounted_hitting(x,tau,p)
            reference=hitting_density_quadrature(x,tau,p)
            err=max(abs(expected[0]-reference.F),abs(expected[1]-reference.G))
            max_error=max(err,max_error)
            compared+=2
            self.assertLess(err,2e-11,('x',x,'tau',tau,'p',p,'error',err))
        self.assertEqual(compared,1000)
        self.assertLess(max_error,2e-11)

    def test_geometric_partition_resolves_small_margin_boundary_layer(self):
        # This is an intentionally difficult regime for plain quad(lo,+inf).
        p=HXParams(r=.08,delta=.1,sigma=.4,xi=2,k=.02)
        x=1e-9;tau=.8
        ref=hitting_density_quadrature(x,tau,p)
        exact=hitting_and_discounted_hitting(x,tau,p)
        self.assertGreater(ref.segments,10)
        self.assertLess(abs(exact[0]-ref.F),1e-11)
        self.assertLess(abs(exact[1]-ref.G),1e-11)
        self.assertGreater(ref.F,.999999)
        self.assertLessEqual(ref.G,ref.F)

    def test_financial_bond_consistency_and_degenerate_input_rejection(self):
        p=HXParams(xi=0.,k=0.)
        x=.24;tau=.8;boundary=56.
        q=hitting_density_quadrature(x,tau,p)
        c0=p.c/p.lam
        independent=c0+math.exp(-p.lam*tau)*(p.p-c0)*(1-q.F)+(
            p.alpha*boundary/p.maturity-c0)*q.G
        self.assertAlmostEqual(independent,bond_price_from_log(x,tau,boundary,p),delta=1e-10)
        self.assertEqual(hitting_density_quadrature(0.,.4,p).F,1.)
        self.assertEqual(hitting_density_quadrature(.4,0.,p).F,0.)
        for x,tau in [(-1.,.5),(.4,-1.),(1e-13,.4),(.4,1e-13)]:
            with self.assertRaises(ValueError):
                hitting_density_quadrature(x,tau,p)

if __name__=='__main__':unittest.main()
