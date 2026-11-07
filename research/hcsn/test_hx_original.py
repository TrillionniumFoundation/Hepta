"""Independent P0 tests for ORIGINAL HX coupled bond/equity free boundary."""
import math
import random
import unittest

try:
 from .hx_original import (HXParams, closed_boundary, independent_boundary,
     hitting_and_discounted_hitting,bond_price_from_log,hx_integrals,
     equity_green,equity_smooth_derivative_at_boundary,equity_pde_residual_fd)
except ImportError:
 from hx_original import (HXParams,closed_boundary,independent_boundary,
     hitting_and_discounted_hitting,bond_price_from_log,hx_integrals,
     equity_green,equity_smooth_derivative_at_boundary,equity_pde_residual_fd)

class OriginalHXTests(unittest.TestCase):
    def test_exact_paper_baseline_and_independent_boundary(self):
        p=HXParams()
        b=closed_boundary(p)
        self.assertAlmostEqual(b,67.44151539060374,delta=2e-8)
        self.assertAlmostEqual(independent_boundary(p),b,delta=3e-7)
        self.assertLess(abs(equity_smooth_derivative_at_boundary(b,p)),1e-7)
        self.assertEqual(equity_green(b,b,p),0.)

    def test_eq8_boundary_terminal_and_far_survival(self):
        p=HXParams();b=closed_boundary(p)
        for tau in (.05,.5,1.):
            self.assertAlmostEqual(bond_price_from_log(0.,tau,b,p),p.alpha*b/p.maturity,places=11)
        for x in (.01,.1,1.,5.):
            self.assertAlmostEqual(bond_price_from_log(x,0.,b,p),p.p,places=10)
        far=p.c/p.lam+math.exp(-p.lam*p.maturity)*(p.p-p.c/p.lam)
        self.assertAlmostEqual(bond_price_from_log(14.,p.maturity,b,p),far,places=9)

    def test_probability_and_discounted_hit_ineq(self):
        p=HXParams()
        for x in (.00001,.01,.1,.4,1.,3.,7.):
            for tau in (.01,.05,.2,1.):
                f,g=hitting_and_discounted_hitting(x,tau,p)
                self.assertLessEqual(g,f+1e-13)
                self.assertGreaterEqual(g,0)
                self.assertLessEqual(f,1)
        with self.assertRaises(ValueError):hitting_and_discounted_hitting(-1.,1.,p)

    def test_closed_cdf_laplace_matches_independent_quadrature(self):
        from scipy.integrate import quad
        for p in [HXParams(),HXParams(sigma=.31,xi=2.,k=.03),HXParams(sigma=.11,xi=0.,k=0.)]:
            f,g=hx_integrals(p)
            ref=[quad(lambda x:math.exp(-p.eta*x)*hitting_and_discounted_hitting(x,p.maturity,p)[j],
                      0,18.,epsabs=1e-11)[0] for j in (0,1)]
            self.assertAlmostEqual(f,ref[0],delta=2e-9)
            self.assertAlmostEqual(g,ref[1],delta=2e-9)

    def test_original_equity_ode_in_continuation(self):
        p=HXParams();b=closed_boundary(p)
        # FD probe truncation error ~O(dx^2), checked for convergence.
        for x in (.05,.15,.6,1.2):
            r1=abs(equity_pde_residual_fd(x,b,p,step=.004))
            r2=abs(equity_pde_residual_fd(x,b,p,step=.002))
            self.assertLess(r2, r1*.35+1e-6)
            self.assertLess(r2,1e-4)
            self.assertGreater(equity_green(b*math.exp(x),b,p),0)

    def test_adversarial_valid_domain_and_rejection(self):
        for kwargs in ({'sigma':0},{'r':0},{'tax':1},{'alpha':1.4},
                       {'xi':-1},{'maturity':0},{'coupon_total':float('nan')}):
            with self.assertRaises(ValueError):HXParams(**kwargs)
        rng=random.Random(20261031)
        passed=0
        for _ in range(24):
            p=HXParams(r=rng.uniform(.04,.12),delta=rng.uniform(.015,.04),
                sigma=rng.uniform(.12,.35),k=rng.uniform(0,.04),xi=rng.uniform(.1,3),
                alpha=rng.uniform(.3,.8),maturity=rng.uniform(.5,3),
                coupon_total=rng.uniform(3,9),face_total=rng.uniform(45,85))
            try:b=closed_boundary(p)
            except ValueError:continue # Some samples have no economic positive boundary
            ref=independent_boundary(p)
            self.assertAlmostEqual(b,ref,delta=1e-5*max(1,b))
            self.assertLess(abs(equity_smooth_derivative_at_boundary(b,p)),1e-5)
            passed+=1
        self.assertGreaterEqual(passed,15)

if __name__=='__main__':unittest.main(verbosity=2)
