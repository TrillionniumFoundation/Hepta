"""Independent finite-difference original-He--Xiong bond reference tests."""
import math
import unittest
try:
    from .hx_original import HXParams,closed_boundary,bond_price_from_log
    from .bond_fd_reference import solve_bond_pde
except ImportError:
    from hx_original import HXParams,closed_boundary,bond_price_from_log
    from bond_fd_reference import solve_bond_pde


class BondPDETests(unittest.TestCase):
    def test_independent_pde_agrees_with_original_closed_form(self):
        cases=[HXParams(),HXParams(xi=0.,k=0.),
               HXParams(sigma=.4,delta=.04,alpha=.55,maturity=.75)]
        for p in cases:
            vb=closed_boundary(p)
            for tau in (.2*p.maturity,p.maturity):
                result=solve_bond_pde(p,vb,tau,max_x=7.,points=501,steps=1400)
                self.assertAlmostEqual(result.at(0.),p.alpha*vb/p.maturity,delta=1e-9)
                for x in (.12,.3,.6,1.2,2.):
                    with self.subTest(params=p,x=x,tau=tau):
                        expected=bond_price_from_log(x,tau,vb,p)
                        self.assertLess(abs(result.at(x)-expected),
                                        .002+0.001*abs(expected))

    def test_spatial_temporal_refinement(self):
        p=HXParams();vb=closed_boundary(p)
        coarse=solve_bond_pde(p,vb,p.maturity,points=251,steps=500)
        fine=solve_bond_pde(p,vb,p.maturity,points=501,steps=1400)
        err0=max(abs(coarse.at(x)-bond_price_from_log(x,p.maturity,vb,p))
                 for x in (.18,.33,.68,1.1))
        err1=max(abs(fine.at(x)-bond_price_from_log(x,p.maturity,vb,p))
                 for x in (.18,.33,.68,1.1))
        self.assertLess(err1,err0)

    def test_coupon_and_boundary_sanity(self):
        p=HXParams();vb=closed_boundary(p)
        result=solve_bond_pde(p,vb,p.maturity)
        self.assertGreater(result.at(.4),result.at(0.))
        self.assertLess(result.at(6.),p.p+5.)
        self.assertTrue(all(math.isfinite(v) for v in result.values))

    def test_fail_closed_bad_grids(self):
        p=HXParams();vb=closed_boundary(p)
        for kwargs in ({'points':80},{'steps':10},{'max_x':20.}):
            with self.assertRaises(ValueError):
                solve_bond_pde(p,vb,.5,**kwargs)
        with self.assertRaises(ValueError):
            solve_bond_pde(p,vb,p.maturity+0.01)


if __name__=='__main__':unittest.main()
