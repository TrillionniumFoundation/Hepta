"""Strict bounded numerical P0 reference tests; NOT a global proof."""
import math
import unittest

try:
    from .hx_original import HXParams,closed_boundary,equity_green
    from .hx_a7 import equity_a7
    from .hx_equity_fd_independent import solve_boundary_fd,solve_equity_fd
except ImportError:
    from hx_original import HXParams,closed_boundary,equity_green
    from hx_a7 import equity_a7
    from hx_equity_fd_independent import solve_boundary_fd,solve_equity_fd


CASES=(
    ('baseline',{}),
    ('zero_liquidity',{'xi':0.,'k':0.}),
    ('high_vol',{'sigma':.45,'delta':.04,'coupon_total':8.5,'maturity':2.}),
    ('short_maturity',{'sigma':.12,'delta':.05,'xi':4.,'k':.05}),
    ('low_rate_high_vol',{'r':.055,'delta':.025,'sigma':.34,'alpha':.4,'tax':.15}),
    ('mixed',{'xi':6.,'k':.03,'maturity':.5,'delta':.06,'sigma':.15}),
)


class OriginalHXEquityFDTests(unittest.TestCase):
    def test_boundary_slope_root_and_second_order_convergence(self):
        for name,arguments in CASES:
            with self.subTest(panel=name):
                p=HXParams(**arguments)
                baseline=closed_boundary(p)
                b800,_=solve_boundary_fd(p,cells=800)
                b1600,_=solve_boundary_fd(p,cells=1600)
                b3200,reference=solve_boundary_fd(p,cells=3200)
                # Independent FD root without Eq12, with O(h**2) extrapolation.
                rich=(4*b3200-b1600)/3.
                self.assertLess(abs(rich/baseline-1),5e-6)
                self.assertLess(abs(b3200-baseline),abs(b800-baseline))
                self.assertLess(abs(reference.boundary_log_derivative),1e-7)
                self.assertLess(reference.max_equation_residual,1e-7)

    def test_independent_equity_fd_compares_with_green_and_a7(self):
        for name,arguments in CASES:
            with self.subTest(panel=name):
                p=HXParams(**arguments)
                boundary=closed_boundary(p)
                ref=solve_equity_fd(p,boundary,cells=3200)
                for x in (.025,.1,.4,1.,2.,3.):
                    # x_max=8 and cells=3200 => exact grid nodes for 0.025 etc.
                    at=x/ref.h
                    i=int(at)
                    frac=at-i
                    efd=(1-frac)*ref.equity[i]+frac*ref.equity[i+1]
                    target=equity_green(boundary*math.exp(x),boundary,p)
                    self.assertLess(abs(efd-target),
                                    .002*max(1.,abs(target)))
                    if p.xi*p.k>0:
                        a7=equity_a7(boundary*math.exp(x),p,boundary)
                        self.assertLess(abs(efd-a7),
                                        .002*max(1.,abs(a7)))

    def test_far_boundary_and_grid_stability(self):
        p=HXParams()
        b8,_=solve_boundary_fd(p,cells=2400,x_max=8.)
        b10,_=solve_boundary_fd(p,cells=3000,x_max=10.)  # same step
        self.assertLess(abs(b8-b10),3e-4)

    def test_invalid_domain_rejected(self):
        p=HXParams()
        for b,n,L in ((0,1600,8.),(-1,1600,8.),(math.nan,1600,8.),
                      (50.,100,8.),(50.,1600,3.),(50.,1600,math.nan)):
            with self.subTest(boundary=b,cells=n,x_max=L):
                with self.assertRaises(ValueError):
                    solve_equity_fd(p,b,cells=n,x_max=L)
        with self.assertRaises(ValueError):
            solve_boundary_fd(p,trial_1=4,trial_2=2)


if __name__=='__main__':
    unittest.main()
