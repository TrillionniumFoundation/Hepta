"""Independent P0 economic admissibility negative-evidence regression tests."""
import math
from dataclasses import replace
import unittest

import numpy as np

try:
    from .hx_original import HXParams, equity_green, running_reward
    from .hx_equity_fd_independent import solve_equity_fd
    from .hx_local_obstacle_sign import (screen_hx_smooth_fit,
                                           crosscheck_boundary_bond)
except ImportError:
    from hx_original import HXParams, equity_green, running_reward
    from hx_equity_fd_independent import solve_equity_fd
    from hx_local_obstacle_sign import screen_hx_smooth_fit, crosscheck_boundary_bond


# All values within the existing finite exploratory HXParams bounds.
# r>delta and recovery<face are independently verified, not assumed.
HIGH_LIQUIDITY = HXParams(r=.10, delta=.075, sigma=.20, alpha=.40,
                          tax=.27, xi=4., k=.20, maturity=3.,
                          coupon_total=5., face_total=100.)


class HXLocalObstacleSignTests(unittest.TestCase):
    def test_paper_baseline_has_only_necessary_condition_not_acceptance(self):
        p=HXParams()
        got=screen_hx_smooth_fit(p)
        self.assertEqual(got.classification,'NO_LOCAL_SIGN_OBSTRUCTION_ONLY')
        self.assertAlmostEqual(got.boundary,67.44151539060374,delta=2e-8)
        self.assertLess(got.boundary_net_cashflow,-20.)
        self.assertGreater(got.boundary_log_curvature,0)
        self.assertFalse(got.limited_liability_admitted)
        self.assertFalse(got.global_optimality_established)
        self.assertFalse(got.production_activation)
        self.assertAlmostEqual(crosscheck_boundary_bond(p),0,delta=1e-12)

    def test_economically_recovered_below_face_but_negative_local_equity(self):
        p=HIGH_LIQUIDITY
        got=screen_hx_smooth_fit(p)
        self.assertGreater(p.r,p.delta)
        self.assertLess(got.recovery_over_face,.8)
        self.assertEqual(got.classification,'REJECT_NEGATIVE_EQUITY_NEAR_BOUNDARY')
        self.assertAlmostEqual(got.boundary,197.52085498628088,delta=2e-8)
        self.assertAlmostEqual(got.boundary_net_cashflow,4.16684478880852,delta=1e-9)
        self.assertAlmostEqual(got.boundary_log_curvature,-208.3422394404259,delta=1e-7)
        self.assertAlmostEqual(crosscheck_boundary_bond(p),0,delta=1e-12)
        self.assertAlmostEqual(running_reward(0.,got.boundary,p),
                               got.boundary_net_cashflow,delta=1e-10)
        self.assertFalse(got.limited_liability_admitted)

    def test_independent_green_solution_is_negative_and_has_local_curvature(self):
        p=HIGH_LIQUIDITY
        screen=screen_hx_smooth_fit(p)
        v=screen.boundary
        # Unmodified original Eq11 Green expression, independent of this screen.
        for x in (.005,.02,.05):
            self.assertLess(equity_green(v*math.exp(x),v,p),-1e-3 if x>=.02 else -1e-4)
        # E(0)=E_x(0)=0 => E(x)/x^2 -> .5 E_xx(0+); geometric probing.
        estimates=[equity_green(v*math.exp(x),v,p)/(x*x)
                   for x in (.02,.01,.005)]
        exact=.5*screen.boundary_log_curvature
        self.assertLess(abs(estimates[-1]-exact),.1*abs(exact))
        self.assertLess(abs(estimates[-1]-exact),abs(estimates[0]-exact))

    def test_independent_equity_fd_confirms_signed_counterexample(self):
        p=HIGH_LIQUIDITY
        b=screen_hx_smooth_fit(p).boundary
        observed=[]
        for cells in (800,1600,3200):
            z=solve_equity_fd(p,b,cells=cells,x_max=7.)
            window=(z.x>=.025)&(z.x<=.09)
            m=float(np.min(z.equity[window]))
            observed.append(m)
            self.assertLess(m,-.05)
            self.assertLess(z.max_equation_residual,1e-7)
        self.assertLess(abs(observed[-1]-observed[-2]),.01)
        self.assertLess(abs(observed[-1]-observed[-2]),abs(observed[-2]-observed[0]))

    def test_discount_product_invariance_and_near_threshold_nonadmission(self):
        p=HIGH_LIQUIDITY
        q=replace(p,xi=8.,k=.1)  # Same xi*k drives original financial bond Eq8.
        a,b=screen_hx_smooth_fit(p),screen_hx_smooth_fit(q)
        self.assertAlmostEqual(a.boundary,b.boundary,delta=2e-8)
        self.assertAlmostEqual(a.boundary_net_cashflow,b.boundary_net_cashflow,delta=2e-9)
        self.assertEqual(a.classification,b.classification)
        # Deliberately mark even a strong negative sign as indeterminate by
        # using a bounded coarse ambiguity margin; it must never imply acceptance.
        self.assertFalse(screen_hx_smooth_fit(HXParams(),relative_sign_buffer=1e-3).limited_liability_admitted)

    def test_fails_closed_on_invalid_threshold_and_parameter_type(self):
        p=HXParams()
        for x in (float('nan'),float('inf'),0,-1,1e-15, .1, True):
            with self.assertRaises(ValueError):screen_hx_smooth_fit(p,relative_sign_buffer=x)
        with self.assertRaises(TypeError):screen_hx_smooth_fit({'r':.1})


if __name__=='__main__':unittest.main(verbosity=2)
