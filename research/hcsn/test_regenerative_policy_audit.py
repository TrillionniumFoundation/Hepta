"""Independent numerical regressions for fixed-policy and optimal QVI values."""
import math
import unittest

import numpy as np

try:
    from .p0_regenerative_policy_audit import (
        boundary_cases,cdf_cases,density_fixed_policy,density_integral,
        mp_boundary,mp_first_passage,
    )
    from .regenerative_qvi import (
        RegenerativeParams,first_passage_cdf,fixed_policy_value,
        regenerative_residuals,regenerative_value,reset_boundary,
    )
except ImportError:
    from p0_regenerative_policy_audit import (
        boundary_cases,cdf_cases,density_fixed_policy,density_integral,
        mp_boundary,mp_first_passage,
    )
    from regenerative_qvi import (
        RegenerativeParams,first_passage_cdf,fixed_policy_value,
        regenerative_residuals,regenerative_value,reset_boundary,
    )


class RegenerativePolicyAuditTests(unittest.TestCase):
    def test_previously_overflowing_cdf_matches_density_integral(self):
        p=RegenerativeParams(r=.001,delta=.2,sigma=.01)
        reference,error=density_integral(.2,1.,p)
        self.assertLess(error,2e-12)
        self.assertAlmostEqual(first_passage_cdf(.2,1.,p),reference,delta=3e-13)
        self.assertAlmostEqual(reference,.4721034647789,delta=2e-12)

    def test_cdf_matches_mp80_across_drift_and_diffusion(self):
        for name,p,x,t in cdf_cases():
            with self.subTest(configuration=name,x=x,t=t):
                reference=mp_first_passage(x,t,p)
                value=first_passage_cdf(x,t,p)
                self.assertTrue(math.isfinite(value))
                self.assertGreaterEqual(value,0.)
                self.assertLessEqual(value,1.)
                self.assertAlmostEqual(value,reference,delta=3e-13)

    def test_horizon_monotonicity_and_defective_positive_drift(self):
        p=RegenerativeParams(r=.08,delta=.015,sigma=.2)
        values=[first_passage_cdf(.2,t,p) for t in (0.,.01,.1,1.,10.,1e5)]
        self.assertTrue(all(a<=b for a,b in zip(values,values[1:])))
        eventual=math.exp(-2*p.drift_log*.2/(p.sigma*p.sigma))
        self.assertLess(eventual,1.)
        self.assertAlmostEqual(values[-1],eventual,delta=2e-15)
        p0=RegenerativeParams(r=.125,delta=.09375,sigma=.25)
        self.assertEqual(p0.drift_log,0.)
        self.assertAlmostEqual(first_passage_cdf(.2,1.,p0),
                               math.erfc(.2/(.25*math.sqrt(2))),delta=2e-15)

    def test_extreme_finite_clocks_do_not_return_nan(self):
        for p in (RegenerativeParams(r=.001,delta=.2,sigma=.01),
                  RegenerativeParams(r=.08,delta=.015,sigma=.2)):
            for x,t in ((1e300,1e-300),(1.,1e300),(1e300,1e300)):
                with self.subTest(x=x,t=t):
                    value=first_passage_cdf(x,t,p)
                    self.assertTrue(math.isfinite(value))
                    self.assertTrue(0<=value<=1)
        self.assertEqual(first_passage_cdf(0.,0.,RegenerativeParams()),1.)

    def test_invalid_cdf_and_fixed_policy_inputs_refuse(self):
        p=RegenerativeParams()
        for x,t in ((-1,1),(1,-1),(math.nan,1),(1,math.inf)):
            with self.assertRaises(ValueError):first_passage_cdf(x,t,p)
        for v,b in ((0,1),(math.inf,1),(1,0),(1,-1),(1,math.nan),
                    (1,p.reset_value),(1,p.reset_value+1),(True,1),(1,True)):
            with self.assertRaises(ValueError):fixed_policy_value(v,b,p)
        with self.assertRaises(TypeError):fixed_policy_value(1.,.5,object())

    def test_fixed_policy_renewal_uses_given_threshold(self):
        p=RegenerativeParams()
        for b in (.4,.9,1.6):
            for v in (b/2,b,1.8,2.,4.):
                with self.subTest(threshold=b,state=v):
                    reference=density_fixed_policy(v,b,p)
                    self.assertAlmostEqual(fixed_policy_value(v,b,p),reference,delta=2e-11)
            self.assertAlmostEqual(fixed_policy_value(b,b,p),
                                   fixed_policy_value(p.reset_value,b,p)-p.reset_cost,
                                   delta=2e-12)

    def test_fixed_policy_does_not_silently_enforce_smooth_fit(self):
        p=RegenerativeParams()
        b=.5*p.reset_value
        step=b*1e-6
        gradient=(fixed_policy_value(b+step,b,p)-fixed_policy_value(b,b,p))/step
        self.assertGreater(abs(gradient),.1)
        self.assertAlmostEqual(fixed_policy_value(b*(1-1e-8),b,p),
                               fixed_policy_value(b,b,p),delta=1e-14)

    def test_near_reset_threshold_keeps_cost_and_finite_negative_value(self):
        p=RegenerativeParams()
        b=math.nextafter(p.reset_value,0.)
        value=fixed_policy_value(p.reset_value,b,p)
        self.assertTrue(math.isfinite(value))
        self.assertLess(value,-1e12)
        # Removing reset cost in this regime would incorrectly remove the
        # divergent repeated intervention loss.
        self.assertLess(fixed_policy_value(b,b,p),-1e12)

    def test_optimal_qvi_dominates_fixed_threshold_strategies(self):
        for _,p in boundary_cases()[:3]:
            b=reset_boundary(p)
            for state in (.2*b,b,1.2*b,p.reset_value,4*p.reset_value):
                optimum=regenerative_value(state,p)
                self.assertAlmostEqual(fixed_policy_value(state,b,p),optimum,
                                       delta=2e-11*max(1.,abs(optimum)))
                for threshold in np.linspace(.03,.97,49)*p.reset_value:
                    fixed=fixed_policy_value(state,float(threshold),p)
                    self.assertGreaterEqual(optimum-fixed,-2e-10*max(1.,abs(optimum)))

    def test_boundary_matches_independent_mp80_for_cost_limits(self):
        for name,p in boundary_cases():
            with self.subTest(configuration=name):
                reference=mp_boundary(p)
                actual=reset_boundary(p)
                self.assertGreater(actual,0.)
                self.assertLess(actual,p.reset_value-p.reset_cost)
                self.assertAlmostEqual(actual/reference,1.,delta=4e-12)

    def test_zero_cost_and_maximum_cost_limits_are_separate(self):
        p=RegenerativeParams(reset_cost=2e-10)
        b=reset_boundary(p)
        scale=math.sqrt(2*p.reset_cost/(p.reset_value*(p.gamma+1)))
        self.assertAlmostEqual(math.log(p.reset_value/b)/scale,1.,delta=1e-5)
        q=RegenerativeParams(reset_cost=math.nextafter(2.,0.))
        bq=reset_boundary(q)
        self.assertAlmostEqual(bq/(q.reset_value-q.reset_cost),q.gamma/(q.gamma+1),
                               delta=2e-13)
        with self.assertRaises(ArithmeticError):
            reset_boundary(RegenerativeParams(reset_cost=1e-320))
        for cost in (0.,2.):
            with self.assertRaises(ValueError):RegenerativeParams(reset_cost=cost)

    def test_reset_region_satisfies_generator_inequality(self):
        for _,p in boundary_cases():
            b=reset_boundary(p)
            for ratio in (.01,.5,1.):
                v=ratio*b
                generator,impulse,value=regenerative_residuals(v,p)
                expected=p.delta*(v-b)-.5*p.sigma*p.sigma*(p.gamma+1)*b
                self.assertAlmostEqual(generator,expected,delta=2e-12*max(1.,abs(value)))
                self.assertLessEqual(generator,2e-12)
                self.assertAlmostEqual(impulse,0.,delta=2e-11*max(1.,abs(value)))


if __name__=='__main__':
    unittest.main(verbosity=2)
