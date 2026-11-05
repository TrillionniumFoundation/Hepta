"""Independent density quadrature, sampled bridges, and fail-closed P2 clock tests."""
import math
import unittest

import numpy as np
from scipy.integrate import quad

from .p2_hidden_first_hit_clock import (
    first_crossing_probability, first_hit_time_posterior, first_hit_time_quantile,
)


def independent_first_hit_time_integral(a, b, T, sigma, cutoff):
    """Independent first-passage density x Gaussian continuation / endpoint density."""
    def density(u):
        if u == 0 or u == T: return 0.
        logpdf = (math.log(a) + .5*math.log(T) - math.log(sigma)
                  - .5*math.log(2*math.pi) - 1.5*math.log(u) - .5*math.log(T-u)
                  - a*a/(2*sigma*sigma*u)
                  - b*b/(2*sigma*sigma*(T-u))
                  + (b-a)**2/(2*sigma*sigma*T))
        return math.exp(logpdf)
    return quad(density, 0, cutoff, epsabs=2e-12, epsrel=2e-12, limit=450)[0]


class HiddenEventClockTests(unittest.TestCase):
    def test_integral_vs_independent_first_hit_density(self):
        for a,b,T,sigma in [(.4,.4,1.,.4),(.28,.65,1.3,.6),(.7,.26,2.,.9),(.3,.7,.5,.8)]:
            for fraction in (.2,.48,.75):
                calc=first_hit_time_posterior(a,b,T,sigma,T*fraction)
                reference=independent_first_hit_time_integral(a,b,T,sigma,T*fraction)
                self.assertAlmostEqual(calc['joint_probability_first_hit_by_elapsed'],reference,delta=5e-10)

    def test_endpoints_monotone_and_total_bridge_risk(self):
        a,b,T,s=.4,.4,1.,.4
        v=[first_hit_time_posterior(a,b,T,s, k*T/100) for k in range(101)]
        self.assertEqual(v[0]['joint_probability_first_hit_by_elapsed'],0.)
        self.assertAlmostEqual(v[-1]['joint_probability_first_hit_by_elapsed'],math.exp(-2),places=14)
        self.assertTrue(all(v[i]['first_hit_time_cdf_given_crossing']<=v[i+1]['first_hit_time_cdf_given_crossing'] for i in range(100)))
        self.assertTrue(all(0 <= z['first_hit_time_cdf_given_crossing'] <=1 for z in v))
        self.assertTrue(all(z['retrospective_requires_future_endpoint'] and not z['realized_event_time_known'] for z in v))

    def test_refractory_clock_nonidentifiability_witness(self):
        # Endpoints remain safe.  There is nonzero conditional first-hit mass
        # on BOTH sides of a physical deadline inside the missing interval.
        a=b=s=.4;T=1.;deadline=.5
        mid=first_hit_time_posterior(a,b,T,s,deadline)
        self.assertAlmostEqual(mid['first_hit_time_cdf_given_crossing'],.6681020012231705,places=12)
        self.assertGreater(mid['crossing_probability'],.13)
        self.assertGreater(mid['first_hit_time_cdf_given_crossing'],.6)
        self.assertGreater(1-mid['first_hit_time_cdf_given_crossing'],.3)
        self.assertEqual(mid['scientific_gate'],'OPEN')

    def test_conditional_quantiles_and_time_unit_scaling(self):
        a,b,T,s=.4,.4,1.,.4
        qs=[first_hit_time_quantile(a,b,T,s,q) for q in (.1,.5,.9)]
        self.assertTrue(0 < qs[0] < qs[1] < qs[2] < T)
        self.assertAlmostEqual(qs[1],.4032847880037543,delta=1e-11)
        for q,t in zip((.1,.5,.9),qs):
            self.assertAlmostEqual(first_hit_time_posterior(a,b,T,s,t)['first_hit_time_cdf_given_crossing'],q,delta=2e-12)
            self.assertAlmostEqual(first_hit_time_quantile(a,b,T*10,s/math.sqrt(10),q),t*10,delta=2e-10)

    def test_independent_sampled_bridge_at_interior_time(self):
        # Independent MC: sample X_u conditional on two positive endpoints,
        # then sample whether the bridge over [0,u] first crosses zero.
        a,b,T,s,u=.4,.55,1.2,.52,.57
        rng=np.random.default_rng(20261101)
        n=180_000
        alpha=u/T
        m=(1-alpha)*a+alpha*b
        std=s*math.sqrt(u*(1-alpha))
        y=m+std*rng.standard_normal(n)
        p=np.exp(-2*a*np.maximum(y,0)/(s*s*u))
        hits=(y<=0)|(rng.random(n)<p)
        observed=float(hits.mean())
        expected=first_hit_time_posterior(a,b,T,s,u)['joint_probability_first_hit_by_elapsed']
        se=math.sqrt(expected*(1-expected)/n)
        self.assertLess(abs(observed-expected),5*se)

    def test_reject_invalid_or_uncertified_inputs(self):
        for vals in [(0.,.4,1.,.4),(.4,-1.,1.,.4),(.4,.4,0.,.4),(.4,.4,1.,0.),
                     (.4,.4,float('nan'),.4),(True,.4,1.,.4),(.4,.4,1.,float('inf')),
                     (20.,20.,.01,.05),(.4,.4,100.,.4)]:
            with self.assertRaises(ValueError): first_crossing_probability(*vals)
        for elapsed in (-.1,1.1,float('nan'),True):
            with self.assertRaises(ValueError): first_hit_time_posterior(.4,.4,1.,.4,elapsed)
        for quantile in (-.1,1.1,float('nan'),True):
            with self.assertRaises(ValueError): first_hit_time_quantile(.4,.4,1.,.4,quantile)

    def test_different_drifts_same_bridge_posterior_given_endpoints(self):
        # Constant drift is eliminated by conditioning on both endpoints.
        # A deterministic affine boundary also changes only relative drift.
        baseline=first_hit_time_posterior(.4,.6,2.,.7,.8)
        a,b,T,u=.4,.6,2.,.8
        for drift,barrier_slope in [(-.2,-.1),(.4,.9),(1.1,-.5)]:
            relative_drift=drift-barrier_slope
            conditional_mean=a+relative_drift*u+(u/T)*(b-a-relative_drift*T)
            self.assertAlmostEqual(conditional_mean,(1-u/T)*a+(u/T)*b,places=14)
            same=first_hit_time_posterior(a,b,T,.7,u)
            self.assertEqual(baseline,same)

if __name__=='__main__': unittest.main()
