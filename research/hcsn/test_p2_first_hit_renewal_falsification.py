"""Independent numerical, event-stream and multi-seed tests of first-hit mismatch."""
from __future__ import annotations

import math
import unittest

import numpy as np
from scipy.integrate import quad
from scipy.special import erfc
from scipy.stats import norm, poisson

from research.hcsn.p2_first_hit_renewal_falsification import (
    brownian_nth_hit_cdf, calibrated_constant_hazard, poisson_nth_event_cdf,
)
from research.hcsn.p2_physical_hazard_clock import PhysicalHazardClock

DISTANCE=0.4
SIGMA=0.4
TIMES=(.25, .5, 1., 4., 16.)
SEEDS=(11,23,37)


def brownian_density(t, distance=DISTANCE, sigma=SIGMA):
    if t<=0: return 0.
    z=distance/sigma
    return z/math.sqrt(2*math.pi) * t**(-1.5) * math.exp(-z*z/(2*t))


def independent_density_integral(t, n):
    # n Levy increments have *exactly* the same first-hit density with scale n*a.
    return quad(lambda s: brownian_density(s, n*DISTANCE, SIGMA),
                0., t, epsabs=8e-12, epsrel=8e-12, limit=200)[0]


def monte_carlo_prefix_counts(seed, size=40000, max_hits=3):
    """Independent inverse-Gaussian-normal sampling of the Brownian renewal law.

    Z^2 inverse construction uses Brownian first-hit distribution, not the model
    under test nor a Poisson simulator. Adjacent events use independent Z draws.
    """
    rng=np.random.default_rng(seed)
    z=rng.standard_normal((size,max_hits))
    with np.errstate(divide='ignore',over='ignore'):
        increments=(DISTANCE/SIGMA)**2/(z*z)
    return np.cumsum(increments,axis=1)


class FirstHitFalsificationTests(unittest.TestCase):
    def test_analytical_brownian_vs_independent_quadrature(self):
        for t in TIMES:
            for n in (1,2,3):
                actual=brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA)
                independent=independent_density_integral(t,n)
                self.assertAlmostEqual(actual,independent,delta=8e-10)

    def test_analytical_brownian_vs_normal_tail(self):
        for t in TIMES:
            for n in (1,2,3):
                expected=2*norm.sf(n*DISTANCE/(SIGMA*math.sqrt(t)))
                self.assertAlmostEqual(brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA),expected,delta=2e-15)

    def test_analytical_poisson_vs_independent_scipy_reference(self):
        lam=calibrated_constant_hazard(1.,DISTANCE,SIGMA)
        for t in TIMES:
            for n in (1,2,3):
                self.assertAlmostEqual(poisson_nth_event_cdf(t,n,lam),
                                       poisson.sf(n-1,lam*t),delta=1e-14)

    def test_horizon_matched_but_early_and_ood_late_mismatch(self):
        rate=calibrated_constant_hazard(1.,DISTANCE,SIGMA)
        self.assertAlmostEqual(brownian_nth_hit_cdf(1.,1,DISTANCE,SIGMA),
                               poisson_nth_event_cdf(1.,1,rate),delta=1e-14)
        self.assertGreater(poisson_nth_event_cdf(.25,1,rate)-
                           brownian_nth_hit_cdf(.25,1,DISTANCE,SIGMA),.04)
        self.assertGreater(poisson_nth_event_cdf(16.,1,rate)-
                           brownian_nth_hit_cdf(16.,1,DISTANCE,SIGMA),.19)
        self.assertGreater(poisson_nth_event_cdf(16.,3,rate)-
                           brownian_nth_hit_cdf(16.,3,DISTANCE,SIGMA),.48)

    def test_exact_stable_multi_reset_scaling(self):
        # S_n is Levy-stable, not Gamma: P(S_n<=t) = P(S_1<=t/n^2).
        for t in TIMES:
            for n in (1,2,3):
                self.assertAlmostEqual(brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA),
                                       brownian_nth_hit_cdf(t/(n*n),1,DISTANCE,SIGMA),delta=1e-15)

    def test_independent_three_seed_levy_sampler(self):
        for seed in SEEDS:
            cumulative=monte_carlo_prefix_counts(seed)
            for t in (.25,1.,4.,16.):
                for n in (1,2,3):
                    estimate=float(np.mean(cumulative[:,n-1] <= t))
                    reference=brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA)
                    se=math.sqrt(reference*(1-reference)/len(cumulative))
                    self.assertLess(abs(estimate-reference),5*se+0.001)

    def test_actual_clock_matches_poisson_not_brownian_at_ood_time(self):
        rate=calibrated_constant_hazard(1.,DISTANCE,SIGMA)
        # Unmodified #512 implementation, not a separate Poisson simulator.
        count=0
        for seed in range(1000):
            c=PhysicalHazardClock(seed,0.)
            c.advance(0.,16.,rate)
            count+=(len(c.events)>=3)
        observed=count/1000.
        exp_poisson=poisson_nth_event_cdf(16.,3,rate)
        exp_brownian=brownian_nth_hit_cdf(16.,3,DISTANCE,SIGMA)
        self.assertLess(abs(observed-exp_poisson),.035)
        self.assertGreater(observed-exp_brownian,.44)

    def test_no_invalid_time_or_normalization(self):
        for args in ((-1.,1,.4,.4), (1.,0,.4,.4),(1.,1,0,.4),
                     (1.,1,.4,0), (float('nan'),1,.4,.4)):
            with self.assertRaises(ValueError):brownian_nth_hit_cdf(*args)
        with self.assertRaises(ValueError):poisson_nth_event_cdf(1.,0,.5)
        with self.assertRaises(ValueError):poisson_nth_event_cdf(-1.,1,.5)


if __name__ == '__main__':unittest.main()
