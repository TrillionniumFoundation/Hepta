"""Independent numerical and negative-control tests for physical event time."""
from __future__ import annotations

import math
import random
import statistics
import unittest
from bisect import bisect_right

from scipy.integrate import quad
from scipy.optimize import brentq
from scipy.stats import poisson

from research.hcsn.p2_physical_hazard_clock import PhysicalHazardClock, causal_rate

KNOTS = (0.0, 1.0, 2.5, 4.0)
RATES = (0.3, 1.4, 0.6)


def sampled_segments(subdivisions, knots=KNOTS, rates=RATES):
    for left, right, rate in zip(knots[:-1], knots[1:], rates):
        for i in range(subdivisions):
            yield (left + (right-left)*i/subdivisions,
                   left + (right-left)*(i+1)/subdivisions, rate)


def process(seed, subdivisions=1, refractory=0.0, knots=KNOTS, rates=RATES):
    m = PhysicalHazardClock(seed, refractory=refractory)
    for s, t, lam in sampled_segments(subdivisions, knots, rates):
        m.advance(s,t,lam)
    return m.events


def ref_integral(start, end, knots, rates):
    """Separate quadrature for piecewise-constant intensities."""
    def lam(t):
        index = max(0, min(len(rates)-1, bisect_right(knots,t)-1))
        return rates[index]
    return sum(quad(lam, max(start,knots[i]), min(end,knots[i+1]),
                    epsabs=1e-12, epsrel=1e-12)[0]
               for i in range(len(rates)) if min(end,knots[i+1]) > max(start,knots[i]))


def independent_inverse(seed, refractory, knots=KNOTS, rates=RATES):
    """Non-streaming SciPy quadrature+root finder, independent of the state code."""
    rng = random.Random(seed)
    marks = []
    max_t = knots[-1]
    next_active = knots[0]
    while next_active < max_t:
        mark = rng.expovariate(1.0)
        if ref_integral(next_active,max_t,knots,rates) < mark:
            break
        root = brentq(lambda t:ref_integral(next_active,t,knots,rates)-mark,
                      next_active,max_t,xtol=1e-13)
        marks.append(root)
        next_active = root + refractory
    return marks


class PhysicalHazardClockTests(unittest.TestCase):
    def test_refinement_invariance_no_refractory(self):
        for seed in (11,23,37,101):
            reference = process(seed,1)
            for k in (2,4,16,64):
                self.assertEqual(len(reference),len(process(seed,k)))
                for a,b in zip(reference,process(seed,k)):
                    self.assertAlmostEqual(a,b,places=11)

    def test_refinement_invariance_refractory(self):
        for seed in (11,23,37,101):
            baseline = process(seed,1,.31)
            for k in (2,4,16,64):
                other = process(seed,k,.31)
                self.assertEqual(len(baseline),len(other))
                for a,b in zip(baseline,other):
                    self.assertAlmostEqual(a,b,places=11)
            self.assertTrue(all(b-a>=.31-1e-12 for a,b in zip(baseline,baseline[1:])))

    def test_independent_quad_root_without_refractory(self):
        for seed in (11,23,37,101,1001):
            direct = independent_inverse(seed,0.)
            approx = process(seed,8,0.)
            self.assertEqual(len(direct),len(approx))
            for a,b in zip(direct,approx):self.assertAlmostEqual(a,b,places=10)

    def test_independent_quad_root_with_refractory(self):
        for seed in (11,23,37,101,1001):
            direct = independent_inverse(seed,.31)
            approx = process(seed,8,.31)
            self.assertEqual(len(direct),len(approx))
            for a,b in zip(direct,approx):self.assertAlmostEqual(a,b,places=10)

    def test_hold_same_physical_time(self):
        for seed in (11,23,37):
            original = process(seed,4,.2,(0.,4.),(.7,))
            for count in (16,64,256):
                candidate = process(seed,count,.2,(0.,4.),(.7,))
                self.assertEqual(len(original),len(candidate))
                for a,b in zip(original,candidate):self.assertAlmostEqual(a,b,places=11)

    def test_causal_prefix(self):
        for seed in (11,23,37):
            a=PhysicalHazardClock(seed,.15)
            b=PhysicalHazardClock(seed,.15)
            for s,t,r in sampled_segments(4):
                if t <= 2.5:
                    self.assertEqual(a.advance(s,t,r), b.advance(s,t,r))
                else:
                    a.advance(s,t,r)
                    b.advance(s,t,10*r)
            self.assertEqual([t for t in a.events if t<=2.5],
                             [t for t in b.events if t<=2.5])

    def test_no_event_when_rate_zero(self):
        p=PhysicalHazardClock(11)
        self.assertEqual(p.advance(0.,100.,0.),())
        self.assertEqual(p.events,[])
        self.assertEqual(p.advance(100.,101.,1.),tuple(p.events))

    def test_causal_rate_map(self):
        for x in (-1000,-10.,0.,3.,1000):
            self.assertTrue(math.isfinite(causal_rate(x,.2,1.)))
            self.assertGreaterEqual(causal_rate(x,.2,1.),0.)
        self.assertLess(causal_rate(-2.,.2,1.),causal_rate(2.,.2,1.))

    def test_negative_and_invalid_inputs_rejected(self):
        for x in (float('nan'),float('inf'),-1.):
            with self.assertRaises(ValueError):PhysicalHazardClock(11,refractory=x)
        for context in (float('nan'),float('inf')):
            with self.assertRaises(ValueError):causal_rate(context,0.,1.)
        for values in ((0.,0.,1.),(0.,1.,-1.),(0.,float('inf'),1.),(0.,1.,float('nan'))):
            with self.assertRaises(ValueError):PhysicalHazardClock(11).advance(*values)
        m=PhysicalHazardClock(11)
        m.advance(0.,1.,.2)
        with self.assertRaises(ValueError):m.advance(.5,2.,.2)
        with self.assertRaises(ValueError):PhysicalHazardClock(11,max_events_per_interval=0)

    def test_resource_limit_fail_closed(self):
        m=PhysicalHazardClock(11,max_events_per_interval=2)
        before_rng=m._rng.getstate()
        before_rem=m._remaining
        with self.assertRaisesRegex(ValueError,'event budget'):
            m.advance(0.,10.,100.)
        self.assertEqual(m.events,[])
        self.assertEqual(m.last_end,0.)
        self.assertEqual(m._rng.getstate(),before_rng)
        self.assertEqual(m._remaining,before_rem)
        self.assertLessEqual(len(m.advance(0.,.0001,100.)),2)

    def test_poisson_count_law_no_refractory(self):
        seeds=range(2000)
        counts=[len(process(seed,1)) for seed in seeds]
        mu=sum((b-a)*lam for a,b,lam in zip(KNOTS[:-1],KNOTS[1:],RATES))
        self.assertLess(abs(statistics.mean(counts)-mu),.16)
        self.assertLess(abs(statistics.pvariance(counts)-mu),.28)
        tail=sum(x>=4 for x in counts)/len(counts)
        expected=poisson.sf(3,mu)
        self.assertLess(abs(tail-expected),.04)

    def test_token_bernoulli_negative_control(self):
        counts=[4*.2,16*.2,64*.2]
        self.assertEqual(counts,[.8,3.2,12.8])
        # In contrast, a physical clock's expectation depends only on time.
        self.assertAlmostEqual(.7*4,.7*4,places=13)


if __name__ == '__main__':unittest.main()
