"""Independent distributional and hostile-input tests for bounded drifted BM reset."""
import math
import unittest
import numpy as np
from scipy.integrate import quad
from scipy.special import ndtr
from research.hcsn.p2_defective_first_hit_clock import (
    first_hit_cdf,nth_hit_cdf,eventual_hit_probability,
    first_hit_time_from_exp,DefectiveFirstHitClock,
)

A=0.4
SIGMA=0.4
DRIFTS=(-0.4,-0.12,0.,0.12)
TIMES=(0.25,0.5,1.,4.,16.)
SEEDS=(11,23,37)


def reflection_cdf(t,a,mu,sigma):
    """Independent reflection principle CDF, never calls proposed production CDF."""
    if t==0:
        return 0.
    sd=sigma*math.sqrt(t)
    return float(ndtr((mu*t-a)/sd)+math.exp(2*mu*a/sigma**2)*ndtr((-mu*t-a)/sd))


def density_integral(t,a,mu,sigma):
    """Independent first-hit flux integration; separate SciPy quadrature."""
    if t<=0:
        return 0.
    def f(s):
        if s<=0:return 0.
        z=(a-mu*s)/(sigma*math.sqrt(s))
        return a/(sigma*math.sqrt(2*math.pi*s**3))*math.exp(-0.5*z*z)
    return quad(f,0,t,epsabs=3e-11,epsrel=3e-11,limit=350)[0]


def independent_waits(rng,mu,n,draws=25000,refractory=0.0):
    """Independent direct NumPy Wald / normal-square samples, NO clock or PPF."""
    waits=np.zeros(draws)
    for _ in range(n):
        if mu==0:
            z=rng.standard_normal(draws)
            t=(A/(SIGMA*z))**2
        else:
            t=rng.wald(mean=A/abs(mu),scale=(A/SIGMA)**2,size=draws)
            if mu<0:
                hit=rng.random(draws)<math.exp(2*mu*A/SIGMA**2)
                t=np.where(hit,t,np.inf)
        waits+=t
    return waits+(n-1)*refractory


class DefectiveFirstHitTests(unittest.TestCase):
    def test_exact_reference_cdf_and_flux(self):
        for mu in DRIFTS:
            for n in (1,2,3):
                for t in TIMES:
                    expected=reflection_cdf(t,n*A,mu,SIGMA)
                    ours=nth_hit_cdf(t,n,A,mu,SIGMA)
                    flux=density_integral(t,n*A,mu,SIGMA)
                    self.assertAlmostEqual(ours,expected,delta=3e-11)
                    self.assertAlmostEqual(ours,flux,delta=3e-10)

    def test_eventual_defect_and_geometric_counts(self):
        for mu in DRIFTS:
            q=eventual_hit_probability(A,mu,SIGMA)
            self.assertEqual(q<1,mu<0)
            for n in (1,2,3,4):
                self.assertAlmostEqual(eventual_hit_probability(n*A,mu,SIGMA),q**n,places=13)
        self.assertAlmostEqual(eventual_hit_probability(A,-0.12,SIGMA),math.exp(-0.6),places=14)

    def test_exp_compensator_inversion_and_no_hit(self):
        for mu in DRIFTS:
            q=eventual_hit_probability(A,mu,SIGMA)
            for u in (0.05,0.15,0.35,0.52,0.7,0.95):
                e=-math.log1p(-u)
                t=first_hit_time_from_exp(e,A,mu,SIGMA)
                if u>=q:
                    self.assertTrue(math.isinf(t))
                else:
                    self.assertAlmostEqual(first_hit_cdf(t,A,mu,SIGMA),u,delta=4e-12)

    def test_sampling_refinement_and_refractory(self):
        for mu in DRIFTS:
            for seed in SEEDS:
                a=DefectiveFirstHitClock(seed,drift=mu,refractory=0.07)
                b=DefectiveFirstHitClock(seed,drift=mu,refractory=0.07)
                a.advance(0.,16.)
                for i in range(64):
                    b.advance(i*0.25,(i+1)*0.25)
                self.assertEqual(a.events,b.events)
                self.assertTrue(all(y-x>=0.07 for x,y in zip(a.events,a.events[1:])))
                self.assertTrue(all(0<=x<=16 for x in a.events))

    def test_multi_event_in_coarse_interval(self):
        found=False
        for seed in range(80):
            x=DefectiveFirstHitClock(seed,drift=0.4)
            if len(x.advance(0,16))>=3:
                found=True
                break
        self.assertTrue(found)

    def test_atomic_budget_and_hostile_inputs(self):
        x=DefectiveFirstHitClock(11,drift=0.4,max_events_per_interval=1)
        with self.assertRaisesRegex(ValueError,"budget"):
            x.advance(0,1000)
        self.assertEqual(x.end,0)
        self.assertEqual(x.events,[])
        with self.assertRaises(ValueError):x.advance(0,0)
        with self.assertRaises(ValueError):x.advance(1,2)
        with self.assertRaises(ValueError):first_hit_time_from_exp(float('nan'),A,-0.12,SIGMA)
        with self.assertRaises(ValueError):first_hit_cdf(1,A,-0.12,0)
        with self.assertRaises(ValueError):nth_hit_cdf(1,True,A,0,SIGMA)
        y=DefectiveFirstHitClock(11,drift=0.12)
        y.advance(0,2)
        with self.assertRaises(ValueError):y.advance(1,3)

    def test_independent_monte_carlo_with_refractory(self):
        for seed in SEEDS:
            rng=np.random.default_rng(seed)
            for mu in (-0.12,0.,0.12):
                for n in (1,3):
                    refractory=0.1
                    waits=independent_waits(rng,mu,n,draws=25000,refractory=refractory)
                    for t in (1.,4.,16.):
                        expected=nth_hit_cdf(t,n,A,mu,SIGMA,refractory)
                        actual=float(np.mean(waits<=t))
                        se=math.sqrt(expected*(1-expected)/len(waits))
                        self.assertLess(abs(actual-expected),6*se+0.005)

    def test_negative_drift_ever_hit_monte_carlo(self):
        q=math.exp(-0.6)
        for seed in SEEDS:
            rng=np.random.default_rng(seed)
            for n in (1,2,3):
                empirical=float(np.mean(rng.random((25000,n)).max(axis=1)<q))
                p=q**n
                se=math.sqrt(p*(1-p)/25000)
                self.assertLess(abs(empirical-p),6*se)


if __name__=="__main__":
    unittest.main()
