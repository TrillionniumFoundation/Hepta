"""Independent path enumeration, phase-type and SciPy flux references."""
import itertools
import math
import unittest

import numpy as np
from scipy.linalg import expm
from scipy.integrate import quad

from research.hcsn.p2_joint_sojourn_markov import (
    PI,TRANSITION,COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE,
    checked_kernel,kernel_laplace,nth_event_laplace,first_hit_cdf,JointSojournClock,
)


def enumerate_laplace(pi,P,rates,n,s,*,factorized=False):
    """Independent scalar path expansion without candidate matrix routine."""
    total=0.
    for chain in itertools.product(range(2),repeat=n+1):
        probability=pi[chain[0]]
        for i,j in zip(chain,chain[1:]):
            mixture=sum(P[i][k]*rates[i][k]/(rates[i][k]+s) for k in (0,1))
            probability*=P[i][j]*(mixture if factorized else rates[i][j]/(rates[i][j]+s))
        total+=probability
    return total


def phase_type_nth_cdf(t,pi,P,rates,n):
    """Exact independent path-enumerated absorption of n exponential stages.

    Triangular transient generator expm handles repeated rates without
    partial-fraction cancellation. Not the candidate's Laplace evaluator.
    """
    if t<0 or n<1:raise ValueError('invalid horizon/rank')
    total=0.
    for chain in itertools.product(range(2),repeat=n+1):
        weight=pi[chain[0]]
        ls=[]
        for i,j in zip(chain,chain[1:]):
            weight*=P[i][j]
            ls.append(rates[i][j])
        Q=np.diag(-np.asarray(ls,dtype=float))
        for k in range(n-1):Q[k,k+1]=ls[k]
        cdf=1.-float(expm(Q*t)[0].sum())
        total+=weight*cdf
    return total


def double_first_event_flux(t,pi,P,rates):
    """Independent double convolution via scalar quadrature, no expm."""
    total=0.
    for i,j,k in itertools.product((0,1),repeat=3):
        first=rates[i][j]; second=rates[j][k]
        integral=quad(lambda u:first*math.exp(-first*u)*(-math.expm1(-second*(t-u))),
                      0.,t,epsabs=2e-13,epsrel=2e-12)[0]
        total+=pi[i]*P[i][j]*P[j][k]*integral
    return total


def numpy_event_mc(npaths,seed,pi,P,rates,max_rank,horizons=(1.,4.)):
    """Independent NumPy destination-Bernoulli and Exp sampler, vectorized."""
    rng=np.random.default_rng(seed)
    mode=(rng.random(npaths)>=pi[0]).astype(int)
    arrival=np.zeros(npaths)
    rows=[]
    for _ in range(max_rank):
        nxt=(rng.random(npaths)>=np.asarray(P)[mode,0]).astype(int)
        lam=np.asarray(rates)[mode,nxt]
        arrival+=rng.exponential(size=npaths)/lam
        rows.append({str(h):int(np.count_nonzero(arrival<=h)) for h in horizons})
        mode=nxt
    return rows

class TestJointSojournMarkov(unittest.TestCase):
    def test_same_embedded_chain_and_per_mode_holding_mixture(self):
        A=np.array(COUPLED_FAST_TO_ZERO);B=np.array(COUPLED_FAST_TO_ONE)
        np.testing.assert_array_equal(np.sort(A,axis=1),np.sort(B,axis=1))
        for i in (0,1):
            for t in (.01,.25,1.,4.,20.):
                f=lambda m:sum(TRANSITION[i][j]*(-math.expm1(-m[i][j]*t)) for j in (0,1))
                self.assertAlmostEqual(f(COUPLED_FAST_TO_ZERO),f(COUPLED_FAST_TO_ONE),delta=2e-15)
        for t in (0.,.25,1.,4.,8.):
            self.assertAlmostEqual(first_hit_cdf(t,PI,TRANSITION,A),first_hit_cdf(t,PI,TRANSITION,B),delta=2e-15)

    def test_laplace_enumeration_and_factorized_control(self):
        for R in (COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE):
            for factorized in (False,True):
                for s in (0.,.05,.5,2.,17.):
                    for n in range(1,7):
                        actual=nth_event_laplace(PI,TRANSITION,R,n,s,factorized=factorized)
                        expected=enumerate_laplace(PI,TRANSITION,R,n,s,factorized=factorized)
                        self.assertAlmostEqual(actual,expected,delta=2e-14)

    def test_finite_horizon_exact_reference_vs_scalar_flux(self):
        for R in (COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE):
            for t in (.25,1.,4.):
                a=phase_type_nth_cdf(t,PI,TRANSITION,R,2)
                b=double_first_event_flux(t,PI,TRANSITION,R)
                self.assertAlmostEqual(a,b,delta=1e-13)

    def test_strong_negative_finite_time_while_first_rank_equal(self):
        A=COUPLED_FAST_TO_ZERO; B=COUPLED_FAST_TO_ONE
        for t in (.25,1.,2.,4.,8.):
            self.assertAlmostEqual(phase_type_nth_cdf(t,PI,TRANSITION,A,1),
                                   phase_type_nth_cdf(t,PI,TRANSITION,B,1),delta=1e-13)
        second_diff=phase_type_nth_cdf(1.,PI,TRANSITION,A,2)-phase_type_nth_cdf(1.,PI,TRANSITION,B,2)
        third_diff=phase_type_nth_cdf(1.,PI,TRANSITION,A,3)-phase_type_nth_cdf(1.,PI,TRANSITION,B,3)
        self.assertGreater(second_diff,.12)
        self.assertGreater(third_diff,.09)
        self.assertAlmostEqual(nth_event_laplace(PI,TRANSITION,A,3,0.),1.,delta=1e-15)
        self.assertAlmostEqual(nth_event_laplace(PI,TRANSITION,B,3,0.),1.,delta=1e-15)

    def test_independent_monte_carlo_fixed_seeds(self):
        npaths=50000
        for R in (COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE):
            for seed in (11,23,37):
                obs=numpy_event_mc(npaths,seed,PI,TRANSITION,R,3)
                for rank in (1,2,3):
                    for T in (1.,4.):
                        expected=phase_type_nth_cdf(T,PI,TRANSITION,R,rank)
                        measured=obs[rank-1][str(T)]/npaths
                        se=math.sqrt(expected*(1.-expected)/npaths)
                        self.assertLess(abs(expected-measured),6*se+2/npaths)

    def test_partition_invariant_physical_event_times(self):
        for R in (COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE):
            for seed in (11,23,37):
                a=JointSojournClock(seed,rates=R)
                b=JointSojournClock(seed,rates=R)
                a.advance(0.,12.)
                for i in range(96):b.advance(i/8.,(i+1)/8.)
                self.assertEqual(a.events,b.events)
                self.assertTrue(all(ev[0]>0 for ev in a.events))
                self.assertTrue(all(y[0]>x[0] and x[2]==y[1] for x,y in zip(a.events,a.events[1:])))

    def test_atomic_failure_and_timing_reject(self):
        a=JointSojournClock(11,budget=1)
        with self.assertRaisesRegex(ValueError,'budget'):a.advance(0.,20.)
        self.assertEqual(a.end,0.)
        self.assertEqual(a.events,[])
        a.budget=10000;a.advance(0.,20.)
        b=JointSojournClock(11,budget=10000);b.advance(0.,20.)
        self.assertEqual(a.events,b.events)
        with self.assertRaises(ValueError):a.advance(19.,21.)
        with self.assertRaises(ValueError):a.advance(20.,20.)

    def test_invalid_inputs_fail_closed(self):
        bad=[lambda:checked_kernel(PI,TRANSITION,((0.,1.),(.2,.4))),
             lambda:checked_kernel(PI,TRANSITION,((float('nan'),1.),(.2,.4))),
             lambda:checked_kernel((.7,.7),TRANSITION,COUPLED_FAST_TO_ZERO),
             lambda:checked_kernel(PI,((.6,.6),(.5,.5)),COUPLED_FAST_TO_ZERO),
             lambda:checked_kernel(PI,TRANSITION,((1.,),(.2,.4))),
             lambda:kernel_laplace(-.1,TRANSITION,COUPLED_FAST_TO_ZERO),
             lambda:nth_event_laplace(PI,TRANSITION,COUPLED_FAST_TO_ZERO,True,1.),
             lambda:nth_event_laplace(PI,TRANSITION,COUPLED_FAST_TO_ZERO,513,1.),
             lambda:JointSojournClock(True),
             lambda:JointSojournClock(1,budget=0)]
        for fn in bad:
            with self.assertRaises(ValueError):fn()

if __name__=='__main__':unittest.main()
