"""Separate exhaustive/mode-trajectory and physical-clock numerical checks."""
import itertools
import math
import unittest
from scipy.integrate import quad
from scipy.special import ndtr
import numpy as np

from research.hcsn.p2_markov_defective_firsthit import (
    eventual_q,eventual_atleast,nth_event_laplace,laplace_phi,
    first_hit_cdf,first_hit_density,inverse_wait,MarkovDefectiveClock,
)

A=(0.4,0.4);MU=(-0.4,0.12);SIG=(0.4,0.4);R=(0.1,0.2)
PI=(0.5,0.5)
STAY=((0.95,0.05),(0.05,0.95))
FLIP=((0.05,0.95),(0.95,0.05))


def enumerate_laplace(pi,P,a,mu,sigma,r,n,s):
    """2^n path enumeration; no matrix evaluator or shared per-mode Laplace."""
    total=0.
    for z in itertools.product(range(2),repeat=n):
        weight=pi[z[0]]
        for u,v in zip(z,z[1:]):weight*=P[u][v]
        for k,m in enumerate(z):
            root=math.sqrt(mu[m]**2+2*sigma[m]**2*s)
            weight*=math.exp(a[m]*(mu[m]-root)/sigma[m]**2)
            if k<n-1:weight*=math.exp(-s*r[m])
        total+=weight
    return total


def independent_reflection(t,a,mu,sigma):
    if t==0:return 0.
    sd=sigma*math.sqrt(t)
    return float(ndtr((mu*t-a)/sd)+math.exp(2*mu*a/sigma**2)*ndtr((-mu*t-a)/sd))


def exact_two_hit_cdf(t,pi,P,a,mu,sigma,r):
    """Independent first-event flux × second-event CDF convolution."""
    v=0.
    for i in (0,1):
        for j in (0,1):
            if t<=r[i]:continue
            f=lambda u: first_hit_density(u,a[i],mu[i],sigma[i])*independent_reflection(t-r[i]-u,a[j],mu[j],sigma[j])
            v+=pi[i]*P[i][j]*quad(f,0,t-r[i],epsabs=2e-10,epsrel=2e-9,limit=220)[0]
    return v


def direct_np_exact_sampler(N,seed,pi,P,a,mu,sigma,r,max_rank,t):
    """External NumPy Wald / Bernoulli sampler, no candidate quantile or clock."""
    rng=np.random.default_rng(seed)
    states=(rng.random(N)>=pi[0]).astype(int)
    arrival=np.zeros(N)
    rows=[]
    for k in range(max_rank):
        draws=np.empty(N,dtype=float)
        for state in (0,1):
            idx=states==state
            nn=int(np.sum(idx))
            if mu[state]==0:
                normals=rng.standard_normal(nn)
                with np.errstate(divide='ignore'):
                    draws[idx]=(a[state]/(sigma[state]*normals))**2
            else:
                draws[idx]=rng.wald(mean=a[state]/abs(mu[state]),scale=(a[state]/sigma[state])**2,size=nn)
                if mu[state]<0:
                    keep=rng.random(nn)<math.exp(2*mu[state]*a[state]/sigma[state]**2)
                    draws[idx]=np.where(keep,draws[idx],np.inf)
        arrival+=draws
        rows.append((float(np.mean(arrival<=t)),float(np.mean(np.isfinite(arrival)))))
        old=states
        states=(rng.random(N)>=np.asarray(P)[old,0]).astype(int)
        arrival+=np.asarray(r)[old]
    return rows


class TestMarkovDefectiveFirstHit(unittest.TestCase):
    def test_analytic_defect_mass_and_monotone(self):
        q=eventual_q(A,MU,SIG)
        self.assertAlmostEqual(q[0],math.exp(-2),places=13)
        self.assertEqual(q[1],1.)
        x=eventual_atleast(PI,STAY,A,MU,SIG,R,15)
        self.assertTrue(np.all(x[:-1]>=x[1:]))
        self.assertLess(eventual_atleast(PI,STAY,A,MU,SIG,R,100)[-1],0.1)
        self.assertGreater(x[0],0.5)

    def test_absorption_atom_and_repeated_positive_mode_events(self):
        q=float(eventual_q(.4,-.4,.4))
        self.assertTrue(math.isinf(inverse_wait(q,.4,-.4,.4)))
        self.assertTrue(math.isinf(inverse_wait(.9,.4,-.4,.4)))
        # An absorbing no-hit path is not re-sampled at subsequent observations.
        for seed in range(10):
            z=MarkovDefectiveClock(seed,pi=(1.,0.),transition=((1.,0.),(0.,1.)),drift=(-.4,.12))
            z.advance(0.,4.)
            if math.isinf(z._next):
                previous=list(z.events)
                z.advance(4.,100.)
                self.assertEqual(z.events,previous)
        # Independent positive-drift reset cycles can have several real events.
        self.assertTrue(any(len(MarkovDefectiveClock(seed,pi=(0.,1.),transition=((0.,1.),(0.,1.))).advance(0.,16.))>=3 for seed in range(40)))

    def test_exhaustive_paths_laplace(self):
        for p in (STAY,FLIP):
            for s in (0.,0.001,0.13,1.5):
                for n in range(1,8):
                    v=nth_event_laplace(PI,p,A,MU,SIG,R,n,s)
                    exp=enumerate_laplace(PI,p,A,MU,SIG,R,n,s)
                    self.assertAlmostEqual(v,exp,delta=5e-14)

    def test_laplace_zero_matches_eventual_tail(self):
        for p in (STAY,FLIP):
            v=eventual_atleast(PI,p,A,MU,SIG,R,12)
            np.testing.assert_allclose(v,[nth_event_laplace(PI,p,A,MU,SIG,R,n,0.) for n in range(1,13)],rtol=0,atol=4e-15)

    def test_falsify_scalar_mean_q(self):
        x=eventual_atleast(PI,STAY,A,MU,SIG,R,6)
        y=eventual_atleast(PI,FLIP,A,MU,SIG,R,6)
        naive=float(PI@eventual_q(A,MU,SIG)) if isinstance(PI,np.ndarray) else float(np.array(PI)@eventual_q(A,MU,SIG))
        self.assertAlmostEqual(x[0],y[0],places=14)
        self.assertGreater(abs(x[2]-y[2]),.05)
        self.assertGreater(abs(x[2]-naive**3),.03)

    def test_independent_first_hit_reflection_and_flux(self):
        for mu in (-.4,-.12,0.,.12):
            for t in (.5,1.,4.,16.):
                f=first_hit_cdf(t,.4,mu,.4)
                e=independent_reflection(t,.4,mu,.4)
                d=quad(lambda s: first_hit_density(s,.4,mu,.4),0,t,epsabs=1e-10)[0]
                self.assertAlmostEqual(f,e,delta=2e-14)
                self.assertAlmostEqual(f,d,delta=4e-11)

    def test_independent_two_event_convolution_and_mc(self):
        t=8.
        for P in (STAY,FLIP):
            theory=exact_two_hit_cdf(t,PI,P,A,MU,SIG,R)
            for seed in (11,23,37):
                result=direct_np_exact_sampler(45000,seed,PI,P,A,MU,SIG,R,3,t)
                empirical=result[1][0]
                se=math.sqrt(theory*(1-theory)/45000)
                self.assertLess(abs(empirical-theory),6*se+0.003)
                for i,v in enumerate(result):
                    tail=nth_event_laplace(PI,P,A,MU,SIG,R,i+1,0.)
                    se=math.sqrt(tail*(1-tail)/45000)
                    self.assertLess(abs(v[1]-tail),6*se+.003)

    def test_refinement_event_mode_and_refractory(self):
        for P in (STAY,FLIP):
            for seed in (11,23,37):
                a=MarkovDefectiveClock(seed,transition=P)
                b=MarkovDefectiveClock(seed,transition=P)
                a.advance(0.,16.)
                for i in range(64):b.advance(i*.25,(i+1)*.25)
                self.assertEqual(a.events,b.events)
                self.assertTrue(all(y[0]-x[0]>=R[x[1]] for x,y in zip(a.events,a.events[1:])))

    def test_budget_failure_is_atomic(self):
        a=MarkovDefectiveClock(7,drift=(.6,.6),distance=(.1,.1),sigma=(.4,.4),budget=1)
        with self.assertRaisesRegex(ValueError,'budget'):a.advance(0.,100.)
        self.assertEqual(a.end,0.)
        self.assertEqual(a.events,[])
        a.budget=1000
        a.advance(0.,5.)
        b=MarkovDefectiveClock(7,drift=(.6,.6),distance=(.1,.1),sigma=(.4,.4),budget=1000)
        b.advance(0.,5.)
        self.assertEqual(a.events,b.events)

    def test_fail_closed_inputs(self):
        for x in (
            lambda:MarkovDefectiveClock(1,pi=(.7,.7)),
            lambda:MarkovDefectiveClock(1,transition=((1.1,-.1),(.2,.8))),
            lambda:MarkovDefectiveClock(1,sigma=(.1,0)),
            lambda:MarkovDefectiveClock(1,refractory=(0,-.2)),
            lambda:MarkovDefectiveClock(True),
            lambda:nth_event_laplace(PI,STAY,A,MU,SIG,R,True,0),
            lambda:nth_event_laplace(PI,STAY,A,MU,SIG,R,3,-.01),
            lambda:eventual_atleast(PI,STAY,A,MU,SIG,R,10000),
            lambda:inverse_wait(0.,.4,-.1,.4),
        ):
            with self.assertRaises(ValueError):x()
        a=MarkovDefectiveClock(11)
        with self.assertRaises(ValueError):a.advance(0.,0.)
        with self.assertRaises(ValueError):a.advance(1.,2.)

if __name__=='__main__':unittest.main()
