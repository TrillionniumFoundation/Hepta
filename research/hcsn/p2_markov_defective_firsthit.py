"""Research-only Markov-modulated *defective* Brownian first-hit renewal.

Event-driven mode transitions P_ij, fixed per-mode distance a_i>0, drift
mu_i, diffusion sigma_i, outgoing-mode dead time r_i. No mode changes before
an event or during refractory, and each Brownian excursion is independent.

A negative drift has an atom at infinite first-hit time. For each state i,
q_i=P(tau_i<inf)=min(1,exp(2*mu_i*a_i/sigma_i**2)).
For pi as the distribution of the FIRST excursion state, the exact eventual
n-th event probability is pi D_q (P D_q)^(n-1) 1, not (pi@q)^n.

For s>=0 the *defective* Laplace transform of the n-th EVENT TIME is
pi D_phi(s) [D_exp(-s*r) P D_phi(s)]^(n-1) 1, with
phi_i(s)=exp[(mu_i-sqrt(mu_i**2+2*sigma_i**2*s))*a_i/sigma_i**2].
These equalities assume independent post-hit Brownian resets, not HX QVI,
learned controls, or pathwise recovery of hidden actual Brownian events.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import random
from typing import Sequence

import numpy as np
from scipy.special import erfcinv
from scipy.stats import invgauss


def _probabilities(pi:Sequence[float], P:Sequence[Sequence[float]]):
    pi=np.asarray(pi,dtype=np.float64)
    P=np.asarray(P,dtype=np.float64)
    if pi.shape!=(2,) or P.shape!=(2,2) or not np.isfinite(pi).all() or not np.isfinite(P).all():
        raise ValueError('requires finite two-mode pi and P')
    if np.any(pi<0) or np.any(P<0) or not np.isclose(pi.sum(),1.,rtol=0,atol=1e-12) or not np.allclose(P.sum(axis=1),1.,rtol=0,atol=1e-12):
        raise ValueError('invalid mode probabilities')
    return pi,P


def _physical_params(a,mu,sigma,r):
    a=np.asarray(a,dtype=np.float64)
    mu=np.asarray(mu,dtype=np.float64)
    sigma=np.asarray(sigma,dtype=np.float64)
    r=np.asarray(r,dtype=np.float64)
    if any(z.shape!=(2,) or not np.isfinite(z).all() for z in (a,mu,sigma,r)):
        raise ValueError('requires finite two-mode physical parameters')
    if np.any(a<=0) or np.any(sigma<=0) or np.any(r<0):
        raise ValueError('invalid distance/diffusion/refractory')
    return a,mu,sigma,r


def eventual_q(a,mu,sigma):
    """Exactly the event/no-event mass (not a finite-horizon CDF)."""
    a=np.asarray(a);mu=np.asarray(mu);sigma=np.asarray(sigma)
    if np.any(~np.isfinite(a)) or np.any(~np.isfinite(mu)) or np.any(~np.isfinite(sigma)) or np.any(a<=0) or np.any(sigma<=0):
        raise ValueError('invalid first-hit parameters')
    return np.exp(np.minimum(0.,2*np.asarray(mu)*np.asarray(a)/np.asarray(sigma)**2))


def laplace_phi(s:float,a,mu,sigma):
    """Unconditional discounted first-hit probability, incl. atom at infinity."""
    if not math.isfinite(s) or s<0:
        raise ValueError('Laplace rate must be finite and nonnegative')
    a=np.asarray(a);mu=np.asarray(mu);sigma=np.asarray(sigma)
    if np.any(~np.isfinite(a)) or np.any(~np.isfinite(mu)) or np.any(~np.isfinite(sigma)) or np.any(a<=0) or np.any(sigma<=0):
        raise ValueError('invalid physical parameters')
    # Avoid catastrophic cancellation at small s and positive mu by rationalizing.
    root=np.sqrt(mu**2+2*sigma**2*s)
    exponent=np.where(mu>0,-2*s*a/(root+mu+np.finfo(float).tiny),a*(mu-root)/sigma**2)
    return np.exp(exponent)


def nth_event_laplace(pi,P,a,mu,sigma,refractory,n:int,s:float=0.):
    """E[exp(-s*tau_n) 1(tau_n<inf)] with mode-specific refractory."""
    if type(n) is not int or n<1 or n>512:
        raise ValueError('n must be an int in [1,512]')
    pi,P=_probabilities(pi,P)
    a,mu,sigma,r=_physical_params(a,mu,sigma,refractory)
    phi=laplace_phi(s,a,mu,sigma)
    row=pi*phi
    for _ in range(1,n):
        row=(row*np.exp(-s*r))@P*phi
    value=float(row.sum())
    if not (-1e-12<=value<=1+1e-12):
        raise ArithmeticError('outside admissible probability range')
    return value


def eventual_atleast(pi,P,a,mu,sigma,refractory,max_events:int=12):
    """Exact P[N(infinity)>=n], n=1..K; tail is NOT renormalized."""
    if type(max_events) is not int or not 1<=max_events<=512:
        raise ValueError('invalid event budget')
    pi,P=_probabilities(pi,P)
    a,mu,sigma,r=_physical_params(a,mu,sigma,refractory)
    q=eventual_q(a,mu,sigma)
    row=pi.copy()
    atleast=[]
    for _ in range(max_events):
        row=row*q
        atleast.append(float(row.sum()))
        row=row@P
    return np.asarray(atleast,dtype=np.float64)


def first_hit_cdf(t:float,a:float,mu:float,sigma:float):
    """Independent scalar CDF via conditional inverse-Gaussian/Levy."""
    if not all(map(math.isfinite,(t,a,mu,sigma))) or t<0 or a<=0 or sigma<=0:
        raise ValueError('invalid scalar first-hit input')
    if t==0:return 0.
    if mu==0:return math.erfc(a/(sigma*math.sqrt(2*t)))
    shape=a*a/(sigma*sigma)
    chance=float(eventual_q(a,mu,sigma))
    return chance*float(invgauss.cdf(t,mu=(a/abs(mu))/shape,scale=shape))


def first_hit_density(t:float,a:float,mu:float,sigma:float):
    if not all(map(math.isfinite,(t,a,mu,sigma))) or t<0 or a<=0 or sigma<=0:
        raise ValueError('invalid density input')
    if t==0:return 0.
    z=(a-mu*t)/(sigma*math.sqrt(t))
    return a/(sigma*math.sqrt(2*math.pi*t**3))*math.exp(-z*z/2)


def inverse_wait(u:float,a:float,mu:float,sigma:float):
    """Map fixed latent U in (0,1) to an absolute first-hit waiting time."""
    if not all(map(math.isfinite,(u,a,mu,sigma))) or not (0<u<1) or a<=0 or sigma<=0:
        raise ValueError('invalid quantile input')
    q=float(eventual_q(a,mu,sigma))
    if u>=q:return math.inf
    if mu==0:
        z=float(erfcinv(u))
        out=a*a/(2*sigma*sigma*z*z)
    else:
        shape=a*a/(sigma*sigma)
        out=float(invgauss.ppf(u/q,mu=(a/abs(mu))/shape,scale=shape))
    if not math.isfinite(out) or out<=0:
        raise ValueError('floating-point first-hit quantile not representable')
    return out


@dataclass
class MarkovDefectiveClock:
    """A research-only distribution sampler; not an observed-BM event oracle."""
    seed:int
    pi:tuple[float,float]=(0.5,0.5)
    transition:tuple[tuple[float,float],tuple[float,float]]=((0.95,0.05),(0.05,0.95))
    distance:tuple[float,float]=(0.4,0.4)
    drift:tuple[float,float]=(-0.4,0.12)
    sigma:tuple[float,float]=(0.4,0.4)
    refractory:tuple[float,float]=(0.1,0.2)
    budget:int=10000
    end:float=0.
    events:list[tuple[float,int]]=field(default_factory=list)
    _rng:random.Random=field(init=False,repr=False)
    _mode:int=field(init=False,repr=False)
    _next:float=field(init=False,repr=False)
    def __post_init__(self):
        self._pi,self._P=_probabilities(self.pi,self.transition)
        self._a,self._mu,self._sig,self._r=_physical_params(self.distance,self.drift,self.sigma,self.refractory)
        if type(self.seed) is not int or type(self.budget) is not int or not (1<=self.budget<=1000000):
            raise ValueError('invalid seed or budget')
        self._rng=random.Random(self.seed)
        self._mode=int(self._rng.random()>=self._pi[0])
        self._next=inverse_wait(self._rng.random(),self._a[self._mode],self._mu[self._mode],self._sig[self._mode])
    def advance(self,start:float,end:float):
        if not all(map(math.isfinite,(start,end))) or start!=self.end or end<=start:
            raise ValueError('noncontiguous or nonmonotone physical time')
        # Commit only AFTER staging the entire interval incl. the RNG state.
        trial=random.Random();trial.setstate(self._rng.getstate())
        mode=self._mode; next_at=self._next; produced=[]
        while next_at<=end:
            if len(produced)>=self.budget:raise ValueError('event budget exceeded')
            produced.append((next_at,mode))
            old_mode=mode
            mode=int(trial.random()>=self._P[old_mode,0])
            wait=inverse_wait(trial.random(),self._a[mode],self._mu[mode],self._sig[mode])
            next_at=(next_at+float(self._r[old_mode])+wait) if math.isfinite(wait) else math.inf
        self._rng.setstate(trial.getstate());self._mode=mode;self._next=next_at;self.end=end
        self.events.extend(produced)
        return tuple(produced)
