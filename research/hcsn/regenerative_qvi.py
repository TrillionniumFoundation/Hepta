"""A *new* regenerative optimal-impulse HCSN neuron, not He--Xiong 2012.

Exact stationary QVI for GBM dV/V=(r-delta)dt+sigma*dW, reward
f(V)=delta*V-r*K, fixed reset endpoint R and reset cost c:
   max[(L-r)U+f, U(R)-c-U(V)] = 0.

One-sided lower trigger b is an endogenous free boundary. Closed-form
U(V)=V-K+(b/gamma)*(b/V)**gamma for V>b, and U(R)-c for V<=b,
where gamma is the decaying GBM characteristic root and b solves
   gamma*(R-b-c) = b*(1-(b/R)**gamma).

Value matching and smooth fit are exact. Events use *exact* Brownian
first-passage distributions (conditional inverse Gaussian), not a frame-wise
0/1 surrogate. This is a distinct impulse model, not the paper's A7.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np
from scipy.optimize import brentq
from scipy.special import ndtr


@dataclass(frozen=True)
class RegenerativeParams:
    r:float=.05
    delta:float=.03
    sigma:float=.2
    k:float=1.
    reset_value:float=2.
    reset_cost:float=.20

    def __post_init__(self):
        v=(self.r,self.delta,self.sigma,self.k,self.reset_value,self.reset_cost)
        if not all(math.isfinite(t) for t in v):
            raise ValueError('Nonfinite parameter')
        if not (.001<=self.r<=.3 and .001<=self.delta<=.2
                and .01<=self.sigma<=1. and .1<=self.k<=10.
                and .01<=self.reset_value<=30.
                and 0<self.reset_cost<self.reset_value):
            raise ValueError('No admissible fixed-cost upward-reset problem')

    @property
    def drift_log(self):
        return self.r-self.delta-.5*self.sigma*self.sigma

    @property
    def gamma(self):
        a=self.drift_log/(self.sigma*self.sigma)
        return math.hypot(a,math.sqrt(2*self.r)/self.sigma)+a


def reset_boundary(p:RegenerativeParams) -> float:
    """Unique root on (0,R-cost) of positive smooth-fit condition."""
    g=p.gamma;R=p.reset_value;c=p.reset_cost
    def residual(b):
        return g*(R-b-c)-b*(-math.expm1(g*math.log(b/R)))
    b=brentq(residual,max(1e-13,R*1e-12),R-c,xtol=1e-13)
    if not (0<b<R-c):
        raise ArithmeticError('Degenerate regenerative boundary')
    return b


def regenerative_value(v:float,p:RegenerativeParams) -> float:
    """Exact QVI value for finite positive v under immediate reset region."""
    if not math.isfinite(v) or v<=0:
        raise ValueError('State must be finite and positive')
    b=reset_boundary(p)
    A=b/p.gamma
    if v<=b:
        return b-p.k +A
    return v-p.k + A*math.exp(-p.gamma*math.log(v/b))


def regenerative_residuals(v:float,p:RegenerativeParams):
    """Return both QVI branches (continuation, impulse) and the value."""
    if not math.isfinite(v) or v<=0:raise ValueError('Invalid state')
    b=reset_boundary(p);g=p.gamma
    u=regenerative_value(v,p)
    reward=p.delta*v-p.r*p.k
    imp=regenerative_value(p.reset_value,p)-p.reset_cost-u
    if v>b:
        term=(b/g)*math.exp(-g*math.log(v/b))
        grad=1-g*term/v
        hess=g*(g+1)*term/(v*v)
        continuation=((p.r-p.delta)*v*grad+.5*p.sigma*p.sigma*v*v*hess
                      +reward-p.r*u)
    else:
        continuation=reward-p.r*u
    return continuation,imp,u


def first_passage_cdf(log_distance:float,horizon:float,p:RegenerativeParams):
    """Exact P(hit lower boundary by horizon) for GBM starting above b."""
    if not math.isfinite(log_distance) or log_distance<0:
        raise ValueError('Expected finite nonnegative distance')
    if not math.isfinite(horizon) or horizon<0:
        raise ValueError('Expected nonnegative finite horizon')
    if log_distance==0:return 1.
    if horizon==0:return 0.
    mu=p.drift_log
    s=p.sigma*math.sqrt(horizon)
    first=ndtr((-log_distance-mu*horizon)/s)
    second=math.exp(-2*mu*log_distance/(p.sigma*p.sigma))*ndtr(
        (-log_distance+mu*horizon)/s)
    return float(min(1.,max(0.,first+second)))


def sample_exact_first_passage(start:float,boundary:float,p:RegenerativeParams,
                               rng:np.random.Generator) -> float:
    """Exact first-passage time from log(start/boundary)>0 or infinity.

    For positive drift, hit probability exp(-2*mu*x/sigma^2);
    conditional first-passage time is IG(mean=x/abs(mu), scale=x^2/sigma^2).
    For zero drift this is the Levy distribution x^2/(sigma^2*Z^2).
    """
    if not math.isfinite(start) or not math.isfinite(boundary) or start<=boundary or boundary<=0:
        raise ValueError('Exact first-passage sampler needs start > boundary > 0')
    x=math.log(start/boundary)
    mu=p.drift_log
    if mu>0 and rng.uniform()>math.exp(-2*mu*x/p.sigma**2):
        return math.inf
    if abs(mu)<1e-14:
        return (x/(p.sigma*rng.standard_normal()))**2
    return float(rng.wald(x/abs(mu),x*x/(p.sigma*p.sigma)))


def simulate_regenerative_events(start:float,horizon:float,p:RegenerativeParams,
                                  seed:int=1,max_events:int=10000):
    """Exact cycle renewal sampling; each crossing produces a reset at R.

    Returns observed times and a censoring flag. Event count may be zero.
    max_events guards a pathological cost/reset regime; exhaustion raises.
    """
    if not math.isfinite(start) or start<=0 or not math.isfinite(horizon) or horizon<0:
        raise ValueError('Invalid initial state or horizon')
    if not isinstance(seed,int) or not isinstance(max_events,int) or max_events<1:
        raise ValueError('Invalid deterministic sampler settings')
    b=reset_boundary(p)
    rng=np.random.default_rng(seed)
    t=0.
    events=[]
    if start<=b:
        events.append(t)
        start=p.reset_value
    for _ in range(max_events):
        delta=sample_exact_first_passage(start,b,p,rng)
        if t+delta>horizon:
            return {'boundary':b,'times':events,'horizon':horizon,
                    'events':len(events),'censored':True,'reset_value':p.reset_value}
        t+=delta
        if not math.isfinite(t) or t<=0 or (events and t<=events[-1]):
            raise ArithmeticError('Nonincreasing exact reset time')
        events.append(t)
        start=p.reset_value
    raise RuntimeError('Event budget exhausted; refuse potentially explosive simulation')
