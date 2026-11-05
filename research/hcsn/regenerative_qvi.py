"""A *new* regenerative optimal-impulse HCSN neuron, not He--Xiong 2012.

Exact stationary QVI for GBM dV/V=(r-delta)dt+sigma*dW, reward
f(V)=delta*V-r*K, fixed reset endpoint R and reset cost c:
   max[(L-r)U+f, U(R)-c-U(V)] = 0.

One-sided lower trigger b is an endogenous free boundary. Closed-form
U(V)=V-K+(b/gamma)*(b/V)**gamma for V>b, and U(R)-c for V<=b,
where gamma is the decaying GBM characteristic root and b solves
   gamma*(R-b-c) = b*(1-(b/R)**gamma).

``fixed_policy_value`` separately evaluates a supplied threshold by a renewal
equation. It does not optimize that threshold or impose smooth fit. The
``reset_boundary``/``regenerative_value`` pair optimizes the intervention time
for this fixed R/c model; neither operation is the original HX economics.

Value matching and smooth fit hold in the mathematical model. Events use Brownian
first-passage distributions (conditional inverse Gaussian), not a frame-wise
0/1 surrogate. Implementations are finite-precision research references; they
do not certify every real parameter, an arbitrary reset map, or neural benefit.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np
from scipy.optimize import brentq
from scipy.special import erfcx, ndtr


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
        # Rationalize the small root when negative drift would subtract two
        # almost equal positive numbers. This also conditions renewal values.
        mu=self.drift_log
        disc=math.hypot(mu,math.sqrt(2*self.r)*self.sigma)
        if mu<0:
            return 2*self.r/(disc-mu)
        return (disc+mu)/(self.sigma*self.sigma)


def _log_ratio(a:float,b:float)->float:
    """Log(a/b) for positive floats, retaining a representable nearby gap."""
    if abs(a-b)<=.5*b:
        return math.log1p((a-b)/b)
    return math.log(a)-math.log(b)


def _reset_cost_fraction(w:float,g:float)->float:
    """c/R implied by w=log(R/b), including its quadratic zero-cost limit."""
    if (g+1)*w<.01:
        # [g-(g+1)exp(-w)+exp(-(g+1)w)]/g starts at w^2.
        # Expand the whole expression; subtracting two O(w) terms loses the
        # small positive reset cost. Ten terms suffice in this bounded branch.
        leading=((g+1)*w)*w
        polynomial=power=1.
        factorial=2.
        terms=[leading/2]
        for n in range(3,11):
            power*=w
            polynomial=power+(g+1)*w*polynomial
            factorial*=n
            terms.append((-1. if n%2 else 1.)*leading*polynomial/factorial)
        return math.fsum(terms)
    return math.fsum((-math.expm1(-w),
                      math.exp(-w)*math.expm1(-g*w)/g))


def reset_boundary(p:RegenerativeParams) -> float:
    """Unique fixed-R/c smooth-fit root, using dimensionless brackets.

    Near c=R, solve for b/(R-c) so an arbitrary absolute lower bound cannot
    exclude the root. Near c=0, solve for log(R/b) without subtracting the
    leading O(log(R/b)) terms. A trigger indistinguishable from R in binary64
    is refused, rather than being turned into an instantaneous reset loop.
    """
    g=p.gamma;R=p.reset_value;c=p.reset_cost
    if c<=R/2:
        fraction=c/R
        estimate=math.sqrt(fraction)*math.sqrt(2/(g+1))
        if fraction==0 or math.exp(-estimate)==1.:
            raise ArithmeticError('Reset trigger is not distinct from R in binary64')
        upper=2*estimate
        while _reset_cost_fraction(upper,g)<fraction:
            upper*=2
        w=brentq(lambda z:_reset_cost_fraction(z,g)-fraction,0.,upper,
                 xtol=math.ulp(0.),rtol=8*np.finfo(float).eps)
        b=R*math.exp(-w)
    else:
        remaining=R-c
        log_fraction=_log_ratio(remaining,R)
        def residual(t):
            if t==0:return g
            return g*(1-t)+t*math.expm1(g*(log_fraction+math.log(t)))
        ratio=brentq(residual,0.,1.,xtol=math.ulp(0.),
                     rtol=8*np.finfo(float).eps)
        b=remaining*ratio
    if not (0<b<R-c):
        raise ArithmeticError('Degenerate regenerative boundary')
    return b


def fixed_policy_value(v:float,threshold:float,p:RegenerativeParams)->float:
    """Value of a GIVEN lower trigger followed by a reset to p.reset_value.

    With H_b(v)=E_v[exp(-r*tau_b);tau_b<infinity]=(b/v)^gamma,
    the one-cycle reward is (v-K)-H_b(v)*(b-K). The repeated-cycle
    value follows from renewal, not a smooth-fit equation:

        U_b(v)=v-K+H_b(v)*(R-b-c)/(1-H_b(R)),  v>b.

    For v<=b the policy resets immediately and U_b(v)=U_b(R)-c.
    Any finite 0<b<R is permitted, including a costly suboptimal policy.
    No stopping/abandonment action is included in this impulse problem.
    """
    if not isinstance(p,RegenerativeParams):
        raise TypeError('RegenerativeParams required')
    if any(isinstance(x,bool) or not isinstance(x,(int,float))
           or not math.isfinite(x) or x<=0 for x in (v,threshold)):
        raise ValueError('State and threshold must be finite positive numbers')
    R=p.reset_value
    if threshold>=R:
        raise ValueError('Fixed policy requires threshold < reset value')
    log_discount=-p.gamma*_log_ratio(R,threshold)
    denominator=-math.expm1(log_discount)
    if not math.isfinite(denominator) or denominator<=0:
        raise ArithmeticError('Renewal cycle is not contractive in binary64')
    bonus=math.fsum((R,-threshold,-p.reset_cost))/denominator
    if v<=threshold:
        value=math.fsum((threshold,-p.k,bonus))
    else:
        hit=math.exp(-p.gamma*_log_ratio(v,threshold))
        value=math.fsum((v,-p.k,hit*bonus))
    if not math.isfinite(value):
        raise ArithmeticError('Nonfinite fixed-policy renewal value')
    return value


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
    """P(hit lower boundary by horizon), with stable reflection terms.

    Negative log drift can make exp(-2*mu*x/sigma^2) overflow although its
    product with Phi((-x+mu*t)/(sigma*sqrt(t))) is a probability. Combining
    the Gaussian exponent first gives .5*exp(-z1^2/2)*erfcx(-z2/sqrt(2)).
    Both factors are bounded for mu<=0; no infinity-times-zero is evaluated.
    """
    if not math.isfinite(log_distance) or log_distance<0:
        raise ValueError('Expected finite nonnegative distance')
    if not math.isfinite(horizon) or horizon<0:
        raise ValueError('Expected nonnegative finite horizon')
    if log_distance==0:return 1.
    if horizon==0:return 0.
    mu=p.drift_log
    root_time=math.sqrt(horizon)
    scaled_distance=log_distance/(p.sigma*root_time)
    scaled_drift=(mu/p.sigma)*root_time
    z1=-scaled_distance-scaled_drift
    z2=-scaled_distance+scaled_drift
    first=float(ndtr(z1))
    if mu<=0:
        second=.5*math.exp(-.5*z1*z1)*float(erfcx(-z2/math.sqrt(2)))
    else:
        second=math.exp((-2*mu/p.sigma)*(log_distance/p.sigma))*float(ndtr(z2))
    value=first+second
    if not math.isfinite(value) or not -1e-12<=value<=1+1e-12:
        raise ArithmeticError('Invalid first-passage probability')
    return min(1.,max(0.,value))


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
