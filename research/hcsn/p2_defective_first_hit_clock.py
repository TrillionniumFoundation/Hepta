"""Research-only *defective* Brownian first-hit renewal with physical refractory.

Not the original He–Xiong Eq8/11/12/A7/QVI or a trainable HCSN operator.

For X_t=mu*t+sigma*W_t, starting distance a>0 below a fixed barrier:
  F_a(t)=P(tau<=t), q=P(tau<infinity)=min(1,exp(2*mu*a/sigma^2)).
For mu<0, q<1: some paths NEVER hit. A constant positive hazard rate,
including one calibrated at a finite time, incorrectly forces eventual hits.

Each independent regeneration renews the same (a,mu,sigma), followed by a
fixed physical refractory duration. By Lévy/IG first-passage convolution:
  P(N(T)>=n)=F_{n*a}(T-(n-1)*refractory), for valid T.
This identity is exact only for this constrained iid Brownian reset model.

The event scheduler samples a continuous-time waiting time *once per event*,
never once per observation. Its pathwise observations remain sampling-invariant;
this is distributional matching, not recovery of a realized Brownian path.
"""
from __future__ import annotations

from dataclasses import dataclass,field
import math
import random

from scipy.special import erfcinv
from scipy.stats import invgauss


def _params(a:float, mu:float, sigma:float, refractory:float=0.0)->None:
    if not all(math.isfinite(x) for x in (a,mu,sigma,refractory)):
        raise ValueError("nonfinite parameter")
    if a<=0 or sigma<=0 or refractory<0:
        raise ValueError("invalid distance, diffusion or refractory")


def eventual_hit_probability(a:float,mu:float,sigma:float)->float:
    _params(a,mu,sigma)
    return math.exp(2*mu*a/(sigma*sigma)) if mu<0 else 1.0


def first_hit_cdf(t:float,a:float,mu:float,sigma:float)->float:
    """Stable moderate-domain CDF from conditional inverse Gaussian/Levy law."""
    _params(a,mu,sigma)
    if not math.isfinite(t) or t<0:
        raise ValueError("invalid finite time")
    if t==0:
        return 0.0
    if mu==0:
        return math.erfc(a/(sigma*math.sqrt(2*t)))
    mean=a/abs(mu)
    shape=a*a/(sigma*sigma)
    p=float(invgauss.cdf(t,mu=mean/shape,scale=shape))
    return min(eventual_hit_probability(a,mu,sigma)*p,1.0)


def nth_hit_cdf(t:float,n:int,a:float,mu:float,sigma:float,refractory:float=0.0)->float:
    """Exact P(N(t)>=n) with renewed iid drift, volatility, distance, cooldown."""
    _params(a,mu,sigma,refractory)
    if type(n) is not int or n<1:
        raise ValueError("event rank must be positive int")
    if not math.isfinite(t) or t<0:
        raise ValueError("invalid finite time")
    available=t-(n-1)*refractory
    if available<=0:
        return 0.0
    return first_hit_cdf(available,n*a,mu,sigma)


def first_hit_time_from_exp(e:float,a:float,mu:float,sigma:float)->float:
    """Inverse integrated hazard: E~Exp(1) -> tau; tau=inf when E>H(inf)."""
    _params(a,mu,sigma)
    if not math.isfinite(e) or e<=0:
        raise ValueError("expected positive finite exponential draw")
    q=eventual_hit_probability(a,mu,sigma)
    u=-math.expm1(-e)
    if u>=q:
        return math.inf
    if mu==0:
        z=float(erfcinv(u))
        t=a*a/(2*sigma*sigma*z*z)
    else:
        shape=a*a/(sigma*sigma)
        t=float(invgauss.ppf(u/q,mu=(a/abs(mu))/shape,scale=shape))
    if not math.isfinite(t) or t<=0:
        raise ValueError("inverse CDF outside supported FP64 range")
    return t


@dataclass
class DefectiveFirstHitClock:
    """Causal, atomic time observation; no per-sample token-hazard draw."""
    seed:int
    distance:float=0.4
    drift:float=-0.12
    sigma:float=0.4
    refractory:float=0.0
    max_events_per_interval:int=100000
    end:float=0.0
    events:list[float]=field(default_factory=list)
    _rng:random.Random=field(init=False,repr=False)
    _next:float=field(init=False,repr=False)

    def __post_init__(self)->None:
        _params(self.distance,self.drift,self.sigma,self.refractory)
        if type(self.seed) is not int or type(self.max_events_per_interval) is not int or self.max_events_per_interval<1:
            raise ValueError("invalid seed/budget")
        self._rng=random.Random(self.seed)
        self._next=first_hit_time_from_exp(self._rng.expovariate(1.0),self.distance,self.drift,self.sigma)

    def advance(self,start:float,end:float)->tuple[float,...]:
        if not all(math.isfinite(t) for t in (start,end)) or start!=self.end or end<=start:
            raise ValueError("time intervals must be finite, monotone and contiguous")
        # Stage RNG, event time and event list before publishing any state.
        trial=random.Random()
        trial.setstate(self._rng.getstate())
        nxt=self._next
        produced=[]
        while nxt<=end:
            if len(produced)>=self.max_events_per_interval:
                raise ValueError("event budget exceeded; unchanged scheduler")
            produced.append(nxt)
            wait=first_hit_time_from_exp(trial.expovariate(1.0),self.distance,self.drift,self.sigma)
            nxt=math.inf if math.isinf(wait) else nxt+self.refractory+wait
        self._rng.setstate(trial.getstate())
        self._next=nxt
        self.end=end
        self.events.extend(produced)
        return tuple(produced)
