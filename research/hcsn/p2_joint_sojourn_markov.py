"""Research-only two-mode *joint* sojourn/next-mode semi-Markov clock.

K_ij(dt) = P_ij * lambda_ij * exp(-lambda_ij*dt) dt.
For every source mode i, both experiments match the *marginal* holding-time
mixture sum_j P_ij Exp(lambda_ij) and the embedded transition matrix P, but
oppositely couple destination and duration. They therefore have the same
first-event distribution yet different finite-horizon second/third counts.

The n-th event defective Laplace transform is pi K(s)^n 1, where
K_ij(s) = P_ij * lambda_ij/(lambda_ij+s); all rates strictly positive so
Pr(N(infinity)>=n)=1 for finite n. This synthetic semi-Markov control is
NOT Brownian first passage, He-Xiong HX/QVI, or a learned content boundary.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import random
from typing import Sequence

import numpy as np

PI=(1.,0.)
TRANSITION=((.5,.5),(.5,.5))
COUPLED_FAST_TO_ZERO=((4.,.25),(.7,.07))
COUPLED_FAST_TO_ONE=((.25,4.),(.07,.7))


def checked_kernel(pi:Sequence[float], P:Sequence[Sequence[float]], rates:Sequence[Sequence[float]]):
    """Fail closed for malformed probability, physical rate or tensor shape."""
    a=np.asarray(pi,dtype=np.float64)
    p=np.asarray(P,dtype=np.float64)
    rate=np.asarray(rates,dtype=np.float64)
    if a.shape!=(2,) or p.shape!=(2,2) or rate.shape!=(2,2):
        raise ValueError('expected 2 modes and 2x2 joint kernel')
    if not (np.isfinite(a).all() and np.isfinite(p).all() and np.isfinite(rate).all()):
        raise ValueError('nonfinite probabilities or physical rates')
    if np.any(a<0) or np.any(p<0) or np.any(rate<=0):
        raise ValueError('negative probability or nonpositive rate')
    if not np.isclose(a.sum(),1.,rtol=0,atol=1e-12) or not np.allclose(p.sum(axis=1),1.,rtol=0,atol=1e-12):
        raise ValueError('probability rows not normalized')
    return a,p,rate


def kernel_laplace(s:float, P, rates, *, factorized:bool=False):
    """Joint waiting/destination kernel; factorized null breaks correlation."""
    if not math.isfinite(s) or s<0:
        raise ValueError('Laplace rate must be finite >=0')
    _,p,rate=checked_kernel((1.,0.),P,rates)
    conditional=rate/(rate+s)
    if factorized:
        conditional=np.broadcast_to(np.sum(p*conditional,axis=1,keepdims=True),p.shape)
    return p*conditional


def nth_event_laplace(pi,P,rates,n:int,s:float=0., *,factorized:bool=False):
    if type(n) is not int or not 1<=n<=512:
        raise ValueError('n must be integer 1..512')
    a,p,r=checked_kernel(pi,P,rates)
    k=kernel_laplace(s,p,r,factorized=factorized)
    for _ in range(n):
        a=a@k
    v=float(a.sum())
    if not -1e-12<=v<=1.+1e-12:
        raise ArithmeticError('invalid defective probability')
    return v


def first_hit_cdf(t:float,pi,P,rates):
    """One-event exact mixture from initial modes; not a Brownian first hit."""
    if not math.isfinite(t) or t<0:
        raise ValueError('invalid physical horizon')
    a,p,r=checked_kernel(pi,P,rates)
    return float(np.sum(a[:,None]*p*(-np.expm1(-r*t))))


@dataclass
class JointSojournClock:
    """Pre-scheduled event times, invariant under observation grid splitting.

    Default clock uses the joint (destination, rate) kernel, NOT the
    conditionally independent factorization. Sampling at an event updates the
    current mode; it must not be sampled anew at every observation.
    """
    seed:int
    pi:tuple[float,float]=PI
    transition:tuple[tuple[float,float],tuple[float,float]]=TRANSITION
    rates:tuple[tuple[float,float],tuple[float,float]]=COUPLED_FAST_TO_ZERO
    budget:int=10000
    end:float=0.
    events:list[tuple[float,int,int]]=field(default_factory=list)
    _rng:random.Random=field(init=False,repr=False)
    _mode:int=field(init=False,repr=False)
    _to:int=field(init=False,repr=False)
    _next:float=field(init=False,repr=False)

    @staticmethod
    def _sample(rng,mode,p,r):
        dest=int(rng.random()>=p[mode,0])
        # Exponential waiting time, drawn conditional on the destination.
        delay=-math.log1p(-rng.random())/r[mode,dest]
        if delay<=0 or not math.isfinite(delay):
            raise ArithmeticError('nonrepresentable joint waiting time')
        return dest,delay

    def __post_init__(self):
        self._pi,self._P,self._rates=checked_kernel(self.pi,self.transition,self.rates)
        if type(self.seed) is not int or type(self.budget) is not int or not 1<=self.budget<=1000000:
            raise ValueError('invalid seed or event budget')
        self._rng=random.Random(self.seed)
        self._mode=int(self._rng.random()>=self._pi[0])
        self._to,self._next=self._sample(self._rng,self._mode,self._P,self._rates)

    def advance(self,start:float,end:float):
        if not all(map(math.isfinite,(start,end))) or start!=self.end or end<=start:
            raise ValueError('time must advance in contiguous physical intervals')
        staged=random.Random();staged.setstate(self._rng.getstate())
        mode=self._mode; to=self._to; event_at=self._next; new=[]
        while event_at<=end:
            if len(self.events)+len(new)>=self.budget:
                raise ValueError('event budget exceeded; state not committed')
            new.append((event_at,mode,to))
            mode=to
            to,wait=self._sample(staged,mode,self._P,self._rates)
            event_at+=wait
            if event_at==new[-1][0] or not math.isfinite(event_at):
                raise ArithmeticError('invalid physical event time')
        self._mode=mode;self._to=to;self._next=event_at;self._rng.setstate(staged.getstate())
        self.end=end;self.events.extend(new)
        return tuple(new)
