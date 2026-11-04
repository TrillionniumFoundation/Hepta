"""Research-only *input-conditioned* joint marked hazard candidate (P2 OPEN).

This is a competing-risk continuous-time Markov marked point process, NOT a
He-Xiong free-boundary first hit, regenerative QVI, trained neural controller,
or validated Selective Copy/MQAR model. For mode i and input x held constant,
hazard for destination j is R[i,j]*exp(beta*x), including j=i events.

The event's destination is drawn *at the event* from its competing hazards.
The residual unit-exponential budget persists across observation splits and
changes in causal input. No future input is used. Event budget errors are
atomic. The only learned scalar beta is fit from downstream final event parity,
never event times or destinations; this is a narrow task-only identifiability
probe rather than an endorsement of the mechanistic model.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import random
from typing import Sequence
import numpy as np
from scipy.linalg import expm

DEFAULT_RATES=((4.0,0.25),(0.7,0.07))


def checked_rates(rates:Sequence[Sequence[float]]):
    a=np.asarray(rates,dtype=float)
    if a.shape!=(2,2) or not np.isfinite(a).all() or (a<=0).any():
        raise ValueError('rates must be finite positive 2x2 matrix')
    return a


def marked_rates(rates,beta:float,x:float):
    base=checked_rates(rates)
    if not all(map(math.isfinite,(beta,x))) or abs(beta*x)>8:
        raise ValueError('non-finite or out-of-domain beta*x')
    v=base*math.exp(beta*x)
    if not np.isfinite(v).all() or (v<=0).any():
        raise ValueError('invalid physical marked rates')
    return v


def parity_generator(rates,beta:float,x:float):
    """Independent-task observation states: (parity,mode), no event timestamps."""
    lam=marked_rates(rates,beta,x)
    Q=np.zeros((4,4),dtype=float)
    for parity in (0,1):
        for mode in (0,1):
            source=2*parity+mode
            Q[source,source]-=float(lam[mode].sum())
            for dest in (0,1):
                Q[source,2*(1-parity)+dest]+=lam[mode,dest]
    return Q


def parity_probability(segments, beta:float, rates=DEFAULT_RATES):
    """Exact finite-state transfer for piecewise-constant causal input schedule.

    Segments are (physical duration, input) pairs; initial state (mode=0,
    parity=0). Final parity is the task-only output.
    """
    v=np.array([1.,0.,0.,0.],dtype=float)
    if not segments:raise ValueError('nonempty causal segments required')
    for duration,x in segments:
        if not math.isfinite(duration) or duration<=0:
            raise ValueError('physical duration must be finite positive')
        v=v@expm(parity_generator(rates,beta,x)*duration)
    prob=float(v[2]+v[3])
    if not math.isfinite(prob) or not -1e-11<=prob<=1+1e-11:
        raise ArithmeticError('probability not representable')
    return min(1.,max(0.,prob))


@dataclass
class InputHazardClock:
    seed:int
    beta:float
    rates:tuple[tuple[float,float],tuple[float,float]]=DEFAULT_RATES
    budget:int=10000
    end:float=0.0
    mode:int=0
    events:list[tuple[float,int,int]]=field(default_factory=list)
    _rng:random.Random=field(init=False,repr=False)
    _remaining:float=field(init=False,repr=False)

    def __post_init__(self):
        checked_rates(self.rates)
        if type(self.seed) is not int or type(self.budget) is not int or not 1<=self.budget<=1000000:
            raise ValueError('invalid seed or event budget')
        if not math.isfinite(self.beta) or self.mode not in (0,1):
            raise ValueError('invalid beta or initial mode')
        self._rng=random.Random(self.seed)
        self._remaining=-math.log1p(-self._rng.random())
        if not self._remaining>0:raise ArithmeticError('invalid initial hazard budget')

    def advance(self,start:float,end:float,x:float):
        if not all(map(math.isfinite,(start,end))) or start!=self.end or end<=start:
            raise ValueError('physical intervals must be positive and contiguous')
        lam=marked_rates(self.rates,self.beta,x)
        staged=random.Random();staged.setstate(self._rng.getstate())
        t=start;mode=self.mode;remaining=self._remaining;ev=[]
        while t<end:
            row=lam[mode]
            total=float(row.sum());delta=end-t
            if remaining>total*delta:
                remaining-=total*delta
                t=end
                break
            hit=t+remaining/total
            if not math.isfinite(hit) or hit<=t:
                raise ArithmeticError('nonrepresentable autonomous event time')
            if len(self.events)+len(ev)>=self.budget:
                raise ValueError('event budget exceeded; no partial commit')
            dest=int(staged.random()>=row[0]/total)
            ev.append((hit,mode,dest));mode=dest;t=hit
            remaining=-math.log1p(-staged.random())
            if remaining<=0:raise ArithmeticError('nonrepresentable hazard budget')
        self.mode=mode;self._remaining=remaining
        self._rng.setstate(staged.getstate());self.end=end
        self.events.extend(ev)
        return tuple(ev)


def task_parity(segments, seed:int, beta:float, rates=DEFAULT_RATES):
    """Return only final parity; no event supervision is surfaced to trainer."""
    clock=InputHazardClock(seed,beta,rates=rates)
    t=0.0
    for delta,x in segments:
        clock.advance(t,t+delta,x)
        t+=delta
    return len(clock.events)&1
