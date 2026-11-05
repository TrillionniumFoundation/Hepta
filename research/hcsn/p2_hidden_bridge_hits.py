"""Research-only P2: unobserved barrier crossings inside an observation gap.

For X(t)=x0+mu*t+sigma*W(t) and a deterministic affine barrier on each
observation interval, the signed margin has a Brownian bridge conditional on
its endpoints. When both endpoints are strictly positive the conditional
probability of a hidden FIRST crossing is exp(-2*x0*x1/(sigma**2*dt)).

This is a conditional PROBABILITY, never a realized spike or a differentiable
sampled event time. It is exact only for constant diffusion and an affine
barrier over each observed interval. Nonlinear input-driven barriers, QVI,
refractory interactions and repeated autonomous resets are not solved here.
P0-P6 remain OPEN; no production path or scientific admission is exposed.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
import numpy as np
from scipy.special import log_ndtr

@dataclass(frozen=True)
class BridgeRiskState:
    last_margin: np.ndarray
    last_time: np.ndarray
    log_survival: np.ndarray


def conditional_hidden_hit(x0: float, x1: float, dt: float, sigma: float) -> float:
    """P(a lower-barrier crossing | endpoints), including observed hits."""
    if not all(type(q) in (float,int,np.float64) and math.isfinite(q) for q in (x0,x1,dt,sigma)):
        raise ValueError('nonfinite or invalid physical input')
    if not 0 < dt <= 1e6 or not 0 < sigma <= 10 or abs(x0)>100 or abs(x1)>100:
        raise ValueError('outside bounded Brownian research domain')
    if x0 <= 0 or x1 <= 0:
        return 1.0
    return math.exp(-2*x0*x1/(sigma*sigma*dt))


def first_hit_cdf(x0:float, drift:float, sigma:float, horizon:float) -> float:
    """Independent one-sided reflection-principle first-hit reference."""
    if not all(type(q) in (float,int,np.float64) and math.isfinite(q) for q in (x0,drift,sigma,horizon)):
        raise ValueError('nonfinite or invalid physical input')
    if not 0 < x0 <= 100 or not -10 <= drift <= 10 or not 0 < sigma <= 10 or not 0 < horizon <= 1e6:
        raise ValueError('outside bounded reflection reference domain')
    s=sigma*math.sqrt(horizon)
    z0=(-x0-drift*horizon)/s
    z1=(-x0+drift*horizon)/s
    logp=np.logaddexp(log_ndtr(z0),-2*drift*x0/(sigma*sigma)+log_ndtr(z1))
    return float(min(1.,max(0.,math.exp(float(logp)))))


def _checked(margins:np.ndarray,times:np.ndarray,sigma:float,state:BridgeRiskState|None):
    if not (isinstance(margins,np.ndarray) and margins.ndim==2 and margins.dtype==np.float64
            and isinstance(times,np.ndarray) and times.dtype==np.float64 and times.shape==margins.shape
            and 1 <= margins.shape[0] <= 256 and margins.shape[1]>=1 and margins.size<=500000):
        raise ValueError('require bounded FP64 [batch, samples] margin/time arrays')
    if not np.isfinite(margins).all() or not np.isfinite(times).all() or (times<0).any() or (abs(margins)>100).any():
        raise ValueError('bad observation')
    if type(sigma) not in (float,int) or not math.isfinite(sigma) or not 0<sigma<=10:
        raise ValueError('invalid diffusion units')
    if (np.diff(times,axis=1)<=0).any():
        raise ValueError('timestamps must strictly increase')
    b=margins.shape[0]
    if state is None:
        last=margins[:,0].copy()
        t=times[:,0].copy()
        logsurv=np.where(last<=0,-np.inf,0.)
        return BridgeRiskState(last,t,logsurv),1
    if not isinstance(state,BridgeRiskState):
        raise ValueError('invalid streaming state')
    a,btime,s=state.last_margin,state.last_time,state.log_survival
    if (not all(isinstance(v,np.ndarray) and v.dtype==np.float64 and v.shape==(b,) for v in (a,btime,s))
            or not np.isfinite(a).all() or not np.isfinite(btime).all() or (btime<0).any()
            or not (np.isfinite(s) | np.isneginf(s)).all() or (s>0).any()
            or not np.all(times[:,0]>btime)):
        raise ValueError('invalid/noncausal streaming state')
    return BridgeRiskState(a.copy(),btime.copy(),s.copy()),0


def conditional_path_risk(margins:np.ndarray,times:np.ndarray,*,sigma:float,state:BridgeRiskState|None=None):
    """Causal P(any crossing by current observation | all sampled margins).

    For affine deterministic barrier segments, conditioned Brownian bridges
    over non-overlapping intervals are independent. Thus log survival is
    additive. Returns risk for every supplied observation and stream state;
    excludes the duplicated prior observation in a continued chunk.
    The caller must supply signed margins *relative to the barrier*. This
    module never uses future samples to decide a past risk.
    """
    state,start=_checked(margins,times,sigma,state)
    last,tprev,logsurv=(state.last_margin.copy(),state.last_time.copy(),state.log_survival.copy())
    output=np.empty_like(margins)
    if start==1:
        output[:,0]=np.where(last<=0,1.,0.)
    for j in range(start,margins.shape[1]):
        nxt=margins[:,j]
        duration=times[:,j]-tprev
        # No hidden crossing ambiguity where a sampled endpoint is on/below 0.
        p=np.ones(len(last),dtype=np.float64)
        positive=(last>0)&(nxt>0)
        p[positive]=np.exp(-2*last[positive]*nxt[positive]/(sigma*sigma*duration[positive]))
        with np.errstate(divide='ignore',invalid='raise'):
            logsurv=logsurv+np.log1p(-p)
        output[:,j]=-np.expm1(logsurv)
        last=nxt.copy()
        tprev=times[:,j].copy()
    return output,BridgeRiskState(last,tprev,logsurv)


def missed_endpoint_example():
    """Fixed constant-boundary, zero-drift observation-gap counterexample."""
    from scipy.special import ndtr
    x0,drift,sigma,T=.4,0.,.4,1.
    endpoint_only=float(ndtr((-x0-drift*T)/(sigma*math.sqrt(T))))
    continuous=first_hit_cdf(x0,drift,sigma,T)
    return {'x0':x0,'drift':drift,'diffusion_per_sqrt_second':sigma,
            'horizon_seconds':T,'endpoint_only_hit_probability':endpoint_only,
            'continuous_first_hit_probability':continuous,
            'probability_mass_missed_by_endpoint_only':continuous-endpoint_only,
            'conditional_bridge_correction_needed':True,
            'scientific_gate':'OPEN','production_activation':False}
