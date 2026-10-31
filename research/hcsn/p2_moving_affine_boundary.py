"""P2 research-only, two-stage causal *linearly moving* Brownian barriers.

X_t=x0+mu*t+sigma*W_t. A lower barrier b1+s1*t is active in
[0,t1]. On survival, the observed checkpoint state y=X(t1) fixes
b2(y)=b2+gain*(y-x0). The second lower barrier moves as
b2(y)+s2*u for u in [0,t2]. A jump at t1 can immediately hit.

The exact identity for cumulative first-hit risk is a 1D integral of a
killed Gaussian transition density against a constant-slope first-hit CDF.
Numerical quadrature is NOT a universally certified enclosure, nor a
closed-form neural QVI or original He-Xiong firm equilibrium.
No production interfaces, no activation authority.
"""
from __future__ import annotations

import dataclasses
import math
import warnings
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from scipy.integrate import IntegrationWarning, quad
from scipy.special import log_ndtr
import torch


@dataclass(frozen=True)
class MovingTwoStage:
    x0: float = 1.15
    b1: float = 0.0
    slope1: float = 0.12
    b2: float = 0.40
    gain: float = 0.32
    slope2: float = -0.08
    drift: float = 0.08
    diffusion: float = 0.65
    t1: float = 0.75
    t2: float = 0.9

    def validate(self) -> 'MovingTwoStage':
        if any(not math.isfinite(x) for x in dataclasses.astuple(self)):
            raise ValueError('all physical inputs must be finite')
        if not 0 < self.x0-self.b1 <= 20:
            raise ValueError('initial state must strictly exceed first barrier')
        if not -20 <= self.b1 <= 20 or not -20 <= self.b2 <= 20:
            raise ValueError('barrier level outside bounded research domain')
        if not -0.75 <= self.gain <= 0.75:
            raise ValueError('gain must remain bounded below one')
        if abs(self.slope1)>1.5 or abs(self.slope2)>1.5:
            raise ValueError('time slope outside bounded research domain')
        if not -4 <= self.drift <= 4:
            raise ValueError('drift outside bounded research domain')
        if not .05 <= self.diffusion <= 4:
            raise ValueError('diffusion outside bounded research domain')
        if not .02 <= self.t1 <= 64 and .02 <= self.t2 <= 64:
            raise ValueError('time intervals outside bounded research domain')
        return self

    def b2_at(self, checkpoint_state: float, elapsed_after_checkpoint: float = 0.0) -> float:
        """Causal: future noise and endpoint are not arguments."""
        return self.b2 + self.gain*(checkpoint_state-self.x0)+self.slope2*elapsed_after_checkpoint

    @property
    def stage1_end_barrier(self) -> float:
        return self.b1+self.slope1*self.t1

    @property
    def surviving_lower_limit(self) -> float:
        # Survive both the first stage and any immediate upward jump.
        return max(self.stage1_end_barrier, (self.b2-self.gain*self.x0)/(1-self.gain))


def fixed_barrier_hit(distance: float, drift: float, diffusion: float, time: float) -> float:
    """Reflection-principle CDF; drift is relative to the barrier slope."""
    if distance <= 0:
        return 1.0
    s=diffusion*math.sqrt(time)
    z1=(-distance-drift*time)/s
    z2=(-distance+drift*time)/s
    logp=np.logaddexp(log_ndtr(z1),-2*drift*distance/diffusion**2+log_ndtr(z2))
    return float(max(0.,min(1.,math.exp(float(logp)))))


def first_killed_density(checkpoint_state: float, p: MovingTwoStage) -> float:
    """Exact density of X(t1) with no hit of b1+s1*t; valid above b1(t1).

    Subtracting the deterministic barrier slope reduces to constant-barrier
    Brownian motion with effective drift (drift-slope1). Conditional Gaussian
    bridge survival is 1-exp(-2*d_start*d_end/(sigma²*t1)).
    """
    if checkpoint_state <= p.stage1_end_barrier:
        return 0.0
    std=p.diffusion*math.sqrt(p.t1)
    z=(checkpoint_state-p.x0-p.drift*p.t1)/std
    free=math.exp(-.5*z*z)/(std*math.sqrt(2*math.pi))
    d0=p.x0-p.b1
    dend=checkpoint_state-p.stage1_end_barrier
    bridge=-math.expm1(-2*d0*dend/(std*std))
    return free*bridge


def probability_quad(p: MovingTwoStage, *, epsabs: float = 1e-11) -> tuple[float,float]:
    """Integrate exact two-stage probability identity (NOT a certified bound)."""
    p.validate()
    if not math.isfinite(epsabs) or not 0 < epsabs <= 1e-4:
        raise ValueError('invalid numerical quadrature tolerance')
    lower=p.surviving_lower_limit
    def survival_integrand(y: float) -> float:
        d2=y-p.b2_at(y)
        # y is safely above both barriers except at the measure-zero boundary.
        return first_killed_density(y,p)*(1-fixed_barrier_hit(d2,p.drift-p.slope2,p.diffusion,p.t2))
    with warnings.catch_warnings():
        warnings.simplefilter('error',IntegrationWarning)
        survived,error=quad(survival_integrand,lower,math.inf,epsabs=epsabs,epsrel=1e-11,limit=350)
    if not math.isfinite(survived) or not math.isfinite(error) or not -1e-9 <= survived <= 1+1e-9:
        raise ArithmeticError('quadrature produced invalid survival probability')
    return float(min(1.,max(0.,1-survived))),float(error)


@lru_cache(maxsize=12)
def _gauss_legendre(order: int):
    if not isinstance(order,int) or not 32 <= order <= 1024:
        raise ValueError('unqualified Gauss-Legendre quadrature order')
    return np.polynomial.legendre.leggauss(order)


def probability_torch(p: MovingTwoStage, *, order: int=256, **overrides) -> tuple[torch.Tensor,torch.Tensor]:
    """Differentiable FP64 fixed-node integral and omitted free-Gaussian tail mass.

    Every override must be a scalar FP64 tensor. The returned tail does NOT
    certify quadrature bias. A separate independent reference is required.
    """
    p.validate()
    fields=set(vars(p))
    if set(overrides)-fields:
        raise ValueError('unknown parameter overrides')
    if any(not isinstance(v,torch.Tensor) or v.dtype!=torch.float64 or v.ndim!=0
           or v.device.type!='cpu' for v in overrides.values()):
        raise TypeError('all overrides must be scalar CPU torch.float64 tensors')
    if any(not bool(torch.isfinite(v)) for v in overrides.values()):
        raise ValueError('override contains nonfinite tensor')
    # Check actual (possibly trainable) scalar parameters, not only defaults.
    checked=dataclasses.replace(p,**{k:float(v.detach()) for k,v in overrides.items()})
    checked.validate()
    params={k:overrides.get(k,torch.tensor(v,dtype=torch.float64)) for k,v in vars(p).items()}
    x,b1,s1,b2,gain,s2,mu,sigma,t1,t2=(params[k] for k in (
        'x0','b1','slope1','b2','gain','slope2','drift','diffusion','t1','t2'))
    d0=x-b1
    endpoint_b1=b1+s1*t1
    lower=torch.maximum(endpoint_b1,(b2-gain*x)/(1-gain))
    std=sigma*torch.sqrt(t1)
    mean=x+mu*t1
    # The free density upper tail bounds omitted killed-density mass.
    upper=torch.maximum(mean+11*std,lower+11*std)
    ns,ws=_gauss_legendre(order)
    nodes=torch.as_tensor(ns,dtype=torch.float64)
    weights=torch.as_tensor(ws,dtype=torch.float64)
    y=lower+.5*(nodes+1)*(upper-lower)
    z=(y-mean)/std
    pdf=torch.exp(-.5*z*z)/(std*math.sqrt(2*math.pi))
    first_survival=-torch.expm1(-2*d0*(y-endpoint_b1)/std.square())
    density=pdf*first_survival
    d2=y-(b2+gain*(y-x))
    effective=mu-s2
    std2=sigma*torch.sqrt(t2)
    a=(-d2-effective*t2)/std2
    b=(-d2+effective*t2)/std2
    log_hit2=torch.logaddexp(torch.special.log_ndtr(a),
                             -2*effective*d2/sigma.square()+torch.special.log_ndtr(b))
    survival2=(-torch.expm1(log_hit2)).clamp(min=0,max=1)
    survived=.5*(upper-lower)*torch.sum(weights*density*survival2)
    tail=torch.special.ndtr(-(upper-mean)/std)
    return 1-survived,tail


def bridge_mc(p: MovingTwoStage, *, n: int=120_000, seed: int=20261031) -> tuple[float,float,int]:
    """Independent exact-in-time Brownian bridge crossing at two linear barriers.

    This samples endpoint Gaussians and Brownian bridge crossing Bernoullis.
    No numerical time step, no use of quadrature or analytic first-hit CDF.
    """
    p.validate()
    if not isinstance(n,int) or not 100 <= n <= 2_000_000:
        raise ValueError('MC size outside research bounds')
    rng=np.random.default_rng(seed)
    y=p.x0+p.drift*p.t1+p.diffusion*math.sqrt(p.t1)*rng.standard_normal(n)
    end1=p.stage1_end_barrier
    d0=p.x0-p.b1
    de1=y-end1
    u1=rng.random(n)
    hit1=(de1<=0)|(u1<np.exp(-2*d0*np.maximum(de1,0)/(p.diffusion**2*p.t1)))
    at_switch=p.b2+p.gain*(y-p.x0)
    d2=y-at_switch
    hit_jump=d2<=0
    z=y+p.drift*p.t2+p.diffusion*math.sqrt(p.t2)*rng.standard_normal(n)
    de2=z-(at_switch+p.slope2*p.t2)
    u2=rng.random(n)
    hit2=(de2<=0)|(u2<np.exp(-2*np.maximum(d2,0)*np.maximum(de2,0)/(p.diffusion**2*p.t2)))
    count=int(np.count_nonzero(hit1|hit_jump|hit2))
    estimate=count/n
    se=math.sqrt(estimate*(1-estimate)/n)
    return float(estimate),float(se),count
