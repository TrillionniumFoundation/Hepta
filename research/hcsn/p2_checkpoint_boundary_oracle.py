"""Research-only causal two-stage free-boundary first-hit oracle.

A drifted Brownian log state X(t)=x0+mu*t+sigma*W(t) is absorbed at
b1 before t1. At t1, for trajectories that have survived, a *causal* policy
chooses a second barrier b2(X(t1)) = b2_level+gain*(X(t1)-x0). The state
then runs until t1+t2 with that now-frozen second barrier.

Computes P[any hit by t1+t2], including an instantaneous hit from the
barrier jump. Integrates the exact reflection-principle killed density for
the first interval against the exact second-interval first-hit probability.
The one-dimensional quadrature is NOT a closed-form formula nor a certified
all-domain interval enclosure. It is an independent scientific reference for
state-dependent moving-boundary experiments, NOT original He--Xiong equity
and not a solved multi-reset QVI.

This module is deliberately free of HCSN production activation pathways.
"""
from __future__ import annotations

import math
import warnings
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from scipy.integrate import IntegrationWarning, quad
from scipy.special import log_ndtr
from scipy.stats import norm
import torch


@dataclass(frozen=True)
class TwoStageBrownian:
    x0: float = 1.15
    b1: float = 0.0
    b2_level: float = 0.40
    gain: float = 0.32
    drift: float = 0.08
    diffusion: float = 0.65
    t1: float = 0.75
    t2: float = 0.9

    def validate(self):
        vals = vars(self)
        if any(not math.isfinite(x) for x in vals.values()):
            raise ValueError("all parameters must be finite")
        if not (0 < self.x0 - self.b1 <= 20):
            raise ValueError("initial state must exceed first barrier (bounded domain)")
        if not (-20 <= self.b2_level <= 20):
            raise ValueError("second barrier outside evaluated domain")
        if not (-0.75 <= self.gain <= 0.75):
            raise ValueError("causal affine feedback gain outside monotone domain")
        if not (-4 <= self.drift <= 4):
            raise ValueError("drift outside evaluated domain")
        if not (0.05 <= self.diffusion <= 4):
            raise ValueError("diffusion outside evaluated domain")
        if not (0.02 <= self.t1 <= 64 and 0.02 <= self.t2 <= 64):
            raise ValueError("time interval outside evaluated domain")
        return self

    def b2_at(self, y):
        return self.b2_level + self.gain * (y - self.x0)

    @property
    def switch_survival_lower_bound(self):
        # Continuing immediately after the jump requires y>b2_at(y).
        return max(self.b1, (self.b2_level - self.gain * self.x0)/(1 - self.gain))


def first_hit_prob(distance: float, drift: float, diffusion: float, horizon: float) -> float:
    """Exact constant-barrier Brownian first-hit CDF, stable in the tails."""
    if distance <= 0:
        return 1.0
    z1 = (-distance - drift * horizon)/(diffusion*math.sqrt(horizon))
    z2 = (-distance + drift * horizon)/(diffusion*math.sqrt(horizon))
    log_p = np.logaddexp(log_ndtr(z1), -2*drift*distance/(diffusion**2) + log_ndtr(z2))
    return float(min(1.0, math.exp(float(log_p))))


def killed_density(y: float, p: TwoStageBrownian) -> float:
    """First-interval density of non-hit trajectories; stable near b1."""
    if y <= p.b1:
        return 0.0
    std = p.diffusion*math.sqrt(p.t1)
    free = norm.pdf((y-p.x0-p.drift*p.t1)/std)/std
    # Subtract reflected density via expm1 to avoid cancellation at y~b1.
    surviving_bridge = -math.expm1(-2*(p.x0-p.b1)*(y-p.b1)/(std**2))
    return free*surviving_bridge


def probability_quad(p: TwoStageBrownian, epsabs: float = 1e-11):
    """Return (hit_probability, numerical_quad_absolute_error_estimate)."""
    p.validate()
    lower = p.switch_survival_lower_bound
    def integrand(y):
        b2 = p.b2_at(y)
        if y <= b2:
            return 0.0
        return killed_density(y,p) * (1-first_hit_prob(y-b2,p.drift,p.diffusion,p.t2))
    with warnings.catch_warnings():
        warnings.simplefilter("error",IntegrationWarning)
        surviving, abserr = quad(integrand,lower,np.inf,epsabs=epsabs,epsrel=1e-11,limit=300)
    if not (math.isfinite(surviving) and math.isfinite(abserr)) or not (-1e-10 <= surviving <= 1+1e-10):
        raise ArithmeticError("untrusted quadrature result; fail closed")
    return float(max(0.0,min(1.0,1-surviving))),float(abserr)


@lru_cache(maxsize=8)
def _leggauss(n):
    if n < 16 or n > 1024:
        raise ValueError("quadrature order not qualified")
    return np.polynomial.legendre.leggauss(n)


def probability_torch(p: TwoStageBrownian, *, n: int = 256, **trainable):
    """FP64 differentiable fixed-node integral, with explicit tail diagnostic.

    Pass parameters as torch scalar tensors through keyword overrides, e.g.
    probability_torch(p, b2_level=torch.tensor(.4, requires_grad=True)).
    Returns (P_hit, upper-tail-free-density upper bound). The tail diagnostic
    only bounds omitted first-stage unconstrained Gaussian mass; it does NOT
    bound Gauss-Legendre quadrature error by itself.
    """
    p.validate()
    keys=set(vars(p)); unknown=set(trainable)-keys
    if unknown:
        raise ValueError(f"unknown trainable parameters {sorted(unknown)}")
    vals={k:trainable.get(k,torch.tensor(v,dtype=torch.float64)) for k,v in vars(p).items()}
    if not all(isinstance(v,torch.Tensor) and v.ndim==0 and v.dtype==torch.float64 for v in vals.values()):
        raise TypeError("all trainable inputs must be scalar torch.float64 tensors")
    x,b1,b2,gain,mu,sigma,t1,t2=(vals[k] for k in ('x0','b1','b2_level','gain','drift','diffusion','t1','t2'))
    if any(not torch.isfinite(z).item() for z in vals.values()):
        raise ValueError("non-finite tensor input")
    if not (0 < (x-b1).item() <= 20 and -0.75 <= gain.item() <= .75
            and 0.05 <= sigma.item() <= 4 and 0.02 <= t1.item() <=64
            and 0.02 <= t2.item() <= 64 and -4 <= mu.item() <=4
            and -20 <= b2.item() <=20):
        raise ValueError("trainable input outside bounded qualification domain")
    lower=torch.maximum(b1,(b2-gain*x)/(1-gain))
    std=sigma*torch.sqrt(t1)
    mean=x+mu*t1
    # Upper tail beyond at least 11 std of free Gaussian.
    upper=torch.maximum(mean+11*std,lower+11*std)
    nodes_np,weights_np=_leggauss(n)
    nodes=torch.as_tensor(nodes_np,dtype=torch.float64)
    weights=torch.as_tensor(weights_np,dtype=torch.float64)
    y=lower+.5*(nodes+1)*(upper-lower)
    z=(y-mean)/std
    pdf=torch.exp(-.5*z*z)/(std*math.sqrt(2*math.pi))
    killed=pdf*(-torch.expm1(-2*(x-b1)*(y-b1)/std.square()))
    b2_y=b2+gain*(y-x)
    a=y-b2_y
    s2=sigma*torch.sqrt(t2)
    z1=(-a-mu*t2)/s2
    z2=(-a+mu*t2)/s2
    logp=torch.logaddexp(torch.special.log_ndtr(z1), -2*mu*a/sigma.square()+torch.special.log_ndtr(z2))
    hit2=torch.exp(logp).clamp(0,1)
    survival2=(1-hit2).clamp(0,1)
    survival=((upper-lower)*.5*(weights*killed*survival2).sum())
    hit=1-survival
    tail=torch.special.ndtr(-(upper-mean)/std)
    return hit,tail


def probability_bridge_mc(p: TwoStageBrownian, n: int = 150000, seed: int = 0):
    """Independent exact-at-checkpoints Brownian-bridge MC (NO quadrature).

    First and second intervals use free Gaussian endpoints and independent
    bridge-crossing Bernoulli variates; includes instantaneous boundary jump.
    Exact for piecewise-frozen thresholds, not for continuously varying paths.
    """
    p.validate()
    if not (100 <= n <= 2_000_000):
        raise ValueError("MC trajectory count outside evidence budget")
    rng=np.random.default_rng(seed)
    y=p.x0+p.drift*p.t1+p.diffusion*math.sqrt(p.t1)*rng.standard_normal(n)
    u1=rng.random(n)
    crossed1=y<=p.b1
    valid1=~crossed1
    cross_prob1=np.exp(-2*(p.x0-p.b1)*np.maximum(y-p.b1,0)/(p.diffusion**2*p.t1))
    crossed1 |= valid1 & (u1 < cross_prob1)
    b2=p.b2_at(y)
    crossed_switch=y<=b2
    z=y+p.drift*p.t2+p.diffusion*math.sqrt(p.t2)*rng.standard_normal(n)
    u2=rng.random(n)
    cross_prob2=np.exp(-2*np.maximum(y-b2,0)*np.maximum(z-b2,0)/(p.diffusion**2*p.t2))
    crossed2=(z<=b2) | (u2<cross_prob2)
    events=crossed1 | crossed_switch | crossed2
    phat=float(np.mean(events))
    se=math.sqrt(phat*(1-phat)/n)
    return phat,se,int(events.sum())
