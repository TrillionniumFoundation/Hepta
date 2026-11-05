"""P2 research-only: exact counterexample for state-coupled Brownian boundaries.

X(t) is a constant-diffusion Brownian bridge conditional on safe X(0)=a,
X(T)=b. The boundary B(t)=gain*X(t) is adapted to the SAME noise; gain < 1.
Thus the crossing event {X(t) <= B(t)} is exactly {X(t) <= 0}.

The observed margin M(t)=X(t)-B(t)=(1-gain)X(t) has diffusion
(1-gain)*sigma, NOT sigma. Reusing the deterministic/affine barrier bridge
formula with the underlying state's sigma and observed margin endpoints
misestimates first passage. A per-gap gain chosen causally from past input
is covered conditional on that gain; within-gap learned or nonlinear feedback
is NOT covered. All computations are retrospective, never online event times.

No original HX equity, QVI, multiple reset, trained model, or release closure
is established by this limited solvable counterexample. P0-P6 remain OPEN.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

import mpmath
import numpy as np
from scipy.integrate import quad


@dataclass(frozen=True)
class FeedbackBridge:
    a: float = 0.4
    b: float = 0.4
    horizon: float = 1.0
    sigma: float = 0.4
    gain: float = 0.75

    def validate(self) -> 'FeedbackBridge':
        v = (self.a, self.b, self.horizon, self.sigma, self.gain)
        if any(type(x) not in (float, int) or not math.isfinite(x) for x in v):
            raise ValueError('finite real scalar inputs required; bool rejected')
        if not (0.01 <= self.a <= 3.0 and 0.01 <= self.b <= 3.0
                and 0.05 <= self.horizon <= 10.0
                and 0.1 <= self.sigma <= 2.0
                and -0.75 <= self.gain <= 0.90):
            raise ValueError('outside bounded research domain; gain must be < 1')
        exponent = 2 * self.a * self.b / (self.sigma**2 * self.horizon)
        if exponent > 20.0:
            raise ValueError('rare-hit event outside qualified FP64 validation domain')
        return self


def exact_feedback_hit(p: FeedbackBridge) -> float:
    """Exact continuous first-crossing mass, conditional on safe endpoints."""
    p.validate()
    # (1-gain) > 0, hence X-B <= 0 exactly iff X <= 0.
    return math.exp(-2*p.a*p.b / (p.sigma**2*p.horizon))


def invalid_frozen_sigma_hit(p: FeedbackBridge) -> float:
    """Intentionally WRONG extrapolation: margin endpoints, X's raw sigma.

    Negative-control computation only; MUST NOT be used as an estimator.
    """
    p.validate()
    m0=(1-p.gain)*p.a
    m1=(1-p.gain)*p.b
    return math.exp(-2*m0*m1/(p.sigma**2*p.horizon))


def transformed_margin_hit(p: FeedbackBridge) -> float:
    """Correct transformed margin diffusion (1-gain)*sigma."""
    p.validate()
    factor=1-p.gain
    return math.exp(-2*(factor*p.a)*(factor*p.b)/
                    ((factor*p.sigma)**2*p.horizon))


def mp_reference(p: FeedbackBridge, dps: int=80) -> str:
    """Independent arbitrary-precision evaluation from decimal literals."""
    p.validate()
    if type(dps) is not int or not 60 <= dps <= 160:
        raise ValueError('unsupported precision')
    mp=mpmath.mp.clone();mp.dps=dps
    a,b,T,s,g = (mp.mpf(str(v)) for v in
                (p.a,p.b,p.horizon,p.sigma,p.gain))
    m0=(1-g)*a; m1=(1-g)*b; sm=(1-g)*s
    result=mp.exp(-2*m0*m1/(sm**2*T))
    return mp.nstr(result, 50)


def midpoint_quadrature(p: FeedbackBridge) -> tuple[float, float]:
    """Independent Gaussian midpoint/conditional half-bridge integration.

    Numerical quadrature estimate + omitted Gaussian upper-tail bound, *not*
    rigorously outward-rounded error certification for all parameter values.
    Integrate in X-space, without the feedback-margin reflection expression.
    """
    p.validate()
    mu=(p.a+p.b)/2
    std=p.sigma*math.sqrt(p.horizon)/2
    upper=mu+14*std
    k=4/(p.sigma**2*p.horizon)

    def f(x):
        if x <= 0:
            return 0.0
        density=math.exp(-0.5*((x-mu)/std)**2)/(std*math.sqrt(2*math.pi))
        left=-math.expm1(-k*p.a*x)
        right=-math.expm1(-k*p.b*x)
        return density*left*right
    survival,error=quad(f,0.0,upper,epsabs=3e-13,epsrel=3e-13,limit=400)
    tail=0.5*math.erfc((upper-mu)/(std*math.sqrt(2)))
    if not (math.isfinite(survival) and math.isfinite(error)
            and -1e-10 <= survival <= 1+1e-10):
        raise ArithmeticError('untrusted midpoint quadrature')
    return 1-survival, error+tail


def midpoint_bridge_mc(p: FeedbackBridge, n: int=200_000,
                       seed: int=20261101) -> tuple[float,float,int]:
    """Independent midpoint sampling with exact continuous half-gap hits.

    This simulates hit INDICATORS, not realized crossing times, and is not a
    trained neural experiment. Independent of the gain because B=gain*X.
    """
    p.validate()
    if type(n) is not int or not 1_000 <= n <= 1_000_000 or type(seed) is not int:
        raise ValueError('invalid Monte Carlo n/seed')
    rng=np.random.default_rng(seed)
    mu=(p.a+p.b)/2
    std=p.sigma*math.sqrt(p.horizon)/2
    middle=mu+std*rng.standard_normal(n)
    clearance=np.maximum(middle,0)
    scale=4/(p.sigma**2*p.horizon)
    left=np.exp(-scale*p.a*clearance)
    right=np.exp(-scale*p.b*clearance)
    hits=(middle<=0)|(rng.random(n)<left)|(rng.random(n)<right)
    count=int(np.count_nonzero(hits))
    rate=count/n
    return rate,math.sqrt(rate*(1-rate)/n),count
