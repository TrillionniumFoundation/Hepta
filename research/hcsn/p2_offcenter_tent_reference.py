"""Research-only independent bridge reference for an off-centre tent boundary.

Given positive observed margins X_0=a, X_T=b of constant-diffusion Brownian
motion (any constant drift), condition on both endpoints. The deterministic
boundary is zero at 0 and T, height h at t=c*T, affine on each side. The bridge
midpoint M at c*T is N((1-c)a+c*b, sigma^2*T*c*(1-c)). Given M>h, the two
bridge halves survive independently; their survival probabilities are
(1-exp(-lambda_left*(M-h))) and (1-exp(-lambda_right*(M-h))).

This is a retrospective *constant-diffusion predetermined-boundary* reference.
It does not locate a realized hidden event, authorize online control, prove
any input-learned boundary, recurrent reset, or P0-P6 scientific gate closure.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import numpy as np
from scipy.integrate import quad
import mpmath


@dataclass(frozen=True)
class OffcenterTent:
    a: float = 0.2
    b: float = 0.8
    horizon: float = 1.0
    sigma: float = 0.4
    height: float = 0.45
    apex_fraction: float = 0.1

    def validate(self) -> 'OffcenterTent':
        values = (self.a, self.b, self.horizon, self.sigma,
                  self.height, self.apex_fraction)
        if any(type(x) not in (float, int) or not math.isfinite(x) for x in values):
            raise ValueError('finite real scalars required; bool rejected')
        if not (0.01 <= self.a <= 3 and 0.01 <= self.b <= 3 and
                0.05 <= self.horizon <= 10 and 0.1 <= self.sigma <= 2 and
                0 <= self.height <= 2 and 0.05 <= self.apex_fraction <= 0.95):
            raise ValueError('outside qualified offcenter tent research domain')
        return self


def _params(p: OffcenterTent):
    p.validate()
    c = p.apex_fraction
    mean = (1-c)*p.a+c*p.b
    std = p.sigma*math.sqrt(p.horizon*c*(1-c))
    left = 2*p.a/(p.sigma**2*p.horizon*c)
    right = 2*p.b/(p.sigma**2*p.horizon*(1-c))
    return mean, std, left, right


def hit_quadrature(p: OffcenterTent) -> tuple[float, float]:
    """Independent one-dimensional Gaussian conditional-survival integral.

    Second output is an estimated integration error plus Gaussian tail bound,
    NOT a certified outward-rounded interval.
    """
    mean,std,left,right = _params(p)
    upper = max(p.height, mean+14*std)
    if (p.height-mean)/std >= 13:
        raise ArithmeticError('qualified quadrature range exceeded')
    def integrand(m):
        y = m-p.height
        normal = math.exp(-0.5*((m-mean)/std)**2)/(std*math.sqrt(2*math.pi))
        return normal*(-math.expm1(-left*y))*(-math.expm1(-right*y))
    survival, err = quad(integrand,p.height,upper,epsabs=2e-12,epsrel=2e-12,limit=300)
    tail = 0.5*math.erfc((upper-mean)/(std*math.sqrt(2)))
    if not (math.isfinite(survival) and -1e-12 <= survival <= 1+1e-12):
        raise ArithmeticError('numerical survival invalid')
    return 1-survival, err+tail


def hit_mp_closed_form(p: OffcenterTent, dps: int = 80) -> float:
    """Independent truncated-Gaussian exponential moment in cloned MP context.

    Formula: S=I(0)-I(lambda_L)-I(lambda_R)+I(lambda_L+lambda_R),
    I(lambda)=exp(-lambda*(mu-h)+lambda^2*v/2)
              * Phi((mu-h-lambda*v)/sqrt(v)).
    Every parameter is converted from the human-readable decimal value of
    its validated float, not from a prior FP64 quadrature intermediate.
    """
    p.validate()
    if type(dps) is not int or not 60 <= dps <= 200:
        raise ValueError('precision must be an integer between 60 and 200')
    mp = mpmath.mp.clone()
    mp.dps = dps
    a,b,t,s,h,c = (mp.mpf(str(v)) for v in
                     (p.a,p.b,p.horizon,p.sigma,p.height,p.apex_fraction))
    mu=(1-c)*a+c*b
    variance=s*s*t*c*(1-c)
    std=mp.sqrt(variance)
    left=2*a/(s*s*t*c)
    right=2*b/(s*s*t*(1-c))
    def trunc(lam):
        x=(h-mu+lam*variance)/(std*mp.sqrt(2))
        return mp.exp(-lam*(mu-h)+lam*lam*variance/2)*mp.erfc(x)/2
    hit=1-(trunc(0)-trunc(left)-trunc(right)+trunc(left+right))
    if not mp.isfinite(hit) or not (0 <= hit <= 1):
        raise ArithmeticError('MP evaluation outside probability range')
    return float(hit)


def hit_bridge_mc(p: OffcenterTent, n: int=100_000, seed: int=20261101):
    """Conditional midpoint MC: bridge halves sampled analytically in time."""
    mean,std,left,right=_params(p)
    if type(n) is not int or not 1_000 <= n <= 1_000_000 or type(seed) is not int:
        raise ValueError('invalid MC trials or RNG seed')
    rng=np.random.default_rng(seed)
    middle=mean+std*rng.standard_normal(n)
    gap=np.maximum(middle-p.height, 0.)
    p_left=np.exp(-left*gap)
    p_right=np.exp(-right*gap)
    hits=(middle<=p.height)|(rng.random(n)<p_left)|(rng.random(n)<p_right)
    count=int(np.count_nonzero(hits))
    observed=count/n
    se=math.sqrt(observed*(1-observed)/n)
    return observed,se,count
