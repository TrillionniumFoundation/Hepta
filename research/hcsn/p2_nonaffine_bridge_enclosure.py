"""P2 research-only: counterexample to reusing affine bridge hit probability
for an intra-gap tent-shaped continuous boundary. No production activation.

Condition on two positive observed margins a,b of X_0 and X_T relative to
zero and let X be Brownian motion with fixed volatility sigma and constant
drift. Conditional on both endpoints the bridge law is drift-independent.
The deterministic barrier starts/ends at zero and peaks at height h at T/2.
This is a *specified future barrier trajectory*, not a causal learner or an
online spike predictor. Brownian bridges split independently at the midpoint.
"""
from dataclasses import dataclass
import math
import numpy as np
from scipy.integrate import quad
from scipy.special import ndtr

@dataclass(frozen=True)
class TentBridge:
    a: float = 0.4
    b: float = 0.4
    horizon: float = 1.0
    sigma: float = 0.4
    height: float = 0.6

    def validate(self):
        vals=(self.a,self.b,self.horizon,self.sigma,self.height)
        if any(type(x) not in (int,float) or not math.isfinite(x) for x in vals):
            raise ValueError('finite real scalars, not booleans, required')
        if not (0 < self.a <= 10 and 0 < self.b <= 10 and
                .01 <= self.horizon <= 64 and .05 <= self.sigma <= 4 and
                0 <= self.height <= 10):
            raise ValueError('outside bounded positive-endpoint tent research domain')
        return self


def flat_affine_hit(p: TentBridge) -> float:
    p.validate()
    return math.exp(-2*p.a*p.b/(p.sigma*p.sigma*p.horizon))


def midpoint_hit_lower_bound(p: TentBridge) -> float:
    p.validate()
    mean=(p.a+p.b)/2
    std=p.sigma*math.sqrt(p.horizon)/2
    return float(ndtr((p.height-mean)/std))


def tent_hit_quadrature(p: TentBridge) -> tuple[float,float]:
    """Two bridge halves integrated over a Gaussian midpoint. Return hit and
    quadrature error estimate plus an explicit omitted upper-normal tail bound.
    The error estimate is *not* a rigorous interval certification.
    """
    p.validate()
    mean=(p.a+p.b)/2
    std=p.sigma*math.sqrt(p.horizon)/2
    upper=max(p.height,mean+13*std)
    zmin=(p.height-mean)/std
    if zmin>=13:
        # All surviving paths require midpoint > height.  This upper tail
        # can be bounded by Phi(-zmin), but we do not certify the small survival.
        raise ArithmeticError('surviving bridge outside qualified quadrature window')
    k=4/(p.sigma*p.sigma*p.horizon)
    def integrand(mid):
        d=mid-p.height
        normal=math.exp(-.5*((mid-mean)/std)**2)/(std*math.sqrt(2*math.pi))
        return normal*(-math.expm1(-k*p.a*d))*(-math.expm1(-k*p.b*d))
    survival,err=quad(integrand,p.height,upper,epsabs=2e-12,epsrel=2e-12,limit=400)
    if not (math.isfinite(survival) and math.isfinite(err) and -1e-12<=survival<=1+1e-12):
        raise ArithmeticError('untrusted numeric integral')
    tail=0.5*math.erfc((upper-mean)/(std*math.sqrt(2)))
    return 1-survival, err+tail


def tent_hit_bridge_mc(p: TentBridge, n: int=100_000, seed: int=20261101) -> tuple[float,float,int]:
    """Independent conditional bridge MC, exact in time on both affine halves.
    Does not discretize intra-segment Brownian paths or simulate actual spike times.
    """
    p.validate()
    if type(n) is not int or not 1000<=n<=2_000_000 or type(seed) is not int:
        raise ValueError('invalid number of trials or RNG seed')
    rng=np.random.default_rng(seed)
    std=p.sigma*math.sqrt(p.horizon)/2
    midpoint=(p.a+p.b)/2+std*rng.standard_normal(n)
    clearance=np.maximum(midpoint-p.height,0.)
    k=4/(p.sigma*p.sigma*p.horizon)
    p_left=np.exp(-k*p.a*clearance)
    p_right=np.exp(-k*p.b*clearance)
    hits=(midpoint<=p.height)|(rng.random(n)<p_left)|(rng.random(n)<p_right)
    count=int(hits.sum())
    observed=count/n
    return observed,math.sqrt(observed*(1-observed)/n),count
