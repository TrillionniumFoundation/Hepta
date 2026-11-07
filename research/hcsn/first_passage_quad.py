"""Independent density-quadrature F/G reference for original He--Xiong Eq.(8).

The first-passage time density for x+mu*t+sigma*W_t hitting zero is
    x / (sigma sqrt(2*pi*t**3)) * exp(-(x+mu*t)**2 / (2*sigma**2*t)) .
Use y=x/(sigma sqrt(t)) so the density times |dt/dy| is
    sqrt(2/pi) * exp(-0.5*(y+(mu*x/sigma**2)/y)**2).
Integrate y from x/(sigma sqrt(tau)) to infinity; insert exp(-lambda*t)
for G. Neither numerical integrand uses the original CDF representation.

**Important:** an unsplit scipy.quad(lo,inf) can silently miss the O(x)
boundary layer near y=0 when x<1e-6, causing ~1e-6 errors. We split
geometrically [lo,4lo],[4lo,16lo],...,[.,1],[1,inf] to resolve it.
Finite SciPy adaptive quadrature is an independent finite-domain numeric
reference, not a mathematically rigorous global error certificate.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from scipy.integrate import quad
try:
    from .hx_original import HXParams
except ImportError:
    from hx_original import HXParams


@dataclass(frozen=True)
class FirstPassageIntegral:
    F: float
    G: float
    segments: int
    estimated_error_F: float
    estimated_error_G: float
    method: str = 'geometrically-partitioned-hitting-time-density'


def hitting_density_quadrature(x:float,tau:float,p:HXParams) -> FirstPassageIntegral:
    if (not isinstance(p,HXParams) or not math.isfinite(x) or x<0 or x>12
        or not math.isfinite(tau) or not 0<=tau<=p.maturity):
        raise ValueError('Outside finite original-HX density quadrature domain')
    if x==0:
        return FirstPassageIntegral(1.,1.,0,0.,0.)
    if tau==0:
        return FirstPassageIntegral(0.,0.,0,0.,0.)
    if x<1e-12 or tau<1e-12:
        raise ValueError('Unresolved extreme margin/maturity; requires separate precision check')
    mu=p.r-p.delta-.5*p.sigma*p.sigma
    a=mu*x/(p.sigma*p.sigma)
    ylo=x/(p.sigma*math.sqrt(tau))
    scale=math.sqrt(2/math.pi)
    def kernel(y:float,discounted:bool)->float:
        z=y+a/y
        exponent=-.5*z*z
        if discounted:
            exponent-=p.lam*(x/(p.sigma*y))**2
        return scale*math.exp(exponent) if exponent>-745 else 0.

    nodes=[ylo]
    while nodes[-1]<1:
        nodes.append(min(1.,nodes[-1]*4))
    intervals=list(zip(nodes,nodes[1:]))+[(nodes[-1],math.inf)]
    def integrate(discounted:bool):
        total=error=0.
        for lower,upper in intervals:
            value,estimated=quad(lambda y:kernel(y,discounted),lower,upper,
                                 epsabs=5e-14,epsrel=2e-12,limit=100)
            total+=value
            error+=estimated
        return total,error
    f,fe=integrate(False)
    g,ge=integrate(True)
    if not (-1e-12<=g<=f+1e-12 and f<=1+1e-12):
        raise ArithmeticError('Inconsistent hitting-time density quadrature')
    return FirstPassageIntegral(max(0.,min(1.,f)),max(0.,min(1.,g)),
                                len(intervals),fe,ge)
