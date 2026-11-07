"""Literal He--Xiong (2012) Appendix-A7 equity expression, finite domain.

Independent implementation of A5 and A7. Compare against Eq.11 Green
solution from hx_original.py; evaluation is numerical FP64 and NOT a
certified uniformly stable activation kernel near the boundary.
"""
from __future__ import annotations
import math
from scipy.special import ndtr
try:from .hx_original import HXParams,closed_boundary,_expo_ndtr
except ImportError:from hx_original import HXParams,closed_boundary,_expo_ndtr


def _K(v:float,p:HXParams,w:float,h:float) -> float:
    """K(v;a,w,h) from original printed paper Eq.(A5)."""
    t=p.sigma*math.sqrt(p.maturity)
    shift=h-p.a
    logm=.5*(shift*shift-w*w)*t*t
    # The first 2 terms are deliberately paired to reduce cancellation.
    first=(ndtr(w*t)-_expo_ndtr(logm,shift*t))*math.exp(-h*v)
    second=_expo_ndtr(logm-h*v,(-v+shift*t*t)/t)
    third=_expo_ndtr(-(p.a+w)*v,(-v+w*t*t)/t)
    return first+second-third


def _k(v:float,p:HXParams,w:float) -> float:
    t=p.sigma*math.sqrt(p.maturity)
    shift=-p.eta-p.a
    logm=.5*(shift*shift-w*w)*t*t
    return (_expo_ndtr(logm+p.eta*v,(-v+shift*t*t)/t)
           -_expo_ndtr(-(p.a+w)*v,(-v+w*t*t)/t))


def _A(v:float,p:HXParams,y:float) -> float:
    z=p.z
    if abs(z-y)<1e-7:
        raise ValueError('A7 direct form singular; use Green reference')
    return ((_K(v,p,y,p.gamma)+_k(v,p,-y))/(z-y)
           +(_K(v,p,-y,p.gamma)+_k(v,p,y))/(z+y))


def equity_a7(v:float,p:HXParams,boundary:float|None=None):
    """A7 on V>=VB, zero payoff in stopping region."""
    b=closed_boundary(p) if boundary is None else boundary
    if not math.isfinite(v) or v<=0 or not math.isfinite(b) or b<=0:
        raise ValueError('Invalid equity state')
    if v<=b:return 0.
    x=math.log(v/b)
    z=p.z; gamma=p.gamma;eta=p.eta;s2=p.sigma*p.sigma
    c0=p.c/p.lam
    u=p.p-c0
    h=(1-p.tax)*p.coupon_total+(-math.expm1(-p.lam*p.maturity))*u
    return (v -p.delta*b*math.exp(-gamma*x)/(z*s2*(gamma+1))
            - h/(z*s2)*(1/eta+(-math.expm1(-gamma*x))/gamma)
            +(math.exp(-p.lam*p.maturity)*u*_A(x,p,p.a)
              -(p.alpha*b/p.maturity-c0)*_A(x,p,p.zhat))/(z*s2))
