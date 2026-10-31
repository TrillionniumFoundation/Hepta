"""Boundary-local compensated series for ORIGINAL HX equity Eq. (11).

PDE-matched Taylor in log margin x=ln(V/V_B): E(0)=E'(0)=0,
E''(0),E'''(0),E''''(0) from original Eq.11 *and* exact bond
boundary derivatives from Eq.8. The caller passes x directly, avoiding
input rounding in V_B*exp(x). This is a LOCAL analytic expansion only,
not an all-domain FP32 certification. Direct Eq. A7 remains the reference.
"""
from __future__ import annotations
import math
from scipy.special import ndtr
try:from .hx_original import HXParams,closed_boundary
except ImportError:from hx_original import HXParams,closed_boundary


def _normal_pdf(z):
    return math.exp(-.5*z*z)/math.sqrt(2*math.pi)


def _gaussian_exp_derivatives(c,b,t):
    """Derivative at x=0 of exp(c*x)Phi(-x/t+b*t)."""
    phi=_normal_pdf(b*t);cdf=ndtr(b*t)
    first=c*cdf-phi/t
    second=c*c*cdf-(2*c+b)*phi/t
    return first,second


def boundary_coefficients(p:HXParams,boundary:float|None=None):
    """Return log-margin Taylor coefficients (E2,E3,E4) at true boundary."""
    vb=closed_boundary(p) if boundary is None else boundary
    if not math.isfinite(vb) or vb<=0:raise ValueError('Boundary not finite positive')
    t=p.sigma*math.sqrt(p.maturity)
    a,zh=p.a,p.zhat
    f1,f2=[0.,0.],[0.,0.]
    f1=list(_gaussian_exp_derivatives(0.,-a,t))
    f2=list(_gaussian_exp_derivatives(-2*a,a,t))
    g1=list(_gaussian_exp_derivatives(-a+zh,-zh,t))
    g2=list(_gaussian_exp_derivatives(-a-zh,zh,t))
    FF1=f1[0]+f2[0];FF2=f1[1]+f2[1]
    GG1=g1[0]+g2[0];GG2=g1[1]+g2[1]
    c0=p.c/p.lam
    u=p.p-c0
    lu=math.exp(-p.lam*p.maturity)*u
    rec=p.alpha*vb/p.maturity-c0
    d1=-lu*FF1+rec*GG1
    d2=-lu*FF2+rec*GG2
    f0=p.delta*vb-(1-p.tax)*p.coupon_total+p.alpha*vb/p.maturity-p.p
    r1=p.delta*vb+d1
    r2=p.delta*vb+d2
    D=.5*p.sigma*p.sigma;nu=p.r-p.delta-D
    e2=-f0/D
    e3=(-r1-nu*e2)/D
    e4=(p.r*e2-nu*e3-r2)/D
    return e2,e3,e4


def equity_near_boundary(log_margin:float,p:HXParams,boundary:float|None=None):
    """Fourth-order local expansion, valid 0 <= log margin <= 1e-3 only."""
    if not math.isfinite(log_margin) or not 0 <= log_margin <= 1e-3:
        raise ValueError('Outside HX local expansion domain [0, 1e-3]')
    e2,e3,e4=boundary_coefficients(p,boundary)
    x=log_margin
    return x*x*(.5*e2+(e3/6.+(e4/24.)*x)*x)
