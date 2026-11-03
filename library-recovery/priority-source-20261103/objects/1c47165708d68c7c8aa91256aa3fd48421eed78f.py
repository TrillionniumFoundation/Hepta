"""High precision direct HX Appendix A7 with removable xi*k=0 limit.

At zhat=z (zero liquidity hazard), a subterm of A(y) is 0/0.
The continuous limit is -d/dy[K(y,gamma)+k(-y)] at y=z.
mpmath differentiates that numerator at high precision; original paper's
formula and standalone Green integral are separately checked.

Research FP64/MP reference ONLY, not a vectorized neural activation and not
all-domain certified for arbitrary financial parameters.
"""
from __future__ import annotations
import math
import mpmath as mp
try:
    from .hx_original import HXParams,closed_boundary
except ImportError:
    from hx_original import HXParams,closed_boundary


def equity_a7_mp(v:float,p:HXParams,boundary:float|None=None,*,dps:int=75):
    if not isinstance(dps,int) or dps<40 or dps>250:
        raise ValueError('Precision outside reference range')
    b=closed_boundary(p) if boundary is None else boundary
    if not math.isfinite(v) or not math.isfinite(b) or v<=0 or b<=0:
        raise ValueError('Nonpositive or nonfinite state/boundary')
    if v<=b:return 0.
    with mp.workdps(dps):
        num=lambda z:mp.mpf(str(z))
        r=num(p.r);d=num(p.delta);s=num(p.sigma);ss=s*s
        alpha=num(p.alpha);tax=num(p.tax)
        xi=num(p.xi);k=num(p.k);T=num(p.maturity)
        c=num(p.coupon_total)/T;face=num(p.face_total)/T
        coupon=num(p.coupon_total)
        lam=r+xi*k
        a=(r-d-ss/2)/ss
        z=mp.sqrt(a*a+2*r/ss)
        zh=mp.sqrt(a*a+2*lam/ss)
        eta=z-a;gam=z+a
        t=s*mp.sqrt(T)
        x=mp.log(num(v)/num(b))
        nb=num(b)
        phi=lambda y:mp.erfc(-y/mp.sqrt(2))/2
        def K(y, h):
            shift=h-a
            amp=mp.exp((shift*shift-y*y)*t*t/2)
            return ((phi(y*t)-amp*phi(shift*t))*mp.exp(-h*x)
               +amp*mp.exp(-h*x)*phi((-x+shift*t*t)/t)
               -mp.exp(-(a+y)*x)*phi((-x+y*t*t)/t))
        def small_k(y):
            shift=-eta-a
            amp=mp.exp((shift*shift-y*y)*t*t/2)
            return (amp*mp.exp(eta*x)*phi((-x+shift*t*t)/t)
                 -mp.exp(-(a+y)*x)*phi((-x+y*t*t)/t))
        def A(y):
            first=lambda z0: K(z0,gam)+small_k(-z0)
            if abs(z-y)<mp.mpf('1e-25'):
                primary=-mp.diff(first,z)
            else:
                primary=first(y)/(z-y)
            return primary+(K(-y,gam)+small_k(y))/(z+y)
        c0=c/lam
        u=face-c0
        h=(1-tax)*coupon+(1-mp.exp(-lam*T))*u
        E=(num(v)-d*nb*mp.exp(-gam*x)/(z*ss*(gam+1))
            -h/(z*ss)*(1/eta+(1-mp.exp(-gam*x))/gam)
            +(mp.exp(-lam*T)*u*A(a)-(alpha*nb/T-c0)*A(zh))/(z*ss))
        if not mp.isfinite(E):raise ArithmeticError('non-finite MP A7 result')
        return float(E)
