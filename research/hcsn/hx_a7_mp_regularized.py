"""Reference-only He--Xiong A7 with continuous xi*k=0 limit (mpmath).

At zhat=z, A(zhat) has a removable 0/0 term: the limit is
-d/dy[K(y,gamma)+k(-y)] at y=z. Independent Green validation required.
Not a GPU activation or globally certified financial contract.
"""
from __future__ import annotations
import math
import mpmath as mp
from .hx_original import HXParams, closed_boundary

def equity_a7_mp(v:float,p:HXParams,boundary:float|None=None,*,dps:int=75)->float:
    if not isinstance(dps,int) or not 40<=dps<=250:
        raise ValueError("Invalid reference precision")
    b=closed_boundary(p) if boundary is None else boundary
    if not (math.isfinite(v) and math.isfinite(b) and v>0 and b>0):
        raise ValueError("Invalid equity state/boundary")
    if v<=b: return 0.
    with mp.workdps(dps):
        N=lambda x:mp.mpf(str(x))
        r,d,s=N(p.r),N(p.delta),N(p.sigma)
        S=s*s
        tax,alpha=N(p.tax),N(p.alpha)
        lam=r+N(p.xi)*N(p.k)
        T=N(p.maturity)
        c=N(p.coupon_total)/T
        face=N(p.face_total)/T
        a=(r-d-S/2)/S
        z=mp.sqrt(a*a+2*r/S)
        zh=mp.sqrt(a*a+2*lam/S)
        eta,gam=z-a,z+a
        t=s*mp.sqrt(T)
        x=mp.log(N(v)/N(b))
        F=lambda q:mp.erfc(-q/mp.sqrt(2))/2
        def K(y,h):
            sh=h-a
            amp=mp.exp((sh*sh-y*y)*t*t/2)
            return ((F(y*t)-amp*F(sh*t))*mp.exp(-h*x)
                  +amp*mp.exp(-h*x)*F((-x+sh*t*t)/t)
                  -mp.exp(-(a+y)*x)*F((-x+y*t*t)/t))
        def small_k(y):
            sh=-eta-a
            amp=mp.exp((sh*sh-y*y)*t*t/2)
            return (amp*mp.exp(eta*x)*F((-x+sh*t*t)/t)
                 -mp.exp(-(a+y)*x)*F((-x+y*t*t)/t))
        def A(y):
            numerator=lambda z0:K(z0,gam)+small_k(-z0)
            leading=(-mp.diff(numerator,z)
                if abs(z-y)<mp.mpf("1e-25")
                else numerator(y)/(z-y))
            return leading+(K(-y,gam)+small_k(y))/(z+y)
        c0=c/lam
        u=face-c0
        H=(1-tax)*N(p.coupon_total)+(1-mp.exp(-lam*T))*u
        equity=(N(v)-d*N(b)*mp.exp(-gam*x)/(z*S*(gam+1))
               -H/(z*S)*(1/eta+(1-mp.exp(-gam*x))/gam)
               +(mp.exp(-lam*T)*u*A(a)-(alpha*N(b)/T-c0)*A(zh))/(z*S))
        if not mp.isfinite(equity): raise ArithmeticError("Nonfinite MP equity")
        return float(equity)
