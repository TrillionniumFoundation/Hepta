"""Bounded-domain HX-INSPIRED one-shot perpetual Call/Put primitive.

This is NOT the original financial HX Eq.(8)/(12)/(A7) coupled problem.
It solves a simplified scalar obstacle with GBM and running reward
f(V)=delta*V-r*K: max{(L-r)C+f, -C}=0. Stop payoff=0.

An independent finite-difference BVP reference checks the continuation PDE.
Production activation and any all-domain/FP32 certification remain disabled.
"""
from __future__ import annotations
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class PhysicalParameters:
    r: float = .05
    delta: float = .03
    sigma: float = .2
    k: float = 1.0
    def __post_init__(self):
        if not all(math.isfinite(x) for x in (self.r,self.delta,self.sigma,self.k)):
            raise ValueError('Nonfinite parameters')
        # Bounded exploratory validation domain. No all-domain claims.
        if not (.001<=self.r<=.3 and .001<=self.delta<=.2
                and .01<=self.sigma<=1. and .1<=self.k<=10.):
            raise ValueError('Outside declared one-shot reference domain')


def beta_and_boundary(p:PhysicalParameters):
    s2=p.sigma*p.sigma
    q=p.r-p.delta-s2/2
    disc=math.hypot(q, math.sqrt(2*p.r*s2))
    if q<0:
        beta=2*p.r/(disc-q)
    else:
        beta=(disc+q)/s2
    if not math.isfinite(beta) or beta<=0:
        raise ArithmeticError('Root outside valid range')
    b=p.k*beta/(1+beta)
    return beta,b


def values(v:float,p:PhysicalParameters):
    if not (math.isfinite(v) and v>0):
        raise ValueError('V must be finite and positive')
    beta,b=beta_and_boundary(p)
    margin=math.log(v/b)
    if margin<=0:
        return (0.,p.k-v,margin,b,0.,1.)
    # Recover C directly from expm1; avoid complete cancellation very near b.
    m=margin
    if margin < 1e-4 and beta*margin < 1e-3:
        # Taylor with a 5th-order term: remaining O(m^6 * beta^5).
        c=b*m*m*((1+beta)/2+(1-beta**2)*m/6
                 +(1+beta**3)*m*m/24+(1-beta**4)*m**3/120)
    else:
        c=b*math.fsum((math.expm1(m),math.expm1(-beta*m)/beta))
    put=(p.k-b)*math.exp(-beta*margin)
    gate=-math.expm1(-(beta+1)*margin)
    return c,put,margin,b,gate,1-gate


def stationary_pde_residual(v:float,p:PhysicalParameters):
    c,_,m,b,gate,rem=values(v,p)
    if m<=0:
        raise ValueError('Continuation PDE only in v>boundary')
    c1=gate
    c2=(beta_and_boundary(p)[0]+1)*rem/v
    return ((p.r-p.delta)*v*c1+.5*p.sigma*p.sigma*v*v*c2
            +p.delta*v-p.r*p.k-p.r*c)


def independent_finite_difference(p:PhysicalParameters,*,steps:int=512,xmax:float=8.):
    """Independent positive-domain central/upwind FD solve in log(V/b).

    Lower Dirichlet C(0)=0; upper asymptotic C(L)~=b*exp(L)-K.
    Numerical domain/truncation error is reported, not silently certified.
    """
    import numpy as np
    from scipy.linalg import solve_banded
    if not isinstance(steps,int) or steps<64 or steps>8192 or xmax<=0 or xmax>12:
        raise ValueError('Invalid FD domain')
    beta,b=beta_and_boundary(p)
    dx=xmax/steps
    xs=np.linspace(0,xmax,steps+1)
    vv=b*np.exp(xs)
    nu=p.r-p.delta-.5*p.sigma*p.sigma
    diffusion=.5*p.sigma*p.sigma/dx**2
    lower=diffusion-nu/(2*dx)
    upper=diffusion+nu/(2*dx)
    if min(lower,upper)<0:
        # Use monotone upwind to avoid negative transition rates.
        lower=diffusion+max(0.,-nu)/dx
        upper=diffusion+max(0.,nu)/dx
    diag=p.r+lower+upper
    n=steps-1
    ab=np.zeros((3,n),dtype=float)
    ab[0,1:]=-upper
    ab[1,:]=diag
    ab[2,:-1]=-lower
    rhs=p.delta*vv[1:-1]-p.r*p.k
    top=vv[-1]-p.k
    rhs[-1]+=upper*top
    out=np.empty(steps+1)
    out[0]=0.;out[-1]=top
    out[1:-1]=solve_banded((1,1),ab,rhs,check_finite=True)
    if not np.all(np.isfinite(out)):
        raise ArithmeticError('Nonfinite FD reference')
    truth=np.array([values(float(z),p)[0] for z in vv])
    # Exclude the last quarter, where asymptotic Dirichlet truncation matters.
    core=slice(1,3*steps//4)
    error=float(np.max(abs(out[core]-truth[core])))
    scale=float(max(1.,np.max(abs(truth[core]))))
    return {'steps':steps,'domain':xmax,'max_abs_error':error,
            'max_rel_to_core_scale':error/scale,
            'min_fd_value':float(np.min(out)),
            'first_derivative_at_boundary':float((out[1]-out[0])/dx/b),
            'domain_truncation':'upper Dirichlet C(L)=V(L)-K; not a certified tail',
            'scheme':'central if generator offdiagonals >=0 else upwind'}
