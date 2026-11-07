"""Independent finite-difference reference for the ORIGINAL HX equity Eq. (11).

Numerical model: dX = (r-delta-sigma**2/2)dt + sigma dW, X=log(V/V_B).
Continuation-domain equity satisfies (r - L)E = delta*V -(1-tax)*C + d(V,m)-p.

The source is the original HX *bond Eq. (8)*, not an A7/Green equity value;
the linear ODE is solved with a monotone log-space tridiagonal stencil.
We subtract a known affine far-field particular solution before solving to
avoid catastrophic cancellation. No closed_boundary, A7, equity_green, or
smooth-pasting integral is used by this FD solver or its boundary root.

Only a finite-domain, fixed-coefficient numerical diagnostic is claimed.
It is NOT a proof of a global nonlinear coupled free-boundary model, nor
an FP32/BF16 or neural training certificate.
"""
from __future__ import annotations
from dataclasses import dataclass
import math

import numpy as np
from scipy.linalg import solve_banded

try:
    from .hx_original import HXParams, bond_price_from_log
except ImportError:
    from hx_original import HXParams, bond_price_from_log


@dataclass(frozen=True)
class EquityFD:
    x: np.ndarray
    equity: np.ndarray
    correction: np.ndarray
    boundary: float
    h: float
    x_max: float
    boundary_log_derivative: float
    max_equation_residual: float
    tail_correction: float


def _q(p: HXParams) -> float:
    # As X -> infinity, bond price tends to c/lambda + exp(-lambda*m)*(p-c/lambda).
    lam = p.r+p.xi*p.k
    c0 = (p.coupon_total/p.maturity)/lam
    pv_principal = p.face_total/p.maturity
    return ((1-p.tax)*p.coupon_total
            +(pv_principal-c0)*(-math.expm1(-lam*p.maturity)))


def _coefficients(p: HXParams, step: float) -> tuple[float, float]:
    diffusion = .5*p.sigma*p.sigma
    drift = p.r-p.delta-diffusion
    lo = diffusion/(step*step)-drift/(2*step)
    hi = diffusion/(step*step)+drift/(2*step)
    if min(lo,hi)<0:
        # Positive off-diagonal generator, stable for coarse grids / high drift.
        lo=diffusion/(step*step)+max(-drift,0)/step
        hi=diffusion/(step*step)+max(drift,0)/step
    return lo,hi


def solve_equity_fd(p: HXParams, boundary: float, *, cells: int=1600,
                    x_max: float=8.0) -> EquityFD:
    if (not math.isfinite(boundary) or boundary<=0 or cells<120 or cells>40000
            or not math.isfinite(x_max) or not 4.0<=x_max<=12.0):
        raise ValueError('Outside bounded independent HX equity FD reference domain')
    h=x_max/cells
    x=np.linspace(0,x_max,cells+1)
    v=boundary*np.exp(x)
    q=_q(p)
    # E(x) = V_B exp(x) - q/r + u(x); (r-L)u = rollover_source(x).
    # The rollover source is computed from the physical bond Eq. 8, rather
    # than from Appendix A7, so this is an independent numerical equity route.
    correction_rhs=np.fromiter((
        bond_price_from_log(float(t),p.maturity,boundary,p)
        - p.face_total/p.maturity
        - (1-p.tax)*p.coupon_total
        + q
        for t in x[1:-1]), dtype=float,count=cells-1)
    low, high=_coefficients(p,h)
    u0=q/p.r-boundary
    n=cells-1
    ab=np.zeros((3,n),dtype=float)
    ab[0,1:]=-high
    ab[1,:]=p.r+low+high
    ab[2,:-1]=-low
    rhs=correction_rhs.copy()
    rhs[0]+=low*u0
    u_internal=solve_banded((1,1),ab,rhs,overwrite_ab=False,
                            overwrite_b=False,check_finite=True)
    u=np.empty(cells+1,dtype=float)
    u[0]=u0
    u[1:-1]=u_internal
    u[-1]=0.0  # far-field no-exploding-mode condition
    equity=v-q/p.r+u
    equity[0]=0.0
    boundary_derivative=float((-3*equity[0]+4*equity[1]-equity[2])/(2*h))
    residual=low*u[:-2]-(p.r+low+high)*u[1:-1]+high*u[2:]+correction_rhs
    return EquityFD(x,equity,u,float(boundary),float(h),float(x_max),
                    boundary_derivative,float(np.max(np.abs(residual))),
                    float(abs(u[-2])))


def solve_boundary_fd(p: HXParams, *, cells:int=1600, x_max:float=8.0,
                      trial_1:float=1.0,trial_2:float=100.0) -> tuple[float,EquityFD]:
    """Independent free-boundary root of FD smooth-pasting (linear in V_B).

    Does NOT use the paper's algebraic Eq12 or the Green smooth-pasting
    integral; computes the signed boundary derivative from each FD solution.
    """
    if not (0<trial_1<trial_2 and math.isfinite(trial_1+trial_2)):
        raise ValueError('Invalid root trials')
    e1=solve_equity_fd(p,trial_1,cells=cells,x_max=x_max)
    e2=solve_equity_fd(p,trial_2,cells=cells,x_max=x_max)
    d1=e1.boundary_log_derivative
    d2=e2.boundary_log_derivative
    if not math.isfinite(d1+d2) or abs(d2-d1)<1e-12:
        raise ArithmeticError('Boundary not identifiable by FD')
    vb=(trial_1*d2-trial_2*d1)/(d2-d1)
    if not math.isfinite(vb) or vb<=0:
        raise ArithmeticError('No admissible positive FD free boundary')
    solved=solve_equity_fd(p,vb,cells=cells,x_max=x_max)
    return vb,solved
