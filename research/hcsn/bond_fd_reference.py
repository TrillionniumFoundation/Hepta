"""Independent numerical finite-difference reference for He--Xiong bond Eq. (8).

Solves the *time-to-maturity* parabolic PDE on x=log(V/VB):

    d_tau = (sigma^2/2) d_xx + (r-delta-sigma^2/2) d_x
            - (r+xi*k) d + c

Initial d(x,0)=p (for x>0); absorbing/default boundary d(0,tau)=
alpha*VB/m and large-log-state asymptote d(x_max,tau)=c/lambda +
(p-c/lambda)*exp(-lambda*tau).

It intentionally does NOT use He--Xiong's first-passage CDF, Laplace
integrals, or paper Eq. (8) to construct the interior solution. An
unconditional implicit monotone scheme makes the stochastic boundary and
coupon term independent from the closed-form implementation.

Finite x_max and mesh sizes make this only a numerical reference on a
bounded domain, not a proof of an all-domain error bound.  The corner
(x=0,tau=0) is discontinuous when p != alpha*VB/m.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import numpy as np
from scipy.linalg import solve_banded
try:
    from .hx_original import HXParams
except ImportError:
    from hx_original import HXParams


@dataclass(frozen=True)
class BondPDEResult:
    x: np.ndarray
    values: np.ndarray
    tau: float
    steps: int
    dx: float
    left_boundary: float
    right_boundary: float
    scheme: str = "backward-euler-central-log-mmatrix"

    def at(self, x: float) -> float:
        if not math.isfinite(x) or x < self.x[0] or x > self.x[-1]:
            raise ValueError("Outside numerical log-state grid")
        return float(np.interp(x, self.x, self.values))


def solve_bond_pde(p: HXParams, boundary: float, tau: float, *,
                   max_x: float = 7.0, points: int = 501,
                   steps: int = 1600) -> BondPDEResult:
    """Backward Euler on log states; tridiagonal sparse linear solve.

    Central differences are used only inside the positive off-diagonal
    M-matrix coefficient domain. Refuse discretizations violating it.
    This prevents silently claiming positivity or monotonicity with an
    unstable discretization.  Results are per face value of a *single*
    stationary bond, not aggregate debt value.
    """
    if (not isinstance(p, HXParams) or not math.isfinite(boundary)
        or boundary <= 0 or not math.isfinite(tau)
        or not 0 <= tau <= p.maturity or not math.isfinite(max_x)
        or not 4. <= max_x <= 12. or not 101 <= points <= 2001
        or not 100 <= steps <= 8000):
        raise ValueError("Invalid PDE reference parameter/grid domain")
    x=np.linspace(0.,max_x,points)
    dx=x[1]-x[0]
    diffusion=.5*p.sigma*p.sigma
    drift=p.r-p.delta-diffusion
    below=diffusion/(dx*dx)-drift/(2*dx)
    above=diffusion/(dx*dx)+drift/(2*dx)
    if min(below,above)<0:
        raise ValueError("Non-monotone central-difference grid; refine spatial mesh")
    dt=tau/steps
    n=points-2
    lam=p.lam
    initial=p.p
    left=p.alpha*boundary/p.maturity
    arr=np.full(n,initial,dtype=np.float64)
    # banded representation, 1 superdiagonal / 1 subdiagonal
    ab=np.zeros((3,n),dtype=np.float64)
    ab[1,:]=1+dt*(below+above+lam)
    ab[0,1:]=-dt*above
    ab[2,:-1]=-dt*below
    c0=p.c/lam
    for index in range(1,steps+1):
        now=dt*index
        far=c0+(p.p-c0)*math.exp(-lam*now)
        rhs=arr+dt*p.c
        rhs[0]+=dt*below*left
        rhs[-1]+=dt*above*far
        arr=solve_banded((1,1),ab,rhs,overwrite_ab=False,
                         overwrite_b=True,check_finite=False)
    far=c0+(p.p-c0)*math.exp(-lam*tau)
    values=np.concatenate(([left],arr,[far]))
    if not np.all(np.isfinite(values)) or np.min(values)<-1e-7:
        raise ArithmeticError("PDE reference lost finite nonnegative value")
    return BondPDEResult(x,values,tau,steps,dx,left,far)
