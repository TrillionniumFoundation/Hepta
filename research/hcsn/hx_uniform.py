"""P0 robust bounded-domain original He--Xiong equity evaluation.

No claim of closed-form A7 at the xi*k=0 removable singularity: the
independent quadrature Green representation is used there.  State is passed
as its *log-margin* rather than recomputing log(V/V_B) from low-precision V.
This is a slow FP64 CPU reference / numerical fallback, NOT neural GPU code.

Original HX source: He & Xiong (2012), Journal of Finance, eqs (8),(11),
(12), and Appendix A7. Separate from the newly invented HCSN put/QVI.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
try:
    from .hx_original import HXParams,closed_boundary,equity_green
    from .hx_a7 import equity_a7
    from .hx_stable import equity_near_boundary
except ImportError:
    from hx_original import HXParams,closed_boundary,equity_green
    from hx_a7 import equity_a7
    from hx_stable import equity_near_boundary

@dataclass(frozen=True)
class HXEval:
    equity:float
    boundary:float
    log_margin:float
    method:str
    fp64_reference_only:bool=True


def equity_logmargin(x:float,p:HXParams, *,boundary:float|None=None,
                     singular_tol:float=1e-5) -> HXEval:
    """Validate and evaluate the original equity using fail-closed methods.

    Exact boundary is obtained from HX Proposition 1. For 0<=x<=.001 the
    PDE-derived fourth-order local series avoids catastrophic cancellation;
    for zhat~=z, the numerical Green reference is used; otherwise A7.
    We guard negative value, finite precision overflow, and unsupported
    far domain before computing. Method is included for test provenance.
    """
    if not math.isfinite(x) or not (-2. <= x <= 8.):
        raise ValueError('Reference supports finite log-margin [-2,8]')
    if not math.isfinite(singular_tol) or not (1e-10<=singular_tol<=.01):
        raise ValueError('Unsupported degeneracy tolerance')
    b=closed_boundary(p) if boundary is None else boundary
    if not math.isfinite(b) or b<=0:
        raise ValueError('Invalid HX boundary')
    if x<=0:
        return HXEval(0.,b,x,'stopping')
    if x<=1e-3:
        val=equity_near_boundary(x,p,b)
        method='pde_local_series'
    elif abs(p.zhat-p.z) < singular_tol:
        val=equity_green(b*math.exp(x),b,p)
        method='quadrature_green_limit'
    else:
        val=equity_a7(b*math.exp(x),p,b)
        method='original_a7'
    if not math.isfinite(val):
        raise ArithmeticError('Nonfinite original HX value')
    # At the free boundary the true value is non-negative. A noticeable
    # violation is a parameter/model admissibility or numerical failure.
    if val < -1e-7*max(1.,b):
        raise ArithmeticError('Negative HX equity in continuation domain')
    if val<0:val=0.
    return HXEval(val,b,x,method)
