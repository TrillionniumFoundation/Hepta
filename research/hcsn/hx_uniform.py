"""P0 robust bounded-domain original He--Xiong equity evaluation.

Fail-closed RESEARCH reference: Eq12 is a smooth-pasting candidate, not a
certified global optimal-stopping boundary. Reject a candidate that fails or
cannot numerically clear the necessary local equity-curvature screen. The
explicit relative buffer is only exploratory; it is not an error certificate.
No small negative continuation equity is silently clipped to zero.

Original HX source: He and Xiong (2012), Eqs (8), (11), (12), A7. This
CPU FP64 method is NOT a production neural activation or global HX proof.
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
    global_obstacle_certified:bool=False
    production_activation:bool=False


def _check_local_candidate(p:HXParams,b:float)->None:
    """Fail closed on local sign obstruction/ambiguity; never certify a pass.

    With smooth fit E(0)=E_x(0)=0, original Eq11 gives
    E_xx(0+)=-2*[delta*b-(1-tax)*C+alpha*b/m-P/m]/sigma**2.
    A *positive* bracket implies negative equity right above the boundary.
    The conservative scale buffer is an empirical diagnostic, not a rigorous
    floating-point, quadrature, or boundary error bound. Negative bracket
    only means 'not refuted by this local necessary test'.
    """
    inflow=p.delta*b
    coupon=(1-p.tax)*p.coupon_total
    recovery=p.alpha*b/p.maturity
    principal=p.face_total/p.maturity
    net=math.fsum((inflow,-coupon,recovery,-principal))
    scale=max(1.,abs(inflow),abs(coupon),abs(recovery),abs(principal))
    buffer=1e-9*scale
    if not math.isfinite(net) or not math.isfinite(buffer):
        raise ArithmeticError('Original HX local necessary condition is nonfinite')
    if net>=-buffer:
        raise ArithmeticError('Original HX candidate rejected or local sign unresolved; '
                              'smooth pasting alone cannot authorize evaluation')


def equity_logmargin(x:float,p:HXParams, *,boundary:float|None=None,
                     singular_tol:float=1e-5)->HXEval:
    """Evaluate a bounded research reference only when local checks permit it.

    The Eq12 root is checked even if an optional boundary is supplied. No
    local sign verdict, including a strict negative result, proves global
    obstacle admissibility. Green and A7 may still fail elsewhere, so negative
    values always raise rather than being projected onto the zero obstacle.
    """
    if not isinstance(p,HXParams):
        raise TypeError('HXParams required')
    if not math.isfinite(x) or not (-2.<=x<=8.):
        raise ValueError('Reference supports finite log-margin [-2,8]')
    if not math.isfinite(singular_tol) or not (1e-10<=singular_tol<=.01):
        raise ValueError('Unsupported degeneracy tolerance')
    root=closed_boundary(p)
    b=root if boundary is None else boundary
    if not isinstance(b,(int,float)) or isinstance(b,bool) or not math.isfinite(b) or b<=0:
        raise ValueError('Invalid HX boundary')
    if not math.isclose(b,root,rel_tol=1e-12,abs_tol=1e-12):
        raise ValueError('External HX boundary is not the Eq12 candidate')
    _check_local_candidate(p,b)
    if x<=0:
        return HXEval(0.,b,x,'stopping')
    if x<=1e-3:
        val=equity_near_boundary(x,p,b)
        method='pde_local_series'
    elif abs(p.zhat-p.z)<singular_tol:
        val=equity_green(b*math.exp(x),b,p)
        method='quadrature_green_limit'
    else:
        val=equity_a7(b*math.exp(x),p,b)
        method='original_a7'
    if not math.isfinite(val):
        raise ArithmeticError('Nonfinite original HX value')
    if val<0:
        raise ArithmeticError('Negative original HX continuation equity; no silent clipping')
    return HXEval(val,b,x,method)
