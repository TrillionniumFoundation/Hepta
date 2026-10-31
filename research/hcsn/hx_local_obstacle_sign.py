"""Independent *necessary-condition* screen for HX smooth-fit candidates.

The original financial equity equation (He--Xiong 2012, Eq. 11) in
x=log(V/V_B) is

   .5*sigma**2 E_xx + (r-delta-.5*sigma**2) E_x - r E + q(x)=0,
   q(x) = delta*V_B*exp(x) -(1-tax)*C + d(V_B*exp(x),m) - P/m.

At a C2 continuation solution satisfying the *candidate* smooth fit
E(0)=E_x(0)=0, Eq. 8 gives d(V_B,m)=alpha*V_B/m and therefore
E_xx(0+)=-2*q(0+)/sigma**2.  If q(0+) is strictly positive, then
E(x)<0 for all sufficiently small positive x, contradicting equity
limited liability (the obstacle E>=0). Thus such a smooth-fit root
cannot be a globally admissible stopping boundary.

The screen is NECESSARY ONLY. A negative q(0+) does not prove that equity
is nonnegative further out; a near-zero q(0+) is indeterminate. Binary64
signs are numerical diagnostics, not outward-rounded interval proofs.

Research-only: no neural-operator or production admission.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math

try:
    from .hx_original import HXParams, closed_boundary, bond_price_from_log
except ImportError:
    from hx_original import HXParams, closed_boundary, bond_price_from_log


@dataclass(frozen=True)
class LocalSignScreen:
    boundary: float
    boundary_net_cashflow: float
    boundary_log_curvature: float
    recovery_over_face: float
    absolute_sign_margin: float
    classification: str
    limited_liability_admitted: bool = False
    global_optimality_established: bool = False
    production_activation: bool = False


def screen_hx_smooth_fit(p: HXParams, *, relative_sign_buffer: float = 1e-9) -> LocalSignScreen:
    """Refuse local negative-curvature candidates, never *admit* others.

    `relative_sign_buffer` is a deliberately coarse numerical ambiguity
    margin, NOT a rigorous FP error bound or an independent proof. It may
    only control diagnostic resolution; it cannot enable any approval.
    """
    if not isinstance(p, HXParams):
        raise TypeError('HXParams required; no arbitrary input coercion')
    if (not isinstance(relative_sign_buffer, (float, int))
            or isinstance(relative_sign_buffer, bool)
            or not math.isfinite(relative_sign_buffer)
            or not 1e-12 <= relative_sign_buffer <= 1e-3):
        raise ValueError('Sign buffer must be finite and within the finite exploratory range')
    boundary = closed_boundary(p)   # Eq. 12 candidate only, not obstacle solution
    positive_cashflow = p.delta * boundary
    coupon_cost = (1-p.tax)*p.coupon_total
    liquidation_bond = p.alpha*boundary/p.maturity
    rollover_principal = p.face_total/p.maturity
    # Eq.8 at V=V_B is exactly alpha*V_B/m for any maturity>0.
    net = math.fsum((positive_cashflow, -coupon_cost,
                     liquidation_bond, -rollover_principal))
    scale = max(1., positive_cashflow, coupon_cost, liquidation_bond,
                rollover_principal)
    margin = float(relative_sign_buffer)*scale
    curvature = -2.*net/(p.sigma*p.sigma)
    if not all(math.isfinite(t) for t in (boundary, net, margin, curvature)):
        raise ArithmeticError('Nonfinite necessary-condition evaluation')
    if net > margin:
        decision = 'REJECT_NEGATIVE_EQUITY_NEAR_BOUNDARY'
    elif net < -margin:
        decision = 'NO_LOCAL_SIGN_OBSTRUCTION_ONLY'
    else:
        decision = 'INDETERMINATE_SIGN'
    return LocalSignScreen(float(boundary), float(net), float(curvature),
                           float(p.alpha*boundary/p.face_total), float(margin), decision)


def crosscheck_boundary_bond(p: HXParams) -> float:
    """Independent Eq8 call check; does not enter the sign screen decision."""
    boundary=closed_boundary(p)
    return bond_price_from_log(0.,p.maturity,boundary,p)-p.alpha*boundary/p.maturity


def as_evidence(p: HXParams) -> dict:
    """Lossless, type-labelled record of a finite exploratory numerical case."""
    s=screen_hx_smooth_fit(p)
    return {'parameters':asdict(p),'local_sign_screen':asdict(s),
            'bond_boundary_identity_residual':crosscheck_boundary_bond(p),
            'interpretation':'Necessary sign obstruction only; not a global stopping proof',
            'p0_scientific_gate':'OPEN','p1_p6_scientific_gates':'OPEN'}
