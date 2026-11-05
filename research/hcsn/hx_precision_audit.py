"""Independent MP80 check of original HX 2012 Eq. (12) FP64 boundary.

Research-only numerical diagnostic.  It recomputes every algebraic constituent
from the original parameter floats in a cloned high-precision context; it does
NOT reuse the float64 Laplace/CDF integrals, or certify the equity obstacle,
QVI, rounding enclosure, or production admission.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import numbers

import mpmath as mp

try:
    from .hx_original import HXParams, closed_boundary
except ImportError:
    from hx_original import HXParams, closed_boundary


@dataclass(frozen=True)
class HXBoundaryAudit:
    fp64_boundary: float
    mp80_boundary: float
    absolute_difference: float
    relative_difference: float
    precision_digits: int
    global_obstacle_certified: bool = False
    production_activation: bool = False


def high_precision_boundary(p: HXParams, *, digits: int = 80):
    """Positive Eq12 candidate using MP arithmetic from the input parameters.

    This is an *independent-precision evaluation of the same Eq12 formula*,
    not a separate free-boundary equation or error-interval proof.
    """
    if not isinstance(p, HXParams):
        raise TypeError('HXParams required')
    if type(digits) is not int or not 60 <= digits <= 160:
        raise ValueError('Unsupported audit precision')
    c = mp.mp.clone()  # independent context avoids mutating global precision
    c.dps = digits
    r, delta, sigma, alpha, tax, xi, k, maturity, C, P = (
        c.mpf(getattr(p, name)) for name in (
            'r', 'delta', 'sigma', 'alpha', 'tax', 'xi', 'k',
            'maturity', 'coupon_total', 'face_total'
        )
    )
    lam = r + xi*k
    a = (r-delta-sigma*sigma/2)/(sigma*sigma)
    z = c.sqrt(a*a+2*r/(sigma*sigma))
    zh = c.sqrt(a*a+2*lam/(sigma*sigma))
    eta, gamma = z-a, z+a
    t = sigma*c.sqrt(maturity)
    norm = c.sqrt(2*c.pi)

    def phi(x):
        return c.exp(-x*x/2)/norm

    def Phi(x):
        return c.erfc(-x/c.sqrt(2))/2

    def laplace_cdf(rate, drift):
        # Exact removable limit at rate=0. Tiny nonzero rates below
        # 10^(-dps/2) use this analytic limit; error is far below the
        # numeric acceptance threshold, not a rigorous directed bound.
        if abs(rate) < c.power(10, -digits//2):
            u = drift*t
            return t*(u*Phi(u)+phi(u))
        return (Phi(drift*t) - c.exp((rate*rate/2-drift*rate)*t*t)
                * Phi((drift-rate)*t))/rate

    I_f = laplace_cdf(eta,-a) + laplace_cdf(gamma,a)
    I_g = laplace_cdf(z-zh,-zh) + laplace_cdf(z+zh,zh)
    c0 = C/(maturity*lam)
    u = P/maturity-c0
    ell = c.exp(-lam*maturity)
    num = (((1-tax)*C+(1-ell)*u)/eta + ell*u*I_f+c0*I_g)
    den = delta/(eta-1) + alpha/maturity*I_g
    if not (c.isfinite(num) and c.isfinite(den) and den > 0):
        raise ArithmeticError('MP Eq12 numerator/denominator is inadmissible')
    result = num/den
    if not c.isfinite(result) or result <= 0:
        raise ArithmeticError('No finite positive MP Eq12 candidate')
    return result


def audit_boundary(p: HXParams, *, digits: int = 80) -> HXBoundaryAudit:
    """Compare original float64 evaluator with independent-precision Eq12."""
    hi = high_precision_boundary(p, digits=digits)
    lo = closed_boundary(p)
    if not math.isfinite(lo) or lo <= 0:
        raise ArithmeticError('Nonfinite FP64 Eq12 candidate')
    c = hi.context
    diff = abs(c.mpf(lo)-hi)
    rel = diff/hi
    return HXBoundaryAudit(lo, float(hi), float(diff), float(rel), digits)


def require_consistent_boundary(p: HXParams, root: float, *,
                                relative_limit: float = 1e-10,
                                digits: int = 80) -> HXBoundaryAudit:
    """Fail-closed numerical-check guard; does NOT award P0 PASS.

    Threshold is a reviewer-selected numeric *diagnostic*, not a proven
    outward-rounded FP32/BF16 certificate. False rejections remain possible.
    """
    if isinstance(root, bool) or not isinstance(root, numbers.Real) or not math.isfinite(root) or root <= 0:
        raise ValueError('Invalid supplied Eq12 candidate')
    if not math.isfinite(relative_limit) or not 0 < relative_limit <= 1e-6:
        raise ValueError('Invalid exploratory root discrepancy threshold')
    audit = audit_boundary(p, digits=digits)
    if (not math.isclose(root, audit.fp64_boundary, rel_tol=1e-12, abs_tol=1e-12)
            or audit.relative_difference > relative_limit):
        raise ArithmeticError('Unverified FP64 Eq12 root: MP80 discrepancy or wrong candidate')
    return audit
