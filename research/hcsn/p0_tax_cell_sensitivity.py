"""Research-only original HX Eq12 gradient / one-axis FP32 tax preimage.

High-precision CDF quadrature is numerical, NOT outward-rounded. This is
neither a joint parameter-box nor a global obstacle or QVI certificate.
"""
from __future__ import annotations
from fractions import Fraction
import math
import struct
import mpmath as mp
try:
    from .hx_original import HXParams
    from .hx_local_obstacle_mp_reference import mp_first_passage_sign
except ImportError:
    from hx_original import HXParams
    from hx_local_obstacle_mp_reference import mp_first_passage_sign


def _f32(word: int) -> float:
    return struct.unpack('!f', struct.pack('!I', word))[0]


def _tax_rounding_cell(tax: float) -> tuple[int, Fraction, Fraction]:
    if not isinstance(tax, float) or not math.isfinite(tax) or not 0 < tax < 1:
        raise ValueError('Finite interior float tax required')
    word = struct.unpack('!I', struct.pack('!f', tax))[0]
    if not 1 < word < 0x3f800000 - 1:
        raise ValueError('Binary32 tax preimage may cross domain')
    low, mid, high = map(lambda w: Fraction.from_float(_f32(w)),
                         (word-1, word, word+1))
    lo, hi = (low+mid)/2, (mid+high)/2
    if not 0 < lo < hi < 1:
        raise ValueError('Tax preimage is outside [0,1)')
    return word, lo, hi


def audit_tax_cell(p: HXParams, *, digits: int = 50) -> dict:
    """Fixed-other-parameter, necessary-only numerical screen; never admit."""
    if not isinstance(p, HXParams):
        raise TypeError('HXParams required')
    if type(digits) is not int or not 35 <= digits <= 90:
        raise ValueError('Digits must be 35..90')
    word, lo, hi = _tax_rounding_cell(p.tax)
    # Independent first-passage integration, not original FP64 Eq12 Laplace.
    ref = mp_first_passage_sign(p, decimal_digits=digits)
    with mp.workdps(digits):
        d = lambda n: mp.mpf(str(getattr(p, n)))
        r, delta, sig, alpha, xi, k, m, C, P = map(d, (
            'r','delta','sigma','alpha','xi','k','maturity',
            'coupon_total','face_total'))
        lam = r+xi*k
        a = (r-delta-sig**2/2)/sig**2
        eta = mp.sqrt(a*a+2*r/sig**2)-a
        if eta <= 1:
            raise ArithmeticError('No finite positive far-field resolvent')
        If, Ig = mp.mpf(ref['I_f']), mp.mpf(ref['I_g'])
        disc = mp.exp(-lam*m)
        c0, u = C/(m*lam), P/m-C/(m*lam)
        den = delta/(eta-1)+alpha/m*Ig
        if den <= 0:
            raise ArithmeticError('No positive boundary denominator')
        common = (-mp.expm1(-lam*m))/eta + disc*If
        const = C/eta + u*common + c0*Ig
        b = lambda t: (const-t*C/eta)/den
        q = lambda t: (delta+alpha/m)*b(t)-(1-t)*C-P/m
        rat = lambda v: mp.mpf(v.numerator)/v.denominator
        tlo, thi, t0 = rat(lo), rat(hi), d('tax')
        qlo, qhi, b0 = q(tlo), q(thi), b(t0)
        r0 = mp.mpf(ref['boundary'])
        if abs(b0-r0) > 10**(-digits//2)*max(1,abs(r0)):
            raise ArithmeticError('Independent high-precision root mismatch')
        net_min, net_max = min(qlo,qhi), max(qlo,qhi)
        dbdt = -C/(eta*den)
        dqdt = C+(delta+alpha/m)*dbdt
        grad_alpha = -b0*Ig/(m*den)
        grad_C = ((1-t0)/eta-common/(m*lam)+Ig/(m*lam))/den
        grad_P = common/(m*den)
        scale = max(1,abs(qlo),abs(qhi),abs(delta*b0),abs((1-t0)*C),
                    abs(alpha*b0/m),abs(P/m))
        tol = mp.power(10,-digits//2)*scale
        classification = ('REJECT_LOCAL_EQUITY_FOR_ENTIRE_TAX_CELL'
                          if net_min>tol else
                          'ONE_AXIS_ONLY_NO_LOCAL_SIGN_OBSTRUCTION'
                          if net_max < -tol else 'TAX_CELL_LOCAL_SIGN_AMBIGUITY')
        fmt = lambda x: mp.nstr(x,digits-3)
        return {
            'float32_tax_word': f'0x{word:08x}',
            'tax_cell_lower_exact': str(lo),
            'tax_cell_upper_exact': str(hi),
            'boundary_at_supplied_tax': fmt(b0),
            'boundary_at_tax_cell_lower': fmt(b(tlo)),
            'boundary_at_tax_cell_upper': fmt(b(thi)),
            'boundary_cashflow_min': fmt(net_min),
            'boundary_cashflow_max': fmt(net_max),
            'diagnostic_resolution_not_error_bound': fmt(tol),
            'd_boundary_d_tax': fmt(dbdt),
            'd_boundary_d_alpha': fmt(grad_alpha),
            'd_boundary_d_coupon_total': fmt(grad_C),
            'd_boundary_d_face_total': fmt(grad_P),
            'd_cashflow_d_tax': fmt(dqdt),
            'classification': classification,
            'other_parameters_held_exact_decimal': True,
            'mp_quadrature_not_outward_rounded': True,
            'full_fp32_input_box_certified': False,
            'global_equity_obstacle_certified': False,
            'regenerative_qvi_certified': False,
            'p0_scientific_gate': 'OPEN',
            'production_activation': False,
        }
