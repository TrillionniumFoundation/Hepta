"""Round-2 independent checks of original HX and actual low-precision paths.

The MP reference integrates the original Eq11 initial-value Green kernel;
it does not reuse interval Taylor coefficients. Native literal Eq12/A7 is
an adversarial arithmetic diagnostic, not an approved operator. The mixed
path is explicitly FP32 accumulation with optional BF16 output storage.
"""
from __future__ import annotations

from dataclasses import asdict
import math
import mpmath as mp

try:
    from .hx_original import HXParams
    from .hx_precision_audit import high_precision_boundary
    from .hx_interval_domain import rounding_cell
except ImportError:
    from hx_original import HXParams
    from hx_precision_audit import high_precision_boundary
    from hx_interval_domain import rounding_cell


def mp_local_equity(log_margin: float, p: HXParams, *, digits=90):
    """Independent finite integral on 0<=x<=.002, including rounded .001."""
    if not isinstance(p, HXParams):
        raise TypeError('HXParams required')
    if (isinstance(log_margin, bool) or not isinstance(log_margin, (int, float))
            or not math.isfinite(log_margin) or not 0 <= log_margin <= .002):
        raise ValueError('Local MP log margin must lie in [0,.002]')
    if type(digits) is not int or not 70 <= digits <= 150:
        raise ValueError('Independent MP digits must be 70..150')
    c = mp.mp.clone()
    c.dps = digits
    q = {name: c.mpf(value) for name, value in asdict(p).items()}
    x = c.mpf(log_margin)
    if x == 0:
        return c.mpf(0)
    r, delta, sigma = q['r'], q['delta'], q['sigma']
    S = sigma*sigma
    D = S/2
    lam = r+q['xi']*q['k']
    a = (r-delta-D)/S
    z = c.sqrt(a*a+2*r/S)
    zh = c.sqrt(a*a+2*lam/S)
    eta, gamma = z-a, z+a
    maturity = q['maturity']
    t = sigma*c.sqrt(maturity)
    b = c.mpf(high_precision_boundary(p, digits=digits))
    c0 = q['coupon_total']/(maturity*lam)
    face = q['face_total']/maturity
    ell = c.exp(-lam*maturity)
    Phi = lambda v: c.erfc(-v/c.sqrt(2))/2

    def forcing(y):
        F = Phi(-y/t-a*t)+c.exp(-2*a*y)*Phi(-y/t+a*t)
        G = (c.exp((-a+zh)*y)*Phi(-y/t-zh*t)
             +c.exp((-a-zh)*y)*Phi(-y/t+zh*t))
        debt = c0+ell*(face-c0)*(1-F)+(q['alpha']*b/maturity-c0)*G
        return delta*b*c.exp(y)-(1-q['tax'])*q['coupon_total']+debt-face

    def kernel(u):
        return c.exp(-gamma*u)*c.expm1((eta+gamma)*u)/(D*(eta+gamma))

    return -c.quad(lambda y: kernel(x-y)*forcing(y), [0, x/2, x])


def quantized_state_diagnostic(log_margin: float, p: HXParams, dtype: str) -> dict:
    """Measure actual tensor state reconstruction and enclose lost branch sign."""
    import torch
    if dtype not in ('fp32', 'bf16'):
        raise ValueError('Supported format required')
    td = torch.float32 if dtype == 'fp32' else torch.bfloat16
    boundary = float(high_precision_boundary(p))
    state = boundary*math.exp(log_margin)
    vt, bt = torch.tensor(state, dtype=td), torch.tensor(boundary, dtype=td)
    reconstructed = float(torch.log(vt/bt))
    vq, vlo, vhi = rounding_cell(state, dtype)
    bq, blo, bhi = rounding_cell(boundary, dtype)
    if float(vt) != vq or float(bt) != bq:
        raise ArithmeticError('Actual tensor encoding differs from the direct-RNE contract')
    value_status = ('CONTINUATION_PROVED' if vlo > bhi else
                    'STOPPING_PROVED' if vhi <= blo else
                    'UNRESOLVED_QUANTIZED_STATE')
    xq, xlo, xhi = rounding_cell(log_margin, dtype)
    margin_status = ('CONTINUATION_PROVED' if xlo > 0 else
                     'STOPPING_PROVED' if xhi <= 0 else
                     'UNRESOLVED_QUANTIZED_MARGIN')
    return {
        'dtype': dtype, 'original_log_margin': log_margin,
        'actual_reconstructed_log_margin': reconstructed,
        'encoded_state': vq, 'encoded_boundary': bq,
        'state_cell': [vlo, vhi], 'boundary_cell': [blo, bhi],
        'state_verdict': value_status,
        'encoded_direct_margin': xq, 'margin_cell': [xlo, xhi],
        'direct_margin_verdict': margin_status,
        'state_quantization_certificate_only': True,
        'production_activation': False,
    }


def native_literal_hx(log_margin: float, p: HXParams, dtype: str) -> dict:
    """Execute literal Eq12/A7 using actual CPU tensor arithmetic.

    Stable exp(log_amp+log_ndtr(z)) matches the existing FP64 source where
    the backend implements log_ndtr. Unsupported BF16 special functions
    are reported instead of silently computing them in FP32/FP64.
    """
    import torch
    if dtype not in ('fp32', 'bf16'):
        raise ValueError('Supported format required')
    td = torch.float32 if dtype == 'fp32' else torch.bfloat16
    T = lambda v: torch.tensor(v, dtype=td)
    q = {name: T(value) for name, value in asdict(p).items()}
    record = {
        'input_dtype': dtype, 'arithmetic_dtype': dtype,
        'input_parameters': {name: float(value) for name, value in q.items()},
        'direct_log_margin': float(T(log_margin)),
        'production_activation': False,
    }
    try:
        Phi = torch.special.ndtr
        def ep(log_amp, z):
            return torch.exp(log_amp+torch.special.log_ndtr(z))
        r, delta, sigma = q['r'], q['delta'], q['sigma']
        S = sigma*sigma
        a = (r-delta-S/2)/S
        lam = r+q['xi']*q['k']
        z = torch.sqrt(a*a+2*r/S)
        zh = torch.sqrt(a*a+2*lam/S)
        eta, gamma = z-a, z+a
        maturity = q['maturity']
        t = sigma*torch.sqrt(maturity)
        def laplace(rate, drift):
            if float(rate) == 0:
                u = drift*t
                return t*(u*Phi(u)+torch.exp(-u*u/2)/T(math.sqrt(2*math.pi)))
            return (Phi(drift*t)-ep((rate*rate/2-drift*rate)*t*t,
                                   (drift-rate)*t))/rate
        IF = laplace(eta, -a)+laplace(gamma, a)
        IG = laplace(z-zh, -zh)+laplace(z+zh, zh)
        c0 = q['coupon_total']/(maturity*lam)
        u = q['face_total']/maturity-c0
        ell = torch.exp(-lam*maturity)
        H = (1-q['tax'])*q['coupon_total']-torch.expm1(-lam*maturity)*u
        b = (H/eta+ell*u*IF+c0*IG)/(delta/(eta-1)+q['alpha']/maturity*IG)
        record['boundary'] = float(b) if bool(torch.isfinite(b)) else None
        if not bool(torch.isfinite(b)) or float(b) <= 0:
            record['status'] = 'NONFINITE_OR_NONPOSITIVE_NATIVE_BOUNDARY'
            return record
        x = T(log_margin)
        def K(w, power):
            shift = power-a
            logm = (shift*shift-w*w)*t*t/2
            return ((Phi(w*t)-ep(logm, shift*t))*torch.exp(-power*x)
                    +ep(logm-power*x, (-x+shift*t*t)/t)
                    -ep(-(a+w)*x, (-x+w*t*t)/t))
        def small_k(w):
            shift = -eta-a
            logm = (shift*shift-w*w)*t*t/2
            return (ep(logm+eta*x, (-x+shift*t*t)/t)
                    -ep(-(a+w)*x, (-x+w*t*t)/t))
        def A(y):
            if float(z-y) == 0:
                raise ArithmeticError('Native A7 removable denominator rounded to zero')
            return ((K(y, gamma)+small_k(-y))/(z-y)
                    +(K(-y, gamma)+small_k(y))/(z+y))
        value = (b*torch.exp(x)-delta*b*torch.exp(-gamma*x)/(z*S*(gamma+1))
                 -H/(z*S)*(1/eta-torch.expm1(-gamma*x)/gamma)
                 +(ell*u*A(a)-(q['alpha']*b/maturity-c0)*A(zh))/(z*S))
        record['equity'] = float(value) if bool(torch.isfinite(value)) else None
        record['status'] = 'FINITE_NATIVE_RESULT' if record['equity'] is not None else 'NONFINITE_NATIVE_EQUITY'
    except (RuntimeError, ArithmeticError) as exc:
        record['status'] = 'UNSUPPORTED_OR_REFUSED_NATIVE_PATH'
        record['reason'] = f'{type(exc).__name__}: {exc}'
    return record
