"""Whole-state original-HX obstacle certificates beyond recovery monotonicity.

For the exact Eq12 root, let q(x) be Eq11 cashflow with x=log(V/b).
The sufficient condition here is q(0)<0 and, at every x>=0,

    q(x)<0 OR q'(x)>0.

Together with q(x)->infinity this gives a single negative-to-positive zero.
Eq12 makes the full eta-discounted cashflow integral zero, so its partial
integrals are strictly negative and the exact equity is positive everywhere
above b.  This is the same FIXED-DEBT-PRICE stopping problem, including the
absorbing-recovery extension below b, as hx_interval_domain.py.  It is not a
proof of equilibrium uniqueness under repricing or a regenerative QVI.

Finite intervals use outward interval arithmetic; a Gaussian/Mills bound
covers the entire infinite tail.  No sampled points are accepted as a cover.
The mpmath interval trust boundary is inherited unchanged.  Failed sufficient
conditions and budget exhaustion return unresolved, never a false rejection
of the underlying financial model.  No science/production gate is changed.
"""
from __future__ import annotations

import math

try:
    from .hx_original import HXParams
    from .hx_interval_domain import (
        _boundary_work, _export, _finite_scalar, _forcing_derivatives,
    )
except ImportError:
    from hx_original import HXParams
    from hx_interval_domain import (
        _boundary_work, _export, _finite_scalar, _forcing_derivatives,
    )


def _cashflow_at_zero(q, h):
    return ((q['delta']+q['alpha']/q['maturity'])*h['b']
            -(1-q['tax'])*q['coupon_total']-q['face_total']/q['maturity'])


def _tail_work(e, q, h, start):
    """A uniform lower bound on q'(x) for EVERY x>=start.

    Write t=sigma*sqrt(m), a=nu/sigma^2, zhat=sqrt(a^2+2*lambda/sigma^2).
    For X>zhat*t^2, all relevant normal-tail arguments are negative.  Put
    H=phi(X/t+a*t).  H decreases for x>=X.  Mills' upper bound gives

      |F'| <= H*(2/t+2*abs(a)/(X/t-a*t)),
      |G'| <= H*exp(-lambda*m)*(2/t
                    +abs(zhat-a)/(X/t+zhat*t)
                    +abs(zhat+a)/(X/t-zhat*t)).

    Each denominator increases with x.  The affine reward derivative
    delta*b*exp(x) increases.  Thus evaluating these bounds at X bounds the
    entire tail, including each tuple in an input parameter box.
    """
    c = e.c
    X = c.mpf(start)
    a, z, t = h['a'], h['zh'], h['t']
    dm, dp, df = X/t-z*t, X/t+z*t, X/t-a*t
    ga = X/t+a*t
    if min(dm.a, dp.a, df.a, ga.a) <= 0:
        return None
    gaussian = c.exp(-ga*ga/2)/e.normalizer
    ell = c.exp(-h['lam']*q['maturity'])
    F = gaussian*(2/t+2*abs(a)/df)
    G = gaussian*ell*(2/t+abs(z-a)/dp+abs(z+a)/dm)
    coupon = q['coupon_total']/(q['maturity']*h['lam'])
    face = q['face_total']/q['maturity']
    recovery = q['alpha']*h['b']/q['maturity']
    debt_derivative = ell*abs(face-coupon)*F+abs(recovery-coupon)*G
    growth = q['delta']*h['b']*c.exp(X)
    return {
        'start': start,
        'qprime_uniform_lower_bound': _export(growth-debt_derivative)['lower'],
        'affine_derivative_at_start': _export(growth),
        'absolute_debt_derivative_uniform_bound': _export(debt_derivative)['upper'],
        'absolute_F_derivative_uniform_bound': _export(F)['upper'],
        'absolute_G_derivative_uniform_bound': _export(G)['upper'],
        'minimum_positive_tail_argument': min(
            _export(dm)['lower'], _export(dp)['lower'],
            _export(df)['lower'], _export(ga)['lower']),
        'covers_all_x_at_or_above_start': True,
        'method': 'normal Mills upper bound and monotonic Gaussian/denominators',
    }


def cashflow_tail_enclosure(p: HXParams, start: float, *,
                            dtype: str | None = None, digits=100) -> dict:
    """Expose the analytic infinite-tail bound for independent checking.

    A negative lower bound is only inconclusive.  Start must be finite and
    at most 64; invalid Mills denominators are explicitly refused.
    """
    start = _finite_scalar(start)
    if not 0 < start <= 64:
        raise ValueError('Tail start must be in (0,64]')
    domain, e, q, h = _boundary_work(p, dtype=dtype, digits=digits)
    if h['b'].a <= 0:
        raise ArithmeticError('Positive exact Eq12 root unresolved')
    result = _tail_work(e, q, h, start)
    if result is None:
        raise ArithmeticError('Mills-tail sign assumptions are not established')
    return {'domain': domain, 'tail': result, 'production_activation': False}


def global_obstacle_enclosure(p: HXParams, *, dtype: str | None = None,
                              digits=100, max_cells=4096,
                              max_depth=30, max_tail=64.) -> dict:
    """Certify a global original-HX obstacle subset by sign or slope.

    Every successful cell is a closed interval; the final sorted cover is
    checked to start at zero, have no gaps, and end at the certified tail.
    The returned bounds concern the original Eq12 root, NOT a rounded root.
    With dtype, the full legal-original-input quantization preimage is used.
    """
    if type(max_cells) is not int or not 1 <= max_cells <= 16384:
        raise ValueError('max_cells must be an integer in [1,16384]')
    if type(max_depth) is not int or not 0 <= max_depth <= 40:
        raise ValueError('max_depth must be an integer in [0,40]')
    max_tail = _finite_scalar(max_tail)
    if not 1 <= max_tail <= 64:
        raise ValueError('max_tail must be in [1,64]')
    domain, e, q, h = _boundary_work(p, dtype=dtype, digits=digits)
    c = e.c
    result = {
        'status': 'UNRESOLVED',
        'base_domain': domain,
        'theorem': 'exact Eq12; q(0)<0; every x>=0 has q(x)<0 or qprime(x)>0',
        'analytic_scope': domain['analytic_scope'],
        'arithmetic_trust_base': domain['arithmetic_trust_base'],
        'complete_continuous_cover': False,
        'cells': [],
        'tail': None,
        'evaluated_cells': 0,
        'budgets': {'max_cells': max_cells, 'max_depth': max_depth, 'max_tail': max_tail},
        'equilibrium_uniqueness_proved': False,
        'general_hx_parameter_domain_closed': False,
        'production_activation': False,
    }
    if h['b'].b <= 0:
        result['status'] = 'NO_POSITIVE_EQ12_CANDIDATE'
        return result
    if h['b'].a <= 0:
        result['status'] = 'UNRESOLVED_POSITIVE_CANDIDATE'
        return result
    q0 = _cashflow_at_zero(q, h)
    if q0.a > 0:
        result['status'] = 'REFUTED_LOCAL_OBSTACLE'
        return result
    if _export(q0)['upper'] >= 0:
        result['status'] = 'UNRESOLVED_LOCAL_SIGN'
        return result

    # A dyadic integer start lies above the upper endpoint for all parameters.
    required = _export(h['zh']*h['t']*h['t'])['upper']
    start = float(max(1, math.floor(required)+1))
    tail_attempts = []
    while start <= max_tail:
        tail = _tail_work(e, q, h, start)
        if tail is not None:
            tail_attempts.append(tail)
            if tail['qprime_uniform_lower_bound'] > 0:
                result['tail'] = tail
                break
        start *= 2
    result['tail_attempts'] = tail_attempts
    if result['tail'] is None:
        result['status'] = 'UNRESOLVED_TAIL_BUDGET'
        return result

    # Parameter boxes and x ranges are propagated together.  Mean-value
    # inclusion substantially tightens the value enclosure near q(0)=0.
    pending = [(0., start, 0)]
    cells = []
    while pending:
        if result['evaluated_cells'] >= max_cells:
            result['status'] = 'UNRESOLVED_CELL_BUDGET'
            result['remaining_intervals'] = [[lo, hi] for lo, hi, _ in pending]
            break
        lo, hi, depth = pending.pop()
        result['evaluated_cells'] += 1
        x = c.mpf([lo, hi])
        slope = _forcing_derivatives(e, q, h, x, 1)
        exported_slope = _export(slope)
        if exported_slope['lower'] > 0:
            cells.append({'lower': lo, 'upper': hi, 'kind': 'POSITIVE_SLOPE',
                          'enclosure': exported_slope})
            continue
        # For each parameter tuple: q(x)=q(lo)+integral_lo^x q'(s) ds.
        at_lo = q0 if lo == 0 else _forcing_derivatives(e, q, h, c.mpf(lo), 0)
        width = c.mpf(hi)-c.mpf(lo)
        forcing = at_lo+c.mpf([c.mpf(0), width.b])*slope
        exported_forcing = _export(forcing)
        if exported_forcing['upper'] < 0:
            cells.append({'lower': lo, 'upper': hi, 'kind': 'NEGATIVE_CASHFLOW',
                          'enclosure': exported_forcing})
            continue
        midpoint = lo+(hi-lo)/2
        if depth >= max_depth or not lo < midpoint < hi:
            result['status'] = 'UNRESOLVED_CELL_DEPTH'
            result['unresolved_cell'] = {
                'lower': lo, 'upper': hi, 'qprime': exported_slope,
                'cashflow_mean_value_enclosure': exported_forcing,
            }
            break
        pending.extend([(midpoint, hi, depth+1), (lo, midpoint, depth+1)])
    else:
        cells.sort(key=lambda row: row['lower'])
        if (not cells or cells[0]['lower'] != 0.
                or cells[-1]['upper'] != start
                or any(left['upper'] != right['lower']
                       for left, right in zip(cells, cells[1:]))):
            raise ArithmeticError('Internal continuous-cover gap')
        result['complete_continuous_cover'] = True
        result['status'] = 'CERTIFIED_SINGLE_CROSSING_FIXED_DEBT_OBSTACLE'
    result['cells'] = sorted(cells, key=lambda row: row['lower'])
    result['certified_cell_count'] = len(cells)
    return result
