"""Research-only negative control: constant Poisson event rate vs genuine Brownian first hits.

Zero-drift Brownian diffusion with volatility sigma, reset exactly a below a
constant barrier after each true hit. The strong Markov property makes each
cycle's hitting time an independent Levy(0,(a/sigma)**2) random variable.

The n-th hit time is Levy-stable: P(S_n <= t) = erfc(n*a/(sigma*sqrt(2*t))).
By contrast a constant held hazard clock has P(N(t)>=n)=Poisson.sf(n-1,lambda*t).
Choosing lambda to match exactly the first-hit CDF at one horizon is not a
matched continuous-time path law; it can still fail at other times and counts.

Not original He-Xiong Eq8/11/12/A7 or a learned boundary; NO release gate closes.
"""
from __future__ import annotations

import math


def brownian_nth_hit_cdf(t: float, n: int, distance: float, sigma: float) -> float:
    if not all(math.isfinite(v) for v in (t, distance, sigma)):
        raise ValueError('nonfinite Brownian input')
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise ValueError('n must be positive integer')
    if t < 0 or distance <= 0 or sigma <= 0:
        raise ValueError('invalid hitting time parameter')
    if t == 0:
        return 0.0
    return math.erfc((n*distance/sigma)/math.sqrt(2.0*t))


def calibrated_constant_hazard(horizon: float, distance: float, sigma: float) -> float:
    p = brownian_nth_hit_cdf(horizon, 1, distance, sigma)
    if not (0.0 < p < 1.0):
        raise ValueError('first-hit calibration not numerically identifiable')
    return -math.log1p(-p)/horizon


def poisson_nth_event_cdf(t: float, n: int, rate: float) -> float:
    if not all(math.isfinite(v) for v in (t,rate)) or t < 0 or rate < 0:
        raise ValueError('invalid rate or time')
    if not isinstance(n,int) or isinstance(n,bool) or n < 1:
        raise ValueError('n must be positive integer')
    # For n>=1 this is the Gamma/Erlang event-time CDF via the Poisson tail.
    mean = rate*t
    if not math.isfinite(mean):
        raise ValueError('overflowed expected count')
    return -math.expm1(-mean)*1.0 if n == 1 else _erlang_tail(n, mean)


def _erlang_tail(n: int, mean: float) -> float:
    # Use scipy's independently vetted regularized incomplete gamma routine.
    from scipy.special import gammainc
    return float(gammainc(n, mean))
