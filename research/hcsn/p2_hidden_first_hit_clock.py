"""Research-only P2: retrospective first-hit *time* posterior in a sampled gap.

Given two strictly positive signed margins x0, xT observed T seconds apart,
assume X_t = x0 + mu*t + sigma*W_t with constant mu, sigma > 0 and a
DETERMINISTIC AFFINE lower boundary on that gap. The margin relative to the
boundary is a Brownian motion with constant drift. Conditional on both margin
endpoints, its Brownian-bridge law is drift-independent.

This module computes the exact probability that the FIRST crossing occurred
before u, conditional on both endpoints, and its quantiles conditional on a
crossing. It is a *RETROSPECTIVE* law: xT is unavailable until the end of the
gap. It does NOT return the realized crossing time or an online event/spike.
No autoregenerative reset, non-affine/adaptive intra-gap barrier, repeated hit,
HX equity/QVI, or production qualification is implied. P0-P6 remain OPEN.
"""
from __future__ import annotations

import math
from scipy.optimize import brentq
from scipy.special import ndtr, log_ndtr


def _parameters(x0: float, xT: float, horizon: float, sigma: float) -> tuple[float, float, float, float, float]:
    values = (x0, xT, horizon, sigma)
    if any(type(v) not in (float, int) or not math.isfinite(v) for v in values):
        raise ValueError('finite scalar physical inputs required; booleans rejected')
    a, b, t, s = map(float, values)
    if not (0. < a <= 20. and 0. < b <= 20. and .01 <= t <= 64. and .05 <= s <= 4.):
        raise ValueError('outside bounded positive-margin Brownian-bridge research domain')
    k = 2.*a*b/(s*s*t)
    if k > 690.:
        raise ValueError('rare-hit conditional clock below verified numerical range')
    return a, b, t, s, k


def first_crossing_probability(x0: float, xT: float, horizon: float, sigma: float) -> float:
    """Probability of >=1 continuous first crossing given safe endpoints."""
    _, _, _, _, k = _parameters(x0, xT, horizon, sigma)
    return math.exp(-k)


def first_hit_time_posterior(x0: float, xT: float, horizon: float, sigma: float, elapsed: float) -> dict:
    """First-hit posterior, conditioned on *both* safe endpoints.

    Returns P(tau <= elapsed | both endpoints), and P(tau <= elapsed | both
    endpoints, at least one hit). The latter is a time-of-FIRST-hit CDF only
    among paths that hit. Not a real-time event prediction before horizon.

    Reflection/Markov bridge decomposition for alpha=u/T:
       P(tau<=u|end) = Phi(-m/su) + exp(-k)*Phi(n/su),
       m=(1-alpha)*x0+alpha*xT,
       n=-(1-alpha)*x0+alpha*xT,
       su=sigma*sqrt(T*alpha*(1-alpha)), k=2*x0*xT/(sigma^2*T).
    """
    a, b, T, s, k = _parameters(x0, xT, horizon, sigma)
    if type(elapsed) not in (float, int) or not math.isfinite(elapsed) or not 0. <= elapsed <= T:
        raise ValueError('elapsed time must be in the observed interval')
    u = float(elapsed)
    total = math.exp(-k)
    if u == 0.:
        fractional = 0.
    elif u == T:
        fractional = 1.
    else:
        alpha = u/T
        std = s*math.sqrt(T*alpha*(1.-alpha))
        mean = (1.-alpha)*a + alpha*b
        signed = -(1.-alpha)*a + alpha*b
        # Work in log space for the small Gaussian tail divided by hit mass.
        first = math.exp(float(log_ndtr(-mean/std)) + k)
        second = float(ndtr(signed/std))
        fractional = first+second
        if not -1e-12 <= fractional <= 1.+1e-12:
            raise ArithmeticError('posterior normalization failed')
        fractional = min(1., max(0., fractional))
    return {
        'crossing_probability': total,
        'joint_probability_first_hit_by_elapsed': total*fractional,
        'first_hit_time_cdf_given_crossing': fractional,
        'retrospective_requires_future_endpoint': True,
        'realized_event_time_known': False,
        'scientific_gate': 'OPEN',
        'production_activation': False,
    }


def first_hit_time_quantile(x0: float, xT: float, horizon: float, sigma: float, quantile: float) -> float:
    """Retrospective time quantile, *conditional on a hidden crossing*.

    Does not claim to locate an actual spike. Returns seconds since earlier
    observation; downstream use as a deterministic reset time is unjustified.
    """
    a, b, T, s, _ = _parameters(x0, xT, horizon, sigma)
    if type(quantile) not in (float, int) or not math.isfinite(quantile) or not 0. <= quantile <= 1.:
        raise ValueError('quantile outside [0,1]')
    q = float(quantile)
    if q == 0.: return 0.
    if q == 1.: return T
    return float(brentq(lambda u: first_hit_time_posterior(a, b, T, s, u)['first_hit_time_cdf_given_crossing']-q,
                        0., T, xtol=1e-13, rtol=9e-15))
