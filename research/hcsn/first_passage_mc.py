"""Independent Monte Carlo reference for original He--Xiong bond Eq.(8).

Uses the inverse-Gaussian first-passage *sampling distribution* of a drifted
Brownian motion, not Eq.(8)'s closed-form normal-CDF expression, and pays
coupons/recovery/principal directly along each simulated exact first-passage
path. A finite, fixed-seed stochastic sanity check, NOT an analytic proof.

State x=log(V/V_B)>0; log drift mu = r-delta-sigma**2/2; barrier zero.
For mu<0 the hit-time T follows IG(mean=x/(-mu), shape=x**2/sigma**2).
For mu>0 hit probability exp(-2 mu x/sigma**2), conditional hit-time
IG(mean=x/mu, shape=x**2/sigma**2). For mu==0, T=(x/(sigma*Z))**2.
The exact stochastic sampling distribution eliminates path time discretization,
but the Monte Carlo standard error is strictly positive.

Caveat: Equations are independent in numerical implementation, although all
represent the same assumed GBM financial model; this is not independent data.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np
try:
    from .hx_original import HXParams, hitting_and_discounted_hitting, bond_price_from_log
except ImportError:
    from hx_original import HXParams, hitting_and_discounted_hitting, bond_price_from_log


@dataclass(frozen=True)
class MonteCarloStatistic:
    estimated: float
    standard_error: float
    analytic: float
    absolute_error: float
    signed_z_score: float


def _statistic(samples: np.ndarray, reference: float) -> MonteCarloStatistic:
    if len(samples) < 2 or not np.all(np.isfinite(samples)):
        raise ValueError('Nonfinite or insufficient Monte Carlo payoff sample')
    mean = float(np.mean(samples))
    se = float(np.std(samples, ddof=1) / math.sqrt(len(samples)))
    # Zero-variance deterministic payoffs must match exactly (up to fp noise).
    z = (mean-reference) / se if se > 1e-14 else (0. if abs(mean-reference)<1e-12 else math.inf)
    return MonteCarloStatistic(mean,se,reference,abs(mean-reference),z)


def draw_first_passage_times(x: float, p: HXParams, rng: np.random.Generator,
                             sample_size: int) -> np.ndarray:
    """Generate exact first-passage times, using +inf for never-hitting paths.

    Here "exact" refers to the law sampled by the PRNG; random variation is
    present and the law assumes constant drift/volatility and fixed boundary.
    """
    if (not isinstance(p,HXParams) or not isinstance(rng,np.random.Generator)
        or not math.isfinite(x) or x <= 0 or x > 12
        or isinstance(sample_size,bool) or not isinstance(sample_size,int)
        or sample_size < 2 or sample_size > 1_000_000):
        raise ValueError('Invalid fixed-barrier MC reference input')
    mu = p.r-p.delta-.5*p.sigma*p.sigma
    shape = (x/p.sigma)**2
    if abs(mu) <= 1e-12:
        z = rng.standard_normal(sample_size)
        return np.divide(shape,z*z,out=np.full(sample_size,math.inf),where=z!=0)
    times = rng.wald(x/abs(mu),shape,size=sample_size)
    if mu > 0:
        eventual_hit_probability = math.exp(-2*mu*x/(p.sigma*p.sigma))
        hit = rng.random(sample_size) < eventual_hit_probability
        times[~hit] = np.inf
    return times


def sample_bond_reference(x: float, tau: float, boundary: float, p: HXParams,
                          *, seed: int, sample_size: int = 100_000) -> dict:
    """Estimate hitting F/G and bond value using direct stopped cash flows.

    Estimator uses no closed-form F/G formula internally. The latter are used
    only in separately recorded references. No normal approximation is claimed
    at distribution degeneracies; the stderr is descriptive, not a CI proof.
    """
    if (not isinstance(seed,int) or isinstance(seed,bool) or not 0<=seed<2**63
        or not math.isfinite(tau) or not 0<=tau<=p.maturity
        or not math.isfinite(boundary) or boundary<=0):
        raise ValueError('Invalid sampled instrument or deterministic seed')
    rng=np.random.default_rng(seed)
    times=draw_first_passage_times(x,p,rng,sample_size)
    hits=times<=tau
    effective=np.minimum(times,tau)
    discount=np.exp(-p.lam*effective)
    # Each bond receives coupons to default/maturity and then exactly one
    # termination payoff (recover collateral upon default or principal at tau).
    coupon=p.c/p.lam*(1-discount)
    payoffs=coupon + np.where(hits,
                             p.alpha*boundary/p.maturity*discount,
                             p.p*math.exp(-p.lam*tau))
    f,g=hitting_and_discounted_hitting(x,tau,p)
    stats={
        'first_passage_probability':_statistic(hits.astype(np.float64),f),
        'discounted_first_passage':_statistic(np.where(hits,np.exp(-p.lam*times),0.),g),
        'stopped_bond_payoff':_statistic(payoffs,bond_price_from_log(x,tau,boundary,p)),
    }
    return {'schema':'hcsn.original-hx-first-passage-mc.v1',
            'sample_size':sample_size,'seed':seed,'x':x,'tau':tau,
            'drift':p.r-p.delta-.5*p.sigma*p.sigma,
            'eventual_hit_probability':1. if p.r-p.delta-.5*p.sigma*p.sigma<=0 else math.exp(-2*(p.r-p.delta-.5*p.sigma*p.sigma)*x/p.sigma**2),
            'statistics':stats,
            'status':'stochastic-finite-sample-check-not-scientific-gate-closure'}
