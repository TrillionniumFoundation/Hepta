"""Exact finite-horizon multi-reset spike-count law for an HCSN *submodel*.

Consider the signed log safety margin X(t)>0. Between autonomous spikes:

    dX(t) = mu dt + sigma dW(t),  sigma>0.

At the FIRST X(t)<=0 event, the process instantaneously resets to a fixed
positive margin R and continues with the *same* mu and sigma, with fresh Brownian
increments. There are no externally supplied spikes or discretized time ticks.

Strong Markov + spatial homogeneity imply for integer n>=1:
    P[N(T)>=n] = P[tau(x0+(n-1)*R)<=T].
More generally, the nth spike time has the same distribution as the first
hitting time of a Brownian motion at distance x0+(n-1)*R. Discounted expected
spike rewards are sums of the individual discounted first-hit transforms.

This exact renewal law applies ONLY to a stationary, affine-log, constant drift
and volatility *regenerative* neuron with cost-free instantaneous resets; not
an endogenous He--Xiong financial boundary, stochastic reset policies, coupled
cells or general nonstationary QVI. Changing the reset law destroys the exact
closed form. All derivatives are interior fixed-branch derivatives; spike-count
sample paths remain discontinuous. The return includes an explicit censored
upper-tail probability so it is impossible to silently claim that computing the
first max_events terms captures the complete event count distribution.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import torch

try:
    from .moving_boundary_first_passage import affine_hitting_torch
except ImportError:
    from moving_boundary_first_passage import affine_hitting_torch


@dataclass(frozen=True)
class RenewalCountLaw:
    """P[N=k] for k=0..max_events, P[N>max_events], and event statistics."""

    exact_count_probabilities: torch.Tensor
    overflow_probability: torch.Tensor
    at_least_probabilities: torch.Tensor
    discounted_event_reward_lower_bound: torch.Tensor
    expected_count_lower_bound: torch.Tensor
    max_events: int
    assumptions: str = (
        "constant scalar GBM log-margin drift/volatility, same reset margin after "
        "every autonomous event, instantaneous resets, no interactions"
    )
    scientific_admission: bool = False


def renewal_count_law(
    x0: torch.Tensor,
    reset_margin: torch.Tensor,
    drift: torch.Tensor,
    sigma: torch.Tensor,
    horizon: torch.Tensor,
    discount: torch.Tensor,
    *,
    max_events: int = 12,
    maximum_censored_tail: float | None = None,
) -> RenewalCountLaw:
    """Differentiable vector of exact count probabilities with right censoring.

    `at_least_probabilities` has length max_events+1: entries n=1..K+1.
    `exact_count_probabilities` has length K+1: count n=0..K.
    The tail P[count>K] is a separate scalar; it is *not* rolled into K.
    Expected event count and discounted event reward are lower bounds obtained
    by summing the first K exact P[tau_n<=T] and
    E[exp(-discount*tau_n)1(tau_n<=T)], respectively. For discount=0,
    the reward value equals expected_count_lower_bound, but d/d-discount at
    zero is not certified by the underlying first-hit kernel.

    Set `maximum_censored_tail` to fail closed when requested count coverage
    cannot be achieved. All tensors must be CPU float64 scalars; no GPU/bf16
    certification is implied by passing this check.
    """
    args=(x0,reset_margin,drift,sigma,horizon,discount)
    if any(not isinstance(a,torch.Tensor) or a.ndim!=0 or a.dtype!=torch.float64
           or a.device.type!='cpu' for a in args):
        raise TypeError('Expected CPU FP64 torch scalar tensors')
    if any(not bool(torch.isfinite(a)) for a in args):
        raise ValueError('Nonfinite parameter')
    if isinstance(max_events,bool) or not isinstance(max_events,int) or not 1<=max_events<=256:
        raise ValueError('max_events must be an integer in [1,256]')
    if (not 0.02<=x0.item()<=3.0 or not 0.05<=reset_margin.item()<=3.
        or not -.5<=drift.item()<=.5 or not .1<=sigma.item()<=1.
        or not .02<=horizon.item()<=100. or not 0.<=discount.item()<=1.
        or x0.item()+max_events*reset_margin.item()>100.):
        raise ValueError('Outside bounded stationary-renewal research domain')
    # A zero-discount reward has a valid *value*, but the first-hit kernel
    # intentionally uses G(0)=F; its lambda-gradient at exactly zero would be
    # spuriously zero. Refuse that differentiable case rather than silently
    # train a wrong discount sensitivity.
    if discount.item()==0 and discount.requires_grad:
        raise ValueError('Non-certified discount gradient at zero; use positive discount')
    if maximum_censored_tail is not None and (
        isinstance(maximum_censored_tail,bool)
        or not isinstance(maximum_censored_tail,(int,float))
        or not math.isfinite(maximum_censored_tail)
        or not 0<=maximum_censored_tail<1
    ):
        raise ValueError('Invalid maximum_censored_tail')

    distances=x0+torch.arange(max_events+1,dtype=torch.float64)*reset_margin
    hit=affine_hitting_torch(distances,horizon,drift,sigma,
                             torch.zeros_like(drift),discount)
    cdf=hit.probability
    probs=torch.cat((1-cdf[:1],cdf[:-1]-cdf[1:]))
    overflow=cdf[-1]
    reward=hit.discounted_probability[:-1].sum()
    expected=cdf[:-1].sum()
    # No unconditional clamp: probability monotonicity and nonnegativity are
    # mathematical invariants. Reject violations outside strict FP64 rounding.
    with torch.no_grad():
        if (not bool(torch.isfinite(probs).all()) or not bool(torch.isfinite(reward))
            or bool((cdf[1:]-cdf[:-1]>5.e-13).any())
            or bool((probs< -5.e-13).any()) or bool(overflow<0.)
            or abs(float(probs.sum()+overflow)-1.)>5e-12
            or bool(reward>expected+5.e-12)):
            raise ArithmeticError('Invalid renewal event-count probabilities')
        if maximum_censored_tail is not None and float(overflow)>maximum_censored_tail:
            raise ArithmeticError('Unresolved event-count tail exceeds requested budget')
    return RenewalCountLaw(probs,overflow,cdf,reward,expected,max_events)
