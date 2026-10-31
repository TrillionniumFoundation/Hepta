"""Exact finite-horizon count law for a *restricted* Markov-reset HCSN neuron.

The signed safety margin X>0 evolves as dX=mu dt + sigma dW until it first
hits 0. After each event the cell enters a deterministic refractory interval
rho>=0, and is reset to one of TWO strictly positive log margins (R0,R1).
The first post-event mode has distribution pi. Subsequent modes evolve via
row-stochastic matrix P, independently of all Brownian increments and waiting
times. Mode changes happen only at events, never during waiting or refractory.

Let N(T) be the number of events by T, and S_k=R_{Z1}+...+R_{Zk} with
Z1~pi and transitions P. The strong Markov property gives, for n=k+1,
  P(N(T)>=n) = E_Z[F(T-k*rho, x0+S_k; mu, sigma)].
  E[e^{-lambda*tau_n} 1(tau_n<=T)] =
    e^{-lambda*k*rho} E_Z[G(T-k*rho,x0+S_k;mu,sigma,lambda)].
F,G are affine first-passage CDF / discounted transform from an independent
previously validated module. A two-mode count DP evaluates the mark mixture
in O(K^2) rather than enumerating all 2^K sequences. The resulting count law
is exact under the restricted stationary assumptions, NOT for a fully coupled
HX equity QVI, adaptive thresholds, state-dependent input, or general network.

All *sampled* spike counts remain discontinuous. Only the expected count
statistics admit smooth interior derivatives. Explicit right censoring means
truncation never silently normalizes the distribution or pretends tail=0.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import torch
import torch.nn.functional as F

try:
    from .moving_boundary_first_passage import affine_hitting_torch
except ImportError:
    from moving_boundary_first_passage import affine_hitting_torch


@dataclass(frozen=True)
class MarkovResetLaw:
    exact_count_probabilities: torch.Tensor    # P[N=0],...,P[N=K]
    overflow_probability: torch.Tensor         # P[N>K], NEVER folded into K
    at_least_probabilities: torch.Tensor       # P[N>=1],...,P[N>=K+1]
    discounted_event_reward_lower_bound: torch.Tensor
    expected_count_lower_bound: torch.Tensor
    max_events: int
    scientific_admission: bool = False
    assumptions: str = (
        'two-state event-driven Markov resets independent of Brownian path, '
        'fixed drift/volatility/boundary, deterministic refractory, FP64 CPU'
    )


def markov_reset_count_law(
    x0: torch.Tensor,
    reset_margins: torch.Tensor,
    initial_mode: torch.Tensor,
    transition: torch.Tensor,
    drift: torch.Tensor,
    sigma: torch.Tensor,
    horizon: torch.Tensor,
    discount: torch.Tensor,
    refractory: torch.Tensor,
    *,
    max_events: int = 12,
    maximum_censored_tail: float | None = None,
) -> MarkovResetLaw:
    """Differentiate exact count/discounted-reward *expectations*, not spike paths.

    Inputs are scalar CPU float64 except two-vector reset_margins, initial_mode
    and a 2x2 transition matrix. If F(T-k*rho) has T-k*rho<=0 the hitting
    probability is zero. Gradients at exact T=k*rho are NOT certified.
    Discount derivative at lambda=0 is deliberately rejected, matching the
    predecessor affine first-passage kernel's uncertified zero branch.
    """
    scalars = (x0, drift, sigma, horizon, discount, refractory)
    arrays = ((reset_margins, (2,)), (initial_mode, (2,)),
              (transition, (2, 2)))
    if any(not isinstance(x, torch.Tensor) or x.shape!=torch.Size([]) or
           x.dtype!=torch.float64 or x.device.type!='cpu' for x in scalars):
        raise TypeError('Expected CPU FP64 scalar x0/drift/sigma/horizon/discount/refractory')
    if any(not isinstance(x, torch.Tensor) or tuple(x.shape)!=shape or
           x.dtype!=torch.float64 or x.device.type!='cpu' for x,shape in arrays):
        raise TypeError('Expected CPU FP64 reset_margins[2], initial_mode[2], transition[2,2]')
    if any(not bool(torch.isfinite(x).all()) for x in scalars+(reset_margins,initial_mode,transition)):
        raise ValueError('Nonfinite parameters')
    if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1<=max_events<=128:
        raise ValueError('max_events must be in [1,128]')
    if (not 0.02<=x0.item()<=3.0 or not bool(((reset_margins>=0.05)&(reset_margins<=3.)).all())
        or not -0.5<=drift.item()<=0.5 or not .1<=sigma.item()<=1.
        or not .02<=horizon.item()<=100. or not 0.<=discount.item()<=1.
        or not 0.<=refractory.item()<=25.
        or x0.item()+max_events*float(reset_margins.detach().max())>100):
        raise ValueError('Outside restricted Markov-renewal research domain')
    if bool(((initial_mode<0)|(initial_mode>1)).any()) or bool(((transition<0)|(transition>1)).any()):
        raise ValueError('Invalid initial/transition probabilities')
    if abs(float(initial_mode.detach().sum())-1)>1e-12 or bool(((transition.sum(-1)-1).abs()>1e-12).any()):
        raise ValueError('Markov reset distribution is not normalized')
    if discount.item()==0 and discount.requires_grad:
        raise ValueError('Uncertified discount derivative at lambda=0')
    if maximum_censored_tail is not None and (
        isinstance(maximum_censored_tail,bool) or
        not isinstance(maximum_censored_tail,(float,int)) or
        not math.isfinite(maximum_censored_tail) or
        not 0<=maximum_censored_tail<1
    ):
        raise ValueError('Invalid maximum_censored_tail')

    atleast=[]
    discounted=[]
    dp=None  # mass for number of R1 resets j, current mode z in {0,1}
    for k in range(max_events+1):
        # k post-spike resets have occurred before the (k+1)th event.
        if k==0:
            distances=x0.reshape(1)
            weights=torch.ones_like(distances)
        else:
            if k==1:
                dp=torch.diag(initial_mode)
            else:
                # Last mode evolves under P; next margin is determined by new mode.
                p0=dp@transition[:,0]
                p1=dp@transition[:,1]
                dp=torch.stack((F.pad(p0,(0,1)), F.pad(p1,(1,0))),dim=-1)
            j=torch.arange(k+1,dtype=torch.float64)
            distances=x0+(k-j)*reset_margins[0]+j*reset_margins[1]
            weights=dp.sum(-1)
        # A fixed dead-time after EACH of k preceding events. No events
        # can fire when the remaining exposure time is exhausted.
        remaining=horizon-k*refractory
        if float(remaining.detach())<=0:
            cdf=torch.zeros((),dtype=torch.float64)
            reward=torch.zeros((),dtype=torch.float64)
        else:
            h=affine_hitting_torch(
                distances,remaining,drift,sigma,torch.zeros_like(drift),discount)
            cdf=(weights*h.probability).sum()
            reward=torch.exp(-discount*k*refractory)*(weights*h.discounted_probability).sum()
        atleast.append(cdf)
        discounted.append(reward)

    a=torch.stack(atleast)
    probs=torch.cat((1-a[:1],a[:-1]-a[1:]))
    overflow=a[-1]
    expected=a[:-1].sum()
    reward=torch.stack(discounted[:-1]).sum()
    with torch.no_grad():
        if (not bool(torch.isfinite(a).all()) or not bool(torch.isfinite(reward))
            or bool(((a[1:]-a[:-1])>5e-12).any())
            or bool((probs< -5e-12).any()) or bool(overflow< -5e-12)
            or abs(float((probs.sum()+overflow).detach())-1)>1e-11
            or bool(reward>expected+1e-11)):
            raise ArithmeticError('Nonmonotone or invalid Markov renewal count law')
        if maximum_censored_tail is not None and float(overflow.detach())>maximum_censored_tail:
            raise ArithmeticError('Unresolved probability mass outside event-count budget')
    return MarkovResetLaw(probs,overflow,a,reward,expected,max_events)
