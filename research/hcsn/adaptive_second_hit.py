"""HCSN P2: conditional second-event law with time-dependent causal reset.

Given signed log margin X_t=x0+mu*t+sigma*W_t, the first hit of zero
at s autonomously triggers a refractory interval rho(s), a Bernoulli
mode Z with P(Z=1 | s)=sigmoid(bias+slope*(s/T-1/2)), and reset to the
strictly positive margin R_Z(s)=base_Z*(1+amp_Z*sin(2*pi*s/T)). Subsequent
motion restarts with independent Brownian increments and *the same* mu,sigma.

By the strong Markov property (conditioning on first hit time and reset mode):
 Pr(tau_2<=T) = integral_0^T f_1(s) sum_z p_z(s)
                         F(T-s-rho(s); R_z(s),mu,sigma) ds,
 E[e^-lambda*tau_2 1(tau_2<=T)] = integral_0^T f_1(s) exp(-lambda*(s+rho(s)))
                         sum_z p_z(s) G(T-s-rho(s);R_z(s),mu,sigma,lambda) ds.
Here F,G are single-hit analytic transforms; the *new* outer integral
is evaluated with differentiable Gauss-Legendre quadrature and a fail-closed
refinement check. This deliberately does NOT claim a closed form for general
input-dependent resetting or a third spike. A reset schedule may depend
on time elapsed since trial start, but it may not depend on future Brownian
increments; event-time-conditioned schedules are causal.

All outputs are conditional EXPECTATIONS, not differentiable sampled spike
paths. No claim of original He-Xiong A7/QVI correctness, trained recurrent
memory, certified GPU power, FP32/BF16, or production readiness is made.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
import numpy as np
import torch

try:
    from .moving_boundary_first_passage import affine_hitting_torch
except ImportError:
    from moving_boundary_first_passage import affine_hitting_torch


@dataclass(frozen=True)
class SecondHitLaw:
    probability_first: torch.Tensor
    probability_second: torch.Tensor
    probability_zero: torch.Tensor
    probability_exactly_one: torch.Tensor
    probability_two_or_more: torch.Tensor
    discounted_first: torch.Tensor
    discounted_second: torch.Tensor
    quadrature_max_refinement: float
    coarse_order: int
    fine_order: int
    scientific_admission: bool = False
    derivative_scope: str = (
        'interior FP64 expected first/second counts and discounted rewards; '
        'NOT sampled event counts/times, no stochastic differentiated reset path'
    )


def adaptive_second_hit_law(
    x0: torch.Tensor, drift: torch.Tensor, sigma: torch.Tensor,
    horizon: torch.Tensor, discount: torch.Tensor,
    reset_base: torch.Tensor, reset_amplitudes: torch.Tensor,
    mode_bias: torch.Tensor, mode_slope: torch.Tensor,
    refractory_base: torch.Tensor, refractory_slope: torch.Tensor,
    *, coarse_order: int = 96, fine_order: int = 192,
    tolerance: float = 3e-7,
) -> SecondHitLaw:
    """Differentiable first/second crossing statistics for a bounded model.

    Reset amplitude is an *external deterministic causal function of event
    time*. The model intentionally forbids state-time joint adaptivity
    and arbitrary future-input dependence. All inputs CPU float64 tensors.
    """
    scalars = (x0,drift,sigma,horizon,discount,mode_bias,mode_slope,
               refractory_base,refractory_slope)
    vectors = (reset_base,reset_amplitudes)
    if any(not isinstance(q,torch.Tensor) or q.device.type!='cpu' or
           q.dtype!=torch.float64 or q.ndim!=0 for q in scalars):
        raise TypeError('Expected CPU FP64 scalar parameters')
    if any(not isinstance(q,torch.Tensor) or q.device.type!='cpu' or
           q.dtype!=torch.float64 or tuple(q.shape)!=(2,) for q in vectors):
        raise TypeError('Expected CPU FP64 reset vectors of length 2')
    if any(not bool(torch.isfinite(q).all()) for q in scalars+vectors):
        raise ValueError('Nonfinite input')
    if (not .15<=float(x0.detach())<=1.75
        or not -.4<=float(drift.detach())<=.4
        or not .2<=float(sigma.detach())<=1.
        or not 1.<=float(horizon.detach())<=8.
        or not 0<=float(discount.detach())<=1.2
        or not bool(((reset_base>=.12)&(reset_base<=2.5)).all())
        or not bool((reset_amplitudes.detach().abs()<=.4).all())
        or not -6<=float(mode_bias.detach())<=6
        or not -6<=float(mode_slope.detach())<=6
        or not .02<=float(refractory_base.detach())<=1.2
        or not -.5<=float(refractory_slope.detach())<=.5):
        raise ValueError('Outside bounded causal reset model domain')
    if discount.detach().item()==0 and discount.requires_grad:
        raise ValueError('Uncertified derivative through discount=0 branch')
    if (isinstance(coarse_order,bool) or isinstance(fine_order,bool)
        or not isinstance(coarse_order,int) or not isinstance(fine_order,int)
        or not 24<=coarse_order<fine_order<=512
        or not math.isfinite(tolerance) or not 0<tolerance<=.003):
        raise ValueError('Invalid quadrature/refinement budget')

    zero=torch.zeros((),dtype=torch.float64)
    first=affine_hitting_torch(x0,horizon,drift,sigma,zero,discount)

    def integral(order:int):
        nodes, weights=np.polynomial.legendre.leggauss(order)
        # Avoid t=0, where f_1 has an integrable inverse-Gaussian structure.
        # Conditioning on a first-event time is feasible for the next hit
        # only while t + rho(t) < T. Since rho(t) is affine, its exact
        # positive upper support is known and differentiable in parameters.
        cap=(horizon-refractory_base)/(1+refractory_base*refractory_slope/horizon)
        if float(cap.detach())<=0:
            inactive=x0*0.
            return inactive,inactive
        # Sin^2 change of variables clusters nodes at BOTH the fast initial
        # hitting-time density and the final feasible reset-time boundary.
        u=(torch.from_numpy(nodes)+1)*.5
        t=cap*torch.sin((math.pi/2)*u).square()
        w=torch.from_numpy(weights)*cap*(math.pi/4)*torch.sin(math.pi*u)
        frac=t/horizon
        remarg=reset_base[None,:]*(1+reset_amplitudes[None,:]*torch.sin(2*math.pi*frac[:,None]))
        probability_one=torch.sigmoid(mode_bias+mode_slope*(frac-.5))
        p=torch.stack((1-probability_one,probability_one),-1)
        rho=refractory_base*(1+refractory_slope*frac)
        remain=(horizon-t-rho).clamp(min=0.)
        # Independent killed-diffusion flux at 0: density of FIRST hit at t.
        logpdf=(torch.log(x0)-torch.log(sigma)-.5*math.log(2*math.pi)
                -1.5*torch.log(t)-(x0+drift*t).square()/(2*sigma.square()*t))
        f1=torch.exp(logpdf)
        h=affine_hitting_torch(remarg,remain[:,None],drift,sigma,zero,discount)
        q2=torch.sum(w*f1*torch.sum(p*h.probability,dim=-1))
        g2=torch.sum(w*f1*torch.exp(-discount*(t+rho))*
                     torch.sum(p*h.discounted_probability,dim=-1))
        return q2,g2

    c=integral(coarse_order)
    f=integral(fine_order)
    err=max(abs(float((f[i]-c[i]).detach())) for i in (0,1))
    p1=first.probability
    p2,g2=f
    g1=first.discounted_probability
    with torch.no_grad():
        vals=[p1,p2,g1,g2]
        if (not all(bool(torch.isfinite(q)) for q in vals)
            or not 0<=float(p2)<=float(p1)+2e-12<=1+2e-12
            or not 0<=float(g2)<=float(p2)+2e-12
            or not 0<=float(g1)<=float(p1)+2e-12
            or float(g2)>float(g1)+2e-12):
            raise ArithmeticError('Unphysical adaptive second-hit law')
        if err>tolerance:
            raise ArithmeticError(f'Adaptive renewal quadrature unresolved: {err:.3g}>{tolerance:.3g}')
    return SecondHitLaw(p1,p2,1-p1,p1-p2,p2,g1,g2,err,coarse_order,fine_order)
