"""Research-only third autonomous first-passage event with causal time-adaptive resets.

For time-of-event conditioned, independently resampled reset modes, the third
first-passage event has an exact *two-dimensional density integral* conditioned
on first and second event times. It has no elementary closed form in general.
This module approximates that integral with strictly bounded and independently
refined FP64 CPU quadrature. It does NOT train a recurrent neural memory and
is NOT a general endogenous financial QVI or sampled-spike differentiator.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
import numpy as np
import torch
try:
    from .adaptive_second_hit import adaptive_second_hit_law
    from .moving_boundary_first_passage import affine_hitting_torch
except ImportError:
    from adaptive_second_hit import adaptive_second_hit_law
    from moving_boundary_first_passage import affine_hitting_torch


@dataclass(frozen=True)
class ThirdHitLaw:
    first_probability: torch.Tensor
    second_probability: torch.Tensor
    third_probability: torch.Tensor
    discounted_third: torch.Tensor
    third_count_lower_bound: torch.Tensor
    numerical_refinement: float
    scientific_admission: bool = False
    derivative_scope: str = 'continuous expected event probabilities, fixed model topology; not sampled event gradients'


def adaptive_third_hit_law(x0,drift,sigma,horizon,discount,reset_base,
                           reset_amplitudes,mode_bias,mode_slope,refractory_base,
                           refractory_slope,*,coarse_order=56,fine_order=112,
                           tolerance=2e-6)->ThirdHitLaw:
    # Reuse the independently tested parameter and physical-domain checks.
    two=adaptive_second_hit_law(x0,drift,sigma,horizon,discount,
            reset_base,reset_amplitudes,mode_bias,mode_slope,
            refractory_base,refractory_slope)
    if (isinstance(coarse_order,bool) or isinstance(fine_order,bool)
        or not isinstance(coarse_order,int) or not isinstance(fine_order,int)
        or not 16<=coarse_order<fine_order<=256
        or not math.isfinite(tolerance) or not 0<tolerance<=1e-3):
        raise ValueError('Invalid bounded third-hit quadrature configuration')
    def integral(order):
        nodes,weights=np.polynomial.legendre.leggauss(order)
        uu=(torch.from_numpy(nodes)+1)*.5
        ff=torch.sin(math.pi*uu/2).square()
        jac=torch.from_numpy(weights)*math.pi/4*torch.sin(math.pi*uu)
        cap1=(horizon-refractory_base)/(1+refractory_base*refractory_slope/horizon)
        cap2=(cap1-refractory_base)/(1+refractory_base*refractory_slope/horizon)
        if float(cap2.detach())<=0:
            return x0*0.,x0*0.
        s=cap2*ff
        ws=cap2*jac
        fs=s/horizon
        rho_s=refractory_base*(1+refractory_slope*fs)
        pr_s=torch.sigmoid(mode_bias+mode_slope*(fs-.5))
        mode_s=torch.stack((1-pr_s,pr_s),dim=-1)
        r_s=reset_base[None,:]*(1+reset_amplitudes[None,:]*torch.sin(2*math.pi*fs[:,None]))
        log_f0=(torch.log(x0)-torch.log(sigma)-.5*math.log(2*math.pi)
                -1.5*torch.log(s)-(x0+drift*s).square()/(2*sigma.square()*s))
        f0=torch.exp(log_f0)
        # Second hit u is s + rho(s) + d, d>0, and u must allow one more
        # reset and hit. Trig map resolves the singularity at d=0 and its
        # vanishing time-to-third-event endpoint with smooth integrands.
        duration=cap1-s-rho_s
        d=duration[:,None]*ff[None,:]
        wd=duration[:,None]*jac[None,:]
        u=s[:,None]+rho_s[:,None]+d
        frac_u=u/horizon
        rho_u=refractory_base*(1+refractory_slope*frac_u)
        r_u=reset_base[None,None,:]*(1+reset_amplitudes[None,None,:]*
                                           torch.sin(2*math.pi*frac_u[:,:,None]))
        p1=torch.sigmoid(mode_bias+mode_slope*(frac_u-.5))
        mode_u=torch.stack((1-p1,p1),dim=-1)
        rem=(horizon-u-rho_u).clamp(min=0.)
        # F(T; R>=0.07) is exponentially negligible for T<1e-9;
        # explicitly use the exact F(0)=G(0)=0 branch of the reference.
        rem=torch.where(rem<1e-9,torch.zeros_like(rem),rem)
        zero=torch.zeros((),dtype=torch.float64)
        third=affine_hitting_torch(r_u,rem[:,:,None],drift,sigma,zero,discount)
        survival=torch.sum(mode_u*third.probability,dim=-1)
        reward=(torch.sum(mode_u*third.discounted_probability,dim=-1)*
                torch.exp(-discount*(u+rho_u)))
        # Marginalize first reset mode over the first-to-second hitting density.
        rr=r_s[:,None,:]
        dd=d[:,:,None]
        log_fd=(torch.log(rr)-torch.log(sigma)-.5*math.log(2*math.pi)
                -1.5*torch.log(dd)-(rr+drift*dd).square()/(2*sigma.square()*dd))
        hit2=torch.sum(mode_s[:,None,:]*torch.exp(log_fd),dim=-1)
        prob=torch.sum(ws*f0*torch.sum(wd*hit2*survival,dim=-1))
        disc=torch.sum(ws*f0*torch.sum(wd*hit2*reward,dim=-1))
        return prob,disc
    a=integral(coarse_order)
    b=integral(fine_order)
    err=max(abs(float((b[j]-a[j]).detach())) for j in (0,1))
    prob,disc=b
    with torch.no_grad():
        if (not bool(torch.isfinite(prob)) or not bool(torch.isfinite(disc))
            or not 0<=float(disc)<=float(prob)+2e-12
            or float(prob)>float(two.probability_second)+2e-12
            or float(disc)>float(two.discounted_second)+2e-12):
            raise ArithmeticError('Unphysical autonomous third-hit law')
        if err>tolerance:
            raise ArithmeticError(f'Unconverged nonstationary third-hit quadrature: {err:.3g}')
    return ThirdHitLaw(two.probability_first,two.probability_second,
                       prob,disc,two.probability_first+two.probability_second+prob,err)
