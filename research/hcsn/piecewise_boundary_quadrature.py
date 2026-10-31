"""Research-only differentiable, deterministic piecewise moving-barrier integrator.

For X(t)=x0+integral(drift-slope(t)) dt+sigma W(t), kill at X<=0.
On each interval, the killed transition density is the unrestricted Gaussian
transition times [1-exp(-2*x*y/(sigma**2*dt))]. Gauss--Legendre quadrature
composes the kernels over positive endpoint states. Discounted hitting values
are accumulated at the true FIRST hit, not the terminal endpoint.

Each segment kernel is analytically exact for constant sigma/drift/affine log
boundary. Spatial quadrature is approximate and certified ONLY by numerical
refinement, independent MC and an unrestricted Gaussian upper-tail bound;
there is no PDE/QVI global guarantee. This is not original HX Eq.(A7).
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
class QuadratureHitting:
    probability: torch.Tensor
    discounted_probability: torch.Tensor
    probability_mass_error: float
    refinement_error: float
    total_upper_tail_bound: float
    grid_order: int
    derivative_scope: str = 'fixed segment topology; differentiable interior of bounded FP64 domain'


def piecewise_hitting_quadrature(
    x0: torch.Tensor, drift: torch.Tensor, sigma: torch.Tensor,
    slopes: torch.Tensor, durations: torch.Tensor, discount: torch.Tensor,
    *, x_max: float = 6., coarse_order: int = 96,
    fine_order: int = 160, tolerance: float = 1.e-5,
) -> QuadratureHitting:
    """Piecewise moving boundary F(T), discounted G(T), torch FP64 CPU.

    Raises on invalid parameters, truncation risk >1e-10, quadrature non-
    convergence, or negative probability. No silent numerical fallback.
    The user-provided x_max is held FIXED for autograd and finite differences.
    Do not use gradients at zero x0, zero durations, or changed segment counts.
    """
    args=(x0,drift,sigma,slopes,durations,discount)
    if any(not isinstance(z,torch.Tensor) or z.dtype!=torch.float64 or z.device.type!='cpu' for z in args):
        raise TypeError('FP64 CPU tensors only; no certified GPU or quantized operation')
    if any(z.ndim!=0 for z in (x0,drift,sigma,discount)) or slopes.ndim!=1 or durations.ndim!=1 or slopes.shape!=durations.shape:
        raise ValueError('Expected scalar state/drift/volatility/discount and matching 1D segments')
    if any(not bool(torch.isfinite(z).all()) for z in args):
        raise ValueError('Nonfinite input')
    n=len(slopes)
    if (n<1 or n>8 or not .02 <= x0.item() <= 3.
        or not .10<=sigma.item()<=.8 or abs(drift.item())>.5
        or bool((slopes.abs()>.6).any()) or bool((durations<.08).any())
        or bool((durations>5.).any()) or not 0.<=discount.item()<=.6
        or not math.isfinite(x_max) or not x0.item()<x_max<=15.
        or not 24<=coarse_order<fine_order<=384 or not 0<tolerance<=.005):
        raise ValueError('Outside bounded deterministic research domain')
    # A killed path is a subset of the free Gaussian path at each checkpoint.
    # The sum of the Gaussian tail probabilities bounds probability mass lost
    # when discarding x>x_max at intermediate quadrature checkpoints.
    cumulative_t=0.
    cumulative_mu=0.
    tail_bound=0.
    for j in range(n):
        dt=float(durations[j].detach()); mu=float((drift-slopes[j]).detach())
        cumulative_t+=dt; cumulative_mu+=mu*dt
        z=(x_max-float(x0.detach())-cumulative_mu)/(float(sigma.detach())*math.sqrt(cumulative_t))
        tail_bound+=.5*math.erfc(z/math.sqrt(2.))
    if tail_bound>1e-10:
        raise ValueError('Truncation bound too large; increase fixed x_max')

    def one_order(order:int):
        glx,glw=np.polynomial.legendre.leggauss(order)
        nodes=torch.from_numpy((glx+1.)*(x_max/2.))
        weights=torch.from_numpy(glw*(x_max/2.))
        masses=torch.ones(1,dtype=torch.float64)
        positions=x0.reshape(1)
        f_total=x0*0.
        g_total=x0*0.
        elapsed=x0*0.
        for j in range(n):
            dt=durations[j]
            mu=drift-slopes[j]
            fg=affine_hitting_torch(positions,dt,drift,sigma,slopes[j],discount)
            f_total=f_total+torch.sum(masses*fg.probability)
            g_total=g_total+torch.exp(-discount*elapsed)*torch.sum(masses*fg.discounted_probability)
            var=sigma*sigma*dt
            x=positions.reshape(-1,1)
            y=nodes.reshape(1,-1)
            gauss=torch.exp(-.5*(y-x-mu*dt)**2/var)/torch.sqrt(2*math.pi*var)
            bridge=-torch.expm1(-2*x*y/var)
            transition=gauss*bridge
            masses=torch.sum(masses.reshape(-1,1)*transition,dim=0)*weights
            positions=nodes
            elapsed=elapsed+dt
        remainder=torch.sum(masses)
        return f_total,g_total,remainder

    coarse=one_order(coarse_order)
    fine=one_order(fine_order)
    with torch.no_grad():
        errors=[float(torch.abs(a-b)) for a,b in zip(coarse,fine)]
        refine=max(errors)
        mass_err=float(torch.abs(fine[0]+fine[2]-1.))
        f=float(fine[0]);g=float(fine[1])
        if not all(math.isfinite(v) for v in (refine,mass_err,f,g)):
            raise ArithmeticError('Nonfinite numerical result')
        if refine>tolerance or mass_err>tolerance:
            raise ArithmeticError(f'Unconverged quadrature: refinement={refine:.3g}, mass={mass_err:.3g}')
        if not -1e-12<=g<=f+1e-12<=1+1e-12:
            raise ArithmeticError('Hitting probability violates physical bounds')
    return QuadratureHitting(fine[0],fine[1],mass_err,refine,tail_bound,fine_order)
