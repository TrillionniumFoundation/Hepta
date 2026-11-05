"""Finite research audit separating fixed policy evaluation from optimal QVI.

The references below recompute first-passage probabilities at MP80, integrate
the first-hit density, and optimize a renewal value over supplied thresholds.
They do not import the production gamma or root into those references. None
of these finite experiments certifies original HX, arbitrary reset maps,
low-precision neural training, or the HCSN P0-P5 scientific gates.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess

import mpmath as mp
import numpy as np
import scipy
from scipy.integrate import quad
from scipy.optimize import minimize_scalar

try:
    from .regenerative_qvi import (
        RegenerativeParams, first_passage_cdf, fixed_policy_value,
        regenerative_residuals, regenerative_value, reset_boundary,
    )
    from .qvi_fd_reference import solve_qvi_fd
except ImportError:
    from regenerative_qvi import (
        RegenerativeParams, first_passage_cdf, fixed_policy_value,
        regenerative_residuals, regenerative_value, reset_boundary,
    )
    from qvi_fd_reference import solve_qvi_fd


def mp_characteristic(p: RegenerativeParams):
    """Recompute the GBM root from exact input float values at MP80."""
    ctx=mp.mp.clone()
    ctx.dps=80
    r,d,s=(ctx.mpf(z) for z in (p.r,p.delta,p.sigma))
    mu=r-d-s*s/2
    gamma=(ctx.sqrt(mu*mu+2*r*s*s)+mu)/(s*s)
    return ctx,r,mu,s,gamma


def mp_first_passage(x: float,t: float,p: RegenerativeParams) -> float:
    ctx,_,mu,s,_=mp_characteristic(p)
    xx,tt=ctx.mpf(x),ctx.mpf(t)
    if xx==0:return 1.
    if tt==0:return 0.
    Phi=lambda z:ctx.erfc(-z/ctx.sqrt(2))/2
    scale=s*ctx.sqrt(tt)
    value=(Phi((-xx-mu*tt)/scale)
           +ctx.exp(-2*mu*xx/(s*s))*Phi((-xx+mu*tt)/scale))
    return float(value)


def density_integral(x: float,t: float,p: RegenerativeParams) -> tuple[float,float]:
    """Independent time integration of the first-passage density on (0,t)."""
    if not (x>0 and t>0):
        raise ValueError('Positive distance/horizon required for density reference')
    mu=p.r-p.delta-.5*p.sigma*p.sigma
    def density(u):
        if u==0:return 0.
        z=(x+mu*u)/(p.sigma*math.sqrt(u))
        return (x/(p.sigma*math.sqrt(2*math.pi)*u**1.5)
                *math.exp(-.5*z*z))
    # Split near the drift-only arrival to avoid missing a narrow low-sigma
    # density peak. Both subintervals remain inside the original horizon.
    point=x/abs(mu) if mu else None
    points=[point] if point is not None and 0<point<t else None
    value,error=quad(density,0.,t,points=points,epsabs=2e-13,
                     epsrel=2e-13,limit=500)
    return float(value),float(error)


def mp_boundary(p: RegenerativeParams) -> float:
    """MP80 bisection of smooth fit, with no float root or root hints."""
    ctx,_,_,_,g=mp_characteristic(p)
    R,c=ctx.mpf(p.reset_value),ctx.mpf(p.reset_cost)
    lo,hi=ctx.mpf(0),R-c
    for _ in range(240):
        mid=(lo+hi)/2
        residual=g*(R-mid-c)-mid*(1-ctx.power(mid/R,g))
        if residual>0:lo=mid
        else:hi=mid
    return float((lo+hi)/2)


def density_discounted_hit(x: float,p: RegenerativeParams) -> tuple[float,float]:
    """Integrate e^(-r*t) times the first-hit density, over log time.

    The truncation is finite [-28,28] in log time and explicitly reported;
    it is used only for the moderate parameters in this audit, not as an
    all-domain enclosure. It neither calls gamma nor the CDF implementation.
    """
    mu=p.r-p.delta-.5*p.sigma*p.sigma
    def integrand(log_t):
        t=math.exp(log_t)
        z=(x+mu*t)/(p.sigma*math.sqrt(t))
        exponent=math.log(x/p.sigma)-.5*math.log(2*math.pi*t)
        exponent-=.5*z*z+p.r*t
        return math.exp(exponent)
    value,error=quad(integrand,-28.,28.,epsabs=2e-13,epsrel=2e-13,limit=500)
    return float(value),float(error)


def density_fixed_policy(v: float,b: float,p: RegenerativeParams) -> float:
    """Renewal reference with both discounted hitting factors integrated."""
    hR,_=density_discounted_hit(math.log(p.reset_value/b),p)
    bonus=(p.reset_value-b-p.reset_cost)/(1-hR)
    if v<=b:return b-p.k+bonus
    hv,_=density_discounted_hit(math.log(v/b),p)
    return v-p.k+hv*bonus


def cdf_cases():
    configurations=(
        ('baseline',RegenerativeParams()),
        ('low_sigma_downward',RegenerativeParams(r=.001,delta=.2,sigma=.01)),
        ('positive_drift',RegenerativeParams(r=.08,delta=.015,sigma=.2)),
        ('zero_drift',RegenerativeParams(r=.125,delta=.09375,sigma=.25)),
        ('broad_diffusion',RegenerativeParams(r=.02,delta=.16,sigma=.8)),
    )
    for name,p in configurations:
        for x in (.001,.2,1.,3.):
            for t in (.01,.1,1.,10.,1000.):
                yield name,p,x,t


def boundary_cases():
    return (
        ('baseline',RegenerativeParams()),
        ('low_sigma_downward',RegenerativeParams(r=.001,delta=.2,sigma=.01)),
        ('low_sigma_upward',RegenerativeParams(r=.3,delta=.001,sigma=.01,
                                               reset_value=30.,reset_cost=.1)),
        ('near_zero_cost',RegenerativeParams(reset_cost=2e-20)),
        ('near_maximum_cost',RegenerativeParams(reset_value=.01,
                                               reset_cost=.0099999999999999)),
        ('cost_midpoint',RegenerativeParams(reset_cost=1.)),
    )


def run_audit():
    cdf=[]
    for name,p,x,t in cdf_cases():
        value=first_passage_cdf(x,t,p)
        reference=mp_first_passage(x,t,p)
        cdf.append({'configuration':name,'log_distance':x,'horizon':t,
                    'value':value,'mp80_reference':reference,
                    'absolute_error':abs(value-reference)})
    low=RegenerativeParams(r=.001,delta=.2,sigma=.01)
    integral,quad_error=density_integral(.2,1.,low)
    cdf_regression={'parameters':asdict(low),'log_distance':.2,'horizon':1.,
        'value':first_passage_cdf(.2,1.,low),'independent_density_integral':integral,
        'quadrature_estimated_error':quad_error,
        'original_failure':'OverflowError: math range error at exp(796.2)',
        'original_source_sha':'406fb358a15850af2d8063e98d900ff275fe121b'}

    boundaries=[]
    for name,p in boundary_cases():
        b=reset_boundary(p)
        reference=mp_boundary(p)
        boundaries.append({'configuration':name,'parameters':asdict(p),
                            'boundary':b,'mp80_reference':reference,
                            'relative_error':abs(b-reference)/reference})

    p=RegenerativeParams()
    fixed=[]
    for b in (.4,.9,1.6):
        for v in (b/2,b,1.8,2.,4.):
            value=fixed_policy_value(v,b,p)
            reference=density_fixed_policy(v,b,p)
            fixed.append({'threshold':b,'state':v,'value':value,
                          'independent_density_renewal':reference,
                          'absolute_error':abs(value-reference)})

    optimal=[]
    for name,p in (
        ('baseline',RegenerativeParams()),
        ('downward',RegenerativeParams(r=.03,delta=.06,sigma=.35)),
        ('costly_reset',RegenerativeParams(reset_value=1.3,reset_cost=.8)),
    ):
        result=minimize_scalar(lambda b:-density_fixed_policy(p.reset_value,b,p),
             bounds=(.02*p.reset_value,.98*p.reset_value),method='bounded',
             options={'xatol':1e-9})
        b=reset_boundary(p)
        rows=[]
        for state in (b*.2,b,b*1.1,p.reset_value,4*p.reset_value):
            optimum=regenerative_value(state,p)
            for supplied in np.linspace(.03,.97,49)*p.reset_value:
                policy=fixed_policy_value(state,float(supplied),p)
                rows.append(optimum-policy)
        c,g,_=regenerative_residuals(.5*b,p)
        optimal.append({'configuration':name,'analytic_optimal_boundary':b,
            'density_renewal_optimizer_boundary':float(result.x),
            'optimizer_success':bool(result.success),
            'boundary_relative_error':abs(float(result.x)-b)/b,
            'min_value_advantage_over_245_state_policy_pairs':float(min(rows)),
            'reset_region_continuation_branch':c,'reset_region_impulse_branch':g})

    p=RegenerativeParams()
    fd=[]
    for h,steps in ((.04,140),(.02,280),(.01,560)):
        grid=solve_qvi_fd(p,h=h,left_steps=steps,right_steps=steps)
        error=abs(grid.u[grid.reset_index]-regenerative_value(p.reset_value,p))
        fd.append({'h':h,'left_steps':steps,'right_steps':steps,
                   'reset_value_absolute_error':float(error),
                   'estimated_boundary':grid.estimated_boundary,
                   'complementarity_residual':grid.max_complementarity_residual,
                   'finite_log_domain':[-h*steps,h*steps]})

    here=Path(__file__).resolve().parent
    names=('regenerative_qvi.py','qvi_fd_reference.py',
           'p0_regenerative_policy_audit.py','test_regenerative_policy_audit.py')
    sources={name:hashlib.sha256((here/name).read_bytes()).hexdigest() for name in names}
    root=here.parent.parent
    return {'schema':'hcsn.p0.fixed-policy-vs-qvi.audit.v1',
        'source_head_before_publication':subprocess.check_output(
            ['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'source_sha256':sources,
        'runtime':{'python':platform.python_version(),'numpy':np.__version__,
                   'scipy':scipy.__version__,'mpmath':mp.__version__},
        'cdf_regression':cdf_regression,'cdf_mp80_cases':cdf,
        'boundary_mp80_cases':boundaries,'fixed_policy_density_cases':fixed,
        'fixed_policy_threshold_optimization':optimal,'independent_qvi_fd':fd,
        'maximum_cdf_absolute_error':max(row['absolute_error'] for row in cdf),
        'maximum_boundary_relative_error':max(row['relative_error'] for row in boundaries),
        'maximum_fixed_policy_absolute_error':max(row['absolute_error'] for row in fixed),
        'scientific_gates_closed':False,'original_hx_qvi_certified':False,
        'production_activation':False,
        'limitations':[
            'Finite FP64 reference with MP80 and numerical integration controls; no directed error intervals.',
            'Fixed policy and fixed-R/c optimal intervention are separate from original HX and contextual reset models.',
            'Discounted-hit quadrature uses finite log-time interval [-28,28] for the stated moderate cases only.',
            'Tiny costs whose trigger cannot be distinguished from R in binary64 are refused.',
            'Independent QVI FD uses a finite asymptotic upper boundary, not a global continuous-domain certificate.',
            'No new P1 mechanism, P2 learned memory, P3 real multimodal, P4 energy, or P5 scale evidence.',
        ]}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing overwrite')
    report=run_audit()
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({key:report[key] for key in (
        'maximum_cdf_absolute_error','maximum_boundary_relative_error',
        'maximum_fixed_policy_absolute_error','scientific_gates_closed')},indent=2))
