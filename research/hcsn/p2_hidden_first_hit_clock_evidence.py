"""Deterministic P2 retrospective hidden-hit clock audit; never scientific acceptance."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform

import numpy as np
import scipy
from scipy.integrate import quad

from .p2_hidden_first_hit_clock import first_hit_time_posterior,first_hit_time_quantile

SEED=20261101


def reference_density_integral(a,b,T,sigma,u):
    """Independent stopped-path density times endpoint Gaussian transition."""
    def density(t):
        if t<=0 or t>=T:return 0.
        logv=(math.log(a)+.5*math.log(T)-math.log(sigma)-.5*math.log(2*math.pi)
              -1.5*math.log(t)-.5*math.log(T-t)-a*a/(2*sigma*sigma*t)
              -b*b/(2*sigma*sigma*(T-t))+(b-a)**2/(2*sigma*sigma*T))
        return math.exp(logv)
    return float(quad(density,0.,u,epsabs=1e-12,epsrel=1e-12,limit=450)[0])


def generate():
    panels=[(.4,.4,1.,.4),(.28,.65,1.3,.6),(.7,.26,2.,.9),(.3,.7,.5,.8)]
    rows=[]
    for a,b,T,sigma in panels:
        for fraction in (.2,.48,.75):
            u=T*fraction
            target=first_hit_time_posterior(a,b,T,sigma,u)
            independent=reference_density_integral(a,b,T,sigma,u)
            rows.append({'a':a,'b':b,'T':T,'sigma':sigma,'elapsed':u,
                         'analytic_joint':target['joint_probability_first_hit_by_elapsed'],
                         'independent_density_integral':independent,
                         'absolute_error':abs(independent-target['joint_probability_first_hit_by_elapsed'])})
    a,b,T,s,u=.4,.55,1.2,.52,.57
    n=180000
    rng=np.random.default_rng(SEED)
    alpha=u/T
    y=(1-alpha)*a+alpha*b+s*math.sqrt(u*(1-alpha))*rng.standard_normal(n)
    crossing=(y<=0)|(rng.random(n)<np.exp(-2*a*np.maximum(y,0)/(s*s*u)))
    count=int(crossing.sum())
    observed=count/n
    expected=first_hit_time_posterior(a,b,T,s,u)['joint_probability_first_hit_by_elapsed']
    se=math.sqrt(expected*(1-expected)/n)
    witness=first_hit_time_posterior(.4,.4,1.,.4,.5)
    quantiles={str(q):first_hit_time_quantile(.4,.4,1.,.4,q) for q in (.1,.5,.9)}
    root=Path(__file__).resolve().parent
    source_hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest()
                   for name in ('p2_hidden_first_hit_clock.py','test_p2_hidden_first_hit_clock.py','p2_hidden_first_hit_clock_evidence.py')}
    report={
        'scope':'P2 bounded retrospective Brownian-bridge first-hit timing only',
        'source_parent_pr':512,'source_parent_exact_head':'4de1b4eed9d400c80bee40a57ccce3fd59106cd9',
        'model_assumptions':['positive sampled margins','constant diffusion per interval',
                             'constant relative drift','deterministic affine intra-gap barrier',
                             'no reset inside observation gap'],
        'not_proved':['actual hidden event timestamp','online event causality','learned nonlinear boundary',
                      'multiple autonomous resets','first-hit event gradient','P0 original HX global QVI',
                      'P1 positive independent gain','real pretrained multimodal','GPU energy','P6 scaling'],
        'clock_witness':{'x0':.4,'xT':.4,'horizon_seconds':1.,'sigma_per_sqrt_second':.4,
                         'deadline_seconds':.5,**witness,
                         'first_hit_quantiles_seconds_given_crossing':quantiles},
        'independent_density_quadratures':rows,
        'max_absolute_density_error':max(x['absolute_error'] for x in rows),
        'independent_gaussian_bridge_mc':{'seed':SEED,'paths':n,'hits_before_u':count,'u':u,
                                          'empirical':observed,'analytic':expected,
                                          'standard_error':se,'abs_z':abs(observed-expected)/se},
        'source_sha256':source_hashes,
        'environment':{'python':platform.python_version(),'numpy':np.__version__,'scipy':scipy.__version__,
                       'device':'CPU','git_full_checkout':False},
        'gates':{f'P{i}':'OPEN' for i in range(7)},
        'production_activation':False,
        'independent_external_attestation':False,
    }
    if report['max_absolute_density_error']>5e-10 or report['independent_gaussian_bridge_mc']['abs_z']>5:
        raise AssertionError('exploratory numeric audit failed: no scientific gate change')
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error('Refusing evidence overwrite')
    result=generate()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps({'rows':len(result['independent_density_quadratures']),
                      'max_error':result['max_absolute_density_error'],
                      'mc_abs_z':result['independent_gaussian_bridge_mc']['abs_z'],
                      'median':result['clock_witness']['first_hit_quantiles_seconds_given_crossing']['0.5'],
                      'gates':'P0-P6 OPEN','production_activation':False}))
if __name__=='__main__':main()
