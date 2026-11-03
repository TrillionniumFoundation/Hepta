"""Reproducible fixed-seed independent checks for P2 defective first-hit clock.

Writes unrounded raw JSON, including every seed/time/count comparison. No gate
closure; this is a mathematical restricted-submodel counterexample only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import platform
import sys
from pathlib import Path

import numpy as np
import scipy

from research.hcsn.p2_defective_first_hit_clock import (
    nth_hit_cdf, eventual_hit_probability, DefectiveFirstHitClock,
)
from research.hcsn.test_p2_defective_first_hit_clock import (
    A, SIGMA, DRIFTS, TIMES, SEEDS, reflection_cdf, density_integral,
    independent_waits,
)

HORIZONS=(0.25,0.5,1.0,4.0,16.0)
REFRACTORY=0.1
DRAWS=40000


def calculate()->dict:
    grid=[]
    worst_quad=0.
    worst_reflection=0.
    for drift in DRIFTS:
        for n in (1,2,3):
            for t in TIMES:
                effective=t-(n-1)*REFRACTORY
                exact=nth_hit_cdf(t,n,A,drift,SIGMA,REFRACTORY)
                reflection=reflection_cdf(effective,n*A,drift,SIGMA) if effective>0 else 0.
                quadrature=density_integral(effective,n*A,drift,SIGMA) if effective>0 else 0.
                worst_quad=max(worst_quad,abs(exact-quadrature))
                worst_reflection=max(worst_reflection,abs(exact-reflection))
                grid.append({'mu':drift,'n':n,'t_s':t,'refractory_s':REFRACTORY,
                    'cdf_candidate':exact,'cdf_reflection_independent':reflection,
                    'cdf_density_quadrature_independent':quadrature})
    samples=[]
    worst_mc=0.
    for seed in SEEDS:
        rng=np.random.default_rng(seed)
        for drift in (-0.12,0.,0.12):
            for n in (1,2,3):
                waits=independent_waits(rng,drift,n,draws=DRAWS,refractory=REFRACTORY)
                for t in (1.,4.,16.):
                    exact=nth_hit_cdf(t,n,A,drift,SIGMA,REFRACTORY)
                    empirical=float(np.mean(waits<=t))
                    se=math.sqrt(exact*(1-exact)/DRAWS)
                    z=(empirical-exact)/se if se else None
                    if z is not None:worst_mc=max(worst_mc,abs(z))
                    samples.append({'seed':seed,'mu':drift,'rank':n,'t_s':t,'draws':DRAWS,
                        'monte_carlo':empirical,'exact':exact,'binomial_se':se,'z':z})
    lifetime=[]
    for drift in (-0.4,-0.12):
        q=eventual_hit_probability(A,drift,SIGMA)
        for n in (1,2,3):
            lifetime.append({'mu':drift,'n':n,'ever_nth_hit_probability':q**n,
                'never_nth_hit_probability':1-q**n})
    refinements=[]
    for drift in DRIFTS:
        for seed in SEEDS:
            coarse=DefectiveFirstHitClock(seed=seed,drift=drift,refractory=REFRACTORY)
            fine=DefectiveFirstHitClock(seed=seed,drift=drift,refractory=REFRACTORY)
            coarse.advance(0.,16.)
            for i in range(64):fine.advance(i*.25,(i+1)*.25)
            refinements.append({'mu':drift,'seed':seed,'coarse_event_times_s':coarse.events,
               'fine_event_times_s':fine.events,'pathwise_equal':coarse.events==fine.events})
    names=['p2_defective_first_hit_clock.py','test_p2_defective_first_hit_clock.py',
           'p2_defective_first_hit_evidence.py']
    local=Path(__file__).resolve().parent
    return {'schema':'hcsn.p2-defective-firsthit-iteration32.v1',
        'state':{'P'+str(i):'OPEN' for i in range(7)},
        'production_activation':False,'full_closure':False,
        'restricted_scope':'IID fixed-distance, fixed-drift Brownian first hit + fixed physical refractory, not original He–Xiong/QVI or trainable input-driven boundary',
        'source_sha256':{f'research/hcsn/{name}':hashlib.sha256((local/name).read_bytes()).hexdigest() for name in names},
        'environment':{'python':sys.version.split()[0],'numpy':np.__version__,'scipy':scipy.__version__,'platform':platform.platform()},
        'design':{'a':A,'sigma':SIGMA,'drifts':DRIFTS,'times':TIMES,'seeds':SEEDS,
                  'rank':(1,2,3),'refractory_s':REFRACTORY,'mc_draws_per_seed_combo':DRAWS},
        'theory':{'ever_hit':'q=exp(2*mu*a/sigma**2) for mu<0 else 1',
            'nth_reset_with_refractory':'P(N(t)>=n)=F_{n*a}(t-(n-1)*refractory)',
            'random_clock':'E~Exp(1); u=1-exp(-E); if u>=q then tau=infinity; otherwise tau=F^{-1}(u)',
            'conditional_wait':'for nonzero mu, tau conditional on finite hit is IG(mean=a/abs(mu),shape=a*a/sigma**2)',
            'scope_warning':'Probability-law equivalence does not imply realized Brownian pathwise first-hit time recovery.'},
        'comparison_grid':grid,
        'independent_monte_carlo':samples,'lifetime':lifetime,
        'refinement_cases':refinements,
        'summary':{'max_abs_quadrature_diff':worst_quad,
                   'max_abs_reflection_diff':worst_reflection,
                   'max_abs_mc_z':worst_mc,
                   'refinement_cases_all_equal':all(r['pathwise_equal'] for r in refinements),
                   'never_first_hit_minus_0p12':1-eventual_hit_probability(A,-0.12,SIGMA)}}


def main()->None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    result=calculate()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')
    print(json.dumps(result['summary'],indent=2))


if __name__=='__main__':
    main()
