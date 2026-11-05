"""Reproduce fixed-seed raw P2 first-hit surrogate falsification evidence."""
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
from scipy.stats import norm, poisson

from research.hcsn.p2_first_hit_renewal_falsification import (
    brownian_nth_hit_cdf, calibrated_constant_hazard, poisson_nth_event_cdf,
)
from research.hcsn.test_p2_first_hit_renewal_falsification import (
    DISTANCE,SIGMA,TIMES,SEEDS,independent_density_integral,monte_carlo_prefix_counts,
)
from research.hcsn.p2_physical_hazard_clock import PhysicalHazardClock


def generate():
    horizon=1.
    rate=calibrated_constant_hazard(horizon,DISTANCE,SIGMA)
    rows=[]
    max_quadrature=0.
    for t in TIMES:
        for n in (1,2,3):
            true=brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA)
            quad=independent_density_integral(t,n)
            h=poisson_nth_event_cdf(t,n,rate)
            max_quadrature=max(max_quadrature,abs(true-quad))
            rows.append({'horizon_s':t,'nth_event':n,
                'brownian_exact_cdf':true,'brownian_independent_density_quadrature':quad,
                'constant_hazard_cdf':h,'constant_hazard_minus_brownian':h-true})
    per_seed=[]
    for seed in SEEDS:
        samples=monte_carlo_prefix_counts(seed)
        for t in TIMES:
            for n in (1,2,3):
                p=brownian_nth_hit_cdf(t,n,DISTANCE,SIGMA)
                est=float(np.mean(samples[:,n-1]<=t))
                se=math.sqrt(p*(1-p)/len(samples))
                per_seed.append({'seed':seed,'t_s':t,'nth_event':n,'draws':len(samples),
                   'empirical_cdf':est,'expected_cdf':p,'binomial_se':se,
                   'standardized_diff':(est-p)/se if se else None})
    count=0
    actual_hist={}
    for seed in range(1000):
        obj=PhysicalHazardClock(seed=seed)
        obj.advance(0.,16.,rate)
        events=len(obj.events)
        actual_hist[str(events)]=actual_hist.get(str(events),0)+1
        count+=(events>=3)
    files=[Path(__file__),Path(__file__).with_name('p2_first_hit_renewal_falsification.py'),
           Path(__file__).with_name('test_p2_first_hit_renewal_falsification.py'),
           Path(__file__).with_name('p2_physical_hazard_clock.py')]
    return {'schema':'hcsn.p2-levy-vs-hazard-iteration31.v1',
     'scope':'Negative control: independent reset zero-drift Brownian first-hit renewal vs ZOH constant hazard; NOT general dynamic barrier, trainable HCSN, HX/A7/QVI or production proof.',
     'source_sha256':{str(p.relative_to(Path(__file__).resolve().parents[2])):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
     'run':{'python':sys.version.split()[0],'platform':platform.platform(),
            'numpy':np.__version__,'scipy':scipy.__version__},
     'design':{'distance':DISTANCE,'sigma':SIGMA,'horizon_matched_s':horizon,
               'constant_intensity_per_s':rate,'times_s':list(TIMES),
               'event_indices':[1,2,3],'mc_seeds':list(SEEDS),'paths_per_seed':40000,
               'heldout_clock_seeds':1000,'zero_refractory':True,'floating_point':'FP64'},
     'math':{'first_hit_cycle':'T=(a/sigma)^2/Z^2; Z~N(0,1)',
             'nth_event':'P(S_n<=t)=erfc(n*a/(sigma*sqrt(2t)))',
             'calibration':'lambda=-ln(1-F_first(1s))/1s',
             'constant_hazard':'P(N(t)>=n)=scipy.special.gammainc(n,lambda*t)'},
     'cdf_comparison':rows,'max_abs_independent_quadrature_diff':max_quadrature,
     'per_seed_brownian_inverse_normal':per_seed,
     'actual_pr512_physical_hazard_clock':{'samples':1000,'horizon_s':16.,'nth_event':3,
        'empirical_p_ge_n':count/1000.,'poisson_reference':poisson.sf(2,rate*16.),
        'brownian_reference':brownian_nth_hit_cdf(16.,3,DISTANCE,SIGMA),
        'histogram':actual_hist},
     'preserve_existing_negatives':True,'matched_flops':False,
     'trained_boundaries':False,'original_hx_full_domain':False,
     'independent_external_attestation':False,
     'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
     'production_activation':False}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error('refusing to overwrite evidence')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(generate(),indent=2,sort_keys=True)+'\n',encoding='utf-8')

if __name__=='__main__':main()
