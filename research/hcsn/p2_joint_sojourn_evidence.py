"""Iteration 34 reproducibility record: Markov joint-sojourn falsification.

The scenario was selected to expose a *structural* error in the factorized
semi-Markov null; results do not establish the original HCSN/QVI hypothesis.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import platform
from pathlib import Path

import numpy as np
import scipy
from research.hcsn.p2_joint_sojourn_markov import (
    PI,TRANSITION,COUPLED_FAST_TO_ZERO,COUPLED_FAST_TO_ONE,
    nth_event_laplace,first_hit_cdf,JointSojournClock
)
from research.hcsn.test_p2_joint_sojourn_markov import (
    enumerate_laplace,phase_type_nth_cdf,double_first_event_flux,numpy_event_mc
)


def produce(samples=50000):
    if not isinstance(samples,int) or not 1000<=samples<=200000:raise ValueError('invalid sample budget')
    outcomes=[];max_mc_z=0.;max_laplace_error=0.;max_quad_error=0.
    for name,rates in [('fast_to_zero',COUPLED_FAST_TO_ZERO),('fast_to_one',COUPLED_FAST_TO_ONE)]:
        exact=[]
        for horizon in (.25,1.,2.,4.,8.):
            exact.append({'horizon_s':horizon,
                          'P_atleast_ranks_1_to_4':[phase_type_nth_cdf(horizon,PI,TRANSITION,rates,n) for n in (1,2,3,4)]})
        for t in (.25,1.,4.):
            max_quad_error=max(max_quad_error,abs(double_first_event_flux(t,PI,TRANSITION,rates)-phase_type_nth_cdf(t,PI,TRANSITION,rates,2)))
        for s in (0.,.05,.5,2.,17.):
            for n in range(1,7):
                for factorized in (False,True):
                    max_laplace_error=max(max_laplace_error,abs(nth_event_laplace(PI,TRANSITION,rates,n,s,factorized=factorized)-enumerate_laplace(PI,TRANSITION,rates,n,s,factorized=factorized)))
        panels=[]
        for seed in (11,23,37):
            obs=numpy_event_mc(samples,seed,PI,TRANSITION,rates,3)
            clock=JointSojournClock(seed,rates=rates)
            clock.advance(0.,12.)
            clock_split=JointSojournClock(seed,rates=rates)
            for i in range(96):clock_split.advance(i/8.,(i+1)/8.)
            assert clock.events==clock_split.events
            for rank,by_horizon in enumerate(obs,1):
                for t in (1.,4.):
                    expected=phase_type_nth_cdf(t,PI,TRANSITION,rates,rank)
                    count=by_horizon[str(t)]
                    se=math.sqrt(expected*(1-expected)/samples)
                    z=(count/samples-expected)/se
                    max_mc_z=max(max_mc_z,abs(z))
                    panels.append({'seed':seed,'rank':rank,'horizon_s':t,'sample_paths':samples,
                                   'event_count':count,'observed':count/samples,'exact_cdf':expected,
                                   'binomial_se':se,'z_score':z})
        outcomes.append({'name':name,'pi':PI,'transition':TRANSITION,'conditional_rates':rates,
                         'exact_phase_type':exact,'raw_mc_counts':panels,
                         'first_event_cdf_T1':first_hit_cdf(1.,PI,TRANSITION,rates),
                         'rank3_laplace_s1_joint':nth_event_laplace(PI,TRANSITION,rates,3,1.),
                         'rank3_laplace_s1_factorized':nth_event_laplace(PI,TRANSITION,rates,3,1.,factorized=True)})
    a,b=outcomes
    def exact_at(row,t,n):
        return next(x['P_atleast_ranks_1_to_4'][n-1] for x in row['exact_phase_type'] if x['horizon_s']==t)
    root=Path(__file__).resolve().parent
    src=[root/'p2_joint_sojourn_markov.py',root/'test_p2_joint_sojourn_markov.py',root/'p2_joint_sojourn_evidence.py']
    return {'schema':'hcsn.p2.iteration34.joint-sojourn.v1',
            'date_utc':'2026-11-04','scientific_admission':False,'production_activation':False,
            'gates':{f'P{i}':'OPEN' for i in range(7)},
            'scope':'Synthetic two-state semi-Markov joint holding-time/next-mode coupling; no Brownian, HX QVI or learned HCSN claim',
            'software':{'python':platform.python_version(),'numpy':np.__version__,'scipy':scipy.__version__},
            'samples_per_seed_per_scenario':samples,'seeds':[11,23,37],
            'joint_kernel_laplace':'K_ij(s)=P_ij * lambda_ij/(lambda_ij+s)',
            'matched_constraints':['same pi','same embedded transition matrix','same per-mode marginal sojourn-mixture CDF','same first-event CDF at every horizon','same eventual finite-rank hit probabilities=1'],
            'independent_references':['matrix exponential of pathwise transient phase-type generators','SciPy scalar two-fold flux convolution','separately seeded NumPy conditional exponential simulation','full pathwise Laplace expansion'],
            'scenarios':outcomes,
            'T1_second_event_probability_gap':exact_at(a,1.,2)-exact_at(b,1.,2),
            'T1_third_event_probability_gap':exact_at(a,1.,3)-exact_at(b,1.,3),
            'T1_first_event_probability_gap':exact_at(a,1.,1)-exact_at(b,1.,1),
            'max_abs_laplace_path_error':max_laplace_error,
            'max_abs_scalar_quad_vs_phase_type_error':max_quad_error,
            'max_abs_monte_carlo_z':max_mc_z,
            'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in src},
            'limitations':['This is a separate semi-Markov synthetic counterexample, not a trained causal dynamic-boundary benchmark.',
                           'Original He-Xiong Eq8/11/12/A7, full parameter domain, low precision and QVI are not certified.',
                           'No P1 slope/parameter/FLOP/steps matched independent improvement or reversal of existing negative controls.',
                           'No Selective Copy/MQAR multi-seed OOD success, independently heldout four pretrained modalities, hardware joules/p95/p99 or medium model frontier.',
                           'No external signatory or independent scientific acceptance; strict gate MUST remain nonzero.']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--samples',type=int,default=50000)
    args=p.parse_args();o=produce(args.samples);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(o,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf8')
    print(json.dumps({k:o[k] for k in ('T1_first_event_probability_gap','T1_second_event_probability_gap','T1_third_event_probability_gap','max_abs_laplace_path_error','max_abs_scalar_quad_vs_phase_type_error','max_abs_monte_carlo_z')},indent=2))
