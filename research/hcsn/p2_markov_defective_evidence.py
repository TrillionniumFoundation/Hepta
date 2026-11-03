"""Reproduce Markov two-mode defective first-hit negative control and raw stats.

No post hoc claim of P2 closure; JSON is descriptive CPU FP64, not preregistered.
"""
import argparse
import hashlib
import json
import math
import platform
from pathlib import Path

import numpy as np
from research.hcsn.p2_markov_defective_firsthit import eventual_atleast,eventual_q,nth_event_laplace,MarkovDefectiveClock
from research.hcsn.test_p2_markov_defective_firsthit import (
    A,MU,SIG,R,PI,STAY,FLIP,enumerate_laplace,exact_two_hit_cdf,direct_np_exact_sampler
)


def produce(N:int=45000):
    outcomes=[]
    max_z=0.
    for name,P in [('stay',STAY),('alternate',FLIP)]:
        tails=eventual_atleast(PI,P,A,MU,SIG,R,100)
        theory_two_8=exact_two_hit_cdf(8.,PI,P,A,MU,SIG,R)
        panels=[]
        for seed in (11,23,37):
            smp=direct_np_exact_sampler(N,seed,PI,P,A,MU,SIG,R,3,8.)
            for k,(fin,ev) in enumerate(smp,1):
                theory_ev=float(tails[k-1]); n_se=math.sqrt(theory_ev*(1-theory_ev)/N)
                z=(ev-theory_ev)/n_se
                max_z=max(max_z,abs(z))
                panels.append({'seed':seed,'rank':k,'sample_paths':N,
                               'finite_horizon_s':8.,'eventually_hit_observed':ev,'eventually_hit_count':round(ev*N),
                               'within_8s_observed':fin,'within_8s_count':round(fin*N),'eventually_hit_expected':theory_ev,
                               'eventually_hit_se':n_se,'eventually_hit_z':z,
                               'within_8s_reference':theory_two_8 if k==2 else None,
                               'within_8s_z':(fin-theory_two_8)/math.sqrt(theory_two_8*(1-theory_two_8)/N) if k==2 else None})
        laplace_errors=[abs(nth_event_laplace(PI,P,A,MU,SIG,R,n,s) - enumerate_laplace(PI,P,A,MU,SIG,R,n,s))
                        for s in (0.,.001,.13,1.5) for n in range(1,8)]
        outcomes.append({'scenario':name,'pi':PI,'P':P,'a':A,'mu':MU,'sigma':SIG,'outgoing_refractory_s':R,
                         'q_per_mode':eventual_q(A,MU,SIG).tolist(),
                         'eventual_atleast_ranks_1_to_12':tails[:12].tolist(),
                         'eventual_rank_30':float(tails[29]),'eventual_rank_100':float(tails[99]),
                         'finite_two_events_T8_flux_integral':theory_two_8,
                         'max_abs_2_to_7_event_laplace_enumeration_error':max(laplace_errors),
                         'per_seed_rank':panels})
    scalar_naive=(sum(eventual_q(A,MU,SIG))/2)**3
    r={'schema':'hcsn.p2.iteration33.markov-defective.v1',
       'scientific_admission':False,'production_activation':False,'gates':{f'P{i}':'OPEN' for i in range(7)},
       'scope':'Two-mode event-driven Markov Brownian iid excursions, state-specific drift/sigma/distance and post-event refractory; not learning, QVI, or realized Brownian-path event oracle',
       'software':{'python':platform.python_version(),'numpy':np.__version__},
       'num_samples_per_seed_and_transition':N,'seeds':[11,23,37],
       'scenarios':outcomes,
       'naive_stationary_average_q_cubed':float(scalar_naive),
       'eventual_third_stay_minus_flip':outcomes[0]['eventual_atleast_ranks_1_to_12'][2]-outcomes[1]['eventual_atleast_ranks_1_to_12'][2],
       'max_abs_eventual_mc_z':max_z,
       'limitations':['No trained content-conditioned boundary or independent heldout MQAR',
                      'Sampling invariant synthetic law does not reveal realized unobserved BM events',
                      'No original He-Xiong Eq8/11/12/A7 full domain, QVI, P1 matched FLOPs',
                      'No pretrained multimodal models, production hardware energy, or P6 medium-scale frontier',
                      'No independent external trust root or evaluator signature']}
    root=Path(__file__).resolve().parent
    r['sha256_sources']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [root/'p2_markov_defective_firsthit.py',root/'test_p2_markov_defective_firsthit.py',root/'p2_markov_defective_evidence.py']}
    return r

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--samples',type=int,default=45000)
    args=parser.parse_args()
    if not (1000<=args.samples<=200000):raise ValueError('samples outside finite reproducible budget')
    report=produce(args.samples)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({'rank3_difference':report['eventual_third_stay_minus_flip'],
                      'max_abs_eventual_mc_z':report['max_abs_eventual_mc_z'],
                      'P0_P6':'OPEN','production_activation':False},indent=2))
