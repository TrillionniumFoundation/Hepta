"""Reproducible bounded He--Xiong Eq. (8) first-passage Monte Carlo panel.

This panel is exploratory. It was not independently preregistered; its
sampled sanity check cannot close the P0 scientific gate. Expected results
have stochastic error and explicitly reported standard errors. The fixed
seeds make this implementation deterministic for a fixed NumPy build.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
import scipy

from .hx_original import HXParams,closed_boundary
from .first_passage_mc import sample_bond_reference

PANEL=(
    (HXParams(),.22,1.,10201),
    (HXParams(sigma=.46,r=.065,delta=.095,xi=2.,k=.025),.34,.8,10202),
    (HXParams(sigma=.3,r=.065,delta=.02,xi=0.,k=0.),.45,1.,10203),
    (HXParams(sigma=.2,r=.08,delta=.06,xi=2.,k=.015),.28,.6,10204),
)


def panel(sample_size: int=120_000) -> dict:
    if not isinstance(sample_size,int) or isinstance(sample_size,bool) or not 10_000<=sample_size<=1_000_000:
        raise ValueError('Use finite reproducible MC panel sample size')
    records=[]
    for p,x,tau,seed in PANEL:
        boundary=closed_boundary(p)
        data=sample_bond_reference(x,tau,boundary,p,seed=seed,sample_size=sample_size)
        st={k:asdict(v) for k,v in data['statistics'].items()}
        records.append({'parameters':asdict(p),'boundary':boundary,'x':x,
                        'tau':tau,'seed':seed,'drift':data['drift'],
                        'sample_size':sample_size,'eventual_hit_probability':data['eventual_hit_probability'],
                        'statistics':st})
    path=Path(__file__).resolve().parent
    return {
        'schema':'hcsn.original-hx-bond-mc-iteration6.v1',
        'source_sha256':{x:hashlib.sha256((path/x).read_bytes()).hexdigest()
                         for x in ('first_passage_mc.py','test_first_passage_mc.py','p0_mc_evidence.py')},
        'environment':{'python':sys.version.split()[0],'numpy':np.__version__,
                       'scipy':scipy.__version__},
        'panel_exploratory_not_independently_preregistered':True,
        'total_draws':len(PANEL)*sample_size,
        'total_comparisons':len(PANEL)*3,
        'max_abs_z_score':max(abs(v['signed_z_score'])
              for r in records for v in r['statistics'].values()),
        'max_abs_bond_error':max(r['statistics']['stopped_bond_payoff']['absolute_error']
                               for r in records),
        'all_bounded_six_sigma_sanity_checks_pass':all(
            v['absolute_error'] <= 6*v['standard_error']+1e-10
            for r in records for v in r['statistics'].values()),
        'gate_status':{f'P{k}':'OPEN' for k in range(7)},
        'production_ready':False,
        'notes':['Exact-law first-passage sampler, not discretized Euler paths',
                 'Two first-passage probability statistics + stopped cash-flow payout each case',
                 'No all-domain, no low-precision GPU, no independent heldout model utility',
                 'MC error bars are descriptive, not proof of global equivalence'],
        'records':records,
    }

if __name__=='__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--sample-size',type=int,default=120_000)
    args=cli.parse_args()
    if args.output.exists():cli.error('Refuse overwrite')
    result=panel(args.sample_size)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in
                      ('schema','total_draws','total_comparisons','max_abs_z_score',
                       'max_abs_bond_error','all_bounded_six_sigma_sanity_checks_pass','gate_status')},indent=2))
    if not result['all_bounded_six_sigma_sanity_checks_pass']:
        raise SystemExit(3)
