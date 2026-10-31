"""Finite-sample independent evidence for the stationary renewal law.

Runs only independent exact-time Monte Carlo, density quadrature and the
analytic renewal formula; it is NOT a gate or efficacy certification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
try:
    from .stochastic_regenerative_counts import renewal_count_law
    from .test_stochastic_regenerative_counts import independent_mc
except ImportError:
    from stochastic_regenerative_counts import renewal_count_law
    from test_stochastic_regenerative_counts import independent_mc


def run() -> dict:
    outcomes=[]
    panels=[(-.25,202601),(0.,202602),(.18,202603)]
    for drift,seed in panels:
        n=120000
        params=(.52,.39,drift,.44,4.,.12)
        vals=[torch.tensor(v,dtype=torch.float64) for v in params]
        analytic=renewal_count_law(*vals,max_events=8)
        counts,rewards=independent_mc(*params,n,seed,max_events=8)
        pred=analytic.exact_count_probabilities.detach().numpy()
        rows=[]
        for k in range(9):
            empirical=float(np.mean(counts==k))
            se=float(np.sqrt(max(pred[k]*(1-pred[k]),1.e-8)/n))
            rows.append({'count':k,'analytic_probability':float(pred[k]),'mc_probability':empirical,'binomial_standard_error':se,'z_score':(empirical-float(pred[k]))/se})
        tail=float(analytic.overflow_probability)
        empirical_tail=float(np.mean(counts>8))
        tail_se=float(np.sqrt(max(tail*(1-tail),1e-8)/n))
        mean=float(rewards.mean())
        se=float(np.std(rewards,ddof=1)/np.sqrt(n))
        expect=float(analytic.discounted_event_reward_lower_bound)
        outcomes.append({'drift':drift,'seed':seed,'paths':n,'count_histogram':rows,
                         'censored_tail':{'analytic':tail,'mc':empirical_tail,
                             'z_score':(empirical_tail-tail)/tail_se},
                         'first_8_discounted_events':{'analytic_mean':expect,
                             'mc_mean':mean,'standard_error':se,
                             'z_score':(mean-expect)/se},
                         'expected_count_first_8':float(analytic.expected_count_lower_bound)})
    root=Path(__file__).parent
    hashes={n:hashlib.sha256((root/n).read_bytes()).hexdigest()
            for n in ('stochastic_regenerative_counts.py',
                      'test_stochastic_regenerative_counts.py',
                      'moving_boundary_first_passage.py')}
    return {'schema':'hcsn.p2-stationary-stochastic-renewal.v1',
        'date':'2026-10-31',
        'assumptions':'stationary scalar first passage, same x_reset after each event, no state coupling',
        'analytic_identity':'Pr(N(T)>=n)=F(T;x0+(n-1)*reset_margin,mu,sigma)',
        'independent_reference':'inverse-Gaussian/Levy sample of each successive hitting time',
        'count_tails_right_censored':True,'mc_exploratory_not_preregistered':True,
        'kernel_is_original_hx_global_equilibrium':False,
        'scientific_P0_to_P6_closed':False,'production_activation':False,
        'source_sha256':hashes,
        'total_mc_paths':sum(v['paths'] for v in outcomes),
        'max_abs_count_z':max(abs(x['z_score']) for out in outcomes for x in out['count_histogram']),
        'max_abs_discounted_reward_z':max(abs(out['first_8_discounted_events']['z_score']) for out in outcomes),
        'panels':outcomes}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error('Refuse to replace evidence file')
    evidence=run()
    args.output.write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'total_mc_paths':evidence['total_mc_paths'],
        'max_abs_count_z':evidence['max_abs_count_z'],
        'max_abs_discounted_reward_z':evidence['max_abs_discounted_reward_z'],
        'source_sha256':evidence['source_sha256']},indent=2))
