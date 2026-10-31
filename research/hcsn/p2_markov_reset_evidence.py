"""Reproducible descriptive evidence for exact restricted Markov-reset renewal.

This is exploratory numerics, NOT a preregistered scientific admission test.
Neither the process nor this script validates real He-Xiong coupled QVI, P1
benefit, autonomous learned memory, multimodal encoders, or production energy.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import numpy as np
import torch
try:
    from .markov_reset_renewal import markov_reset_count_law
except ImportError:
    from markov_reset_renewal import markov_reset_count_law


def t(x):return torch.tensor(x,dtype=torch.float64)


def independent_exact_mc(x0,resets,pi,transition,mu,sigma,T,lam,rho,K,N,seed):
    """Exact inverse-Gaussian/Levy event-time sampler (no Euler discretization)."""
    rng=np.random.default_rng(seed)
    cumulative=np.zeros(N)
    count=np.zeros(N,dtype=np.int32)
    reward=np.zeros(N)
    distances=np.full(N,x0)
    mode=np.zeros(N,dtype=np.int64)
    for event in range(K+1):
        if mu<0:
            dt=rng.wald(distances/abs(mu),(distances/sigma)**2)
        elif mu>0:
            chance=np.exp(-2*mu*distances/sigma**2)
            dt=rng.wald(distances/mu,(distances/sigma)**2)
            dt=np.where(rng.random(N)<chance,dt,np.inf)
        else:
            normal=rng.standard_normal(N)
            with np.errstate(divide='ignore',over='ignore'):
                dt=(distances/(sigma*normal))**2
        cumulative+=dt+(rho if event else 0.)
        hit=cumulative<=T
        count+=hit
        if event<K:
            reward+=hit*np.exp(-lam*cumulative)
        if event==0:
            mode=(rng.random(N)>=pi[0]).astype(np.int64)
        else:
            mode=(rng.random(N)>=transition[mode,0]).astype(np.int64)
        distances=resets[mode]
    return count,reward


def produce(N=100_000):
    base=dict(x0=.53,resets=np.array([.34,.89]),pi=np.array([.37,.63]),
              transition=np.array([[.81,.19],[.26,.74]]),sigma=.54,
              T=4.6,lam=.31,rho=.12,K=8)
    report=dict(schema='hcsn.p2-markov-renewal.v1',scope=(
        'two-mode history-correlated stochastic reset margins, event-independent '
        'Markov transition, constant drift/sigma, fixed boundary and refractory'),
        scientific_admission=False,production_activation=False,
        p0_to_p6_closed=False,mc_is_exploratory_not_preregistered=True,
        python=platform.python_version(),numpy=np.__version__,torch=torch.__version__,
        sample_paths_per_panel=N,panels=[])
    for drift,seed in [(-.24,120261),(.0,120262),(.22,120263)]:
        b={**base,'mu':drift}
        K=b['K']
        law=markov_reset_count_law(t(b['x0']),t(b['resets']),t(b['pi']),t(b['transition']),
                                   t(b['mu']),t(b['sigma']),t(b['T']),t(b['lam']),
                                   t(b['rho']),max_events=K)
        counts,rewards=independent_exact_mc(**b,N=N,seed=seed)
        ana=law.at_least_probabilities.detach().numpy()
        empirical=np.array([np.mean(counts>=j) for j in range(1,K+2)])
        stderr=np.sqrt(np.maximum(ana*(1-ana),1.e-9)/N)
        z=(empirical-ana)/stderr
        reward_mean=float(np.mean(rewards)); reward_se=float(np.std(rewards,ddof=1)/np.sqrt(N));
        r_ref=float(law.discounted_event_reward_lower_bound)
        row=dict(drift=drift,seed=seed,
            count_at_least_analytic=ana.tolist(),
            count_at_least_mc=empirical.tolist(),
            count_at_least_standard_errors=stderr.tolist(),
            count_z_scores=z.tolist(),max_abs_count_z=float(np.max(np.abs(z))),
            exact_count_probabilities=law.exact_count_probabilities.detach().numpy().tolist(),
            tail_probability=float(law.overflow_probability),
            discount_reward_analytic=r_ref,discount_reward_mc=reward_mean,
            discount_reward_mc_standard_error=reward_se,
            discount_reward_z=(reward_mean-r_ref)/reward_se,
            count_expected_first_K=float(law.expected_count_lower_bound))
        report['panels'].append(row)
    report['max_abs_count_z']=max(p['max_abs_count_z'] for p in report['panels'])
    report['max_abs_reward_z']=max(abs(p['discount_reward_z']) for p in report['panels'])
    here=Path(__file__).resolve().parent
    report['sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (here/'markov_reset_renewal.py',here/'test_markov_reset_renewal.py',
                                here/'moving_boundary_first_passage.py',here/'stochastic_regenerative_counts.py')}
    report['limitations']=[
        'Original HX equity/free-boundary model untouched; no QVI or endogenous dynamic boundary.',
        'Mode Markov transitions independent of Brownian path and time; not learned input-conditioned reset.',
        'Only scalar CPU float64; no GPU/FP32/BF16 or device power certification.',
        'No P1 net benefit, no Selective Copy/MQAR or pretrained multimodal Encoder.',
        'Numerical MC deviations are descriptive; no independently preregistered thresholds.',
        'No gradient through sampled event-count realizations.'
    ]
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--paths',type=int,default=100_000)
    a=p.parse_args()
    if a.paths<1000 or a.paths>1_000_000:raise ValueError('paths outside [1000,1000000]')
    evidence=produce(a.paths)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(evidence,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print(json.dumps({'paths':3*a.paths,'max_abs_count_z':evidence['max_abs_count_z'],
                      'max_abs_reward_z':evidence['max_abs_reward_z'],
                      'scientific_admission':False},indent=2))

if __name__=='__main__':main()
