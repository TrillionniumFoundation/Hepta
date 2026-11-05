"""Produce raw independent HCSN P2 iteration 38 evidence and a strict fail-closed gate."""
from __future__ import annotations
import argparse, json, math, platform, sys
import numpy as np
import scipy
import torch
from p2_task_only_ctmc_retention import (reproduce, exact_probability, independent_ode,
                                       independent_expm, exact_blank_decay, physical_split, independent_event_path)

def run():
    reports = [reproduce(s,steps=420) for s in (11,23,37)]
    random = np.random.default_rng(117181)
    worst_ode=worst_expm=worst_refinement=0.
    for _ in range(60):
        rates = random.uniform(.03,4,size=(3,2))
        sched = [(float(random.uniform(.05,2)),int(random.integers(0,3))) for _ in range(4)]
        p = exact_probability(sched,rates)
        worst_ode=max(worst_ode,abs(p-independent_ode(sched,rates)))
        worst_expm=max(worst_expm,abs(p-independent_expm(sched,rates)))
        for n in (4,16,64):
            worst_refinement=max(worst_refinement,abs(p-exact_probability(physical_split(sched,n),rates)))
    if max(worst_ode,worst_expm)>4e-11 or worst_refinement>3e-12:
        raise AssertionError('independent numerical or physical clock reference failed')
    for report in reports:
        if not report['train_final_loss']<report['train_initial_loss']-.09:
            raise AssertionError('task-only training did not improve')
        if not report['heldout_blank_lengths'][-1]['bayes_accuracy']<.501:
            raise AssertionError('leakage OOD counterexample not reproduced')
    autonomous_samples=[]
    for report in reports:
        r=report['six_learned_rates']
        for label, writes in ((0,[(1.,1),(1.,0)]),(1,[(1.,0),(1.,1)])):
            sched=writes+[(16.,2)]
            n=10000
            paths=[independent_event_path(sched,r,100000*report['seed']+i) for i in range(n)]
            empirical=sum(state for state,events in paths)/n
            mean_events=sum(events for state,events in paths)/n
            p=exact_probability(sched,r)
            z=abs(empirical-p)/math.sqrt(p*(1-p)/n)
            if z>=4: raise AssertionError('independent event path MC >4sigma')
            autonomous_samples.append({'seed':report['seed'],'last_write':label,'physical_blank_s':16,
                'paths':n,'empirical_state1':empirical,'exact_state1':p,
                'z_error':z,'mean_autonomous_events':mean_events})
    return {
        'research_only':True,'P0_P6':{f'P{i}':'OPEN' for i in range(7)},
        'production_activation':False,'strict_exit_code':2,
        'study':'exact task-only trained two-state CTMC with positive blank-rate floor; NOT He-Xiong first hit',
        'training':'3 seeds, 420 Adam updates, exact differentiable state transfer, last-write label only; 16 paired schedules, delay 0/.5/1/2',
        'torch':torch.__version__,'scipy':scipy.__version__,'numpy':np.__version__,
        'python':platform.python_version(),
        'independent_reference':{'random_scenarios':60,'split_factors':[4,16,64],
          'max_scipy_DOP853_abs':worst_ode,'max_scipy_matrix_expm_abs':worst_expm,
          'max_physical_refinement_abs':worst_refinement},
        'per_seed':reports,'autonomous_event_MC':autonomous_samples,
        'limits':['synthetic binary last-write only, not full Selective Copy or MQAR',
                  'positive blank-rate floor imposed by design, not empirically identified from HCSN',
                  'no train/test budget and FLOP parity against strong GRU/ordinary gate',
                  'no independent external scientific gate or pretrained modality/GPU evidence']}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--strict',action='store_true')
    args=p.parse_args()
    try:
        print(json.dumps(run(),indent=2,sort_keys=True,allow_nan=False))
    except Exception as exc:
        print(json.dumps({'error':str(exc),'P0_P6':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False}))
        sys.exit(3)
    if args.strict: sys.exit(2)
