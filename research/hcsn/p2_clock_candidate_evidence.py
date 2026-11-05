"""Predeclared paired CPU diagnostic: original token clock vs exact held-context ODE.

This evidence cannot close P0-P6; it keeps all prior negatives and uses only
query labels for training. Compute/FLOPs are NOT matched (only steps/data/seeds).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

import numpy as np
import torch
from torch.nn import functional as F
from research.hcsn.p2_no_event_dynamic_boundary import (
    CausalBoundary, MODES, DIM, NKEYS, samples, _metrics)
from research.hcsn.p2_physical_clock_candidate import ClockCorrectedBoundary
from research.hcsn.test_p2_physical_clock_candidate import same_physical_hold

POLICIES = ('clock_corrected', 'dynamic', 'instantaneous', 'no_reset')
SEEDS = (11,23,37)
STEPS=40
BATCH=16
EVAL_N=48
TRAIN_LENGTH=64


def _train(seed,policy):
    torch.manual_seed(seed)
    m=ClockCorrectedBoundary() if policy=='clock_corrected' else CausalBoundary(policy)
    opt=torch.optim.Adam(m.parameters(),lr=.025)
    train_start=time.perf_counter()
    for it in range(STEPS):
        x,y,q,_=samples(BATCH,TRAIN_LENGTH,4,seed*100000+it)
        opt.zero_grad(set_to_none=True)
        out,_,_=m.rollout(x,hard=False)
        loss=F.binary_cross_entropy_with_logits(out[q],y[q])
        loss.backward()
        for name,p in m.named_parameters():
            if policy=='no_reset' and name in ('threshold','sensitivity'):
                if p.grad is not None:
                    raise AssertionError('unused no-reset detector unexpectedly received gradient')
            elif p.grad is None or not bool(torch.isfinite(p.grad).all()):
                raise AssertionError(f'nonfinite / missing gradient for {policy}: {name}')
        torch.nn.utils.clip_grad_norm_(m.parameters(),5.)
        opt.step()
    return m,float(loss.detach()),time.perf_counter()-train_start


def generate():
    torch.set_num_threads(1)
    results=[]
    for seed in SEEDS:
        for policy in POLICIES:
            model,loss,elapsed=_train(seed,policy)
            data_id=samples(EVAL_N,TRAIN_LENGTH,4,88000+seed)
            data_ood=samples(EVAL_N,TRAIN_LENGTH*2,6,99000+seed,noise=.23,irregular=True)
            cases={'id':_metrics(model,data_id),'ood_long_noisy_irregular':_metrics(model,data_ood)}
            traces=[same_physical_hold(model,n) for n in (4,16,64)] if policy in ('clock_corrected','dynamic') else None
            results.append({'seed':seed,'policy':policy,'train_steps':STEPS,'train_batch':BATCH,
                            'train_length':TRAIN_LENGTH,'declared_parameters':sum(p.numel() for p in model.parameters()),
                            'active_parameters':sum(p.numel() for name,p in model.named_parameters()
                                if policy!='no_reset' or name not in ('threshold','sensitivity')),
                            'train_wall_s':elapsed,'last_train_loss':loss,
                            'trained_parameters':{name:float(v.detach()) for name,v in model.named_parameters()},
                            'metrics':cases,'held_context_probe':traces})
    summary={}
    for panel in ('id','ood_long_noisy_irregular'):
        summary[panel]={}
        for policy in POLICIES:
            subset=[x['metrics'][panel] for x in results if x['policy']==policy]
            summary[panel][policy]={k:float(np.mean([x[k] for x in subset])) for k in (
                'soft_query_accuracy','hard_query_accuracy','event_precision','event_recall',
                'detected_events_per_stream','applied_resets_per_stream')}
    paired_ood={}
    for opponent in ('dynamic','instantaneous','no_reset'):
        paired_ood[opponent]={}
        for metric in ('hard_query_accuracy','soft_query_accuracy','event_precision','event_recall','detected_events_per_stream'):
            paired_ood[opponent][metric]=[
                next(x for x in results if x['seed']==seed and x['policy']=='clock_corrected')['metrics']['ood_long_noisy_irregular'][metric]
                -next(x for x in results if x['seed']==seed and x['policy']==opponent)['metrics']['ood_long_noisy_irregular'][metric]
                for seed in SEEDS]
    corrected_traces=[r['held_context_probe'] for r in results if r['policy']=='clock_corrected']
    old_traces=[r['held_context_probe'] for r in results if r['policy']=='dynamic']
    if any(max(z['volatility'] for z in tri)-min(z['volatility'] for z in tri)>1e-6 for tri in corrected_traces):
        raise AssertionError('clock correction failed resampling-invariant state')
    if not all([z['probe_hit'] for z in tri]==[True,False,False] for tri in old_traces):
        raise AssertionError('original negative control no longer reproduced')
    return {
      'schema':'hcsn.p2-held-context-clock-candidate-paired.v1',
      'protocol':'Trained 40 Adam updates at 16x64/query-only, seed-matched data; ID 48x64, OOD 48x128/6 segments/noise 0.23/irregular dt; hard/soft readout and detector metrics; 4 policies; no event-supervision.',
      'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'upstream_sha256':hashlib.sha256(Path(__file__).with_name('p2_no_event_dynamic_boundary.py').read_bytes()).hexdigest(),
      'candidate_sha256':hashlib.sha256(Path(__file__).with_name('p2_physical_clock_candidate.py').read_bytes()).hexdigest(),
      'seeds':list(SEEDS),'train_steps':STEPS,'train_batch':BATCH,
      'same_seed_data_and_parameter_count':True,'matched_train_updates':True,
      'matched_flops':False,'original_negative_retained':True,
      'external_independent_attestation':False,
      'clock_semantics':'Exact zero-order-held deterministic context ODE, not a hidden stochastic first-hit oracle or input-continuous Brownian QVI.',
      'measurements':results,'summary':summary,'paired_ood_candidate_minus_control':paired_ood,
      'science_gates':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False,
      'limitations':'Synthetic noisy scalar context only. No causal between-sample hit-time recovery; sample-count event chatter may remain. No multi-modal pretrained encoders, QVI, matched FLOPs, full repository CI, real GPU/energy or independent signatures.'}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    if a.output.exists():
        ap.error('refusing existing output')
    result=generate()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'summary':result['summary'],
            'paired_ood':result['paired_ood_candidate_minus_control']},indent=2,sort_keys=True))

if __name__=='__main__':
    main()
