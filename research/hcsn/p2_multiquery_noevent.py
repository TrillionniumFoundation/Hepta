"""Research-only HCSN P2: causal multi-query and selective-copy reset stress.

Uses the unchanged 17-parameter model from p2_learned_autonomous_content.py.
No event target is passed to training. This synthetic benchmark is NOT a
financial QVI, optimal-stopping solution, or real pretrained encoder test.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import torch
from torch.nn import functional as F

from .p2_learned_autonomous_content import AutonomousBoundaryMemory, DIM, MODES, NKEYS


def make_mqar(n: int, length: int, segments: int, seed: int, *, irregular: bool = False):
    """Returns inputs, query labels/mask, hidden *evaluation-only* reset labels.

    Each example has per-segment positive and negative writes plus a stale
    positive written only in the first segment and queried in *every* segment.
    Ground truth is segment-scoped; the stale key must be cleared after resets.
    No future labels/events are present in x.  3 queries/segment per example.
    """
    if any(type(z) is not int for z in (n,length,segments,seed)):
        raise ValueError('integer n, length, segments, seed required')
    if n < 1 or not 4 <= segments <= 8 or length < segments * 14:
        raise ValueError('requires >=14 tokens/segment and 4..8 contexts')
    rng=np.random.default_rng(seed)
    x=np.zeros((n,length,DIM),np.float32)
    targets=np.zeros((n,length),np.float32)
    mask=np.zeros((n,length),np.bool_)
    events=np.zeros((n,length),np.bool_)
    for i in range(n):
        stale=int(rng.integers(NKEYS))
        context=float(rng.choice([-1,1]))
        # deterministic equal-length segments avoid hidden alignment randomness
        bounds=[(j*length)//segments for j in range(segments+1)]
        for j in range(segments):
            start,end=bounds[j],bounds[j+1]
            sl=end-start
            if j:
                context=-context
                events[i,start]=True
            x[i,start:end,NKEYS+3]=context
            x[i,start:end,NKEYS+4]=(rng.uniform(.04,3.5,size=sl) if irregular
                                     else rng.uniform(.7,1.3,size=sl))
            eligible=[k for k in range(NKEYS) if k!=stale]
            pos,neg=[int(k) for k in rng.choice(eligible,2,replace=False)]
            writes=[(pos,1.0),(neg,-1.0)]
            if j==0:
                writes.append((stale,1.0))
            # Distinct early write times; final queries require retaining state.
            wp=rng.choice(np.arange(start+1,start+5),len(writes),replace=False)
            for t,(key,val) in zip(wp,writes):
                x[i,t,key]=1.0
                x[i,t,NKEYS]=val
                x[i,t,NKEYS+1]=1.0
            # Three query times, including one delayed near segment end.
            qp=[start+sl//2, start+(3*sl)//4, end-2]
            probe=[(stale,1.0 if j==0 else 0.0),(pos,1.0),(neg,0.0)]
            rng.shuffle(probe)
            for t,(key,label) in zip(qp,probe):
                x[i,t,key]=1.0
                x[i,t,NKEYS+2]=1.0
                targets[i,t]=label
                mask[i,t]=True
    if not (mask.sum(axis=1)==3*segments).all():
        raise AssertionError('invalid query schedule')
    return (torch.from_numpy(x),torch.from_numpy(targets),torch.from_numpy(mask),
            torch.from_numpy(events))


def exact_stream_oracle(x: torch.Tensor, *, reset: bool):
    """Reference dictionary semantics; no learnable gate or label access.

    Reset oracle uses causal observed context transitions. No-reset oracle
    deliberately preserves stale entries, exposing the task's distractor.
    """
    if x.ndim!=3 or x.shape[-1]!=DIM:
        raise ValueError('invalid input')
    answers=torch.zeros(x.shape[:2],dtype=x.dtype,device=x.device)
    for i in range(x.shape[0]):
        memory=torch.zeros(NKEYS,dtype=x.dtype,device=x.device)
        prev=None
        for t in range(x.shape[1]):
            xt=x[i,t]
            ctx=float(xt[NKEYS+3])
            if prev is not None and ctx!=prev and reset:
                memory.zero_()
            prev=ctx
            if float(xt[NKEYS+1])==1.0:
                memory[xt[:NKEYS].argmax()]=xt[NKEYS]
            if float(xt[NKEYS+2])==1.0:
                answers[i,t]=float(memory[xt[:NKEYS].argmax()]>0)
    return answers


def rollout(model, x: torch.Tensor, *, hard: bool=False, state=None, trace=False):
    """Chunk-safe causal streaming rollout with logits at every step."""
    if x.ndim != 3 or x.shape[-1] != DIM or not x.shape[1]:
        raise ValueError('expected [B,L,DIM] nonempty stream')
    if state is None:
        state=model.initial(x)
    rows=[]; event_rows=[]
    for t in range(x.shape[1]):
        xt=x[:,t,:]
        state, _,event,_,_,_=model._step(xt,state,hard)
        read=(state.memory*xt[:,:NKEYS]).sum(-1)
        rows.append(model.output_gain*read+model.output_bias)
        if trace:
            event_rows.append(event.squeeze(-1))
    return (torch.stack(rows,1),state,
            torch.stack(event_rows,1) if trace else None)


def _accuracy(logits,target,mask):
    return float(((logits>0)==(target>.5))[mask].float().mean())


def train_one(mode,seed,*,steps=65,batch=24,length=64,eval_n=96,lr=.012):
    if mode not in MODES:
        raise ValueError('unknown model mode')
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=AutonomousBoundaryMemory(mode)
    opt=torch.optim.Adam(model.parameters(),lr=lr)
    started=time.perf_counter()
    last_loss=float('nan')
    max_gradient=0.0
    for step in range(steps):
        x,y,q,_=make_mqar(batch,length,4,seed*100_000+step)
        opt.zero_grad(set_to_none=True)
        logits,_,_=rollout(model,x)
        loss=F.binary_cross_entropy_with_logits(logits[q],y[q])
        loss.backward()
        for name,param in model.named_parameters():
            if param.grad is None:
                if mode=='no_reset' and name=='temperature_raw':
                    continue # disabled erasure has no valid gradient path
                raise ArithmeticError('missing parameter gradient '+name)
            if not bool(torch.isfinite(param.grad).all()):
                raise ArithmeticError('nonfinite gradient '+name)
            max_gradient=max(max_gradient,float(param.grad.abs().max()))
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        opt.step()
        last_loss=float(loss.detach())
    elapsed=time.perf_counter()-started
    observed={}
    with torch.no_grad():
        for key,L,S,irr,eval_seed in [('id',length,4,False,88000),
                                       ('ood_long_irregular',length*2,6,True,99000)]:
            x,y,q,ev=make_mqar(eval_n,L,S,eval_seed+seed,irregular=irr)
            soft,_,_=rollout(model,x)
            hard,_,hit=rollout(model,x,hard=True,trace=True)
            # Precision/recall deliberately concern PREDICTED crossings.
            true_positives=(hit & ev).sum()
            observed[key]={
                'soft_query_accuracy':_accuracy(soft,y,q),
                'hard_query_accuracy':_accuracy(hard,y,q),
                'event_precision':float(true_positives/hit.sum().clamp(min=1)),
                'event_recall':float(true_positives/ev.sum()),
                'predicted_crossings_per_sequence':float(hit.sum()/eval_n),
                'applied_hard_resets_per_sequence':(0.0 if mode=='no_reset'
                                                    else float(hit.sum()/eval_n)),
                'query_count':int(q.sum()),
                'true_context_changes_per_sequence':S-1,
                'tokens':L,'irregular_time':irr,
            }
    return {'mode':mode,'seed':seed,
            'trainable_parameter_count':sum(p.numel() for p in model.parameters()),
            'steps':steps,'batch':batch,'last_loss':last_loss,
            'max_gradient_absolute':max_gradient,'train_wall_seconds':elapsed,
            'event_supervision':False,'results':observed}


def run(*,seeds=(11,23,37),steps=65,batch=24,length=64,eval_n=96):
    if length<56 or length%4:
        raise ValueError('training length must be divisible by 4 and >=56')
    records=[train_one(mode,seed,steps=steps,batch=batch,length=length,eval_n=eval_n)
             for seed in seeds for mode in MODES]
    summary={}
    for tag in ('id','ood_long_irregular'):
        summary[tag]={mode:{metric:float(np.mean([row['results'][tag][metric]
                                 for row in records if row['mode']==mode]))
                         for metric in ('soft_query_accuracy','hard_query_accuracy',
                                        'event_precision','event_recall',
                                        'applied_hard_resets_per_sequence')}
                      for mode in MODES}
    return {'schema':'hcsn.p2-multiquery-taskonly.exploratory.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'train_eval_seed_offset':{'id':88000,'ood':99000},
            'no_event_supervision':True,'scientific_gates_closed':False,
            'production_activation':False,
            'limitations':'Synthetic explicit key/value and visible ±1 contexts, three seeds, no pre-registered scientific test, no FLOP/slope/energy match; no HX QVI or encoder.',
            'records':records,'summary':summary}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--steps',type=int,default=65)
    p.add_argument('--batch',type=int,default=24)
    p.add_argument('--length',type=int,default=64)
    p.add_argument('--eval-n',type=int,default=96)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('evidence output already exists; refuse overwrite')
    result=run(seeds=tuple(a.seeds),steps=a.steps,batch=a.batch,
               length=a.length,eval_n=a.eval_n)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result['summary'],sort_keys=True,indent=2))

if __name__=='__main__':main()
