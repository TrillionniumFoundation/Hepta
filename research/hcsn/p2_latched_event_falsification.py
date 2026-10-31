"""P2 diagnostic: does a causal edge latch fix ST false-reset chatter?

Research-only: this is a causal hysteretic discrete-event heuristic, NOT a
He-Xiong free-boundary/QVI solution or differentiable hitting-time derivative.
Latching adds non-trainable state and work; it is NOT a FLOP-matched P1 control.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import NamedTuple

import numpy as np
import torch
from torch.nn import functional as F

from .p2_learned_autonomous_content import AutonomousBoundaryMemory, MemoryState, MODES, NKEYS, DIM
from .p2_multiquery_noevent import make_mqar, rollout, _accuracy
from .p2_hard_forward_soft_gradient import rollout_st


class LatchedState(NamedTuple):
    core: MemoryState
    armed: torch.Tensor  # bool [batch,1] per trajectory; never a model input


def rollout_latched(model, x, *, state=None, surrogate=False, trace=False,
                    release_margin=0.0):
    """Causal event-on-entry, re-arm only after margin > release_margin.

    For identical model parameters, hard mode processes exactly the same input
    step kernel as earlier HCSN but substitutes a rising-edge event policy.
    ST mode uses the same soft _step backward as PR #505. Only hard forward
    can be claimed exact. 'armed' MUST be carried across streaming chunks.
    """
    if (x.ndim != 3 or x.shape[-1] != DIM or x.shape[1] < 1
            or not bool(torch.isfinite(x).all())
            or not bool(((x[:, :, NKEYS+4] > 0)&(x[:, :, NKEYS+4] <= 4)).all())):
        raise ValueError('finite nonempty [B,L,DIM] and 0 < dt <=4 required')
    if not isinstance(release_margin, (float, int)) or not 0 <= release_margin <= 2:
        raise ValueError('nonnegative release_margin <= 2 required')
    if state is None:
        state=LatchedState(model.initial(x),torch.ones((len(x),1),device=x.device,dtype=torch.bool))
    if (state.core.memory.shape != (len(x),NKEYS) or
            state.armed.shape != (len(x),1) or state.armed.dtype!=torch.bool):
        raise ValueError('incompatible streamed latch state')
    rows=[]; events=[]
    for t in range(x.shape[1]):
        xt=x[:,t,:]
        if surrogate:
            soft,*_=model._step(xt,state.core,False)
        with torch.no_grad():
            hard,_,level,margin,call,put=model._step(xt,state.core,True)
            fires=level & state.armed
            # Exact no-reset comparison for THIS _step, without modifying any
            # source or coefficients in the existing protected experiment.
            if model.mode in ('analytic','no_reset'):
                features=torch.cat((call,put,torch.tanh(margin)),-1)
            else:
                features=torch.cat((torch.sigmoid(3*margin),
                                    torch.sigmoid(-3*margin),torch.tanh(margin)),-1)
            strength=torch.sigmoid(model.write_raw+features@model.write_features).unsqueeze(-1)
            update=xt[:,NKEYS+1:NKEYS+2]*xt[:,:NKEYS]*strength
            unreset=state.core.memory*torch.exp(-F.softplus(model.raw_decay)*xt[:,NKEYS+4:NKEYS+5])
            unreset=unreset*(1-update)+update*xt[:,NKEYS:NKEYS+1]
            hard_mem=(unreset if model.mode=='no_reset' else
                      torch.where(fires,hard.memory,unreset))
            armed_next=torch.where(fires,torch.zeros_like(state.armed),
                                   state.armed | (margin>release_margin))
        mem=(hard_mem+(soft.memory-soft.memory.detach())) if surrogate else hard_mem
        state=LatchedState(MemoryState(mem,hard.context,hard.initialized),armed_next)
        rows.append(model.output_gain*(mem*xt[:,:NKEYS]).sum(-1)+model.output_bias)
        if trace: events.append(fires.squeeze(-1))
    return torch.stack(rows,1), state, (torch.stack(events,1) if trace else None)


def train_one(mode, seed, *, latch, steps=30, batch=12, length=56, eval_n=48,
              lr=.012, release_margin=0.0):
    if mode not in MODES or steps<1 or batch<1 or eval_n<1:
        raise ValueError('invalid experiment setting')
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=AutonomousBoundaryMemory(mode)
    optimizer=torch.optim.Adam(model.parameters(), lr=lr)
    last_loss=0.0
    start=time.perf_counter()
    for i in range(steps):
        x,y,q,_=make_mqar(batch,length,4,seed*100000+i)
        optimizer.zero_grad(set_to_none=True)
        logits=(rollout_latched(model,x,surrogate=True,release_margin=release_margin)[0]
                if latch else rollout_st(model,x)[0])
        loss=F.binary_cross_entropy_with_logits(logits[q],y[q])
        loss.backward()
        for name,p in model.named_parameters():
            if p.grad is None and mode=='no_reset' and name=='temperature_raw':continue
            if p.grad is None or not bool(p.grad.isfinite().all()):
                raise ArithmeticError(f'bad gradient: {name}')
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.0)
        optimizer.step()
        last_loss=float(loss.detach())
    elapsed=time.perf_counter()-start
    result={}
    with torch.no_grad():
        for tag,L,S,irregular,evseed in [('id',length,4,False,88000),
                                      ('ood_long_irregular',length*2,6,True,99000)]:
            x,y,q,ev=make_mqar(eval_n,L,S,evseed+seed,irregular=irregular)
            if latch:
                hard,_,events=rollout_latched(model,x,trace=True,release_margin=release_margin)
                st,_,_=rollout_latched(model,x,surrogate=True,release_margin=release_margin)
            else:
                hard,_,events=rollout(model,x,hard=True,trace=True)
                st,_=rollout_st(model,x)
            # Probe under exactly the same frozen trained parameters.
            ordinary_hard,_,ordinary_events=rollout(model,x,hard=True,trace=True)
            tp=(events&ev).sum()
            result[tag]={
                'hard_query_accuracy':_accuracy(hard,y,q),
                'st_hard_max_abs':float((st-hard).abs().max()),
                'unlatched_hard_accuracy':_accuracy(ordinary_hard,y,q),
                'crossings_per_stream':float(events.sum()/eval_n),
                'event_precision':float(tp/events.sum().clamp(min=1)),
                'event_recall':float(tp/ev.sum()),
                'false_positive_events_per_stream':float((events & ~ev).sum()/eval_n),
                'reduction_vs_own_unlatched_events':float((ordinary_events.sum()-events.sum())/eval_n),
                'theoretical_true_transitions_per_stream':S-1,
                'query_count':int(q.sum()),
            }
    return {'mode':mode,'seed':seed,'policy':'latched_ST' if latch else 'level_ST',
            'trainable_parameters_declared':sum(p.numel() for p in model.parameters()),
            'steps':steps,'batch':batch,'length':length,'last_loss':last_loss,
            'train_seconds':elapsed,'metrics':result}


def run(*,seeds=(11,23,37),steps=30,batch=12,length=56,eval_n=48):
    if length < 56 or length%4: raise ValueError('length>=56 divisible by 4')
    records=[train_one(mode,seed,latch=latched,steps=steps,batch=batch,
                       length=length,eval_n=eval_n)
             for seed in seeds for mode in MODES for latched in (False,True)]
    summary={}
    for tag in ('id','ood_long_irregular'):
        summary[tag]={}
        for mode in MODES:
            for policy in ('level_ST','latched_ST'):
                group=[row['metrics'][tag] for row in records if row['mode']==mode and row['policy']==policy]
                summary[tag][f'{mode}:{policy}']={k:float(np.mean([item[k] for item in group]))
                    for k in ('hard_query_accuracy','event_precision','event_recall',
                              'crossings_per_stream','false_positive_events_per_stream',
                              'reduction_vs_own_unlatched_events','st_hard_max_abs')}
    return {'schema':'hcsn.p2-latched-st-negative-control.exploratory.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scientific_gates_closed':False,'production_activation':False,
            'limitations':'Three exploratory seeds; explicit context inputs; surrogate gradients, no event-time derivative, no FLOP match, no pretrained encoders, no independent signoff; latched policy adds non-trainable armed state.',
            'summary':summary,'records':records}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--steps',type=int,default=30)
    p.add_argument('--batch',type=int,default=12)
    p.add_argument('--length',type=int,default=56)
    p.add_argument('--eval-n',type=int,default=48)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('refuse overwrite')
    out=run(seeds=tuple(a.seeds),steps=a.steps,batch=a.batch,length=a.length,eval_n=a.eval_n)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
    print(json.dumps(out['summary'],sort_keys=True,indent=2))
