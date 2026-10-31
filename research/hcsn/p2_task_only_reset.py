"""Research-only P2 task-loss-only event-learning falsification, NO event targets.

Uses the exact iteration15 causal model/data but never reads event supervision
in training.  A visible context code may still provide an easy reset signal.
This is NOT unsupervised financial QVI/optimal stopping, but it tests whether
P2 can train its own event boundary from recall loss without explicit labels.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import torch
from torch.nn import functional as F
try:
    from .p2_learned_autonomous_content import (AutonomousBoundaryMemory,
                         make_context_recall,MODES)
except ImportError:
    from p2_learned_autonomous_content import (AutonomousBoundaryMemory,
                         make_context_recall,MODES)


def train_task_only(mode:str,seed:int,*,steps:int=120,batch:int=48,
                    length:int=42,eval_n:int=192,lr:float=.012):
    if mode not in MODES:raise ValueError('unknown control')
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=AutonomousBoundaryMemory(mode)
    opt=torch.optim.Adam(model.parameters(),lr=lr)
    start=time.perf_counter()
    for t in range(steps):
        x,y,_=make_context_recall(batch,length,seed*100000+t)
        opt.zero_grad(set_to_none=True)
        pred,_=model(x)
        loss=F.binary_cross_entropy_with_logits(pred,y)
        loss.backward()
        for name,p in model.named_parameters():
            if p.grad is None and mode=='no_reset' and name=='temperature_raw':
                continue  # correctly inactive: q is disabled and unlabelled
            if p.grad is None or not p.grad.isfinite().all().item():
                raise ArithmeticError(f'invalid training gradient: {name}')
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        opt.step()
    duration=time.perf_counter()-start
    with torch.no_grad():
        performance={}
        for tag,tokens,segs,irregular,eval_seed in (
          ('id',length,4,False,81000),
          ('long_irregular',max(length*2,84),6,True,91000)):
            x,y,ev=make_context_recall(eval_n,tokens,eval_seed+seed,
                                       segments=segs,irregular=irregular)
            soft,_=model(x)
            hard,_,trace=model(x,hard=True,trace=True)
            performance[tag]={
                'soft_accuracy':float(((soft>0)==(y>.5)).float().mean()),
                'hard_accuracy':float(((hard>0)==(y>.5)).float().mean()),
                'event_precision':float(((trace.hard_events)&(ev>.5)).sum()/
                                        trace.hard_events.sum().clamp(min=1)),
                'event_recall':float(((trace.hard_events)&(ev>.5)).sum()/(ev>.5).sum()),
                'predicted_events_per_sequence':float(trace.hard_events.float().sum()/eval_n),
                'applied_events_per_sequence':(0. if mode=='no_reset' else
                                              float(trace.hard_events.float().sum()/eval_n)),
                'samples':eval_n,'steps':tokens,'segments':segs}
    return {'seed':seed,'mode':mode,'trainable_parameters':sum(p.numel() for p in model.parameters()),
            'event_supervision':False,'train_steps':steps,'wall_seconds':duration,
            'last_loss':float(loss.detach()),'results':performance}


def run(seeds=(11,23,37),steps=120,batch=48,length=42,eval_n=192):
    records=[]
    for seed in seeds:
        for mode in MODES:
            records.append(train_task_only(mode,seed,steps=steps,batch=batch,
                                 length=length,eval_n=eval_n))
    summary={m:{k:{q:sum(z['results'][k][q] for z in records if z['mode']==m)/len(seeds)
                    for q in ('soft_accuracy','hard_accuracy','event_precision','event_recall',
                              'predicted_events_per_sequence','applied_events_per_sequence')}
                  for k in ('id','long_irregular')} for m in MODES}
    return {'schema':'hcsn.p2-task-loss-only-autoreset.exploratory-v1',
            'event_supervision':False,'scientific_gate_P2_closed':False,
            'production_activation':False,'seeds':list(seeds),'rows':records,
            'summary':summary}


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--steps',type=int,default=120)
    p.add_argument('--batch',type=int,default=48)
    p.add_argument('--length',type=int,default=42)
    p.add_argument('--eval-n',type=int,default=192)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    a=p.parse_args()
    if a.output.exists():p.error('Refuse overwrite')
    result=run(tuple(a.seeds),a.steps,a.batch,a.length,a.eval_n)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result['summary'],indent=2))
