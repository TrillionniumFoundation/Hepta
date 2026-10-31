"""HCSN P2 falsification benchmark: learned content-conditioned boundary resets.

RESEARCH ONLY.  No exogenous reset bit is given to the model.  A context code
changes and the model *learns* a causal boundary response using auxiliary
labels for first-context transitions.  This is NOT a solution of the general
He--Xiong QVI, NOT an unsupervised optimal boundary, and NOT exact first-passage
Brownian dynamics.  Its trainable continuous channels come from a separately
invented one-shot perpetual obstacle, not the coupled original HX A7.

The storage is an explicit differentiable key/value scratchpad, *not* evidence
that a full encoder has been trained.  Both analytic and ordinary controls
use exactly the same parameters and data; a no-reset control ablates clearing.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
import time
from typing import NamedTuple

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

NKEYS=6
DIM=NKEYS+5  # onehot key, value, write, query, context, delta_time
MODES=('analytic','ordinary','no_reset')


class MemoryState(NamedTuple):
    memory: torch.Tensor
    context: torch.Tensor
    initialized: torch.Tensor


@dataclass
class BoundaryTrace:
    event_logits: torch.Tensor
    hard_events: torch.Tensor
    margins: torch.Tensor
    call: torch.Tensor
    put: torch.Tensor


def make_context_recall(n:int,length:int,seed:int,*,segments:int=4,
                        irregular:bool=False)->tuple[torch.Tensor,torch.Tensor,torch.Tensor]:
    """Produce a true held-out stream (X, query label, hidden event labels).

    Each sequence has >=3 autonomous context changes, no reset marker in X.
    The final query may target a key that was last written in a PREVIOUS
    context; without erasure, this yields an adversarial stale positive.
    The final step is always the query, so it cannot expose later answers.
    """
    if not isinstance(n,int) or n<1 or not isinstance(length,int) or length<30:
        raise ValueError('n and length out of bounds')
    if not isinstance(segments,int) or not 4<=segments<=7 or length<segments*6+2:
        raise ValueError('must provide >=4 distinct >=6-step contexts')
    rng=np.random.default_rng(seed)
    x=np.zeros((n,length,DIM),dtype=np.float32)
    y=np.zeros(n,dtype=np.float32)
    hidden=np.zeros((n,length),dtype=np.float32)
    for i in range(n):
        # Positive-length segments with modest independent timing jitter.
        boundaries=[0]
        for j in range(1,segments):
            nominal=round(j*length/segments)
            low=max(boundaries[-1]+6,nominal-2)
            high=min(length-(segments-j)*6,nominal+2)
            if low>high:raise ValueError('length too short for segment jitter')
            boundaries.append(int(rng.integers(low,high+1)))
        boundaries.append(length)
        ctx=float(rng.choice((-1,1)))
        key=int(rng.integers(NKEYS))
        last_write=bool(rng.random()<.65)
        last_value=1. if rng.random()<.7 else -1.
        y[i]=1. if last_write and last_value>0 else 0.
        for j in range(segments):
            start,end=boundaries[j:j+2]
            if j>0:
                ctx=-ctx
                hidden[i,start]=1.
            x[i,start:end,NKEYS+3]=ctx
            x[i,start:end,NKEYS+4]=rng.uniform(.08,2.9 if irregular else 1.2,size=end-start)
            candidates=list(range(start+1,end-1))
            rng.shuffle(candidates)
            if j<segments-1:
                # A stale positive for the eventual query key is guaranteed.
                writes=[(key,1.)]
                other=int(rng.choice([k for k in range(NKEYS) if k!=key]))
                writes.append((other,float(rng.choice((-1,1)))))
            else:
                writes=[(key,last_value)] if last_write else []
                other=rng.choice([k for k in range(NKEYS) if k!=key],size=2,replace=False)
                writes.extend((int(k),float(rng.choice((-1,1)))) for k in other)
            for t,(k,v) in zip(candidates,writes):
                x[i,t,k]=1.
                x[i,t,NKEYS]=v
                x[i,t,NKEYS+1]=1.
        x[i,-1,key]=1.
        x[i,-1,NKEYS+2]=1.
        x[i,-1,NKEYS]=0.
    return torch.from_numpy(x),torch.from_numpy(y),torch.from_numpy(hidden)


class AutonomousBoundaryMemory(nn.Module):
    """Causal differentiable memory; hard events only in inference mode.

    State conditioned free boundary via an HX-inspired analytic option with
    newly defined regenerative threshold.  The mode only changes the two
    continuous feature maps, so active trainable parameter counts are exact.
    """
    def __init__(self,mode='analytic'):
        super().__init__()
        if mode not in MODES:raise ValueError('unrecognized model')
        self.mode=mode
        self.raw_r=nn.Parameter(torch.tensor(-2.97))
        self.raw_delta=nn.Parameter(torch.tensor(-3.50))
        self.raw_sigma=nn.Parameter(torch.tensor(-1.50))
        self.raw_k=nn.Parameter(torch.tensor(.54))
        self.reserve_bias=nn.Parameter(torch.tensor(.08))
        self.novelty_raw=nn.Parameter(torch.tensor(-2.1))
        self.memory_feedback=nn.Parameter(torch.tensor(.03))
        self.context_feedback=nn.Parameter(torch.tensor(.02))
        self.time_feedback=nn.Parameter(torch.tensor(.015))
        self.temperature_raw=nn.Parameter(torch.tensor(-2.5))
        self.write_raw=nn.Parameter(torch.tensor(3.5))
        self.write_features=nn.Parameter(torch.tensor([.08,-.08,.10]))
        self.raw_decay=nn.Parameter(torch.tensor(-8.0))
        self.output_gain=nn.Parameter(torch.tensor(4.0))
        self.output_bias=nn.Parameter(torch.tensor(-.65))

    def initial(self,inputs:torch.Tensor)->MemoryState:
        b=inputs.shape[0]
        return MemoryState(inputs.new_zeros((b,NKEYS)),
                           inputs.new_zeros((b,1)),
                           torch.zeros((b,1),dtype=torch.bool,device=inputs.device))

    def _step(self,xt:torch.Tensor,state:MemoryState,hard:bool):
        mem,prev,initialized=state
        key=xt[:,:NKEYS]
        val=xt[:,NKEYS:NKEYS+1]
        write=xt[:,NKEYS+1:NKEYS+2]
        ctx=xt[:,NKEYS+3:NKEYS+4]
        dt=xt[:,NKEYS+4:NKEYS+5]
        novelty=(ctx-torch.where(initialized,prev,ctx)).abs()
        r=F.softplus(self.raw_r)+.005
        delta=F.softplus(self.raw_delta)+.002
        sigma=F.softplus(self.raw_sigma)+.01
        s2=sigma.square()
        a=(r-delta-.5*s2)/s2
        beta=torch.hypot(a,torch.sqrt(2*r/s2))+a
        k=F.softplus(self.raw_k)+.05
        b0=k*beta/(1+beta)
        log_v=self.reserve_bias+self.memory_feedback*mem.abs().mean(-1,keepdim=True)\
              -self.time_feedback*dt
        log_b=torch.log(b0)+F.softplus(self.novelty_raw)*novelty\
              +self.context_feedback*mem.mean(-1,keepdim=True)
        margin=log_v-log_b
        continuation=margin.clamp(min=0)
        boundary=torch.exp(log_b)
        local_k=boundary*(beta+1)/beta
        # Cancellation-controlled analytic value near the free boundary.
        near=boundary*(.5*(1+beta)*continuation.square() +
                  (1-beta.square())*continuation.pow(3)/6+
                  (1+beta.pow(3))*continuation.pow(4)/24)
        direct=boundary*(torch.expm1(continuation)+torch.expm1(-beta*continuation)/beta)
        call=torch.where(continuation<.002,near,direct)/local_k
        put=torch.where(margin<=0,local_k-torch.exp(log_v),
                              boundary/beta*torch.exp(-beta*continuation))/local_k
        if self.mode in ('analytic','no_reset'):
            features=torch.cat([call,put,torch.tanh(margin)],-1)
        else:
            features=torch.cat([torch.sigmoid(3*margin),
                                torch.sigmoid(-3*margin),torch.tanh(margin)],-1)
        gate_logits=-margin/(F.softplus(self.temperature_raw)+.015)
        q=torch.sigmoid(gate_logits)
        event=margin<=0
        if self.mode=='no_reset':
            renewed=mem
        elif hard:
            renewed=torch.where(event,torch.zeros_like(mem),mem)
        else:
            renewed=(1-q)*mem
        decay=F.softplus(self.raw_decay)*dt
        renewed=renewed*torch.exp(-decay)
        strength=torch.sigmoid(self.write_raw+features @ self.write_features).unsqueeze(-1)
        update=write*key*strength
        renewed=renewed*(1-update)+update*val
        out=MemoryState(renewed,ctx,torch.ones_like(initialized))
        return out,gate_logits,event,margin,call,put

    def forward(self,x:torch.Tensor,*,state:MemoryState|None=None,
                hard:bool=False,trace:bool=False):
        if x.ndim!=3 or x.shape[-1]!=DIM or x.shape[1]<1 or not bool(torch.isfinite(x).all()):
            raise ValueError('Expected finite [batch,time,DIM] input')
        if not bool(((x[:,:,NKEYS+4]>.0)&(x[:,:,NKEYS+4]<=4.)).all()):
            raise ValueError('Invalid positive delta times')
        if state is None:state=self.initial(x)
        if state.memory.shape!=(len(x),NKEYS):raise ValueError('Invalid streaming state shape')
        event_logits=[];hard_events=[];margins=[];calls=[];puts=[]
        for t in range(x.shape[1]):
            state,el,ev,m,c,p=self._step(x[:,t,:],state,hard)
            if trace:
                event_logits.append(el.squeeze(-1))
                hard_events.append(ev.squeeze(-1))
                margins.append(m.squeeze(-1))
                calls.append(c.squeeze(-1))
                puts.append(p.squeeze(-1))
        read=(state.memory*x[:,-1,:NKEYS]).sum(-1)
        logits=self.output_gain*read+self.output_bias
        if trace:
            record=BoundaryTrace(*(torch.stack(a,1) for a in
                     [event_logits,hard_events,margins,calls,puts]))
            return logits,state,record
        return logits,state


def train_one(mode:str,seed:int,*,steps=120,batch=48,length=42,
              lr=.012,eval_n=192)->dict:
    if mode not in MODES:raise ValueError('Unknown mode')
    torch.manual_seed(seed)
    model=AutonomousBoundaryMemory(mode)
    optimizer=torch.optim.Adam(model.parameters(),lr=lr)
    start=time.perf_counter()
    last_loss=None
    for t in range(steps):
        x,y,ev=make_context_recall(batch,length,seed*100000+t)
        optimizer.zero_grad(set_to_none=True)
        logits,_,tr=model(x,trace=True)
        recall=F.binary_cross_entropy_with_logits(logits,y)
        detection=F.binary_cross_entropy_with_logits(tr.event_logits,ev,
                pos_weight=torch.tensor(8.,dtype=x.dtype))
        loss=recall+.20*detection
        loss.backward()
        if not all(p.grad is not None and torch.isfinite(p.grad).all().item()
                   for p in model.parameters()):
            raise ArithmeticError('Nonfinite/missing BPTT gradient')
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        optimizer.step()
        last_loss=float(loss.detach())
    duration=time.perf_counter()-start
    model.eval()
    performance={}
    for tag,n_steps,n_segs,irregular,e_seed in (
            ('id',length,4,False,81000),
            ('long_irregular',max(84,length*2),6,True,91000)):
        x,y,ev=make_context_recall(eval_n,n_steps,e_seed+seed,
                                    segments=n_segs,irregular=irregular)
        with torch.no_grad():
            soft,_,st=model(x,trace=True)
            hard,_,ht=model(x,hard=True,trace=True)
        performance[tag]={
            'soft_accuracy':float(((soft>0)==(y>.5)).float().mean()),
            'hard_accuracy':float(((hard>0)==(y>.5)).float().mean()),
            'event_accuracy':float(((ht.hard_events)==(ev>.5)).float().mean()),
            'event_precision':float(((ht.hard_events)&(ev>.5)).sum()/ht.hard_events.sum().clamp(min=1)),
            'event_recall':float(((ht.hard_events)&(ev>.5)).sum()/(ev>.5).sum()),
            'hard_events_per_sequence':float(ht.hard_events.float().sum()/eval_n),
            'applied_hard_resets_per_sequence':(0. if mode=='no_reset' else
                       float(ht.hard_events.float().sum()/eval_n)),
            'supervised_transitions_per_sequence':n_segs-1,
            'samples':eval_n,'length':n_steps,
            'irregular':irregular}
    return {'mode':mode,'seed':seed,'active_parameters':sum(p.numel() for p in model.parameters()),
            'optimizer_updates':steps,'train_length':length,'train_batch':batch,
            'training_wall_s':duration,'last_loss':last_loss,'results':performance}


def run(seeds=(11,23,37),steps=120,batch=48,length=42,eval_n=192):
    torch.set_num_threads(1)
    rows=[]
    for seed in seeds:
        for mode in MODES:
            rows.append(train_one(mode,seed,steps=steps,batch=batch,length=length,eval_n=eval_n))
    summary={}
    for mode in MODES:
        group=[r for r in rows if r['mode']==mode]
        summary[mode]={k:{metric:sum(r['results'][k][metric] for r in group)/len(group)
                               for metric in ('soft_accuracy','hard_accuracy',
                                            'event_accuracy','event_precision','event_recall')}
                       for k in ('id','long_irregular')}
    return {'schema':'hcsn.p2-learned-context-boundary.v1',
        'notes':'Auxiliary supervised context-change targets; hard reset at learned threshold. This is not unsupervised QVI or general HX A7. Equal parameters and updates, not matched FLOPs or full pretrained Encoder.',
        'seeds':list(seeds),'rows':rows,'summary':summary,
        'scientific_p0_p6_accepted':False,'production_activation':False}


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--steps',type=int,default=120)
    p.add_argument('--batch',type=int,default=48)
    p.add_argument('--length',type=int,default=42)
    p.add_argument('--eval-n',type=int,default=192)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    a=p.parse_args()
    if a.output.exists():p.error('Refusing to overwrite output evidence')
    result=run(tuple(a.seeds),a.steps,a.batch,a.length,a.eval_n)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result['summary'],sort_keys=True,indent=2))
