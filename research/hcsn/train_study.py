"""Exploratory analytic-channel versus ordinary-gate supervised value study.

All variants receive the SAME four public coordinates, active parameter count,
seeds and Adam update budget. Two additional fixed differentiable transforms
are controlled by `mode`. The task target is independent exact Bayes-Bellman
READ advantage, NOT the He--Xiong equity function. This does NOT match local
slopes, kernel FLOPs, or independent public preregistration; P1 stays OPEN.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import time

import torch
from torch import nn
from torch.nn import functional as F

try:
    from .boundary_content_bridge import (PublicState, SealedEpisode, _episode_seed,
          advantage, execute, policy_value, sample_public, value)
except ImportError:
    from boundary_content_bridge import (PublicState, SealedEpisode, _episode_seed,
          advantage, execute, policy_value, sample_public, value)

MODES=('call_only','put_only','margin_only','dual_call_put','ordinary_two_gate')


def two_features(x:torch.Tensor,mode:str) -> torch.Tensor:
    p,q,c,n=x.unbind(-1)
    v=2*torch.minimum(p,1-p).clamp(min=1e-5)
    k=1+.5*c
    r,delta,sigma=.05,.03,.20
    t=r-delta-.5*sigma**2
    beta=(t+math.sqrt(t*t+2*r*sigma**2))/sigma**2
    vb=(beta/(beta+1))*k
    log_ratio=torch.log(v)-torch.log(vb)
    option=(k-vb)*torch.exp(-beta*log_ratio.clamp(min=0))
    call=torch.where(v>vb,v-k+option,torch.zeros_like(v))/k
    put=torch.where(v>vb,option,k-v)/k
    margin=torch.tanh(log_ratio)
    if mode=='call_only':return torch.stack((call,call.square()),-1)
    if mode=='put_only':return torch.stack((put,put.square()),-1)
    if mode=='margin_only':return torch.stack((margin,margin.square()),-1)
    if mode=='dual_call_put':return torch.stack((call,put),-1)
    if mode=='ordinary_two_gate':
        base=torch.maximum(p,1-p)
        return torch.stack((torch.sigmoid(12*(q-base-c)),
                            torch.sigmoid(8*(q-base))),-1)
    raise ValueError('Invalid feature mode')


def vector_features(x:torch.Tensor,mode:str) -> torch.Tensor:
    if x.ndim!=2 or x.shape[1]!=4:
        raise ValueError('Inputs must be [batch, 4] public belief/q/cost/budget')
    return torch.cat((x[:,:3],x[:,3:4]/5,two_features(x,mode)),dim=-1)


class MatchedHead(nn.Module):
    def __init__(self,mode:str,width:int=20):
        super().__init__()
        if mode not in MODES:raise ValueError('Invalid mode')
        self.mode=mode
        self.proj=nn.Linear(6,width)
        self.out=nn.Linear(width,1)

    def forward(self,x):
        return self.out(torch.tanh(self.proj(vector_features(x,self.mode)))).squeeze(-1)


def make_data(seed:int,n:int,*,ood:bool=False):
    rng=random.Random(seed+(1 if ood else 0)*98765)
    records=[]
    for _ in range(n):
        if ood:
            p=rng.uniform(.01,.99);q=rng.uniform(.51,.99)
            c=rng.uniform(0.,.2);steps=rng.randrange(1,6)
        else:
            p=rng.uniform(.05,.95);q=rng.uniform(.6,.95)
            c=rng.uniform(.005,.13);steps=rng.randrange(1,5)
        s=PublicState(p,q,c,steps)
        records.append((p,q,c,steps,advantage(s)))
    tensor=torch.tensor(records,dtype=torch.float32)
    return tensor[:,:4],tensor[:,4]


def train_one(mode,seed,*,train_rows=512,steps=90,lr=.008):
    torch.manual_seed(seed)
    model=MatchedHead(mode)
    optimizer=torch.optim.Adam(model.parameters(),lr=lr)
    x,y=make_data(seed+123000,train_rows)
    t0=time.process_time_ns()
    # All variants share exactly these training rows and optimizer updates.
    for _ in range(steps):
        optimizer.zero_grad(set_to_none=True)
        pred=model(x)
        loss=F.mse_loss(pred,5*y)
        loss.backward()
        if not all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
            raise ArithmeticError('Missing/nonfinite trained gradient')
        optimizer.step()
    cpu=time.process_time_ns()-t0
    return model,{'seed':seed,'mode':mode,'train_samples':train_rows,
                  'optimizer_updates':steps,'train_process_cpu_ns':cpu,
                  'last_train_mse_scaled':float(loss.detach()),
                  'trainable_parameters':sum(p.numel() for p in model.parameters())}


def inference_policy(model):
    model.eval()
    def act(s):
        if s.remaining==0:return False
        x=torch.tensor([[s.p,s.q,s.cost,float(s.remaining)]],dtype=torch.float32)
        with torch.no_grad():return bool(model(x).item()>0)
    return act


def evaluate(model,*,seed=181,n=150,ood=False):
    rng=random.Random(seed+(70000 if ood else 0))
    pol=inference_policy(model)
    reads=0;quality=0;utility=0.;regret=0.;cpu=0
    for i in range(n):
        s=sample_public(rng,ood=ood)
        a,b=_episode_seed(seed,i)
        truth=1 if random.Random(a).random()<s.p else -1
        obs=execute(SealedEpisode(s,truth,b),pol)
        reads+=obs['reads'];quality+=obs['correct'];utility+=obs['utility']
        cpu+=obs['process_cpu_ns']
        regret+=max(0.,value(s.p,s.q,s.cost,s.remaining)-policy_value(s,pol))
    return {'episodes':n,'mean_reads':reads/n,'quality':quality/n,
            'mean_utility':utility/n,'exact_regret':regret/n,
            'inference_process_cpu_ns':cpu,'energy_joules':None}


def study(*,seeds=(11,23,37),train_rows=512,steps=90,eval_rows=150):
    torch.set_num_threads(1)
    rows=[]
    # Loop seed then mode. Each seed's input stream and test trajectories match.
    for seed in seeds:
        for mode in MODES:
            model,record=train_one(mode,seed,train_rows=train_rows,steps=steps)
            record['id']=evaluate(model,seed=seed+810001,n=eval_rows)
            record['ood']=evaluate(model,seed=seed+920001,n=eval_rows,ood=True)
            rows.append(record)
    summary={}
    for mode in MODES:
        group=[r for r in rows if r['mode']==mode]
        summary[mode]={}
        for field in ('id','ood'):
            summary[mode][field]={metric:sum(row[field][metric] for row in group)/len(group)
                                  for metric in ('mean_reads','quality','mean_utility','exact_regret')}
    return {'schema':'hcsn.boundary-content-ablation.exploratory-v1',
            'modes':list(MODES),'seeds':list(seeds),'rows':rows,'summary':summary,
            'protocol':'fixed active parameter count, optimizer settings, input labels and test episodes; NOT signed-slope or measured FLOP matching',
            'source':'independent exact finite-horizon Bayesian task-value labels; no future observation leaks into policy',
            'production_activation':False,'p1_causal_superiority_gate_closed':False,
            'full_p0_p6_scientific_closure':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--steps',type=int,default=90)
    parser.add_argument('--train-rows',type=int,default=512)
    parser.add_argument('--eval-rows',type=int,default=150)
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing to overwrite existing result')
    result=study(steps=args.steps,train_rows=args.train_rows,eval_rows=args.eval_rows)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result['summary'],indent=2))
