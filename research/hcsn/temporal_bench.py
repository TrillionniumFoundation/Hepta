"""P2 REAL unrolled BP/BPTT smoke harness: selective copy, MQAR, irregular time.

Train/heldout seeds are disjoint. Includes a same-parameter ordinary-gated
recurrent control and a similar-size GRU. Short synthetic tasks only: NOT a
pre-registered performance benchmark and NOT a claim of P2 closure.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import time

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

INPUT_DIM=12


def make_sequences(task:str,n:int,t:int,seed:int,*,irregular:bool=False):
    if task not in ('selective_copy','mqar') or t<12 or n<1:
        raise ValueError('Unsupported task or shape')
    g=np.random.default_rng(seed)
    x=np.zeros((n,t,INPUT_DIM),dtype=np.float32)
    y=np.zeros((n,),dtype=np.float32)
    for i in range(n):
        x[i,:,8]=g.choice([-1.,1.],size=t)
        x[i,:,11]=g.uniform(.05,1.3 if not irregular else 3.,size=t)
        if task=='selective_copy':
            marked=np.sort(g.choice(np.arange(1,t-1),size=3,replace=False))
            x[i,marked,9]=1.
            x[i,-1,10]=1.
            y[i]=float(x[i,marked[-1],8]>0)
        else:
            # Four key/value pairs are written, once each, to random positions.
            keys=g.choice(8,size=4,replace=False)
            times=np.sort(g.choice(np.arange(1,t-1),size=4,replace=False))
            values=g.choice([-1.,1.],size=4)
            for idx,key in enumerate(keys):
                x[i,times[idx],int(key)]=1.
                x[i,times[idx],8]=values[idx]
                x[i,times[idx],9]=1.
            query=int(g.integers(0,4))
            x[i,-1,int(keys[query])]=1.
            x[i,-1,10]=1.
            y[i]=float(values[query]>0)
    return torch.from_numpy(x),torch.from_numpy(y)


class BoundaryRNN(nn.Module):
    """Call/Put/margin gate actually participates in recurrent state update."""
    def __init__(self,width:int=16,mode:str='free_boundary'):
        super().__init__()
        if mode not in ('free_boundary','ordinary_gate','free_boundary_v2','ordinary_gate_v2'):
            raise ValueError('Invalid gate')
        self.mode=mode
        self.in_proj=nn.Linear(INPUT_DIM,width)
        self.rec_proj=nn.Linear(width,width,bias=False)
        self.gate_proj=nn.Linear(width*3,width)
        self.readout=nn.Linear(width,1)
        self.raw_r=nn.Parameter(torch.tensor(-2.2))
        self.raw_delta=nn.Parameter(torch.tensor(-3.0))
        self.raw_sigma=nn.Parameter(torch.tensor(-1.1))
        self.raw_k=nn.Parameter(torch.tensor(0.2))
        self.raw_leak=nn.Parameter(torch.tensor(0.2))

    def forward(self,x):
        if x.ndim!=3 or x.shape[-1]!=INPUT_DIM or x.shape[1]==0:
            raise ValueError('Input expected [B,T,12]')
        h=x.new_zeros((x.shape[0],self.in_proj.out_features))
        r=F.softplus(self.raw_r)+.002
        delta=F.softplus(self.raw_delta)+.002
        sigma=F.softplus(self.raw_sigma)+.01
        k=F.softplus(self.raw_k)+.1
        D=sigma.square()
        a=(r-delta-.5*D)/D
        beta=torch.sqrt(a.square()+2*r/D)+a
        boundary=k*beta/(beta+1)
        leak=F.softplus(self.raw_leak)+.005
        for step in range(x.shape[1]):
            dt=x[:,step,11:12]
            retain=torch.exp(-dt*leak)
            proposal=torch.tanh(self.in_proj(x[:,step])+self.rec_proj(h))
            candidate=retain*h+(1-retain)*proposal
            if self.mode.startswith('free_boundary'):
                v=torch.exp(candidate.clamp(-7.,7.))
                margin=torch.log(v)-torch.log(boundary)
                m=margin.clamp(min=0.)
                # Cancel low-order terms symbolically near boundary.
                approx=boundary*(.5*(1+beta)*m.square()
                    +(1-beta.square())*m.pow(3)/6
                    +(1+beta.pow(3))*m.pow(4)/24)
                regular=boundary*(torch.expm1(m)+torch.expm1(-beta*m)/beta)
                call=torch.where(m<.002,approx,regular)
                put=torch.where(margin>0,(k-boundary)*torch.exp(-beta*m),k-v)
                features=torch.cat((call/k,put/k,torch.tanh(margin)),dim=-1)
            else:
                # Same recurrent architecture, same 5 scalar trainable
                # parameters, same gate_proj widths and exact parameter count.
                # Harmless zero-valued trainable dependency to maintain
                # architecture count; no false claims of equal FLOPs.
                b=boundary+0.*(r+delta+sigma+k)
                margin=candidate-b
                features=torch.cat((torch.sigmoid(4*margin),
                        torch.sigmoid(-4*margin),torch.tanh(margin)),dim=-1)
            if self.mode.endswith('_v2'):
                # Learned selective memory write. Both analytic and ordinary
                # variants have identical parameters and update equation.
                gate=torch.sigmoid(self.gate_proj(features))
                h=h+(1-retain)*gate*(proposal-h)
            else:
                h=candidate+.15*torch.tanh(self.gate_proj(features))
        return self.readout(h).squeeze(-1)


class GRUControl(nn.Module):
    def __init__(self,width=15):
        super().__init__()
        self.rec=nn.GRU(INPUT_DIM,width,batch_first=True)
        self.readout=nn.Linear(width,1)
    def forward(self,x):
        return self.readout(self.rec(x)[0][:,-1]).squeeze(-1)


def model_for(name:str):
    if name=='hcsn':return BoundaryRNN(mode='free_boundary')
    if name=='ordinary':return BoundaryRNN(mode='ordinary_gate')
    if name=='hcsn_v2':return BoundaryRNN(mode='free_boundary_v2')
    if name=='ordinary_v2':return BoundaryRNN(mode='ordinary_gate_v2')
    if name=='gru':return GRUControl()
    raise ValueError('Invalid architecture')


def train_temporal(task:str,model_name:str,seed:int=1,steps:int=120,
                   batch_size:int=48,train_length:int=24):
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=model_for(model_name)
    opt=torch.optim.Adam(model.parameters(),lr=.008)
    elapsed=time.perf_counter()
    for update in range(steps):
        train_x,train_y=make_sequences(task,batch_size,train_length,
                                      seed*100000+update)
        opt.zero_grad(set_to_none=True)
        scores=model(train_x)
        loss=F.binary_cross_entropy_with_logits(scores,train_y)
        loss.backward()
        if not all(p.grad is not None and torch.isfinite(p.grad).all().item() for p in model.parameters()):
            raise ArithmeticError('Missing or nonfinite BPTT gradient')
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        opt.step()
    seconds=time.perf_counter()-elapsed
    outcomes={}
    model.eval()
    for name,n,T,held_seed,irregular in [('id',256,train_length,800001,False),
                                        ('long_irregular',256,train_length*2,900001,True)]:
        x,y=make_sequences(task,n,T,held_seed,irregular=irregular)
        t0=time.perf_counter()
        with torch.inference_mode():
            z=model(x)
            ce=float(F.binary_cross_entropy_with_logits(z,y))
            accuracy=float(((z>0)==(y>.5)).float().mean())
        outcomes[name]={'accuracy':accuracy,'cross_entropy':ce,'n':n,
                        'length':T,'latency_ms_per_sequence_cpu':
                         1000*(time.perf_counter()-t0)/n}
    return {'task':task,'architecture':model_name,'seed':seed,'steps':steps,
            'parameters':sum(p.numel() for p in model.parameters()),
            'train_elapsed_sec_cpu':seconds,'train_last_loss':float(loss.detach()),
            'outcomes':outcomes}


def run_panel(steps=120):
    rows=[]
    for task in ('selective_copy','mqar'):
        for name in ('hcsn','ordinary','gru','hcsn_v2','ordinary_v2'):
            rows.append(train_temporal(task,name,steps=steps))
    return {'schema':'hcsn.p2-temporal-smoke.v1','steps':steps,'rows':rows,
            'hardware':'CPU-only, PyTorch eager','pre_registered':False,
            'p2_closed':False,
            'notes':'Short train, long irregular heldout. No SSM/SpikingSSM and no power measurement.'}


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--steps',type=int,default=120)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    if args.output.exists():ap.error('Refusing overwrite')
    result=run_panel(steps=args.steps)
    result['sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for r in result['rows']:
        print(r['task'],r['architecture'],'params',r['parameters'],
              'id',r['outcomes']['id']['accuracy'],
              'long',r['outcomes']['long_irregular']['accuracy'],
              'sec',round(r['train_elapsed_sec_cpu'],2),flush=True)
