"""P1 research control: C1 piecewise cubic-Hermite Call/Put approximation.

The normalized HX-inspired Call/Put neurons for fixed r/delta/sigma depend
ONLY on the single log-margin m=log(V/Vb), not on other finance quantities.
This is an independent ordinary *table lookup* control that matches the
analytic feature value and signed derivative at every grid knot; no
per-token option closed form is evaluated by the replacement.

Not a proof of model efficacy, not FLOP matched, not a true model of the
original coupled He--Xiong equity Eq.(A7).  Demonstrates an ability to
isolate intrinsic *activation shape* from closed-form evaluation cost.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import time
from pathlib import Path
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
try:
    from .train_study import MatchedHead,make_data,train_one,two_features
    from .p1_audit import _regret_on_states
except ImportError:
    from train_study import MatchedHead,make_data,train_one,two_features
    from p1_audit import _regret_on_states


def physical_beta():
    r,delta,sigma=.05,.03,.2
    mu=r-delta-.5*sigma*sigma
    return (mu+math.sqrt(mu*mu+2*r*sigma*sigma))/(sigma*sigma)


class HermiteGate(nn.Module):
    def __init__(self,num_knots:int=1321,lo:float=-12.,hi:float=3.):
        super().__init__()
        if num_knots<17 or (num_knots-1)%11 or not (lo<0<hi):
            raise ValueError('Require declared Hermite knot density and margin support')
        b=physical_beta(); a=b/(b+1)
        nodes=torch.linspace(lo,hi,num_knots,dtype=torch.float64)
        ep=torch.exp(nodes)
        eq=torch.exp(-b*nodes)
        right=nodes>0
        c=torch.where(right,a*ep-1+(1-a)*eq,torch.zeros_like(nodes))
        cp=torch.where(right,a*(ep-eq),torch.zeros_like(nodes))
        p=torch.where(right,(1-a)*eq,1-a*ep)
        pp=torch.where(right,-b*(1-a)*eq,-a*ep)
        self.register_buffer('knots',nodes)
        self.register_buffer('values',torch.stack((c,p),-1))
        self.register_buffer('slopes',torch.stack((cp,pp),-1))
        self.register_buffer('beta',torch.tensor(b,dtype=torch.float32))

    def forward(self,m:torch.Tensor):
        if not bool(torch.isfinite(m).all()) or not bool(((m>=self.knots[0])&(m<=self.knots[-1])).all()):
            raise ValueError('Input margin outside declared C1 table interval')
        md=m.to(dtype=torch.float64)
        i=torch.searchsorted(self.knots,md.contiguous(),right=False).clamp(1,len(self.knots)-1)-1
        lo=self.knots[i];hi=self.knots[i+1]
        length=hi-lo
        t=(md-lo)/length
        y0,y1=self.values[i],self.values[i+1]
        s0,s1=self.slopes[i],self.slopes[i+1]
        h00=2*t**3-3*t**2+1
        h10=t**3-2*t**2+t
        h01=-2*t**3+3*t**2
        h11=t**3-t**2
        out=(h00[...,None]*y0+h10[...,None]*length[...,None]*s0
                +h01[...,None]*y1+h11[...,None]*length[...,None]*s1)
        return out.to(m.dtype)


class HermiteMatchedHead(MatchedHead):
    def __init__(self,width=20,num_knots=1321):
        super().__init__('dual_call_put',width=width)
        self.gate=HermiteGate(num_knots)

    def transformed(self,x:torch.Tensor):
        p,q,c,n=x.unbind(-1)
        v=2*torch.minimum(p,1-p).clamp(min=1e-5)
        k=1+.5*c
        beta=self.gate.beta
        vb=beta/(beta+1)*k
        m=torch.log(v/vb)
        return self.gate(m)

    def forward(self,x:torch.Tensor):
        if x.ndim!=2 or x.shape[1]!=4:
            raise ValueError('Expected [batch,4] public belief observations')
        feat=torch.cat((x[:,:3],x[:,3:4]/5,self.transformed(x)),1)
        return self.out(torch.tanh(self.proj(feat))).squeeze(-1)


def train_hermite(seed:int,steps:int=90,train_rows:int=512):
    torch.manual_seed(seed)
    model=HermiteMatchedHead()
    opt=torch.optim.Adam(model.parameters(),lr=.008)
    x,y=make_data(seed+123000,train_rows)
    t0=time.perf_counter()
    for _ in range(steps):
        opt.zero_grad(set_to_none=True)
        loss=F.mse_loss(model(x),5*y)
        loss.backward()
        if not all(z.grad is not None and bool(torch.isfinite(z.grad).all()) for z in model.parameters()):
            raise ArithmeticError('Missing gradient in Hermite matched control')
        opt.step()
    return model.eval(),{'parameters':sum(z.numel() for z in model.parameters()),
            'train_sec_cpu':time.perf_counter()-t0,'loss':float(loss.detach())}


def run_hermite_audit(seeds=(11,23,37),steps=90,rows=420):
    torch.set_num_threads(1)
    frozen={}
    for ood,tag,seed in [(False,'id',726381),(True,'ood',726382)]:
        x,_=make_data(seed,rows,ood=ood)
        frozen[tag]=(x,hashlib.sha256(x.numpy().tobytes()).hexdigest())
    results=[]
    for seed in seeds:
        plain,rec_plain=train_one('dual_call_put',seed,steps=steps)
        lookup,rec_lookup=train_hermite(seed,steps=steps)
        assert rec_plain['trainable_parameters']==rec_lookup['parameters']==161
        scores={}
        for tag,(x,h) in frozen.items():
            scores[tag]={'analytic':float(_regret_on_states(plain,x).mean()),
                         'c1_lookup':float(_regret_on_states(lookup,x).mean())}
        results.append({'seed':seed,'scores':scores,'analytic_training':rec_plain,
                        'lookup_training':rec_lookup})
    # Independent heldout feature/Jacobian test, not recycled train points.
    x,_=make_data(917253,512,ood=True)
    m=HermiteMatchedHead()
    xf=x.clone().requires_grad_(True)
    feat1=two_features(xf,'dual_call_put')
    feat2=m.transformed(xf)
    diff=float((feat1-feat2).abs().max().detach())
    # Coupled vector-Jacobian product checks the signed slopes wrt all inputs.
    j1=torch.autograd.grad(feat1.sum(),xf,retain_graph=True)[0]
    j2=torch.autograd.grad(feat2.sum(),xf)[0]
    jac=float((j1-j2).abs().max().detach())
    return {'schema':'hcsn.p1-c1-lookup-shaped-null.v1','seeds':list(seeds),
            'frozen_input_sha256':{k:v[1] for k,v in frozen.items()},
            'optimization_steps':steps,'rows_per_split':rows,'matched_trainables':161,
            'lookup_knots':1321,'lookup_support':[-12.,3.],
            'heldout_max_feature_abs_error':diff,'heldout_max_signed_vjp_error':jac,
            'results':results,'flops_matched':False,'p1_closed':False,
            'interpretation':'A first-order shape-matched table-based null; evidence about closed form evaluation versus shape, NOT superior HCSN capability.'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--steps',type=int,default=90)
    p.add_argument('--rows',type=int,default=420)
    a=p.parse_args()
    if a.output.exists():p.error('Refusing overwrite')
    out=run_hermite_audit(steps=a.steps,rows=a.rows)
    out['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
    for z in out['results']:print(z['seed'],z['scores'],flush=True)
    print('max value/jacobian errors',out['heldout_max_feature_abs_error'],out['heldout_max_signed_vjp_error'])
