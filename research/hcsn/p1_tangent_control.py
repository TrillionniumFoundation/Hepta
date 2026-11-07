"""P1 matched-local-Jacobian null: analytically slopes and values match.

Construct an *ordinary sigmoid gate plus affine tangent correction* using
only the anchor point's dual-call-put value and Jacobian.  This is a
first-order matched control at ONE declared anchor, not a globally slope
matched model; it deliberately allows a baseline to share the dual's local
linearization and tests whether its nonlinear curvature matters.

For fair parameter counts both networks use the same 161-parameter head;
learned initialization, data, optimizer, and updates are identical.
The affine adjustment needs no learned parameters; actual kernel FLOPs and
wall-clock differences are explicitly disclosed.  Not an efficacy claim.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import time
from pathlib import Path
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
try:
    from .train_study import MatchedHead,make_data,two_features
    from .p1_audit import _regret_on_states
except ImportError:
    from train_study import MatchedHead,make_data,two_features
    from p1_audit import _regret_on_states

ANCHOR=(.30,.82,.06,3.)
SEEDS=(11,23,37)


def tangent_constants(anchor=ANCHOR):
    x=torch.tensor([anchor],dtype=torch.float64,requires_grad=True)
    def features(z,which):
        return two_features(z,which)[0]
    a=features(x,'ordinary_two_gate')
    b=features(x,'dual_call_put')
    ja=torch.autograd.functional.jacobian(lambda z:features(z,'ordinary_two_gate'),x).reshape(2,4)
    jb=torch.autograd.functional.jacobian(lambda z:features(z,'dual_call_put'),x).reshape(2,4)
    return (x.detach()[0].float(),b.detach().float(),a.detach().float(),
            (jb-ja).detach().float())


class TangentMatchedHead(MatchedHead):
    def __init__(self,width=20,anchor=ANCHOR):
        super().__init__('ordinary_two_gate',width=width)
        x,y,z,j=tangent_constants(anchor)
        self.register_buffer('anchor',x)
        self.register_buffer('dual_at_anchor',y)
        self.register_buffer('ordinary_at_anchor',z)
        self.register_buffer('jacobian_correction',j)

    def transformed(self,x):
        sig=two_features(x,'ordinary_two_gate')
        return sig-self.ordinary_at_anchor+self.dual_at_anchor+(x-self.anchor)@self.jacobian_correction.T

    def forward(self,x):
        if x.ndim!=2 or x.shape[1]!=4:
            raise ValueError('Expected same four public state coordinates')
        z=torch.cat((x[:,:3],x[:,3:4]/5,self.transformed(x)),dim=-1)
        return self.out(torch.tanh(self.proj(z))).squeeze(-1)


def train_tangent(seed:int,steps:int=90,train_rows:int=512):
    torch.manual_seed(seed)
    model=TangentMatchedHead()
    opt=torch.optim.Adam(model.parameters(),lr=.008)
    x,y=make_data(seed+123000,train_rows)
    t0=time.perf_counter()
    for _ in range(steps):
        opt.zero_grad(set_to_none=True)
        loss=F.mse_loss(model(x),5*y)
        loss.backward()
        if not all(p.grad is not None and torch.isfinite(p.grad).all().item()
                   for p in model.parameters()):
            raise ArithmeticError('P1 matched-null missing or nonfinite gradient')
        opt.step()
    return model.eval(),{'train_sec_cpu':time.perf_counter()-t0,'loss':float(loss),
                          'parameters':sum(p.numel() for p in model.parameters())}


def run_tangent_study(rows=150,steps=90):
    torch.set_num_threads(1)
    from .train_study import train_one
    outputs={}
    with torch.enable_grad():
        anchor=torch.tensor([ANCHOR],requires_grad=True)
        def jf(f):return torch.autograd.functional.jacobian(f,anchor).reshape(2,4)
        tm=TangentMatchedHead()
        aj=jf(lambda x:tm.transformed(x)[0])
        bj=jf(lambda x:two_features(x,'dual_call_put')[0])
        mismatch=float((aj-bj).abs().max())
    frozen={}
    for ood,tag,seed in [(False,'id',20261031),(True,'ood',20261032)]:
        x,_=make_data(seed,rows,ood=ood)
        frozen[tag]={'x':x,'sha256':hashlib.sha256(x.numpy().tobytes()).hexdigest()}
    for seed in SEEDS:
        base,brec=train_one('ordinary_two_gate',seed,steps=steps)
        dual,drec=train_one('dual_call_put',seed,steps=steps)
        tangent,trec=train_tangent(seed,steps=steps)
        out={}
        for tag,obj in frozen.items():
            x=obj['x']
            losses={}
            for name,model in [('ordinary',base),('dual',dual),('tangent_ordinary',tangent)]:
                losses[name]=float(_regret_on_states(model,x).mean())
            out[tag]=losses
        outputs[str(seed)]={'outcomes':out,'train':{'ordinary':brec,'dual':drec,'tangent':trec}}
    # Compare actual Jacobian difference AWAY from chosen anchor.
    x=frozen['id']['x'][:36].detach().clone().requires_grad_(True)
    tj=[];dj=[]
    for i in range(len(x)):
        xx=x[i:i+1]
        j1=torch.autograd.functional.jacobian(lambda u:TangentMatchedHead().transformed(u)[0],xx)
        j2=torch.autograd.functional.jacobian(lambda u:two_features(u,'dual_call_put')[0],xx)
        tj.append(float((j1-j2).abs().max()))
    return {'schema':'hcsn.p1-tangent-matched-local-null.v1',
        'anchor':ANCHOR,'anchor_max_abs_jacobian_mismatch':mismatch,
        'off_anchor_max_jacobian_mismatch':max(tj),
        'frozen_input_hashes':{k:v['sha256'] for k,v in frozen.items()},
        'parameters_equal':True,'signed_slope_matched_only_at_anchor':True,
        'global_slope_matched':False,'flops_matched':False,
        'seeds':SEEDS,'rows_per_distribution':rows,'optimizer_updates':steps,
        'by_seed':outputs,'p1_closed':False,
        'interpretation':'First-order tangent match at one anchor controls one local confound only; all-domain and compute confounds remain.'}


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--rows',type=int,default=150)
    p.add_argument('--steps',type=int,default=90)
    a=p.parse_args()
    if a.output.exists():p.error('Refuse overwrite')
    result=run_tangent_study(rows=a.rows,steps=a.steps)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('P1 tangent',json.dumps({s:rr['outcomes'] for s,rr in result['by_seed'].items()},indent=2))
