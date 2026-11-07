"""P2 learned-state, real BPTT, multiple-reset and joint-recall falsification test.

The experiment includes TWO declared external reset markers. These cause
an input-conditioned free-boundary shift and an actual neural state reset;
that is NOT a demonstration of learned autonomous endogenous spike timing.
The first-passage channel is evaluated for frozen per-step GBM parameters,
not a solution of a time-dependent stochastic control QVI.

Analytic and ordinary-gated controls share the same recurrent trainables,
first-passage kernel, reset budget, data, and training protocol. It isolates
analytic Call/Put features, not the overall utility of the renewal mechanism.
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

DIM=13


def make_joint_reset(n:int,length:int,seed:int,*,irregular:bool):
    if length<21 or n<1:raise ValueError('unsupported multi-reset episode')
    rng=np.random.default_rng(seed)
    x=np.zeros((n,length,DIM),np.float32)
    y=np.empty(n,np.float32)
    for i in range(n):
        reset_times=(length//3,2*length//3)
        x[i,:,11]=rng.uniform(.15,1.2 if not irregular else 2.5,size=length)
        x[i,:,8]=rng.choice([-1.,1.],size=length)
        x[i,list(reset_times),12]=1.
        # Earlier segments contain incompatible distractors on the exact
        # queried keys, preventing shortcuts based on global write counts.
        keys=rng.choice(8,size=2,replace=False)
        vals=rng.choice([-1.,1.],size=2)
        for section in (0,1,2):
            lo=1 if section==0 else reset_times[section-1]+1
            hi=reset_times[section] if section<2 else length-1
            if hi-lo<3:raise ValueError('not enough writes per section')
            locs=rng.choice(np.arange(lo,hi),size=2,replace=False)
            for j,k in enumerate(keys):
                x[i,locs[j],int(k)]=1.
                x[i,locs[j],9]=1.
                x[i,locs[j],8]=(-vals[j] if section<2 else vals[j])
        x[i,-1,keys]=1.
        x[i,-1,10]=1.
        x[i,-1,8]=0.
        y[i]=float(vals[0]==vals[1])
    return torch.from_numpy(x),torch.from_numpy(y)


def _hitting_probability(margin:torch.Tensor,dt:torch.Tensor,
                         drift:torch.Tensor,sigma:torch.Tensor):
    """GBM first-passage CDF for m>=0; explicit immediate crossing for m<=0.

    Note that the smooth part is conditional on frozen drift/vol/boundary.
    All exponential arguments are guarded for numerical safety.
    """
    z=margin.clamp(min=0.)
    den=sigma*torch.sqrt(dt)
    a=(-z-drift*dt)/den
    b=(-z+drift*dt)/den
    exp_arg=(-2*drift*z/sigma.square()).clamp(-60.,60.)
    p=torch.special.ndtr(a)+torch.exp(exp_arg)*torch.special.ndtr(b)
    return torch.where(margin<=0,torch.ones_like(p),p.clamp(0,1))


class RegenerativeRNN(nn.Module):
    def __init__(self,width=16,mode='analytic'):
        super().__init__()
        if mode not in ('analytic','ordinary'):
            raise ValueError('unrecognized baseline')
        self.mode=mode
        self.in_proj=nn.Linear(DIM,width)
        self.rec_proj=nn.Linear(width,width,bias=False)
        self.bound_proj=nn.Linear(width+DIM,width)
        self.mix=nn.Linear(4*width,width)
        self.readout=nn.Linear(width,1)
        self.reset_state=nn.Parameter(torch.full((width,),1.))
        self.raw_r=nn.Parameter(torch.tensor(-2.3))
        self.raw_delta=nn.Parameter(torch.tensor(-3.1))
        self.raw_sigma=nn.Parameter(torch.tensor(-1.1))
        self.raw_k=nn.Parameter(torch.tensor(.25))
        self.raw_leak=nn.Parameter(torch.tensor(-.05))

    def forward(self,x:torch.Tensor,*,hard:bool=False,trace:bool=False):
        if x.ndim!=3 or x.shape[-1]!=DIM or x.shape[1]==0 or not bool(torch.isfinite(x).all()):
            raise ValueError('expected finite [B,T,13]')
        h=x.new_zeros((len(x),self.reset_state.numel()))
        r=F.softplus(self.raw_r)+.002
        delta=F.softplus(self.raw_delta)+.002
        sigma=F.softplus(self.raw_sigma)+.01
        ss=sigma.square()
        a=(r-delta-.5*ss)/ss
        beta=torch.hypot(a,torch.sqrt(2*r/ss))+a
        k=F.softplus(self.raw_k)+.1
        b0=k*beta/(1+beta)
        leak=F.softplus(self.raw_leak)+.005
        drift=r-delta-.5*ss
        traces=[]
        for time_index in range(x.shape[1]):
            xt=x[:,time_index]
            dt=xt[:,11:12].clamp(.05,3.)
            retain=torch.exp(-leak*dt)
            proposal=torch.tanh(self.in_proj(xt)+self.rec_proj(h))
            candidate=retain*h+(1-retain)*proposal
            # Semantic reset markers intentionally push the instantaneous
            # optimal boundary above the neural activation reserve.
            logb=torch.log(b0)+.18*torch.tanh(self.bound_proj(torch.cat((h,xt),1)))\
                 + 6.*xt[:,12:13]
            margin=candidate.clamp(-8,8)-logb
            m=margin.clamp(min=0.)
            b=torch.exp(logb.clamp(-40,40))
            local_k=b*(1+beta)/beta
            near=b*(.5*(1+beta)*m.square()+(1-beta.square())*m.pow(3)/6
                    +(1+beta.pow(3))*m.pow(4)/24)
            direct=b*(torch.expm1(m)+torch.expm1(-beta*m)/beta)
            call=torch.where(m<=.002,near,direct)/local_k
            put=torch.where(margin<=0,local_k-torch.exp(candidate.clamp(-8,8)),
                b/beta*torch.exp(-beta*m))/local_k
            q=_hitting_probability(margin,dt,drift,sigma)
            if self.mode=='analytic':
                features=torch.cat((call,put,torch.tanh(margin),q),1)
            else:
                features=torch.cat((torch.sigmoid(3*margin),
                    torch.sigmoid(-3*margin),torch.tanh(margin),q),1)
            write=torch.sigmoid(self.mix(features))
            renewed=h+(1-retain)*write*(proposal-h)
            if hard:
                event=margin<=0
                h=torch.where(event,self.reset_state.expand_as(h),renewed)
            else:
                event=margin<=0
                h=(1-q)*renewed+q*self.reset_state
            if trace:
                traces.append({'event':event.detach(),
                    'mean_event_probability':q.detach().mean(),
                    'min_margin':margin.detach().min()})
        logits=self.readout(h).squeeze(-1)
        return (logits,traces) if trace else logits



class ResetGRU(nn.Module):
    """Comparable recurrent control; explicit reset markers, not HX features."""
    def __init__(self,width=19):
        super().__init__()
        self.cell=nn.GRUCell(DIM,width)
        self.readout=nn.Linear(width,1)
    def forward(self,x,*,hard=False,trace=False):
        h=x.new_zeros((len(x),self.cell.hidden_size))
        records=[]
        for t in range(x.shape[1]):
            event=(x[:,t,12:13]>.5).expand_as(h)
            h=self.cell(x[:,t],torch.where(event,torch.zeros_like(h),h))
            if trace:
                records.append({'event':event.detach(),
                     'mean_event_probability':event.float().mean().detach(),
                     'min_margin':x.new_tensor(0.)})
        z=self.readout(h).squeeze(-1)
        return (z,records) if trace else z

def train_joint_reset(mode,seed,steps=170,batch_size=48,length=30):
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=ResetGRU() if mode=='gru' else RegenerativeRNN(mode=mode)
    opt=torch.optim.Adam(model.parameters(),lr=.006)
    start=time.perf_counter()
    for i in range(steps):
        x,y=make_joint_reset(batch_size,length,seed*100000+i,irregular=False)
        opt.zero_grad(set_to_none=True)
        logits=model(x)
        loss=F.binary_cross_entropy_with_logits(logits,y)
        loss.backward()
        if not all(p.grad is not None and torch.isfinite(p.grad).all().item()
                   for p in model.parameters()):
            raise ArithmeticError('BPTT gradient failed or nonfinite')
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        opt.step()
    time_taken=time.perf_counter()-start
    model.eval()
    outcomes={}
    for tag,seq_length,irregular,test_seed in [
        ('id',length,False,800001),('long_irregular',length*2,True,900001)]:
        x,y=make_joint_reset(384,seq_length,test_seed,irregular=irregular)
        with torch.inference_mode():
            logit,trace=model(x,trace=True)
            accuracy=float(((logit>0)==(y>.5)).float().mean())
            ce=float(F.binary_cross_entropy_with_logits(logit,y))
            hardlog,hardtrace=model(x,hard=True,trace=True)
            hardacc=float(((hardlog>0)==(y>.5)).float().mean())
            forced=[seq_length//3,2*seq_length//3]
            hard_at_forced=all(bool(hardtrace[t]['event'].all()) for t in forced)
            hard_reset_count=float(torch.stack([z['event'].float().sum() for z in hardtrace]).sum()/len(x))
            hard_reset_ticks=float(torch.stack([z['event'].any(dim=1).float().sum() for z in hardtrace]).sum()/len(x))
        outcomes[tag]={'accuracy_soft':accuracy,'accuracy_hard':hardacc,
            'cross_entropy':ce,'forced_boundary_events_observed':hard_at_forced,
            'hard_neuron_events_per_sequence':hard_reset_count,
            'hard_event_timesteps_per_sequence':hard_reset_ticks,'n':len(x),'length':seq_length}
    return {'mode':mode,'seed':seed,'parameters':sum(p.numel() for p in model.parameters()),
        'train_seconds_cpu':time_taken,'steps':steps,'last_loss':float(loss.detach()),
        'outcomes':outcomes}


def run_panel(steps:int=170,seeds=(11,23,37),batch_size:int=48,length:int=30):
    records=[]
    for seed in seeds:
        for mode in ('analytic','ordinary','gru'):
            records.append(train_joint_reset(mode,seed,steps=steps,
                batch_size=batch_size,length=length))
    return {'schema':'hcsn.p2-multi-reset-joint-recall.v1',
        'task':'two-key equality in final segment after two explicit reset markers',
        'training_reset_semantics':'dynamic boundary forced at reset input; no autonomous spike timing claim',
        'results':records,'seeds':seeds,'steps':steps,
        'batch_size':batch_size,'train_length':length,
        'p2_closed':False,'hardware':'CPU eager; no GPU or energy measurements'}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--steps',type=int,default=170)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    p.add_argument('--batch-size',type=int,default=48)
    p.add_argument('--train-length',type=int,default=30)
    a=p.parse_args()
    if a.output.exists():p.error('refusing overwrite')
    r=run_panel(steps=a.steps,seeds=tuple(a.seeds),
        batch_size=a.batch_size,length=a.train_length)
    r['sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    for line in r['results']:
        print(line['mode'],line['seed'],'ID',line['outcomes']['id']['accuracy_soft'],
            'long',line['outcomes']['long_irregular']['accuracy_soft'],
            'hard',line['outcomes']['long_irregular']['accuracy_hard'],flush=True)
