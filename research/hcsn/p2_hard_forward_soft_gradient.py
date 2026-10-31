"""P2 hard-forward/soft-backward surrogate; exploratory research ONLY.

A diagnostic for the soft-training / hard-inference mismatch.  It deliberately
uses a surrogate gradient, so it cannot support the claim that HCSN needs no
surrogate for hard events.  It also doubles the step kernel work and does not
close any P0-P6 scientific gate.
"""
from __future__ import annotations
import argparse,hashlib,json,time
from pathlib import Path
import numpy as np
import torch
from torch.nn import functional as F
from .p2_learned_autonomous_content import AutonomousBoundaryMemory,MODES,NKEYS
from .p2_multiquery_noevent import make_mqar,rollout,_accuracy


def rollout_st(model,x,*,state=None):
    """Hard event path forward; soft differentiable path backward (STE).

    hard_memory is evaluated under no_grad and exact at current state.  The
    gradient goes only through soft_memory, a surrogate that is NOT the event
    time derivative of a true stopping-time problem.
    """
    if x.ndim!=3 or x.shape[1]<1:raise ValueError('nonempty [B,L,D] required')
    if state is None:state=model.initial(x)
    outs=[]
    for t in range(x.shape[1]):
        xt=x[:,t,:]
        soft,_,_,_,_,_=model._step(xt,state,False)
        with torch.no_grad():
            hard,_,_,_,_,_=model._step(xt,state,True)
        mem=hard.memory+(soft.memory-soft.memory.detach())
        state=type(soft)(mem,soft.context,soft.initialized)
        outs.append(model.output_gain*(mem*xt[:,:NKEYS]).sum(-1)+model.output_bias)
    return torch.stack(outs,1),state


def train_one_st(mode,seed,*,steps=30,batch=12,length=56,eval_n=48,lr=.012):
    if mode not in MODES:raise ValueError('invalid mode')
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=AutonomousBoundaryMemory(mode)
    opt=torch.optim.Adam(model.parameters(),lr=lr)
    started=time.perf_counter()
    max_g=0.0
    for step in range(steps):
        x,y,q,_=make_mqar(batch,length,4,seed*100000+step)
        opt.zero_grad(set_to_none=True)
        logits,_=rollout_st(model,x)
        loss=F.binary_cross_entropy_with_logits(logits[q],y[q]);loss.backward()
        for name,p in model.named_parameters():
            if p.grad is None and mode=='no_reset' and name=='temperature_raw':continue
            if p.grad is None or not bool(p.grad.isfinite().all()):
                raise ArithmeticError('missing/nonfinite surrogate gradient: '+name)
            max_g=max(max_g,float(p.grad.abs().max()))
        torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
        opt.step()
    wall=time.perf_counter()-started
    out={}
    with torch.no_grad():
        for tag,L,S,irr,evseed in [('id',length,4,False,88000),
                                   ('ood_long_irregular',length*2,6,True,99000)]:
            x,y,q,ev=make_mqar(eval_n,L,S,evseed+seed,irregular=irr)
            ste,_=rollout_st(model,x)
            hard,_,hit=rollout(model,x,hard=True,trace=True)
            soft,_,_=rollout(model,x)
            if not torch.allclose(ste,hard,atol=1e-6,rtol=1e-5):
                raise AssertionError('hard-forward training parity failed')
            true_hits=(hit & ev).sum()
            out[tag]={
                'hard_accuracy':_accuracy(hard,y,q),
                'surrogate_forward_accuracy':_accuracy(ste,y,q),
                'plain_soft_accuracy':_accuracy(soft,y,q),
                'hard_vs_surrogate_max_logit_abs':float((hard-ste).abs().max()),
                'crossings_per_stream':float(hit.sum()/eval_n),
                'event_precision':float(true_hits/hit.sum().clamp(min=1)),
                'event_recall':float(true_hits/ev.sum()),
                'samples':eval_n,'length':L,
            }
    return {'mode':mode,'seed':seed,'steps':steps,'batch':batch,
            'total_declared_parameters':sum(p.numel() for p in model.parameters()),
            'max_absolute_surrogate_gradient':max_g,
            'train_wall_seconds':wall,'last_loss':float(loss.detach()),
            'results':out}


def run(seeds=(11,23,37),steps=30,batch=12,length=56,eval_n=48):
    records=[train_one_st(mode,seed,steps=steps,batch=batch,length=length,eval_n=eval_n)
             for seed in seeds for mode in MODES]
    summary={tag:{mode:{metric:float(np.mean([r['results'][tag][metric] for r in records
                                              if r['mode']==mode]))
                        for metric in ('hard_accuracy','plain_soft_accuracy',
                                       'surrogate_forward_accuracy',
                                       'hard_vs_surrogate_max_logit_abs',
                                       'event_precision','event_recall',
                                       'crossings_per_stream')}
                  for mode in MODES}
             for tag in ('id','ood_long_irregular')}
    return {'schema':'hcsn.p2-hard-forward-soft-backward.exploratory.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'surrogate_gradient':True,
            'disclaimer':'This is a hard-event surrogate, not true event-time differentiation; two forward cores per time step, no compute match, explicit context, three seeds, P0-P6 OPEN.',
            'scientific_gates_closed':False,'production_activation':False,
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
    if a.output.exists():p.error('output exists: refuse overwrite')
    result=run(tuple(a.seeds),a.steps,a.batch,a.length,a.eval_n)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result['summary'],sort_keys=True,indent=2))
