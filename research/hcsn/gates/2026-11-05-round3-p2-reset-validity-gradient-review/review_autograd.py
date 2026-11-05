"""Zero-fit, synthetic-only backward review of frozen hard-reset P2 source.

Runs the unchanged model; observers only record actual tensors.  No datasets,
checkpoints, optimizers, backward parameter updates, or heldout results are used.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path('/workspace/scratch/4a81596942e6/p2-work')
OUT = Path('/workspace/scratch/4a81596942e6/p2-gradient-review')
FROZEN_SHA = '7ebeaf9069bdd547a2e41d607345a3ce3b29c300d93acf187bdfb51ebc99a02d'
SOURCE = ROOT/'research/hcsn/p2_reset_validity.py'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == FROZEN_SHA
sys.path.insert(0, str(ROOT))
import torch
from torch.nn import functional as F
from research.hcsn import p2_reset_validity as rv

torch.set_num_threads(1)
MODES = [*rv.RESET_VALIDITY_MODES, rv.MAPPED_MODE]


def scalar_summary(x):
    if x is None:
        return {'used': False, 'numel': 0, 'nonzero': 0, 'max_abs': 0., 'l2': 0.}
    z = x.detach()
    assert bool(torch.isfinite(z).all())
    return {'used': True, 'numel': z.numel(), 'nonzero': int(torch.count_nonzero(z)),
            'max_abs': float(z.abs().max()), 'l2': float(torch.linalg.vector_norm(z))}


def serial(x):
    return x.detach().cpu().tolist()


def model_for(mode, dtype, *, write, reset_bias=0., context_feedback=True):
    # These are hand-set diagnostic coefficients, not learned or optimized.
    torch.manual_seed(1907)
    model = rv.RawResetValidityMemory(mode, embedding=2, key_width=2,
                                     value_width=2, control_width=2).to(dtype)
    with torch.no_grad():
        for p in model.parameters():
            p.zero_()
        model.embedding.weight[0] = torch.tensor([1., .2], dtype=dtype)
        model.embedding.weight[1] = torch.tensor([-1., .3], dtype=dtype)
        model.address.weight.copy_(torch.eye(2, dtype=dtype))
        model.value.weight.copy_(torch.tensor([[.4, -.2], [.1, .5]], dtype=dtype))
        model.control.weight[0, 4] = .8
        model.control.weight[1, 4] = 1.
        model.control.weight[:, 3] = .1
        if context_feedback:
            model.control.weight[:, 0] = torch.tensor([.15, .2], dtype=dtype)
        model.control.bias[0] = .1
        model.control_logits.weight.copy_(torch.tensor([[1., .1], [.2, 1.4]], dtype=dtype))
        model.channel_weights.copy_(torch.tensor([[2., 3.], [-2., -3.]], dtype=dtype))
        model.channel_bias.copy_(torch.tensor([4. if write else -4., reset_bias], dtype=dtype))
        model.readout[0].weight.copy_(torch.tensor([[.7, -.2], [.1, .6]], dtype=dtype))
        model.readout[0].bias.copy_(torch.tensor([.15, -.1], dtype=dtype))
        model.readout[2].weight.copy_(torch.tensor([[.4, -.3], [-.1, .5], [.2, .4], [-.3, -.2]], dtype=dtype))
        model.readout[2].bias.copy_(torch.tensor([.1, -.05, .2, -.15], dtype=dtype))
    return model


def initial_for(dtype):
    return tuple(torch.tensor(x, dtype=dtype, requires_grad=True) for x in (
        [[[.7, -.2], [.3, .5]]], [[.8, -.1]], [[.6, .8]], [[-.4, .2]]))


@contextlib.contextmanager
def observe(model):
    """Record real intermediate tensors without modifying their returned values."""
    captured = {'soft': [], 'event': [], 'address': [], 'key': [], 'reads': []}
    old_event, old_normalize = rv.hard_event, F.normalize
    def event(probability):
        out = old_event(probability)
        captured['soft'].append(probability)
        captured['event'].append(out)
        return out
    def normalize(value, *args, **kwargs):
        out = old_normalize(value, *args, **kwargs)
        captured['key'].append(out)
        return out
    def address_hook(module, args, output):
        captured['address'].append(output)
    def read_hook(module, args):
        captured['reads'].append(args[0])
    handles = [model.address.register_forward_hook(address_hook),
               model.readout.register_forward_pre_hook(read_hook)]
    rv.hard_event, F.normalize = event, normalize
    try:
        yield captured
    finally:
        rv.hard_event, F.normalize = old_event, old_normalize
        for h in handles:
            h.remove()


def differentiation(loss, model, initial, captured, binding, intermediate=()):
    names, inputs = [], []
    for name, p in model.named_parameters():
        names.append('parameter.'+name); inputs.append(p)
    for name, x in zip(('memory','validity','previous','older'), initial):
        names.append('initial.'+name); inputs.append(x)
    for kind in ('soft','event','address','key','reads'):
        for t, x in enumerate(captured[kind]):
            names.append(f'{kind}.{t}'); inputs.append(x)
    for t, x in enumerate(binding):
        names.append(f'binding_logit.{t}'); inputs.append(x)
    for name, x in zip(('memory','validity','previous','older'), intermediate):
        names.append('intermediate.'+name); inputs.append(x)
    grads = torch.autograd.grad(loss, inputs, retain_graph=True, allow_unused=True)
    by_name = dict(zip(names,grads))
    summaries = {k:scalar_summary(v) for k,v in by_name.items()}
    actual = {k:None if v is None else serial(v) for k,v in by_name.items()
              if not k.startswith('parameter.')}
    return summaries, actual, by_name


def event_jacobian(outputs, event):
    rows=[]
    for value in outputs.flatten():
        grad = torch.autograd.grad(value,event,retain_graph=True,allow_unused=True)[0]
        rows.append([0.,0.] if grad is None else serial(grad.flatten()))
    return rows


def case(mode, dtype, kind, *, write=False, feedback=True):
    constant = 8. if kind == 'all_reset' else (-8. if kind == 'no_reset' else 0.)
    model=model_for(mode,dtype,write=write,reset_bias=constant,context_feedback=feedback)
    initial=initial_for(dtype)
    duration=torch.ones((1,1),dtype=dtype)
    with observe(model) as obs:
        if kind == 'future':
            first,state0,trace0=model(torch.tensor([[0]]),duration,initial,
                                     return_state=True,return_trace=True)
            scores,state,trace=model(torch.tensor([[1]]),duration,state0,
                                    return_state=True,return_trace=True)
            loss=F.cross_entropy(scores[:,0],torch.tensor([0]))
            bindings=[trace0['binding_logit'],trace['binding_logit']]
            intermediate=state0
        elif kind == 'all_reset':
            scores,state,trace=model(torch.tensor([[0,1,0]]),torch.ones((1,3),dtype=dtype),initial,
                                    return_state=True,return_trace=True)
            loss=F.cross_entropy(scores.flatten(0,1),torch.zeros(3,dtype=torch.long))
            bindings=[trace['binding_logit']];intermediate=()
        else:
            scores,state,trace=model(torch.tensor([[0]]),duration,initial,
                                    return_state=True,return_trace=True)
            loss=F.cross_entropy(scores[:,0],torch.tensor([0]))
            bindings=[trace['binding_logit']];intermediate=()
    summaries,actual,raw=differentiation(loss,model,initial,obs,bindings,intermediate)
    result={'mode':mode,'dtype':str(dtype),'kind':kind,'hard_write':int(write),
            'context_feedback':feedback,'loss':float(loss.detach()),
            'soft_controls':[serial(x) for x in obs['soft']],
            'events':[serial(x) for x in obs['event']],
            'keys':[serial(x) for x in obs['key']],
            'reads':[serial(x) for x in obs['reads']],
            'binding_logits':[serial(x) for x in bindings],
            'unknown_probability':serial(scores.exp()[...,-1]),
            'state':[serial(x) for x in state],
            'gradients':summaries,'intermediate_gradients':actual}
    core=[n for n in summaries if n.startswith('parameter.') and not n.startswith('parameter.readout.')]
    result['core_parameter_gradient_max']=max(summaries[n]['max_abs'] for n in core)
    if kind != 'future':
        assert all(float(x.detach()[0,0]) == float(write) for x in obs['event'])
    if kind in ('immediate','all_reset'):
        assert all(float(x.detach()[0,1])==1. for x in obs['event'])
        assert result['core_parameter_gradient_max']==0.
        assert all(summaries[n]['used'] for n in core)
        assert all(summaries[f'event.{t}']['max_abs']==0. for t in range(len(obs['event'])))
        assert all(summaries[f'soft.{t}']['max_abs']==0. for t in range(len(obs['soft'])))
        assert all(torch.count_nonzero(x)==0 for x in obs['reads'])
        assert all(torch.count_nonzero(x)==0 for x in obs['key'])
        assert summaries['parameter.readout.2.bias']['nonzero']>0
        assert summaries['parameter.readout.0.weight']['max_abs']==0.
        assert summaries['parameter.readout.0.bias']['nonzero']>0
        if kind=='immediate':
            result['state_event_jacobians']={name:event_jacobian(x,obs['event'][0])
                  for name,x in zip(('memory','validity','previous','older'),state)}
            result['key_event_jacobian']=event_jacobian(obs['key'][0],obs['event'][0])
            assert summaries['reads.0']['nonzero']>0
            assert summaries['binding_logit.0']['nonzero']>0
            expected=initial[2].detach().flatten().mul(-1e8)
            computed=torch.tensor(result['key_event_jacobian'],dtype=dtype)[:,1]
            assert torch.allclose(expected,computed,rtol=1e-6,atol=1e-7)
    elif kind=='future':
        assert [float(x.detach()[0,1]) for x in obs['event']]==[1.,0.]
        assert [float(x.detach()[0,0]) for x in obs['event']]==[0.,0.]
        dstate=(-initial[0].detach(),-initial[1].detach(),torch.zeros_like(initial[2]),-initial[2].detach())
        contributions={name:float((raw['intermediate.'+name]*deriv).sum())
             for name,deriv in zip(('memory','validity','previous','older'),dstate)}
        result['future_reset_gradient_decomposition']=contributions
        result['future_reset_decomposition_sum']=sum(contributions.values())
        result['first_reset_event_gradient']=float(raw['event.0'][0,1])
        result['first_write_event_gradient']=float(raw['event.0'][0,0])
        assert abs(result['first_reset_event_gradient'])>1e-4
        assert result['first_write_event_gradient']==0.
        assert math.isclose(result['first_reset_event_gradient'],sum(contributions.values()),rel_tol=2e-6,abs_tol=2e-6)
        with torch.no_grad():
            joined=model(torch.tensor([[0,1]]),torch.ones((1,2),dtype=dtype),tuple(x.detach() for x in initial))
        result['segmented_vs_joint_max_abs']=float((joined[:,1]-scores[:,0].detach()).abs().max())
        assert result['segmented_vs_joint_max_abs']<2e-6
    else:
        assert float(obs['event'][0].detach()[0,1])==0.
        assert summaries['event.0']['nonzero']>0
        assert result['core_parameter_gradient_max']>0.
    return result


def main():
    cases=[]
    for dtype in (torch.float32,torch.float64):
        for mode in MODES:
            for write in (False,True):
                cases.append(case(mode,dtype,'immediate',write=write))
            cases.append(case(mode,dtype,'all_reset',write=True))
            cases.append(case(mode,dtype,'no_reset',write=False))
            for feedback in (False,True):
                cases.append(case(mode,dtype,'future',feedback=feedback))
    payload={'schema':1,'source_sha256':FROZEN_SHA,'source_path':str(SOURCE),
      'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'dependency_sha256': {name:hashlib.sha256((ROOT/'research/hcsn'/name).read_bytes()).hexdigest() for name in ('p2_associative_memory.py','p2_round2_raw_tokens.py')},
      'torch_version':torch.__version__,'python':sys.version,
      'optimizer_steps':0,'fits':0,'checkpoints_read':[], 'datasets_read':[],
      'heldout_read':False,'cases':cases,
      'scope':'Synthetic local STE/autograd mechanism review; not empirical task evaluation or evidence of global unlearnability.',
      'counts':{'total':len(cases),'immediate':sum(c['kind']=='immediate' for c in cases),
                'all_reset':sum(c['kind']=='all_reset' for c in cases),
                'no_reset':sum(c['kind']=='no_reset' for c in cases),
                'future':sum(c['kind']=='future' for c in cases)}}
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==FROZEN_SHA
    path=OUT/'autograd_evidence.json'
    temp=path.with_suffix('.json.tmp')
    temp.write_text(json.dumps(payload,indent=2,allow_nan=False)+'\n')
    os.replace(temp,path)
    readback=json.loads(path.read_text())
    assert len(readback['cases'])==36
    for c in cases:
        if c['dtype']=='torch.float64' and c['mode']==MODES[0]:
            compact={k:c[k] for k in ('kind','hard_write','context_feedback','loss','core_parameter_gradient_max')}
            if c['kind']=='future': compact.update(c['future_reset_gradient_decomposition'],reset_grad=c['first_reset_event_gradient'])
            print(json.dumps(compact))
    print(json.dumps({'status':'PASS','counts':payload['counts'],
         'path':str(path),'bytes':path.stat().st_size,
         'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
         'frozen_source_unchanged':True,'fits':0}))

if __name__=='__main__':main()
