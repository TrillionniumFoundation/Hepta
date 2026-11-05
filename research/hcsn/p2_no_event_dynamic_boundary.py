"""Exploratory P2: task-only learned causal dynamic reset boundary under OOD.

Research only; no event supervision, no hidden reset labels in model input.
Not original He-Xiong QVI, not a proof of endogenous stopping-time gradients,
not fair P1 matched-slope/compute, not pretrained multi-modal evidence.
All P0-P6 gates remain OPEN and deployment activation remains false.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import time

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

NKEYS = 6
DIM = NKEYS + 5
MODES = ('dynamic', 'instantaneous', 'no_reset')


def samples(n: int, length: int, segments: int, seed: int, *, noise: float = .08,
            irregular: bool = False):
    """Masked-context MQAR: event labels returned ONLY for independent evaluation.

    Context is a noisy continuous proxy; neither exact segment ID nor
    transition flag is an input feature. Stale-key supervision is query-only.
    """
    if any(type(v) is not int for v in (n, length, segments, seed)):
        raise ValueError('integer n/length/segments/seed needed')
    if n < 1 or not 3 <= segments <= 8 or length < segments * 14:
        raise ValueError('invalid stream geometry')
    if not isinstance(noise, (int, float)) or isinstance(noise, bool) or not math.isfinite(noise) or not 0 <= noise <= 1:
        raise ValueError('invalid noise')
    rng = np.random.default_rng(seed)
    x = np.zeros((n, length, DIM), dtype=np.float32)
    y = np.zeros((n, length), dtype=np.float32)
    query = np.zeros((n, length), dtype=bool)
    actual_events = np.zeros((n, length), dtype=bool)
    for i in range(n):
        stale = int(rng.integers(NKEYS))
        level = float(rng.uniform(-1.5, 1.5))
        for j in range(segments):
            start, end = (j * length) // segments, ((j + 1) * length) // segments
            span = end - start
            if j:
                candidates = [float(rng.uniform(-1.5, 1.5)) for _ in range(100)]
                possible = [z for z in candidates if abs(z-level) >= .75]
                if not possible:
                    raise ArithmeticError('context sampling failed')
                level = possible[0]
                actual_events[i, start] = True
            # The regime is observable only as a noisy value, not as a boundary bit.
            x[i, start:end, NKEYS+3] = level + rng.normal(0, noise, span)
            x[i, start:end, NKEYS+4] = (rng.uniform(.08, 3.5, span) if irregular
                                        else rng.uniform(.8, 1.2, span))
            choices = [k for k in range(NKEYS) if k != stale]
            pos, neg = [int(k) for k in rng.choice(choices, size=2, replace=False)]
            writes = [(pos, 1.), (neg, -1.)]
            if j == 0:
                writes.append((stale, 1.))
            write_times = rng.choice(np.arange(start+1, start+6), len(writes), replace=False)
            for t, (key, value) in zip(write_times, writes):
                x[i, t, key] = 1.
                x[i, t, NKEYS] = value
                x[i, t, NKEYS+1] = 1.
            queries = [(stale, 1. if j == 0 else 0.), (pos, 1.), (neg, 0.)]
            rng.shuffle(queries)
            for t, (key, answer) in zip((start+span//2, start+(3*span)//4, end-2), queries):
                x[i,t,key] = 1.
                x[i,t,NKEYS+2] = 1.
                y[i,t] = answer
                query[i,t] = True
    if not (query.sum(axis=1) == 3*segments).all():
        raise AssertionError('generator query mismatch')
    return tuple(torch.from_numpy(z) for z in (x, y, query, actual_events))


@dataclass
class State:
    memory: torch.Tensor
    level: torch.Tensor
    volatility: torch.Tensor
    initialized: torch.Tensor


class CausalBoundary(nn.Module):
    """4 scalar trainables for each policy, with declared vs active distinction."""
    def __init__(self, mode: str):
        super().__init__()
        if mode not in MODES:
            raise ValueError('unsupported mode')
        self.mode = mode
        self.threshold = nn.Parameter(torch.tensor(-1.2))
        self.sensitivity = nn.Parameter(torch.tensor(0.))
        self.output_gain = nn.Parameter(torch.tensor(5.))
        self.output_bias = nn.Parameter(torch.tensor(-1.5))

    def initial(self, x: torch.Tensor):
        return State(x.new_zeros((len(x), NKEYS)), x.new_zeros(len(x)),
                     x.new_zeros(len(x)), torch.zeros(len(x), dtype=torch.bool, device=x.device))

    def step(self, xt: torch.Tensor, state: State, *, hard: bool):
        if xt.ndim != 2 or xt.shape[1] != DIM or xt.shape[0] != len(state.memory):
            raise ValueError('expected [batch,DIM] and matched state')
        if not bool(torch.isfinite(xt).all()) or not bool(((xt[:,NKEYS+4] > 0) & (xt[:,NKEYS+4] <= 4)).all()):
            raise ValueError('invalid observation or positive time increment')
        ctx = xt[:, NKEYS+3]
        delta = torch.abs(ctx - state.level)
        dt = xt[:, NKEYS+4]
        # Both statistics depend only on the current and previous observations.
        alpha = -torch.expm1(-dt / 4.)
        next_level = state.level + alpha * (ctx-state.level)
        next_vol = .9*state.volatility + .1*delta
        if self.mode == 'dynamic':
            # A learned state-dependent threshold: conditioned on causal volatility.
            boundary = F.softplus(self.threshold + self.sensitivity*state.volatility)
        else:
            # Same parameter count, but context-local control, no temporal volatility state.
            boundary = F.softplus(self.threshold + self.sensitivity*torch.abs(ctx))
        margin = delta - boundary
        allowed = state.initialized
        event = (margin > 0) & allowed
        if self.mode == 'no_reset':
            erase = torch.zeros_like(delta)
        elif hard:
            erase = event.to(delta.dtype)
        else:
            erase = torch.sigmoid(8.*margin) * allowed.to(delta.dtype)
        memory = state.memory * (1.-erase[:,None])
        write = xt[:, NKEYS+1:NKEYS+2]*xt[:, :NKEYS]
        memory = memory*(1.-write) + write*xt[:, NKEYS:NKEYS+1]
        new_state = State(memory, next_level, next_vol, torch.ones_like(allowed))
        read = (memory*xt[:,:NKEYS]).sum(dim=-1)
        logit = self.output_gain*read + self.output_bias
        return new_state, logit, event

    def rollout(self, x: torch.Tensor, *, hard: bool, state: State | None=None):
        if x.ndim != 3 or x.shape[-1] != DIM or x.shape[1] < 1:
            raise ValueError('expected nonempty [batch,time,DIM]')
        if state is None:
            state = self.initial(x)
        logits, events = [], []
        for t in range(x.shape[1]):
            state, logit, event = self.step(x[:,t,:], state, hard=hard)
            logits.append(logit)
            events.append(event)
        return torch.stack(logits,dim=1), torch.stack(events,dim=1), state


def dictionary_oracle(x: torch.Tensor, true_events: torch.Tensor):
    """Evaluation ONLY: ideal reset-policy upper bound supplied with hidden labels.

    It intentionally consumes the ground-truth event array; it is NOT an
    achievable online classifier and is never passed into model training.
    """
    if x.ndim != 3 or x.shape[-1] != DIM or true_events.shape != x.shape[:2]:
        raise ValueError('invalid evaluation-oracle inputs')
    if true_events.dtype != torch.bool:
        raise ValueError('ground truth events must be bool')
    out = torch.zeros(x.shape[:2], dtype=x.dtype)
    for i in range(x.shape[0]):
        mem = torch.zeros(NKEYS, dtype=x.dtype)
        for t in range(x.shape[1]):
            xt=x[i,t]
            if bool(true_events[i,t]):
                mem.zero_()
            if float(xt[NKEYS+1]):
                mem[xt[:NKEYS].argmax()]=xt[NKEYS]
            if float(xt[NKEYS+2]):
                out[i,t]=float(mem[xt[:NKEYS].argmax()]>0)
    return out


def _metrics(model, data):
    x,y,q,true = data
    with torch.no_grad():
        soft,_,_=model.rollout(x,hard=False)
        hard,hit,_=model.rollout(x,hard=True)
    matched=int((hit & true).sum())
    predicted=int(hit.sum())
    actual=int(true.sum())
    return {
        'soft_query_accuracy':float(((soft>0)==(y>.5))[q].float().mean()),
        'hard_query_accuracy':float(((hard>0)==(y>.5))[q].float().mean()),
        'event_precision':matched/max(1,predicted),
        'event_recall':matched/max(1,actual),
        'detected_events_per_stream':predicted/len(x),
        'applied_resets_per_stream':(0. if model.mode=='no_reset' else predicted/len(x)),
        'event_precision_is_detector_only':model.mode=='no_reset',
        'true_events_per_stream':actual/len(x),
        'query_count':int(q.sum()),
    }


def experiment(*, seeds=(11,23,37), steps=40, batch=16, eval_n=48, length=64):
    if length<56 or length%4 or steps<1 or batch<1 or eval_n<1:
        raise ValueError('invalid study geometry')
    torch.set_num_threads(1)
    records=[]
    for seed in seeds:
        for mode in MODES:
            torch.manual_seed(seed)
            model=CausalBoundary(mode)
            opt=torch.optim.Adam(model.parameters(),lr=.025)
            started=time.perf_counter()
            for step in range(steps):
                x,y,q,_=samples(batch,length,4,seed*100_000+step)
                opt.zero_grad(set_to_none=True)
                logits,_,_=model.rollout(x, hard=False)
                loss=F.binary_cross_entropy_with_logits(logits[q],y[q])
                loss.backward()
                for name,p in model.named_parameters():
                    if mode=='no_reset' and name in ('threshold','sensitivity'):
                        if p.grad is not None: raise AssertionError('disabled reset gradient')
                    elif p.grad is None or not bool(torch.isfinite(p.grad).all()):
                        raise ArithmeticError('invalid training gradient: '+name)
                torch.nn.utils.clip_grad_norm_(model.parameters(),5.)
                opt.step()
            observed={
                'id':_metrics(model, samples(eval_n,length,4,88000+seed)),
                'ood_long_noisy_irregular':_metrics(model, samples(eval_n,length*2,6,99000+seed,
                                                                 noise=.23,irregular=True)),
            }
            records.append({'seed':seed,'mode':mode,'steps':steps,'batch':batch,
                            'declared_parameters':sum(p.numel() for p in model.parameters()),
                            'active_parameters':sum(p.numel() for name,p in model.named_parameters()
                                                    if mode!='no_reset' or name not in ('threshold','sensitivity')),
                            'train_wall_s':time.perf_counter()-started,
                            'loss':float(loss.detach()),'results':observed})
    summary={panel:{mode:{metric:float(np.mean([r['results'][panel][metric] for r in records if r['mode']==mode]))
                          for metric in ('soft_query_accuracy','hard_query_accuracy','event_precision','event_recall','detected_events_per_stream','applied_resets_per_stream')}
                    for mode in MODES} for panel in ('id','ood_long_noisy_irregular')}
    return {'schema':'hcsn.p2-dynamic-boundary-task-only-negative.exploratory.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'seed_list':list(seeds),'train_only_query_supervision':True,
            'dynamic_input_driven':True,'true_stopping_time_gradient':False,
            'comparison_compute_matched':False,'science_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,
            'limitations':'Synthetic noisy scalar context proxy, no pretrained encoder, no QVI, no fair P1 slope/FLOP match; a diagnostic not science acceptance.',
            'records':records,'summary':summary}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--steps',type=int,default=40)
    p.add_argument('--batch',type=int,default=16)
    p.add_argument('--eval-n',type=int,default=48)
    p.add_argument('--length',type=int,default=64)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('evidence exists: overwrite refused')
    result=experiment(seeds=tuple(a.seeds),steps=a.steps,batch=a.batch,eval_n=a.eval_n,length=a.length)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result['summary'],sort_keys=True,indent=2))

if __name__=='__main__':
    main()
