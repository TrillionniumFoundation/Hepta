"""P2 research diagnostic: causal edge/refractory filtering of hard boundary events.

This is an evaluation-only post-training intervention with *zero trainable
parameters*. It is NOT event-time differentiation, optimal stopping, the
original He--Xiong QVI, or evidence of a neural gain over ordinary controls.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import NamedTuple

import numpy as np
import torch
from torch.nn import functional as F
from .p2_learned_autonomous_content import AutonomousBoundaryMemory, MODES, NKEYS, DIM
from .p2_multiquery_noevent import make_mqar, _accuracy, rollout
from .p2_hard_forward_soft_gradient import rollout_st

POLICIES = ('raw', 'edge', 'refractory', 'edge_refractory')


class FilterState(NamedTuple):
    memory_state: object
    previous_raw: torch.Tensor
    cooldown: torch.Tensor


class FilterTrace(NamedTuple):
    raw_events: torch.Tensor
    applied_events: torch.Tensor


def initial_filter_state(model, x):
    return FilterState(model.initial(x),
                       torch.zeros((x.shape[0], 1), dtype=torch.bool, device=x.device),
                       torch.zeros((x.shape[0], 1), dtype=torch.int64, device=x.device))


def rollout_filtered(model, x, *, policy='edge_refractory', refractory_tokens=8,
                     state=None, trace=False):
    """Hard-forward causal filter, with exact streaming state and no lookahead.

    Edge: allow a new reset only when raw margin first becomes nonpositive.
    Refractory: withhold resets for `refractory_tokens` subsequent tokens.
    Edge+refractory: both must be satisfied. Counts are in tokens, NOT seconds.
    `raw` reproduces the unmodified hard-forward model exactly.

    Suppressing a raw event must restore memory that the upstream hard _step
    erased, including ordinary-mode write gating. Never use eval event labels.
    """
    if policy not in POLICIES or type(refractory_tokens) is not int or not (0 <= refractory_tokens <= 1024):
        raise ValueError('invalid causal filter policy/refractory_tokens')
    if x.ndim != 3 or x.shape[-1] != DIM or x.shape[0] < 1 or x.shape[1] < 1:
        raise ValueError('expected nonempty [batch,time,DIM]')
    if not bool(torch.isfinite(x).all()):
        raise ValueError('nonfinite stream')
    if not bool(((x[:, :, NKEYS+4] > 0.) & (x[:, :, NKEYS+4] <= 4.)).all()):
        raise ValueError('invalid delta times')
    if state is None:
        state = initial_filter_state(model, x)
    if (state.memory_state.memory.shape != (x.shape[0], NKEYS)
        or state.previous_raw.shape != (x.shape[0], 1)
        or state.previous_raw.dtype != torch.bool
        or state.cooldown.shape != (x.shape[0], 1)
        or state.cooldown.dtype != torch.int64):
        raise ValueError('incorrect streaming filter state')
    scores, raw_rows, applied_rows = [], [], []
    for step in range(x.shape[1]):
        xt = x[:, step, :]
        hard, _, raw, margin, call, put = model._step(xt, state.memory_state, True)
        allowed_edge = (~state.previous_raw) if policy in ('edge', 'edge_refractory') else torch.ones_like(raw)
        allowed_gap = (state.cooldown == 0) if policy in ('refractory', 'edge_refractory') else torch.ones_like(raw)
        applied = raw & allowed_edge & allowed_gap
        if model.mode == 'no_reset':
            # Upstream detector-only ablation; never miscount predicted hits as erasures.
            applied = torch.zeros_like(raw)
        if policy == 'raw' or model.mode == 'no_reset':
            memory = hard.memory
        else:
            # Reconstruct an *unreset* _step from the hard update exactly:
            # after a raw event, hard.memory is the write contribution only.
            if model.mode == 'analytic':
                features = torch.cat((call, put, torch.tanh(margin)), -1)
            elif model.mode == 'ordinary':
                features = torch.cat((torch.sigmoid(3*margin),
                                      torch.sigmoid(-3*margin), torch.tanh(margin)), -1)
            else:
                raise ValueError('unsupported model mode')
            strength = torch.sigmoid(model.write_raw + features @ model.write_features).unsqueeze(-1)
            update = xt[:, NKEYS+1:NKEYS+2] * xt[:, :NKEYS] * strength
            retained = state.memory_state.memory * torch.exp(
                -F.softplus(model.raw_decay) * xt[:, NKEYS+4:NKEYS+5]) * (1-update)
            unreset = hard.memory + raw.to(xt.dtype) * retained
            memory = torch.where(applied, hard.memory, unreset)
        next_memory = type(hard)(memory, hard.context, hard.initialized)
        next_cooldown = torch.where(applied,
                                    torch.full_like(state.cooldown, refractory_tokens),
                                    torch.clamp(state.cooldown - 1, min=0))
        state = FilterState(next_memory, raw, next_cooldown)
        scores.append(model.output_gain * (memory*xt[:, :NKEYS]).sum(-1) + model.output_bias)
        if trace:
            raw_rows.append(raw.squeeze(-1))
            applied_rows.append(applied.squeeze(-1))
    events = (FilterTrace(torch.stack(raw_rows, 1), torch.stack(applied_rows, 1))
              if trace else None)
    return torch.stack(scores, 1), state, events


def _metric(logits, y, queries, event_labels, events):
    hits = events.applied_events
    true_hits = (hits & event_labels).sum()
    raw_hits = events.raw_events
    return {'hard_query_accuracy': _accuracy(logits, y, queries),
            'applied_event_precision': float(true_hits / hits.sum().clamp(min=1)),
            'applied_event_recall': float(true_hits / event_labels.sum().clamp(min=1)),
            'applied_resets_per_stream': float(hits.sum() / len(y)),
            'raw_detector_crossings_per_stream': float(raw_hits.sum() / len(y)),
            'applied_false_resets_per_stream': float((hits & ~event_labels).sum() / len(y)),
            'query_count': int(queries.sum()),
            'true_transitions_per_stream': float(event_labels.sum() / len(y))}


def run(seeds=(11, 23, 37), *, steps=30, batch=12, length=56, eval_n=48,
        refractory_tokens=8):
    """Train ST once per (mode,seed); paired post-training interventions.

    Predeclared token cooldown=8; we do not choose a gate on heldout OOD.
    Training uses the same model/optimizer/data/seeds as iteration19.
    """
    if not seeds or len(set(seeds)) != len(seeds) or any(type(s) is not int for s in seeds):
        raise ValueError('expected unique integer seeds')
    if type(refractory_tokens) is not int or refractory_tokens < 0:
        raise ValueError('invalid cooldown')
    if any(type(v) is not int or v < 1 for v in (steps, batch, eval_n)):
        raise ValueError('invalid budget')
    if length < 56 or length%4:
        raise ValueError('length must be >=56, divisible by four')
    torch.set_num_threads(1)
    rows = []
    for seed in seeds:
        for mode in MODES:
            torch.manual_seed(seed)
            model = AutonomousBoundaryMemory(mode)
            optimizer = torch.optim.Adam(model.parameters(), lr=.012)
            for t in range(steps):
                x, y, q, _ = make_mqar(batch, length, 4, seed*100000+t)
                optimizer.zero_grad(set_to_none=True)
                out, _ = rollout_st(model, x)
                loss = F.binary_cross_entropy_with_logits(out[q], y[q])
                loss.backward()
                for name, p in model.named_parameters():
                    if p.grad is None and mode == 'no_reset' and name == 'temperature_raw':
                        continue
                    if p.grad is None or not bool(torch.isfinite(p.grad).all()):
                        raise ArithmeticError('invalid ST gradient ' + name)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 5.)
                optimizer.step()
            score = {}
            with torch.no_grad():
                for tag, n, segments, irr, off in (
                    ('id', length, 4, False, 88000),
                    ('ood_long_irregular', length*2, 6, True, 99000)):
                    x, y, q, ev = make_mqar(eval_n, n, segments, off+seed, irregular=irr)
                    result = {}
                    for policy in ('raw', 'edge', 'edge_refractory'):
                        logits, _, trace = rollout_filtered(model, x, policy=policy,
                                            refractory_tokens=refractory_tokens, trace=True)
                        if policy == 'raw':
                            base, _, hits = rollout(model, x, hard=True, trace=True)
                            if not torch.equal(logits, base) or not torch.equal(trace.raw_events, hits):
                                raise AssertionError('raw hard baseline parity failure')
                        result[policy] = _metric(logits, y, q, ev, trace)
                    score[tag] = result
            rows.append({'mode':mode,'seed':seed,'declared_parameters':sum(p.numel() for p in model.parameters()),
                         'optimizer_steps':steps,'train_loss':float(loss.detach()),'results':score})
    summary = {tag:{mode:{policy:{key:float(np.mean([
             row['results'][tag][policy][key] for row in rows if row['mode']==mode]))
                for key in ('hard_query_accuracy','applied_event_precision','applied_event_recall',
                            'applied_resets_per_stream','applied_false_resets_per_stream')}
                for policy in ('raw','edge','edge_refractory')}
             for mode in MODES} for tag in ('id','ood_long_irregular')}
    return {'schema':'hcsn.p2-causal-edge-refractory.exploratory.v1',
            'scientific_gates_closed':False,'production_activation':False,
            'event_supervision':False,'surrogate_gradient_training':True,
            'predeclared_cooldown_tokens':refractory_tokens,
            'evaluation_only_same_trained_weights':True,
            'no_fair_matched_flops_or_event_time_gradients':True,
            'seeds':list(seeds),'steps':steps,'batch':batch,'length':length,'eval_n':eval_n,
            'summary':summary,'rows':rows}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--steps',type=int,default=30)
    p.add_argument('--batch',type=int,default=12)
    p.add_argument('--length',type=int,default=56)
    p.add_argument('--eval-n',type=int,default=48)
    p.add_argument('--refractory-tokens',type=int,default=8)
    p.add_argument('--seeds',type=int,nargs='+',default=[11,23,37])
    a=p.parse_args()
    if a.output.exists():p.error('refuse overwrite')
    result=run(tuple(a.seeds),steps=a.steps,batch=a.batch,length=a.length,
               eval_n=a.eval_n,refractory_tokens=a.refractory_tokens)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result['summary'],indent=2,sort_keys=True))

if __name__=='__main__':main()
