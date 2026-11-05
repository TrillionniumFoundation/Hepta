"""Independent vectorized finite-horizon Bayes policy evaluator (P1 research only).

Enumerates both *potential* binary READ outcomes per public state, evaluates
all reachable public states in batches, then applies Bellman recursion backwards.
No private labels, observation RNG, trained targets or HX financial equations
are used at evaluation time. This is a CPU/float64 reference for the synthetic
Bayesian decision task, NOT a neural HX proof or production GPU kernel.
"""
from __future__ import annotations
import numpy as np
import torch


def exact_policy_regret(model: torch.nn.Module, x: torch.Tensor) -> dict:
    """Return per-state optimal value, neural policy value and exact regret.

    `model` must be an eval-mode module mapping float32 [batch,4] public
    `(belief, accuracy, cost, remaining)` to finite READ logits. The public
    coordinates are kept in binary64 for posterior recursion and only the
    model's *observed* state input is converted to binary32. At most 2^12
    leaves per initial state; bound the total leaf count before expansion.
    """
    if not isinstance(x, torch.Tensor) or x.ndim != 2 or x.shape[1] != 4:
        raise ValueError('Expected tensor [states,4]')
    if x.device.type != 'cpu' or x.dtype not in (torch.float32, torch.float64):
        raise ValueError('CPU float32/float64 reference only')
    if not 1 <= x.shape[0] <= 10000 or not bool(torch.isfinite(x).all()):
        raise ValueError('Nonfinite/empty/unbounded public states')
    if model.training:
        raise ValueError('Evaluation requires an eval-mode frozen model')
    p, q, cost, rem = x.unbind(-1)
    if not (bool(((p > 0) & (p < 1)).all())
            and bool(((q >= .5) & (q < 1)).all())
            and bool(((cost >= 0) & (cost < 1)).all())
            and bool(((rem >= 0) & (rem <= 12) & (rem == torch.floor(rem))).all())):
        raise ValueError('Invalid public state domain')
    remaining = rem.to(torch.int64)
    # Admission bound prevents a caller sending e.g. 10k 12-read states.
    leaves = sum(1 << int(z) for z in remaining.tolist())
    if leaves > 131072:
        raise ValueError('Exact tree leaf budget exceeded')
    optimum = np.empty(x.shape[0], dtype=np.float64)
    policy = np.empty(x.shape[0], dtype=np.float64)
    with torch.inference_mode():
        for depth in sorted(set(remaining.tolist())):
            indices = torch.where(remaining == depth)[0]
            group = x[indices].to(torch.float64)
            belief = group[:, 0:1]
            quality = group[:, 1:2]
            unit_cost = group[:, 2:3]
            history = []
            for t in range(depth):
                width = belief.shape[1]
                quality_nodes = quality.expand_as(belief)
                cost_nodes = unit_cost.expand_as(belief)
                observed = torch.stack((belief, quality_nodes, cost_nodes,
                                        torch.full_like(belief, float(depth-t))), dim=-1)
                logits = model(observed.reshape(-1,4).to(torch.float32))
                if not isinstance(logits, torch.Tensor) or logits.shape != (len(indices)*width,):
                    raise ValueError('Model must return one READ logit per public state')
                if not bool(torch.isfinite(logits).all()):
                    raise ArithmeticError('Nonfinite READ policy')
                probability = belief*quality_nodes+(1-belief)*(1-quality_nodes)
                stop = torch.maximum(belief,1-belief)
                history.append((logits.reshape(len(indices),width)>0, probability, stop))
                children = torch.stack((belief*quality_nodes/probability,
                              belief*(1-quality_nodes)/(1-probability)),dim=-1)
                belief = children.reshape(len(indices),width*2)
            optimal = torch.maximum(belief,1-belief)
            chosen = optimal
            for act, prob, stop in reversed(history):
                optchildren = optimal.reshape(len(indices),-1,2)
                polchildren = chosen.reshape(len(indices),-1,2)
                next_opt = (-unit_cost+prob*optchildren[...,0]
                            +(1-prob)*optchildren[...,1])
                next_pol = (-unit_cost+prob*polchildren[...,0]
                            +(1-prob)*polchildren[...,1])
                optimal = torch.maximum(stop,next_opt)
                chosen = torch.where(act,next_pol,stop)
            optimum[indices.numpy()] = optimal[:,0].numpy()
            policy[indices.numpy()] = chosen[:,0].numpy()
    delta = optimum-policy
    if not np.isfinite(delta).all() or np.min(delta) < -1e-9:
        raise ArithmeticError('Computed policy beats exact Bellman optimum')
    return {'optimal':optimum, 'policy':policy, 'regret':np.maximum(delta,0.),
            'smallest_raw_regret':float(np.min(delta)), 'total_tree_leaves':leaves}


def paired_seed_state_ci(difference: np.ndarray, *, seed: int=20261031,
                         draws: int=2000) -> dict:
    """Exploratory paired seed/state bootstrap; NOT independent preregistration."""
    d=np.asarray(difference,dtype=np.float64)
    if (d.ndim!=2 or d.shape[0]<3 or d.shape[1]<24 or d.size>500000
            or not np.isfinite(d).all() or not 200<=draws<=20000
            or isinstance(seed,bool) or not isinstance(seed,int)):
        raise ValueError('Invalid paired confidence interval protocol')
    g=np.random.default_rng(seed)
    boot=np.empty(draws,dtype=np.float64)
    for k in range(draws):
        ids=g.integers(0,d.shape[0],size=d.shape[0])
        rows=g.integers(0,d.shape[1],size=(d.shape[0],d.shape[1]))
        boot[k]=float(np.mean(d[ids[:,None],rows]))
    return {'difference_positive_means_candidate_worse':True,
            'mean':float(np.mean(d)),
            'per_seed_means':[float(t) for t in np.mean(d,axis=1)],
            'exploratory_bootstrap_95pct':[float(v) for v in np.quantile(boot,[.025,.975])],
            'draws':draws, 'independent_preregistration':False}
