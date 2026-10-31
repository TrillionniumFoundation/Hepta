"""Heldout paired decision-regret audit of P1 five architecture variants.

The split and seed pairs are frozen before fitting. Uses exact Bayes Bellman
values, a *toy* task distinct from original He--Xiong credit dynamics.
No slope/compute matching is claimed; audit measures the mismatch.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import time

import numpy as np
import torch
try:
 from .train_study import MODES,MatchedHead,train_one,two_features,make_data
 from .boundary_content_bridge import PublicState,policy_value,oracle
except ImportError:
 from train_study import MODES,MatchedHead,train_one,two_features,make_data
 from boundary_content_bridge import PublicState,policy_value,oracle

SEEDS=(11,23,37)
TRAIN=512
STEPS=90
ID_SEED=20261031
OOD_SEED=20261032
N_TEST=420
BOOTSTRAP=1000


def _test_x(ood:bool):
    x,_=make_data((OOD_SEED if ood else ID_SEED),N_TEST,ood=ood)
    return x


def _regret_on_states(model, x):
    with torch.inference_mode():pred=model(x).numpy()
    res=[]
    for row,z in zip(x.tolist(),pred):
        s=PublicState(*row[:3],int(row[3]))
        opt=policy_value(s,oracle)
        choice=(s.remaining>0 and float(z)>0)
        def policy(_s):
            # Fast enough for a small heldout audit. Re-evaluate own belief
            # at subsequent read steps, never use the private true label.
            if _s==s:return choice
            with torch.inference_mode():
                v=model(torch.tensor([[_s.p,_s.q,_s.cost,float(_s.remaining)]],dtype=torch.float32))
                return bool(v.item()>0) if _s.remaining else False
        res.append(max(0.,opt-policy_value(s,policy)))
    return np.asarray(res,dtype=float)


def _feature_slope_report(x):
    slopes={}
    for mode in MODES:
        z=x.detach().clone().requires_grad_(True)
        features=two_features(z,mode)
        gradients=[]
        for k in range(2):
            g=torch.autograd.grad(features[:,k].sum(),z,retain_graph=True)[0]
            gradients.append(g.detach().numpy())
        g=np.stack(gradients,axis=1)
        derivatives=np.linalg.norm(g[:,:,:3],axis=(1,2))
        slopes[mode]={'rms_jacobian':float(np.sqrt(np.mean(derivatives**2))),
                     'nearly_zero_jacobian_fraction':float(np.mean(derivatives<1e-7)),
                     'median_jacobian':float(np.median(derivatives))}
    return slopes


def _runtime_steady_state(x, mode):
    # Both analytic options and ordinary gates are scalar operations on the
    # same CPU (no GPU availability in this environment). Median is robust
    # to background scheduling. Not a hardware power benchmark.
    for _ in range(4):two_features(x,mode)
    times=[]
    for _ in range(40):
        a=time.perf_counter_ns()
        two_features(x,mode)
        times.append(time.perf_counter_ns()-a)
    return float(statistics.median(times))/x.shape[0]


def run_audit():
    torch.set_num_threads(1)
    x_id=_test_x(False);x_ood=_test_x(True)
    frozen_hashes={key:hashlib.sha256(value.numpy().tobytes()).hexdigest()
                   for key,value in [('id',x_id),('ood',x_ood)]}
    models={}
    reports=[]
    for seed in SEEDS:
        models[seed]={}
        for mode in MODES:
            model,log=train_one(mode,seed,train_rows=TRAIN,steps=STEPS)
            models[seed][mode]=model.eval()
            reports.append(log)
    by_set={}
    for setname,x in [('id',x_id),('ood',x_ood)]:
        values={}
        for seed in SEEDS:
            for mode in MODES:
                values[f'{seed}:{mode}']=_regret_on_states(models[seed][mode],x)
        base='ordinary_two_gate'
        seed_results={}
        for seed in SEEDS:
            ref=values[f'{seed}:{base}']
            one={}
            for mode in MODES:
                vals=values[f'{seed}:{mode}']
                difference=vals-ref
                one[mode]={'mean_exact_regret':float(vals.mean()),
                           'difference_vs_ordinary':float(difference.mean())}
            seed_results[str(seed)]=one
        # Hierarchical seed*state paired bootstrap: sample three seed blocks
        # and heldout states within blocks. This is exploration, not a
        # pre-registered causal inference claim.
        rng=np.random.default_rng(919 if setname=='id' else 920)
        per_seed=np.stack([values[f'{seed}:dual_call_put']-values[f'{seed}:{base}']
                           for seed in SEEDS])
        boots=np.empty(BOOTSTRAP)
        for k in range(BOOTSTRAP):
            rs=rng.integers(0,len(SEEDS),len(SEEDS))
            ri=rng.integers(0,N_TEST,(len(SEEDS),N_TEST))
            boots[k]=float(np.mean(per_seed[rs[:,None],ri]))
        by_set[setname]={'seed_results':seed_results,
                         'paired_mean_dual_minus_ordinary':float(per_seed.mean()),
                         'bootstrap_95pct':list(map(float,np.quantile(boots,[.025,.975]))),
                         'heldout_examples':N_TEST}
    runtime={mode:_runtime_steady_state(x_id,mode) for mode in MODES}
    return {'schema':'hcsn.p1-honest-heldout-audit.v2',
            'frozen_protocol':{'train_seed_group':SEEDS,'train_rows':TRAIN,'updates':STEPS,
                'independent_test_seeds':[ID_SEED,OOD_SEED],
                'test_rows_per_distribution':N_TEST,'bootstrap_draws':BOOTSTRAP,
                'holdout_input_sha256':frozen_hashes},
            'by_distribution':by_set,'slope_report':_feature_slope_report(x_id),
            'median_feature_forward_ns_per_example_cpu':runtime,
            'models_train_log':reports,
            'slope_matched':False,'flops_matched':False,
            'real_encoder_benchmark':False,'p1_closed':False,
            'interpretation':'Different analytic transform families are not slope/compute equivalent; ordinary baseline remains a critical null.'}


if __name__=='__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--output',type=Path,required=True)
    a=cli.parse_args()
    if a.output.exists():cli.error('Refusing to overwrite existing result')
    obj=run_audit()
    obj['implementation_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'summary':obj['by_distribution'],
                      'slope_report':obj['slope_report'],
                      'median_ns_per_example':obj['median_feature_forward_ns_per_example_cpu']},indent=2))
