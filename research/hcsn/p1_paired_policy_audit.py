"""P1 independent heldout policy-value comparison: analytic vs null controls.

Replays the already declared synthetic Bayesian READ task, train seeds,
optimizer budgets and C1 Hermite null without changing original trainers.
Uses a NEW exact vectorized Bellman evaluator for paired policy regret.
Honest scope: CPU-only, three exploratory seeds, no measured matched FLOPs,
no globally proven slope equivalence, no preregistration or production gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import time
import torch
try:
    from .train_study import MODES, make_data, train_one, two_features
    from .p1_hermite_control import HermiteMatchedHead, train_hermite
    from .p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci
except ImportError:
    from train_study import MODES, make_data, train_one, two_features
    from p1_hermite_control import HermiteMatchedHead, train_hermite
    from p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci

SEEDS=(11,23,37)
N_TRAIN=512
UPDATES=90
N_HOLDOUT=420
ID_SEED=77441001
OOD_SEED=77441002


def _frozen_splits(rows):
    out={}
    for name, seed, ood in [('id',ID_SEED,False),('ood',OOD_SEED,True)]:
        x,_=make_data(seed,rows,ood=ood)
        out[name]={'input':x,'sha256':hashlib.sha256(x.numpy().tobytes()).hexdigest()}
    return out


def _signed_feature_match(x):
    z=x.detach().clone().requires_grad_(True)
    analytic=two_features(z,'dual_call_put')
    lookup=HermiteMatchedHead().transformed(z)
    max_value=float(torch.max(torch.abs(analytic-lookup)).detach())
    gaps=[]
    for j in range(2):
        ja=torch.autograd.grad(analytic[:,j].sum(),z,retain_graph=True)[0]
        jl=torch.autograd.grad(lookup[:,j].sum(),z,retain_graph=True)[0]
        gaps.append(float((ja-jl).abs().max().detach()))
    return {'max_abs_feature_value_difference':max_value,
            'max_abs_signed_jacobian_difference':max(gaps),
            'features_and_jacobians_checked_on_heldout':len(z),
            'equivalence_global_certified':False}


def _median_forward_ns(model,x):
    model.eval()
    with torch.inference_mode():
        for _ in range(4):model(x)
        samples=[]
        for _ in range(30):
            t=time.perf_counter_ns()
            model(x)
            samples.append((time.perf_counter_ns()-t)/len(x))
    return float(statistics.median(samples))


def run(*,smoke:bool=False):
    torch.set_num_threads(1)
    seeds=(11,23,37) if not smoke else (11,23,37)
    train_rows=N_TRAIN if not smoke else 40
    steps=UPDATES if not smoke else 3
    holdout=N_HOLDOUT if not smoke else 24
    splits=_frozen_splits(holdout)
    names=(*MODES,'c1_hermite_null')
    cache={name:{d:[] for d in splits} for name in names}
    logs=[]
    runtimes={name:[] for name in names}
    training_hashes={}
    for seed in seeds:
        train_x,train_y=make_data(seed+123000,train_rows)
        training_hashes[str(seed)]=hashlib.sha256(
            train_x.numpy().tobytes()+train_y.numpy().tobytes()).hexdigest()
        models={}
        for mode in MODES:
            model, rec=train_one(mode,seed,train_rows=train_rows,steps=steps)
            models[mode]=model.eval()
            logs.append(rec)
        hermite,rec=train_hermite(seed,steps=steps,train_rows=train_rows)
        models['c1_hermite_null']=hermite.eval()
        logs.append({'seed':seed,'mode':'c1_hermite_null',
                     'train_samples':train_rows,'optimizer_updates':steps,**rec})
        params={name:sum(p.numel() for p in m.parameters()) for name,m in models.items()}
        if set(params.values())!={161}:
            raise ArithmeticError('P1 head parameter parity broken')
        for tag,datum in splits.items():
            x=datum['input']
            for name,model in models.items():
                actual=exact_policy_regret(model,x)
                cache[name][tag].append(actual['regret'])
                if tag=='id':runtimes[name].append(_median_forward_ns(model,x))
    from numpy import stack
    analysis={}
    for tag in splits:
        results={name:float(stack(cache[name][tag]).mean()) for name in names}
        deltas={}
        for reference in ('ordinary_two_gate','c1_hermite_null'):
            different=stack(cache['dual_call_put'][tag])-stack(cache[reference][tag])
            deltas['dual_minus_'+reference]=paired_seed_state_ci(different,
                 seed=33455 if tag=='id' else 33456,draws=1000)
        analysis[tag]={'mean_exact_policy_regret':results,
                       'paired_differences':deltas,'states_per_seed':holdout}
    slope_check,_=make_data(77441003,512,ood=True)
    return {'schema':'hcsn.p1-vectorized-paired-exact-policy.v1',
            'protocol':{'exploratory_smoke':smoke,'seeds':list(seeds),'training_rows':train_rows,
                        'optimizer_updates':steps,'holdout_rows_per_distribution':holdout,
                        'holdout_input_sha256':{n:v['sha256'] for n,v in splits.items()},
                        'training_input_and_label_sha256':training_hashes,
                        'heldout_not_training':True},
            'by_distribution':analysis,
            'signed_slope_control':_signed_feature_match(slope_check),
            'median_CPU_forward_ns_per_sample_by_seed':runtimes,
            'train_logs':logs,
            'trainable_parameters_matched':True,
            'optimizer_updates_matched':True,
            'trained_on_identical_seed_rows':True,
            'cpu_forward_time_measured':True,
            'matched_backward_flops_proven':False,
            'full_input_slope_equivalence_proven':False,
            'independent_preregistered':False,
            'externally_attested':False,
            'independent_gain_demonstrated':False,
            'p1_scientific_gate':'OPEN','production_activation':False,
            'scope':'Synthetic public Bayes READ policy only; not the original HX equity, a real encoder, or an energy/GPU benchmark.'}


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--smoke',action='store_true',help='small code-path test, NOT comparable efficacy')
    args=ap.parse_args()
    report=run(smoke=args.smoke)
    report['executed_source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as fp:
        json.dump(report,fp,indent=2,sort_keys=True)
        fp.write('\n')
    print(json.dumps({'by_distribution':report['by_distribution'],
                      'signed_slope_control':report['signed_slope_control'],
                      'gate':report['p1_scientific_gate']},indent=2))
