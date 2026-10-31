"""Deterministic P2 moving linear barrier evidence (scientific NO_GO)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import pathlib
import random
import statistics
import time

import torch
from .p2_moving_affine_boundary import MovingTwoStage,bridge_mc,probability_quad,probability_torch

HERE=pathlib.Path(__file__).resolve().parent


def run():
    panels=[
        MovingTwoStage(),
        MovingTwoStage(slope1=0.,slope2=0.),
        MovingTwoStage(slope1=-.23,slope2=.30,gain=-.42,b2=-.2),
        MovingTwoStage(slope1=.45,slope2=-.36,gain=.60,b2=.7,drift=-.24),
        MovingTwoStage(slope1=-.35,slope2=.17,gain=.12,b2=-.8,drift=.37),
        MovingTwoStage(slope1=.29,slope2=.34,gain=.55,b2=.68,drift=-.19,diffusion=.42),
    ]
    rows=[]
    for i,p in enumerate(panels):
        quad,qe=probability_quad(p)
        tensor,tail=probability_torch(p,order=256)
        mc,se,count=bridge_mc(p,n=180_000,seed=20261031+i)
        rows.append({'parameters':dataclasses.asdict(p),'adaptive_quad_hit':quad,
                     'quad_abs_error_estimate':qe,'torch_256_hit':float(tensor.detach()),
                     'torch_vs_quad_abs':abs(float(tensor.detach())-quad),
                     'free_gaussian_omitted_tail_upper':float(tail.detach()),
                     'exact_linear_bridge_mc_hit':mc,'mc_se':se,'mc_hit_count':count,
                     'mc_z_descriptive':(mc-quad)/se if se>0 else None})
    check=MovingTwoStage(b1=-.2,b2=.41,gain=.3,slope1=.17,slope2=-.13)
    coords={k:torch.tensor(v,dtype=torch.float64,requires_grad=True) for k,v in vars(check).items()}
    t,_=probability_torch(check,order=256,**coords)
    grads=torch.autograd.grad(t,tuple(coords.values()))
    gradrows=[]
    for (name,v),grad in zip(coords.items(),grads):
        h=1e-4*max(1.,abs(float(v.detach())))
        plus=dataclasses.replace(check,**{name:float(v.detach())+h})
        minus=dataclasses.replace(check,**{name:float(v.detach())-h})
        fd=(probability_quad(plus)[0]-probability_quad(minus)[0])/(2*h)
        gradrows.append({'coordinate':name,'autograd':float(grad.detach()),
                         'independent_quad_central_fd':fd,'absolute_difference':abs(float(grad.detach())-fd)})
    rng=random.Random(20261031)
    errrows=[]
    for i in range(150):
        p=MovingTwoStage(x0=rng.uniform(.6,2.5),b1=rng.uniform(-.5,.3),
            slope1=rng.uniform(-.7,.7),b2=rng.uniform(-.4,1.4),
            gain=rng.uniform(-.65,.65),slope2=rng.uniform(-.7,.7),
            drift=rng.uniform(-.5,.5),diffusion=rng.uniform(.2,1.5),
            t1=rng.uniform(.1,2.4),t2=rng.uniform(.1,2.4))
        q,_=probability_quad(p)
        v,_=probability_torch(p,order=256)
        errrows.append({'id':i,'abs_difference':abs(float(v.detach())-q)})
    # Pure scalar Python/Eager CPU timing is explanatory only, not P5 evidence.
    sample=panels[0]
    _=probability_torch(sample)
    durations=[]
    for _ in range(80):
        start=time.perf_counter_ns()
        val,_=probability_torch(sample)
        _=float(val.detach())
        durations.append((time.perf_counter_ns()-start)/1e6)
    files=['p2_moving_affine_boundary.py','test_p2_moving_affine_boundary.py','p2_moving_affine_evidence.py']
    digests={f:hashlib.sha256((HERE/f).read_bytes()).hexdigest() for f in files}
    output={'admission':'DENY_ALL / NO_GO','production_activation':False,
      'all_scientific_blockers_closed':False,'research_scope':'P2 linear-within-stage causal Brownian boundary',
      'python_tests':9,'checkpoint_panels':rows,'signed_gradients':gradrows,
      'randomized_adversarial_panels':150,
      'randomized_max_abs_quad_vs_torch':max(v['abs_difference'] for v in errrows),
      'checkpoint_max_abs_quad_vs_torch':max(v['torch_vs_quad_abs'] for v in rows),
      'max_abs_descriptive_mc_z':max(abs(v['mc_z_descriptive']) for v in rows),
      'max_abs_signed_grad_fd_error':max(v['absolute_difference'] for v in gradrows),
      'mc_total_paths':len(rows)*180000,
      'cpu_scalar_eager_p50_ms':statistics.median(durations),
      'source_sha256':digests,
      'limits':['No original coupled HX, no regenerative QVI',
      'Noncertified quadrature error outside exercised panels',
      'No learned multi-event memory or Selective Copy/MQAR',
      'No P3/P4 real multimodal encoder or P5 power/p99 or P6 scaling']}
    path=HERE/'gates'/'2026-10-31-iteration17-evidence.json'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(output,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in output.items() if k in (
        'admission','checkpoint_max_abs_quad_vs_torch','max_abs_descriptive_mc_z',
        'max_abs_signed_grad_fd_error','randomized_max_abs_quad_vs_torch','mc_total_paths',
        'cpu_scalar_eager_p50_ms')},indent=2))
    print('written',path)
    return output

if __name__=='__main__': run()
