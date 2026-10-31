"""Deterministic exploratory autograd/FD check on moving-boundary events.

Not a learned neural benchmark; excludes discontinuous event-count surfaces.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch

try:
    from .moving_boundary_events import simulate_moving_boundary
except ImportError:
    from moving_boundary_events import simulate_moving_boundary


def t(v, grad=False):
    return torch.tensor(v,dtype=torch.float64,requires_grad=grad)


def run(seed:int=940471,attempts:int=128):
    rng=np.random.default_rng(seed)
    checked=0;skipped_no_events=0;skipped_transition=0
    count_hist={};max_diff=0.;worst=None;components=0
    for i in range(attempts):
        x0=float(rng.uniform(.65,1.1));b0=0.;reset=float(rng.uniform(.5,.9))
        sv=rng.uniform(-.14,.08,size=3);bv=rng.uniform(.32,.64,size=3)
        dt=rng.uniform(.9,1.9,size=3)
        base=[x0,b0,reset,sv.tolist(),bv.tolist(),dt.tolist()]
        q=simulate_moving_boundary(*(t(v,True) for v in base))
        if len(q.event_times)==0:
            skipped_no_events+=1;continue
        endpoints=np.cumsum(dt)
        if np.min(np.abs(q.event_times.detach().numpy()[:,None]-endpoints[None,:]))<.06:
            skipped_transition+=1;continue
        # Recompute inputs explicitly for independent signed parameter VJPs.
        p=[t(v,True) for v in base]
        result=simulate_moving_boundary(*p)
        loss=result.event_times.sum()+.1*result.log_state_end
        exact_grads=torch.autograd.grad(loss,p)
        def objective(values):
            sim=simulate_moving_boundary(*(t(v) for v in values))
            if len(sim.event_times)!=len(result.event_times):
                raise ArithmeticError('Transition crossed during fixed-count derivative check')
            return float(sim.event_times.sum()+.1*sim.log_state_end)
        for group,index in [(0,0),(1,0),(2,0)]+[(j,k) for j in (3,4,5) for k in range(3)]:
            plus=[base[0],base[1],base[2],list(base[3]),list(base[4]),list(base[5])]
            minus=[base[0],base[1],base[2],list(base[3]),list(base[4]),list(base[5])]
            eps=1.e-6
            if group<3:
                plus[group]+=eps;minus[group]-=eps
                analytic=float(exact_grads[group].detach())
            else:
                plus[group][index]+=eps;minus[group][index]-=eps
                analytic=float(exact_grads[group][index].detach())
            diff=abs((objective(plus)-objective(minus))/(2*eps)-analytic)
            components+=1
            if diff>max_diff:
                max_diff=diff;worst={'attempt':i,'group':group,'index':index,'error':diff}
        count_hist[str(len(result.event_times))]=count_hist.get(str(len(result.event_times)),0)+1
        checked+=1
    return {'schema':'hcsn.p2-moving-free-boundary-gradient-sanity.v1',
            'seed':seed,'attempts':attempts,'checked_fixed_event_count':checked,
            'skipped_zero_events':skipped_no_events,
            'skipped_near_event_count_transitions':skipped_transition,
            'signed_gradient_components':components,
            'largest_abs_gradient_discrepancy':max_diff,
            'worst_case':worst,'event_count_histogram':count_hist,
            'scope':'deterministic piecewise-affine moving free boundary; fixed event count only',
            'supports_event_count_differentiation':False,
            'p2_scientific_gate':'OPEN','production_activation':False,
            'source_sha256':{name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
                             for name in ('moving_boundary_events.py','test_moving_boundary_events.py','p2_moving_boundary_evidence.py')}}


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True)
    args=p.parse_args()
    out=run()
    with open(args.output,'x',encoding='utf-8') as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({k:v for k,v in out.items() if k in ('checked_fixed_event_count','signed_gradient_components','largest_abs_gradient_discrepancy','skipped_near_event_count_transitions')}))
    return 0 if out['checked_fixed_event_count']>=90 and out['largest_abs_gradient_discrepancy']<5e-6 else 3


if __name__=='__main__':raise SystemExit(main())
