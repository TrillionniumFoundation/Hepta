"""Small bounded P0/P2 iteration-5 evidence recorder; fails closed on error.

Not a phase closure certificate; all seven gates remain OPEN. Record the
actual computed errors, independent analytic reference, test command,
source hashes, limitations and frozen experimental parameters.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
import torch
from .hx_original import HXParams,closed_boundary,bond_price_from_log
from .bond_fd_reference import solve_bond_pde
from .autonomous_event_time import simulate_autonomous,event_time_calibration


def build_evidence() -> dict:
    pde=[]
    for p in [HXParams(),HXParams(xi=0.,k=0.),HXParams(sigma=.4,delta=.04,alpha=.55,maturity=.75)]:
        vb=closed_boundary(p)
        for tau in (.2*p.maturity,p.maturity):
            solution=solve_bond_pde(p,vb,tau,max_x=7.,points=501,steps=1400)
            samples=[]
            for x in (.12,.3,.6,1.2,2.):
                a=solution.at(x)
                b=bond_price_from_log(x,tau,vb,p)
                samples.append({'x':x,'pde':a,'closed_form':b,'abs_error':abs(a-b),
                                'rel_error':abs(a-b)/max(1.,abs(b))})
            pde.append({'params':asdict(p),'tau':tau,'free_boundary':vb,
                        'dx':solution.dx,'steps':solution.steps,
                        'max_abs_error':max(s['abs_error'] for s in samples),
                        'max_rel_error':max(s['rel_error'] for s in samples),
                        'samples':samples})
    def t(x,grad=False):return torch.tensor(x,dtype=torch.float64,requires_grad=grad)
    m=t(.8,True);reset=t(.6,True)
    rates=t([.38,.41,.43],True);durations=t([2.,2.,3.],True)
    path=simulate_autonomous(m,reset,rates,durations)
    score=sum((k+1)*v for k,v in enumerate(path.events))+.1*path.margin_end
    grad=torch.autograd.grad(score,(m,reset,rates,durations))
    def scalar(inputs):
        result=simulate_autonomous(t(inputs[0]),t(inputs[1]),
                                  t(inputs[2]),t(inputs[3]))
        if len(result.events)!=len(path.events):
            raise ArithmeticError('Crossed a nonsmooth event-count surface during FD')
        return sum((k+1)*float(v) for k,v in enumerate(result.events))+.1*float(result.margin_end)
    base=[float(m.detach()),float(reset.detach()),rates.detach().tolist(),durations.detach().tolist()]
    diffs=[]
    for kind,index in ((0,0),(1,0),(2,0),(2,1),(2,2),(3,0),(3,1),(3,2)):
        x=[base[0],base[1],list(base[2]),list(base[3])]
        y=[base[0],base[1],list(base[2]),list(base[3])]
        eps=1e-6
        if kind<2:
            x[kind]+=eps;y[kind]-=eps
            v=float(grad[kind])
        else:
            x[kind][index]+=eps;y[kind][index]-=eps
            v=float(grad[kind][index])
        approx=(scalar(x)-scalar(y))/(2*eps)
        diffs.append({'variable':kind,'index':index,'autograd':v,
                      'fd':approx,'abs_error':abs(v-approx)})
    source_files=['bond_fd_reference.py','test_bond_fd_reference.py',
                  'autonomous_event_time.py','test_autonomous_event_time.py',
                  'iteration5_evidence.py']
    path_here=Path(__file__).parent
    return {'schema':'hcsn.p0-p6.iteration5.v1',
            'timestamp_utc':datetime.now(timezone.utc).isoformat(),
            'production_activation':False,
            'science_gates':{f'P{k}':'OPEN' for k in range(7)},
            'p0_bond_independent_pde':{
                'n_param_and_maturity_cases':len(pde),
                'sample_points_per_case':5,
                'max_abs_error':max(z['max_abs_error'] for z in pde),
                'max_rel_error':max(z['max_rel_error'] for z in pde),
                'method':'monotone implicit backward Euler, finite log grid',
                'details':pde},
            'p2_autonomous':{
                'event_count':len(path.events),
                'max_signed_autograd_fd_abs_error':max(x['abs_error'] for x in diffs),
                'gradient_checks':diffs,
                'calibration':event_time_calibration(),
                'limited_to_fixed_event_count':True},
            'source_sha256':{x:hashlib.sha256((path_here/x).read_bytes()).hexdigest()
                             for x in source_files},
            'limitations':[
                'No global all-domain truncation/quantization certification of paper Eq. (8) or (A7)',
                'No stochastic or learned boundary event-time differentiability proof',
                'Event count is non-differentiable; fixed-count calibration is an illustrative toy',
                'No independent real data/model P1 superiority, real encoder, GPU or energy evidence',
                'All P0-P6 phase gates remain OPEN until independent scientific acceptance'
            ]}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('Refusing overwrite')
    out=build_evidence()
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'max_p0_pde_abs_error':out['p0_bond_independent_pde']['max_abs_error'],
                      'max_p0_pde_rel_error':out['p0_bond_independent_pde']['max_rel_error'],
                      'max_p2_gradient_error':out['p2_autonomous']['max_signed_autograd_fd_abs_error'],
                      'calibration':out['p2_autonomous']['calibration'],
                      'science_gates':out['science_gates']},indent=2))
