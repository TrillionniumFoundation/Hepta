"""Regenerate fixed-seed query-only training and OOD diagnostics. Research only."""
import argparse
import json
import math
import random
from pathlib import Path
import numpy as np
from scipy.optimize import minimize_scalar
from research.hcsn.p2_joint_input_hazard import DEFAULT_RATES,parity_probability,task_parity
from research.hcsn.test_p2_joint_input_hazard import ode_parity_reference


def safe_loss(n1,n,p):
    return -(n1*math.log(max(1e-12,p))+(n-n1)*math.log(max(1e-12,1-p)))


def generate(seed,beta_true,xs,n):
    rng=random.Random(seed);out=[]
    for x in xs:
        seg=[(0.7,float(x))]
        successes=sum(task_parity(seg,rng.randrange(1<<62),beta_true) for _ in range(n))
        out.append(dict(x=float(x),n=n,odd=successes,reference_probability=parity_probability(seg,beta_true)))
    return out


def evaluate(beta,rows):
    loss=0; brier=0
    for r in rows:
        p=parity_probability([(0.7,r['x'])],beta)
        loss+=safe_loss(r['odd'],r['n'],p)
        brier+=r['odd']*(1-p)**2+(r['n']-r['odd'])*p*p
    return {'nll_per_example':loss/sum(r['n'] for r in rows),'brier':brier/sum(r['n'] for r in rows)}


def run(train_n=200,test_n=300):
    true=1.0
    train_x=np.linspace(-0.9,0.9,15)
    ood_x=(-1.8,-1.4,1.4,1.8)
    rows=[]; maxima=0
    # Independent SciPy ODE vs expm across three piecewise schedules.
    for s in ([(.5,-.5),(.5,.8)],[(.1,1.7),(.6,-1.)],[(.25,0.),(.25,1.),(.5,-1.)]):
        maxima=max(maxima,abs(parity_probability(s,true)-ode_parity_reference(s,true)))
    for seed in (11,23,37):
        train=generate(seed*17+3,true,train_x,train_n)
        ood=generate(seed*19+7,true,ood_x,test_n)
        objective=lambda beta:evaluate(beta,train)['nll_per_example']
        fit=minimize_scalar(objective,bounds=(-2.4,2.4),method='bounded',options={'xatol':1e-8})
        if not fit.success:raise RuntimeError(fit.message)
        fitted=float(fit.x)
        rows.append({'seed':seed,'beta_true':true,'beta_fitted':fitted,
                     'train':train,'ood':ood,
                     'train_fitted':evaluate(fitted,train),
                     'ood_fitted':evaluate(fitted,ood),
                     'ood_constant_null':evaluate(0.,ood),
                     'ood_true_oracle':evaluate(true,ood)})
    return {'schema':'hcsn.iteration35.input-conditioned-joint-hazard.v1',
            'claims_scope':'two-mode synthetic marked hazard only; not brownian/QVI/HCSN/free-boundary; P0-P6 OPEN',
            'fixed_rates':DEFAULT_RATES,'training':'parity labels only, zero access to event timestamps, mode or event count',
            'train_per_x':train_n,'ood_per_x':test_n,'max_scipy_ode_difference':maxima,
            'rows':rows,'negative_controls_preserved':True,'production_activation':False,
            'gate_states':{f'P{i}':'OPEN' for i in range(7)}}


def main():
    p=argparse.ArgumentParser();p.add_argument('--train-n',type=int,default=200);p.add_argument('--test-n',type=int,default=300);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not 10<=a.train_n<=100000 or not 10<=a.test_n<=100000:raise ValueError('invalid sample budget')
    a.output.write_text(json.dumps(run(a.train_n,a.test_n),sort_keys=True,indent=2)+'\n')

if __name__=='__main__':main()
