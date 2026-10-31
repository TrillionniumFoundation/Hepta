"""Create-only P0 *negative* evidence for financial HX obstacle admissibility.

This panel intentionally retains every attempted case and every numerical
failure; counts are descriptive only. No heldout model performance is tested.
No score/threshold is used to enable a scientific or production gate.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random

try:
    from .hx_original import HXParams, equity_green
    from .hx_equity_fd_independent import solve_equity_fd
    from .hx_local_obstacle_sign import as_evidence, screen_hx_smooth_fit
except ImportError:
    from hx_original import HXParams, equity_green
    from hx_equity_fd_independent import solve_equity_fd
    from hx_local_obstacle_sign import as_evidence, screen_hx_smooth_fit


SEED = 20261031
COUNT = 256


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def panel_inputs():
    rng=random.Random(SEED)
    for i in range(COUNT):
        yield i, HXParams(r=rng.uniform(.05,.13),
               delta=rng.uniform(.015,.08),
               sigma=rng.uniform(.10,.45),
               alpha=rng.uniform(.25,.75),
               tax=rng.uniform(.05,.4),
               xi=rng.uniform(0.,6.),
               k=rng.uniform(0.,.25),
               maturity=rng.uniform(.5,4.),
               coupon_total=rng.uniform(3.,13.),
               face_total=rng.uniform(45.,110.))


def compute():
    reference=Path(__file__).resolve().parent
    baseline=HXParams()
    adversary=HXParams(r=.10,delta=.075,sigma=.20,alpha=.40,tax=.27,
                       xi=4.,k=.20,maturity=3.,coupon_total=5.,face_total=100.)
    records=[]
    counts={'REJECT_NEGATIVE_EQUITY_NEAR_BOUNDARY':0,
            'NO_LOCAL_SIGN_OBSTRUCTION_ONLY':0,'INDETERMINATE_SIGN':0,
            'NUMERICALLY_UNRESOLVED':0,
            'REJECT_WITH_RECOVERY_BELOW_FACE':0}
    for i,p in panel_inputs():
        try:
            out=as_evidence(p)
            outcome=out['local_sign_screen']['classification']
            counts[outcome]+=1
            if (outcome=='REJECT_NEGATIVE_EQUITY_NEAR_BOUNDARY'
                    and out['local_sign_screen']['recovery_over_face']<1):
                counts['REJECT_WITH_RECOVERY_BELOW_FACE']+=1
            records.append({'index':i,**out})
        except (ValueError, ArithmeticError, OverflowError, ZeroDivisionError) as ex:
            counts['NUMERICALLY_UNRESOLVED']+=1
            records.append({'index':i,'parameters':asdict(p),
                            'classification':'NUMERICALLY_UNRESOLVED',
                            'error_type':type(ex).__name__,
                            'error_message':str(ex)})
    b=screen_hx_smooth_fit(adversary)
    v=b.boundary
    independent_green={str(x):float(equity_green(v*__import__('math').exp(x),v,adversary))
                       for x in (.005,.02,.05,.1,.2)}
    independent_fd={}
    for cells in (800,1600,3200):
        sol=solve_equity_fd(adversary,v,cells=cells,x_max=7.)
        mask=(sol.x>=.025)&(sol.x<=.09)
        independent_fd[str(cells)]={'min_equity_x0025_009':float(sol.equity[mask].min()),
                                    'max_eq_residual':sol.max_equation_residual,
                                    'boundary_log_derivative':sol.boundary_log_derivative}
    return {
        'schema':'hcsn.p0-hx-necessary-local-obstacle-rejection.v1',
        'date':'2026-10-31',
        'paper':'He and Xiong (2012), Journal of Finance, Eq (8),(11),(12)',
        'input_distribution':{'seed':SEED,'count':COUNT,
                'ranges':'see panel_inputs() frozen Python random.Random uniform bounds'},
        'counts':counts,
        'cases':records,
        'paper_baseline':as_evidence(baseline),
        'primary_counterexample':{
            'parameters':asdict(adversary),
            'local_sign_screen':asdict(b),
            'independent_green_equity':independent_green,
            'independent_fixed_boundary_fd':independent_fd,
            'obstacle_satisfied':False,
            'reason':'Negative boundary curvature forces negative equity immediately above smooth-fit candidate',
            'scope':'Fixed financial HX bond-equity model; numeric finite-domain verification only'},
        'hashes':{name:sha(reference/name) for name in (
            'hx_original.py','hx_equity_fd_independent.py',
            'hx_local_obstacle_sign.py','test_hx_local_obstacle_sign.py',
            'p0_local_obstacle_evidence.py')},
        'preregistration':False,
        'p0_full_domain_certified':False,
        'p0_scientific_gate':'OPEN',
        'p1_p6_scientific_gates':'OPEN',
        'production_activation':False,
        'all_scientific_blockers_closed':False,
        'full_repo_ci_verified':False,
        'external_signature_verified':False,
        'notes':'Finite binary64 screen; positive net flow yields local sign obstruction under C2 regularity. Negative net flow is NOT sufficient for global obstacle feasibility. No formal interval bounds or machine-learning advantage claimed.'
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',required=True,type=Path)
    args=ap.parse_args()
    report=compute()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as f:
        json.dump(report,f,indent=2,sort_keys=True,allow_nan=False)
        f.write('\n')
    print(json.dumps({'cases':COUNT,'counts':report['counts'],
                     'counterexample':report['primary_counterexample']['local_sign_screen'],
                     'output':str(args.output)},indent=2))


if __name__=='__main__':main()
