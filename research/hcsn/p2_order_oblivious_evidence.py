"""Deterministic independent P2 negative witness, not a gate closure."""
import json
from pathlib import Path
from scipy.integrate import solve_ivp
from research.hcsn.p2_joint_input_hazard import parity_generator,parity_probability
from research.hcsn.p2_order_oblivious_hazard import (
    ordered_last_write_pair,endpoint_distribution,exposure,
    balanced_pair_endpoint_ceiling,online_endpoint
)
import numpy as np

def run():
    (a,label_a),(b,label_b)=ordered_last_write_pair()
    rows=[];mx=0;total=0;mismatch=0
    for beta in (-1.8,-1.1,-0.5,0.,0.7,1.3,1.8):
        da,db=endpoint_distribution(a,beta),endpoint_distribution(b,beta)
        # Independent time-variable ODE reference (not SciPy expm / clock itself).
        q=parity_generator(((4.,.25),(.7,.07)),0.,0.)
        initial=np.array([1.,0.,0.,0.])
        def ode(segments):
            v=initial.copy()
            for duration,x in segments:
                sol=solve_ivp(lambda _,v:np.exp(beta*x)*(v@q),(0.,duration),v,
                              method='DOP853',rtol=2e-12,atol=2e-14)
                if not sol.success:raise RuntimeError(sol.message)
                v=sol.y[:,-1]
            return v
        oa,ob=ode(a),ode(b)
        gap=float(max(abs(da-db)))
        err=float(max(max(abs(da-oa)),max(abs(db-ob))))
        mx=max(mx,err)
        for seed in range(3000):
            total+=1
            if online_endpoint(a,seed,beta)!=online_endpoint(b,seed,beta):mismatch+=1
        rows.append({'beta':beta,'exposure_a':exposure(a,beta),'exposure_b':exposure(b,beta),
                     'parity_a':parity_probability(a,beta),'parity_b':parity_probability(b,beta),
                     'four_state_a':da.tolist(),'four_state_b':db.tolist(),
                     'max_analytic_endpoint_gap':gap,'max_independent_ode_error':err,
                     'balanced_last_write_bayes_accuracy_ceiling':balanced_pair_endpoint_ceiling(a,b,beta),
                     'paired_pathwise_endpoints_checked':3000})
    return {'schema':'hcsn.iteration36.order-oblivious-marked-hazard.v1',
            'scope':'iteration35 common-scalar hazard ENDPOINT only; not event timestamps, Brownian first-hit, full HCSN, or neural dynamic boundary',
            'ordered_pair_a':a,'ordered_pair_b':b,'label_a':label_a,'label_b':label_b,
            'rows':rows,'sampled_path_pairs':total,'paired_endpoint_mismatches':mismatch,
            'max_independent_ode_error':mx,'all_scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,'negative_controls_preserved':True}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();args.output.write_text(json.dumps(run(),indent=2,sort_keys=True)+'\n')
