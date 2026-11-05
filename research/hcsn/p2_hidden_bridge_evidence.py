"""Deterministic audit JSON for P2 missed intra-interval first hits; never gates PASS."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform

import numpy as np
from scipy.integrate import quad
from scipy.stats import norm
from .p2_hidden_bridge_hits import (conditional_hidden_hit, first_hit_cdf,
    missed_endpoint_example, conditional_path_risk)

CASES=((.4,0.,.4,1.),(.63,.17,.65,.8),(.3,-.25,.52,1.5),(.9,.3,.8,2.))


def run():
    rows=[]
    for x0,drift,sigma,t in CASES:
        mean=x0+drift*t
        std=sigma*math.sqrt(t)
        f=lambda x: norm.pdf(x,loc=mean,scale=std)*conditional_hidden_hit(x0,x,t,sigma)
        # Omitted free Gaussian mass beyond [-20,20] is negligible for these
        # frozen cases; this is NOT a universal verified integration bound.
        integral=quad(f,-20.,0.,epsabs=2e-11,epsrel=1e-11)[0]+quad(
            f,0.,20.,epsabs=2e-11,epsrel=1e-11)[0]
        reflection=first_hit_cdf(x0,drift,sigma,t)
        endpoint=float(norm.cdf((0.-mean)/std))
        rows.append({'initial_margin':x0,'drift':drift,'sigma_per_sqrt_second':sigma,
                     'horizon_seconds':t,'exact_first_hit_reflection':reflection,
                     'independent_bridge_endpoint_integral':integral,
                     'abs_crosscheck_error':abs(reflection-integral),
                     'endpoint_only_hit_probability':endpoint,
                     'missed_probability_mass':reflection-endpoint})
    # Fixed-seed exact-endpoint bridge MC (not a time-discretized Brownian path).
    seed=492001;n=180000;x0,drift,sigma,t=.4,-.12,.5,1.4
    rng=np.random.default_rng(seed)
    ends=x0+drift*t+sigma*math.sqrt(t)*rng.standard_normal(n)
    u=rng.random(n)
    count=int(np.count_nonzero((ends<=0)|(u<np.exp(-2*x0*np.maximum(ends,0)/(sigma*sigma*t)))))
    empirical=count/n
    predicted=first_hit_cdf(x0,drift,sigma,t)
    se=math.sqrt(predicted*(1-predicted)/n)
    path=np.array([[.45,.62,.33]],dtype=np.float64)
    clock=np.array([[0.,1.,3.]],dtype=np.float64)
    risk,_=conditional_path_risk(path,clock,sigma=.4)
    home=Path(__file__).parent
    files=('p2_hidden_bridge_hits.py','test_p2_hidden_bridge_hits.py','p2_hidden_bridge_evidence.py')
    return {'schema':'hcsn.p2-hidden-bridge-hits.research-only.v1',
            'parent_pr':512,'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,'independent_external_attestation':False,
            'only_constant_diffusion_affine_deterministic_barrier':True,
            'learned_input_driven_boundary_validated':False,
            'realized_autonomous_spike_times_validated':False,
            'repeated_reset_qvi_validated':False,
            'pretrained_multimodal_encoder_validated':False,
            'local_cpu_only':True,'python':platform.python_version(),
            'numpy':np.__version__,
            'source_sha256':{f:hashlib.sha256((home/f).read_bytes()).hexdigest() for f in files},
            'fixed_zero_drift_counterexample':missed_endpoint_example(),
            'independent_crosschecks':rows,
            'monte_carlo':{'seed':seed,'n':n,'hits':count,'estimate':empirical,
                           'reflection_prediction':predicted,'binomial_se':se,
                           'absolute_error':abs(predicted-empirical),
                           'standardized_deviation':abs(predicted-empirical)/se},
            'two_gap_cumulative_conditional_risk':risk[0].tolist(),
            'interpretation':'An endpoint-only 0/1 detector misses within-interval first crossings even with an elapsed-time refractory filter. The bridge probability estimates risk; it is neither a reconstructed spike timestamp nor validation of a trained neural controller.'}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    if args.output.exists():
        ap.error('refuse overwriting existing audit evidence')
    result=run()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'crosschecks':len(result['independent_crosschecks']),
                      'max_abs_error':max(q['abs_crosscheck_error'] for q in result['independent_crosschecks']),
                      'mc_z':result['monte_carlo']['standardized_deviation'],
                      'scientific_gates':result['scientific_gates']},sort_keys=True))

if __name__=='__main__':main()
