"""Reproduce bounded retrospective state-coupled barrier negative control.

Run with Python 3 and pinned environment versions recorded in emitted JSON.
Does not sign evidence, claim learned HCSN, or activate a gate.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import platform

import mpmath
import numpy as np
import scipy

try:
    from research.hcsn.p2_endogenous_feedback_bridge import (
        FeedbackBridge, exact_feedback_hit, invalid_frozen_sigma_hit,
        transformed_margin_hit, mp_reference, midpoint_quadrature,
        midpoint_bridge_mc)
except ModuleNotFoundError:
    from p2_endogenous_feedback_bridge import (
        FeedbackBridge, exact_feedback_hit, invalid_frozen_sigma_hit,
        transformed_margin_hit, mp_reference, midpoint_quadrature,
        midpoint_bridge_mc)

SCENARIOS = (
    ('symmetric',.4,.4,.4,1.),
    ('asymmetric',.2,.6,.7,.8),
    ('late_skew',.9,.3,.6,1.5),
)
GAINS=(-.5,0.,.5,.75,.9)
SEEDS=(11,23,37)
TRIALS=120_000


def run(parent_sha: str) -> dict:
    rows=[]
    for tag,a,b,sigma,T in SCENARIOS:
        for gain in GAINS:
            p=FeedbackBridge(a=a,b=b,sigma=sigma,horizon=T,gain=gain)
            truth=exact_feedback_hit(p)
            wrong=invalid_frozen_sigma_hit(p)
            transformed=transformed_margin_hit(p)
            high_precision=mp_reference(p)
            quad,estimated_error=midpoint_quadrature(p)
            if abs(quad-truth)>max(1e-11,10*estimated_error):
                raise AssertionError(f'independent midpoint integral disagreement: {tag}/{gain}')
            if abs(float(high_precision)-truth)>2e-15 or abs(transformed-truth)>2e-15:
                raise AssertionError(f'independent transformed/high-precision disagreement: {tag}/{gain}')
            for seed in SEEDS:
                mc,se,count=midpoint_bridge_mc(p,n=TRIALS,seed=seed)
                z=abs(mc-truth)/se
                if z>6.0:
                    raise AssertionError(f'independent Monte Carlo disagreement: {tag}/{gain}/{seed}: {z}')
                rows.append({
                    'scenario':tag,'parameters':asdict(p), 'seed':seed,
                    'mc_n':TRIALS,'mc_hits':count,'mc_probability':mc,'mc_standard_error':se,
                    'mc_abs_z':z, 'true_hit':truth,
                    'wrong_deterministic_barrier_extrapolation':wrong,
                    'difference_wrong_minus_true':wrong-truth,
                    'transformed_margin_hit':transformed,
                    'mp80_hit_decimal':high_precision,
                    'independent_midpoint_quadrature':quad,
                    'quadrature_error_estimate_plus_tail':estimated_error,
                })
    source=Path(__file__).with_name('p2_endogenous_feedback_bridge.py')
    test=Path(__file__).with_name('test_p2_endogenous_feedback_bridge.py')
    return {
        'schema':'hcsn.p2-endogenous-feedback-retrospective-negative.v1',
        'source_parent_pr512_head':parent_sha,
        'limitations':[
            'Research-only constant-volatility Brownian bridge conditional on both endpoints',
            'Gain is fixed within each interval and may be selected causally from past input; not trained in this experiment',
            'This is a counterexample to incorrectly freezing sigma for an adapted state-dependent boundary, not a bug claim about existing deterministic-boundary methods',
            'Midpoint MC uses exact half-bridge hit indicators and does not simulate realized hit times',
            'Equal seed across feedback gains deliberately reuses same paired Brownian paths',
            'Quadrature error is an estimate with Gaussian tail bound, not a rigorous outward-rounded proof',
            'Not He-Xiong A7/global QVI, end-to-end MQAR, pretrained multimodal encoder, real hardware, or production evidence',
        ],
        'environment':{'python':platform.python_version(),'numpy':np.__version__,
                       'scipy':scipy.__version__,'mpmath':mpmath.__version__,
                       'platform':platform.platform()},
        'sha256':{str(p.name):sha256(p.read_bytes()).hexdigest() for p in (source,test)},
        'paired_seeds':list(SEEDS),'trials_per_row':TRIALS,
        'num_rows':len(rows),'max_mc_abs_z':max(row['mc_abs_z'] for row in rows),
        'max_quadrature_abs_error':max(abs(row['true_hit']-row['independent_midpoint_quadrature']) for row in rows),
        'gates':{f'P{i}':'OPEN' for i in range(7)},
        'scientific_closure':False,'production_activation':False,
        'rows':rows,
    }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-parent-sha',required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite evidence file')
    if len(args.source_parent_sha)!=40 or any(x not in '0123456789abcdef' for x in args.source_parent_sha):
        parser.error('Expected full 40-character lowercase Git commit SHA')
    result=run(args.source_parent_sha)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n','utf-8')
    print(f"{result['num_rows']} cases; max_mc_abs_z={result['max_mc_abs_z']:.4f}; "
          f"max_quad_abs_error={result['max_quadrature_abs_error']:.3e}; P0-P6 OPEN")


if __name__=='__main__':main()
