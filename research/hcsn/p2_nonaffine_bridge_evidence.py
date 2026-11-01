"""Emit frozen raw P2 non-affine midpoint bridge bounds, no production claims."""
import argparse
import json
from pathlib import Path
try:
    from .p2_nonaffine_bridge_enclosure import (TentBridge,flat_affine_hit,
        midpoint_hit_lower_bound,tent_hit_quadrature,tent_hit_bridge_mc)
except ImportError:
    from p2_nonaffine_bridge_enclosure import (TentBridge,flat_affine_hit,
        midpoint_hit_lower_bound,tent_hit_quadrature,tent_hit_bridge_mc)

def run():
    settings=[]
    for h in (0.,.2,.4,.6):
        p=TentBridge(height=h)
        q,err=tent_hit_quadrature(p)
        ph,se,hits=tent_hit_bridge_mc(p,n=120000,seed=20261101)
        settings.append({'barrier_height':h,'parameters':vars(p),
            'affine_flat_endpoint_formula':flat_affine_hit(p),
            'midpoint_hit_lower_bound':midpoint_hit_lower_bound(p),
            'tent_integral_hit_probability':q,
            'quadrature_estimate_plus_omitted_gaussian_tail':err,
            'bridge_mc_hit_fraction':ph,'bridge_mc_standard_error':se,
            'bridge_mc_hit_count':hits,'bridge_mc_trials':120000,
            'bridge_mc_seed':20261101})
    return {'schema':'hcsn.p2.nonaffine_bridge_endpoint_counterexample.v1',
        'scientific_gate':'OPEN','production_activation':False,
        'source_assumptions':'Brownian bridge conditioned on both safe endpoints; deterministic tent boundary with midpoint kink; constant diffusion and drift; no recurrent reset',
        'retrospective_only':True,'scientifically_independent_certification':False,
        'comparison':settings}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing overwrite')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(run(),indent=2,sort_keys=True)+'\n')
