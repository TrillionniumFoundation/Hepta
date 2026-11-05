"""Generate immutable raw retrospective P2 offcenter-tent research evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform

try:
    from .p2_offcenter_tent_reference import (OffcenterTent,hit_mp_closed_form,
                                                hit_quadrature,hit_bridge_mc)
except ImportError:
    from p2_offcenter_tent_reference import (OffcenterTent,hit_mp_closed_form,
                                            hit_quadrature,hit_bridge_mc)


def evidence() -> dict:
    rows=[]
    for c in (.1,.25,.5,.75,.9):
        p=OffcenterTent(apex_fraction=c)
        mp=hit_mp_closed_form(p,dps=80)
        quadrature,err=hit_quadrature(p)
        seeds=[]
        for seed in (20261101,20261102,20261103):
            observed,se,count=hit_bridge_mc(p,n=120_000,seed=seed)
            seeds.append({'seed':seed,'n':120000,'count':count,
                          'fraction':observed,'standard_error':se,
                          'z_against_mp80':(observed-mp)/se if se>0 else None})
        rows.append({'parameters':vars(p),'mp80_closed_form':mp,
                     'independent_scipy_quadrature':quadrature,
                     'quadrature_error_estimate_plus_normal_tail':err,
                     'abs_quad_mp80':abs(quadrature-mp),'monte_carlo':seeds})
    source=Path(__file__).with_name('p2_offcenter_tent_reference.py')
    tests=Path(__file__).with_name('test_p2_offcenter_tent_reference.py')
    return {'schema':'hcsn.p2.offcenter_tent_retro_bridge.v1',
            'source_ref_before_patch':'8e3806cfb9a1aa4b62292ac02b5e7eca3498b66a',
            'source_blob_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'test_blob_sha256':hashlib.sha256(tests.read_bytes()).hexdigest(),
            'python_version':platform.python_version(),
            'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,
            'retrospective_requires_future_endpoint':True,
            'independently_attested':False,
            'assumptions':'Constant diffusion; conditioned on two safe observed endpoints; deterministic piecewise-affine tent with fixed offcenter apex; Brownian half bridges independent given apex state; no learned barrier, recurrent reset, causal event time or multimodal encoding',
            'source_commands':['OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p test_p2_offcenter_tent_reference.py -v',
                               'OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_offcenter_tent_evidence --output research/hcsn/gates/2026-11-01-iteration25-offcenter-tent.json',
                               'python -m research.hcsn.independent_gate --bundle research/hcsn --strict'],
            'cases':rows}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing overwrite of immutable research evidence')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(evidence(),sort_keys=True,indent=2)+'\n','utf8')
