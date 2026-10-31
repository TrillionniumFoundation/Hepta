"""Reproduce fixed-trace time-unit counterexample with raw inputs and digests."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import numpy as np
from .p2_refractory_time_invariance import (
    sampling_grid,elapsed_edge_refractory,token_edge_refractory,accepted_times)


def run():
    cases=[]
    for dt in (.25,.125):
        raw,t=sampling_grid(dt)
        physical,_=elapsed_edge_refractory(raw,t,seconds=2.)
        token=token_edge_refractory(raw,cooldown_tokens=5)
        cases.append({'dt_seconds':dt,'sample_count':int(t.shape[1]),
                      'raw_event_times_seconds':accepted_times(raw,t)[0],
                      'physical_event_times_seconds':accepted_times(physical,t)[0],
                      'token_event_times_seconds':accepted_times(token,t)[0],
                      'input_sha256':hashlib.sha256(raw.tobytes()+t.tobytes()).hexdigest()})
    assert cases[0]['raw_event_times_seconds']==cases[1]['raw_event_times_seconds']==[0.,1.,2.,3.,4.,5.]
    assert cases[0]['physical_event_times_seconds']==cases[1]['physical_event_times_seconds']==[0.,2.,4.]
    assert cases[0]['token_event_times_seconds']==[0.,2.,4.]
    assert cases[1]['token_event_times_seconds']==[0.,1.,2.,3.,4.,5.]
    src=Path(__file__).with_name('p2_refractory_time_invariance.py')
    tst=Path(__file__).with_name('test_p2_refractory_time_invariance.py')
    return {'schema':'hcsn.p2-refractory-clock-unit-counterexample.v1',
            'reference_parent_pr':512,'parent_branch_at_inspection':'research/hcsn-edge-refractory-negative-20261031-gpt6',
            'parent_sha_at_inspection':'52de111d3b6e6931a5500f3985e54c8f6eeac9dc',
            'python':platform.python_version(),'numpy':np.__version__,
            'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),
            'test_sha256':hashlib.sha256(tst.read_bytes()).hexdigest(),
            'evidence_generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'fixed_trace_only':True,'true_pretrained_encoder':False,
            'learned_boundary':False,'solves_original_hx_qvi':False,
            'end_to_end_model_clock_invariance_tested':False,
            'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,'independent_attestation':False,
            'interpretation':'Inserted non-hit samples change token-based cooldown decisions although true hit timestamps are unchanged; the elapsed-clock reference is sampling-invariant only in this frozen trace experiment.',
            'cases':cases}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    if a.output.exists():ap.error('Refuse overwriting existing evidence')
    result=run()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
