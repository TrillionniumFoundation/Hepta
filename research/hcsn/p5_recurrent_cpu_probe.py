"""P5 subgate CPU *complete recurrent-head forward* timing and hard events.

This is end-to-end from synthetic sequence features through recurrent head
and logits; it does NOT include a real modality encoder, input IO, GPU, power
or optimized fused kernels.  All raw iterations, CPU time and process peak
RSS are exposed to avoid false claims of energy or large-model throughput.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import time
import numpy as np
import torch
try:
    from .p2_regen_recall import RegenerativeRNN,ResetGRU,make_joint_reset
except ImportError:
    from p2_regen_recall import RegenerativeRNN,ResetGRU,make_joint_reset


def run_cpu_probe(n_list=(64,256,1024,4096),lengths=(30,60),repeats=30):
    if repeats<10 or not n_list or not lengths:
        raise ValueError('Need repeatable CPU sample sizes')
    torch.set_num_threads(1)
    torch.manual_seed(20261031)
    nets={'analytic':RegenerativeRNN(mode='analytic'),
          'ordinary':RegenerativeRNN(mode='ordinary'),
          'gru':ResetGRU()}
    for m in nets.values():m.eval()
    results=[]
    for length in lengths:
        for n in n_list:
            x,_=make_joint_reset(n,length,seed=length*100000+n,irregular=True)
            for name,net in nets.items():
                with torch.inference_mode():
                    for _ in range(4):net(x)
                    t=[]; cpu=[]; finite=True
                    for _ in range(repeats):
                        t0=time.perf_counter_ns()
                        c0=time.process_time_ns()
                        y=net(x)
                        cpu.append(time.process_time_ns()-c0)
                        t.append(time.perf_counter_ns()-t0)
                        finite=finite and bool(torch.isfinite(y).all())
                    assert finite
                t_arr=np.asarray(t,dtype=np.float64)/1e6
                cpu_arr=np.asarray(cpu,dtype=np.float64)/1e6
                results.append({'architecture':name,'batch':n,'length':length,
                    'trainable_parameters':sum(p.numel() for p in net.parameters()),
                    'p50_end_to_end_head_ms':float(np.quantile(t_arr,.5)),
                    'p95_end_to_end_head_ms':float(np.quantile(t_arr,.95)),
                    'p99_end_to_end_head_ms':float(np.quantile(t_arr,.99)),
                    'mean_process_cpu_ms':float(cpu_arr.mean()),
                    'sequences_per_sec_at_p50':float(n/(np.quantile(t_arr,.5)/1e3)),
                    'peak_process_rss_mb_so_far':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
                    'all_outputs_finite':finite,
                    'raw_wall_ms':[round(float(v),6) for v in t_arr]})
    return {'schema':'hcsn.p5-cpu-complete-recurrent-head.v1',
        'device':'cpu','torch':str(torch.__version__),'python':platform.python_version(),
        'torch_threads':1,'repeats':repeats,'results':results,
        'pretrained_encoder_included':False,'gpu':False,'energy_joules':None,
        'fused_kernels':False,'p5_closed':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--repeats',type=int,default=30)
    a=p.parse_args()
    if a.output.exists():p.error('Refusing overwrite')
    data=run_cpu_probe(repeats=a.repeats)
    data['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    for row in data['results']:
        if row['batch']==4096:print(row['architecture'],row['length'],round(row['p99_end_to_end_head_ms'],3),'ms p99',flush=True)
