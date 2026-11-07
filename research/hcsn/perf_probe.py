"""Narrow CPU performance observations, not a certified P5 hardware gate.

Feature inference only, PyTorch eager, CPU 1 thread. Reports p50/p99
latency, output elements/s, process peak RSS, and no fabricated energy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import time

import numpy as np
import psutil
import torch
try:from .train_study import two_features
except ImportError:from train_study import two_features

SIZES=(64,256,1024,4096)
MODES=('dual_call_put','ordinary_two_gate','margin_only')


def run_probe(iterations=250):
    torch.set_num_threads(1)
    proc=psutil.Process(os.getpid())
    rng=np.random.default_rng(20261031)
    rows=[]
    for n in SIZES:
        x=torch.from_numpy(np.column_stack((rng.uniform(.01,.99,n),
            rng.uniform(.5,.99,n),rng.uniform(.005,.15,n),
            rng.integers(1,6,n))).astype('float32'))
        for mode in MODES:
            for _ in range(10):two_features(x,mode)
            times=[]
            for _ in range(iterations):
                start=time.perf_counter_ns()
                with torch.inference_mode():
                    z=two_features(x,mode)
                assert z.shape==(n,2) and torch.isfinite(z).all()
                times.append(time.perf_counter_ns()-start)
            p50=float(np.percentile(times,50))
            p99=float(np.percentile(times,99))
            rows.append({'n':n,'mode':mode,'p50_ms':p50/1e6,
                         'p99_ms':p99/1e6,'elements_per_sec_at_p50':n/p50*1e9,
                         'rss_megabytes_process':proc.memory_info().rss/1e6,
                         'power_watts':None,'energy_joules':None})
    return {'schema':'hcsn.p5-cpu-feature-eager-probe.v1','cpu_threads':1,
        'iterations_per_case':iterations,'rows':rows,
        'hardware_power_measurement':False,'fused_kernel':False,
        'end_to_end_encoder':False,'p5_closed':False}


if __name__=='__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--output',type=Path,required=True)
    a=cli.parse_args()
    if a.output.exists():cli.error('Refuse overwrite')
    o=run_probe();o['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(o,indent=2,sort_keys=True)+'\n')
    for r in o['rows']:
        if r['n']==4096:print(r,flush=True)
