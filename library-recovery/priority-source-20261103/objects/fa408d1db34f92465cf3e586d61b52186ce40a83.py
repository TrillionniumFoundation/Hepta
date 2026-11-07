"""P5 real recurrent end-to-end synthetic input CPU latency and CDF approx.

The numerical CDF approximation is only analyzed, NOT silently swapped into
the model. No actual kernel fusion or power measurement is claimed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
import numpy as np
import psutil
import torch
try:
    from .p2_regen_recall import make_joint_reset, RegenerativeRNN, ResetGRU
except ImportError:
    from p2_regen_recall import make_joint_reset, RegenerativeRNN, ResetGRU


def ndtr_approx(z:torch.Tensor):
    """Abramowitz--Stegun 7.1.26 style 5-coefficient CDF approximation."""
    a=z.abs()
    t=1/(1+0.2316419*a)
    poly=t*(.319381530+t*(-.356563782+t*(1.781477937+
          t*(-1.821255978+t*1.330274429))))
    pos=1-.3989422804014327*torch.exp(-.5*a*a)*poly
    return torch.where(z>=0,pos,1-pos)


def cdf_error(n=16001):
    x=torch.linspace(-8.,8.,n,dtype=torch.float64,requires_grad=True)
    approx=ndtr_approx(x)
    exact=torch.special.ndtr(x)
    abs_error=(approx-exact).abs()
    g=torch.autograd.grad(approx.sum(),x)[0]
    refgrad=torch.exp(-.5*x.square())/(2*torch.pi)**.5
    return {'grid_n':n,'domain':[-8.,8.],
        'cdf_max_abs_error':float(abs_error.max()),
        'derivative_max_abs_error':float((g-refgrad).abs().max()),
        'cdf_finite':bool(torch.isfinite(approx).all()),
        'grad_finite':bool(torch.isfinite(g).all())}


def run_cpu_benchmark(iterations:int=40,batches=(1,32,128),lengths=(24,48)):
    if iterations<10:raise ValueError('at least ten measured iterations required')
    torch.set_num_threads(1)
    proc=psutil.Process(os.getpid())
    rows=[]
    for T in lengths:
        for B in batches:
            x,_=make_joint_reset(B,T,800801+T+B,irregular=True)
            for mode in ('analytic','ordinary','gru'):
                torch.manual_seed(123)
                model=(ResetGRU() if mode=='gru' else RegenerativeRNN(mode=mode)).eval()
                with torch.inference_mode():
                    for _ in range(6):
                        y=model(x)
                        assert y.shape==(B,) and bool(torch.isfinite(y).all())
                    timing=[]
                    process_rss=[]
                    for _ in range(iterations):
                        start=time.perf_counter_ns()
                        y=model(x)
                        timing.append(time.perf_counter_ns()-start)
                        process_rss.append(proc.memory_info().rss)
                assert bool(torch.isfinite(y).all())
                times=np.asarray(timing,dtype=float)/1e6
                rows.append({'arch':mode,'B':B,'T':T,
                    'parameters':sum(p.numel() for p in model.parameters()),
                    'p50_forward_ms':float(np.percentile(times,50)),
                    'p99_forward_ms':float(np.percentile(times,99)),
                    'sequences_per_sec_p50':float(B*1000/np.percentile(times,50)),
                    'rss_peak_mb_process':float(max(process_rss)/1e6),
                    'energy_joules':None})
    return {'schema':'hcsn.p5-full-recurrence-eager-cpu.v1',
        'hardware':'CPU x86_64 PyTorch eager single thread',
        'benchmark_type':'full recurrent forward, synthetic data preprocessing excluded',
        'cdf_approx':cdf_error(),
        'iterations':iterations,
        'rows':rows,'power_measured':False,'fused':False,'p5_closed':False}

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--output',required=True,type=Path)
    a.add_argument('--iterations',type=int,default=40)
    args=a.parse_args()
    if args.output.exists():a.error('Refusing overwrite')
    result=run_cpu_benchmark(iterations=args.iterations)
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'cdf':result['cdf_approx'],
        'samples':[r for r in result['rows'] if r['B']==128]},indent=2))
