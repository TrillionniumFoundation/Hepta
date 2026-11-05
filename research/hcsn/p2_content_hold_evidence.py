"""Fixed-budget content-hold experiment; always leaves scientific gates OPEN."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import subprocess
import sys
import time

import numpy as np
import scipy
import torch
try:
    from .p2_content_hold import MODES, ContentHoldMemory, make_task, train, evaluate, paired_delay, independent_matrix_reference
except ImportError:
    from p2_content_hold import MODES, ContentHoldMemory, make_task, train, evaluate, paired_delay, independent_matrix_reference


def data_hash(data):
    digest=hashlib.sha256()
    for value in (data.payload,data.duration,data.query_key,data.target,data.query_mask):
        digest.update(value.numpy().tobytes())
    return digest.hexdigest()


def independent_sample(model, last, delay, seed):
    """Exact exponential holding times; no closed transition or training RNG."""
    rng=random.Random(seed)
    state=int(rng.random()<.5)
    learned=model.write_rates().detach().numpy()
    events=0
    for payload,duration in ((-1. if last else 1.,1.),(1. if last else -1.,1.),(0.,delay)):
        a,b=payload**2*((1-payload)/2*learned[0]+(1+payload)/2*learned[1])
        if model.mode=='leaky_ctmc': a+=model.blank_floor; b+=model.blank_floor
        remaining=duration
        while remaining>0:
            hazard=float(b if state else a)
            if hazard==0: break
            wait=rng.expovariate(hazard)
            if wait>=remaining: break
            remaining-=wait;state=1-state;events+=1
            if events>100000: raise ArithmeticError('independent event budget exceeded')
    return state,events


def run(steps=240):
    torch.set_num_threads(1)
    configurations={
      'heldout_id':dict(seed=812301,n=192,length=28),
      'keyed_overwrite_128':dict(seed=812302,n=192,length=128),
      'irregular_blank_128':dict(seed=812303,n=192,length=128,blank_max=32.),
      'one_key_selective_payload':dict(seed=812304,n=192,length=128,keys=1,blank_max=32.),
      'short_write_ood_128':dict(seed=812305,n=192,length=128,write_min=.02,write_max=.2,blank_max=32.),
    }
    datasets={name:make_task(**settings) for name,settings in configurations.items()}
    models={};runs=[]
    for seed in (11,23,37):
        for mode in MODES:
            start=time.perf_counter();cpu=time.process_time()
            model,report=train(mode,seed,steps=steps)
            report['wall_seconds']=time.perf_counter()-start
            report['process_cpu_seconds']=time.process_time()-cpu
            report['train_data_sha256']=data_hash(make_task(seed+103000,n=64,length=28))
            report['heldout']={name:evaluate(model,data) for name,data in datasets.items()}
            report['retention']=[paired_delay(model,d) for d in (1.,16.,64.,256.,4096.)]
            report['persistent_noise']=[paired_delay(model,4096.,noise=x) for x in (.001,.01,.05)]
            report['missing_final_write_balanced_bound']=.5
            models[(seed,mode)]=model;runs.append(report)
    rng=np.random.default_rng(50119)
    worst_matrix=worst_split=worst_equivalent=0.
    for seed in (11,23,37):
        for mode in MODES:
            model=models[(seed,mode)]
            x=rng.uniform(-1,1,(2,12,4));x[:,4]=0
            dt=rng.uniform(.02,6.,(2,12))
            with torch.no_grad():
                actual=model(torch.tensor(x),torch.tensor(dt)).numpy()
                refined=model(torch.tensor(x).repeat_interleave(9,1),torch.tensor(dt).repeat_interleave(9,1)/9)[:,8::9].numpy()
            worst_split=max(worst_split,float(abs(actual-refined).max()))
            for row in range(2):
                ref=independent_matrix_reference(model,x[row],dt[row])
                worst_matrix=max(worst_matrix,float(abs(actual[row]-ref).max()))
        data=datasets['keyed_overwrite_128']
        with torch.no_grad():
            a=models[(seed,'protected_ctmc')](data.payload,data.duration)
            b=models[(seed,'ordinary_exponential')](data.payload,data.duration)
            worst_equivalent=max(worst_equivalent,float((a-b).abs().max()))
    sampled=[]
    for seed in (11,23,37):
        for mode,delay in (('protected_ctmc',4096.),('leaky_ctmc',64.)):
            model=models[(seed,mode)]
            exact=paired_delay(model,delay)
            for last in (0,1):
                count=2000
                samples=[independent_sample(model,last,delay,seed*100000+last*10000+i) for i in range(count)]
                empirical=sum(s for s,_ in samples)/count
                mean_events=sum(e for _,e in samples)/count
                expected=exact['p_after_last_one' if last else 'p_after_last_zero']
                se=math.sqrt(max(expected*(1-expected),1e-30)/count)
                sampled.append({'model_seed':seed,'mode':mode,'last_value':last,'blank_s':delay,
                                'paths':count,'expected_p1':expected,'observed_p1':empirical,
                                'absolute_z_diagnostic':abs(empirical-expected)/se,'mean_autonomous_events':mean_events})
    if max(worst_matrix,worst_split)>1e-11 or worst_equivalent>1e-10:
        raise AssertionError('independent numerical/ordinary-control comparison failed')
    summary={}
    for mode in MODES:
        selected=[r for r in runs if r['mode']==mode]
        summary[mode]={name:float(np.mean([r['heldout'][name]['expected_sampled_state_accuracy'] for r in selected])) for name in datasets}
        summary[mode]['blank_4096_bayes']=float(np.mean([r['retention'][-1]['balanced_endpoint_bayes_accuracy'] for r in selected]))
        summary[mode]['noise_0.01_4096_bayes']=float(np.mean([r['persistent_noise'][1]['balanced_endpoint_bayes_accuracy'] for r in selected]))
        summary[mode]['noise_0.05_4096_bayes']=float(np.mean([r['persistent_noise'][2]['balanced_endpoint_bayes_accuracy'] for r in selected]))
    here=Path(__file__).resolve().parent
    sources=[here/'p2_content_hold.py',here/'p2_content_hold_evidence.py',here/'test_p2_content_hold.py',here/'gates/2026-11-05-iteration39-content-hold-protocol.md']
    try: head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=here,text=True).strip()
    except (OSError,subprocess.CalledProcessError): head=None
    return {'experiment':'HCSN P2 iteration39 content-supported holding','base_head':head,
            'scope':'synthetic keyed task; exact input routing; task-only query likelihood; not HX or raw-token MQAR',
            'protocol':{'seeds':[11,23,37],'steps':steps,'train_rows':64,'train_length':28,'learned_parameters':4,
                        'heldout':configurations,'prospective_local_protocol_not_independent_preregistration':True},
            'environment':{'python':platform.python_version(),'numpy':np.__version__,'scipy':scipy.__version__,
                           'torch':torch.__version__,'torch_threads':torch.get_num_threads(),'device':'cpu'},
            'source_sha256':{str(p.relative_to(here)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
            'dataset_sha256':{name:data_hash(data) for name,data in datasets.items()},
            'summary_mean_over_seeds':summary,'runs':runs,
            'independent_checks':{'maximum_matrix_error':worst_matrix,'maximum_refinement_error':worst_split,
               'maximum_independently_trained_protected_vs_ordinary_error':worst_equivalent,
               'gillespie_trajectories':sum(s['paths'] for s in sampled),'gillespie_endpoints':sampled},
            'limitations':['Zero-content support and key routing are architectural assumptions, not learned event recognition.',
              'Expected sampled-state accuracy is not deterministic probability-readout accuracy.',
              'Mapped ordinary flow is mathematically equivalent; no HX or spiking advantage is demonstrated.',
              'Persistent low-amplitude input can erase retained information; missing final writes have balanced bound 0.5.',
              'No real pretrained encoder, independent subject, energy measurement or scaled training.'],
            'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);parser.add_argument('--strict',action='store_true')
    args=parser.parse_args();report=run()
    text=json.dumps(report,indent=2,allow_nan=False)+'\n'
    if args.output: args.output.write_text(text)
    else: print(text,end='')
    return 2 if args.strict else 0

if __name__=='__main__': sys.exit(main())
