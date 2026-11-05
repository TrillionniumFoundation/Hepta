"""Run the frozen round-2 raw-token P2 protocol and preserve failures and models."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

import numpy as np
import torch
try:
    from .p2_round2_raw_tokens import (MODES, RawTokenMemory, make_batch, train_one, evaluate,
        batch_digest, missing_write_panel, previous_flow_operating_domain)
except ImportError:
    from p2_round2_raw_tokens import (MODES, RawTokenMemory, make_batch, train_one, evaluate,
        batch_digest, missing_write_panel, previous_flow_operating_domain)

SEEDS=(101,211,307)
PANELS={
 'selective_copy_id':dict(seed=841001,n=128,kind='selective_copy',copy_length=24),
 'selective_copy_long':dict(seed=841002,n=128,kind='selective_copy',copy_length=128),
 'mqar_id':dict(seed=841003,n=128,kind='mqar',noise_gap=2),
 'mqar_long_distractors':dict(seed=841004,n=128,kind='mqar',noise_gap=24),
 'overwrite':dict(seed=841005,n=128,kind='overwrite',noise_gap=4,overwrites=8),
 'state_tracking':dict(seed=841006,n=128,kind='state_tracking',noise_gap=4,overwrites=8),
 'repeated_visible_resets':dict(seed=841007,n=128,kind='multi_reset',noise_gap=2,episodes=4),
 'irregular_time':dict(seed=841008,n=128,duration_min=.02,duration_max=16.),
 'short_intervals':dict(seed=841009,n=128,duration_min=.005,duration_max=.02),
}


def digest_file(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_model(model,path):
    state={k:v.detach().numpy() for k,v in model.state_dict().items()}
    np.savez_compressed(path,**state)
    return {'filename':Path(path).name,'sha256':digest_file(path),'format':'numpy tensor state; allow_pickle=False'}


def load_model(mode,path):
    model=RawTokenMemory(mode)
    with np.load(path,allow_pickle=False) as source:
        state={k:torch.from_numpy(source[k].copy()) for k in source.files}
    model.load_state_dict(state,strict=True)
    return model.eval()


def run(output):
    torch.set_num_threads(1)
    output=Path(output)
    if output.exists():raise FileExistsError('refusing to overwrite a completed frozen study')
    artifact_dir=output.parent/(output.stem+'-artifacts')
    artifact_dir.mkdir(parents=True,exist_ok=False)
    here=Path(__file__).resolve().parent
    sources=[here/'p2_round2_raw_tokens.py',here/'p2_round2_raw_tokens_evidence.py',
             here/'test_p2_round2_raw_tokens.py',here/'gates/2026-11-05-round2-p2-raw-token-protocol.md']
    source_sha={str(p.relative_to(here)):digest_file(p) for p in sources}
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=here,text=True).strip()
    runs=[]
    started=time.perf_counter()
    # All training finishes before any held-out scoring begins.
    for seed in SEEDS:
        for mode in MODES:
            start=time.perf_counter();cpu=time.process_time()
            def progress(step,loss):print(json.dumps({'training':mode,'seed':seed,'step':step,'query_loss':loss}),flush=True)
            model,report=train_one(mode,seed,steps=600,batch_size=24,width=48,learning_rate=.003,progress=progress)
            report['training_wall_seconds']=time.perf_counter()-start
            report['training_process_cpu_seconds']=time.process_time()-cpu
            report['checkpoint']=save_model(model,artifact_dir/f'{mode}-{seed}-weights.npz')
            runs.append(report)
            del model
            print(json.dumps({'training_complete':mode,'seed':seed,'development_nll':report['development_final_nll']}),flush=True)
    for seed in SEEDS:
        pair=[r for r in runs if r['seed']==seed]
        if pair[0]['training_stream_sha256']!=pair[1]['training_stream_sha256']:
            raise AssertionError('paired models saw different training examples')
    calibration=make_batch(730001,n=128)
    panels={name:make_batch(**spec) for name,spec in PANELS.items()}
    for report in runs:
        mode,seed=report['mode'],report['seed']
        model=load_model(mode,artifact_dir/report['checkpoint']['filename'])
        report['calibration_diagnostic_only']=evaluate(model,calibration)
        report['heldout']={}
        raw={}
        for name,data in panels.items():
            report['heldout'][name]=evaluate(model,data)
            with torch.inference_mode():
                logits=model(data.tokens,data.duration);mask=data.targets!=-100
                positions=mask.nonzero()
                raw[name+'_positions']=positions.numpy()
                raw[name+'_targets']=data.targets[mask].numpy()
                raw[name+'_probabilities']=logits[mask].softmax(-1).numpy()
                raw[name+'_predictions']=logits[mask].argmax(-1).numpy()
        raw_path=artifact_dir/f'{mode}-{seed}-heldout-queries.npz'
        np.savez_compressed(raw_path,**raw)
        report['raw_heldout_queries']={'filename':raw_path.name,'sha256':digest_file(raw_path)}
        report['missing_update_information']=missing_write_panel(model)
        report['finite_operational_panels_pass']=all(x['query_accuracy']>=.95 and x['sequence_exact_accuracy']>=.90
                                                     for x in report['heldout'].values())
        if mode=='hcsn':
            mapped=RawTokenMemory('put_linear_equivalent');mapped.load_state_dict(model.state_dict())
            worst=0.
            with torch.inference_mode():
                for data in panels.values():
                    worst=max(worst,float((model(data.tokens,data.duration)-mapped(data.tokens,data.duration)).abs().max()))
            report['put_linear_mapped_maximum_logit_error']=worst
        print(json.dumps({'evaluated':mode,'seed':seed,'all_finite_panels_pass':report['finite_operational_panels_pass']}),flush=True)
    after={str(p.relative_to(here)):digest_file(p) for p in sources}
    if after!=source_sha:raise AssertionError('source or local protocol changed during execution')
    summary={mode:{} for mode in MODES}
    for mode in MODES:
        selected=[r for r in runs if r['mode']==mode]
        for name in panels:
            summary[mode][name]={
              'query_accuracy_mean':float(np.mean([r['heldout'][name]['query_accuracy'] for r in selected])),
              'query_accuracy_min_seed':min(r['heldout'][name]['query_accuracy'] for r in selected),
              'sequence_exact_mean':float(np.mean([r['heldout'][name]['sequence_exact_accuracy'] for r in selected])),
              'queries_per_seed':selected[0]['heldout'][name]['queries'],
              'all_seeds_pass_finite_threshold':all(r['heldout'][name]['query_accuracy']>=.95 and r['heldout'][name]['sequence_exact_accuracy']>=.90 for r in selected),
            }
    report={'schema':'hcsn.p2.raw-token-fixed-budget.v1','base_head':head,
            'source_sha256':source_sha,'model_seeds':list(SEEDS),'panel_specifications':PANELS,
            'calibration_dataset_sha256':batch_digest(calibration),
            'heldout_dataset_sha256':{k:batch_digest(v) for k,v in panels.items()},
            'environment':{'python':platform.python_version(),'torch':torch.__version__,'numpy':np.__version__,
                           'torch_threads':torch.get_num_threads(),'device':'cpu'},
            'scope':'raw symbolic online tokens; learned routing; visible reset commands; simplified stopping HCSN channels',
            'deterministic_causal_parser_reference':{'all_generated_labels_checked':True,'uses_future_information':False,
               'learned':False,'role':'grammar-correct causal reference, not a matched learned competitor'},
            'old_flow_noise_short_write_negative':previous_flow_operating_domain(),
            'summary_mean_over_model_seeds':summary,'runs':runs,
            'total_wall_seconds':time.perf_counter()-started,
            'process_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            'limitations':['RESET is an observable input command; autonomous boundary/spike-event learning is not established.',
                'Discrete token observation updates replace the old duration-scaled write semantics explicitly.',
                'Ordinary and HCSN parameter counts, data and updates match; global slopes and FLOPs do not.',
                'Simplified Call/Put channels are not the complete He-Xiong coupled model or optimal neural QVI.',
                'Finite symbolic tests do not establish real-encoder noise rejection, unknown-input behavior or energy advantage.',
                'No test-driven tuning or checkpoint selection; all six fixed training runs and failures retained.'],
            'scientific_gates':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--strict',action='store_true');args=parser.parse_args()
    result=run(args.output)
    print(json.dumps({'output':str(args.output),'production_activation':result['production_activation'],
                      'summary':result['summary_mean_over_model_seeds']},indent=2))
    return 2 if args.strict else 0

if __name__=='__main__':sys.exit(main())
