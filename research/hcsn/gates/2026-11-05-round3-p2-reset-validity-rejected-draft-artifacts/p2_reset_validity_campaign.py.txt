"""Registered bounded campaign for raw-token learned hard events and validity.

Registration is checked against an actual git commit before any fit. No heldout
panel is built before every planned fit completes. Metrics and raw query arrays
derive from one scoring forward per fit/panel; conditional erasure witnesses use
a separately specified development stream and are not quality measurements.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import platform
import resource
import subprocess
import time
import numpy as np
import torch
from torch.nn import functional as F
from .p2_reset_validity import RawResetValidityMemory,make_reset_validity_panel,MAPPED_MODE
from .p2_associative_memory import delta_batch
from .p2_associative_campaign import metrics_from_logits
from .p2_round2_raw_tokens import batch_digest,RESET


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path,value):
    tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')
    tmp.replace(path)


def source_hashes(here,protocol):
    return {name:sha(here/name) for name in protocol['source_sha256']}


def verify_registration(protocol_path,protocol,registration_repo,registration_commit):
    if len(registration_commit)!=40 or any(x not in '0123456789abcdef' for x in registration_commit):
        raise ValueError('an actual full registration commit SHA is required')
    relative='research/hcsn/gates/'+Path(protocol_path).name
    committed=subprocess.check_output(['git','show',f'{registration_commit}:{relative}'],cwd=registration_repo)
    if hashlib.sha256(committed).hexdigest()!=sha(protocol_path):
        raise AssertionError('registered protocol bytes differ from executed protocol')
    here=Path(__file__).resolve().parent
    if source_hashes(here,protocol)!=protocol['source_sha256']:
        raise AssertionError('source no longer matches registered hashes')
    return dict(commit=registration_commit,protocol_path=relative,protocol_sha256=sha(protocol_path),
                verification_time_utc=utc(),
                commit_time_utc=subprocess.check_output(['git','show','-s','--format=%cI',registration_commit],
                                                        cwd=registration_repo,text=True).strip())


def save_model(model,path):
    np.savez_compressed(path,**{k:v.detach().numpy() for k,v in model.state_dict().items()})
    return dict(filename=path.name,sha256=sha(path))


def load_model(mode,path):
    model=RawResetValidityMemory(mode)
    with np.load(path,allow_pickle=False) as data:
        model.load_state_dict({name:torch.from_numpy(data[name].copy()) for name in data.files},strict=True)
    return model.eval()


def event_diagnostics(batch,trace):
    hard=trace['events'][...,1].bool()
    windows=detected=total=outside=write_events=0
    for row,L in enumerate(batch.lengths):
        covered=torch.zeros(L,dtype=torch.bool)
        covered[0]=True  # A MAP-prefix event is not called an unexplained reset.
        for position in (batch.tokens[row,:L]==RESET).nonzero().flatten().tolist():
            next_query=(batch.targets[row,position:L]!=-100).nonzero().flatten()
            if not len(next_query):continue
            end=position+int(next_query[0]);covered[position:end+1]=True
            windows+=1;detected+=int(bool(hard[row,position:end+1].any()))
        total+=int(hard[row,:L].sum())
        outside+=int((hard[row,:L]&~covered).sum())
        write_events+=int(trace['events'][row,:L,0].sum())
    return dict(observed_reset_windows=windows,windows_with_detected_event=detected,
                reset_events=total,reset_events_outside_command_to_first_query_windows=outside,
                write_events=write_events,
                window_definition='visible RESET through its first subsequent query, inclusive',
                outside_event_count_is_not_a_direct_error_label=True)


def conditional_erasure_witness(model,spec):
    batch=make_reset_validity_panel(spec)
    with torch.inference_mode():
        _,trace=model(batch.tokens,batch.duration,return_trace=True)
    chosen=None
    for row,L in enumerate(batch.lengths):
        for reset in (batch.tokens[row,:L]==RESET).nonzero().flatten().tolist():
            query=(batch.targets[row,reset:L]!=-100).nonzero().flatten()
            if not len(query):continue
            end=reset+int(query[0])
            event=(trace['events'][row,reset:end+1,1]>.5).nonzero().flatten()
            if len(event):chosen=(row,reset+int(event[0]));break
        if chosen is not None:break
    if chosen is None:
        return dict(status='NO_LEARNED_EVENT_IN_DEVELOPMENT_RESET_WINDOW',dataset_sha256=batch_digest(batch))
    row,t=chosen
    with torch.inference_mode():
        _,state=model(batch.tokens[row:row+1,:t],batch.duration[row:row+1,:t],return_state=True)
        altered=(state[0]*-7+11,state[1]*5-13,state[2].clone(),state[3].clone())
        token=batch.tokens[row:row+1,t:t+1];duration=batch.duration[row:row+1,t:t+1]
        x,sx,tx=model(token,duration,state,return_state=True,return_trace=True)
        y,sy,ty=model(token,duration,altered,return_state=True,return_trace=True)
    error=max(float((a-b).abs().max()) for a,b in zip(sx,sy))
    return dict(status='WITNESSED' if error==0 and float((x-y).abs().max())==0 else 'FAILED',
                dataset_sha256=batch_digest(batch),row=row,position=t,
                perturbation='memory -> -7*M+11; validity -> 5*v-13; same causal token context',
                reset_events=[float(tx['events'][0,0,1]),float(ty['events'][0,0,1])],
                max_post_state_difference=error,max_post_log_probability_difference=float((x-y).abs().max()),
                memory_absolute_max=float(sx[0].abs().max()),validity_absolute_max=float(sx[1].abs().max()),
                older_context_absolute_max=float(sx[3].abs().max()),
                scope='conditional learned-event erasure, not quality scoring or semantic event supervision')


def run(protocol_path,output,registration_repo,registration_commit):
    here=Path(__file__).resolve().parent
    protocol=json.loads(Path(protocol_path).read_text())
    output=Path(output)
    if output.exists():raise FileExistsError('refuse to overwrite campaign evidence')
    registration=verify_registration(protocol_path,protocol,registration_repo,registration_commit)
    artifacts=output.parent/(output.stem+'-artifacts')
    artifacts.mkdir(parents=True,exist_ok=False)
    torch.set_num_threads(1)
    report=dict(schema='hcsn.p2.reset-validity-executed.v1',status='RUNNING',
                registration=registration,source_sha256=protocol['source_sha256'],protocol_sha256=sha(protocol_path),
                execution_base_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=here,text=True).strip(),
                start_time_utc=utc(),runs=[],quality_thresholds=protocol['acceptance'],
                scientific_gates={f'P{i}':'OPEN' for i in range(7)},production_activation=False,
                external_independent_attestation=False,
                environment=dict(python=platform.python_version(),torch=torch.__version__,numpy=np.__version__,
                                 device='cpu',torch_threads=1))
    start=time.perf_counter();cpu_start=time.process_time();training_cpu=0.;exhausted=False
    training=protocol['training']
    for seed in training['model_seeds']:
        for mode in protocol['model']['modes']:
            torch.manual_seed(seed)
            model=RawResetValidityMemory(mode)
            optimizer=torch.optim.Adam(model.parameters(),lr=training['learning_rate'],
                                       betas=tuple(training['betas']),eps=training['eps'])
            initial=hashlib.sha256()
            for p in model.parameters():initial.update(p.detach().numpy().tobytes())
            entry=dict(mode=mode,seed=seed,status='RUNNING',updates=0,planned_updates=training['steps_per_model'],
                       parameter_count=sum(p.numel() for p in model.parameters()),state_float_values=176,
                       initial_parameters_sha256=initial.hexdigest(),losses=[],preclip_gradient_norms=[],
                       training_queries=0,nonfinite_events=0,development=[])
            stream=hashlib.sha256();c0=time.process_time();w0=time.perf_counter()
            try:
                for step in range(training['steps_per_model']):
                    if training_cpu+time.process_time()-c0>=protocol['budget']['training_cpu_soft_stop_seconds']:
                        exhausted=True;entry['status']='BUDGET_EXHAUSTED';break
                    stage=training['stages'][0] if step<training['stages'][0]['updates'] else training['stages'][1]
                    batch=delta_batch(training['stream_base']+seed*100000+step,n=training['batch_size'],
                        kinds=tuple(stage['tasks_round_robin']),noise_gap=training['noise_gap'],
                        overwrites=training['overwrites'],episodes=training['episodes'],
                        ignore_probability=training['ignore_probability'])
                    stream.update(batch_digest(batch).encode())
                    entry['training_queries']+=int((batch.targets!=-100).sum())
                    model.train();optimizer.zero_grad(set_to_none=True)
                    logits=model(batch.tokens,batch.duration)
                    loss=F.cross_entropy(logits.flatten(0,1),batch.targets.flatten())
                    if not bool(torch.isfinite(loss)):raise ArithmeticError('nonfinite task loss')
                    loss.backward()
                    if any(p.grad is None or not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
                        raise ArithmeticError('missing or nonfinite task gradient')
                    norm=float(torch.nn.utils.clip_grad_norm_(model.parameters(),training['gradient_clip']))
                    optimizer.step();entry['losses'].append(float(loss.detach()))
                    entry['preclip_gradient_norms'].append(norm);entry['updates']=step+1
                    if step+1 in protocol['development']['evaluate_after_updates']:
                        dev=dict(update=step+1,panels={});model.eval()
                        with torch.inference_mode():
                            for name,spec in protocol['development']['panels'].items():
                                b=make_reset_validity_panel(spec)
                                dev['panels'][name]=metrics_from_logits(model(b.tokens,b.duration),b)
                        entry['development'].append(dev)
                    if (step+1)%50==0:
                        print(json.dumps(dict(mode=mode,seed=seed,step=step+1,loss=entry['losses'][-1])),flush=True)
                if entry['updates']==training['steps_per_model']:entry['status']='COMPLETED'
            except (ArithmeticError,RuntimeError) as error:
                entry['status']='FIT_FAILURE_RETAINED';entry['error']=str(error);entry['nonfinite_events']+=1
                print(json.dumps(dict(mode=mode,seed=seed,error=str(error))),flush=True)
            entry['training_cpu_seconds']=time.process_time()-c0;entry['training_wall_seconds']=time.perf_counter()-w0
            training_cpu+=entry['training_cpu_seconds'];entry['training_stream_sha256']=stream.hexdigest()
            entry['checkpoint']=save_model(model,artifacts/f'{mode}-{seed}-weights.npz')
            report['runs'].append(entry);write_json(output,report)
            if exhausted:break
        if exhausted:break
    report['all_training_finished_time_utc']=utc()
    report['all_four_training_runs_completed']=len(report['runs'])==4 and all(r['status']=='COMPLETED' for r in report['runs'])
    report['paired_initialization_and_training_verified']=False
    if report['all_four_training_runs_completed']:
        for seed in training['model_seeds']:
            pair=[r for r in report['runs'] if r['seed']==seed]
            for key in ('initial_parameters_sha256','training_stream_sha256','updates','parameter_count'):
                if pair[0][key]!=pair[1][key]:raise AssertionError('unmatched paired '+key)
        report['paired_initialization_and_training_verified']=True
        report['heldout_construction_started_time_utc']=utc()
        panels={name:make_reset_validity_panel(spec) for name,spec in protocol['heldout'].items()}
        for entry in report['runs']:
            model=load_model(entry['mode'],artifacts/entry['checkpoint']['filename'])
            mapped=None
            if entry['mode']=='hcsn_reset_validity':
                mapped=RawResetValidityMemory(MAPPED_MODE);mapped.load_state_dict(model.state_dict());mapped.eval()
            entry['heldout']={};raw={};mapped_error=0.;mapped_events_equal=True
            with torch.inference_mode():
                for name,batch in panels.items():
                    logits,trace=model(batch.tokens,batch.duration,return_trace=True)
                    entry['heldout'][name]=metrics_from_logits(logits,batch)
                    entry['heldout'][name]['event_diagnostics']=event_diagnostics(batch,trace)
                    mask=batch.targets!=-100
                    raw[name+'_positions']=mask.nonzero().numpy()
                    raw[name+'_targets']=batch.targets[mask].numpy()
                    raw[name+'_probabilities']=logits[mask].exp().numpy()
                    raw[name+'_predictions']=logits[mask].argmax(-1).numpy()
                    raw[name+'_binding_logits']=trace['binding_logit'][mask].numpy()
                    raw[name+'_events']=trace['events'].to(torch.uint8).numpy()
                    if mapped is not None:
                        mapped_logits,mapped_trace=mapped(batch.tokens,batch.duration,return_trace=True)
                        mapped_error=max(mapped_error,float((mapped_logits-logits).abs().max()))
                        mapped_events_equal=mapped_events_equal and bool(torch.equal(mapped_trace['events'],trace['events']))
            path=artifacts/f'{entry["mode"]}-{entry["seed"]}-queries.npz'
            np.savez_compressed(path,**raw);entry['raw_queries']=dict(filename=path.name,sha256=sha(path))
            if mapped is not None:
                entry['mapped_put_linear_max_log_probability_error']=mapped_error
                entry['mapped_put_linear_events_identical']=mapped_events_equal
            entry['conditional_erasure_witness']=conditional_erasure_witness(model,protocol['development']['erasure_witness'])
            entry['all_bounded_panels_pass']=all(x['bounded_quality_pass'] for x in entry['heldout'].values())
            reset_metrics=[entry['heldout'][name] for name in protocol['mechanism_claim']['reset_panels']]
            entry['reset_panel_unknown_false_accepts']=sum(x['unknown_false_accepts'] for x in reset_metrics)
            entry['reset_panel_stale_answers_emitted']=sum(x['stale_answers_emitted'] for x in reset_metrics)
            entry['all_reset_windows_detected']=all(x['event_diagnostics']['observed_reset_windows']==
                x['event_diagnostics']['windows_with_detected_event'] for x in reset_metrics)
            entry['registered_reset_gap_criteria_pass']=entry['all_bounded_panels_pass'] and (
                entry['reset_panel_unknown_false_accepts']==0) and entry['all_reset_windows_detected'] and (
                entry['conditional_erasure_witness']['status']=='WITNESSED')
            write_json(output,report)
    report['status']='COMPLETED' if report['all_four_training_runs_completed'] else 'INCOMPLETE_RETAINED'
    report['reset_gap_closed_on_registered_panels']=report['all_four_training_runs_completed'] and all(
        r['registered_reset_gap_criteria_pass'] for r in report['runs'])
    report['source_hashes_unchanged']=source_hashes(here,protocol)==protocol['source_sha256']
    if not report['source_hashes_unchanged']:raise AssertionError('source changed during campaign')
    report['training_cpu_seconds']=training_cpu;report['cpu_seconds']=time.process_time()-cpu_start
    report['wall_seconds']=time.perf_counter()-start;report['end_time_utc']=utc()
    report['peak_rss_bytes']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
    write_json(output,report)
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--registration-repo',type=Path,required=True)
    parser.add_argument('--registration-commit',required=True)
    args=parser.parse_args();result=run(args.protocol,args.output,args.registration_repo,args.registration_commit)
    print(json.dumps({key:result[key] for key in ('status','all_four_training_runs_completed',
        'reset_gap_closed_on_registered_panels','cpu_seconds','wall_seconds','peak_rss_bytes')}),flush=True)
    return 0 if result['status']=='COMPLETED' else 2


if __name__=='__main__':raise SystemExit(main())
