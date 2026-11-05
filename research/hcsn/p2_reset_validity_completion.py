"""Transparent completion of four fixed configurations after the 180s failure.

The parent execution is immutable. Three final checkpoints are copied by hash.
The fourth configuration is replayed from its identical seed/optimizer/data;
each old-prefix loss and gradient norm and the prefix checkpoint must match
exactly BEFORE any heldout panel may be constructed. This is an additional fit,
and all replay work is charged. The learned architecture is never changed.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time
import numpy as np
import torch
from torch.nn import functional as F
from .p2_reset_validity import RawResetValidityMemory,make_reset_validity_panel,MAPPED_MODE
from .p2_associative_memory import delta_batch
from .p2_associative_campaign import metrics_from_logits
from .p2_round2_raw_tokens import batch_digest
from .p2_reset_validity_campaign import (
    sha,utc,write_json,verify_registration,source_hashes,save_model,load_model,
    event_diagnostics,conditional_erasure_witness,
)


def verify_prefix_number(actual,expected,label,update):
    if not math.isfinite(actual) or not math.isfinite(expected) or actual!=expected:
        raise AssertionError(f'prefix {label} mismatch at update {update}: actual={actual!r}, expected={expected!r}')


def verify_prefix_checkpoint(model,path):
    actual=model.state_dict()
    with np.load(path,allow_pickle=False) as expected:
        if set(actual)!=set(expected.files):raise AssertionError('prefix checkpoint tensor names differ')
        for name,value in actual.items():
            left=value.detach().numpy();right=expected[name]
            if left.dtype!=right.dtype or left.shape!=right.shape or left.tobytes(order='C')!=right.tobytes(order='C'):
                raise AssertionError('prefix checkpoint tensor differs: '+name)
    return dict(all_tensors_bitwise_equal=True,tensors=len(actual),parent_checkpoint_sha256=sha(path))


def save_optimizer(optimizer,artifact_dir,stem):
    state=optimizer.state_dict();arrays={};index={}
    for parameter,fields in state['state'].items():
        index[str(parameter)]={}
        for name,value in fields.items():
            key=f'parameter_{parameter}_{name}'
            arrays[key]=value.detach().numpy() if torch.is_tensor(value) else np.asarray(value)
            index[str(parameter)][name]=dict(array=key,was_tensor=torch.is_tensor(value))
    data=artifact_dir/(stem+'-optimizer.npz');meta=artifact_dir/(stem+'-optimizer.json')
    np.savez_compressed(data,**arrays)
    write_json(meta,dict(param_groups=state['param_groups'],state_arrays=index))
    return dict(arrays=dict(filename=data.name,sha256=sha(data)),metadata=dict(filename=meta.name,sha256=sha(meta)))


def run(protocol_path,output,registration_repo,registration_commit):
    here=Path(__file__).resolve().parent
    protocol=json.loads(Path(protocol_path).read_text());output=Path(output)
    if output.exists():raise FileExistsError('refuse to overwrite completion evidence')
    registration=verify_registration(protocol_path,protocol,registration_repo,registration_commit)
    for name,digest in protocol['parent_evidence_sha256'].items():
        if sha(here/name)!=digest:raise AssertionError('parent evidence changed: '+name)
    parent_protocol=json.loads((here/protocol['parent_protocol_path']).read_text())
    parent=json.loads((here/protocol['parent_results_path']).read_text())
    if parent['status']!='INCOMPLETE_RETAINED' or parent['all_four_training_runs_completed']:
        raise AssertionError('parent must remain the original incomplete execution')
    if protocol['heldout']!=parent_protocol['heldout'] or protocol['development']!=parent_protocol['development']:
        raise AssertionError('completion changes registered data panels')
    if protocol['training']!=parent_protocol['training']:
        raise AssertionError('completion changes training configuration')
    expected=protocol['replay_configuration']
    partial=[r for r in parent['runs'] if (r['mode'],r['seed'])==(expected['mode'],expected['seed'])]
    if len(partial)!=1:raise AssertionError('missing unique partial configuration')
    partial=partial[0]
    if partial['status']!='BUDGET_EXHAUSTED' or partial['updates']!=expected['prefix_updates']:
        raise AssertionError('partial configuration differs from completion registration')
    parent_artifacts=(here/protocol['parent_results_path']).parent/((here/protocol['parent_results_path']).stem+'-artifacts')
    artifacts=output.parent/(output.stem+'-artifacts');artifacts.mkdir(parents=True,exist_ok=False)
    start=time.perf_counter();cpu_start=time.process_time();torch.set_num_threads(1)
    report=dict(schema='hcsn.p2.reset-validity-completion-executed.v1',status='RUNNING',
        registration=registration,source_sha256=protocol['source_sha256'],protocol_sha256=sha(protocol_path),
        execution_base_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=here,text=True).strip(),
        parent_protocol_sha256=sha(here/protocol['parent_protocol_path']),
        parent_results_sha256=sha(here/protocol['parent_results_path']),
        parent_execution_status='INCOMPLETE_RETAINED',original_180_second_budget_pass=False,
        original_training_cpu_seconds=parent['training_cpu_seconds'],original_cpu_seconds=parent['cpu_seconds'],
        original_optimizer_updates=sum(r['updates'] for r in parent['runs']),
        original_training_queries=sum(r['training_queries'] for r in parent['runs']),
        original_actual_fit_attempts=len(parent['runs']),additional_actual_fit_attempts=1,
        total_actual_fit_attempts=len(parent['runs'])+1,
        environment=dict(python=platform.python_version(),torch=torch.__version__,numpy=np.__version__,device='cpu',torch_threads=1),
        start_time_utc=utc(),runs=[],scientific_gates={f'P{i}':'OPEN' for i in range(7)},
        production_activation=False,external_independent_attestation=False)
    for original in parent['runs']:
        if original is partial:continue
        if original['status']!='COMPLETED' or original['updates']!=protocol['training']['steps_per_model']:
            raise AssertionError('only completed final checkpoints may be reused')
        source=parent_artifacts/original['checkpoint']['filename']
        if sha(source)!=original['checkpoint']['sha256']:raise AssertionError('reused checkpoint changed')
        shutil.copy2(source,artifacts/source.name)
        entry=copy.deepcopy(original);entry['completion_origin']='reused_parent_final_checkpoint_without_training'
        report['runs'].append(entry)
    training=protocol['training'];mode=expected['mode'];seed=expected['seed']
    torch.manual_seed(seed);model=RawResetValidityMemory(mode)
    optimizer=torch.optim.Adam(model.parameters(),lr=training['learning_rate'],betas=tuple(training['betas']),eps=training['eps'])
    initial=hashlib.sha256()
    for p in model.parameters():initial.update(p.detach().numpy().tobytes())
    if initial.hexdigest()!=partial['initial_parameters_sha256']:raise AssertionError('replayed numeric initialization differs')
    entry=dict(mode=mode,seed=seed,status='RUNNING',updates=0,planned_updates=training['steps_per_model'],
        completion_origin='additional_full_replay_fit_from_same_seed',parameter_count=sum(p.numel() for p in model.parameters()),
        state_float_values=176,initial_parameters_sha256=initial.hexdigest(),losses=[],preclip_gradient_norms=[],
        training_queries=0,nonfinite_events=0,development=[],prefix_losses_exact=0,prefix_gradients_exact=0)
    stream=hashlib.sha256();c0=time.process_time();w0=time.perf_counter()
    try:
        for step in range(training['steps_per_model']):
            if time.process_time()-c0>=protocol['budget']['additional_training_cpu_soft_stop_seconds']:
                entry['status']='COMPLETION_BUDGET_EXHAUSTED';break
            stage=training['stages'][0] if step<training['stages'][0]['updates'] else training['stages'][1]
            batch=delta_batch(training['stream_base']+seed*100000+step,n=training['batch_size'],
                kinds=tuple(stage['tasks_round_robin']),noise_gap=training['noise_gap'],
                overwrites=training['overwrites'],episodes=training['episodes'],ignore_probability=training['ignore_probability'])
            stream.update(batch_digest(batch).encode());entry['training_queries']+=int((batch.targets!=-100).sum())
            model.train();optimizer.zero_grad(set_to_none=True)
            scores=model(batch.tokens,batch.duration)
            loss=F.cross_entropy(scores.flatten(0,1),batch.targets.flatten())
            if not bool(torch.isfinite(loss)):raise ArithmeticError('nonfinite task loss')
            loss.backward()
            if any(p.grad is None or not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
                raise ArithmeticError('missing or nonfinite task gradient')
            norm=float(torch.nn.utils.clip_grad_norm_(model.parameters(),training['gradient_clip']))
            loss_value=float(loss.detach());optimizer.step()
            entry['losses'].append(loss_value);entry['preclip_gradient_norms'].append(norm);entry['updates']=step+1
            if step<partial['updates']:
                verify_prefix_number(loss_value,partial['losses'][step],'loss',step+1);entry['prefix_losses_exact']+=1
                verify_prefix_number(norm,partial['preclip_gradient_norms'][step],'gradient norm',step+1);entry['prefix_gradients_exact']+=1
            if step+1==partial['updates']:
                if stream.hexdigest()!=partial['training_stream_sha256']:raise AssertionError('partial training stream differs')
                if entry['training_queries']!=partial['training_queries']:raise AssertionError('partial query count differs')
                entry['prefix_checkpoint_verification']=verify_prefix_checkpoint(model,parent_artifacts/partial['checkpoint']['filename'])
                entry['prefix_training_stream_exact']=True
                print(json.dumps(dict(event='PREFIX_VERIFIED',updates=step+1,losses_exact=entry['prefix_losses_exact'],
                                      gradient_norms_exact=entry['prefix_gradients_exact'],checkpoint_tensors_equal=True)),flush=True)
            if step+1 in protocol['development']['evaluate_after_updates']:
                dev=dict(update=step+1,panels={});model.eval()
                with torch.inference_mode():
                    for name,spec in protocol['development']['panels'].items():
                        b=make_reset_validity_panel(spec)
                        dev['panels'][name]=metrics_from_logits(model(b.tokens,b.duration),b)
                entry['development'].append(dev)
            if (step+1)%50==0:
                print(json.dumps(dict(mode=mode,seed=seed,step=step+1,loss=loss_value)),flush=True)
        if entry['updates']==training['steps_per_model']:entry['status']='COMPLETED'
    except (AssertionError,ArithmeticError,RuntimeError) as error:
        entry['status']='REPLAY_OR_NUMERIC_FAILURE_RETAINED';entry['error']=str(error)
        print(json.dumps(dict(event=entry['status'],error=str(error))),flush=True)
    entry['training_cpu_seconds']=time.process_time()-c0;entry['training_wall_seconds']=time.perf_counter()-w0
    entry['training_stream_sha256']=stream.hexdigest()
    entry['checkpoint']=save_model(model,artifacts/f'{mode}-{seed}-weights.npz')
    entry['optimizer_checkpoint']=save_optimizer(optimizer,artifacts,f'{mode}-{seed}')
    report['runs'].append(entry);report['all_final_checkpoints_ready_time_utc']=utc();write_json(output,report)
    complete=len(report['runs'])==4 and all(r['status']=='COMPLETED' for r in report['runs'])
    prefix=entry['prefix_losses_exact']==partial['updates'] and entry['prefix_gradients_exact']==partial['updates'] and bool(
        entry.get('prefix_checkpoint_verification',{}).get('all_tensors_bitwise_equal',False)) and entry.get('prefix_training_stream_exact',False)
    report['prefix_replay_verified_before_heldout']=bool(prefix)
    report['all_four_final_configurations_completed']=bool(complete and prefix)
    # Compatibility for the artifact auditor; this refers only to this final
    # configuration set. The immutable parent report remains incomplete.
    report['all_four_training_runs_completed']=report['all_four_final_configurations_completed']
    report['all_four_training_runs_completed_scope']='final configurations after explicitly charged additional replay fit, not original 180s execution'
    report['paired_initialization_and_training_verified']=False
    if complete and prefix:
        for paired_seed in training['model_seeds']:
            pair=[r for r in report['runs'] if r['seed']==paired_seed]
            for key in ('initial_parameters_sha256','training_stream_sha256','updates','parameter_count'):
                if len(pair)!=2 or pair[0][key]!=pair[1][key]:raise AssertionError('final matched-pair mismatch: '+key)
        report['paired_initialization_and_training_verified']=True
        report['heldout_construction_started_time_utc']=utc()
        panels={name:make_reset_validity_panel(spec) for name,spec in protocol['heldout'].items()}
        for final in report['runs']:
            trained=load_model(final['mode'],artifacts/final['checkpoint']['filename']);mapped=None
            if final['mode']=='hcsn_reset_validity':
                mapped=RawResetValidityMemory(MAPPED_MODE);mapped.load_state_dict(trained.state_dict());mapped.eval()
            final['heldout']={};raw={};mapped_error=0.;mapped_events_equal=True
            with torch.inference_mode():
                for name,batch in panels.items():
                    logits,trace=trained(batch.tokens,batch.duration,return_trace=True)
                    final['heldout'][name]=metrics_from_logits(logits,batch)
                    final['heldout'][name]['event_diagnostics']=event_diagnostics(batch,trace)
                    mask=batch.targets!=-100
                    raw[name+'_positions']=mask.nonzero().numpy();raw[name+'_targets']=batch.targets[mask].numpy()
                    raw[name+'_probabilities']=logits[mask].exp().numpy();raw[name+'_predictions']=logits[mask].argmax(-1).numpy()
                    raw[name+'_binding_logits']=trace['binding_logit'][mask].numpy()
                    raw[name+'_events']=trace['events'].to(torch.uint8).numpy()
                    if mapped is not None:
                        other,other_trace=mapped(batch.tokens,batch.duration,return_trace=True)
                        mapped_error=max(mapped_error,float((other-logits).abs().max()))
                        mapped_events_equal=mapped_events_equal and bool(torch.equal(other_trace['events'],trace['events']))
            path=artifacts/f'{final["mode"]}-{final["seed"]}-queries.npz';np.savez_compressed(path,**raw)
            final['raw_queries']=dict(filename=path.name,sha256=sha(path))
            if mapped is not None:
                final['mapped_put_linear_max_log_probability_error']=mapped_error
                final['mapped_put_linear_events_identical']=mapped_events_equal
            final['conditional_erasure_witness']=conditional_erasure_witness(trained,protocol['development']['erasure_witness'])
            final['all_bounded_panels_pass']=all(x['bounded_quality_pass'] for x in final['heldout'].values())
            reset_metrics=[final['heldout'][name] for name in protocol['mechanism_claim']['reset_panels']]
            final['reset_panel_unknown_false_accepts']=sum(x['unknown_false_accepts'] for x in reset_metrics)
            final['reset_panel_stale_answers_emitted']=sum(x['stale_answers_emitted'] for x in reset_metrics)
            final['all_reset_windows_detected']=all(x['event_diagnostics']['observed_reset_windows']==
                x['event_diagnostics']['windows_with_detected_event'] for x in reset_metrics)
            final['registered_reset_gap_criteria_pass']=final['all_bounded_panels_pass'] and final['reset_panel_unknown_false_accepts']==0 and (
                final['all_reset_windows_detected']) and final['conditional_erasure_witness']['status']=='WITNESSED'
            write_json(output,report)
    report['status']='COMPLETED_FIXED_CONFIGURATION_SET' if complete and prefix else 'COMPLETION_INCOMPLETE_RETAINED'
    report['reset_gap_closed_on_registered_panels']=bool(complete and prefix and all(r['registered_reset_gap_criteria_pass'] for r in report['runs']))
    report['source_hashes_unchanged']=source_hashes(here,protocol)==protocol['source_sha256']
    report['parent_evidence_unchanged']=all(sha(here/name)==digest for name,digest in protocol['parent_evidence_sha256'].items())
    if not report['source_hashes_unchanged'] or not report['parent_evidence_unchanged']:raise AssertionError('frozen input changed')
    report['additional_training_cpu_seconds']=entry['training_cpu_seconds']
    report['additional_optimizer_updates']=entry['updates'];report['additional_training_queries']=entry['training_queries']
    report['total_actual_optimizer_updates']=report['original_optimizer_updates']+entry['updates']
    report['total_actual_training_queries']=report['original_training_queries']+entry['training_queries']
    report['repeated_prefix_updates']=min(entry['updates'],partial['updates'])
    report['combined_training_cpu_seconds']=parent['training_cpu_seconds']+entry['training_cpu_seconds']
    report['cpu_seconds']=time.process_time()-cpu_start;report['wall_seconds']=time.perf_counter()-start
    report['combined_recorded_campaign_cpu_seconds']=parent['cpu_seconds']+report['cpu_seconds']
    report['peak_rss_bytes']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024;report['end_time_utc']=utc()
    write_json(output,report);return report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--registration-repo',type=Path,required=True)
    parser.add_argument('--registration-commit',required=True);args=parser.parse_args()
    result=run(args.protocol,args.output,args.registration_repo,args.registration_commit)
    print(json.dumps({key:result[key] for key in ('status','original_180_second_budget_pass','prefix_replay_verified_before_heldout',
        'all_four_final_configurations_completed','reset_gap_closed_on_registered_panels','additional_optimizer_updates',
        'additional_training_cpu_seconds','cpu_seconds','combined_recorded_campaign_cpu_seconds')}),flush=True)
    return 0 if result['status']=='COMPLETED_FIXED_CONFIGURATION_SET' else 2


if __name__=='__main__':raise SystemExit(main())
