"""Execute the pre-existing frozen associative-memory protocol without test tuning.

This is a raw symbolic learned-address experiment, not a complete P2 certificate.
It preserves partial runs on budget exhaustion, final checkpoints, all losses,
and every held-out query. All held-out metrics come from one forward per panel.
"""
from __future__ import annotations
import argparse
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
from .p2_associative_memory import RawDeltaMemory, delta_batch
from .p2_round2_raw_tokens import batch_digest, UNKNOWN


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metrics_from_logits(logits, batch):
    valid = batch.targets != -100
    prediction = logits.argmax(-1)
    correct = prediction == batch.targets
    exact = (correct | ~valid).all(-1)
    result = dict(queries=int(valid.sum()), correct_queries=int((correct & valid).sum()),
                  query_accuracy=float(correct[valid].double().mean()),
                  sequences=len(batch.lengths), exact_sequences=int(exact.sum()),
                  sequence_exact_accuracy=float(exact.double().mean()),
                  query_nll=float(F.cross_entropy(logits[valid], batch.targets[valid])),
                  maximum_token_length=max(batch.lengths), dataset_sha256=batch_digest(batch),
                  by_query_type={})
    for tag in sorted({x for row in batch.query_kinds for x in row if x}):
        mask = torch.tensor([[x == tag for x in row] for row in batch.query_kinds])
        result['by_query_type'][tag] = dict(queries=int(mask.sum()), correct=int(correct[mask].sum()),
                                            accuracy=float(correct[mask].double().mean()))
    old = valid & (batch.stale_answers >= 0) & (batch.stale_answers != batch.targets)
    unknown = valid & (batch.targets == UNKNOWN)
    result.update(stale_answer_opportunities=int(old.sum()),
                  stale_answers_emitted=int(((prediction == batch.stale_answers) & old).sum()),
                  unknown_queries=int(unknown.sum()),
                  unknown_false_accepts=int(((prediction != UNKNOWN) & unknown).sum()))
    result['bounded_quality_pass'] = result['query_accuracy'] >= .95 and result['sequence_exact_accuracy'] >= .90
    return result


def save_model(model, path):
    np.savez_compressed(path, **{k: v.detach().numpy() for k, v in model.state_dict().items()})
    return dict(filename=Path(path).name, sha256=sha(path))


def load_model(mode, path):
    model = RawDeltaMemory(mode)
    with np.load(path, allow_pickle=False) as z:
        model.load_state_dict({k: torch.from_numpy(z[k].copy()) for k in z.files}, strict=True)
    return model.eval()


def run(protocol_path, output):
    here = Path(__file__).resolve().parent
    protocol = json.loads(Path(protocol_path).read_text())
    output = Path(output)
    if output.exists():
        raise FileExistsError('refuse to overwrite a completed campaign')
    artifacts = output.parent / (output.stem + '-artifacts')
    artifacts.mkdir(parents=True, exist_ok=False)
    sources = [here/'p2_associative_memory.py', here/'p2_round2_raw_tokens.py',
               here/'p2_associative_campaign.py', here/'test_p2_associative_campaign.py',
               Path(protocol_path)]
    source_hashes = {str(p.relative_to(here)): sha(p) for p in sources}
    torch.set_num_threads(1)
    training = protocol['training']
    report = dict(schema='hcsn.p2.associative-executed.v1',
                  source_sha256=source_hashes,
                  head=subprocess.check_output(['git','rev-parse','HEAD'], cwd=here, text=True).strip(),
                  protocol_sha256=sha(protocol_path), runs=[], status='RUNNING',
                  quality_thresholds=dict(query_accuracy=.95, sequence_exact_accuracy=.90),
                  scientific_gates={f'P{i}':'OPEN' for i in range(7)}, production_activation=False,
                  external_independent_attestation=False,
                  environment=dict(python=platform.python_version(), torch=torch.__version__,
                                   numpy=np.__version__, torch_threads=1, device='cpu'))
    start = time.perf_counter()
    start_cpu = time.process_time()
    training_cpu = 0.
    exhausted = False
    for seed in training['model_seeds']:
        for mode in protocol['model']['modes']:
            torch.manual_seed(seed)
            model = RawDeltaMemory(mode)
            opt = torch.optim.Adam(model.parameters(), lr=training['learning_rate'],
                                   betas=tuple(training['betas']), eps=training['eps'])
            stream = hashlib.sha256()
            entry = dict(seed=seed, mode=mode, planned_updates=training['steps_per_model'],
                         updates=0, losses=[], preclip_gradient_norms=[], training_queries=0,
                         development=[], parameter_count=sum(p.numel() for p in model.parameters()),
                         state_float_values=160, nonfinite_events=0, status='RUNNING')
            initial = hashlib.sha256()
            for p in model.parameters(): initial.update(p.detach().numpy().tobytes())
            entry['initial_parameters_sha256'] = initial.hexdigest()
            c0 = time.process_time(); w0 = time.perf_counter()
            try:
                for step in range(training['steps_per_model']):
                    if training_cpu + time.process_time()-c0 >= protocol['budget']['new_training_cpu_soft_stop_seconds']:
                        exhausted = True; entry['status'] = 'BUDGET_EXHAUSTED'; break
                    stage = training['stages'][0] if step < training['stages'][0]['updates'] else training['stages'][1]
                    batch = delta_batch(100000000+seed*100000+step, n=training['batch_size'],
                        kinds=tuple(stage['tasks_round_robin']), noise_gap=training['noise_gap'],
                        overwrites=training['overwrites'], episodes=training['episodes'],
                        ignore_probability=training['ignore_probability'])
                    stream.update(batch_digest(batch).encode())
                    entry['training_queries'] += int((batch.targets != -100).sum())
                    model.train(); opt.zero_grad(set_to_none=True)
                    logits = model(batch.tokens,batch.duration)
                    loss = F.cross_entropy(logits.flatten(0,1), batch.targets.flatten())
                    if not bool(torch.isfinite(loss)): raise ArithmeticError('nonfinite loss')
                    loss.backward()
                    if any(p.grad is None or not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
                        raise ArithmeticError('missing or nonfinite gradient')
                    entry['preclip_gradient_norms'].append(float(torch.nn.utils.clip_grad_norm_(model.parameters(), training['gradient_clip'])))
                    opt.step(); entry['losses'].append(float(loss.detach())); entry['updates'] = step+1
                    if step+1 in protocol['development']['evaluate_after_updates']:
                        dev = dict(update=step+1, panels={})
                        model.eval()
                        with torch.inference_mode():
                            for kind, devseed in protocol['development']['seeds'].items():
                                b = delta_batch(devseed,n=protocol['development']['n'],kinds=(kind,))
                                dev['panels'][kind] = metrics_from_logits(model(b.tokens,b.duration),b)
                        entry['development'].append(dev)
                    if (step+1)%50 == 0:
                        print(json.dumps(dict(seed=seed,mode=mode,step=step+1,loss=entry['losses'][-1])),flush=True)
                if entry['updates'] == training['steps_per_model']: entry['status']='COMPLETED'
            except ArithmeticError as error:
                entry['status']='NUMERIC_FAILURE';entry['error']=str(error);entry['nonfinite_events']+=1
            entry['training_cpu_seconds']=time.process_time()-c0
            entry['training_wall_seconds']=time.perf_counter()-w0
            training_cpu+=entry['training_cpu_seconds']
            entry['training_stream_sha256']=stream.hexdigest()
            entry['checkpoint']=save_model(model,artifacts/f'{mode}-{seed}-weights.npz')
            report['runs'].append(entry)
            output.write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n')
            if exhausted: break
        if exhausted: break
    report['all_four_training_runs_completed']=len(report['runs'])==4 and all(r['status']=='COMPLETED' for r in report['runs'])
    report['paired_initialization_and_training_verified']=False
    if report['all_four_training_runs_completed']:
        for seed in training['model_seeds']:
            pair=[r for r in report['runs'] if r['seed']==seed]
            for key in ['initial_parameters_sha256','training_stream_sha256','parameter_count','updates']:
                if pair[0][key]!=pair[1][key]:raise AssertionError('unmatched paired '+key)
        report['paired_initialization_and_training_verified']=True
        panels={name:delta_batch(**spec) for name,spec in protocol['heldout'].items()}
        for entry in report['runs']:
            model=load_model(entry['mode'],artifacts/entry['checkpoint']['filename'])
            mapped=None
            if entry['mode']=='hcsn_delta':
                mapped=RawDeltaMemory('put_linear_delta');mapped.load_state_dict(model.state_dict());mapped.eval()
            entry['heldout']={};raw={};mapped_error=0.
            with torch.inference_mode():
                for name,batch in panels.items():
                    logits=model(batch.tokens,batch.duration)
                    entry['heldout'][name]=metrics_from_logits(logits,batch)
                    mask=batch.targets!=-100
                    raw[name+'_positions']=mask.nonzero().numpy()
                    raw[name+'_targets']=batch.targets[mask].numpy()
                    raw[name+'_probabilities']=logits[mask].softmax(-1).numpy()
                    raw[name+'_predictions']=logits[mask].argmax(-1).numpy()
                    if mapped is not None:
                        mapped_error=max(mapped_error,float((mapped(batch.tokens,batch.duration)-logits).abs().max()))
            rawpath=artifacts/f'{entry["mode"]}-{entry["seed"]}-queries.npz'
            np.savez_compressed(rawpath,**raw)
            entry['raw_queries']=dict(filename=rawpath.name,sha256=sha(rawpath))
            if mapped is not None:entry['mapped_put_linear_max_logit_error']=mapped_error
            entry['all_bounded_panels_pass']=all(x['bounded_quality_pass'] for x in entry['heldout'].values())
    report['status']='COMPLETED' if report['all_four_training_runs_completed'] else 'INCOMPLETE_RETAINED'
    report['source_hashes_unchanged']={str(p.relative_to(here)):sha(p) for p in sources}==source_hashes
    if not report['source_hashes_unchanged']:raise AssertionError('source changed during campaign')
    report['wall_seconds']=time.perf_counter()-start;report['cpu_seconds']=time.process_time()-start_cpu
    report['training_cpu_seconds']=training_cpu
    report['peak_rss_bytes']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
    report['charged_prior_development_seconds']=protocol['budget']['prior_development_seconds_charged']
    report['combined_cost_seconds']=report['cpu_seconds']+report['charged_prior_development_seconds']
    report['combined_cost_is_mixed_prior_wall_plus_current_cpu']=True
    output.write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--protocol',type=Path,default=Path(__file__).resolve().parent/'gates/2026-11-05-round2-associative-protocol.json')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=run(args.protocol,args.output)
    print(json.dumps({k:result[k] for k in ['status','all_four_training_runs_completed','wall_seconds','cpu_seconds','peak_rss_bytes']}),flush=True)
    return 0 if result['status']=='COMPLETED' else 2

if __name__=='__main__':raise SystemExit(main())
