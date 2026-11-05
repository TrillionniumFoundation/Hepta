"""Replay frozen reset-validity artifacts; not an external evaluator attestation."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import numpy as np
import torch
from .p2_reset_validity import make_reset_validity_panel
from .p2_reset_validity_campaign import load_model,conditional_erasure_witness
from .p2_round2_raw_tokens import batch_digest,UNKNOWN


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(protocol_path,report_path):
    start=time.perf_counter();cpu=time.process_time()
    here=Path(__file__).resolve().parent
    protocol=json.loads(Path(protocol_path).read_text())
    report=json.loads(Path(report_path).read_text())
    if report['protocol_sha256']!=sha(protocol_path):raise AssertionError('protocol hash differs')
    if report['source_sha256']!=protocol['source_sha256']:raise AssertionError('reported source hash map differs')
    for name,digest in protocol['source_sha256'].items():
        if sha(here/name)!=digest:raise AssertionError('source bytes differ: '+name)
    if not report['source_hashes_unchanged']:raise AssertionError('campaign reported changed source')
    torch.set_num_threads(1)
    artifacts=Path(report_path).parent/(Path(report_path).stem+'-artifacts')
    checks=[];queries=0;max_error=0.
    for entry in report['runs']:
        if len(entry['losses'])!=entry['updates'] or len(entry['preclip_gradient_norms'])!=entry['updates']:
            raise AssertionError('training trace incomplete')
        checkpoint=artifacts/entry['checkpoint']['filename']
        if sha(checkpoint)!=entry['checkpoint']['sha256']:raise AssertionError('checkpoint digest differs')
        model=load_model(entry['mode'],checkpoint)
        if sum(p.numel() for p in model.parameters())!=entry['parameter_count']:raise AssertionError('parameter count differs')
        if 'heldout' not in entry:
            checks.append(dict(mode=entry['mode'],seed=entry['seed'],status=entry['status'],partial_checkpoint_verified=True))
            continue
        raw_path=artifacts/entry['raw_queries']['filename']
        if sha(raw_path)!=entry['raw_queries']['sha256']:raise AssertionError('raw query digest differs')
        with np.load(raw_path,allow_pickle=False) as raw:
            for name,spec in protocol['heldout'].items():
                batch=make_reset_validity_panel(spec);expected=entry['heldout'][name]
                if batch_digest(batch)!=expected['dataset_sha256']:raise AssertionError('dataset digest differs')
                with torch.inference_mode():scores,trace=model(batch.tokens,batch.duration,return_trace=True)
                mask=batch.targets!=-100;pred=scores.argmax(-1);correct=pred==batch.targets
                arrays=dict(positions=mask.nonzero().numpy(),targets=batch.targets[mask].numpy(),
                            probabilities=scores[mask].exp().numpy(),predictions=pred[mask].numpy(),
                            binding_logits=trace['binding_logit'][mask].numpy(),events=trace['events'].to(torch.uint8).numpy())
                for suffix,array in arrays.items():
                    if not np.array_equal(array,raw[name+'_'+suffix]):
                        raise AssertionError('replay differs: '+entry['mode']+'/'+name+'/'+suffix)
                difference=float(np.max(np.abs(arrays['probabilities']-raw[name+'_probabilities'])))
                max_error=max(max_error,difference);queries+=int(mask.sum())
                # Direct integer recomputation is independent of the campaign metric helper.
                counts=dict(queries=int(mask.sum()),correct_queries=int((mask&correct).sum()),
                            exact_sequences=int((correct|~mask).all(-1).sum()),sequences=len(batch.lengths),
                            unknown_queries=int(((batch.targets==UNKNOWN)&mask).sum()),
                            unknown_false_accepts=int(((batch.targets==UNKNOWN)&mask&(pred!=UNKNOWN)).sum()))
                stale=mask&(batch.stale_answers>=0)&(batch.stale_answers!=batch.targets)
                counts['stale_answer_opportunities']=int(stale.sum())
                counts['stale_answers_emitted']=int((stale&(pred==batch.stale_answers)).sum())
                for key,value in counts.items():
                    if value!=expected[key]:raise AssertionError('metric differs: '+key)
                passed=counts['correct_queries']/counts['queries']>=.95 and counts['exact_sequences']/counts['sequences']>=.90
                if passed!=expected['bounded_quality_pass']:raise AssertionError('quality gate differs')
                checks.append(dict(mode=entry['mode'],seed=entry['seed'],panel=name,queries=counts['queries'],
                                   dataset_sha256=batch_digest(batch),probability_max_difference=difference,
                                   raw_arrays_exact=True,integer_metrics_exact=True,bounded_quality_pass=passed))
        witness=conditional_erasure_witness(model,protocol['development']['erasure_witness'])
        if witness!=entry['conditional_erasure_witness']:raise AssertionError('erasure witness differs')
    return dict(schema='hcsn.p2.reset-validity-artifact-audit.v1',status='PASS',
                report_sha256=sha(report_path),protocol_sha256=sha(protocol_path),
                all_planned_fits_completed=report['all_four_training_runs_completed'],
                quality_queries_replayed=queries,max_probability_difference=max_error,
                checks=checks,source_hashes_verified=True,checkpoints_and_raw_arrays_verified=True,
                internal_computational_replay_only=True,external_independent_attestation=False,
                cpu_seconds=time.process_time()-cpu,wall_seconds=time.perf_counter()-start)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('refuse to overwrite audit')
    result=audit(args.protocol,args.report)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({key:result[key] for key in ('status','quality_queries_replayed','max_probability_difference','cpu_seconds')}))


if __name__=='__main__':main()
