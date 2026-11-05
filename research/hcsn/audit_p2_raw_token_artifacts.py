"""Read-only, independent replay of the prior raw-token negative-result bundle."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import numpy as np
import torch
from .p2_round2_raw_tokens import RawTokenMemory, make_batch, batch_digest


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():raise FileExistsError('audit output already exists')
    base=Path(__file__).resolve().parent;d=json.loads(args.report.read_text())
    artifacts=args.report.parent/(args.report.stem+'-artifacts')
    torch.set_num_threads(1);started=time.perf_counter();checks=[]
    for relative,digest in d['source_sha256'].items():
        if hashlib.sha256((base/relative).read_bytes()).hexdigest()!=digest:raise AssertionError('source drift '+relative)
    for seed in d['model_seeds']:
        runs=[r for r in d['runs'] if r['seed']==seed]
        if len(runs)!=2 or runs[0]['training_stream_sha256']!=runs[1]['training_stream_sha256']:raise AssertionError('training pairing mismatch')
    panels={n:make_batch(**s) for n,s in d['panel_specifications'].items()}
    for name,b in panels.items():
        if batch_digest(b)!=d['heldout_dataset_sha256'][name]:raise AssertionError('data drift '+name)
    max_probability_error=0.;total_queries=0
    for entry in d['runs']:
        if len(entry['all_update_losses'])!=entry['updates'] or not np.isfinite(entry['all_update_losses']).all():raise AssertionError('loss trace invalid')
        for key in ['checkpoint','raw_heldout_queries']:
            p=artifacts/entry[key]['filename']
            if hashlib.sha256(p.read_bytes()).hexdigest()!=entry[key]['sha256']:raise AssertionError('artifact drift '+str(p))
        model=RawTokenMemory(entry['mode'])
        with np.load(artifacts/entry['checkpoint']['filename'],allow_pickle=False) as state:
            model.load_state_dict({k:torch.from_numpy(state[k].copy()) for k in state.files},strict=True)
        model.eval()
        with np.load(artifacts/entry['raw_heldout_queries']['filename'],allow_pickle=False) as raw,torch.inference_mode():
            for name,b in panels.items():
                mask=b.targets!=-100;positions=mask.nonzero().numpy();labels=b.targets[mask].numpy()
                logits=model(b.tokens,b.duration)[mask];predictions=logits.argmax(-1).numpy()
                probs=logits.softmax(-1).numpy();stored=raw[name+'_probabilities']
                if not np.array_equal(positions,raw[name+'_positions']):raise AssertionError('position drift')
                if not np.array_equal(labels,raw[name+'_targets']):raise AssertionError('label drift')
                if not np.array_equal(predictions,raw[name+'_predictions']):raise AssertionError('prediction drift')
                error=float(np.max(np.abs(probs-stored)));max_probability_error=max(error,max_probability_error)
                if error>1e-7:raise AssertionError('probability drift')
                correct=predictions==labels
                exact=sum(bool(correct[positions[:,0]==row].all()) for row in range(len(b.lengths)))
                old=entry['heldout'][name]
                if int(correct.sum())!=old['correct_queries'] or exact!=old['exact_sequences']:raise AssertionError('metric mismatch')
                if len(labels)!=old['queries']:raise AssertionError('denominator mismatch')
                total_queries+=len(labels)
                checks.append(dict(mode=entry['mode'],seed=entry['seed'],panel=name,queries=len(labels),
                                   correct_queries=int(correct.sum()),exact_sequences=exact,probability_max_error=error))
    result=dict(schema='hcsn.p2.prior-raw-token-replay-audit.v1',report_sha256=hashlib.sha256(args.report.read_bytes()).hexdigest(),
                source_hashes_checked=len(d['source_sha256']),models=len(d['runs']),panels=len(panels),
                model_panel_replays=len(checks),total_query_replays=total_queries,
                max_probability_discrepancy=max_probability_error,checks=checks,wall_seconds=time.perf_counter()-started,
                status='PASS_ARTIFACT_CONSISTENCY_ONLY',scientific_acceptance=False,production_activation=False)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({k:result[k] for k in result if k!='checks'}))

if __name__=='__main__':main()
