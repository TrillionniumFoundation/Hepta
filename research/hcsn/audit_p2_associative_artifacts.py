"""Independently recount and replay frozen associative checkpoint evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from .p2_associative_memory import RawDeltaMemory, delta_batch
from .p2_round2_raw_tokens import batch_digest


def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);p.add_argument('--protocol',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError('refusing to overwrite audit')
    here=Path(__file__).resolve().parent;d=json.loads(a.report.read_text());protocol=json.loads(a.protocol.read_text())
    if not d['all_four_training_runs_completed'] or d['production_activation']:raise AssertionError('incomplete or activated campaign')
    for k,v in d['source_sha256'].items():
        if hashlib.sha256((here/k).read_bytes()).hexdigest()!=v:raise AssertionError('source drift '+k)
    if hashlib.sha256(a.protocol.read_bytes()).hexdigest()!=d['protocol_sha256']:raise AssertionError('protocol drift')
    artifacts=a.report.parent/(a.report.stem+'-artifacts');torch.set_num_threads(1)
    panels={n:delta_batch(**s) for n,s in protocol['heldout'].items()}
    checks=[];total_queries=0;worst=0.
    for r in d['runs']:
        if r['updates']!=protocol['training']['steps_per_model'] or len(r['losses'])!=r['updates']:raise AssertionError('update budget mismatch')
        if len(r['preclip_gradient_norms'])!=r['updates'] or not np.isfinite(r['preclip_gradient_norms']).all():raise AssertionError('gradient trace invalid')
        for key in ['checkpoint','raw_queries']:
            f=artifacts/r[key]['filename']
            if hashlib.sha256(f.read_bytes()).hexdigest()!=r[key]['sha256']:raise AssertionError('artifact hash mismatch')
        model=RawDeltaMemory(r['mode'])
        with np.load(artifacts/r['checkpoint']['filename'],allow_pickle=False) as z:
            model.load_state_dict({k:torch.from_numpy(z[k].copy()) for k in z.files},strict=True)
        model.eval()
        with torch.inference_mode(),np.load(artifacts/r['raw_queries']['filename'],allow_pickle=False) as z:
            for name,b in panels.items():
                valid=b.targets!=-100;pos=valid.nonzero().numpy();target=b.targets[valid].numpy()
                logits=model(b.tokens,b.duration)[valid];pred=logits.argmax(-1).numpy();probs=logits.softmax(-1).numpy()
                for key,values in [('positions',pos),('targets',target),('predictions',pred)]:
                    if not np.array_equal(values,z[name+'_'+key]):raise AssertionError(name+' '+key+' mismatch')
                diff=float(abs(probs-z[name+'_probabilities']).max());worst=max(worst,diff)
                if diff>1e-7:raise AssertionError('probability drift')
                if not np.allclose(probs.sum(-1),1.,atol=1e-6):raise AssertionError('invalid probabilities')
                correct=pred==target;exact=sum(bool(correct[pos[:,0]==i].all()) for i in range(len(b.lengths)))
                old=r['heldout'][name]
                if old['dataset_sha256']!=batch_digest(b) or old['queries']!=len(target):raise AssertionError('data mismatch')
                if old['correct_queries']!=int(correct.sum()) or old['exact_sequences']!=exact:raise AssertionError('metric mismatch')
                quality=float(correct.mean())>=.95 and exact/len(b.lengths)>=.90
                if old['bounded_quality_pass']!=quality:raise AssertionError('quality verdict mismatch')
                total_queries+=len(target)
                checks.append(dict(seed=r['seed'],mode=r['mode'],panel=name,queries=len(target),correct_queries=int(correct.sum()),exact_sequences=exact,bounded_quality_pass=quality))
    for seed in protocol['training']['model_seeds']:
        pair=[r for r in d['runs'] if r['seed']==seed]
        if len(pair)!=2:raise AssertionError('missing pair')
        for k in ['initial_parameters_sha256','training_stream_sha256','parameter_count','updates']:
            if pair[0][k]!=pair[1][k]:raise AssertionError('pair mismatch '+k)
    out=dict(status='PASS_ARTIFACT_CONSISTENCY_ONLY',report_sha256=hashlib.sha256(a.report.read_bytes()).hexdigest(),
             model_panel_replays=len(checks),queries_replayed=total_queries,probability_max_error=worst,
             checks=checks,scientific_acceptance=False,production_activation=False)
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({k:v for k,v in out.items() if k!='checks'}))

if __name__=='__main__':main()
