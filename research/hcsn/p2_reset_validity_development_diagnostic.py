"""Post hoc development-only gate diagnosis. No fitting or heldout generation."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import torch
from torch.nn import functional as F
from .p2_reset_validity import make_reset_validity_panel
from .p2_reset_validity_campaign import load_model
from .p2_associative_memory import IGNORE
from .p2_round2_raw_tokens import WRITE,RESET,KEY_BASE,VALUE_BASE,VOCAB_SIZE,KEY_COUNT,UNKNOWN,batch_digest


def run(protocol_path,report_path):
    start=time.process_time();torch.set_num_threads(1)
    protocol=json.loads(Path(protocol_path).read_text());report=json.loads(Path(report_path).read_text())
    if report['status']=='RUNNING':raise ValueError('wait for the campaign to finish')
    artifacts=Path(report_path).parent/(Path(report_path).stem+'-artifacts')
    batch=make_reset_validity_panel(protocol['development']['panels']['multi_reset'])
    runs=[]
    for entry in report['runs']:
        model=load_model(entry['mode'],artifacts/entry['checkpoint']['filename'])
        with torch.inference_mode():scores,trace=model(batch.tokens,batch.duration,return_trace=True)
        groups={name:[] for name in ('true_write_value','ignored_value','visible_reset','query','other')}
        for row,L in enumerate(batch.lengths):
            for t in range(L):
                current=int(batch.tokens[row,t])
                if t>=2 and int(batch.tokens[row,t-2])==WRITE and VALUE_BASE<=current<VOCAB_SIZE:
                    tag='true_write_value'
                elif t>=2 and int(batch.tokens[row,t-2])==IGNORE and VALUE_BASE<=current<VOCAB_SIZE:
                    tag='ignored_value'
                elif current==RESET:tag='visible_reset'
                elif int(batch.targets[row,t])!=-100:tag='query'
                else:tag='other'
                groups[tag].append((row,t))
        summaries={}
        for name,positions in groups.items():
            if not positions:continue
            rows,columns=zip(*positions)
            event=trace['events'][rows,columns];soft=trace['soft_controls'][rows,columns]
            summaries[name]=dict(tokens=len(positions),proposed_write_events=int(event[:,0].sum()),
                actual_write_events_after_reset_priority=int((event[:,0]*(1-event[:,1])).sum()),
                reset_events=int(event[:,1].sum()),mean_soft_write_probability=float(soft[:,0].mean()),
                mean_soft_reset_probability=float(soft[:,1].mean()))
        known=(batch.targets!=-100)&(batch.targets!=UNKNOWN);unknown=batch.targets==UNKNOWN
        prediction=scores.argmax(-1)
        with torch.inference_mode():
            address=F.normalize(model.address(model.embedding(torch.arange(KEY_BASE,VALUE_BASE))),dim=-1)
            offdiagonal=address@address.T-torch.eye(KEY_COUNT)
        runs.append(dict(mode=entry['mode'],seed=entry['seed'],fit_status=entry['status'],updates=entry['updates'],
            token_groups=summaries,known_queries=int(known.sum()),known_predictions_UNKNOWN=int(((prediction==UNKNOWN)&known).sum()),
            unknown_queries=int(unknown.sum()),unknown_false_accepts=int(((prediction!=UNKNOWN)&unknown).sum()),
            query_binding_logit_min=float(trace['binding_logit'][known|unknown].min()),
            query_binding_logit_max=float(trace['binding_logit'][known|unknown].max()),
            learned_key_offdiagonal_gram_max=float(offdiagonal.abs().max())))
    return dict(schema='hcsn.p2.reset-validity-development-diagnosis.v1',post_hoc=True,
        report_sha256=hashlib.sha256(Path(report_path).read_bytes()).hexdigest(),
        dataset_sha256=batch_digest(batch),dataset_role='the registered multi_reset development panel; never heldout',
        fitting_or_checkpoint_selection=False,new_fits=0,runs=runs,cpu_seconds=time.process_time()-start,
        limitations=['descriptive diagnosis, not a preregistered quality claim or causal attribution',
                     'semantic tags are analysis-only and are never supplied to model forward'])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('refuse to overwrite diagnosis')
    result=run(args.protocol,args.report)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True,allow_nan=False))


if __name__=='__main__':main()
