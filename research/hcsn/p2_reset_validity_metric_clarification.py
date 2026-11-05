"""Clarify legacy stale counts from saved arrays; no fits or model forwards."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from .p2_reset_validity import make_reset_validity_panel
from .p2_round2_raw_tokens import UNKNOWN,batch_digest


def clarify(protocol_path,report_path):
    protocol=json.loads(Path(protocol_path).read_text());report=json.loads(Path(report_path).read_text())
    if report['status']!='COMPLETED_FIXED_CONFIGURATION_SET':raise ValueError('require completed fixed configurations')
    folder=Path(report_path).parent/(Path(report_path).stem+'-artifacts')
    batches={name:make_reset_validity_panel(spec) for name,spec in protocol['heldout'].items()}
    runs=[]
    for entry in report['runs']:
        path=folder/entry['raw_queries']['filename']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['raw_queries']['sha256']:raise AssertionError('raw bytes differ')
        panels={}
        with np.load(path,allow_pickle=False) as raw:
            for name,batch in batches.items():
                if batch_digest(batch)!=entry['heldout'][name]['dataset_sha256']:raise AssertionError('dataset differs')
                pos=raw[name+'_positions'];target=raw[name+'_targets'];pred=raw[name+'_predictions']
                if not np.array_equal(batch.targets.numpy()[pos[:,0],pos[:,1]],target):raise AssertionError('labels differ')
                old=batch.stale_answers.numpy()[pos[:,0],pos[:,1]]
                known=(target>=0)&(target<UNKNOWN);unknown=target==UNKNOWN
                legacy=(old>=0)&(old!=target)
                old_known=(old>=0)&(old<UNKNOWN)&(old!=target)
                event=raw[name+'_events'][pos[:,0],pos[:,1]];binding=raw[name+'_binding_logits']
                metrics=dict(queries=len(pred),known_targets=int(known.sum()),known_correct=int((known&(pred==target)).sum()),
                    known_refusals=int((known&(pred==UNKNOWN)).sum()),unknown_targets=int(unknown.sum()),
                    unknown_false_accepts=int((unknown&(pred!=UNKNOWN)).sum()),
                    predictions_UNKNOWN=int((pred==UNKNOWN).sum()),
                    legacy_stale_predictions=int((legacy&(pred==old)).sum()),
                    old_UNKNOWN_previous_label_predictions=int(((old==UNKNOWN)&known&(pred==UNKNOWN)).sum()),
                    old_known_value_opportunities=int(old_known.sum()),
                    old_known_value_predictions=int((old_known&(pred==old)).sum()),
                    query_reset_events=int(event[:,1].sum()),
                    query_actual_write_events_after_reset_priority=int((event[:,0]*(1-event[:,1])).sum()),
                    binding_logit_min=float(binding.min()),binding_logit_max=float(binding.max()))
                if metrics['legacy_stale_predictions']!=entry['heldout'][name]['stale_answers_emitted']:
                    raise AssertionError('legacy count differs')
                panels[name]=metrics
        count_keys=[k for k in next(iter(panels.values())) if not k.startswith('binding_logit_')]
        total={k:sum(p[k] for p in panels.values()) for k in count_keys}
        total['binding_logit_min']=min(p['binding_logit_min'] for p in panels.values())
        total['binding_logit_max']=max(p['binding_logit_max'] for p in panels.values())
        runs.append(dict(mode=entry['mode'],seed=entry['seed'],panels=panels,totals=total))
    return dict(schema='hcsn.p2.reset-validity-metric-clarification.v1',post_hoc=True,new_fits=0,new_model_forwards=0,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        report_sha256=hashlib.sha256(Path(report_path).read_bytes()).hexdigest(),
        definitions={'known_target':'0 <= target < UNKNOWN (4)',
                     'known_refusal':'known target and predicted UNKNOWN',
                     'legacy_stale':'previous label >=0, different from target; predicted previous label; includes UNKNOWN=4',
                     'old_known_value':'0 <= previous label < UNKNOWN; different from target; predicted previous label',
                     'query_reset_events':'saved reset event at each saved query position',
                     'binding_logit':'saved learned binding logit at each saved query position'},
        frozen_legacy_metrics_unchanged=True,runs=runs)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('refuse to overwrite clarification')
    result=clarify(args.protocol,args.report)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps([dict(mode=r['mode'],seed=r['seed'],**r['totals']) for r in result['runs']],indent=2))


if __name__=='__main__':main()
