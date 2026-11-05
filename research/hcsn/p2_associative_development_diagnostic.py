"""Post-run diagnostics on the already disclosed development splits only.

No fitting, checkpoint selection, held-out evaluation, or policy changes occur.
The diagnostic identifies which learned gates failed; it does not attribute an
optimization failure universally to a function family.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from .p2_associative_memory import delta_batch,gate_diagnostics
from .p2_associative_campaign import load_model


def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True)
    p.add_argument('--protocol',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError('do not overwrite diagnostic')
    d=json.loads(a.report.read_text());protocol=json.loads(a.protocol.read_text())
    artifacts=a.report.parent/(a.report.stem+'-artifacts');torch.set_num_threads(1)
    rows=[]
    for entry in d['runs']:
        model=load_model(entry['mode'],artifacts/entry['checkpoint']['filename'])
        row=dict(seed=entry['seed'],mode=entry['mode'],checkpoint_sha256=entry['checkpoint']['sha256'],panels={})
        for kind,seed in protocol['development']['seeds'].items():
            b=delta_batch(seed,n=protocol['development']['n'],kinds=(kind,))
            row['panels'][kind]=gate_diagnostics(model,b)
        rows.append(row)
    out=dict(schema='hcsn.p2.associative-posthoc-development-diagnostic.v1',
             posthoc=True,development_only=True,uses_heldout=False,changes_policy=False,
             report_sha256=hashlib.sha256(a.report.read_bytes()).hexdigest(),rows=rows,
             scientific_acceptance=False,production_activation=False)
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True,allow_nan=False)+'\n')
    for row in rows:
        panel=row['panels']['multi_reset']
        print(json.dumps(dict(seed=row['seed'],mode=row['mode'],true_value=panel.get('true_value'),ignored_value=panel.get('ignored_value'),reset=panel.get('reset'),max_offdiagonal=panel['learned_key_offdiagonal_gram_max'])))

if __name__=='__main__':main()
