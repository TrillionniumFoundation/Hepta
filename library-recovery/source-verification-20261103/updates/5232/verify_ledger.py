#!/usr/bin/env python3
"""Rebuild and validate the cumulative ledger; no network or source execution."""
import hashlib
import json
from pathlib import Path

here=Path(__file__).resolve().parent
prior=here.parent.parent
def load(path):return json.loads(path.read_bytes())
manifest=load(prior/'CHECKPOINT_MANIFEST.json')
for row in manifest['files']:
    data=(prior/row['path']).read_bytes()
    assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
old_header=load(prior/'LEDGER_HEADER.json')
old_objects=[r for name in old_header['objects_files'] for r in load(prior/name)]
old_ledger={key:old_objects if key=='objects' else old_header['metadata'][key] for key in old_header['top_level_key_order']}
old_bytes=(json.dumps(old_ledger,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
assert hashlib.sha256(old_bytes).hexdigest()=='49f2ad294a7edfb9741d1b5354057437464982cad7047960cd9c62689ac67770'
header=load(here/'LEDGER_HEADER.json')
delta=load(here/header['delta_file'])
objects=sorted(old_objects+delta,key=lambda r:r['git_blob_sha'])
ledger={key:objects if key=='objects' else header['metadata'][key] for key in header['top_level_key_order']}
raw=(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
assert len(raw)==header['reconstructed_bytes']
assert hashlib.sha256(raw).hexdigest()==header['reconstructed_sha256']
candidates=[r for name in manifest['candidate_files'] for r in load(prior/name)]
baseline=[r for name in manifest['baseline_files'] for r in load(prior/name)]
by_candidate={r['git_blob_sha']:r for r in candidates}
by_baseline={r['git_blob_sha']:r for r in baseline}
by_object={r['git_blob_sha']:r for r in objects}
assert len(by_candidate)==len(candidates)==6116
assert len(by_baseline)==len(baseline)==2017
assert len(by_object)==len(objects)==3215
assert len(delta)==263
assert not by_baseline.keys() & by_object.keys()
for row in baseline+objects:
    candidate=by_candidate[row['git_blob_sha']]
    assert (row['sha256'],row['bytes'],row['candidate_group'])==(candidate['sha256'],candidate['bytes'],candidate['candidate_group'])
for row in objects:
    assert row['verified'] is True
    assert all(row[k] for k in ('repo','commit','path','ref'))
assert ledger['all_library_source_synced'] is False
assert ledger['library_deletion_performed'] is False
print(json.dumps({'verified':5232,'candidate_union':6116,'unverified':884,'increment':3215,'reconstructed_sha256':hashlib.sha256(raw).hexdigest(),'fresh_remote_reads_by_this_script':False,'archived_source_executed':False,'clearance_allowed':False}))
