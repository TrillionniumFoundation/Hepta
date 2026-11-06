#!/usr/bin/env python3
"""Reconstruct the exact verification ledger; no network or preserved source execution."""
import hashlib
import json
from pathlib import Path

here=Path(__file__).resolve().parent
base=here.parent.parent
def load(path):return json.loads(path.read_bytes())
def serialize(ledger):return (json.dumps(ledger,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
def rebuild(header,objects):
    ledger={k:objects if k=='objects' else header['metadata'][k] for k in header['top_level_key_order']}
    raw=serialize(ledger)
    assert len(raw)==header['reconstructed_bytes']
    assert hashlib.sha256(raw).hexdigest()==header['reconstructed_sha256']
    return ledger

manifest=load(base/'CHECKPOINT_MANIFEST.json')
for row in manifest['files']:
    raw=(base/row['path']).read_bytes()
    assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
original_header=load(base/'LEDGER_HEADER.json')
original_objects=[r for name in original_header['objects_files'] for r in load(base/name)]
original={k:original_objects if k=='objects' else original_header['metadata'][k] for k in original_header['top_level_key_order']}
assert hashlib.sha256(serialize(original)).hexdigest()=='49f2ad294a7edfb9741d1b5354057437464982cad7047960cd9c62689ac67770'
previous_dir=here.parent/'5232'
previous_header=load(previous_dir/'LEDGER_HEADER.json')
previous_delta=load(previous_dir/previous_header['delta_file'])
previous_objects=sorted(original_objects+previous_delta,key=lambda r:r['git_blob_sha'])
previous=rebuild(previous_header,previous_objects)
assert hashlib.sha256(serialize(previous)).hexdigest()=='04f32b2678ac20937821d2e21dc243eda95ff3b7c06e2c125427486f7ff103e5'
header=load(here/'LEDGER_HEADER.json')
delta=load(here/header['delta_file'])
objects=sorted(previous_objects+delta,key=lambda r:r['git_blob_sha'])
ledger=rebuild(header,objects)
candidates=[r for name in manifest['candidate_files'] for r in load(base/name)]
baseline=[r for name in manifest['baseline_files'] for r in load(base/name)]
by_candidate={r['git_blob_sha']:r for r in candidates}
by_baseline={r['git_blob_sha']:r for r in baseline}
by_object={r['git_blob_sha']:r for r in objects}
assert len(candidates)==len(by_candidate)==6116
assert len(baseline)==len(by_baseline)==2017
assert len(objects)==len(by_object)==3415
assert len(delta)==200
assert not by_baseline.keys() & by_object.keys()
for row in baseline+objects:
    c=by_candidate[row['git_blob_sha']]
    assert (row['sha256'],row['bytes'],row['candidate_group'])==(c['sha256'],c['bytes'],c['candidate_group'])
for row in objects:
    assert row['verified'] is True
    assert all(row[k] for k in ('repo','commit','path','ref'))
assert ledger['total_verified_unique']==5432
assert ledger['unverified_candidates_remaining']==684
assert ledger['all_library_source_synced'] is False
assert ledger['library_deletion_performed'] is False
print(json.dumps({'verified':5432,'candidate_union':6116,'unverified':684,'increment':3415,'reconstructed_sha256':hashlib.sha256(serialize(ledger)).hexdigest(),'fresh_remote_reads_by_this_script':False,'archived_source_executed':False,'clearance_allowed':False}))
