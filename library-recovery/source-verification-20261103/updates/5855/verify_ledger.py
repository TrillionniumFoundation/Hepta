#!/usr/bin/env python3
"""Reconstruct exact verification records; no network or preserved source execution."""
import hashlib
import json
import sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError("ledger verification requires checks enabled; run without -O or PYTHONOPTIMIZE")

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
objects=[r for name in original_header['objects_files'] for r in load(base/name)]
original={k:objects if k=='objects' else original_header['metadata'][k] for k in original_header['top_level_key_order']}
assert hashlib.sha256(serialize(original)).hexdigest()=='49f2ad294a7edfb9741d1b5354057437464982cad7047960cd9c62689ac67770'
for step,digest,count in [
    ('5232','04f32b2678ac20937821d2e21dc243eda95ff3b7c06e2c125427486f7ff103e5',3215),
    ('5432','ea42c0440c58c5ae57c843f139735c0db48691bceee54e7ed74168d2cb639830',3415),
    ('5584','b3f7fae6369fc8cdb6bf39b43c6895c5aba8a148444afeae3de2b50b8485b4c7',3567),
    ('5702','9b9099ad1c7a9bb5ee29dfed0200f7d06d8ea84baae10b6e56556f31de79a1c7',3685),
    ('5708','6aeda243a5ed28f7aa516fc1ad067de386684f8d4ba63ce147e80de3c1bf479e',3691),
    ('5711','0a176050682aeb82ad7badaa78edc2f707869b5dedbabd12f3a903058c635dda',3694),
    ('5729','256fac282c185dabebf1acc79cd0c91537cd9e30055ef853399e2fb411489441',3712),
    ('5737','cf8d0e55bb9cf6e772970f7f31bee9a045a355a1cfbaa2afeee579236d9cdd82',3720),
    ('5742','74c15a203fda233e443e04a535b8bf45ef6274ae2005a63abf749b19798c86c3',3725),
    ('5789','4418480e315597986c7d2284bc6a0d660de5ef51989728857c4009d65475b237',3772),
]:
    directory=here.parent/step
    previous_header=load(directory/'LEDGER_HEADER.json')
    previous_delta=load(directory/previous_header['delta_file'])
    objects=sorted(objects+previous_delta,key=lambda r:r['git_blob_sha'])
    previous=rebuild(previous_header,objects)
    assert len(objects)==len({r['git_blob_sha'] for r in objects})==count
    assert hashlib.sha256(serialize(previous)).hexdigest()==digest
header=load(here/'LEDGER_HEADER.json')
assert header['reconstructed_sha256']=='60961b6884189f87d5d91e43c18e083b7bc75a3e129e81d8b4e91e9fa8458988'
delta=load(here/header['delta_file'])
objects=sorted(objects+delta,key=lambda r:r['git_blob_sha'])
ledger=rebuild(header,objects)
candidates=[r for name in manifest['candidate_files'] for r in load(base/name)]
baseline=[r for name in manifest['baseline_files'] for r in load(base/name)]
by_candidate={r['git_blob_sha']:r for r in candidates}
by_baseline={r['git_blob_sha']:r for r in baseline}
by_object={r['git_blob_sha']:r for r in objects}
assert len(candidates)==len(by_candidate)==6116
assert len(baseline)==len(by_baseline)==2017
assert len(objects)==len(by_object)==3838
assert len(delta)==66
assert not by_baseline.keys() & by_object.keys()
for row in baseline+objects:
    c=by_candidate[row['git_blob_sha']]
    assert (row['sha256'],row['bytes'],row['candidate_group'])==(c['sha256'],c['bytes'],c['candidate_group'])
for row in objects:
    assert row['verified'] is True
    assert all(row[k] for k in ('repo','commit','path','ref'))
refs=load(here/'ARCHIVE_REFS.json')
assert refs==ledger['new_batch']['preserved_refs']
retained={(r['repo'],r['commit'],r['ref']) for r in refs if r['verified']}
assert all((r['repo'],r['commit'],r['ref']) in retained for r in delta)
assert ledger['total_verified_unique']==5855
assert ledger['unverified_candidates_remaining']==261
assert ledger['all_library_source_synced'] is False
assert ledger['eligible_to_clear_library'] is False
assert ledger['library_deletion_performed'] is False
print(json.dumps({'verified':5855,'candidate_union':6116,'unverified':261,'increment':3838,'reconstructed_sha256':hashlib.sha256(serialize(ledger)).hexdigest(),'fresh_remote_reads_by_this_script':False,'archived_source_executed':False,'clearance_allowed':False}))
