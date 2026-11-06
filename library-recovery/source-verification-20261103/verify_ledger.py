#!/usr/bin/env python3
"""Verify the archived ledger and fingerprints; no network or recovered-code execution."""
import hashlib
import json
from pathlib import Path, PurePosixPath

root=Path(__file__).resolve().parent
def require(value,message):
    if not value:raise SystemExit(message)
def read(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts,'unsafe checkpoint path')
    path=root.joinpath(*p.parts)
    require(not path.is_symlink(),'unexpected symlink')
    return path.read_bytes()
def load(name):return json.loads(read(name))
manifest=load('CHECKPOINT_MANIFEST.json')
for row in manifest['files']:
    data=read(row['path'])
    require(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'file mismatch: '+row['path'])
header=load('LEDGER_HEADER.json')
objects=[row for name in header['objects_files'] for row in load(name)]
ledger={key:objects if key=='objects' else header['metadata'][key] for key in header['top_level_key_order']}
raw=(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
require(len(raw)==header['reconstructed_original_bytes'] and hashlib.sha256(raw).hexdigest()==header['reconstructed_sha256'],'reconstructed ledger mismatch')
candidate_rows=[row for name in manifest['candidate_files'] for row in load(name)]
candidates={r['git_blob_sha']:r for r in candidate_rows}
baseline_rows=[row for name in manifest['baseline_files'] for row in load(name)]
baseline={r['git_blob_sha']:r for r in baseline_rows}
increment={r['git_blob_sha']:r for r in objects}
require(len(candidates)==len(candidate_rows)==6116,'candidate count or duplicate mismatch')
require(len(baseline)==len(baseline_rows)==2017,'baseline count or duplicate mismatch')
require(len(increment)==len(objects)==2952,'increment count or duplicate mismatch')
require(not baseline.keys() & increment.keys(),'baseline/increment overlap')
for row in baseline_rows+objects:
    candidate=candidates.get(row['git_blob_sha'])
    require(candidate is not None,'unknown candidate')
    require(candidate['bytes']==row['bytes'] and candidate['sha256']==row['sha256'],'candidate byte-fingerprint mismatch')
for row in objects:
    require(row.get('verified') is True,'unverified incremental row')
    require(all(row.get(k) for k in ('repo','commit','path','ref')),'missing source locator')
require(ledger.get('all_library_source_synced') is False,'incorrect synchronization closure')
require(load('RECONSTRUCTION_RECEIPT.json')['clearance_allowed'] is False,'incorrect clearance')
print('Checkpoint metadata verified: 2017 + 2952 = 4969 of 6116; 1147 remain unverified.')
print('Reconstructed JSON SHA-256:',hashlib.sha256(raw).hexdigest())
print('Remote byte reads repeated by this verifier: false; recovered source executed: false; clearance: false.')
