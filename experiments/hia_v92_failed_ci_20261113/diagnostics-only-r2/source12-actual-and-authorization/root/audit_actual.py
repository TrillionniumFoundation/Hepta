"""Independent full-body readback; never import or rerun the tested implementation."""
from pathlib import Path
import collections
import hashlib
import io
import json
import os
import stat
import zipfile
import zlib

SOURCE=Path('/home/agent/hia-v92-diagnostics-only-remote-r2-20261113-e26e')
ACTUAL=Path('/home/agent/hia-v92-diagnostics-only-source12-r2b-output-20261113-e26e')
OUT=Path('/workspace/scratch/e26ed3e2edcf/root/v92-diagnostics-only-source12-r2b-invocation')
def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    path=Path(path); before=path.lstat()
    assert stat.S_ISREG(before.st_mode),str(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        assert identity(os.fstat(f.fileno()))==identity(before)
        raw=f.read();assert identity(os.fstat(f.fileno()))==identity(before)
    assert len(raw)==before.st_size and identity(path.lstat())==identity(before)
    return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(before)}
owner_raw,owner_pin=read(OUT/'OWNER-FIRST-READBACK.json')
assert owner_pin['sha256']=='302c40c697347c3d5a3a77325be1383483f0cf8459c863e1df3d4752a3bc7aa3'
assert json.loads(owner_raw)['status']=='BOUND_CURRENT_OWNER_NATURAL_0_ECHILD'
request_raw,request_pin=read(SOURCE/'CONTROL-REQUEST-r2b.json');request=json.loads(request_raw)
assert request_pin['sha256']=='0d2cffe505a7915bc183da38bf3aa7a8c966d47cec730a901342559779e8643d'
inputs=[]
for expected in request['inputs']:
    raw,pin=read(expected['path']);assert pin=={k:expected[k] for k in pin}
    inputs.append({**pin,'role':expected['role']})
rows=[];bodies={}
def walk(path):
    before=path.lstat();rel=str(path.relative_to(ACTUAL))
    assert before.st_uid==os.geteuid()
    row={'path':rel,'identity':identity(before)}
    if stat.S_ISDIR(before.st_mode):
        row['kind']='directory';rows.append(row)
        for name in sorted(os.listdir(path)):walk(path/name)
    elif stat.S_ISLNK(before.st_mode):
        row.update(kind='symlink_fixture_not_followed',target=os.readlink(path));rows.append(row)
    else:
        assert stat.S_ISREG(before.st_mode) and before.st_nlink in (1,2)
        raw,pin=read(path);bodies[rel]=raw
        row.update(kind='regular',bytes=len(raw),sha256=pin['sha256'],synthetic_hardlink_failure=before.st_nlink==2);rows.append(row)
    assert identity(path.lstat())==identity(before)
walk(ACTUAL)
by_path={r['path']:r for r in rows};assert len(by_path)==len(rows)<=4096
total=sum(map(len,bodies.values()));assert total<=64<<20
originals=json.loads(bodies['ORIGINALS.json']);old=originals['files_and_directories']
assert {r['path'] for r in old}|{'ORIGINALS.json','FINAL.json'}==set(by_path)
for row in old:
    observed=by_path[row['path']]
    if row['path']=='.':
        assert row['identity'][:6]==observed['identity'][:6]
    else:assert row==observed,row['path']
assert sum(r.get('bytes',0) for r in old)==originals['bytes_fully_read']==7954362
report=json.loads(bodies['REPORT.json']);final=json.loads(bodies['FINAL.json'])
assert report['status']==final['status']=='SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
assert report['expected_ids']==report['loaded_ids']==report['executed_ids']==report['success_ids']==request['expected_ids']
assert len(request['expected_ids'])==len(set(request['expected_ids']))==12
assert all(report[k]==[] for k in ('failures','errors','skips','expected_failures','unexpected_successes','loader_errors','forbidden_attempts'))
assert report['exception'] is None and report['inputs_unchanged'] is True and final['errors']==[]
assert final['closed'] is True and final['natural'] is True
assert final['qualification_seconds']==20 and final['cleanup_seconds']==3
assert report['synthetic_only'] is True and report['network_requests']==report['native_calls']==0
assert report['product_imported'] is False and report['historical_460_originals_recovered'] is False
assert report['old_R4_owner_status']==final['old_local_R4_owner_status']=='UNKNOWN_NOT_RECLASSIFIED'
assert final['source_request_sha256']==request_pin['sha256'] and bodies['REQUEST.original.json']==request_raw
for key,name in [('report','REPORT.json'),('originals','ORIGINALS.json')]:
    pin=final[key];r=by_path[name]
    assert pin=={'path':str(ACTUAL/name),'bytes':r['bytes'],'sha256':r['sha256'],'identity':r['identity']}
for name in ('INPUTS-BEFORE.json','INPUTS-AFTER.json','PARENT-INPUTS-BEFORE.json','PARENT-INPUTS-AFTER.json'):
    assert json.loads(bodies[name])==inputs
log=bodies['unittest.log'].decode();assert log.rstrip().endswith('OK')
assert len([line for line in log.splitlines() if line.endswith(' ... ok')])==12
policy=json.loads((SOURCE/'candidate/policy.json').read_bytes())
def fixture(number,suffix=''):
    name=request['expected_ids'][number-1].split('.',1)[1]
    return 'fixtures/'+name+suffix
def obj(name):return json.loads(bodies[name])
positive=fixture(1);small=positive+'/public/small'
capture=obj(small+'/SMALL-READBACK.json');index=obj(small+'/originals/INDEX.json')
assert capture['complete'] is True and capture['status']=='AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION'
assert capture['selected_count']==460 and capture['selected_bytes']==3012789 and len(capture['files'])==463
assert capture['missing_expected']==policy['expected_diagnostics']['missing_expected'] and len(capture['missing_expected'])==5
assert capture['errors']==[] and capture['qualification_executed'] is False and capture['original_failure_reclassified'] is False
assert index['all_members_fully_read'] is True and index['expected_originals_all_present'] is False
assert index['members']==462 and index['expanded_bytes']==3012856 and len(index['selected'])==460
assert not any(n.startswith(positive+'/private/diagnostics/') for n in bodies)
assert not any('/parts/' in n or '/part-' in n for n in by_path)
for row in capture['files']:
    original,retained=row['original'],row['retained'];actual=by_path[small+'/originals/'+row['name']]
    assert (original['bytes'],original['sha256'])==(retained['bytes'],retained['sha256'])==(actual['bytes'],actual['sha256'])
    assert original['identity'][:2]==retained['identity'][:2] and retained['identity']==actual['identity']
    assert retained['identity'][5]==1 and stat.S_IMODE(retained['identity'][2])==0o400
    assert row['accepted_complete_original'] is True and row['partial_not_promoted'] is False
    assert retained['path']==str(ACTUAL/small/'originals'/row['name'])
inventory=[json.loads(line) for line in bodies[small+'/originals/FULL-INVENTORY.jsonl'].splitlines()]
directory=[json.loads(line) for line in bodies[small+'/originals/DIRECTORY.jsonl'].splitlines()]
assert len(inventory)==len(directory)==462 and len({r['name'] for r in inventory})==462
zip_rows=[]
with zipfile.ZipFile(io.BytesIO(bodies[positive+'/private/original/fixture.zip'])) as archive:
    for info in archive.infolist():
        raw=archive.read(info)
        zip_rows.append({'name':info.filename,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'crc32':zlib.crc32(raw)&0xffffffff})
    assert len(zip_rows)==462 and sum(r['bytes'] for r in zip_rows)==3012856
    actual_zip={r['name']:r for r in zip_rows}
    for row in index['selected']:
        raw=archive.read(row['name']);retained=bodies[small+'/originals/'+row['retained_name']]
        assert raw==retained and row['body_fully_read'] is True and row['truncated'] is False
        assert all(row[k]==actual_zip[row['name']][k] for k in ('bytes','sha256','crc32'))
for row in inventory:
    assert all(row[k]==actual_zip[row['name']][k] for k in ('bytes','sha256','crc32'))
checks=[]
for number in range(2,6):
    result=obj(fixture(number)+'/public/small/SMALL-READBACK.json')
    assert result['status']=='HOLD' and result['complete'] is False and len(result['files'])==12 and result['errors']
    assert all(r['partial_not_promoted'] is True for r in result['files'])
    for r in result['files']:
        v=by_path[fixture(number)+'/public/small/originals/'+r['name']]
        assert r['retained']['sha256']==v['sha256'] and r['retained']['bytes']==v['bytes']
    checks.append({'case':number,'status':'EXPECTED_HOLD_ALL12_RETAINED'})
assert bodies[fixture(3)+'/public/small/originals/member-00000.bin']==b'SYNTHETIC_CHANGED_ACTUAL_BYTES\n'
assert not bodies[fixture(4)+'/public/small/originals/FULL-INVENTORY.jsonl'].endswith(b'\n')
duplicate=bodies[fixture(5)+'/public/small/originals/FULL-INVENTORY.jsonl'].splitlines();assert duplicate[0]==duplicate[1]
symlinks=[r for r in rows if r['kind']=='symlink_fixture_not_followed'];assert len(symlinks)==3
hardlinks=[r for r in rows if r.get('synthetic_hardlink_failure')];assert len(hardlinks)==4
groups=collections.defaultdict(list)
for r in hardlinks:groups[tuple(r['identity'][:2])].append(r)
assert len(groups)==2 and all(len(v)==2 and len({r['sha256'] for r in v})==1 for v in groups.values())
occupied=fixture(6,'-occupied')+'/public/small/originals/member-00000.bin'
assert bodies[occupied]==b'EXISTING_TARGET_MUST_NOT_CHANGE'
interrupted=[r for r in hardlinks if r['path'].startswith(fixture(7)+'/')]
assert len(interrupted)==2 and interrupted[0]['identity'][:2]==interrupted[1]['identity'][:2]
corrupt=obj(fixture(8)+'/private/diagnostics/INDEX.json')
assert corrupt['status']=='HOLD' and corrupt['all_members_fully_read'] is False
assert corrupt['complete_selection_of_available_originals'] is False and corrupt['errors'][0]['type']=='BadZipFile'
try:
    with zipfile.ZipFile(io.BytesIO(bodies[fixture(8)+'/private/original/fixture.zip'])) as archive:
        for info in archive.infolist():archive.read(info)
except zipfile.BadZipFile:corrupt_independently_refused=True
else:raise AssertionError('damaged unselected original unexpectedly accepted')
for number in (9,11):
    result=obj(fixture(number)+'/public/small/FINAL.json')
    assert result['status']=='DIAGNOSTIC_CUSTODY_HOLD' and 'closed_echild' not in result and 'diagnostic_capture' not in result
    assert len([n for n in bodies if n.startswith(fixture(number)+'/private/diagnostics/')])==10
closed_failure=obj(fixture(10)+'/public/small/FINAL.json')
assert closed_failure['status']=='DIAGNOSTIC_CUSTODY_HOLD' and closed_failure['closed_echild'] is True
assert closed_failure['complete_local_diagnostic_readback'] is False and len(closed_failure['diagnostic_capture']['files'])==10
assert any(r['stage']=='NATURAL_GUARDIAN' for r in closed_failure['errors'])
assert bodies[fixture(10)+'/public/small/controls/guard--child.stdout.log']==b'SYNTHETIC_CLOSED_FAILURE_LOG\n'
result={'schema':'hia.root.diagnostics-source12-r2b-full-readback.v1',
 'status':'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY','canonical_request_commit':'e72669c33591bd73f5f3feb1c70425263855d34a',
 'owner_first':owner_pin,'request':request_pin,'inputs':inputs,'source_methods':12,'seconds':report['seconds'],
 'expected_loaded_executed_success_equal':True,'all_five_anomalies_loader_and_forbidden_empty':True,
 'whole_output_entries':len(rows),'regular_files':len(bodies),'full_regular_bytes':total,
 'actual_originals':rows,'positive_all462_zip_bodies_CRC_and_SHA_read':True,'selected460_exact_bodies_and3_lists_verified':True,
 'positive_selected_bytes':3012789,'missing5':capture['missing_expected'],'damaged_controls':checks,
 'symlinks_not_followed':len(symlinks),'hardlink_names_preserved':len(hardlinks),'corrupt_unselected_zip_independently_refused':corrupt_independently_refused,
 'unknown_and_foreign_guardians_not_accepted':True,'closed_nonzero_kept_HOLD_and_all_originals':True,
 'historical_artifact_recovery_executions':0,'product_or_native_executions':0,'old_R4_owner_status':'UNKNOWN_NOT_RECLASSIFIED'}
raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with (OUT/'READBACK.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'status':result['status'],'entries':len(rows),'regular_files':len(bodies),'full_bytes':total,'seconds':report['seconds'],'readback_bytes':len(raw),'readback_sha256':hashlib.sha256(raw).hexdigest()}))
