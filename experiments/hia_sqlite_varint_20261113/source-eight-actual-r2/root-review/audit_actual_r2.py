"""Read original source8 r2 owner first, then all originals and VM buffers."""
from pathlib import Path
import hashlib
import json
import os
import stat

REVIEW = Path(__file__).resolve().parent
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/sqlite-varint-source8-r2-invocation')
PLAN = Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e')
ACTUAL = Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e')

def read(path):
    path = Path(path)
    identity = lambda s: [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not path.is_symlink(), str(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        assert identity(os.fstat(f.fileno())) == identity(before)
        raw = f.read()
        assert identity(os.fstat(f.fileno())) == identity(before)
    assert identity(path.lstat()) == identity(before)
    pin = {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
           'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'identity':identity(before)}
    return pin, raw

def save(name, value):
    raw = (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with (OUT/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return {'path':str(OUT/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

request_pin, request_raw = read(PLAN/'REQUEST.json')
assert request_pin['sha256']=='7edf8b146dec5aa0acdfe75fa3dbd69aaae4916436de40736c237d2817fffcb7'
request=json.loads(request_raw)
parent={}
for name in ('OWNER-RETURN.json','lifecycle.json','lifecycle.json.request.json'):
    pin,raw=read(ACTUAL/name);parent[name]={'pin':pin,'value':json.loads(raw)}
returned=parent['OWNER-RETURN.json']['value'];life=parent['lifecycle.json']['value'];owner=parent['lifecycle.json.request.json']['value']
projected=dict(returned);supervisor=projected.pop('supervisor_returncode');receipt=projected.pop('receipt_sha256')
assert projected==life and supervisor==0 and receipt==parent['lifecycle.json']['pin']['sha256']
assert life['implementation_sha256']==owner['implementation_sha256']==request['inputs']['control/process_owner_impl.py']['sha256']
assert life['request_sha256']==parent['lifecycle.json.request.json']['pin']['sha256']
assert owner['command']==request['command'] and owner['cwd']==str(PLAN) and owner['env']==request['environment']
assert owner['receipt_path']==str(ACTUAL/'lifecycle.json') and owner['stdout_path']==str(ACTUAL/'stdout.log') and owner['stderr_path']==str(ACTUAL/'stderr.log')
assert life['qualification_seconds']==owner['qualification_seconds']==180 and life['cleanup_seconds']==owner['cleanup_seconds']==3
assert owner['deadline_ns']-owner['started_ns']==180000000000
cleanup=life['cleanup']
assert life['subreaper_enabled'] is True and life['event_overflow'] is False
assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
assert cleanup['remaining_direct_children']==[] and cleanup['errors']==[] and cleanup['deadline_exceeded'] is False
assert life['status']=='OWNED_PROCESS_COMPLETED' and life['returncode']==0 and life['timed_out'] is False
assert life['exit_observed_before_deadline'] is True and life.get('owner_error') is None and life['interrupted_signals']==[]
assert [e['kind'] for e in life['events']]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped']
assert all(e['pid']==life['qualification_pid'] for e in life['events'])
owner_pin=save('OWNER-FIRST-READBACK-r2.json',{'status':'ORIGINAL_BOUND180_3_NATURAL_ZERO_ECHILD','parent_originals':parent,'child_outputs_read':False,'reader_r1_optional_field_error_preserved':True})

# Only after the complete owner join above: enumerate and read all child bodies.
files={};raws={}
for p in sorted(ACTUAL.rglob('*')):
    info=p.lstat();assert not stat.S_ISLNK(info.st_mode)
    if stat.S_ISDIR(info.st_mode):continue
    pin,raw=read(p);assert len(raw)<=16<<20
    files[str(p.relative_to(ACTUAL))]=pin;raws[str(p.relative_to(ACTUAL))]=raw
assert len(files)<=64 and sum(x['bytes'] for x in files.values())<=16<<20
assert raws['REQUEST.original.json']==request_raw
final=json.loads(raws['FINAL.json']);report=json.loads(raws['tests/REPORT.json'])
assert final['status']==report['status']=='SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY'
assert final['closed_owner'] is True and final['natural_owner'] is True and final['source_eight_pass'] is True and final['complete_output_custody'] is True and final['errors']==[]
assert final['request']==report['request']==request_pin
assert report['expected_ids']==report['loaded_ids']==report['actual_ids']==report['success_ids']==request['expected_ids']
assert report['tests_run']==8 and report['exception'] is None
for key in ('failures','errors','skipped','expected_failures','unexpected_successes','denied_effects','secondary_errors'):
    assert report[key]==[]
for key in ('native_executed','native_compiler_executed','C_oracle_compiled','network_used','database_opened','product_qualification_executed'):
    assert final[key] is False and report[key] is False
assert final['old_source8_request_replayed'] is False and report['old_source8_request_replayed'] is False
assert report['local_development_runtime']==[3,12,14]
runtime,_=read(Path(request['runtime']['path']));assert runtime==request['runtime']==report['runtime']
before=json.loads(raws['INPUTS-BEFORE.json']);after=json.loads(raws['INPUTS-AFTER.json'])
assert before==after==report['inputs_before']==report['inputs_after']
assert len(before)==46
for name,expected in before.items():
    pin,_=read(PLAN/name);assert pin==expected
source=json.loads(raws['SOURCE-BEFORE.json'])
assert source==json.loads(raws['SOURCE-AFTER.json'])==json.loads(raws['tests/SOURCE-BEFORE.json'])==json.loads(raws['tests/SOURCE-AFTER.json'])==json.loads((REVIEW/'ROOT-SOURCE-BEFORE.json').read_bytes())
assert len(source)==1686 and sum(x['bytes'] for x in source.values())==40890650
for name,expected in source.items():
    pin,_=read(PLAN/'source-base'/name);assert pin==expected
assert report['source_before']==files['tests/SOURCE-BEFORE.json'] and report['source_after']==files['tests/SOURCE-AFTER.json']
catalog=json.loads(raws['ORIGINAL-CATALOG.json'])
for pin in catalog['records']:
    rel=str(Path(pin['path']).relative_to(ACTUAL));assert files[rel]==pin
assert catalog['regular_bytes']==sum(x['bytes'] for x in catalog['records'])

vm=json.loads(raws['tests/VM-RAW.json']);assert vm['schema']=='hia.sqlite-varint.source-vm-raw.v1'
assert vm['native_executed'] is False and vm['compiler_executed'] is False and len(vm['calls'])==1618
counts={k:0 for k in request['expected_ids']};sequence=[]
def expected_result(s,o,w):
    if len(w)!=16 or int.from_bytes(w[:8],'little')!=int.from_bytes(b'HIASVR01','little'):
        return 0xfffffffd,o
    op=int.from_bytes(w[8:],'little')
    if op==1:
        if len(s)>9 or len(o)!=8:return 0xfffffffd,o
        count=next((i+1 for i,x in enumerate(s[:8]) if x<128),None)
        if count is None:
            if len(s)<9:return 0xfffffffe,o
            value=sum((s[i]%128)*(128**(7-i))*256 for i in range(8))+s[8];count=9
        else:value=sum((s[i]%128)*(128**(count-1-i)) for i in range(count))
        return count,value.to_bytes(8,'little')
    if op==2:
        if len(s)!=8 or len(o)>9:return 0xfffffffd,o
        value=int.from_bytes(s,'little')
        if value>=256**7:
            head,last=divmod(value,256);digits=[]
            for _ in range(8):head,digit=divmod(head,128);digits.append(digit+128)
            encoded=bytes(reversed(digits))+bytes([last])
        else:
            digits=[]
            while True:
                value,digit=divmod(value,128);digits.append(digit)
                if not value:break
            encoded=bytes(x+(128 if i else 0) for i,x in reversed(list(enumerate(digits))))
        if len(o)<len(encoded):return 0xfffffffc,o
        return len(encoded),encoded+o[len(encoded):]
    return 0xfffffffd,o
for row in vm['calls']:
    assert row['actual_returned'] is True and row['case'] in counts and type(row['status']) is int
    bs={key:bytes.fromhex(value) for key,value in row.items() if key.endswith('_hex')}
    assert all(bs[key].hex()==row[key] for key in bs)
    assert bs['source_before_hex']==bs['source_after_hex'] and bs['workspace_before_hex']==bs['workspace_after_hex']
    expected=expected_result(bs['source_before_hex'],bs['output_before_hex'],bs['workspace_before_hex'])
    assert (row['status'],bs['output_after_hex'])==expected,(row['case'],row['status'])
    counts[row['case']]+=1;sequence.append(row['case'])
assert counts==request['expected_vm_by_id']
assert sequence==[key for key in request['expected_ids'] for _ in range(counts[key])]
assert final['vm']==report['vm'] and report['vm']['pin']==files['tests/VM-RAW.json'] and report['vm']['by_id']==counts and report['vm']['actual_return_count']==1618
assert final['core']==report['core'] and report['core']['assembly']==files['tests/sqlite_varint.hiaasm'] and report['core']['core']==files['tests/CORE.json']
core=json.loads(raws['tests/CORE.json']);functions=core['functions'];blocks=[b for f in functions for b in f['blocks']]
assert len(functions)==6 and len(blocks)==report['core']['blocks'] and sum(len(b['ops']) for b in blocks)==report['core']['operations']
assert len(raws['tests/sqlite_varint.hiaasm'])<=1048576 and len(raws['tests/sqlite_varint.hiaasm'].decode().split('\n'))==report['core']['lines']<=16384
imports=set()
for item in report['imports']:
    assert item['module'] not in imports;imports.add(item['module'])
    if item.get('namespace_only') is True:assert item=={'module':'tools','namespace_only':True}
    else:
        actual,_=read(item['source']['path']);assert actual==item['source'] and actual in list(source.values())+list(before.values())
assert request['test_module'] in imports
wrapper=json.loads((OUT/'RETURN.json').read_bytes());assert wrapper['wrapper_returncode']==0
readback={'schema':'hia.root.sqlite-source8-r2-complete-actual-readback.v1',
 'status':'ALL8_SOURCE_VM_METHODS_AND1618_COMPLETE_RETURNS_VERIFIED',
 'canonical_request_commit':'045f1ae1e88f9be6680f618bf220857c42a4cbbb',
 'request_sha256':request_pin['sha256'],'owner_first':owner_pin,
 'original_owner_seconds':180,'cleanup_seconds':3,'natural_zero_ECHILD':True,
 'tests_expected_loaded_actual_success':8,'all_five_anomalies_zero':True,
 'all1618_return_values_and_complete_buffers_independently_recomputed':True,
 'actual_VM_by_ID':counts,'source_worker_elapsed_seconds':report['elapsed_seconds'],
 'wrapper_elapsed_ns':wrapper['elapsed_ns'],'source_files_full_read':1686,'source_bytes':40890650,
 'request_inputs_full_read':46,'actual_original_files_full_read':len(files),
 'actual_original_bytes_full_read':sum(x['bytes'] for x in files.values()),'actual_files':files,
 'core_counts':{k:report['core'][k] for k in ('lines','functions','blocks','operations','maximum_ssa_index')},
 'native_or_C_or_database_or_full_product_executed':False,
 'old_R4_status':'UNKNOWN_NOT_RECLASSIFIED','old_source8_executions':0,
 'root_reader_r1_error_preserved':'ROOT-OWNER-READER-R1-HOLD.original.json',
 'product_replay':False,'legacy_removed':False}
pin=save('READBACK.json',readback)
print(json.dumps({k:readback[k] for k in ('status','source_worker_elapsed_seconds','wrapper_elapsed_ns','actual_original_files_full_read','actual_original_bytes_full_read','core_counts')}))
print(json.dumps({'readback':pin}))
