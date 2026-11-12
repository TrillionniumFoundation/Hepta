"""Read-only audit of the one synthetic permission-controller operation."""
from pathlib import Path
import hashlib
import json
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ACTUAL = ROOT / 'actual-permission-controls-r1'

def digest(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def original(path):
    before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    raw=path.read_bytes(); after=path.lstat()
    assert before == after
    row={'path':str(path),'device':before.st_dev,'inode':before.st_ino,
         'mode':stat.S_IMODE(before.st_mode),'uid':before.st_uid,'gid':before.st_gid,
         'nlink':before.st_nlink,'size':before.st_size,'mtime_ns':before.st_mtime_ns,
         'ctime_ns':before.st_ctime_ns,**digest(raw)}
    return raw,row

def main():
    policy=json.loads((ROOT/'PERMISSION-CONTROLS-REQUEST.json').read_bytes())
    raw,final_pin=original(ACTUAL/'FINAL.json'); final=json.loads(raw)
    assert final['status']=='SYNTHETIC_PERMISSION_CONTROLS_PASS'
    assert final['closed_owner_confirmed'] is True and final['child_originals_read'] is True
    assert all(final[k] is False for k in ('source83_executed','generator_executed','native_executed','real_negative_commands_executed'))
    rows=[]
    for expected in final['actual_originals']:
        body,observed=original(Path(expected['path'])); assert observed == expected
        rows.append({'relative_path':Path(expected['path']).relative_to(ACTUAL).as_posix(),**observed})
    actual_paths={p for p in ACTUAL.rglob('*') if p.is_file()}
    assert actual_paths == {Path(x['path']) for x in final['actual_originals']}|{ACTUAL/'FINAL.json'}
    life_raw,life_pin=original(ACTUAL/'lifecycle.json'); life=json.loads(life_raw)
    request_raw,request_pin=original(ACTUAL/'lifecycle.json.request.json'); request=json.loads(request_raw)
    wrapper=json.loads((ACTUAL/'wrapper.json').read_bytes())
    assert wrapper['receipt_sha256'] == hashlib.sha256(life_raw).hexdigest()
    assert {k:v for k,v in wrapper.items() if k not in ('receipt_sha256','supervisor_returncode')} == life
    assert wrapper['supervisor_returncode']==0 and life['returncode']==0
    assert life['request_sha256']==hashlib.sha256(request_raw).hexdigest()
    assert request['command']==policy['command'] and request['cwd']==str(ROOT)
    assert request['qualification_seconds']==life['qualification_seconds']==20
    assert request['cleanup_seconds']==life['cleanup_seconds']==3
    assert request['deadline_ns']-request['started_ns']==20_000_000_000
    assert request['implementation_sha256']==life['implementation_sha256']==policy['process_owner']['sha256']
    assert life['status']=='OWNED_PROCESS_COMPLETED' and life['timed_out'] is False
    assert life['exit_observed_before_deadline'] is True and life.get('owner_error') is None
    assert life['interrupted_signals']==[] and life['event_overflow'] is False
    cleanup=life['cleanup']
    assert all(cleanup[k] is True for k in ('attempted','complete','observed_echild','leader_reaped'))
    assert cleanup['deadline_exceeded'] is False and cleanup['remaining_direct_children']==cleanup['errors']==[]
    kinds=[r['kind'] for r in life['events']]
    assert kinds==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped']
    report=json.loads((ACTUAL/'evidence/report.json').read_bytes())
    assert report['status']=='SYNTHETIC_CONTROLLER_CONTROLS_PASS'
    assert report['expected_ids']==report['loaded_ids']==report['executed_ids']==policy['expected_ids']
    assert report['tests_run']==len(report['executed_ids'])==4
    for name in ('errors','failures','expectedFailures','unexpectedSuccesses','skipped','loader_errors','real_subprocess_attempts','project_modules_loaded'):
        assert report[name]==[],name
    for expected in policy['input_pins']:
        _,observed=original(Path(expected['path']));assert observed==expected
    rows.append({'relative_path':'FINAL.json',**final_pin})
    output={'schema':'hepta.source83-r3-synthetic-permission-independent-readback.v1',
            'status':'ACTUAL_FOUR_SYNTHETIC_CONTROLS_AND_CUSTODY_PASS',
            'source_control_commit':'df4e7e5168877130e5e2b139c0d227b0d8ebff0a',
            'source_control_tree':'271e592cd18a807dc64032e04bf8d5b71e1c8221',
            'original_files':rows,'original_count':len(rows),'original_bytes':sum(x['size'] for x in rows),
            'input_pins_unchanged':len(policy['input_pins']),'expected_ids':policy['expected_ids'],
            'qualification_seconds':20,'cleanup_seconds':3,'event_kinds':kinds,
            'seconds_until_exit_observed':(life['events'][2]['monotonic_ns']-life['events'][0]['monotonic_ns'])/1e9,
            'observed_echild':True,'real_negative_project_processes':0,
            'source83_executed':False,'generators_executed':False,'native_executed':False,
            'scope':'CPython 3.12.14 synthetic permission-controller checks only; no remote/source83 result inherited.'}
    target=HERE/'AUDIT.json'
    with target.open('x') as f:json.dump(output,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({k:output[k] for k in ('status','original_count','original_bytes','input_pins_unchanged','seconds_until_exit_observed')}))

if __name__=='__main__':main()
