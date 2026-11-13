"""Freeze metadata-only R3 and copy already-closed R2 evidence. No execution."""
from pathlib import Path
import copy
import difflib
import hashlib
import json
import os
import stat
import time

OLD = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
NEW = Path('/home/agent/hia-v92-three-view-plan-r3-20261113-e26e')
ROOT = Path('/home/agent/hia-root-v92-three-view-r2-20261113-e26e')
ACTUAL = Path('/tmp/hia-v92-three-view-source20-r2-20261113-e26e')
NEW_ACTUAL = Path('/tmp/hia-v92-three-view-source20-r3-20261113-e26e')
NEW_PROXY = Path('/tmp/hia-v92-three-view-original-proxy-r3-20261113-e26e.private.json')
PARENT = '96fd0500e4f05ca710cf947a84aeec69bc0ff704'
REF_SHA = '89ac4f110cc6e3d5c4dc2471f3ecd801200b479bba06f0ba6c5fffd548cf8606'

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    raw = path.read_bytes()
    assert identity(before) == identity(path.lstat()) and len(raw) == before.st_size
    return raw

def save(name, value, raw=False, mode=0o600):
    path = NEW / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = value if raw else wire(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    assert read(path) == body
    return pin(body)

def changed(a, b, path=''):
    if type(a) is dict and type(b) is dict:
        assert set(a) == set(b)
        return sum((changed(a[k], b[k], path + '/' + k) for k in sorted(a)), [])
    if type(a) is list and type(b) is list:
        assert len(a) == len(b)
        return sum((changed(x,y,path+'/'+str(i)) for i,(x,y) in enumerate(zip(a,b))), [])
    return [] if type(a) is type(b) and a == b else [{'pointer':path,'before':a,'after':b}]

def observed(path):
    s = path.lstat(); fs = os.statvfs(path)
    assert stat.S_ISDIR(s.st_mode)
    return {'path':str(path),'device':s.st_dev,'identity':identity(s),
            'free_bytes':fs.f_bavail*fs.f_frsize,'free_inodes':fs.f_favail,'time_ns':time.time_ns()}

def preserve_actual(old_controls):
    # Read owner originals and establish binding/closure before traversing outputs.
    life_raw = read(ACTUAL/'lifecycle.json'); life = json.loads(life_raw)
    req_raw = read(ACTUAL/'lifecycle.json.request.json'); req = json.loads(req_raw)
    returned = json.loads(read(ACTUAL/'OWNER-RETURN.json'))
    cleanup = life['cleanup']
    assert req['command'] == old_controls['command'] and req['cwd'] == str(OLD)
    assert req['env'] == old_controls['environment']
    assert req['qualification_seconds'] == life['qualification_seconds'] == 20
    assert req['cleanup_seconds'] == life['cleanup_seconds'] == 3
    assert req['deadline_ns']-req['started_ns'] == 20*10**9
    assert req['implementation_sha256'] == life['implementation_sha256'] == old_controls['inputs']['control/process_owner_impl.py']['sha256']
    assert life['request_sha256'] == pin(req_raw)['sha256']
    assert life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
    assert life['subreaper_enabled'] is True and life['qualification_started'] is True
    assert life['timed_out'] is False and life['exit_observed_before_deadline'] is True
    assert life.get('owner_error') is None and life['interrupted_signals'] == [] and life['event_overflow'] is False
    assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
    assert cleanup['deadline_exceeded'] is False and cleanup['errors'] == [] and cleanup['remaining_direct_children'] == []
    assert returned['supervisor_returncode'] == 0 and returned['receipt_sha256'] == pin(life_raw)['sha256']
    assert {k:v for k,v in returned.items() if k not in ('supervisor_returncode','receipt_sha256')} == life
    assert not any(row['kind'] == 'owned_child_sigkill' for row in life['events'])
    final = json.loads(read(ACTUAL/'FINAL.json'))
    report_raw = read(ACTUAL/'tests/REPORT.json'); report = json.loads(report_raw)
    assert final['status'] == 'TWENTY_SOURCE_IO_PASS_ONLY' and final['closed_owner'] is True and final['natural_owner'] is True
    assert final['errors'] == [] and final['product_execution'] is False and final['receiver_executed'] is False
    assert final['lifecycle']['sha256'] == pin(life_raw)['sha256'] and final['report']['sha256'] == pin(report_raw)['sha256']
    assert final['request']['sha256'] == pin(read(OLD/'CONTROL-REQUEST.json'))['sha256']
    assert report['tests_run'] == 20
    for key in ('expected_ids','loaded_ids','actual_ids','success_ids'):
        assert report[key] == old_controls['expected_ids']
    for key in ('errors','failures','skipped','expected_failures','unexpected_successes','denied_effects'):
        assert report[key] == []
    assert report['network_bytes'] == 0 and report['private_proxy_capture_performed'] is False
    assert report['product_execution'] is False and report['receiver_executed'] is False
    assert report['inputs_before'] == report['inputs_after'] == old_controls['inputs']
    before = json.loads(read(ACTUAL/'INPUTS-BEFORE.json'))
    assert before == json.loads(read(ACTUAL/'INPUTS-AFTER.json')) and len(before) == 35
    for path, row in before.items():
        actual = pin(read(Path(path)))
        assert row['path'] == path and row['bytes'] == actual['bytes'] and row['sha256'] == actual['sha256']
        assert row['identity'] == identity(Path(path).lstat())
    root_readback = json.loads(read(ROOT/'source20-r2-invocation/READBACK.json'))
    root_rows = {row['path']:row for row in root_readback['actual_files']}
    files = sorted(p for p in ACTUAL.rglob('*') if p.is_file())
    assert len(files) == len(root_rows) == 13 and set(root_rows) == {str(p) for p in files}
    rows = []
    for path in files:
        body = read(path); actual = pin(body); old = root_rows[str(path)]
        assert actual['bytes'] == old['bytes'] and actual['sha256'] == old['sha256'] and actual['git_blob_sha1'] == old['git_blob']
        name = 'history/r2-source20/actual/' + str(path.relative_to(ACTUAL))
        save(name, body, raw=True, mode=stat.S_IMODE(path.lstat().st_mode))
        rows.append({'archive_path':name,'original_path':str(path),'identity':identity(path.lstat()),**actual})
    root_names = ['source20-r2-invocation/INTENT.json','source20-r2-invocation/RETURNED.json',
                  'source20-r2-invocation/READBACK.json','source20-r2-invocation/launcher.stdout.log',
                  'source20-r2-invocation/launcher.stderr.log','invoke_source20_r2_once.py',
                  'audit_source20_r2_actual.py','request-review/ROOT-REVIEW.json','review_request_r2.py',
                  'PRIVATE-ENVIRONMENT-PREFLIGHT-HOLD.json','provider-references-r1/READBACK.json']
    for name in root_names:
        path = ROOT/name; body = read(path)
        out = 'history/r2-root/' + name
        save(out, body, raw=True, mode=stat.S_IMODE(path.lstat().st_mode))
        rows.append({'archive_path':out,'original_path':str(path),'identity':identity(path.lstat()),**pin(body)})
    audit = {'schema':'hia.v92-r2-source20-closed-originals-independent-audit.v1',
        'status':'PASS_READBACK_OF_EXISTING_R2_SOURCE20_NOT_R3_EXECUTION','r2_request':PARENT,
        'owner_raw_binding_closed_before_child_read':True,'runtime_inputs_35_full_bytes_identity_preserved':True,
        'actual_originals':13,'actual_bytes':sum(row['bytes'] for row in rows[:13]),
        'root_originals':len(root_names),'complete_originals':rows,'expected_ids':old_controls['expected_ids'],
        'source_seconds':report['elapsed_seconds'],'qualification_elapsed_ns':root_readback['qualification_elapsed_ns'],
        'source_executions_by_this_author':0,'receiver_executions':0,'network_GETs':0,
        'old_proxy_private_body_read':False,'provider_private_bodies_read':False}
    save('R2-ACTUAL-READBACK.json',audit)
    return audit

def main():
    old_policy = json.loads(read(OLD/'POLICY.json'))
    old_controls = json.loads(read(OLD/'CONTROL-REQUEST.json'))
    assert len(old_policy['inputs']) == 34 and len(old_controls['inputs']) == 35
    assert not os.path.lexists(NEW_ACTUAL) and not os.path.lexists(NEW_PROXY)
    for volume in old_policy['volumes'].values(): assert not os.path.lexists(volume['root'])
    runtime = old_policy['runtime']; runtime_path=Path(runtime['path'])
    assert pin(read(runtime_path))['sha256'] == runtime['sha256'] and identity(runtime_path.lstat()) == runtime['identity']
    rows = []
    for name, expected in old_policy['inputs'].items():
        source = OLD/name; body=read(source); actual=pin(body)
        assert all(actual[k] == expected[k] for k in ('bytes','sha256'))
        save(name, body, raw=True, mode=stat.S_IMODE(source.lstat().st_mode))
        rows.append({'path':name,**actual,'byte_identical_to_r2':True})
    actual_audit = preserve_actual(old_controls)
    refs_receipt = json.loads(read(ROOT/'provider-references-r1/READBACK.json'))
    assert pin(read(ROOT/'provider-references-r1/READBACK.json'))['sha256'] == '1411c4b8f7fd32761cb2a631877d33b072451167d83f83ba2b1855e2cfc2b3cc'
    refs_pin = refs_receipt['private_input']
    assert refs_pin['path'] == old_policy['provider_references_path'] and refs_pin['bytes'] == 1562 and refs_pin['sha256'] == REF_SHA
    assert identity(Path(refs_pin['path']).lstat()) == refs_pin['identity']
    hold=json.loads(read(ROOT/'PRIVATE-ENVIRONMENT-PREFLIGHT-HOLD.json'))
    assert hold['actual_roots_absent'] is True and hold['receiver_invocation_count'] == hold['local_large_GETs'] == 0
    assert hold['provider_reference_requests'] == 3 and hold['private_file_overwritten_or_recaptured'] is False
    policy = copy.deepcopy(old_policy)
    policy['mandatory_source_controls']['actual_root'] = str(NEW_ACTUAL)
    policy['proxy_configuration_path'] = str(NEW_PROXY)
    policy['parts'][2]['volume'] = 'workspace'
    moved = policy['parts'][2]['artifact']['bytes']; assert moved == 119894487
    policy['volumes']['tmp']['limits']['container'] -= moved
    policy['volumes']['workspace']['limits']['container'] += moved
    delta = changed(old_policy,policy)
    allowed = ['/mandatory_source_controls/actual_root','/parts/2/volume','/proxy_configuration_path',
               '/volumes/tmp/limits/container','/volumes/workspace/limits/container']
    assert [row['pointer'] for row in delta] == allowed
    assert sum(v['limits']['container'] for v in policy['volumes'].values()) == 657570577
    for key, volume in policy['volumes'].items():
        assert volume['limits']['container'] == sum(item['artifact']['bytes'] for item in policy['parts'] if item['volume']==key)
        assert volume['limits']['reserve'] == 536870912 and volume['limits']['inodes'] == 4096
    policy_pin=save('POLICY.json',policy)
    controls=copy.deepcopy(old_controls)
    controls['command'][-1]=str(NEW/'controls/run_controls.py')
    controls['operation_root']=str(NEW_ACTUAL);controls['output']=str(NEW_ACTUAL/'tests')
    controls['inputs']['POLICY.json']={k:policy_pin[k] for k in ('bytes','sha256')}
    controls['scope']=('The same20 synthetic tiny-file controls under a new R3 metadata binding, including the new proxy input path '
        'and part02 home-volume allocation. All20 must execute under the original20/3 owner in separate r3 output. '
        'R1/R2 actual source PASS and R2 environment preflight HOLD remain historical, not adopted. '
        'No receiver, network, private capture or product execution. FROZEN_UNEXECUTED.')
    control_pin=save('CONTROL-REQUEST.json',controls)
    control_launch=json.loads(read(OLD/'CONTROL-LAUNCH.json'))
    control_launch['command'][-1]=str(NEW/'controls/launch_controls.py');control_launch['cwd']=str(NEW);control_launch['request']=control_pin
    source_launch_pin=save('CONTROL-LAUNCH.json',control_launch)
    request=json.loads(read(OLD/'REQUEST.json'))
    request['policy']=policy_pin;request['source20_request']=control_pin
    request['parts']=copy.deepcopy(policy['parts']);request['volumes']=copy.deepcopy(policy['volumes'])
    request['private_input_shapes']['proxy']=('After R3 source20 is accepted, Root creates one new mode0600 private proxy input at '
        + str(NEW_PROXY) + ' from the actual inherited environment, preserving the old r1 capture. Capture and unique receiver invocation '
        'are performed continuously within the same inheriting Root process. The unchanged full fresh equality remains mandatory. '
        'The existing three provider references at '+policy['provider_references_path']+' (1562 bytes/SHA256 '+REF_SHA+') must be reused; '
        'no provider reference is acquired again. Opaque private seals only; no secret body or URL enters public evidence.')
    request_pin=save('REQUEST.json',request)
    launch=json.loads(read(OLD/'LAUNCH.json'))
    launch['argv_prefix'][-1]=str(NEW/'control/launch.py');launch['cwd']=str(NEW);launch['request']=request_pin
    launch_pin=save('LAUNCH.json',launch)
    observations={k:observed(Path(v['parent'])) for k,v in policy['volumes'].items()}
    capacity=json.loads(read(OLD/'CAPACITY-PROOF.json'))
    for k,v in capacity['volumes'].items():
        limits=policy['volumes'][k]['limits'];observation=observations[k]
        v['container_bytes']=limits['container']
        v['persistent_total_maximum']=sum(limits[n] for n in ('container','selected','metadata','parent'))
        v['minimum_start_free_bytes']=v['persistent_total_maximum']+limits['reserve']
        v['observed_authoring_free_bytes']=observation['free_bytes'];v['observed_authoring_free_inodes']=observation['free_inodes']
        assert observation['device']==v['device']==policy['volumes'][k]['parent_device']
    assert capacity['volumes']['tmp']['minimum_start_free_bytes']==956703893
    assert capacity['volumes']['workspace']['minimum_start_free_bytes']==1009489532
    capacity_pin=save('CAPACITY-PROOF.json',capacity)
    save('VOLUME-OBSERVATIONS.json',{'schema':'hia.v92-r3-volume-observations.v1','observations':observations,
        'observation_is_not_runtime_capacity_admission':True,'no_actual_roots_created':True,
        'private_bodies_read':False,'private_capture_executed':False})
    # Complete unchanged-runtime and exact metadata inverses; no imported project/control code.
    inverse=copy.deepcopy(policy)
    for row in delta:
        parts=row['pointer'].split('/')[1:];current=inverse
        for name in parts[:-1]:current=current[int(name)] if type(current) is list else current[name]
        current[int(parts[-1]) if type(current) is list else parts[-1]]=row['before']
    assert wire(inverse)==read(OLD/'POLICY.json')
    for name,expected in controls['inputs'].items():
        actual=pin(read(NEW/name));assert all(actual[k]==expected[k] for k in ('bytes','sha256'))
    for row in rows:assert read(NEW/row['path'])==read(OLD/row['path'])
    assert controls['expected_ids']==old_controls['expected_ids'] and controls['qualification_seconds']==20 and controls['cleanup_seconds']==3
    assert policy['limits']=={'cleanup_seconds':3,'complete_seconds':720,'owner_seconds':900}
    assert policy['selection']==old_policy['selection'] and policy['diagnostics']==old_policy['diagnostics']
    mechanical={'schema':'hia.v92-r3-five-leaf-metadata-mechanical-proof.v1','status':'STATIC_MECHANICAL_PASS_ONLY',
        'parent':PARENT,'policy_exact_changes':delta,'all34_runtime_inputs_byte_identical':rows,'algorithm_files_unchanged':13,
        'source20_ids':controls['expected_ids'],'source20_input_count':35,'source20_execution_count':0,
        'owner_limits_unchanged':policy['limits'],'network_implementation_unchanged':True,
        'fresh_proxy_equality_unchanged':True,'provider_reference_acquisitions_by_this_author':0,
        'existing_provider_references_reused':refs_pin,'private_bodies_read':False,'new_proxy_captured':False,
        'part02_container_bytes_moved':moved,'total_container_bytes_unchanged':657570577,
        'all_other_volume_limits_unchanged':True,'two_actual_output_roots_unchanged_and_absent':True,
        'code_selection_basis':[
          {'path':'control/operation.py','functions':['volume_roots','part_directory','read_containers','observed_outputs'],
           'mechanism':'part_directory uses item.volume; parent observation/readback traverses both roots and charges actual category.'},
          {'path':'control/worker.py','mechanism':'Per-part DownloadBudget uses budgets[item.volume].'},
          {'path':'control/view_format.py','mechanism':'StoredView consumes held-fd offsets/lengths in ordinal order, independent of volume name.'},
          {'path':'control/common.py','mechanism':'VolumeBudget retains reserve plus all unwritten fixed future quotas; no transfer or fallback at runtime.'}],
        'receiver_executed':False,'local_large_GETs':0}
    save('MECHANICAL-R3.json',mechanical)
    names=['POLICY.json','CONTROL-REQUEST.json','CONTROL-LAUNCH.json','REQUEST.json','LAUNCH.json','CAPACITY-PROOF.json']
    diff=''.join(''.join(difflib.unified_diff(read(OLD/n).decode().splitlines(True),read(NEW/n).decode().splitlines(True),
                      fromfile='r2/'+n,tofile='r3/'+n)) for n in names)
    diff_pin=save('REVISION-R3.diff',diff.encode(),raw=True)
    handoff={'schema':'hia.v92-three-container-r3-handoff.v1','status':'FROZEN_UNEXECUTED_REQUIRES_R3_SOURCE20',
        'root':str(NEW),'proposed_sole_parent':PARENT,'policy':policy_pin,'request':request_pin,'source20_request':control_pin,
        'source20_launch':source_launch_pin,'consumer_launch':launch_pin,'capacity_proof':capacity_pin,'diff':diff_pin,
        'all34_runtime_inputs_identical':True,'all13_algorithm_files_identical':True,'policy_exact_changes':delta,
        'original_CI_and_recovery_failures_preserved':True,'old_r2_source20_actual_readback':{'files':13,
          'bytes':actual_audit['actual_bytes'],'source_seconds':actual_audit['source_seconds'],'source_control_runs_by_author':0},
        'original_R2_equality_hold_preserved':True,'old_private_capture_never_overwritten':True,
        'existing_three_private_provider_references':refs_pin,'provider_refs_to_acquire':0,
        'new_proxy_path':str(NEW_PROXY),'new_source20_actual_root':str(NEW_ACTUAL),
        'receiver_actual_roots_unchanged':{k:v['root'] for k,v in policy['volumes'].items()},
        'volumes':capacity['volumes'],'receiver_limits':policy['limits'],
        'required_order':['Root reviews canonical exact R3 metadata-only delta and preserved R2 actual/HOLD',
          'Root uniquely executes the same20 source controls with R3 request/output under20/3; full actual gate required',
          'Root reuses the already-captured exact3 private provider references; zero new reference requests',
          'Within one inheriting Root process, create the new fixed proxy file once and retain the old r1 file',
          'Run unchanged fresh complete equality, runtime/source/actual gate, two-volume future-capacity+512MiB/inode checks',
          'Root invokes unchanged receiver once using the existing refs SHA and newly captured opaque proxy SHA',
          'Keep original900/3 owner and start+720 deadline through parent full readback; retain all original containers/partial bytes'],
        'no_execution_or_download_performed_by_author':True,'no_new_ref_or_workflow':True}
    save('HANDOFF.json',handoff)
    files=[{'path':str(p.relative_to(NEW)),**pin(read(p))} for p in sorted(NEW.rglob('*')) if p.is_file()]
    save('FROZEN-FILES.json',{'schema':'hia.v92-r3-frozen-files.v1','files':files,'frozen':True,
         'runtime_controls_invoked':False,'private_bodies_read':False,'provider_refs_acquired':0,'GETs':0})
    print(json.dumps({'root':str(NEW),'policy':policy_pin,'request':request_pin,'source20_request':control_pin,
                     'source20_launch':source_launch_pin,'capacity':capacity['volumes'],'files_before_manifest':len(files)}))

if __name__ == '__main__':
    main()
