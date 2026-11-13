"""Author a separate storage-only r2 request; never invoke frozen controls."""
from pathlib import Path
import copy
import difflib
import hashlib
import json
import os
import stat
import time

OLD = Path('/workspace/scratch/e26ed3e2edcf/v92-three-part-view-plan-r1-20261113-e26e')
NEW = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
SOURCE_ACTUAL = Path('/tmp/hia-v92-three-view-source20-r2-20261113-e26e')
HOME_PARENT = Path('/home/agent')
HOME_OUTPUT = HOME_PARENT / 'hia-v92-three-view-r2-20261113-e26e'
OLD_ACTUAL_COMMIT = '503f3ef7c75ca71b6be06ff6dbbbeafc9de3d703'


def wire(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    raw = path.read_bytes()
    after = path.lstat()
    for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
        assert getattr(before,k) == getattr(after,k)
    assert len(raw) == before.st_size
    return raw


def save(name, value, *, raw=False, mode=0o600):
    path = NEW / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = value if raw else wire(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    assert read(path) == body
    return pin(body)


def observed(path):
    before = path.lstat(); fs = os.statvfs(path)
    assert stat.S_ISDIR(before.st_mode)
    return {'path': str(path), 'dev': before.st_dev, 'ino': before.st_ino,
            'mode': before.st_mode, 'uid': before.st_uid, 'gid': before.st_gid,
            'free_bytes': fs.f_bavail * fs.f_frsize, 'free_inodes': fs.f_favail,
            'observation_time_ns': time.time_ns()}


def main():
    old_policy = json.loads(read(OLD / 'POLICY.json'))
    assert len(old_policy['inputs']) == 34
    assert not os.path.lexists(HOME_OUTPUT) and not os.path.lexists(SOURCE_ACTUAL)
    assert not os.path.lexists(old_policy['operation_root'])
    assert not os.path.lexists(old_policy['provider_references_path'])
    old_actual_root = Path(old_policy['volumes']['workspace']['root'])
    assert not os.path.lexists(old_actual_root)
    runtime = old_policy['runtime']
    assert pin(read(Path(runtime['path'])))['sha256'] == runtime['sha256']
    s = Path(runtime['path']).lstat()
    assert [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns] == runtime['identity']
    implementation_rows = []
    for name, expected in old_policy['inputs'].items():
        source = OLD / name; body = read(source); actual = pin(body)
        assert all(actual[k] == expected[k] for k in ('bytes','sha256'))
        save(name, body, raw=True, mode=stat.S_IMODE(source.lstat().st_mode))
        implementation_rows.append({'path': name, **actual, 'byte_identical_to_r1': True})
    home = observed(HOME_PARENT); tmp = observed(Path('/tmp'))
    assert home['dev'] == 41 and tmp['dev'] == 39 and home['dev'] != tmp['dev']
    policy = copy.deepcopy(old_policy)
    policy['volumes']['workspace']['parent'] = str(HOME_PARENT)
    policy['volumes']['workspace']['root'] = str(HOME_OUTPUT)
    policy['volumes']['workspace']['parent_device'] = home['dev']
    policy['mandatory_source_controls']['actual_root'] = str(SOURCE_ACTUAL)
    # The logical volume key remains workspace. Only its physical backing moves.
    assert policy['operation_root'] == old_policy['operation_root']
    assert policy['provider_references_path'] == old_policy['provider_references_path']
    assert policy['proxy_configuration_path'] == old_policy['proxy_configuration_path']
    policy_pin = save('POLICY.json', policy)

    controls = json.loads(read(OLD / 'CONTROL-REQUEST.json'))
    controls['command'][-1] = str(NEW / 'controls/run_controls.py')
    controls['operation_root'] = str(SOURCE_ACTUAL)
    controls['output'] = str(SOURCE_ACTUAL / 'tests')
    controls['inputs']['POLICY.json'] = {k: policy_pin[k] for k in ('bytes','sha256')}
    controls['scope'] = ('The same20 synthetic tiny-file boundary controls under a new physical storage binding. '
        'All20 must execute under the original20/3 owner in the separate r2 output; r1 actualPASS is retained, not adopted. '
        'No receiver, network, private capture or product execution. FROZEN_UNEXECUTED.')
    assert len(controls['inputs']) == 35
    control_pin = save('CONTROL-REQUEST.json', controls)
    control_launch = json.loads(read(OLD / 'CONTROL-LAUNCH.json'))
    control_launch['command'][-1] = str(NEW / 'controls/launch_controls.py')
    control_launch['cwd'] = str(NEW)
    control_launch['request'] = control_pin
    control_launch_pin = save('CONTROL-LAUNCH.json', control_launch)

    capture_path = ROOT / 'v92-three-view-private-proxy-r1/READBACK.json'
    capture_raw = read(capture_path); capture = json.loads(capture_raw)
    captured = capture['private_input']
    assert captured['path'] == policy['proxy_configuration_path'] and captured['bytes'] == 3426
    assert captured['sha256'] == '99844e0230469a6e614f6e1e3d35be0b0b0bab87109044053785266d9770eaaf'
    s = Path(captured['path']).lstat()
    assert [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns] == captured['identity']
    assert s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1
    # Only the already public opaque receipt and current lstat were read.
    # No proxy value, signed URL, actual proxy body or provider ref is opened.
    capture_pin = save('ROOT-EXISTING-PRIVATE-CAPTURE-RECEIPT.json', capture_raw, raw=True)

    request = json.loads(read(OLD / 'REQUEST.json'))
    request['policy'] = policy_pin
    request['source20_request'] = control_pin
    request['volumes'] = copy.deepcopy(policy['volumes'])
    request['private_input_shapes']['proxy'] = ('Reuse the exact existing Root r1 private proxy file, opaque receipt '
        '3426B/99844e0230469a6e614f6e1e3d35be0b0b0bab87109044053785266d9770eaaf, '
        'because operation_root and private paths remain unchanged. No recapture. The unchanged launcher '
        'must still seal it, bind its whole identity, and compare it with the actual inherited configuration.')
    request_pin = save('REQUEST.json', request)
    launch = json.loads(read(OLD / 'LAUNCH.json'))
    launch['argv_prefix'][-1] = str(NEW / 'control/launch.py')
    launch['cwd'] = str(NEW)
    launch['request'] = request_pin
    launch_pin = save('LAUNCH.json', launch)

    capacity = json.loads(read(OLD / 'CAPACITY-PROOF.json'))
    capacity['volumes']['workspace']['parent'] = str(HOME_PARENT)
    capacity['volumes']['workspace']['device'] = home['dev']
    observations = {'tmp': observed(Path('/tmp')), 'workspace': observed(HOME_PARENT)}
    for key, observation in observations.items():
        v = capacity['volumes'][key]
        v['observed_authoring_free_bytes'] = observation['free_bytes']
        v['observed_authoring_free_inodes'] = observation['free_inodes']
        limits = policy['volumes'][key]['limits']
        required = sum(value for name,value in limits.items() if name != 'inodes')
        assert v['minimum_start_free_bytes'] == required
    capacity_pin = save('CAPACITY-PROOF.json', capacity)
    save('VOLUME-OBSERVATIONS.json', {'schema':'hia.v92-r2-volume-readonly-observations.v1',
        'observations':observations,'existing_home_parent_no_creation_needed':True,
        'home_actual_root_absent':not os.path.lexists(HOME_OUTPUT),
        'private_proxy_body_read':False,'public_private_capture_receipt':capture_pin,
        'capacity_observation_is_not_launch_admission':True})

    # Mechanical inverse: exactly these four policy leaves, no hidden algorithm
    # or limit modification. All34 input bodies remain exactly the old bytes.
    inverse = copy.deepcopy(policy)
    inverse['volumes']['workspace'] = copy.deepcopy(old_policy['volumes']['workspace'])
    inverse['mandatory_source_controls']['actual_root'] = old_policy['mandatory_source_controls']['actual_root']
    assert wire(inverse) == read(OLD / 'POLICY.json')
    assert policy['limits'] == {'cleanup_seconds':3,'complete_seconds':720,'owner_seconds':900}
    assert request['limits'] == old_policy['limits']
    assert controls['expected_ids'] == json.loads(read(OLD/'CONTROL-REQUEST.json'))['expected_ids']
    assert controls['qualification_seconds'] == 20 and controls['cleanup_seconds'] == 3
    assert request['parts'] == old_policy['parts'] == policy['parts']
    assert policy['selection'] == old_policy['selection'] and policy['diagnostics'] == old_policy['diagnostics']
    for key in old_policy['volumes']:
        assert policy['volumes'][key]['limits'] == old_policy['volumes'][key]['limits']
    for row in implementation_rows:
        assert read(NEW / row['path']) == read(OLD / row['path'])
    for name, expected in controls['inputs'].items():
        actual=pin(read(NEW/name));assert all(actual[k]==expected[k] for k in ('bytes','sha256'))
    mechanism = {'schema':'hia.v92-r2-metadata-only-mechanical-proof.v1','status':'STATIC_MECHANICAL_PASS_NOT_SOURCE20_EXECUTION',
        'r1_request':'81325ef09af975bce51912b9173a369070da340d','r1_source20_actual':OLD_ACTUAL_COMMIT,
        'policy_exact_changed_leaves':['volumes.workspace.parent','volumes.workspace.root','volumes.workspace.parent_device','mandatory_source_controls.actual_root'],
        'all34_runtime_inputs_byte_identical':implementation_rows,'algorithm_files_unchanged':13,
        'source20_ids_unchanged':controls['expected_ids'],'source20_input_count':35,
        'receiver_limits_unchanged':policy['limits'],'part_membership_order_sha_size_and_mapping_unchanged':True,
        'all_two_volume_quotas_and_512MiB_reserves_unchanged':True,'original_proxy_operation_root_unchanged':True,
        'source20_required_before_receiver':True,'r2_source20_runs':0,'r2_receiver_runs':0,'provider_refs_or_GETs':0}
    save('MECHANICAL-R2.json',mechanism)
    changed=['POLICY.json','CONTROL-REQUEST.json','CONTROL-LAUNCH.json','REQUEST.json','LAUNCH.json','CAPACITY-PROOF.json']
    diff=''.join(''.join(difflib.unified_diff(read(OLD/n).decode().splitlines(True),read(NEW/n).decode().splitlines(True),fromfile='r1/'+n,tofile='r2/'+n)) for n in changed)
    save('REVISION-R2.diff',diff.encode(),raw=True)
    handoff={'schema':'hia.v92-three-container-r2-storage-only-handoff.v1','status':'FROZEN_UNEXECUTED_REQUIRES_FRESH_SOURCE20',
        'root':str(NEW),'proposed_sole_parent':OLD_ACTUAL_COMMIT,'old_request_and_source20_actual_preserved':True,
        'old_receiver_executed':False,'new_metadata_only_revision':True,'changed_policy_leaves':mechanism['policy_exact_changed_leaves'],
        'logical_workspace_key_retained_but_physical_parent_is_home_agent':True,
        'policy':policy_pin,'request':request_pin,'consumer_launch':launch_pin,'source20_request':control_pin,
        'source20_launch':control_launch_pin,'capacity_proof':capacity_pin,'source20_ids':controls['expected_ids'],
        'all34_runtime_inputs_identical':True,'all13_algorithm_files_identical':True,
        'source20_owner':{'seconds':20,'cleanup_seconds':3,'output':str(SOURCE_ACTUAL),'runs':0},
        'receiver_limits':policy['limits'],'source_and_receiver_never_invoked_by_author':True,
        'fixed_tmp_operation_root':policy['operation_root'],'fixed_private_refs_path':policy['provider_references_path'],
        'fixed_private_proxy_path':policy['proxy_configuration_path'],'existing_private_proxy_opaque_receipt':captured,
        'existing_private_proxy_body_not_read_by_author':True,'proxy_recapture_required':False,
        'required_order':['Root reviews full byte/mode metadata-only diff and canonical request',
            'Root authorizes one new source20/20+3 under r2 request/output; all20 actual required',
            'Read bound source20 actual lifecycle/final/report; do not adopt r1 result',
            'Root acquires exactly3 official references into the same still-fresh fixed private ref path',
            'Root supplies original private proxy receipt SHA; no repeat capture',
            'Fresh original per-volume quota+512MiB reserve+4096-inode gates; observations do not waive them',
            'Root uniquely launches900+3 receiver with complete start+720 through final full readback'],
        'original_CI_and_remote_recovery_failures_preserved':True,
        'not_a_native_or_supplier_or_CI_retry':True,'no_new_ref_or_workflow_requested':True,
        'capacity_now_observed_only':{k:{'minimum_bytes':capacity['volumes'][k]['minimum_start_free_bytes'],
            'observed_bytes':v['free_bytes'],'observed_inodes':v['free_inodes'],
            'observed_sufficient':v['free_bytes']>=capacity['volumes'][k]['minimum_start_free_bytes'] and v['free_inodes']>=4096}
            for k,v in observations.items()}}
    save('HANDOFF.json',handoff)
    files=[]
    for path in sorted(NEW.rglob('*')):
        if path.is_file():files.append({'path':str(path.relative_to(NEW)),**pin(read(path))})
    save('FROZEN-FILES.json',{'schema':'hia.v92-storage-r2-static-files.v1','files':files,'frozen':True,
        'control_or_receiver_execution':False,'Git_mutations':0,'provider_refs_or_GETs':0})
    print(json.dumps({'root':str(NEW),'policy':policy_pin,'request':request_pin,'source20_request':control_pin,
        'files_before_manifest':len(files),'observed_capacity':handoff['capacity_now_observed_only']}))


if __name__=='__main__':
    main()
