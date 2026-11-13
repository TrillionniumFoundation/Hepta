"""Freeze two-leaf R4 input revision after confirmed reference expiry; no calls."""
from pathlib import Path
import copy
import difflib
import hashlib
import json
import os
import stat
import time

OLD=Path('/home/agent/hia-v92-three-view-plan-r3-20261113-e26e')
NEW=Path('/home/agent/hia-v92-three-view-plan-r4-20261113-e26e')
ROOT=Path('/home/agent/hia-root-v92-three-view-r3-20261113-e26e')
PARENT='3dac5006c8aeb98559fc52dc85099b2114c8c4b4'
ACTUAL=Path('/tmp/hia-v92-three-view-source20-r4-20261113-e26e')
REFS=Path('/tmp/hia-v92-three-view-provider-refs-r4-20261113-e26e.private.json')

def wire(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    b=p.read_bytes();assert identity(s)==identity(p.lstat()) and len(b)==s.st_size
    return b
def save(name,value,raw=False,mode=0o600):
    p=NEW/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);b=value if raw else wire(value)
    f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(f,'wb') as s:s.write(b);s.flush();os.fsync(s.fileno())
    assert read(p)==b
    return pin(b)
def changes(a,b,p=''):
    if type(a) is dict and type(b) is dict:
        assert set(a)==set(b);return sum((changes(a[k],b[k],p+'/'+k) for k in sorted(a)),[])
    if type(a) is list and type(b) is list:
        assert len(a)==len(b);return sum((changes(x,y,p+'/'+str(i)) for i,(x,y) in enumerate(zip(a,b))),[])
    return [] if type(a) is type(b) and a==b else [{'pointer':p,'before':a,'after':b}]

def main():
    old=json.loads(read(OLD/'POLICY.json'));assert len(old['inputs'])==34
    assert not os.path.lexists(ACTUAL) and not os.path.lexists(REFS)
    assert not os.path.lexists(old['mandatory_source_controls']['actual_root'])
    assert not os.path.lexists(old['proxy_configuration_path'])
    for v in old['volumes'].values():assert not os.path.lexists(v['root'])
    runtime=old['runtime'];assert pin(read(Path(runtime['path'])))['sha256']==runtime['sha256']
    assert identity(Path(runtime['path']).lstat())==runtime['identity']
    rows=[]
    for name,expected in old['inputs'].items():
        p=OLD/name;b=read(p);a=pin(b);assert all(a[k]==expected[k] for k in ('bytes','sha256'))
        save(name,b,raw=True,mode=stat.S_IMODE(p.lstat().st_mode));rows.append({'path':name,**a,'byte_identical_to_r3':True})
    history=[]
    for p,name in [(ROOT/'R1-PROVIDER-REFERENCES-EXPIRY-HOLD.json','history/R1-PROVIDER-REFERENCES-EXPIRY-HOLD.json'),
                   (ROOT/'request-review/ROOT-REVIEW.json','history/ROOT-R3-REVIEW.json'),
                   (ROOT/'review_request_r3.py','history/review_request_r3.py'),
                   (OLD/'publication/CANONICAL.json','history/R3-CANONICAL.json')]:
        b=read(p);save(name,b,raw=True,mode=stat.S_IMODE(p.lstat().st_mode));history.append({'original_path':str(p),'copy':name,**pin(b)})
    expiry=json.loads(read(NEW/'history/R1-PROVIDER-REFERENCES-EXPIRY-HOLD.json'))
    assert pin(read(NEW/'history/R1-PROVIDER-REFERENCES-EXPIRY-HOLD.json'))['sha256']=='530ff8699b3fdfebeec48944e163a4bd31cb60d35ad6344af791be73eba69da9'
    assert expiry['status']=='ALL3_EXISTING_REFERENCES_EXPIRED_BEFORE_ANY_LOCAL_GET'
    assert expiry['local_large_GETs']==expiry['receiver_invocations']==0 and expiry['reference_requests_already_performed']==3
    assert expiry['r3_source20_never_invoked'] is True and expiry['old_private_file_preserved'] is True
    assert expiry['private_input']['path']==old['provider_references_path']
    assert expiry['private_input']['sha256']=='89ac4f110cc6e3d5c4dc2471f3ecd801200b479bba06f0ba6c5fffd548cf8606'
    assert [x['artifact_id'] for x in expiry['exact_expiry_metadata_only']]==[x['artifact']['id'] for x in old['parts']]
    assert all(x['seconds_past_expiry']>0 for x in expiry['exact_expiry_metadata_only'])
    policy=copy.deepcopy(old);policy['mandatory_source_controls']['actual_root']=str(ACTUAL);policy['provider_references_path']=str(REFS)
    delta=changes(old,policy);assert [x['pointer'] for x in delta]==['/mandatory_source_controls/actual_root','/provider_references_path']
    pp=save('POLICY.json',policy)
    controls=json.loads(read(OLD/'CONTROL-REQUEST.json'))
    controls['command'][-1]=str(NEW/'controls/run_controls.py');controls['operation_root']=str(ACTUAL);controls['output']=str(ACTUAL/'tests')
    controls['inputs']['POLICY.json']={k:pp[k] for k in ('bytes','sha256')}
    controls['scope']=('The same20 synthetic tiny-file controls under a new R4 provider-input binding. All20 must execute once '
        'under the original20/3 owner in separate r4 output. R2 source20 PASS and R3 expired-reference HOLD remain history, '
        'not R4 acceptance. No receiver, network, private capture or product execution. FROZEN_UNEXECUTED.')
    cp=save('CONTROL-REQUEST.json',controls)
    cl=json.loads(read(OLD/'CONTROL-LAUNCH.json'));cl['command'][-1]=str(NEW/'controls/launch_controls.py');cl['cwd']=str(NEW);cl['request']=cp
    clp=save('CONTROL-LAUNCH.json',cl)
    request=json.loads(read(OLD/'REQUEST.json'));request['policy']=pp;request['source20_request']=cp
    request['private_input_shapes']['proxy']=('R4 changes only the provider-reference input path and source20 output identity. '
        'The old r1 provider references are proved expired and must never be used for a local GET. Preserve all old refs/ACKs/expiry '
        'and the old r1 proxy capture. After the complete R4 review and actual R4 source20 PASS, Root obtains exactly one new '
        'official reference for each of the three unchanged artifacts into '+str(REFS)+'. These new references are obtained '
        'at the last moment, not before source20 or canonical review. Immediately, in one inheriting Root process, create '
        'the still-fresh r3 proxy input at '+policy['proxy_configuration_path']+' and invoke the unchanged receiver once after '
        'its full fresh equality, runtime/source/actual and per-volume gates. No URL/private value is published, no expired '
        'URL is tried, no retry or direct fallback is permitted, and no resource or algorithm changes are introduced.')
    rp=save('REQUEST.json',request)
    launch=json.loads(read(OLD/'LAUNCH.json'));launch['argv_prefix'][-1]=str(NEW/'control/launch.py');launch['cwd']=str(NEW);launch['request']=rp
    lp=save('LAUNCH.json',launch)
    capacity=json.loads(read(OLD/'CAPACITY-PROOF.json'));observations={}
    for key,volume in policy['volumes'].items():
        parent=Path(volume['parent']);s=parent.lstat();fs=os.statvfs(parent)
        assert stat.S_ISDIR(s.st_mode) and s.st_dev==volume['parent_device']
        observations[key]={'path':str(parent),'device':s.st_dev,'free_bytes':fs.f_bavail*fs.f_frsize,'free_inodes':fs.f_favail,'time_ns':time.time_ns()}
        capacity['volumes'][key]['observed_authoring_free_bytes']=observations[key]['free_bytes']
        capacity['volumes'][key]['observed_authoring_free_inodes']=observations[key]['free_inodes']
    capacity_pin=save('CAPACITY-PROOF.json',capacity)
    save('VOLUME-OBSERVATIONS.json',{'schema':'hia.v92-r4-volume-observations.v1','observations':observations,
         'observations_do_not_grant_capacity_admission':True,'actual_roots_and_new_private_files_not_created':True})
    inverse=copy.deepcopy(policy);inverse['mandatory_source_controls']['actual_root']=old['mandatory_source_controls']['actual_root'];inverse['provider_references_path']=old['provider_references_path']
    assert wire(inverse)==read(OLD/'POLICY.json')
    assert policy['parts']==old['parts'] and policy['volumes']==old['volumes']
    assert policy['limits']==old['limits']=={'cleanup_seconds':3,'complete_seconds':720,'owner_seconds':900}
    assert policy['network']==old['network'] and policy['selection']==old['selection'] and policy['diagnostics']==old['diagnostics']
    assert controls['expected_ids']==json.loads(read(OLD/'CONTROL-REQUEST.json'))['expected_ids']
    assert controls['qualification_seconds']==20 and controls['cleanup_seconds']==3
    for name,e in controls['inputs'].items():
        a=pin(read(NEW/name));assert all(a[k]==e[k] for k in ('bytes','sha256'))
    for row in rows:assert read(NEW/row['path'])==read(OLD/row['path'])
    proof={'schema':'hia.v92-r4-two-leaf-mechanical-proof.v1','status':'STATIC_METADATA_ONLY_PASS_NOT_EXECUTION','parent':PARENT,
        'policy_exact_changes':delta,'all34_runtime_inputs_byte_identical':rows,'algorithm_files_unchanged':13,
        'source20_input_count':35,'source20_ids':controls['expected_ids'],'source20_owner_seconds':20,'source20_cleanup_seconds':3,
        'receiver_limits_unchanged':policy['limits'],'parts_full_bytes_sha_offsets_order_and_volumes_unchanged':True,
        'all_capacity_categories_reserves_and_inode_gates_unchanged':True,'proxy_r3_path_unchanged_and_still_absent':True,
        'r3_old_reference_status':'EXPIRED_WITH_ZERO_LOCAL_GETS','old3_reference_requests_retained':3,
        'new_provider_reference_requests_by_author':0,'receiver_executions':0,'private_capture_or_bodies_read':False,
        'history_originals':history}
    save('MECHANICAL-R4.json',proof)
    names=['POLICY.json','CONTROL-REQUEST.json','CONTROL-LAUNCH.json','REQUEST.json','LAUNCH.json','CAPACITY-PROOF.json']
    diff=''.join(''.join(difflib.unified_diff(read(OLD/n).decode().splitlines(True),read(NEW/n).decode().splitlines(True),fromfile='r3/'+n,tofile='r4/'+n)) for n in names)
    dp=save('REVISION-R4.diff',diff.encode(),raw=True)
    handoff={'schema':'hia.v92-three-container-r4-handoff.v1','status':'FROZEN_UNEXECUTED_REQUIRES_NEW_SOURCE20',
        'root':str(NEW),'proposed_sole_parent':PARENT,'policy':pp,'request':rp,'source20_request':cp,'source20_launch':clp,'consumer_launch':lp,'capacity_proof':capacity_pin,'diff':dp,
        'exact_policy_changes':delta,'all34_runtime_and13_algorithms_byte_identical':True,
        'source20_actual_root':str(ACTUAL),'new_provider_reference_path':str(REFS),'proxy_r3_path_preserved':policy['proxy_configuration_path'],
        'actual_output_roots_preserved':{k:v['root'] for k,v in policy['volumes'].items()},'part02_home_assignment_preserved':True,
        'old_R2_source20_13_originals_and_environment_hold_in_parent_chain':True,
        'old_R3_source20_and_receiver_invocations':0,'old_provider_references_known_expired_never_to_be_used':True,
        'historical_provider_acquisitions':3,'new_provider_acquisitions_required_only_after_review_and_source20':3,
        'new_source20_or_capture_or_GET_by_author':0,'source20_ids':controls['expected_ids'],
        'required_order':['Root completes exact canonical R4 review','Root uniquely executes and fully admits all20 R4 controls under20/3',
          'Root performs fresh two-volume capacity/runtime/source/private-path preflight without fetching references',
          'Only then obtain three exact official references once each into the new private refs file',
          'Immediately enter one inheriting Root process, create the r3 proxy file once, and run unchanged full equality and all fresh gates',
          'Uniquely invoke unchanged900/3 receiver; each artifact has one GET and no retry; complete720 includes parent full readback'],
        'unchanged_minimum_start_free_bytes':{'tmp':956703893,'workspace_home':1009489532},
        'unchanged_two_reserves_bytes':536870912,'no_ref_or_workflow_requested':True,'no_native_or_CI_rerun':True}
    save('HANDOFF.json',handoff)
    files=[{'path':str(p.relative_to(NEW)),**pin(read(p))} for p in sorted(NEW.rglob('*')) if p.is_file()]
    save('FROZEN-FILES.json',{'schema':'hia.v92-r4-frozen-files.v1','files':files,'frozen':True,'source_or_receiver_executed':False,'GETs':0,'private_bodies_read':False})
    print(json.dumps({'root':str(NEW),'policy':pp,'request':rp,'source20_request':cp,'source20_launch':clp,'files_before_manifest':len(files),'observations':observations}))

if __name__=='__main__':main()
