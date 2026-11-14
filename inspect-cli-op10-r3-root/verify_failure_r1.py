"""Read-only Root admission of the bounded op10 metadata successor."""
import ast, copy, hashlib, json, os, stat, time
from pathlib import Path
BASE=Path('/tmp/hia-inspect-cli-controls-r3-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/op10-r3-sharded-root-preflight.json')
started=time.monotonic_ns()
seen={}
def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path, mode=None):
    p=Path(path)
    s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and not p.is_symlink(), str(p)
    with p.open('rb') as f: raw=f.read()
    assert seven(s)==seven(p.lstat()), str(p)
    if mode is not None: assert stat.S_IMODE(s.st_mode)==mode, str(p)
    previous=seen.setdefault(str(p),seven(s))
    assert previous==seven(s),str(p)
    return raw
def pin(raw):
    return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':'100644','sha256':hashlib.sha256(raw).hexdigest()}
def fixed(d):
    raw=read(d['path'],d['posix_mode'])
    assert pin(raw)==d['pin'],d['path']
    return raw
def enc(v):
    return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def tree(rows):
    root={}
    for name,row in rows.items():
        node=root
        parts=name.split('/')
        for part in parts[:-1]: node=node.setdefault(part,{})
        node[parts[-1]]=(row['mode'],row['git_blob'])
    def walk(node):
        raw=b''
        for name,value in sorted(node.items(),key=lambda kv:(kv[0]+('/' if isinstance(kv[1],dict) else '')).encode()):
            if isinstance(value,dict): mode,digest='40000',walk(value)
            else: mode,digest=value
            raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return walk(root)
ROOT=Path('/dev/shm/hia-inspect-cli-controls-r3-dda7/attempt-r1')
LAUNCH_ROOT=Path('/tmp/hia-root-op10-r3-execution-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/op10-r3-product-failure-root-terminal.json')
INVENTORY=OUT.with_name('op10-r3-product-failure-root-inventory.json')
inventory={}
for label,root in (('attempt',ROOT),('launch',LAUNCH_ROOT)):
 for directory,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert not (Path(directory)/name).is_symlink()
  for name in files:
   path=Path(directory)/name;raw=read(path)
   inventory[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'posix_mode':stat.S_IMODE(path.lstat().st_mode),'seven_stats':seven(path.lstat())}
plan_raw=read(ROOT/'PLAN-USED.json',0o600);p=json.loads(plan_raw)
assert pin(plan_raw)['git_blob']=='9858ef43a7b04d4be692f558c990b7130034dd97'
outer_raw=read(ROOT/'OUTER.json',0o600);outer=json.loads(outer_raw)
launch_raw=read(LAUNCH_ROOT/'OUTER.json');launch=json.loads(launch_raw)
assert launch['returncode']==1 and launch['product_execution_attempts']==1 and launch['automatic_retry'] is False
assert outer['status']=='FAIL' and outer['halted_after_first_failure'] is True and outer['owner_launch_attempts']==5
assert [r['label'] for r in outer['stages']]==p['group_order'][:5]
source_map=json.loads(fixed(p['source_manifest']));modes=json.loads(fixed(p['source_modes']))
guard={'tree':p['source_tree'],'count':3191,'modes':modes}
assert outer['source_after']==guard
test_rows=[];owners=[]
for i,label in enumerate(p['group_order'][:5]):
 directory=ROOT/('%02d-'%(i+1)+label)
 stage=json.loads(read(directory/'STAGE.json'))
 request_raw=read(directory/'REQUEST.json');request=json.loads(request_raw)
 owner_raw=read(directory/'OWNER.json');owner=json.loads(owner_raw)
 returned=json.loads(read(directory/'OWNER-RETURNED.json'))
 actual_raw=read(directory/'RESULT.json');actual=json.loads(actual_raw)
 command=json.loads(read(directory/'COMMAND.json'))
 owner_request=json.loads(read(directory/'OWNER.json.request.json'))
 assert stage==outer['stages'][i] and stage['source_after']==guard
 assert request['group']==label and request['ids']==p['groups'][label]['ids']
 assert actual['request_pin']==pin(request_raw) and actual['source_before']==actual['source_after']==guard and actual['source_unchanged'] is True
 assert owner['request_sha256']==hashlib.sha256(read(directory/'OWNER.json.request.json')).hexdigest()
 assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3
 assert owner['timed_out'] is False and owner['exit_observed_before_deadline'] is True
 assert owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True
 assert returned=={**owner,'supervisor_returncode':returned['supervisor_returncode'],'receipt_sha256':hashlib.sha256(owner_raw).hexdigest()}
 assert returned['supervisor_returncode']==0
 assert command['command']==owner_request['command'] and command['environment']==owner_request['env']
 assert command['cwd']==owner_request['cwd']==p['source']
 assert command['qualification_seconds']==180 and command['cleanup_seconds']==3
 assert command['command'][1:3]==['-I','-B'] and command['command'][-1]==pin(request_raw)['sha256']
 expected_rc=0 if i<4 else 1
 assert owner['returncode']==expected_rc and actual['status']==stage['status']==('PASS' if i<4 else 'FAIL')
 assert not stage.get('guard_error')
 owners.append({'label':label,'returncode':expected_rc,'status':owner['status'],'ECHILD':True,'timed_out':False,'historical_descendant_inventory_complete':owner['historical_descendant_inventory_complete']})
 if label in ('source10','source8','witness-01'):
  tests=json.loads(read(directory/'TESTS.json'))
  ids=p['groups'][label]['ids']
  assert tests['declared_ids']==tests['loaded_ids']==tests['started_ids']==tests['stopped_ids']==ids
  assert tests['events']==[pair for name in ids for pair in (['start',name],['stop',name])]
  if i<4:
   assert tests==actual['tests'] and tests['status']=='PASS'
   assert not any(tests[k] for k in ('errors','failures','skipped','expected_failures','unexpected_successes','loader_errors'))
  else:
   assert tests['status']=='FAIL' and len(tests['errors'])==1 and tests['tests_run']==1
   assert not any(tests[k] for k in ('failures','skipped','expected_failures','unexpected_successes','loader_errors'))
   error=tests['errors'][0][1]
   assert 'in setUp' in error and 'ValueError: selected function is not the frozen policy definition' in error
   assert 'function_signature' in error
  test_rows.append({'label':label,'status':tests['status'],'tests':tests['tests_run'],'events':len(tests['events']),'subtests':len(tests['subtests']),'errors':len(tests['errors'])})
for i,label in enumerate(p['group_order'][5:],start=6):assert not (ROOT/('%02d-'%i+label)).exists()
compiler_raw=fixed(p['compiler']);compiler_sha=hashlib.sha256(compiler_raw).hexdigest()
receipts=sorted(ROOT.rglob('*.receipt.json'));assert len(receipts)==7
compiled=[]
for path in receipts:
 r=json.loads(read(path));request_path=path.with_name(path.name.replace('.receipt.json','.request.json'));req=json.loads(read(request_path))
 assert r['status']=='returned' and r['abi_status']==0 and r['source_unchanged'] is True
 assert not r['forbidden_compiler_modules_loaded']
 assert req['capacity']==req['workspace_size']==1048576 and req['workspace_fill']==0
 assert r['limits']['cpu_seconds']==10 and r['limits']['output_capacity']==r['limits']['workspace_bytes']==1048576
 assert req['image_sha256']==r['image_sha256']==compiler_sha and req['image']==p['compiler']['path']
 input_raw=read(req['source']);output_raw=read(req['output']);image_raw=read(r['produced_image'])
 assert hashlib.sha256(input_raw).hexdigest()==req['source_sha256']==r['input_sha256']==r['source_sha256']
 assert len(input_raw)==r['input_bytes'] and len(output_raw)==1048576
 assert hashlib.sha256(output_raw).hexdigest()==r['output_sha256']
 assert len(image_raw)==r['produced_bytes']==r['core_u32']==r['result_u64'] and output_raw[:len(image_raw)]==image_raw
 assert hashlib.sha256(image_raw).hexdigest()==r['produced_sha256']
 compiled.append({'receipt':str(path),'receipt_pin':pin(read(path)),'image':pin(image_raw),'full_workspace_observed':False})
inspect_result=json.loads(read(ROOT/'04-build-inspect/RESULT.json'))['build']
assert inspect_result['image']==p['predecessor_inspect_image']['pin']
six_result=json.loads(read(ROOT/'03-build-report-six/RESULT.json'))['build']
assert six_result['six_real_compilations'] is True and len(six_result['children'])==6
for row in six_result['children'].values():
 assert pin(read(row['image']))==row['image_pin'] and pin(read(row['manifest']))==row['manifest_pin']
source=Path(p['source']);actual_names=set()
for directory,dirs,files in os.walk(source,followlinks=False):
 for name in dirs:assert not (Path(directory)/name).is_symlink()
 for name in files:actual_names.add((Path(directory)/name).relative_to(source).as_posix())
assert actual_names==set(source_map)==set(modes)
for name,row in source_map.items():
 raw=read(source/name,modes[name]);s=(source/name).lstat()
 got=pin(raw);got['mode']='100755' if s.st_mode&0o111 else '100644'
 assert got==row and s.st_nlink==1
assert tree(source_map)==p['source_tree']
for key in ('controls','retained_authorities'):
 for d in p[key].values():fixed(d)
for key in ('executable','library'):
 d=p['runtime'][key];raw=read(Path(d['path']).resolve(),d['mode']);s=Path(d['path']).stat()
 assert len(raw)==d['bytes'] and hashlib.sha256(raw).hexdigest()==d['sha256']
 assert [s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns]==[d['device'],d['inode'],d['mtime_ns'],d['ctime_ns']]
for path,before in seen.items():assert seven(Path(path).lstat())==before,path
current=set()
for label,root in (('attempt',ROOT),('launch',LAUNCH_ROOT)):
 for directory,dirs,files in os.walk(root,followlinks=False):
  for name in files:current.add(label+'/'+(Path(directory)/name).relative_to(root).as_posix())
assert current==set(inventory)
inventory_raw=enc(inventory)
with INVENTORY.open('xb') as f:f.write(inventory_raw)
proof={'schema':'hepta.root.inspect-cli-op10-failure-terminal.v1','status':'PASS_FAILURE_EVIDENCE_VERIFIED',
 'product_status':'FAIL','actual_session':45546,'actual_returncode':1,'elapsed_ns':launch['elapsed_ns'],
 'outer':pin(outer_raw),'launch_outer':pin(launch_raw),'plan':pin(plan_raw),'inventory':pin(inventory_raw),
 'raw_files':len(inventory),'raw_bytes':sum(v['pin']['bytes'] for v in inventory.values()),
 'all_raw_complete_bytes_modes_pathset_and_seven_stats':True,'owners':owners,'tests':test_rows,
 'actual_compiles':len(compiled),'compiled_images':compiled,'compile_full_workspaces_observed':False,
 'current_source_files':3191,'current_source_tree':p['source_tree'],'full_current_source_controls_runtime_rechecked':True,
 'failed_group':'witness-01','failed_id':p['groups']['witness-01']['ids'][0],
 'failure_point':'setUp -> issue_preselected_inspect_record -> _capture_definition(function_signature)',
 'failure':'ValueError: selected function is not the frozen policy definition',
 'test_body_entered':False,'new_op10_positive_qualification':False,'remaining_original_groups_not_started':13,
 'native_admission_calls_before_error_not_counted_as_op10_body':True,'automatic_retry':False,
 'matching_current_cold':False,'default_activated':False,'whole_native':False,'production_legacy_retired':False,
 'reader_elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof)
with OUT.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(OUT),'pin':pin(raw),'inventory':pin(inventory_raw),'raw_files':len(inventory),'raw_bytes':proof['raw_bytes'],'reader_seconds':proof['reader_elapsed_ns']/1e9},sort_keys=True))
