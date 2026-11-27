"""Read-only Root admission of the bounded op10 metadata successor."""
import ast, copy, hashlib, json, os, stat, time, zlib
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
ROOT=Path('/dev/shm/hia-inspect-cli-controls-r4-dda7/attempt-r1')
LAUNCH_ROOT=Path('/tmp/hia-root-inspect-cli-r4-execution-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/inspect-cli-r4-product-failure-root-terminal.json')
INVENTORY=OUT.with_name('inspect-cli-r4-product-failure-root-inventory.json')
inventory={}
for label,root in (('attempt',ROOT),('launch',LAUNCH_ROOT)):
 for directory,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert not (Path(directory)/name).is_symlink()
  for name in files:
   path=Path(directory)/name;raw=read(path)
   inventory[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'posix_mode':stat.S_IMODE(path.lstat().st_mode),'seven_stats':seven(path.lstat())}
plan_raw=read(ROOT/'PLAN-USED.json',0o600);p=json.loads(plan_raw)
assert pin(plan_raw)['git_blob']=='c5f94b6680777297d98b69f24f0eb3c7111341bc'
outer_raw=read(ROOT/'OUTER.json',0o600);outer=json.loads(outer_raw)
launch_raw=read(LAUNCH_ROOT/'OUTER.json');launch=json.loads(launch_raw)
assert launch['returncode']==1 and launch['execution_attempts']==1 and launch['automatic_retry'] is False
assert outer['status']=='FAIL' and outer['halted_after_first_failure'] is True and outer['owner_launch_attempts']==9
assert [r['label'] for r in outer['stages']]==p['group_order'][:9]
source_map=json.loads(fixed(p['source_manifest']));modes=json.loads(fixed(p['source_modes']))
guard={'tree':p['source_tree'],'count':3191,'modes':modes}
assert outer['source_after']==guard
test_rows=[];owners=[]
for i,label in enumerate(p['group_order'][:9]):
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
 assert returned['supervisor_returncode']==(0 if i<8 else 1)
 assert command['command']==owner_request['command'] and command['environment']==owner_request['env']
 assert command['cwd']==owner_request['cwd']==p['source']
 assert command['qualification_seconds']==180 and command['cleanup_seconds']==3
 assert command['command'][1:3]==['-I','-B'] and command['command'][-1]==pin(request_raw)['sha256']
 expected_rc=0 if i<8 else 1
 assert owner['returncode']==expected_rc and actual['status']==stage['status']==('PASS' if i<8 else 'FAIL')
 assert not stage.get('guard_error')
 owners.append({'label':label,'returncode':expected_rc,'status':owner['status'],'ECHILD':True,'timed_out':False,'historical_descendant_inventory_complete':owner['historical_descendant_inventory_complete']})
 if label in ('source10','source8') or label.startswith('witness-'):
  tests=json.loads(read(directory/'TESTS.json'))
  ids=p['groups'][label]['ids']
  assert tests['declared_ids']==tests['loaded_ids']==tests['started_ids']==tests['stopped_ids']==ids
  assert tests['events']==[pair for name in ids for pair in (['start',name],['stop',name])]
  if i<8:
   assert tests==actual['tests'] and tests['status']=='PASS'
   assert not any(tests[k] for k in ('errors','failures','skipped','expected_failures','unexpected_successes','loader_errors'))
  else:
   assert tests['status']=='FAIL' and not tests['subtests'] and not tests['loader_errors']
   assert 'errors' not in tests and 'tests_run' not in tests
   error=read(directory/'stderr.raw').decode()
   assert 'test_every_import_failure' in error and '_inspect_import35_operand_port' in error
   assert 'line -1' in error and 'ImportFailure: import:hia_program' in error
   assert '_get_code_position' in error and 'RuntimeError: generator raised StopIteration' in error
  test_rows.append({'label':label,'status':tests['status'],'tests_run_reported':tests.get('tests_run'),'started':len(tests['started_ids']),'events':len(tests['events']),'subtests':len(tests['subtests']),'errors_reported':len(tests['errors']) if 'errors' in tests else None})

for i,label in enumerate(p['group_order'][9:],start=10):assert not (ROOT/('%02d-'%i+label)).exists()
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

# Every actual observed frame, including the failed group's unfinalized journals.
machine_rows=[];decoded_paths={};observed_calls=0;closed_journals=0;unfinalized_journals=0
for stage in p['group_order'][4:9]:
 directory=ROOT/('%02d-'%(p['group_order'].index(stage)+1)+stage)/'controls'
 admission=json.loads(read(directory/'ADMISSION.json'))
 counts={}
 for machine in sorted(directory.glob('machine-*')):
  component=machine.name.removeprefix('machine-')
  before_paths=sorted((machine/'frames').glob('*-BEFORE.json'))
  after_paths=sorted((machine/'frames').glob('*-AFTER.json'))
  assert len(before_paths)==len(after_paths)
  index_path=machine/'INDEX.json'
  index=json.loads(read(index_path)) if index_path.exists() else None
  if index is None:
   assert stage=='witness-05';unfinalized_journals+=1
  else:
   assert index['started_calls']==index['complete_calls']==len(before_paths)==len(index['frames']) and index['all_source_unchanged']
   closed_journals+=1
  used=set()
  for number,(bp,ap) in enumerate(zip(before_paths,after_paths,strict=True)):
   before=json.loads(read(bp));after=json.loads(read(ap))
   assert bp.name=='%08d-BEFORE.json'%number and ap.name=='%08d-AFTER.json'%number
   assert before['index']==after['index']==number and before['returned'] is False and after['returned'] is True and after['source_unchanged'] is True
   assert all(after[k]==v for k,v in before.items() if k!='returned')
   assert after['image_sha256']==admission['native_origins'][component]['sha256']
   if index is not None:assert index['frames'][number]==after
   buffers={}
   for region in ('source','output','workspace'):
    for side in ('before','after'):
     desc=after[region+'_'+side];assert desc['file']==desc['sha256']+'.zlib'
     path=machine/'buffers'/desc['file'];compressed=read(path)
     decoder=zlib.decompressobj();value=decoder.decompress(compressed)+decoder.flush()
     assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
     assert pin(value)=={k:v for k,v in desc.items() if k!='file'}
     assert (region!='source' or len(value)>0)
     used.add(desc['file']);buffers[region+'_'+side]=value
     actual=decoded_paths.setdefault(str(path),pin(value));assert actual==pin(value)
   assert buffers['source_before']==buffers['source_after']
   observed_calls+=1
  assert used=={x.name for x in (machine/'buffers').glob('*.zlib')}
  counts[component]=len(before_paths)
  machine_rows.append({'stage':stage,'component':component,'observed_complete_calls':len(before_paths),'index_finalized':index is not None,'unique_full_buffers':len(used)})
 if stage!='witness-05':
  observations=json.loads(read(directory/'CONTROL-OBSERVATIONS.json'))
  assert observations['actual_counts']==counts and observations['complete_frames_read_back'] and observations['fault_losses']==[]
  for number,row in enumerate(observations['observations'],1):
   assert json.loads(read(directory/('OBSERVATION-%04d.json'%number)))==row
   assert row['call_delta']=={key:row['after_calls'][key]-row['before_calls'][key] for key in row['before_calls']}
 else:
  assert not (directory/'CONTROL-OBSERVATIONS.json').exists()
assert observed_calls==600 and closed_journals==28 and unfinalized_journals==7
actual_source_capture=json.loads(read(Path(p['source']).parent/'SOURCE-CAPTURE.json'))
for name,row in actual_source_capture['files'].items():assert seven((source/name).lstat())==row['seven_stats']

for path,before in seen.items():assert seven(Path(path).lstat())==before,path
current=set()
for label,root in (('attempt',ROOT),('launch',LAUNCH_ROOT)):
 for directory,dirs,files in os.walk(root,followlinks=False):
  for name in files:current.add(label+'/'+(Path(directory)/name).relative_to(root).as_posix())
assert current==set(inventory)
inventory_raw=enc(inventory)
with INVENTORY.open('xb') as f:f.write(inventory_raw)
proof={'schema':'hepta.root.inspect-cli-op10-failure-terminal.v1','status':'PASS_FAILURE_EVIDENCE_VERIFIED',
 'product_status':'FAIL','actual_session':37139,'actual_returncode':1,'elapsed_ns':launch['elapsed_ns'],
 'outer':pin(outer_raw),'launch_outer':pin(launch_raw),'plan':pin(plan_raw),'inventory':pin(inventory_raw),
 'raw_files':len(inventory),'raw_bytes':sum(v['pin']['bytes'] for v in inventory.values()),
 'all_raw_complete_bytes_modes_pathset_and_seven_stats':True,'owners':owners,'tests':test_rows,
 'actual_compiles':len(compiled),'compiled_images':compiled,'compile_full_workspaces_observed':False,
 'current_source_files':3191,'current_source_tree':p['source_tree'],'full_current_source_controls_runtime_rechecked':True,
 'failed_group':'witness-05','failed_id':p['groups']['witness-05']['ids'][0],
 'failure_point':'test_every_import_failure -> actual import35 operand raises ImportFailure -> traceback position lookup exhausts co_positions',
 'failure':'RuntimeError: generator raised StopIteration during original traceback formatting; original ImportFailure remains in full stderr',
 'test_body_entered':True,'witness01_through04_only_passed':True,'new_op10_whole_control_qualification':False,'remaining_original_groups_not_started':9,
 'setup_admission_calls_precede_journals_and_not_in_600_count':True,'observed_full_six_buffer_calls':observed_calls,'all_machine_rows':machine_rows,'full_decoded_unique_buffers':len(decoded_paths),'full_decoded_bytes':sum(x['bytes'] for x in decoded_paths.values()),'closed_journals':closed_journals,'unfinalized_failed_group_journals':unfinalized_journals,'all_frames_retired':False,'automatic_retry':False,
 'matching_current_cold':False,'default_activated':False,'whole_native':False,'production_legacy_retired':False,
 'reader_elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof)
with OUT.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(OUT),'pin':pin(raw),'inventory':pin(inventory_raw),'raw_files':len(inventory),'raw_bytes':proof['raw_bytes'],'reader_seconds':proof['reader_elapsed_ns']/1e9},sort_keys=True))
