"""Read-only complete Root review of actual PatchResult R4.2 generation."""
import ast, hashlib, json, os, stat, time
from pathlib import Path
START=time.monotonic_ns()
A=Path('/tmp/hia-patch-result-owner-r4-dda7')
R=Path('/dev/shm/hia-patch-result-generation-r4-dda7')
O=Path('/tmp/hia-root-patch-generation-r4-2-dda7')
D=Path('/tmp/hia-root-v141-dda7')
seen={}
evidence={}
def seven(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(raw,mode=None):
 v={'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
 if mode is not None:v['mode']=mode
 return v
def read(p,expected=None):
 p=Path(p);s=p.lstat()
 assert stat.S_ISREG(s.st_mode) and not p.is_symlink(),str(p)
 with p.open('rb') as f:
  assert seven(os.fstat(f.fileno()))==seven(s)
  raw=f.read()
  assert seven(os.fstat(f.fileno()))==seven(s)
 assert len(raw)==s.st_size and seven(p.lstat())==seven(s),str(p)
 assert seen.setdefault(str(p),seven(s))==seven(s)
 if expected is not None:assert pin(raw,expected.get('mode'))==expected,str(p)
 return raw
def data(p,expected=None):return json.loads(read(p,expected))
def fixed(row):
 raw=read(row['path'],row['pin']);assert stat.S_IMODE(Path(row['path']).lstat().st_mode)==row['posix_mode']
 return raw
def tree(rows):
 node={}
 for name,row in rows.items():
  sub=node;parts=name.split('/')
  for part in parts[:-1]:sub=sub.setdefault(part,{})
  sub[parts[-1]]=(row['mode'],row['git_blob'])
 def go(sub):
  raw=b''
  for name,v in sorted(sub.items(),key=lambda kv:(kv[0]+('/' if isinstance(kv[1],dict) else '')).encode()):
   mode,sha=('40000',go(v)) if isinstance(v,dict) else v
   raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return go(node)
def capture_check(root,c):
 assert not c['errors'] and set(c['files'])==set(c['stat'])
 names=set();identities=set();total=0
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:names.add((Path(folder)/name).relative_to(root).as_posix())
 assert names==set(c['files'])
 for name,row in c['files'].items():
  p=Path(root)/name;raw=read(p,row);s=p.lstat();total+=len(raw)
  actual={'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'nlink':s.st_nlink}
  assert actual==c['stat'][name] and row['mode']==('100755' if s.st_mode&0o111 else '100644')
  identities.add((s.st_dev,s.st_ino))
 return identities,total
plan_raw=read(A/'GENERATION-PLAN-R4.2.json')
assert pin(plan_raw)['git_blob']=='cced69c01f660b35db92d44bc1a2c3b08ac99a12'
p=json.loads(plan_raw);assert read(R/'PLAN.json')==plan_raw
launch_raw=read(A/'GENERATION-LAUNCH-R4.2.json');launch=json.loads(launch_raw)
runner=read(A/'authoring/run_generation_only_r4_2.py',p['runner_pin'])
for row in p['controls']:fixed(row)
assert len(p['controls'])==61
runtime=json.loads(fixed(p['runtime_capture']));assert runtime==p['runtime']
for key in ('executable','library'):
 row=runtime[key];path=Path(row['path']).resolve();raw=read(path);s=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns,s.st_ctime_ns]==[row['device'],row['inode'],row['mode'],row['mtime_ns'],row['ctime_ns']]
base=json.loads(fixed(p['base_capture']))
packet=json.loads(fixed(p['source_packet']))
prepared=dict(base['files'])
for name,row in packet['files'].items():
 assert name not in prepared and row['before'] is None and pin(row['text'].encode(),'100644')==row['after']
 prepared[name]=row['after']
assert len(base['files'])==3188 and len(prepared)==3199
assert tree(base['files'])==p['base_tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96'
assert data(R/'PREPARED-MAP.json')==prepared and tree(prepared)==p['prepared_tree']=='c162d2735b9aa4f85539a9923e6167cfc8b801a4'
for n in ('BASE-BEFORE.json','BASE-AFTER.json','FINAL-BASE-OBSERVATION.json'):assert data(R/n)==base
before=data(R/'SOURCE-BEFORE.json');after=data(R/'SOURCE-AFTER.json');final=data(R/'FINAL-SOURCE-OBSERVATION.json')
assert not before['errors'] and before['files']==prepared and after==final
fm=data(R/'FINAL-MAP.json');assert fm==final['files']
result_raw=read(R/'RESULT.json');result=json.loads(result_raw)
assert result['status']=='PASS' and not result['final_capture_errors']
assert result['completed']==result['owner_launch_intents']==result['stage_order']==p['stage_order']==['generation-1','generation-2','generation-check']
assert result['product_operations']==p['product_operations']=={'default_activation':0,'native_calls':0,'native_compile':0,'tests':0,'vm_calls':0}
assert result['new_hardlinks']==0 and result['independent_byte_copy'] and result['source_all_bytes_modes_verified']
assert result['source_files']==len(fm)==3202 and result['source_final_tree']==tree(fm)=='b86c073b441bf049ab294e5830b8c5d22fd2121a'
assert not result['default_activated'] and not result['matching_current_cold']
bi,bbytes=capture_check(Path(p['base_source']),base)
ni,nbytes=capture_check(R/'source',final)
assert len(ni)==3202 and len(bi)==3188 and ni.isdisjoint(bi)
assert all(x['nlink']==1 for x in final['stat'].values())
for name in prepared:assert final['files'][name]==before['files'][name] and final['stat'][name]==before['stat'][name]
assert set(fm)-set(prepared)==set(p['generated_paths'])
outputs=result['actual_generated']
assert outputs['complete_core_verify'] and outputs['native_calls']==outputs['vm_calls']==0
assert outputs['core_counts']=={'functions':24,'blocks':247,'operations':1876}
for name,row in outputs['files'].items():
 for folder in ('1','2'):
  assert read(R/'outputs'/folder/Path(name).name,row)==read(R/'source'/name,row)
 assert fm[name]==row
for folder in ('1','2'):assert sorted(x.name for x in (R/'outputs'/folder).iterdir())==sorted(Path(n).name for n in p['generated_paths'])
identity={}
for n in ast.parse(read(R/'source/hepta/hia_patch_result_data.py')).body:
 if isinstance(n,ast.Assign):identity[n.targets[0].id]=ast.literal_eval(n.value)
assert set(identity)=={'SOURCE_BYTES','SOURCE_SHA256','HOST_SOURCE_SHA256'}
assert identity['SOURCE_BYTES']==103357 and identity['SOURCE_SHA256']==fm['examples/hia_bootstrap/patch_result.hepta']['sha256']
host_defs=[n for n in ast.parse(read(R/'source/hepta/hia_patch_result_native.py')).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='HOST_SOURCE_FILES']
hosts=ast.literal_eval(host_defs[0].value);assert len(host_defs)==1 and len(hosts)==len(set(hosts))==13
assert set(identity['HOST_SOURCE_SHA256'])==set(hosts)
assert identity['HOST_SOURCE_SHA256']==outputs['actual_host_sha256']=={name:fm['hepta/'+name]['sha256'] for name in hosts}
owners=[]
owner_impl=hashlib.sha256(read(R/'source/tools/hia_selfhost_process_owner.py')).hexdigest()
for index,kind in enumerate(p['stage_order']):
 stage=R/kind
 request=data(stage/'REQUEST.json');oreq_raw=read(stage/'OWNER.json.request.json');oreq=json.loads(oreq_raw)
 owner_raw=read(stage/'OWNER.json');owner=json.loads(owner_raw);returned=data(stage/'OWNER-RETURN.json')
 child=data(stage/'CHILD-RESULT.json');outer=data(stage/'OUTER.json')
 assert returned==dict(owner,receipt_sha256=hashlib.sha256(owner_raw).hexdigest(),supervisor_returncode=0)
 assert outer=={'status':'PASS','owner':returned,'child':child}
 assert owner['request_sha256']==hashlib.sha256(oreq_raw).hexdigest()
 assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and not owner['timed_out'] and owner['exit_observed_before_deadline']
 assert owner['qualification_seconds']==oreq['qualification_seconds']==180 and owner['cleanup_seconds']==oreq['cleanup_seconds']==3
 assert oreq['deadline_ns']-oreq['started_ns']==180000000000
 assert owner['implementation_sha256']==oreq['implementation_sha256']==owner_impl
 cleanup=owner['cleanup']
 assert cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped'] and not cleanup['errors'] and not cleanup['remaining_direct_children'] and cleanup['elapsed_ns']<=3000000000
 assert owner['historical_descendant_inventory_complete'] is False
 expected_command=launch['argv']+['--child',kind]
 assert request['command']==oreq['command']==expected_command
 assert request['source']==oreq['cwd']==str(R/'source')
 assert oreq['env']==request['environment']==p['environment'] and request['runtime']==runtime and request['limits']==p['limits'] and request['kind']==kind
 assert oreq['receipt_path']==str(stage/'OWNER.json') and oreq['stdout_path']==str(stage/'stdout.log') and oreq['stderr_path']==str(stage/'stderr.log')
 assert child['status']=='PASS' and child['kind']==kind and child['product_operations']==p['product_operations'] and child['generated']==outputs
 assert all(child[k]=='PASS' for k in ('source_guard','base_guard','runtime_guard','control_guard'))
 assert child['python']==runtime['python'] and child['finished_ns']>child['started_ns']
 argv=[str(R/'source/tools/generate_hia_patch_result.py'),'--output',str(R/'outputs'/('1' if index==0 else '2')/'patch_result.hepta'),'--ports',str(R/'outputs'/('1' if index==0 else '2')/'hia_patch_result_ports.py'),'--identity',str(R/'outputs'/('1' if index==0 else '2')/'hia_patch_result_data.py')]
 if index==2:argv+=['--check']
 assert child['generator_argv']==argv
 owners.append({'kind':kind,'qualification_seconds':180,'cleanup_seconds':3,'returncode':0,'observed_echild':True,'cleanup_ns':cleanup['elapsed_ns'],'child_elapsed_ns':child['finished_ns']-child['started_ns']})
outer=data(O/'OUTER.json')
assert outer['status']=='EXITED' and outer['returncode']==0 and outer['execution_attempts']==1 and not outer['automatic_retry']
assert outer['authorization']['git_blob']=='78fbc95c6d482285a21e8616588c0cf36d66a1c7'
assert outer['launch']==pin(launch_raw)
for name in ('stdout.raw','stderr.raw'):read(O/name,outer[name])
for root,label in ((R,'generation'),(O,'root-outer')):
 for folder,dirs,files in os.walk(root,followlinks=False):
  if Path(folder)==R:dirs[:]=[x for x in dirs if x!='source']
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:
   path=Path(folder)/name;raw=read(path)
   evidence[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'mode':stat.S_IMODE(path.lstat().st_mode),'seven_stat':seven(path.lstat())}
for name,previous in seen.items():assert seven(Path(name).lstat())==previous,name
inventory=(json.dumps(evidence,sort_keys=True,indent=2)+'\n').encode()
ip=D/'patch-generation-r4-2-root-inventory.json'
with ip.open('xb') as f:f.write(inventory)
proof={'schema':'hepta.root.patch-result-generation-r4-2-terminal.v1','status':'PASS_ACTUAL_GENERATION_ONLY','actual_session':45405,'outer_exit_code':0,'outer_elapsed_ns':outer['elapsed_ns'],'actual_result':pin(result_raw),'actual_plan':pin(plan_raw),'actual_source_files':3202,'actual_source_bytes':nbytes,'actual_source_tree':tree(fm),'base_files':3188,'base_bytes':bbytes,'base_tree':tree(base['files']),'all_full_current_bytes_modes_pathsets_seven_stats':True,'all_actual_successor_inodes_unique_disjoint_from_base':True,'all_3199_prepared_files_full_bytes_modes_and_identities_unchanged':True,'two_actual_generations_one_actual_check':True,'all_six_output_files_and_three_installed_files_full_bytes_equal':True,'actual_three_Core_verified_child_observations_agree':outputs['core_counts'],'all_13_actual_host_source_pins_verified':True,'owners':owners,'historical_descendant_inventory_complete':False,'raw_files':len(evidence),'raw_bytes':sum(x['pin']['bytes'] for x in evidence.values()),'raw_inventory':pin(inventory),'all_unique_final_stat_rechecks':len(seen),'new_products_by_reader':0,'generation_product_operations':p['product_operations'],'default_activated':False,'matching_current_cold':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
out=D/'patch-generation-r4-2-root-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'raw_files':len(evidence),'raw_bytes':proof['raw_bytes'],'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
