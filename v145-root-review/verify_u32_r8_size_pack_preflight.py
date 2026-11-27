"""Read-only Root review of fixed u32 R8 size/pack controls, all inputs and source."""
import ast, hashlib, json, os, stat, time
from pathlib import Path
START=time.monotonic_ns()
R=Path('/tmp/hia-u32-r8-size-pack-r1-dda7')
D=Path('/tmp/hia-root-v141-dda7')
seen={}
def stamp(s):return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')}
def pin(raw,mode=None):
 v={'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
 if mode is not None:v.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
 return v
def read(path,identity=None):
 p=Path(path);s=p.lstat();assert stat.S_ISREG(s.st_mode)
 with p.open('rb') as f:
  assert stamp(os.fstat(f.fileno()))==stamp(s);raw=f.read();assert stamp(os.fstat(f.fileno()))==stamp(s)
 assert len(raw)==s.st_size and stamp(p.lstat())==stamp(s)
 assert seen.setdefault(str(p),stamp(s))==stamp(s)
 if identity is not None:assert pin(raw,identity.get('mode'))==identity,str(p)
 return raw
def data(path):return json.loads(read(path))
def functions(raw):
 text=raw.decode();lines=text.splitlines(keepends=True)
 return {n.name:''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def tree(rows):
 root={}
 for name,row in rows.items():
  p=root;parts=name.split('/')
  for n in parts[:-1]:p=p.setdefault(n,{})
  p[parts[-1]]=(row['git_mode'],row['git_blob'])
 def go(p):
  raw=b''
  for n,v in sorted(p.items(),key=lambda kv:(kv[0]+('/' if isinstance(kv[1],dict) else '')).encode()):
   mode,sha=('40000',go(v)) if isinstance(v,dict) else v
   raw+=mode.encode()+b' '+n.encode()+b'\0'+bytes.fromhex(sha)
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return go(root)
plan_raw=read(R/'EXECUTION-PLAN.json');p=json.loads(plan_raw)
assert pin(plan_raw)['git_blob']=='cd6f29f4abce41ed360ac5edb3a1a914af48d794'
launch_raw=read(R/'COMMAND-INTENT.json');launch=json.loads(launch_raw)
assert launch['plan']==pin(plan_raw)
assert launch['argv']==[p['runtime']['executable']['path'],'-I','-S','-B',str(R/'run_size_pack.py'),'--plan-sha256',pin(plan_raw)['sha256']]
assert launch['cwd']==str(R) and launch['environment']==p['environment'] and launch['unique_output']==p['output']
assert not os.path.lexists(p['output'])
runner_raw=read(R/'run_size_pack.py');support_raw=read(R/'size_support.py')
assert pin(runner_raw)['git_blob']=='ef734a7a469d7b8a873f5452a559642c6529370c'
assert pin(support_raw)['git_blob']=='bc25da7158e89cda4369c79a0e94d9bbce150a60'
assert len(p['controls'])==16
for row in p['controls'].values():read(row['path'],row['identity'])
for row in p['runtime'].values():read(row['path'],row['identity'])
manifest=data(R/'INPUTS.json');assert len(manifest['files'])==36
input_bytes=0;captured_inodes=set();origin_inodes=set()
for row in manifest['files']:
 a=Path(row['origin']);b=R/row['captured']
 aa=read(a,row['origin_identity']);bb=read(b,row['captured_identity'])
 assert aa==bb and stamp(a.lstat())==row['origin_stat']
 ai=(a.lstat().st_dev,a.lstat().st_ino);bi=(b.lstat().st_dev,b.lstat().st_ino)
 assert ai!=bi and b.lstat().st_nlink==1 and bi not in captured_inodes
 captured_inodes.add(bi);origin_inodes.add(ai);input_bytes+=len(bb)
assert captured_inodes.isdisjoint(origin_inodes) and input_bytes==7579451
source=Path(p['source']['path']);expected=data(R/'FROZEN-3180-SOURCE.json')
names=set()
for directory,dirs,files in os.walk(source,followlinks=False):
 for name in dirs:assert stat.S_ISDIR((Path(directory)/name).lstat().st_mode)
 for name in files:names.add((Path(directory)/name).relative_to(source).as_posix())
assert names==set(expected) and len(expected)==3180
source_bytes=0
for name,row in expected.items():source_bytes+=len(read(source/name,row))
assert tree(expected)==p['source']['tree']=='4c62be4ed66ff107fa6f88c6131313a354868bd9'
projection=data(R/'PROJECTION.json')
original_raw=read(projection['original_builder'],projection['original_builder_identity'])
old_functions=functions(original_raw);new_functions=functions(read(R/'retained_pack_contract.py'))
for name,row in projection['functions'].items():assert old_functions[name]==new_functions[name]==row['text']
assert len(projection['functions'])==3
for name,row in projection['unchanged_loader_files'].items():assert read(R/name,row['captured_identity'])==read(row['origin'])
retained=data(R/'RETAINED-SUPPORT.json')
old_support=functions(read(retained['original_path'],retained['original_identity']))
new_support=functions(support_raw)
assert len(retained['functions'])==14
for name,text in retained['functions'].items():assert old_support[name]==new_support[name]==text,name
# Only previously reviewed, read-only functions are evaluated. No module top-level,
# observer, compiler, owner, product module, frame or ELF function is executed.
allowed={'require','pin','state','read_regular','identity','function_text','projection_guard','input_bytes','input_guard'}
module=ast.parse(support_raw)
ns={'__file__':str(R/'size_support.py'),'ROOT':R,'PLAN':p,'PLAN_RAW':plan_raw,'PLAN_PATH':R/'EXECUTION-PLAN.json','SOURCE':source,'CAPACITY':1<<20,'STAT_KEYS':('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')}
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef) and n.name in allowed],type_ignores=[]),'[reviewed read-only input projection]','exec'),ns)
retained_checks=ns['input_guard']();projection_checks=ns['projection_guard']()
assert retained_checks['old_actual_compiler_receipts']==4 and retained_checks['actual_B3_original_member_bindings']==7
e=p['execution']
assert e['compile_calls']==e['pack_calls_if_both_capacity_gates_pass']==1
assert e['owner_qualification_seconds']==180 and e['owner_cleanup_seconds']==3 and e['native_per_call_seconds']==20 and e['native_cpu_seconds']==10
assert e['source_output_workspace_max_bytes']==1048576 and e['VM_calls']==e['ELF_exec_calls']==e['semantic_native_cases']==e['aggregate_cases']==0
assert e['automatic_retry'] is False and e['compile_pack_share_one_owner'] is True
capacity=p['capacity']
assert capacity=={'bytes':1048576,'exact_reduction_required_from_old_R8':5370,'fixed_controller_bytes':59889,'fixed_representation_bytes':430261,'frame_header_bytes':48,'image_offsets':[1024,60928,491200],'maximum_new_image_by_ELF':557376,'maximum_new_image_by_frame':558378,'page_size':4096}
assert 1048576-491200==557376 and 1048576-48-59889-430261==558378
assert p['storage']['required_free_bytes']==234881024
free=os.statvfs(R).f_bavail*os.statvfs(R).f_frsize
assert free>=p['storage']['required_free_bytes']
for path,previous in seen.items():assert stamp(Path(path).lstat())==previous,path
proof={'schema':'hepta.root.u32-r8-size-pack-preflight.v1','status':'PASS_PREEXECUTION_ONLY','actual_plan':pin(plan_raw),'launch':pin(launch_raw),'runner':pin(runner_raw),'support':pin(support_raw),'controls':16,'fixed_inputs':36,'fixed_input_bytes':input_bytes,'all_input_copies_full_bytes_modes_origin_seven_stats_and_independent_inodes':True,'source_files':3180,'source_bytes':source_bytes,'source_tree':tree(expected),'all_source_full_bytes_modes_pathset_recomputed_tree_and_final_seven_stats':True,'original_pack_functions_full_text':3,'original_support_functions_full_text':14,'original_loader_files_full_bytes':2,'read_only_selected_provenance_guard':{'old_actual_compile_receipts':4,'actual_B3_original_member_bindings':7,'history_preserved':True},'scope':e,'capacity':capacity,'free_bytes':free,'required_free_bytes':p['storage']['required_free_bytes'],'all_unique_final_stat_checks':len(seen),'product_calls':0,'new_project_imports':0,'source_policy_executions':0,'matching_current_cold':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
out=D/'u32-r8-size-pack-root-preflight.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'path':str(out),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
