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
import types
BASE=Path('/tmp/hia-patch-result-owner-r4-dda7')
PRIOR=Path('/tmp/hia-patch-result-owner-r1-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/patch-generation-r4-2-root-preflight.json')
plan_raw=read(BASE/'GENERATION-PLAN-R4.2.json',0o644)
assert pin(plan_raw)['git_blob']=='cced69c01f660b35db92d44bc1a2c3b08ac99a12'
p=json.loads(plan_raw)
launch_raw=read(BASE/'GENERATION-LAUNCH-R4.2.json',0o644);launch=json.loads(launch_raw)
assert launch['plan_pin']==pin(plan_raw)
assert launch['argv']==[p['runtime']['launch_executable'],'-I','-B',str(BASE/'authoring/run_generation_only_r4_2.py'),'--plan',str(BASE/'GENERATION-PLAN-R4.2.json'),'--sha256',pin(plan_raw)['sha256']]
assert launch['env']==p['environment'] and launch['cwd']==str(BASE)
assert len(p['controls'])==61
for row in p['controls']:fixed(row)
runner_raw=read(BASE/'authoring/run_generation_only_r4_2.py',0o644)
assert pin(runner_raw)==p['runner_pin']
r4_2=runner_raw.decode()
r3=read(PRIOR/'authoring/run_generation_only_r3.py',0o644).decode()
r2=read(PRIOR/'authoring/run_generation_only_r2.py',0o644).decode()
r1=read(PRIOR/'authoring/run_generation_only.py',0o644).decode()
old_literal="root.name == 'hia-patch-result-generation-r1-dda7'"
new_literal="root.name == 'hia-patch-result-generation-r4-dda7'"
assert r4_2.count(new_literal)==1 and r4_2.replace(new_literal,old_literal)==r3
assert p['attempt']=='/dev/shm/hia-patch-result-generation-r4-dda7'
addition="                else:\n                    raise AssertionError('required final source root is missing: ' + str(path))\n"
assert r3.count(addition)==1 and r3.replace(addition,'',1)==r2
def functions(text):
 return {n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
f1,f2,f3=map(functions,(r1,r2,r3))
assert set(f1)==set(f2)==set(f3)
for name in set(f1)-{'execute'}:assert f1[name]==f2[name]==f3[name],name
assert "compare_capture(actual_final, base['files'], stable=base['stat'])" in r3
assert "compare_capture(actual_final, final_expected)" in r3
assert "'runtime', lambda: runtime_guard(runtime)" in r3 and "'controls', lambda: load_plan(plan_path, digest)" in r3
assert p['limits']=={'blocks':1536,'cleanup_seconds':3,'functions':128,'minimum_free_bytes':1073741824,'operations':8192,'qualification_seconds':180,'source_bytes':1048576}
assert p['stage_order']==['generation-1','generation-2','generation-check']
assert p['product_operations']=={'default_activation':0,'native_calls':0,'native_compile':0,'tests':0,'vm_calls':0}
packet_raw=fixed(p['source_packet']);packet=json.loads(packet_raw)
assert pin(packet_raw)['git_blob']=='2324df56da63a7a17b66144ac67177e50b3fb435'
assert len(packet['files'])==11 and packet['base_files']==3188 and packet['base_source']==p['base_source']
base=json.loads(fixed(p['base_capture']))
assert not base['errors'] and len(base['files'])==3188 and tree(base['files'])==p['base_tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96'
source=Path(p['base_source']);names=set();source_bytes=0
for directory,dirs,files in os.walk(source,followlinks=False):
 for name in dirs:assert not (Path(directory)/name).is_symlink()
 for name in files:names.add((Path(directory)/name).relative_to(source).as_posix())
assert names==set(base['files'])==set(base['stat'])
for name,row in base['files'].items():
 path=source/name;raw=read(path,base['stat'][name]['mode']);s=path.lstat()
 got=pin(raw);got['mode']='100755' if s.st_mode&0o111 else '100644'
 assert got==row
 observed={'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'nlink':s.st_nlink}
 assert observed==base['stat'][name]
 source_bytes+=len(raw)
prepared=copy.deepcopy(base['files'])
for name,row in packet['files'].items():
 assert name not in prepared and row['before'] is None
 raw=row['text'].encode()
 assert pin(raw)==row['after'] and read(BASE/'source'/name,0o644)==raw
 if name.endswith('.py'):ast.parse(raw)
 prepared[name]=row['after']
assert len(prepared)==3199 and tree(prepared)==p['prepared_tree']=='c162d2735b9aa4f85539a9923e6167cfc8b801a4'
assert p['generated_paths']==packet['generated_paths_pending']==['examples/hia_bootstrap/patch_result.hepta','hepta/hia_patch_result_ports.py','hepta/hia_patch_result_data.py']
for name in p['generated_paths']:assert name not in prepared and not (BASE/'source'/name).exists()
prior_packet=json.loads(read(PRIOR/'SOURCE-PACKET.json',0o644))
assert set(prior_packet['files'])==set(packet['files'])
changed=[name for name in packet['files'] if packet['files'][name]!=prior_packet['files'][name]]
assert sorted(changed)==['hepta/hia_patch_result_definitions.py','tests/test_hia_patch_result_source.py']
slice_addition="    if _TYPE(left) is slice:\n        return (_constant_equal(left.start, right.start)\n                and _constant_equal(left.stop, right.stop)\n                and _constant_equal(left.step, right.step))\n"
definitions_new=packet['files']['hepta/hia_patch_result_definitions.py']['text']
assert definitions_new.count(slice_addition)==1
assert definitions_new.replace(slice_addition,'',1)==prior_packet['files']['hepta/hia_patch_result_definitions.py']['text']
old_test=prior_packet['files']['tests/test_hia_patch_result_source.py']['text']
new_test=packet['files']['tests/test_hia_patch_result_source.py']['text']
left=0
while left<min(len(old_test),len(new_test)) and old_test[left]==new_test[left]:left+=1
right=0
while right<len(old_test)-left and old_test[-1-right]==new_test[-1-right]:right+=1
assert left+right==len(old_test)
assert new_test[:left]+new_test[len(new_test)-right:]==old_test
original_text=read(source/'hepta/hia_program_tools.py').decode()
definition_text=packet['files']['hepta/hia_patch_result_definitions.py']['text']
policy_text=packet['files']['tools/hia_patch_result_policy.py']['text']
original_functions=functions(original_text);definition_functions=functions(definition_text);policy_functions=functions(policy_text)
policy_names=['_check_patch_interface','apply_program_patch']
for name in policy_names:assert original_functions[name]==definition_functions[name]==policy_functions[name]
original_code=compile(original_text,str(source/'hepta/hia_program_tools.py'),'exec',dont_inherit=True,optimize=0)
definition_code=compile(definition_text,str(BASE/'source/hepta/hia_patch_result_definitions.py'),'exec',dont_inherit=True,optimize=0)
def code_children(module):
 return {c.co_name:c for c in module.co_consts if isinstance(c,types.CodeType)}
fields=('co_argcount','co_posonlyargcount','co_kwonlyargcount','co_nlocals','co_stacksize','co_flags','co_code','co_names','co_varnames','co_freevars','co_cellvars','co_name','co_qualname','co_exceptiontable')
def normalized(value):
 if isinstance(value,types.CodeType):return ('code',tuple((k,normalized(getattr(value,k))) for k in fields),normalized(value.co_consts))
 if type(value) is tuple:return ('tuple',tuple(normalized(x) for x in value))
 if type(value) is slice:return ('slice',normalized(value.start),normalized(value.stop),normalized(value.step))
 assert type(value) in (bool,int,str,bytes,type(None)) or value is Ellipsis,type(value)
 return (type(value).__name__,value)
original_codes=code_children(original_code);definition_codes=code_children(definition_code)
for name in policy_names:assert normalized(original_codes[name])==normalized(definition_codes[name]),name
native_text=packet['files']['hepta/hia_patch_result_native.py']['text']
inspect_text=read(source/'hepta/hia_inspect_program_native.py').decode()
def methods(text,class_name):
 c=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name==class_name)
 return {n.name:ast.dump(n,include_attributes=False) for n in c.body if isinstance(n,ast.FunctionDef)}
a,b=methods(native_text,'PatchResultFrame'),methods(inspect_text,'InspectProgramFrame')
unchanged_frame=('_invoke','step','service','drive','take','close','_retire')
for name in unchanged_frame:assert a[name]==b[name],name
assert '__init__' not in a
cp=json.loads(read(BASE/'CONTROL-PLAN.json',0o644))
assert len(cp['source_ids'])==11 and len(cp['native_ids'])==12 and len(cp['vm_ids'])==12 and len(cp['original_cli43_ids'])==43
assert cp['tests_executed']==0 and cp['default_activated'] is False
old_cp=json.loads(read(PRIOR/'CONTROL-PLAN.json',0o644))
new_ids=[name for name in cp['source_ids'] if name not in old_cp['source_ids']]
assert len(new_ids)==1 and new_ids[0].endswith('.test_exact_slice_constants_preserve_full_codes_and_reject_unknown_fields')
assert [name for name in cp['source_ids'] if name not in new_ids]==old_cp['source_ids']
for key in ('native_ids','vm_ids','original_cli43_ids'):assert cp[key]==old_cp[key]
def test_functions(text):
 c=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef))
 return {n.name:ast.get_source_segment(text,n) for n in c.body if isinstance(n,ast.FunctionDef)}
old_methods,new_methods=test_functions(old_test),test_functions(new_test)
assert len(new_methods)==len(old_methods)+1
for name,value in old_methods.items():assert new_methods[name]==value,name
runtime=json.loads(fixed(p['runtime_capture']));assert runtime==p['runtime']
for key in ('executable','library'):
 d=runtime[key];raw=read(Path(d['path']).resolve(),d['mode']);s=Path(d['path']).stat()
 assert len(raw)==d['bytes'] and hashlib.sha256(raw).hexdigest()==d['sha256']
 assert [s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns]==[d['device'],d['inode'],d['mtime_ns'],d['ctime_ns']]
assert not Path(p['attempt']).exists()
parent=Path(p['output_parent']['path']);s=parent.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_dev==p['output_parent']['device'] and s.st_ino==p['output_parent']['inode'] and stat.S_IMODE(s.st_mode)==p['output_parent']['posix_mode']
available=os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize
assert available>=p['limits']['minimum_free_bytes']+p['storage_estimate']['peak_additional_bytes_upper_estimate']
for path,before in seen.items():assert seven(Path(path).lstat())==before,path
proof={'schema':'hepta.root.patch-result-generation-preflight.v1','status':'PASS_GENERATION_ONLY_PREEXECUTION',
 'plan':pin(plan_raw),'launch':pin(launch_raw),'runner':pin(runner_raw),'source_packet':pin(packet_raw),
 'all_controls':len(p['controls']),'base_files':3188,'base_bytes':source_bytes,'base_tree':p['base_tree'],
 'base_full_bytes_modes_pathset_and_all_seven_stats_verified':True,'new_authored_files':11,
 'prepared_files':3199,'prepared_tree':p['prepared_tree'],'generated_files_before_execution':0,'expected_final_files':3202,
 'complete_original_two_policy_bodies_equal':True,'independent_passive_code_templates_all_nonlocation_fields_equal':True,
 'actual_runtime_compiler':'CPython 3.14.4 compile-only no module execution','policy_future_flags':{name:original_codes[name].co_flags for name in policy_names},
 'seven_frame_methods_AST_equal':list(unchanged_frame),'constructor_inherited':True,
 'R3_whole_byte_inverse_to_R2':True,'R4_2_exact_root_literal_whole_inverse_to_R3':True,'source_only_exact_slice_and_one_new_test_changed':True,'all_old_Source10_methods_full_bytes_unchanged':True,'all_generation_functions_except_execute_identical_to_R1':sorted(set(f1)-{'execute'}),
 'final_base_and_source_missing_or_drift_or_runtime_control_change_refused':True,
 'author_Source11_Native12_VM12_not_executed':True,'original_CLI43_retained':True,
 'generation_invocations_authorized_by_scope':2,'generation_check_invocations_by_scope':1,'limits':p['limits'],
 'product_operations':p['product_operations'],'available_bytes':available,'all_unique_file_stats_rechecked':len(seen),
 'default_activated':False,'matching_current_cold':False,'whole_native':False,'elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof)
with OUT.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(OUT),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
