"""Read-only complete Root review of the one-import Inspect CLI R4 successor."""
import ast,copy,hashlib,json,os,stat,time,types
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7')
helper=(D/'verify_op10_r3_sharded_preflight.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='232cf93646bf33808b70360454741fa84f4a7b37'
module=ast.parse(helper)
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[previously reviewed read-only primitives]','exec'),globals())
seen={};started=time.monotonic_ns()
B=Path('/tmp/hia-inspect-cli-controls-r4-dda7')
request_raw=read(B/'PREPARATION-PLAN.json',0o644);request=json.loads(request_raw)
assert pin(request_raw)['git_blob']=='65048a9eb147977637e1113d46f9c60ef1d2db78'
launch_raw=read(B/'PREPARATION-LAUNCH.json',0o644);launch=json.loads(launch_raw)
assert pin(launch_raw)['git_blob']=='2042bc706e6230a78b1641b025fe1bd98bb02f06'
assert fixed(launch['request'])==request_raw and fixed(launch['runner'])==fixed(request['author_files']['bind_context_plan.py'])
assert launch['product_executions']==0 and launch['retry'] is False
assert launch['argv']==['/workspace/scratch/dda74a4fae35/v96-union-r13/local-runtime-r1/venv/bin/python3.14','-I','-B',str(B/'bind_context_plan.py'),'--prepare',str(B/'PREPARATION-PLAN.json'),'--request-sha256',pin(request_raw)['sha256']]
assert launch['cwd']==str(B)
for row in request['author_files'].values():fixed(row)
old_raw=fixed(request['original_bound_plan']);proposed_raw=fixed(request['proposed_plan'])
assert pin(old_raw)['git_blob']=='9858ef43a7b04d4be692f558c990b7130034dd97'
assert pin(proposed_raw)['git_blob']=='c5f94b6680777297d98b69f24f0eb3c7111341bc' and len(proposed_raw)<16<<20
old=json.loads(old_raw);p=json.loads(proposed_raw)
changed=['source','source_manifest','source_modes','source_tree','adapter_files','attempt','controls','predecessor_evidence']
assert set(k for k in old if old[k]!=p[k])==set(changed)
inverse=copy.deepcopy(p)
for k in changed:inverse[k]=old[k]
assert enc(inverse)==old_raw
assert p['limits']==old['limits']=={'owner_seconds':180,'cleanup_seconds':3,'compile_seconds':20,'image_bytes':1048576,'vm_steps':10000000,'storage_free_bytes':1073741824}
assert len(p['groups'])==len(p['group_order'])==18 and sum(len(x['ids']) for x in p['groups'].values())==76 and sum(x.get('real_compile_calls',0) for x in p['groups'].values())==7
assert len(old['controls'])==13 and len(p['controls'])==16
assert {k:v for k,v in p['controls'].items() if k not in request['r4_controls']}==old['controls']
for row in p['controls'].values():fixed(row)
for row in p['retained_authorities'].values():fixed(row)
fixed(p['compiler']);fixed(p['predecessor_inspect_image'])
new_runner=fixed(request['r4_controls']['r4_executor']).decode()
old_runner=fixed(old['controls']['r3_executor']).decode()
new_literal="value['row_count'] == 61683";old_literal="value['row_count'] == 61550"
assert new_runner.count(new_literal)==1 and new_runner.replace(new_literal,old_literal,1)==old_runner
assert "flags = ['-B'] if label == 'original-cli43' else ['-I', '-B']" in new_runner
for key,name in [('r4_control_support_copy','r3_control_support_copy'),('r4_witness_tests_copy','r3_witness_tests_copy')]:
 assert fixed(request['r4_controls'][key])==fixed(old['controls'][name])
 assert Path(request['r4_controls'][key]['path']).stat().st_ino!=Path(old['controls'][name]['path']).stat().st_ino
value=p['predecessor_evidence']
assert value['parts'][:4]==old['predecessor_evidence']['parts'] and len(value['parts'])==5 and value['row_count']==61683
rows=[];total_bytes=0
for i,part in enumerate(value['parts']):
 assert part['ordinal']==i and part['first_row']==len(rows)
 chunk_raw=fixed(part['descriptor']);chunk=json.loads(chunk_raw)
 assert len(chunk_raw)<=8<<20 and len(chunk)==part['row_count']
 for row in chunk:total_bytes+=len(fixed(row))
 rows.extend(chunk)
assert len(rows)==61683 and pin(enc(rows))==value['ordered_rows_pin']
assert pin(enc(rows[:61550]))==old['predecessor_evidence']['ordered_rows_pin']
terminal_raw=fixed(request['failure_terminal']);inventory_raw=fixed(request['failure_inventory'])
terminal=json.loads(terminal_raw);inventory=json.loads(inventory_raw)
assert pin(terminal_raw)['git_blob']=='37e63160f5d1c7e7a85f8c3a300abd79ac6c19b2'
assert pin(inventory_raw)['git_blob']=='85979f729e0bd3a8a72a419f134f6ffa9e945554'
assert len(inventory)==131 and terminal['product_status']=='FAIL' and terminal['test_body_entered'] is False
assert rows[61550:61552]==[request['failure_terminal'],request['failure_inventory']]
assert rows[61552:]==[{k:row[k] for k in ('path','pin','posix_mode')} for row in inventory.values()]
for row in inventory.values():assert seven(Path(row['path']).lstat())==row['seven_stats']
source=Path(old['source']);m=json.loads(fixed(old['source_manifest']));modes=json.loads(fixed(old['source_modes']))
names=set();inode=set();source_bytes=0
for directory,dirs,files in os.walk(source,followlinks=False):
 for name in dirs:assert stat.S_ISDIR((Path(directory)/name).lstat().st_mode)
 for name in files:names.add((Path(directory)/name).relative_to(source).as_posix())
assert names==set(m)==set(modes) and len(m)==3191 and tree(m)==old['source_tree']=='65e6f3b81f864f2629e73fc371f2576a67185744'
for name,row in m.items():
 path=source/name;raw=read(path,modes[name]);s=path.lstat();v=pin(raw);v['mode']='100755' if s.st_mode&0o111 else '100644'
 assert v==row and s.st_nlink==1 and (s.st_dev,s.st_ino) not in inode
 inode.add((s.st_dev,s.st_ino));source_bytes+=len(raw)
old_records=fixed(request['records_before']);new_records=fixed(request['records_after'])
assert old_records==read(source/'hepta/hia_inspect_cli_records.py')
assert new_records==old_records.replace(b'from __future__ import annotations\n',b'from __future__ import annotations\nimport copy\n',1)
assert len(new_records)-len(old_records)==12 and pin(new_records)['git_blob']=='4669e99e773538efa862ab2101f42e76b7cdbe00'
projected=dict(m);projected['hepta/hia_inspect_cli_records.py']=pin(new_records)
assert fixed(request['projected_source_map'])==enc(projected) and fixed(request['projected_source_modes'])==enc(modes)
assert tree(projected)==p['source_tree']=='fa3d74c64f7dfc6bb13a712dfd9e466676ec5665'
assert p['source']==request['new_root']+'/source' and p['attempt']==request['new_root']+'/attempt-r1'
assert p['source_manifest']=={'path':request['new_root']+'/SOURCE-MAP.json','pin':pin(enc(projected)),'posix_mode':0o600}
assert p['source_modes']=={'path':request['new_root']+'/SOURCE-MODES.json','pin':pin(enc(modes)),'posix_mode':0o600}
adapters=dict(old['adapter_files']);adapters['hepta/hia_inspect_cli_records.py']=pin(new_records)
assert adapters==p['adapter_files']
# Fixed-interpreter compile-only checks; no original/passive project module executes.
original=read(source/'hepta/hia_program_tools.py')
fields=('co_argcount','co_posonlyargcount','co_kwonlyargcount','co_nlocals','co_stacksize','co_flags','co_code','co_names','co_varnames','co_freevars','co_cellvars','co_name','co_qualname','co_exceptiontable')
def norm(v):
 if type(v) is types.CodeType:return ('code',tuple((k,norm(getattr(v,k))) for k in fields),norm(v.co_consts))
 if type(v) is tuple:return ('tuple',tuple(norm(x) for x in v))
 assert type(v) in (bool,int,str,bytes,type(None)) or v is Ellipsis,type(v)
 return (type(v).__name__,v)
def children(raw):return {x.co_name:x for x in compile(raw,'[complete source compile-only]','exec',dont_inherit=True,optimize=0).co_consts if type(x)is types.CodeType}
actual,prior,new=children(original),children(old_records),children(new_records)
assert norm(actual['function_signature'])!=norm(prior['function_signature'])
for name in ('function_signature','inspect_program'):assert norm(actual[name])==norm(new[name])
for key in ('executable','library'):
 row=p['runtime'][key];path=Path(row['path']).resolve();raw=read(path,row['mode']);s=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns]==[row['device'],row['inode'],row['mtime_ns'],row['ctime_ns']]
assert not os.path.lexists(request['new_root'])
free=os.statvfs('/dev/shm').f_bavail*os.statvfs('/dev/shm').f_frsize
assert free>=(1<<30)+source_bytes+12+(32<<20)
for path,previous in seen.items():assert seven(Path(path).lstat())==previous,path
proof={'schema':'hepta.root.inspect-cli-r4-context-preflight.v1','status':'PASS_READ_ONLY_NO_BINDER_NO_PRODUCT','request':pin(request_raw),'launch':pin(launch_raw),'proposed_plan':pin(proposed_raw),'old_actual_failed_plan':pin(old_raw),'new_runner':pin(new_runner.encode()),'whole_runner_single_literal_inverse_equal':True,'whole_plan_eight_fields_inverse_equal':True,'source':str(source),'source_files':3191,'source_bytes':source_bytes,'base_tree':tree(m),'projected_tree':tree(projected),'projected_tree_is_not_actual_materialization':True,'records_exact_12_byte_import_copy_insertion':True,'all_original_code_comparators_functions_and_classes_byte_preserved':True,'fixed_CPython314_compile_only_two_full_code_objects_equal':True,'new_module_setup_import_is_an_observable_profile_change':True,'all_61683_predecessor_rows_full_bytes_modes_order':True,'predecessor_bytes_including_repeated_rows':total_bytes,'original_61550_rows_exact_prefix':True,'failure_rows_appended':133,'original_R3_failure_retained':True,'all_3191_source_full_bytes_modes_pathsets_unique_nlink1_inodes':True,'all_final_seven_stat_checks':len(seen),'groups':18,'method_invocations':76,'compile_calls':7,'all_original_ids_bodies_assertions_budgets_retained':True,'CLI43_original_B_flag_retained':True,'limits':p['limits'],'free_bytes':free,'binder_executions':0,'product_executions':0,'default_activated':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof);out=D/'inspect-cli-r4-root-preflight.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9,'unique_files':len(seen)},sort_keys=True))
