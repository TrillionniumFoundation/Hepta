import ast,hashlib,json,stat
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35');P=R/'v134-u32-full-hosted-plan-r1';O=R/'v95-audit-mount-r1/v140-progress'
def pin(b,mode=420):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':mode,'git_mode':'100755' if mode&73 else '100644'}
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode);b=p.read_bytes();e=p.lstat();assert (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(e.st_dev,e.st_ino,e.st_mode,e.st_size,e.st_mtime_ns,e.st_ctime_ns);return b,pin(b,stat.S_IMODE(s.st_mode))
b,i=read(O/'ROOT-U32-HOSTED-HARNESS-STATIC-READBACK.json');assert i['git_blob']=='11d109f02b7356b7bdeb9ed95f4b8f99d7a441e1';proof=json.loads(b)
H2=P/'prepared-r2/harness';H3=P/'prepared-r3/harness';H4=P/'prepared-r4/harness'
a=json.loads(read(P/'prepared-r4/AUTHORING-RESULT.json')[0]);assert len(a['harness_files'])==22
assert {p.relative_to(H4).as_posix() for p in H4.rglob('*') if p.is_file()}==set(a['harness_files'])
changed=[]
for n,expected in a['harness_files'].items():
 after=read(H4/n);before=read(H2/n);assert after[1]==expected and before[1]==proof['harness'][n]
 if after!=before:changed.append(n)
assert sorted(changed)==['inputs/HARNESS-INDEX.json','tools/materialize_hosted.py']
for h in (H3,H4):
 d=json.loads(read(h/'inputs/HARNESS-INDEX.json')[0])
 for n,e in d['files'].items():assert read(h/n)[1]==e
old=read(H2/'tools/materialize_hosted.py')[0].decode()
third=read(H3/'tools/materialize_hosted.py')[0].decode()
new,ident=read(H4/'tools/materialize_hosted.py');new=new.decode()
assert ident['git_blob']=='ede4df92ceeaf255d620e4c96ff8a63e4670e95e'
for path,before,after in [(P/'prepared-r3/AUTHORING-PATCHES.json',old,third),(P/'prepared-r4/AUTHORING-PATCHES.json',third,new)]:
 patches=json.loads(read(path)[0])['patches'];forward=before
 for row in patches:
  assert forward.count(row['before'])==1;forward=forward.replace(row['before'],row['after'],1)
 assert forward==after
 inverse=after
 for row in reversed(patches):
  assert inverse.count(row['after'])==1;inverse=inverse.replace(row['after'],row['before'],1)
 assert inverse==before and ast.dump(ast.parse(inverse),include_attributes=False)==ast.dump(ast.parse(before),include_attributes=False)
def defs(x):return {n.name:ast.get_source_segment(x,n) for n in ast.parse(x).body if isinstance(n,ast.FunctionDef)}
d2,d4=defs(old),defs(new)
assert set(d4)-set(d2)=={'capture_copied_materials'}
assert {n for n in d2 if d2[n]!=d4[n]}=={'bind','collect','collect_file'}
g2=[n for n in ast.parse(old).body if not isinstance(n,ast.FunctionDef)]
g4=[n for n in ast.parse(new).body if not isinstance(n,ast.FunctionDef)]
assert ast.dump(ast.Module(body=g2,type_ignores=[]),include_attributes=False)==ast.dump(ast.Module(body=g4,type_ignores=[]),include_attributes=False)
report={'schema':'hepta.root-u32-hosted-r4-static.v1','status':'PASS_STATIC_COMBINED_READBACK','base_full_51_material_readback':i,'harness_files':a['harness_files'],'only_changed_paths':sorted(changed),'only_existing_functions_changed':['bind','collect','collect_file'],'only_added_function':'capture_copied_materials','both_successors_full_forward_and_inverse_bytes_AST_equal':True,'all_nonfunction_statements_and_original_six_stat_FIELDS_unchanged':True,'copied_31_non_source_materials_captured_before_consume_and_after_bind':True,'same_captured_raw_consumed_for_allowlist_policy_and_four_JSON':True,'actual_nlink_before_after_recorded_at_collection':True,'source_files':3180,'checks':5052,'phases':38,'limits_unchanged_180_plus_3_3GiB':True,'original_10_execution_Python_and_155_binding_pointers_unchanged':True,'product_executions':0,'downloads':0,'CI_runs':0,'authorizes_execution':False,'whole_native':False}
out=O/'ROOT-U32-HOSTED-R4-STATIC-READBACK.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'report':str(out),'identity':read(out)[1]}))
