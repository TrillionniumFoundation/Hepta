"""Static text/AST metadata review only; never import/call project code."""
import ast,difflib,hashlib,json,os,re,stat
from pathlib import Path
R=Path('/tmp/hia-op13-execution-author-r1-dda7')
A=Path('/tmp/hia-cli-patch-result-author-r3-dda7')
F=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(raw,mode='100644'):
 return {'bytes':len(raw),'mode':mode,'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def cap(path):
 path=Path(path);a=path.lstat();assert stat.S_ISREG(a.st_mode)and a.st_nlink==1
 raw=path.read_bytes();assert all(getattr(a,k)==getattr(path.lstat(),k)for k in F)
 return {'path':str(path),'pin':pin(raw,'100755'if a.st_mode&0o111 else'100644'),'stat':{k:getattr(a,k)for k in F}}
def fixed(row,full=True):
 path=Path(row['path']);s=path.lstat()
 assert path.is_absolute()and'..'not in path.parts and stat.S_ISREG(s.st_mode)and s.st_nlink==1
 assert {k:getattr(s,k)for k in F}==row['stat']
 assert ('100755'if s.st_mode&0o111 else'100644')==row['pin']['mode']
 if full:assert cap(path)==row
def load(path):return json.loads(Path(path).read_bytes())
def put(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 with path.open('xb')as stream:stream.write(raw)
 assert path.read_bytes()==raw
def tree(files):
 root={}
 for name,row in files.items():
  node=root;parts=name.split('/');assert all(p and p not in('.','..')for p in parts)
  for p in parts[:-1]:node=node.setdefault(p,{})
  assert parts[-1]not in node;node[parts[-1]]=row
 def visit(node):
  rows=[]
  for name,row in node.items():
   if'git_blob'in row:rows.append((name.encode(),row['mode'].encode(),bytes.fromhex(row['git_blob'])))
   else:rows.append(((name+'/').encode(),b'40000',visit(row)))
  raw=b''.join(m+b' '+n.rstrip(b'/')+b'\0'+s for n,m,s in sorted(rows))
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
 return visit(root).hex()
def funcs(text):return {n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def methods(path,cls,prefix):
 node=next(n for n in ast.parse(Path(path).read_bytes()).body if isinstance(n,ast.ClassDef)and n.name==cls)
 return [prefix+n.name for n in node.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')]
p=load(R/'PREPARATION-PLAN.json');oldp=load(R/'PREPARATION-PLAN-DRAFT.json')
rows=load(p['origin_rows']['path']);oldrows=load(R/'SOURCE-ORIGINS.json');m=load(p['projected_source_map']['path'])
r5=load(A/'authority/R5-SOURCE-MAP.json');patch=load(A/'authority/PATCH14-SOURCE-MAP.json')
assert len(rows)==len(m)==3210 and len(r5)==3191 and len(patch)==14
assert len(set(m)-set(r5))==19 and not(set(r5)&set(patch))
assert all(m[n]==v for n,v in r5.items())and all(m[n]==v for n,v in patch.items())
assert tree(m)==p['source_tree']=='821bb0ac9c4ce7a7648c1c34ef91406e3a45fbcb'
assert tree(r5)=='d5e3ca6576607e3bfaad4bae09058a6c9fcfd1a5'
assert [r['relative']for r in rows]==sorted(m)
assert len({r['descriptor']['path']for r in rows})==3210
assert len({(r['descriptor']['stat']['st_dev'],r['descriptor']['stat']['st_ino'])for r in rows})==3210
small=large=0
for row in rows:
 assert row['expected']==row['descriptor']['pin']==m[row['relative']]
 full=not row['descriptor']['path'].startswith('/tmp/hia-r8-source-recovery-20261114-r1/source/')
 fixed(row['descriptor'],full);small+=int(full);large+=int(not full)
assert(small,large)==(50,3160)
changed=[i for i,(a,b)in enumerate(zip(oldrows,rows))if a!=b];assert len(changed)==1
n=changed[0];assert oldrows[n]['relative']==rows[n]['relative']=='hepta/hia_checker_identity.py'
assert oldrows[n]['descriptor']is None and oldrows[n]['expected']==rows[n]['expected']
changedp=[k for k in p if p[k]!=oldp[k]]
assert changedp==['controls','missing_sources','origin_rows','protected_source','provenance','state']and set(p)==set(oldp)
assert p['state']=='AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION'and not p['missing_sources']
assert [k for k in p['controls']if p['controls'][k]!=oldp['controls'][k]]==['run_execution.py']
assert set(p['controls'])==set(oldp['controls'])and len(p['controls'])==19
assert all(p['provenance'][k]==v for k,v in oldp['provenance'].items())
assert load(p['protected_source']['state']['path'])==load(oldp['protected_source']['state']['path'])
for row in p['controls'].values():fixed(row)
for row in p['provenance'].values():fixed(row)
for row in (p['origin_rows'],p['projected_source_map'],p['compiler'],p['runtime_map'],p['template'],p['protected_source']['map'],p['protected_source']['state']):fixed(row)
for row in p['expected_runtime'].values():fixed(row,False)
limits={'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,'owner_seconds':180,'vm_call_depth':128,'vm_heap':8388608,'vm_steps':10000000}
assert p['limits']==limits and p['storage_floor']==1073741824
assert p['compiler']['pin']['sha256']=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'and p['compiler']['pin']['bytes']==673413
assert p['scope']=='/dev/shm/hia-op13-execution-r1-dda7'and not os.path.lexists(p['scope'])
launch=load(R/'PREPARATION-LAUNCH.json');product=load(R/'PRODUCT-LAUNCH-TEMPLATE-FINAL.json')
assert launch['fixed_inputs']['plan']==cap(R/'PREPARATION-PLAN.json')and launch['fixed_inputs']['entry']==p['controls']['bind_execution.py']
assert launch['argv']==[p['expected_runtime']['executable']['path'],'-I','-B',p['controls']['bind_execution.py']['path'],'--plan',str(R/'PREPARATION-PLAN.json'),'--plan-sha256',launch['fixed_inputs']['plan']['pin']['sha256']]
assert launch['environment']['LD_LIBRARY_PATH']==str(Path(p['expected_runtime']['library']['path']).parent)
assert 'LD_PRELOAD'not in launch['environment']and launch['output_filesystem']=='/dev/shm'
assert not os.path.lexists(launch['outer'])and launch['state']=='FROZEN_REQUIRES_SEPARATE_ROOT_AUTHORIZATION'
assert product['actual_plan']is None and product['actual_binding_result']is None and product['state']=='UNBOUND_NO_EXECUTION'
assert product['entry']==p['controls']['run_execution.py']
retained={'run_control_child.py':('authoring/run_control_child.py','eb7925ecdb0dd3cb375bc835532e97cad1360aba'),'inspect_exec_support.py':('authority/inspect-kit/inspect_exec_support.py','f6d59fd0caef181064c5b77adca2b7e9216ac332'),'inspect_cli_control_support.py':('authority/inspect_cli_control_support.py','b65cdbd5be3890e7d4bb424504a2a7ff4e70a371')}
for name,(source,want)in retained.items():
 raw=(R/'controls'/name).read_bytes();assert raw==(A/source).read_bytes()and pin(raw)['git_blob']==want
build=funcs((R/'controls/run_build_child.py').read_text());original=load(A/'authority/ORIGINAL-R5-BUILD-FUNCTIONS.json');oldbuild=funcs((A/'authority/ORIGINAL-R5-CONTROL-RUNNER.py').read_text())
for name in('build_inspect','build_report'):assert build[name]==oldbuild[name]==original[name]['text']
parsed=[]
for path in sorted((R/'controls').glob('*.py')):ast.parse(path.read_bytes());parsed.append(cap(path))
assert len(parsed)==8
before=(R/'AUTHOR-PARENT-PREADMISSION-BEFORE.py').read_text();after=(R/'controls/run_execution.py').read_text()
replacements=[("result['stages'].append(stage);actual=None","result['stages'].append(stage);actual=None;pending_build=None"),("                if not is_build:\n                    tests=decode(checked(capture(directory/'TESTS.json')))","                if is_build:\n                    pending_build=take_build(plan,directory,label,actual)\n                else:\n                    tests=decode(checked(capture(directory/'TESTS.json')))"),("                new,new_bundle,artifacts=take_build(plan,directory,label,actual)","                require(pending_build is not None,'missing admitted actual build')\n                new,new_bundle,artifacts=pending_build\n                artifacts.append(capture(directory/'STAGE.json'))")]
forward=before
for a,b in replacements:assert forward.count(a)==1;forward=forward.replace(a,b)
assert forward==after
inverse=after
for a,b in reversed(replacements):assert inverse.count(b)==1;inverse=inverse.replace(b,a)
assert inverse==before
assert {k:v for k,v in funcs(before).items()if k!='execute'}=={k:v for k,v in funcs(after).items()if k!='execute'}
matrix=load(A/'plans/CONTROL-MATRIX.json');template=load(A/'EXECUTION-PLAN.json')
sourceids=methods(A/'source/tests/test_hia_patch_cli_source.py','PatchCliSourceTests','tests.test_hia_patch_cli_source.PatchCliSourceTests.')
nativeids=methods(A/'source/tests/test_hia_patch_cli_native.py','PatchCliNativeTests','tests.test_hia_patch_cli_native.PatchCliNativeTests.')
vmids=methods(A/'authority/patch14/tests/test_hia_patch_result_vm.py','PatchResultFrameVMTests','tests.test_hia_patch_result_vm.PatchResultFrameVMTests.')
assert sourceids==matrix['source_ids']and len(sourceids)==8
assert nativeids==[x['id']for x in matrix['native_groups']]and len(nativeids)==12
assert [x['signature_native']for x in matrix['native_groups']]==[False]*9+[True,False,False]
assert vmids==matrix['reuse_original_patch_vm12']['ids']and len(vmids)==12
assert template['new_group_order']==product['exact_stage_order']==['op13-source8','build-report-six','build-inspect','build-patch']+[x['group']for x in matrix['native_groups']]
assert matrix['limits']==template['child_limits']==limits and template['storage_free_bytes_minimum']==p['storage_floor']
assert matrix['retained_r5_witness10']=='FAIL_UNCHANGED_NOT_REQUALIFIED'and not matrix['apply_contract_proposal']
assert not matrix['default_selection_changed']and not matrix['current_cold']
assert re.fullmatch(r'[0-9a-f]{64}\.zlib','a'*64+'.zlib')and not re.fullmatch(r'[0-9a-f]{64}\.zlib','a'*64+'Xzlib')
result={'schema':'hepta.hia.op13.static-author-review.v1','status':'PASS_STATIC_ONLY','products':0,'project_imports':0,'source_copy':0,'binder_execution':0,'runtime_probe':0,'plan':cap(R/'PREPARATION-PLAN.json'),'launch':cap(R/'PREPARATION-LAUNCH.json'),'source_files':3210,'source_tree':tree(m),'r5_exact_files':3191,'patch_additions':14,'op13_additions':5,'small_sources_fully_read':small,'Root_verified_source_new_stats_checked':large,'Root_full_source_authority':p['provenance']['source_root_readback'],'source_inodes_all_unique':True,'origin_paths_all_unique':True,'exact_checker_completed':True,'metadata_reconstruction_count':1,'control_files':parsed,'retained_control_copies':retained,'original_build_functions':{n:pin(build[n].encode())for n in('build_inspect','build_report')},'whole_parent_draft_forward_inverse':True,'unexecuted_author_replacements':replacements,'plan_changed_fields':changedp,'plan_other_fields_unchanged':True,'source_declared_ids':sourceids,'native_declared_ids':nativeids,'future_vm_declared_ids':vmids,'declarations_not_executed_tests':True,'limits':limits,'storage_floor':p['storage_floor'],'future_compiles':8,'future_owners':16,'all_frames_retired':False,'compile_full_workspace_claim':False,'old_R5_witness10':'FAIL_UNCHANGED_NOT_REQUALIFIED','default':False,'current_cold':False,'whole':False,'remaining_blockers':['Root complete review and explicit preparation authorization','Actual independent 3210 source binding and runtime capture','Root actual BOUND-PLAN/BINDING-RESULT readback and product authorization','Actual Source8/eight compiles/Native12; no prior qualification transfer','Future original VM12 remains a separate gate'],'target_absent':not os.path.lexists(p['scope'])}
put(R/'STATIC-REVIEW.json',result)
for old,new,name in [('PREPARATION-PLAN-DRAFT.json','PREPARATION-PLAN.json','PLAN.diff'),('PREPARATION-LAUNCH-DRAFT.json','PREPARATION-LAUNCH.json','LAUNCH.diff'),('PRODUCT-LAUNCH-TEMPLATE.json','PRODUCT-LAUNCH-TEMPLATE-FINAL.json','PRODUCT-TEMPLATE.diff')]:
 text=''.join(difflib.unified_diff((R/old).read_text().splitlines(keepends=True),(R/new).read_text().splitlines(keepends=True),fromfile=old,tofile=new))
 with(R/name).open('x')as out:out.write(text)
print(json.dumps({'status':'PASS_STATIC_ONLY','sources':3210,'small_full_reads':small,'Root_source_stat_checks':large,'Source_declared':8,'Native_declared':12,'future_VM_declared':12,'controls':19,'products':0,'report':cap(R/'STATIC-REVIEW.json')['pin']}))
