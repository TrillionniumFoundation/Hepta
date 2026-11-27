"""Root read-only Source11 binder admission from the actual generated source."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/source11')
START=time.monotonic_ns();seen={}
helper=(D/'verify_patch_generation_r4_2_terminal.py').read_bytes()
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[Root full-generation read primitives]','exec'),globals())
authority_raw=read(B/'AUTHORITY.json');a=json.loads(authority_raw)
assert pin(authority_raw)['git_blob']=='0b5693081591a95357591c7fa952ddd2738260a2'
launch_raw=read(B/'BINDING-LAUNCH.json');launch=json.loads(launch_raw)
assert pin(launch_raw)['git_blob']=='034b1ab7d33d2bbd9e99b15054af266755e3a27c'
assert fixed(launch['authority'])==authority_raw
handoff=data(B/'HANDOFF.json')
for row in handoff['entries']:fixed(row)
for row in a['controls']:fixed(row)
assert len(a['controls'])==65
binder=fixed(a['binder']);runner=fixed(a['runner'])
assert pin(binder)['git_blob']=='233c5d07e12e7f69de1c8defeef8d57a1465c3b6'
assert pin(runner)['git_blob']=='625229147d5f160a3c746c7b0a20d0fa0818539b'
assert runner==read('/tmp/hia-patch-result-owner-r4-dda7/authoring/run_controls.py')
def functions(raw):
 text=raw.decode();return {n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
bf=functions(binder);gf=functions(read('/tmp/hia-patch-result-owner-r4-dda7/authoring/run_generation_only_r4_2.py'))
s=data(B/'STATIC.json')
for name in s['readback_utility_exact_source_names']:assert bf[name]==gf[name],name
assignments={n.targets[0].id:n.value for n in ast.parse(binder).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
assert ast.literal_eval(assignments['STAGES'])==('source',)
assert a['stage_order']==['source'] and a['source_files']==3202
assert launch['argv']==[a['runtime']['launch_executable'],'-I','-B',str(B/'bind_source11.py'),'--authority',str(B/'AUTHORITY.json'),'--sha256',pin(authority_raw)['sha256'],'--bind','source']
assert launch['environment']==a['environment'] and launch['cwd']==str(B)
assert a['limits']=={'qualification_seconds':180,'cleanup_seconds':3,'native_compile_seconds':20,'native_cpu_seconds':10,'capacity':1048576,'vm_steps':10000000,'vm_heap_bytes':8388608,'vm_call_depth':128}
generation=a['generation']
gp=json.loads(fixed(generation['plan']));result_raw=fixed(generation['result']);result=json.loads(result_raw);fm=json.loads(fixed(generation['final_map']))
proof_raw=read(D/'patch-generation-r4-2-root-terminal.json');proof=json.loads(proof_raw)
assert pin(proof_raw)['git_blob']=='cecbb619eee747611684df2d874c598185ac33cf'
assert proof['actual_result']==pin(result_raw) and proof['actual_source_tree']==result['source_final_tree']==generation['final_tree']=='b86c073b441bf049ab294e5830b8c5d22fd2121a'
root=Path(generation['root']);final=data(root/'FINAL-SOURCE-OBSERVATION.json');base=json.loads(fixed(gp['base_capture']))
assert final['files']==fm and tree(fm)==generation['final_tree']
ni,source_bytes=capture_check(root/'source',final);bi,base_bytes=capture_check(Path(gp['base_source']),base)
assert len(ni)==3202 and len(bi)==3188 and ni.isdisjoint(bi) and all(x['nlink']==1 for x in final['stat'].values())
cp=json.loads(fixed(a['control_plan']));oldcp=data('/tmp/hia-patch-result-owner-r1-dda7/CONTROL-PLAN.json')
assert cp['source_ids'][:-1]==oldcp['source_ids'] and len(cp['source_ids'])==11 and cp['source_ids']==handoff['source_ids']
assert cp['native_ids']==oldcp['native_ids'] and cp['vm_ids']==oldcp['vm_ids'] and cp['original_cli43_ids']==oldcp['original_cli43_ids']
source_text=read(root/'source/tests/test_hia_patch_result_source.py')
cls=next(n for n in ast.parse(source_text).body if isinstance(n,ast.ClassDef) and n.name=='PatchResultSourceTests')
ids=['tests.test_hia_patch_result_source.PatchResultSourceTests.'+n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
assert ids==cp['source_ids']
runtime=json.loads(fixed(a['runtime_capture']));assert runtime==a['runtime']==gp['runtime']
for key in ('executable','library'):
 row=runtime[key];path=Path(row['path']).resolve();raw=read(path);info=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode),info.st_mtime_ns,info.st_ctime_ns]==[row['device'],row['inode'],row['mode'],row['mtime_ns'],row['ctime_ns']]
assert not os.path.lexists(launch['output']) and not os.path.lexists(a['evidence_root'])
parent=Path(a['output_parent']['path']);info=parent.lstat();assert [info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode)]==[a['output_parent']['device'],a['output_parent']['inode'],a['output_parent']['posix_mode']]
free=os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize
assert free>=1073741824
for path,previous in seen.items():assert seven(Path(path).lstat())==previous,path
report={'schema':'hepta.root.patch-source11-binding-preflight.v1','status':'PASS_READ_ONLY_NO_BINDER_NO_TEST','authority':pin(authority_raw),'launch':pin(launch_raw),'binder':pin(binder),'runner':pin(runner),'all_original_runner_bytes_equal':True,'all_original_read_utilities_full_text_equal':s['readback_utility_exact_source_names'],'all65_authority_controls_current':True,'source_files':3202,'source_bytes':source_bytes,'source_tree':generation['final_tree'],'all_current_source_and_base_full_bytes_modes_pathsets_seven_stats':True,'actual_generation_root_proof':pin(proof_raw),'source_ids':ids,'original_Source10_full_bodies_retained_plus_slice1':True,'source_test_generator_reproduction_is_inside_original_owner':True,'limits':a['limits'],'allowed_bind_launch_actions':['source'],'actual_free_bytes':free,'final_stat_checks':len(seen),'binder_calls':0,'test_calls':0,'native_compile_calls':0,'native_calls':0,'vm_calls':0,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();out=D/'patch-source11-root-binding-preflight.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'elapsed_seconds':report['elapsed_ns']/1e9},sort_keys=True))
