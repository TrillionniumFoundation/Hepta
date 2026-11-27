"""Root complete read-only final finite PatchResult gate receipt."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/vm12-r3');R=B/'bindings/05-final-readback';O=Path('/tmp/hia-root-patch-vm12-r3-finish-dda7')
START=time.monotonic_ns();seen={}
helper=(D/'verify_patch_generation_r4_2_terminal.py').read_bytes()
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[Root complete read primitives]','exec'),globals())
araw=read(B/'AUTHORITY.json');a=json.loads(araw)
assert pin(araw)['git_blob']=='b277e061c45f6ace1074177261f9747958cddad7'
assert pin(read(B/'bind_vm12.py'))['git_blob']=='827b1caabac47aeb1fb61795fba02c205d45941d'
outer_raw=read(O/'OUTER.json');outer=json.loads(outer_raw);lraw=read(O/'LAUNCH.json');launch=json.loads(lraw)
assert outer['status']=='EXITED' and outer['returncode']==0 and outer['readback_attempts']==1 and outer['product_calls']==0 and not outer['automatic_retry']
assert outer['launch']==pin(lraw) and pin(lraw)['git_blob']=='94b9ab3edf51ccffaff657242cf814adeac73e46'
assert outer['authorization']==pin(read(O/'AUTHORIZATION.json')) and outer['authorization']['git_blob']=='2ad59ce911ece7ba8c824b313a1df5c001d96f05'
assert launch['argv']==[a['runtime']['launch_executable'],'-I','-B',str(B/'bind_vm12.py'),'--authority',str(B/'AUTHORITY.json'),'--sha256',pin(araw)['sha256'],'--finish']
assert launch['cwd']==str(B) and launch['environment']==a['environment'] and launch['product_calls']==0 and launch['output']==str(R)
for name in ('stdout.raw','stderr.raw'):read(O/name,outer[name])
assert read(O/'stderr.raw')==b''
rraw=read(R/'RESULT.json');report=json.loads(rraw);rows=data(R/'READBACK-INVENTORY.json')['files']
assert report['schema']=='hepta.hia.patch-result.finite-gates-readback.v1' and report['status']=='PASS'
assert report['source_unchanged'] and report['source_files']==3202 and report['source_methods']==11 and report['actual_compile_calls']==1 and report['native_methods']==report['vm_methods']==12
assert report['product_operations']=={'native_compile':0,'native_calls':0,'vm_calls':0,'tests':0,'default_activation':0}
assert not report['matching_current_cold'] and not report['default_activated'] and not report['whole_runtime'] and not report['all_native_frames_replayed']
native_raw=read(D/'patch-native12-root-terminal.json');native=json.loads(native_raw)
vm_raw=read(D/'patch-vm12-r3-root-terminal.json');vm=json.loads(vm_raw)
assert pin(native_raw)['git_blob']=='fe37a923933c139c7f5e7f191f9dadd439072e55' and pin(vm_raw)['git_blob']=='99d7f25a5146fe002182d2deb63c78addf7a9c83'
assert report['native_observations']==native['actual_frames']
assert report['finite_vm_readback']=={'frames':12,'max_actual_steps':vm['maximum_actual_VM_steps'],'full_six_spans_per_case':True,'all_native_frames_replayed':False}
assert len({r['path'] for r in rows})==len(rows)
for row in rows:
 fixed(row);s=Path(row['path']).lstat()
 assert {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'nlink':s.st_nlink}==row['stat']
capture=data(R/'SOURCE-AFTER.json');fm=json.loads(fixed(a['generation']['final_map']))
assert fm==capture['files'] and len(fm)==3202 and tree(fm)==report['source_tree']==a['generation']['final_tree']=='b86c073b441bf049ab294e5830b8c5d22fd2121a'
ids,source_bytes=capture_check(Path(a['generation']['root'])/'source',capture);assert len(ids)==3202
for row in a['controls']:fixed(row)
for key in ('executable','library'):
 row=a['runtime'][key];path=Path(row['path']).resolve();raw=read(path);s=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns,s.st_ctime_ns]==[row['device'],row['inode'],row['mode'],row['mtime_ns'],row['ctime_ns']]
assert {p.name for p in R.iterdir()}=={'RESULT.json','READBACK-INVENTORY.json','SOURCE-AFTER.json'}
inventory={}
for root,label in ((R,'finish'),(O,'root-outer')):
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:
   path=Path(folder)/name;raw=read(path);s=path.lstat()
   inventory[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'mode':stat.S_IMODE(s.st_mode),'seven_stat':seven(s)}
for path,before in seen.items():assert seven(Path(path).lstat())==before,path
iraw=(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode()
with (D/'patch-finite-gates-root-inventory.json').open('xb') as f:f.write(iraw)
proof={'schema':'hepta.root.patch-finite-gates-terminal.v1','status':'PASS_ACTUAL_SOURCE11_BUILD_NATIVE12_VM12_FINITE_CHAIN','metadata_session':63613,'metadata_outer_exit':0,'metadata_outer_elapsed_ns':outer['elapsed_ns'],'actual_result':pin(rraw),'actual_outer':pin(outer_raw),'source_methods':11,'compile_stages':1,'native_methods':12,'VM_methods':12,'all_actual_predecessors_full_current_readback_rows':len(rows),'current_source_files':3202,'current_source_tree':tree(fm),'current_source_bytes':source_bytes,'all_native_frames_replayed':False,'all_frames_retired':False,'observed_fault_quarantines_retained':native['lost_claim_quarantine_retained'],'maximum_VM_steps':vm['maximum_actual_VM_steps'],'VM_step_limit':10000000,'all_source_controls_runtime_full_current':True,'raw_files':len(inventory),'raw_bytes':sum(r['pin']['bytes'] for r in inventory.values()),'inventory':pin(iraw),'all_unique_final_stat_checks':len(seen),'products_by_finish':0,'products_by_root_reader':0,'matching_current_cold':False,'default_activated':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode();out=D/'patch-finite-gates-root-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'raw_files':len(inventory),'raw_bytes':proof['raw_bytes'],'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
