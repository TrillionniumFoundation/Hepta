"""Root independent full actual R8 compilation/packing and twelve-buffer readback."""
import ast,hashlib,json,os,stat,struct,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');A=Path('/tmp/hia-u32-r8-size-pack-r1-dda7');R=A/'evidence/attempt-r1';O=Path('/tmp/hia-root-u32-r8-size-pack-dda7')
START=time.monotonic_ns();seen={}
helper=(D/'verify_u32_r8_size_pack_preflight.py').read_bytes()
m=ast.parse(helper)
exec(compile(ast.Module(body=[n for n in m.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[Root reviewed read-only helpers]','exec'),globals())
p=data(A/'EXECUTION-PLAN.json');plan_raw=read(A/'EXECUTION-PLAN.json')
assert pin(plan_raw)['git_blob']=='cd6f29f4abce41ed360ac5edb3a1a914af48d794' and read(R/'PLAN.json')==plan_raw
assert read(R/'RUNNER.py')==read(A/'run_size_pack.py')
launch=data(A/'COMMAND-INTENT.json')
result_raw=read(R/'RESULT.json');result=json.loads(result_raw);outer=data(R/'OUTER.json');root_outer=data(O/'OUTER.json')
status='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
assert result['status']==outer['status']==status and outer['child']==outer['actual_child_result']==result
assert not result['finalization_errors'] and not outer['finalization_errors']
assert result['compile_calls_attempted']==result['pack_calls_attempted']==outer['compile_calls_attempted']==outer['pack_calls_attempted']==1
assert outer['owner_launch_intents']==1
for k in ('semantic_native_cases','semantic_vm_cases','aggregate_cases','ELF_exec_calls'):assert result[k]==0
for k in ('automatic_retry','whole_native','qualification','matching_current_new_cold','ordinary_compiler_admission','production_profile_changed','ordinary_SOURCE_rebound'):assert result[k] is False
assert root_outer['status']=='EXITED' and root_outer['returncode']==0 and root_outer['execution_attempts']==1 and not root_outer['automatic_retry']
assert root_outer['launch']==pin(read(A/'COMMAND-INTENT.json')) and root_outer['authorization']['git_blob']=='d01e895e7eb600c87e355a085bda8bc54615c958'
for name in ('stdout.raw','stderr.raw'):read(O/name,root_outer[name])
warning=read(O/'stderr.raw')
assert warning==read(R/'child.stderr.bin') and warning==b"/tmp/hia-u32-r8-size-pack-r1-dda7/run_size_pack.py:193: SyntaxWarning: 'return' in a 'finally' block\n  return 1\n"
assert json.loads(read(R/'child.stdout.bin'))==result
snapshots=[data(R/n) for n in ('SOURCE-OUTER-BEFORE.json','SOURCE-CHILD-BEFORE.json','SOURCE-CHILD-AFTER.json','SOURCE-OUTER-AFTER.json')]
assert all(x==snapshots[0] for x in snapshots)
snapshot=snapshots[0];source=Path(p['source']['path']);expected=data(A/'FROZEN-3180-SOURCE.json')
assert snapshot['files']==expected and len(expected)==3180 and tree(expected)==snapshot['tree']==p['source']['tree']=='4c62be4ed66ff107fa6f88c6131313a354868bd9'
names=set();source_bytes=0
for folder,dirs,files in os.walk(source,followlinks=False):
 for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
 for name in files:names.add((Path(folder)/name).relative_to(source).as_posix())
assert names==set(expected)
for name,row in expected.items():
 raw=read(source/name,row);source_bytes+=len(raw);assert stamp((source/name).lstat())==snapshot['inode_states'][name]
for row in p['controls'].values():read(row['path'],row['identity'])
for row in p['runtime'].values():read(row['path'],row['identity'])
inputs=data(A/'INPUTS.json');assert len(inputs['files'])==36
for row in inputs['files']:
 assert read(A/row['captured'],row['captured_identity'])==read(row['origin'],row['origin_identity'])
 assert stamp(Path(row['origin']).lstat())==row['origin_stat']
for stem in ('CONTROLS','INPUTS','PROJECTION','RUNTIME'):
 values=[data(R/(stem+'-PREFLIGHT.json')),data(R/('CHILD-'+stem+'.json')),data(R/(stem+'-CHILD-AFTER.json')),data(R/(stem+'-OUTER-AFTER.json'))]
 assert all(x==values[0] for x in values),stem
 if stem=='RUNTIME':
  assert values[0]['environment']==p['environment']
  assert [values[0][k] for k in ('isolated','ignore_environment','no_site','dont_write_bytecode')]==[1,1,1,1]
 if stem=='CONTROLS':assert values[0]=={k:row['identity'] for k,row in p['controls'].items()}
owner_raw=read(R/'OWNER.json');owner=json.loads(owner_raw);returned=data(R/'OWNER-RETURNED.json')
oreq_raw=read(R/'OWNER.json.request.json');oreq=json.loads(oreq_raw);intent=data(R/'LAUNCH-INTENT.json')
assert returned==outer['owner']==dict(owner,receipt_sha256=hashlib.sha256(owner_raw).hexdigest(),supervisor_returncode=0)
assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and not owner['timed_out'] and owner['exit_observed_before_deadline']
assert owner['qualification_seconds']==oreq['qualification_seconds']==intent['qualification_seconds']==180
assert owner['cleanup_seconds']==oreq['cleanup_seconds']==intent['cleanup_seconds']==3
assert oreq['deadline_ns']-oreq['started_ns']==180000000000
assert owner['request_sha256']==hashlib.sha256(oreq_raw).hexdigest()
assert owner['implementation_sha256']==hashlib.sha256(read(source/'tools/hia_selfhost_process_owner.py')).hexdigest()
assert oreq['command']==intent['command']==launch['argv']+['--child']
assert oreq['cwd']==intent['cwd']==str(source) and oreq['env']==intent['env']==intent['supervisor_env']==p['environment']
cleanup=owner['cleanup'];assert cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped'] and not cleanup['remaining_direct_children'] and not cleanup['errors'] and cleanup['elapsed_ns']<=3000000000
assert owner['historical_descendant_inventory_complete'] is False
r8=read(R/'R8.u32.image.bin',result['image']);elf=read(R/'R8.private-nonexecuted.elf.bin',result['ELF'])
assert len(r8)==549866 and len(elf)==1044480 and stat.S_IMODE((R/'R8.private-nonexecuted.elf.bin').stat().st_mode)==0o644
controller=read(A/'inputs/retained/controller.image.bin');representation=read(A/'inputs/retained/representation.image.bin')
package=read(R/'packer-input.bin');images=(controller,representation,r8)
assert package==struct.pack('<6Q',int.from_bytes(b'HFRTPAK1','little'),1,*map(len,images),0)+b''.join(images)
assert len(package)==1040064
size=data(R/'SIZE-ADMISSION.json');assert size==result['size']
assert size['actual_reduction_bytes']==562746-len(r8)==12880
assert size['frame_admitted'] and size['ELF_admitted'] and size['actual_frame_bytes']==len(package) and size['required_aligned_ELF_bytes']==len(elf)
# Pure byte inspection by the retained original contract; no HIA/native/ELF execution.
ns={}
exec(compile(read(A/'retained_pack_contract.py'),'[retained byte inspection only]','exec'),ns)
assert ns['_elf_structure'](elf,images)==result['elf_inspection']
frame_inventory=data(R/'ACTUAL-FRAMES.json')
assert frame_inventory==result['actual_frames'] and frame_inventory['attempted_compiles']==frame_inventory['attempted_packs']==1 and frame_inventory['require_complete'] is True and len(frame_inventory['buffer_files'])==12
for path,row in frame_inventory['buffer_files'].items():read(R/path,row)
calls=[]
for label,image_path,source_bytes_,produced,key in (
 ('compile-r8',A/'inputs/u32/B3.image.bin',read(A/'inputs/R8.hepta'),r8,'compile'),
 ('pack-r8',A/'inputs/retained/packer.image.bin',package,elf,'pack')):
 f=R/label;c=R/'frames'/label
 image=read(image_path);request_raw=read(f/'request.json');request=json.loads(request_raw)
 child_raw=read(f/'CHILD-REPORT.json');child=json.loads(child_raw)
 observation_raw=read(f/'OBSERVATION.json');observation=json.loads(observation_raw)
 frame_raw=read(c/'FRAME.json');frame=json.loads(frame_raw);summary=result[key]
 assert frame['status']=='CAPTURED_ALL_SIX' and not frame['errors'] and frame['label']==label and frame['image']==pin(image)
 assert request['image']==str(image_path) and request['image_sha256']==pin(image)['sha256'] and request['mode']=='ordinary' and request['report']==str(f/'CHILD-REPORT.json')
 assert child['status']=='returned' and child['result_u64']==len(produced) and child['forbidden_modules_loaded']==[]
 assert child['image_sha256']==pin(image)['sha256'] and child['request_sha256']==pin(request_raw)['sha256']
 assert child['limits']=={'wall_seconds':20,'cpu_seconds':10,'source_output_workspace_bytes':1048576,'address_bytes':268435456,'stack_bytes':8388608,'core_dumpable':False}
 assert child['whole'] is False and child['matched_cold'] is False
 assert observation['child']==child and observation['returncode']==0 and not observation['timed_out'] and observation['timeout_seconds']==20 and observation['cleanup_seconds']==3
 assert observation['canaries']==[True,True,True] and observation['stdout_hex']==observation['stderr_hex']=='' and observation['stdin_consumed']==0
 for filename in ('stdin.bin','stdout.bin','stderr.bin'):assert read(f/filename)==b''
 assert len(request['buffers'])==3
 for name,before_expected,row in zip(('source','output','workspace'),(source_bytes_,b'\xa5'*1048576,bytes(1048576)),request['buffers'],strict=True):
  before=read(c/(name+'.before.bin'));after=read(c/(name+'.after.bin'));physical=read(f/(name+'.shared'))
  assert before==before_expected and frame['before'][name]==pin(before)
  assert row=={'path':str(f/(name+'.shared')),'bytes':len(before)+128,'sha256':pin(b'\xd3'*64+before+b'\xd3'*64)['sha256'],'extent':len(before)}
  assert physical==b'\xd3'*64+after+b'\xd3'*64 and len(after)==len(before)
  assert frame['after'][name]=={'logical':pin(after),'physical':pin(physical),'mode':0o644,'canaries':True}
  assert after.hex()==observation[name+'_hex']
  if name=='source':assert after==before
  if name=='output':assert after[:len(produced)]==produced and after[len(produced):]==before[len(produced):]
 assert summary['returned']==len(produced) and summary['image']==pin(image) and summary['source']==pin(source_bytes_)
 assert summary['request']==pin(request_raw,0o644) and summary['child_report']==pin(child_raw,0o644) and summary['observation']==pin(observation_raw,0o644) and summary['frames']==pin(frame_raw,0o644)
 assert all(summary[x] is True for x in ('six_complete_buffers','three_canaries','source_unchanged','output_tail_unchanged'))
 calls.append({'label':label,'result_bytes':len(produced),'native_elapsed_ns':child['native_elapsed_ns'],'six_full_buffers':True,'physical_canaries':3,'wall_limit_seconds':20,'cpu_limit_seconds':10})
index=data(R/'RAW-INDEX.json');assert index['count']==len(index['files'])==70 and index['excludes_this_index_itself'] is True
actual_paths={p.relative_to(R).as_posix() for p in R.rglob('*') if p.is_file()}
assert actual_paths==set(index['files'])|{'RAW-INDEX.json'}
for path,row in index['files'].items():read(R/path,row)
assert index['raw_bytes']==sum(row['bytes'] for row in index['files'].values())
inventory={}
for root,label in ((R,'actual'),(O,'root-outer')):
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:
   path=Path(folder)/name;raw=read(path)
   inventory[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'mode':stat.S_IMODE(path.stat().st_mode),'seven_stat':stamp(path.lstat())}
for path,previous in seen.items():assert stamp(Path(path).lstat())==previous,path
iraw=(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode()
with (D/'u32-r8-size-pack-root-inventory.json').open('xb') as f:f.write(iraw)
proof={'schema':'hepta.root.u32-r8-size-pack-terminal.v1','status':'PASS_ACTUAL_SIZE_AND_PRIVATE_PACK_ONLY','actual_session':93012,'outer_exit_code':0,'outer_elapsed_ns':root_outer['elapsed_ns'],'actual_result':pin(result_raw),'image':pin(r8),'ELF':pin(elf),'ELF_mode':0o644,'image_reduction_bytes':12880,'original_ELF_capacity':1048576,'actual_frame_bytes':len(package),'ELF_capacity_remaining_bytes':1048576-len(elf),'all_actual_twelve_full_buffers_read':True,'calls':calls,'single_original_owner_180_plus_3_ECHILD':True,'historical_descendant_inventory_complete':False,'four_full_source_captures_equal':True,'all3180_current_source_bytes_modes_pathsets_tree_and_seven_stats':True,'source_tree':tree(expected),'all36_inputs_and16controls_and_runtime_full_bytes_current':True,'original_SyntaxWarning_retained':pin(warning),'actual_raw_files':len(inventory),'actual_raw_bytes':sum(x['pin']['bytes'] for x in inventory.values()),'inventory':pin(iraw),'all_unique_final_stat_checks':len(seen),'semantic_native':0,'semantic_VM':0,'aggregate_cases':0,'ELF_exec':0,'product_calls_by_reader':0,'matching_current_cold':False,'ordinary_SOURCE_rebound':False,'production_R5_pin_changed':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode();out=D/'u32-r8-size-pack-root-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'raw_files':len(inventory),'raw_bytes':proof['actual_raw_bytes'],'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
