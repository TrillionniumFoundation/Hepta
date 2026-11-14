import ast,collections,hashlib,json,os,stat,struct,sys,time,zlib
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35')
A=Path('/tmp/hia-inspect-source18-evidence-r2-dda7')
E=Path('/dev/shm/hia-inspect-stages-dda7/native-vm-attempt-r1')
D=Path('/tmp/hia-root-v141-dda7')
raw=(R/'v95-audit-mount-r1/v140-progress/verify_source18_proposal.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()=='c932413d529442b855043d13afb3e4d6aefa0973'
t=ast.parse(raw);ns={}
exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'<root-read-only-helpers>','exec'),ns)
read,obj,tree=ns['read'],ns['obj'],ns['tree']
def pinbytes(raw):return dict(bytes=len(raw),mode='100644',sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
def pin(path):return read(path)[1]
p=obj(A/'NATIVE-PLAN.json');launch=obj(A/'NATIVE-LAUNCH.json');r=obj(E/'RESULT.json');outer=obj(E.parent/'native-vm-outer-r1/OUTER.json')
assert pin(E/'RESULT.json')['git_blob']=='10905272bd3b83ff6025d8b3e7e53f229c1130ab'
assert pin(A/'NATIVE-PLAN.json')['git_blob']=='46a1c86949e63a242a4ead2bc14a73739e509b6b'
assert r['status']=='FAIL' and r['phase']=='native-vm' and r['owner_launch_attempts']==3 and r['halted_after_first_failed_group']
assert r['complete_source_guard_pass'] and r['source_tree']==p['source']['tree'] and r['source_files']==3188
assert r['plan_pin']==pin(A/'NATIVE-PLAN.json') and r['actual_source_predecessor']==obj(p['source_predecessor']['path'])
assert r['runtime']==p['runtime'] and not r['matching_current_cold'] and not r['whole_cli_native'] and not r['CLI_op10_connected']
assert not r['original3_or_CLI43_executed'] and r['historical_results_not_inherited']
assert outer['returncode']==1 and outer['status']=='FAIL' and not outer['automatic_retry']
assert outer['argv']==launch['argv'] and outer['cwd']==launch['cwd'] and outer['launch_git']==pin(A/'NATIVE-LAUNCH.json')['git_blob']
assert outer['qualification_seconds_per_owner']==180 and outer['cleanup_seconds_per_owner']==3
assert outer['output_filesystem']==p['evidence_authority'] and outer['entry_available_bytes']>=1073741824
assert outer['root_authorization']=='5c6e5f03e009ff0c9872ea8e66549e7a92cd4d89'
evidence_names=set()
for row in r['evidence']:
 raw,got,st=read(row['path']);assert got==row['pin'] and st['mode']==row['posix_mode'];evidence_names.add(row['path'])
assert len(evidence_names)==len(r['evidence'])==58127
current={str(x) for x in E.rglob('*') if x.is_file()}
assert current==evidence_names|{str(E/'RESULT.json')}
assert not (E/'NATIVE-VM-CATALOG.json').exists()
order=['build-inspect']+p['native_group_order']+p['vm_group_order']
assert [x['label'] for x in r['stages']]==order[:3]
for index,label in enumerate(order[3:],4):assert not (E/('%02d-%s'%(index,label))).exists()
captures={role:obj(p['inputs'][key]['path']) for role,key in [('base','base_final'),('source','source_final')]}
inodes={}
for role,capture in captures.items():
 root=Path(p[role]['path']);assert not capture['errors'] and tree(capture['files'])==p[role]['tree']
 seen=set();inodes[role]=set()
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:seen.add((Path(folder)/name).relative_to(root).as_posix())
 assert seen==set(capture['files'])
 for name,expected in capture['files'].items():
  raw,got,st=read(root/name);assert got==expected and st==capture['stat'][name],role+'/'+name
  inodes[role].add((st['device'],st['inode']))
  if role=='source':assert st['nlink']==1
assert len(inodes['source'])==3188 and not inodes['source']&inodes['base']
guards=list(E.glob('GUARD-*.json'));assert len(guards)==8
for path in guards:
 g=obj(path);assert g['all_bytes_and_seven_stat_fields']
 for role in ('base','source'):
  row=g[role];assert pin(row['path'])==row['pin'] and obj(row['path'])==captures[role]
rows=[];native_tests=[];journals=[];cross_by_nonce=collections.defaultdict(list)
for index,stage in enumerate(r['stages']):
 label=stage['label'];d=Path(stage['directory']);child=obj(d/'RESULT.json');request=obj(d/'REQUEST.json');command=obj(d/'COMMAND.json')
 owner=obj(d/'OWNER.json');returned=obj(d/'OWNER-RETURNED.json');oreq=obj(d/'OWNER.json.request.json')
 assert stage['source_guard_pass'] and stage['status']==('FAIL' if index==2 else 'PASS')
 assert child['status']==('FAIL' if index==2 else 'PASS') and child['request_pin']==pin(d/'REQUEST.json')
 assert child['source_unchanged'] and child['compiler_unchanged'] and child['source_before_tree']==child['source_after_tree']==p['source']['tree']
 assert request['group']==label and request['source']==p['source']['path'] and request['runtime_context']==p['runtime']
 assert command['argv']==oreq['command'] and command['cwd']==oreq['cwd']==p['source']['path'] and command['environment']==oreq['env']==command['supervisor_environment']
 for x in (command,owner,oreq):assert x['qualification_seconds']==180 and x['cleanup_seconds']==3
 assert returned==stage['owner_returned'] and returned['receipt_sha256']==pin(d/'OWNER.json')['sha256']
 assert {k:v for k,v in returned.items() if k not in ('receipt_sha256','supervisor_returncode')}==owner
 assert owner['request_sha256']==pin(d/'OWNER.json.request.json')['sha256']
 assert owner['returncode']==(1 if index==2 else 0) and owner['status']==('QUALIFICATION_FAILED' if index==2 else 'OWNED_PROCESS_COMPLETED')
 assert not owner['timed_out'] and owner['exit_observed_before_deadline'] and not owner['event_overflow'] and not owner['interrupted_signals']
 clean=owner['cleanup'];assert clean['complete'] and clean['observed_echild'] and clean['leader_reaped'] and not clean['deadline_exceeded'] and not clean['errors'] and not clean['remaining_direct_children'] and clean['elapsed_ns']<=3000000000
 row=dict(label=label,stage_status=stage['status'],child=pin(d/'RESULT.json'),owner=pin(d/'OWNER.json'),owner_status=owner['status'],returncode=owner['returncode'],cleanup_ns=clean['elapsed_ns'],final_ECHILD=True,historical_descendant_inventory_complete=owner['historical_descendant_inventory_complete'])
 if index==0:
  build=child['build'];assert build==stage['build'] and build['status']=='BUILT_AND_READ_BACK' and build['compile_seconds']==20 and build['capacity']==1048576
  assert build['complete_source_map_pin']==p['inputs']['source_map']['pin'] and not build['matching_current_cold']
  for b in build['observation_bindings']:
   raw,got,st=read(b['path']);assert got['bytes']==b['bytes'] and got['sha256']==b['sha256'] and st['mode']==b['mode']
  manifest=obj(build['manifest']);assert pin(build['manifest'])=={k:v for k,v in build['manifest_binding'].items() if k!='path'}
  assert build['image']['bytes']==120231 and build['image']['sha256']=='1458c7d482dda1370854ae32036d4d27ac1daff333454b639cdd956e97007cd1'
  row['image']=build['image'];row['full_post_call_compiler_workspace_claimed']=False
 else:
  tests=obj(d/'TESTS.json');assert tests==child['tests']
  for k in ('declared_ids','loaded_ids','started_ids','stopped_ids'):assert tests[k]==p['groups'][label]['ids']
  assert tests['tests_run']==len(tests['declared_ids']) and tests['events']==[[event,n] for n in tests['declared_ids'] for event in ('start','stop')]
  for k in ('failures','skipped','expected_failures','unexpected_successes','loader_errors'):assert not tests[k]
  if index==1:assert tests==stage['tests'] and tests['status']=='PASS' and not tests['errors']
  else:
   assert tests['status']=='FAIL' and len(tests['errors'])==1 and tests['errors'][0][0]==p['groups'][label]['ids'][1]
   assert 'result2 = self.owner.finish(second)' in tests['errors'][0][1] and 'native machine-plan observation lacks its actual acknowledgement' in tests['errors'][0][1]
  native_tests.extend(tests['started_ids']);row.update(tests=pin(d/'TESTS.json'),methods=tests['tests_run'],errors=len(tests['errors']))
  machine=d/'controls/machine';j=obj(machine/'INDEX.json');assert j['schema']=='hepta.hia.inspect-full-machine-frames.v1'
  assert j['started_calls']==j['complete_calls']==len(j['frames']) and j['all_source_unchanged']
  unique_buffers=set();full_bytes=0
  for f in j['frames']:
   assert f['index']==j['frames'].index(f) and f['source_unchanged'] and f['image_sha256']==build['image']['sha256']
   assert f==obj(machine/'frames'/('%08d-AFTER.json'%f['index']))
   before=obj(machine/'frames'/('%08d-BEFORE.json'%f['index']))
   assert before['returned'] is False
   for key,value in before.items():
    if key!='returned':assert f[key]==value
   for key in ('source_before','output_before','workspace_before','source_after','output_after','workspace_after'):
    b=f[key];assert b['file']==b['sha256']+'.zlib'
    if b['file'] not in unique_buffers:
     decoded=zlib.decompress(read(machine/'buffers'/b['file'])[0]);assert pinbytes(decoded)=={k:b[k] for k in ('bytes','mode','sha256','git_blob')}
     unique_buffers.add(b['file']);full_bytes+=len(decoded)
    if index==2 and f['case']=='cross-frame-and-repeated-claim' and key=='workspace_before':
     decoded=zlib.decompress(read(machine/'buffers'/b['file'])[0]);head=struct.unpack_from('<6Q',decoded);assert head[0]==f['command'];cross_by_nonce[head[1]].append([f['index'],head[0],f['result']])
  assert {x.name for x in (machine/'buffers').iterdir()}==unique_buffers
  journals.append(dict(label=label,index=pin(machine/'INDEX.json'),actual_complete_calls=len(j['frames']),full_original_before_after_records=True,unique_complete_buffers=len(unique_buffers),decoded_bytes=full_bytes,all_full_buffer_bytes_and_pins=True,VM_execution_by_reader=0))
 rows.append(row)
assert len(native_tests)==12
assert set(cross_by_nonce)=={3,4}
assert len(cross_by_nonce[3])==168 and cross_by_nonce[3][-1]==[504,1,5]
assert cross_by_nonce[4]==[[337,0,1],[505,4,4294967293]]
report=dict(schema='hepta.root-inspect-native-first-failure-readback.v1',status='CONFIRMED_ORIGINAL_NATIVE_PROTOCOL_FAILURE_NOT_QUALIFIED',result=pin(E/'RESULT.json'),outer=pin(E.parent/'native-vm-outer-r1/OUTER.json'),plan=pin(A/'NATIVE-PLAN.json'),source_tree=p['source']['tree'],stages=rows,compile_attempts=1,compile_pass=1,native_methods_run=12,native_methods_pass=11,native_method_errors=1,native_methods_not_started=5,VM_methods_run=0,VM_methods_not_started=12,all_actual58127_evidence_files_full_bytes_modes=True,evidence_bytes=sum(x['pin']['bytes'] for x in r['evidence']),all_current3187_3188_source_bytes_modes_seven_stats=True,source_guards=8,all_three_process_owners_clean_ECHILD=True,all_frames_retired=False,second_frame_actual_pending_never_claimed=True,second_frame_nonce4_actual_calls=cross_by_nonce[4],second_frame_retirement_return_4294967293_preserved=True,journals=journals,first_failure_stopped_following=True,automatic_retry=False,outer_elapsed_ns=outer['elapsed_ns'],whole_native=False,matching_current_cold=False,VM_or_native_products_by_reader=0,diagnosis='Original drive begins step unconditionally; actual second pending observation was never serviced. Existing missing-ack guard correctly refuses. A fix must use the original service/claim/effect/ack path and preserve unknown retirement.')
out=D/'ROOT-NATIVE-TERMINAL-FAILURE.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(status=report['status'],report=str(out),pin=pin(out),journals=journals)))
