import ast,hashlib,json,os,stat
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35')
A=Path('/tmp/hia-inspect-drive-source18-r3-dda7')
E=Path('/dev/shm/hia-inspect-drive-r3-dda7/source-controls-attempt-r1')
O=E.parent/'source-controls-outer-r1'
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-DRIVE-R3-SOURCE18-TERMINAL.json')
raw=(R/'v95-audit-mount-r1/v140-progress/verify_source18_proposal.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()=='c932413d529442b855043d13afb3e4d6aefa0973'
t=ast.parse(raw);ns={}
exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'<root-read-only-helpers>','exec'),ns)
read,obj,tree=ns['read'],ns['obj'],ns['tree']
def pin(p):return read(p)[1]
def bound(row):
 raw,got,st=read(row['path']);assert got==row['pin']
 if 'posix_mode' in row:assert st['mode']==row['posix_mode']
 return json.loads(raw)
p=obj(A/'SOURCE-PLAN.json');launch=obj(A/'SOURCE-LAUNCH.json');r=obj(E/'RESULT.json');outer=obj(O/'OUTER.json')
assert pin(E/'RESULT.json')['git_blob']=='66a7fcb126e87224d171b6869be08e28e2d1cec6'
assert pin(A/'SOURCE-PLAN.json')['git_blob']=='ec2ce52faca4281d43151be0242186450e4acfd9'
assert pin(A/'run_inspect_stages.py')==p['runner'] and p['runner']['git_blob']=='cd9cecf3321a0b7a1e1a8717e08962deeca487e6'
assert (E/'PLAN-USED.json').read_bytes()==(A/'SOURCE-PLAN.json').read_bytes()
assert r['status']=='SOURCE_CONTROLS_PASS' and r['phase']=='source-controls' and r['owner_launch_attempts']==2
assert r['complete_source_guard_pass'] and r['source_phase_has_no_compiler_Native_or_VM_invocation']
assert not any(r[k] for k in ['CLI_op10_connected','matching_current_cold','whole_cli_native','original3_or_CLI43_executed'])
assert r['source_tree']==p['source']['tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96' and r['source_files']==3188
assert r['generation_result_pin']==p['inputs']['generation_result']['pin'] and r['plan_pin']==pin(A/'SOURCE-PLAN.json')
assert outer['returncode']==0 and outer['status']=='OUTER_EXIT_ZERO' and not outer['automatic_retry']
assert outer['argv']==launch['argv'] and outer['cwd']==launch['cwd'] and outer['launch_git']==pin(A/'SOURCE-LAUNCH.json')['git_blob']
assert outer['plan_sha256']==pin(A/'SOURCE-PLAN.json')['sha256']
assert (outer['qualification_seconds_per_owner'],outer['cleanup_seconds_per_owner'],outer['new_compile_Native_VM'])==(180,3,0)
assert outer['entry_available_bytes']>=1073741824 and outer['output_filesystem']==p['evidence_authority']
for key in ['outer_stdout','outer_stderr']:
 row=outer[key];got=pin(Path(row['path']));assert row['bytes']==got['bytes'] and row['sha256']==got['sha256']
for row in r['evidence']:
 raw,got,st=read(row['path']);assert got==row['pin'] and st['mode']==row['posix_mode']
assert len(r['evidence'])==49
assert {str(x) for x in E.rglob('*') if x.is_file()}=={row['path'] for row in r['evidence']}|{str(E/'RESULT.json')}
outer_files=[x for x in O.rglob('*') if x.is_file()]
for path in outer_files:read(path)
captures={k:bound(v) for k,v in p['inputs'].items()}
assert r['runtime']==obj(E/'RUNTIME.json')==p['runtime']==captures['generation_runtime']
inodes={}
for role,key in [('base','base_final'),('predecessor','predecessor_final'),('source','source_final')]:
 root=Path(p[role]['path']);capture=captures[key];assert not capture['errors']
 assert len(capture['files'])==p[role]['files'] and tree(capture['files'])==p[role]['tree']
 seen=set();inodes[role]=set()
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:seen.add((Path(folder)/name).relative_to(root).as_posix())
 assert seen==set(capture['files'])
 for name,expected in capture['files'].items():
  raw,got,st=read(root/name);assert got==expected and st==capture['stat'][name],role+'/'+name
  inodes[role].add((st['device'],st['inode']))
  if role=='source':assert st['nlink']==1
assert len(inodes['source'])==3188 and not inodes['source']&(inodes['base']|inodes['predecessor'])
guards=list(E.rglob('GUARD-*.json'));assert len(guards)==10
for path in guards:
 g=obj(path);assert g['all_bytes_and_seven_stat_fields']
 assert bound(g['base'])==captures['base_final'] and bound(g['predecessor'])==captures['predecessor_final'] and bound(g['source'])==captures['source_final']
assert [x['label'] for x in r['stages']]==p['source_group_order']
rows=[]
for stage in r['stages']:
 label=stage['label'];group=p['groups'][label];d=Path(stage['directory']);child=obj(d/'child/RESULT.json')
 request=obj(d/'REQUEST.json');command=obj(d/'COMMAND.json');owner=obj(d/'OWNER.json');returned=obj(d/'OWNER-RETURNED.json');oreq=obj(d/'OWNER.json.request.json')
 assert stage['status']=='PASS' and stage['source_guard_pass'] and pin(d/'child/RESULT.json')==stage['child_result_pin']
 assert child['status']=='PASS' and child['request_pin']==pin(d/'REQUEST.json') and child['all_original_and_generated_source_bytes_modes_stats_unchanged']
 assert child['Native_compilation']==child['VM_group_execution']==0 and not child['matching_current_cold'] and not child['old3_or_CLI43_executed']
 assert request['group']==label and request['ids']==group['ids'] and request['runtime_context']==p['runtime'] and request['plan_sha256']==pin(A/'SOURCE-PLAN.json')['sha256']
 assert command['argv']==[p['runtime']['launch_executable'],'-I','-B',str(A/'run_inspect_stages.py'),'--child',str(d/'REQUEST.json'),'--request-sha256',pin(d/'REQUEST.json')['sha256']]
 assert command['cwd']==p['source']['path'] and oreq['command']==command['argv'] and oreq['cwd']==command['cwd'] and oreq['env']==command['environment']
 assert command['environment']==command['supervisor_environment'] and command['environment']['TMPDIR']==str(E/'tmp') and command['environment']['LD_LIBRARY_PATH']==p['runtime']['library_directory'] and 'LD_PRELOAD' not in command['environment']
 for x in [command,owner,oreq]:assert x['qualification_seconds']==180 and x['cleanup_seconds']==3
 assert returned==stage['owner_returned'] and returned['supervisor_returncode']==0 and returned['receipt_sha256']==pin(d/'OWNER.json')['sha256']
 assert {k:v for k,v in returned.items() if k not in ['supervisor_returncode','receipt_sha256']}==owner and owner['request_sha256']==pin(d/'OWNER.json.request.json')['sha256']
 assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and not owner['timed_out'] and owner['exit_observed_before_deadline'] and not owner['event_overflow'] and not owner['interrupted_signals']
 clean=owner['cleanup'];assert clean['complete'] and clean['observed_echild'] and clean['leader_reaped'] and not clean['deadline_exceeded'] and not clean['errors'] and not clean['remaining_direct_children'] and clean['elapsed_ns']<=3000000000
 tests=obj(d/'child/TESTS.json');assert tests==child['tests']==stage['tests'] and tests['status']=='PASS'
 for k in ['declared_ids','loaded_ids','started_ids','stopped_ids']:assert tests[k]==group['ids']
 assert tests['tests_run']==len(group['ids']) and tests['events']==[[event,name] for name in group['ids'] for event in ['start','stop']]
 for k in ['errors','expected_failures','failures','loader_errors','skipped','unexpected_successes']:assert not tests[k]
 sub=obj(d/'child/SUBTESTS.json');assert sub==stage['subtests'] and sub['ordinary_TextTestResult_restored'] and sub['no_foreign_repr_added']
 assert sub['declared_method_projection']==group['subtest_method_projection']
 actual=sub['actual_subtests'];assert len(actual)==group['expected_subtests'] and [x['method_id'] for x in actual]==group['subtest_method_projection']
 assert [x['ordinal'] for x in actual]==list(range(1,len(actual)+1)) and all(x['success'] is True and x['exception_type'] is None for x in actual)
 if label=='source8-physical-lease':assert [x['parameters'] for x in actual]==group['subtest_parameters']
 rows.append(dict(label=label,methods=len(group['ids']),events=len(tests['events']),subtests=len(actual),owner=pin(d/'OWNER.json'),tests=pin(d/'child/TESTS.json'),subtest_record=pin(d/'child/SUBTESTS.json'),cleanup_ns=clean['elapsed_ns'],final_ECHILD=True,historical_descendant_inventory_complete=owner['historical_descendant_inventory_complete']))
for key in ['executable','library']:
 row=p['runtime'][key];raw,got,st=read(row['path']);assert got['bytes']==row['bytes'] and got['sha256']==row['sha256']
 for field in ['device','inode','mode','mtime_ns','ctime_ns']:assert st[field]==row[field]
report=dict(schema='hepta.root-drive-r3-source18-terminal-readback.v1',actual_session=9085,status='PASS_ALL_ACTUAL_SOURCE18_AND_CURRENT_SOURCE_READBACK',result=pin(E/'RESULT.json'),outer=pin(O/'OUTER.json'),plan=pin(A/'SOURCE-PLAN.json'),runner=p['runner'],stages=rows,methods=18,events=36,subtests=21,evidence_files_full_pins=49,complete_attempt_file_pathset=True,outer_files_read=len(outer_files),complete_parent_child_guard_maps=10,base_files=3187,predecessor_files=3188,source_files=3188,source_tree=p['source']['tree'],all_current_bytes_modes_seven_stats_exact=True,all_private_inodes_unique_nlink1_disjoint_from_both_old_trees=True,runtime_actual_full_bytes_and_stats=True,outer_elapsed_ns=outer['elapsed_ns'],output_filesystem=p['evidence_authority'],compile_Native_VM_op10=0,matching_current_cold=False,whole_native=False,new_products_by_this_reader=0)
with OUT.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(status=report['status'],report=str(OUT),pin=pin(OUT))))
