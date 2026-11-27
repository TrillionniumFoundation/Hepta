"""Root full raw/owners/frames/source readback; no product calls or writes to evidence."""
import ast,json,hashlib,os,stat,time
from pathlib import Path
ROOT=Path('/tmp/hia-u32-entry-layout-r1-dda7')
PLAN_RAW=(ROOT/'EXECUTION-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW);OUT=Path(PLAN['output']);SOURCE=Path(PLAN['source']['path']);DATA=OUT/'entry.evidence';CAPACITY=1<<20
STAT_KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
support_raw=(ROOT/'entry_support.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(support_raw)).encode()+b'\0'+support_raw).hexdigest()=='d2987513058771de3083e15f7c6bbc7a3d9bd26c'
selected={'require','pin','state','read_regular','identity','frame_inventory','owner_return','complete_owner'}
ns=ast.parse(support_raw);exec(compile(ast.Module(body=[n for n in ns.body if isinstance(n,ast.FunctionDef) and n.name in selected],type_ignores=[]),'[frozen read-only support definitions]','exec'),globals())
def dump(path,value):assert json.loads(Path(path).read_bytes())==value
def obj(path):return json.loads(Path(path).read_bytes())
start=time.monotonic_ns()
raw=obj(OUT/'RAW-INVENTORY.json');assert len(raw['files'])==830 and raw['logical_bytes']==173880184
actual=set()
for folder,dirs,files in os.walk(OUT,followlinks=False):
 for n in dirs:assert stat.S_ISDIR((Path(folder)/n).lstat().st_mode)
 actual.update((Path(folder)/n).relative_to(OUT).as_posix() for n in files)
assert actual==set(raw['files'])|{'RAW-INVENTORY.json'}
for n,row in raw['files'].items():assert identity(OUT/n)==row
assert sum(r['bytes'] for r in raw['files'].values())==raw['logical_bytes']
o=obj(OUT/'OUTER.json');r=obj(OUT/'RESULT.json')
assert o['status']==r['status']=='PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY' and o['child']==r
assert o['finalization_errors']==r['finalization_errors']==[] and o['product_retries']==r['product_retries']==0
assert r['entry_projection_calls']==1 and o['owner_launch_intents']==1
assert r['entry']['checks']==r['entry']['passing']==20 and r['entry']['failing_ids']==[]
assert r['entry']['ordered_check_ids']==PLAN['expected']['check_ids']
assert r['entry']['call_counts']==PLAN['expected']['call_counts']
rep=obj(OUT/'ENTRY-REPORT.json')
assert list(rep['checks'])==PLAN['expected']['check_ids'] and all(v is True for v in rep['checks'].values())
assert rep['references_completed_before_native_compilation'] is True and len(rep['references'])==4
assert rep['all_input_correctness_proved'] is False and rep['whole_stack_rewrite_complete'] is False
journal=obj(OUT/'CALL-INDEX.json');calls=journal['calls']
assert len(calls)==77 and journal['counts']==PLAN['expected']['call_counts']
assert journal['all_original_bindings_restored'] is True and journal['missing_results_synthesized'] is False
assert [row['index'] for row in calls]==list(range(77)) and all(row['status']=='RETURNED' for row in calls)
events=[json.loads(line) for line in (OUT/'CALLS.jsonl').read_text().splitlines()]
assert len(events)==154
for call in calls:
 pair=[e for e in events if e['index']==call['index']]
 assert len(pair)==2 and [e['event'] for e in pair]==['start','stop']
 assert {k:v for k,v in pair[1].items() if k!='event'}==call
 assert call['finished_monotonic_ns']>=call['started_monotonic_ns']
refs=[c for c in calls if c['kind']=='reference'];comp=[c for c in calls if c['kind']=='compile']
assert len(refs)==8 and max(c['finished_monotonic_ns'] for c in refs)<min(c['started_monotonic_ns'] for c in comp)
assert all(c['max_steps_default']==1000000 and c['explicit_max_steps_not_supplied'] is True for c in refs)
for kind,key in [('compile','compile_labels'),('invoke','invoke_labels'),('tool','link_labels'),('executable','executable_labels')]:
 assert [c['label'] for c in calls if c['kind']==kind]==PLAN['expected'][key]
for c in calls:
 for key in ('image','produced'):
  if key in c:assert identity(c[key+'_path'])==c[key]
owner=obj(OUT/'OWNER-RETURNED.json')
assert o['owner']==owner
owner_return(OUT/'OWNER.json',owner);complete_owner(owner,180)
request=obj(OUT/'OWNER.json.request.json');intent=obj(OUT/'LAUNCH-INTENT.json')
assert request['command']==intent['command'] and request['env']==intent['env']==PLAN['environment']
assert request['cwd']==intent['cwd']==str(SOURCE)
assert hashlib.sha256((OUT/'OWNER.json.request.json').read_bytes()).hexdigest()==owner['request_sha256']
assert owner['cleanup']['errors']==[] and owner['cleanup']['remaining_direct_children']==[] and owner['cleanup']['elapsed_ns']<=3000000000
assert owner['historical_descendant_inventory_complete'] is False
bridges=obj(OUT/'runtime-bridges/INDEX.json')
assert bridges['calls_started']==4 and len(bridges['calls'])==4 and bridges['original_run_owned_restored'] is True
for b in bridges['calls']:
 assert b['status']=='RETURNED'
 d=Path(b['path']);q=obj(d/'REQUEST.json');v=obj(d/'RETURNED.json');done=obj(d/'RESULT.json')
 complete_owner(v,15)
 assert q['qualification_seconds']==15 and q['cleanup_seconds']==3 and q['command'][4]==str(SOURCE/'tools/hia_selfhost_cli_child.py')
 assert done['status']=='RETURNED' and done['original_environment_unchanged'] is True
 for k,value in q.items():
  if k!='status':assert done[k]==value
 paths=[OUT/n for n,row in raw['files'].items() if row['sha256']==v['receipt_sha256']]
 assert len(paths)==1
 owner_return(paths[0],v)
 actual_request=Path(str(paths[0])+'.request.json')
 assert pin(actual_request.read_bytes())['sha256']==v['request_sha256']
 qq=obj(actual_request);assert qq['command']==q['command'] and qq['env']==q['effective_child_environment']
 assert v['cleanup']['errors']==[] and v['cleanup']['elapsed_ns']<=3000000000
frames=frame_inventory(True)
assert frames['count']==frames['complete_count']==32
source_before=obj(OUT/'SOURCE-OUTER-BEFORE.json');manifest=obj(ROOT/'FROZEN-3180-SOURCE.json')
assert source_before['files']==manifest and source_before['tree']==PLAN['source']['tree']
for name in ['SOURCE-CHILD-BEFORE.json','SOURCE-CHILD-AFTER.json','SOURCE-OUTER-AFTER.json']:assert obj(OUT/name)==source_before
found=set()
for folder,dirs,files in os.walk(SOURCE,followlinks=False):
 for n in dirs:assert stat.S_ISDIR((Path(folder)/n).lstat().st_mode)
 found.update((Path(folder)/n).relative_to(SOURCE).as_posix() for n in files)
assert found==set(manifest) and len(found)==3180
for n,row in manifest.items():
 data,mode,stamp=read_regular(SOURCE/n)
 assert pin(data,mode)==row and stamp==source_before['inode_states'][n]
control={}
for n,row in PLAN['controls'].items():
 control[n]=identity(row['path']);assert control[n]==row['identity']
for name in ['CONTROLS-PREFLIGHT.json','CONTROLS-CHILD-BEFORE.json','CONTROLS-CHILD-AFTER.json','CONTROLS-OUTER-AFTER.json']:assert obj(OUT/name)==control
assert (OUT/'PLAN.json').read_bytes()==PLAN_RAW and (ROOT/'EXECUTION-PLAN.json').read_bytes()==PLAN_RAW
for row in PLAN['runtime'].values():assert identity(row.get('resolved_path',row['path']))==row['identity']
for row in PLAN['toolchain'].values():assert identity(row['path'])==row['identity']
runtime=obj(OUT/'RUNTIME-PREFLIGHT.json')
assert runtime['environment']==PLAN['environment']
for name in ['RUNTIME-CHILD-BEFORE.json','RUNTIME-CHILD-AFTER.json','RUNTIME-OUTER-AFTER.json']:assert obj(OUT/name)==runtime
for a,b in [('ORIGINAL-FUNCTIONS-BEFORE.json','FUNCTIONS-CHILD-AFTER.json'),('PROJECTION-CHILD-BEFORE.json','PROJECTION-CHILD-AFTER.json')]:assert obj(OUT/a)==obj(OUT/b)
launchout=obj(ROOT/'LAUNCH.stdout')
assert launchout['status']==o['status'] and launchout['elapsed_ns']==o['elapsed_ns'] and launchout['raw']==dict(files=830,logical_bytes=173880184)
stderr=(ROOT/'LAUNCH.stderr').read_bytes()
assert b"SyntaxWarning: 'return' in a 'finally' block" in stderr and b'Traceback' not in stderr
proof=dict(schema='hepta.root-u32-entry20-terminal-readback.v1',status='PASS_FULL_ACTUAL_RAW_20_CHECKS_32_FRAMES_AND_CURRENT_SOURCE',
 actual_session=1207,actual_exit_code=0,product_elapsed_ns=o['elapsed_ns'],child_elapsed_ns=r['elapsed_ns'],
 plan=pin(PLAN_RAW),outer=pin((OUT/'OUTER.json').read_bytes()),child=pin((OUT/'RESULT.json').read_bytes()),
 raw_inventory=pin((OUT/'RAW-INVENTORY.json').read_bytes()),raw_files=830,raw_bytes=173880184,complete_raw_pathset=True,
 actual_call_index_entries=77,actual_call_events=154,call_counts=journal['counts'],checks=20,passing=20,
 all_eight_original_budget_VM_references_completed_before_first_native=True,VM_reference_default_steps=1000000,
 actual_32_complete_six_buffers=True,full_frame_files=256,ELF_internal_workspaces_observed=False,
 exact_outer_owner_180_plus_3_and_four_ELF_owners_15_plus_3=True,all_five_owners_ECHILD=True,
 historical_descendant_inventory_complete=False,source_files=3180,source_tree=PLAN['source']['tree'],
 four_full_source_guards_and_current_full_bytes_modes_seven_stats=True,controls_full_bytes_modes=len(control),
 original_function_and_projection_guards_equal=True,actual_clean_environment=runtime['environment'],
 original_runtime_tools_full_bytes_modes=True,launch_stderr=pin(stderr),launch_stderr_observation="Preserved frozen runner SyntaxWarning about return-in-finally; actual exit 0 and complete owner/frame checks passed.",
 original_unittest_method_executed=False,ordinary_encoding_qualification='NOT_RUN',matching_current_new_cold=False,
 product_retries=0,reader_product_calls=0,whole_native=False,production_legacy_retired=False,
 reader_elapsed_ns=time.monotonic_ns()-start)
proof_path=Path('/tmp/hia-root-v141-dda7/ROOT-U32-ENTRY-TERMINAL.json')
with proof_path.open('x') as f:f.write(json.dumps(proof,sort_keys=True,indent=2)+'\n')
print(json.dumps(proof,sort_keys=True))
