"""Complete read-only Root Source11 owner/test and full-source terminal review."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/source11');K=B/'bindings/01-source11';R=Path('/dev/shm/hia-patch-result-controls-r1-dda7/01-source11');O=Path('/tmp/hia-root-patch-source11-execution-dda7')
START=time.monotonic_ns();seen={}
helper=(D/'verify_patch_generation_r4_2_terminal.py').read_bytes()
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[read-only complete generation helpers]','exec'),globals())
praw=read(K/'PLAN.json');p=json.loads(praw);a=data(B/'AUTHORITY.json')
assert pin(praw)['git_blob']=='eae7ac743a06f4856b39af333ff9764223765dea'
outer_raw=read(R/'OUTER.json');outer=json.loads(outer_raw);child_raw=read(R/'CHILD-RESULT.json');child=json.loads(child_raw)
tests_raw=read(R/'TESTS.json');tests=json.loads(tests_raw);root_outer=data(O/'OUTER.json')
assert root_outer['status']=='EXITED' and root_outer['returncode']==0 and root_outer['execution_attempts']==1 and not root_outer['automatic_retry']
assert root_outer['authorization']['git_blob']=='24e388402c8aa4f83b31d96677513606aa08d62c'
assert outer['status']==child['status']==tests['status']=='PASS' and outer['owner_launch_attempts']==1 and outer['child']==child and child['tests']==tests
assert child['kind']=='source' and child['source_files']==3202 and child['source_unchanged'] and child['controls_unchanged']
assert tests['declared']==tests['loaded']==tests['started']==tests['stopped']==p['ids'] and len(p['ids'])==tests['count']==11
assert tests['events']==[row for name in p['ids'] for row in (['start',name],['stop',name])]
assert len(tests['subtests'])==15 and all(row['ok'] for row in tests['subtests'])
assert not any(tests[name] for name in ('errors','failures','skipped','expected_failures','unexpected_successes','loader_errors'))
assert child['python']==p['runtime_context']['python'] and not child['default_activated'] and not child['matching_current_cold']
for name in ('stdout.raw','stderr.raw'):read(O/name,root_outer[name])
assert read(O/'stdout.raw')==read(O/'stderr.raw')==b''
owner_raw=read(R/'OWNER.json');owner=json.loads(owner_raw);returned=outer['owner']
assert returned==dict(owner,receipt_sha256=hashlib.sha256(owner_raw).hexdigest(),supervisor_returncode=0)
assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and not owner['timed_out'] and owner['exit_observed_before_deadline']
assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3 and owner['historical_descendant_inventory_complete'] is False
cleanup=owner['cleanup'];assert cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped'] and not cleanup['remaining_direct_children'] and not cleanup['errors'] and cleanup['elapsed_ns']<=3000000000
request_raw=read(R/'OWNER.json.request.json');request=json.loads(request_raw);launch=data(R/'LAUNCH.json');exec_intent=data(K/'LAUNCH-INTENT.json')
assert hashlib.sha256(request_raw).hexdigest()==owner['request_sha256']
assert request['deadline_ns']-request['started_ns']==180000000000 and request['qualification_seconds']==180 and request['cleanup_seconds']==3
assert request['cwd']==p['source'] and request['env']==launch['environment']==a['environment'] and launch['limits']==p['limits'] and launch['runtime_context']==p['runtime_context']
command=[p['runtime_context']['launch_executable'],'-I','-B',str(B/'run_controls.py'),'--child',str(K/'PLAN.json'),'--sha256',pin(praw)['sha256']]
assert request['command']==launch['command']==command
assert exec_intent['command']==[p['runtime_context']['launch_executable'],'-I','-B',str(B/'run_controls.py'),'--plan',str(K/'PLAN.json'),'--sha256',pin(praw)['sha256']]
assert exec_intent['kind']=='source' and exec_intent['environment']==a['environment']
assert owner['implementation_sha256']==hashlib.sha256(read(Path(p['source'])/'tools/hia_selfhost_process_owner.py')).hexdigest()
for row in p['controls']:read(row['path'],row['pin'])
for row in a['controls']:fixed(row)
fm=data(p['source_map']);capture=data(K/'SOURCE-AFTER.json')
assert fm==capture['files'] and len(fm)==3202 and tree(fm)==a['generation']['final_tree']=='b86c073b441bf049ab294e5830b8c5d22fd2121a'
inodes,source_bytes=capture_check(Path(p['source']),capture);assert len(inodes)==3202 and all(s['nlink']==1 for s in capture['stat'].values())
for key in ('executable','library'):
 row=p['runtime_context'][key];path=Path(row['path']).resolve();raw=read(path);s=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns,s.st_ctime_ns]==[row['device'],row['inode'],row['mode'],row['mtime_ns'],row['ctime_ns']]
inventory={}
for root,label in ((R,'source11'),(O,'root-outer'),(K,'binding')):
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:
   path=Path(folder)/name;raw=read(path)
   inventory[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'mode':stat.S_IMODE(path.lstat().st_mode),'seven_stat':seven(path.lstat())}
for path,previous in seen.items():assert seven(Path(path).lstat())==previous,path
iraw=(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode()
with (D/'patch-source11-root-inventory.json').open('xb') as f:f.write(iraw)
report={'schema':'hepta.root.patch-source11-terminal.v1','status':'PASS_ACTUAL_ORIGINAL_SOURCE11','actual_session':28469,'outer_exit_code':0,'outer_elapsed_ns':root_outer['elapsed_ns'],'actual_plan':pin(praw),'actual_tests':pin(tests_raw),'actual_child':pin(child_raw),'actual_group_outer':pin(outer_raw),'methods':11,'events':22,'subtests':15,'all_original10_methods_plus_slice1_retained':True,'all_declared_loaded_started_stopped_ids_exact_order':True,'all_errors_failures_skips_expected_failures_unexpected_successes_empty':True,'single_owner_seconds':180,'cleanup_seconds':3,'authoritative_ECHILD_cleanup':True,'historical_descendant_inventory_complete':False,'source_test_original_generation_reproduction_retained':True,'all3202_current_source_full_bytes_modes_pathsets_seven_stats_and_nlink1':True,'source_tree':tree(fm),'source_bytes':source_bytes,'all89_bound_and65_authority_controls_current_full_bytes':True,'fixed_runtime_current':True,'raw_files':len(inventory),'raw_bytes':sum(row['pin']['bytes'] for row in inventory.values()),'inventory':pin(iraw),'all_unique_final_stat_checks':len(seen),'Native_test_methods':0,'VM_test_methods':0,'native_compile_stages':0,'products_by_reader':0,'matching_current_cold':False,'default_activated':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();out=D/'patch-source11-root-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'raw_files':len(inventory),'raw_bytes':report['raw_bytes'],'elapsed_seconds':report['elapsed_ns']/1e9},sort_keys=True))
