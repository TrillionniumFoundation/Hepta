"""Read actual Source11 binding and all current authorities before one owner."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/source11');R=B/'bindings/01-source11';O=Path('/tmp/hia-root-patch-source11-binding-dda7')
START=time.monotonic_ns();seen={}
helper=(D/'verify_patch_generation_r4_2_terminal.py').read_bytes()
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[read-only full-source primitives]','exec'),globals())
authority_raw=read(B/'AUTHORITY.json');a=json.loads(authority_raw);ready=data(R/'READY.json')
assert ready['status']=='READY_FOR_EXPLICIT_ROOT_EXECUTE' and ready['kind']=='source' and not ready['product_executed_by_binding']
praw=read(R/'PLAN.json',ready['plan_pin']);p=json.loads(praw)
braw=read(R/'BINDING-RESULT.json',ready['binding_result_pin']);bound=json.loads(braw)
launch_raw=read(R/'LAUNCH.json');launch=json.loads(launch_raw)
assert bound['status']=='PASS' and bound['kind']=='source' and bound['source_unchanged'] and bound['prior_completed']==[]
assert bound['source_tree']==ready['source_tree']==a['generation']['final_tree']=='b86c073b441bf049ab294e5830b8c5d22fd2121a'
assert bound['product_operations']=={'native_compile':0,'native_calls':0,'vm_calls':0,'tests':0,'default_activation':0}
assert p['kind']=='source' and p['status']=='BOUND_TO_ACTUAL_PREDECESSORS' and p['context']=={} and p['limits']==a['limits']
cp=json.loads(fixed(a['control_plan']));assert p['ids']==cp['source_ids'] and len(p['ids'])==11
assert p['binding_authority_sha256']==ready['authority_sha256']==bound['authority_sha256']==pin(authority_raw)['sha256']
assert p['generation_result_pin']==a['generation']['result']['pin'] and p['source']==a['generation']['root']+'/source'
assert p['output']==a['evidence_root']+'/01-source11' and p['runtime_context']==a['runtime']
assert p['runner_pin']==pin(fixed(a['runner']))
assert p['source_map']==a['generation']['final_map']['path'] and p['source_map_pin']==pin(fixed(a['generation']['final_map']))
assert launch['argv']==[a['runtime']['launch_executable'],'-I','-B',str(B/'bind_source11.py'),'--authority',str(B/'AUTHORITY.json'),'--sha256',pin(authority_raw)['sha256'],'--launch','source']
assert launch['cwd']==str(B) and launch['environment']==a['environment'] and launch['limits']==a['limits'] and launch['kind']=='source'
assert launch['plan_pin']==pin(praw) and launch['ready_pin']==pin(read(R/'READY.json'))
inventory=data(R/'READBACK-INVENTORY.json')
assert inventory['product_modules_imported']==[] and inventory['generator_compiler_vm_or_test_calls']==0 and len(inventory['files'])==123
for row in inventory['files']:
 fixed(row);s=Path(row['path']).lstat()
 actual={'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'nlink':s.st_nlink}
 assert actual==row['stat']
assert len(p['controls'])==89
for row in p['controls']:read(row['path'],row['pin'])
before=data(R/'SOURCE-BEFORE.json');after=data(R/'SOURCE-AFTER.json');assert before==after
fm=data(p['source_map']);assert before['files']==fm and len(fm)==3202 and tree(fm)==bound['source_tree']
ids,source_bytes=capture_check(Path(p['source']),after);assert len(ids)==3202
outer=data(O/'OUTER.json');assert outer['status']=='EXITED' and outer['returncode']==0 and outer['binding_attempts']==1 and outer['product_calls']==0 and not outer['automatic_retry']
assert outer['authorization']['git_blob']=='e0d4b91f6ff60a786882dc46146a91272cedbb3b'
for name in ('stdout.raw','stderr.raw'):read(O/name,outer[name])
assert not os.path.lexists(p['output']) and not os.path.lexists(R/'LAUNCH-INTENT.json')
for path,previous in seen.items():assert seven(Path(path).lstat())==previous,path
report={'schema':'hepta.root.patch-source11-bound-terminal.v1','status':'PASS_ACTUAL_SOURCE11_BOUND_NOT_EXECUTED','session':22822,'outer_exit_code':0,'outer_elapsed_ns':outer['elapsed_ns'],'actual_plan':pin(praw),'actual_launch':pin(launch_raw),'actual_binding_result':pin(braw),'all123_actual_readback_rows_full_bytes_modes_seven_stats':True,'all89_actual_product_controls_full_bytes_current':True,'all3202_current_source_bytes_modes_pathsets_seven_stats':True,'source_tree':tree(fm),'source_bytes':source_bytes,'original_Source11_ids':p['ids'],'limits':a['limits'],'binding_product_operations':bound['product_operations'],'final_stat_checks':len(seen),'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-START}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();out=D/'patch-source11-root-binding-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'elapsed_seconds':report['elapsed_ns']/1e9},sort_keys=True))
