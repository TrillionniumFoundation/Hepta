import pathlib,subprocess,os,json,time,hashlib,traceback,signal
root=pathlib.Path('/home/qian-qi/work/hia-seven-ndu-20261104')
out=pathlib.Path('/home/qian-qi/work/hia-seven-raw-native-20261104-r2')
upstream=pathlib.Path('/home/qian-qi/work/hia-ndu-pin-8e52-object-mirror-r6.git')
previous=pathlib.Path('/home/qian-qi/work/hia-seven-raw-native-20261104-r1')
python='/home/qian-qi/work/hia-tools-20261103/venv/bin/python';cargo='/home/qian-qi/.cargo/bin/cargo'
expected='99d4cb5942755ba12e1d3006558bb53d435734d8';pin='8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
started=time.monotonic_ns();out.mkdir(exist_ok=False)
def write(name,value):(out/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
env=dict(os.environ);env.update(RUSTUP_TOOLCHAIN='1.95.0',RUSTC='/home/qian-qi/.cargo/bin/rustc',CARGO_NET_OFFLINE='true',CARGO_TARGET_DIR=str(out/'target'),CARGO_BUILD_JOBS='2',PYTHONDONTWRITEBYTECODE='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
def git(path,*args):return subprocess.check_output(['git',*args],cwd=path,env=env,text=True,timeout=15).strip()
rows=[];failure=None
try:
 assert git(root,'rev-parse','HEAD')==expected and git(root,'status','--porcelain=v1')==''
 assert git(upstream,'rev-parse','--verify',pin+'^{commit}')==pin
 assert git(upstream,'rev-parse','--is-bare-repository')=='true'
 assert git(upstream,'remote')==''
 source={'head':expected,'tree':git(root,'rev-parse','HEAD^{tree}'),'ndu_commit':pin,'ndu_input_kind':'preexisting local bare object mirror; no remote; selected archive blobs are verified by builder','python_planner_sha256':sha(root/'hepta/hia_ndu_cost.py'),'rustc':subprocess.check_output([env['RUSTC'],'-vV'],env=env,text=True),'cargo':subprocess.check_output([cargo,'--version'],env=env,text=True)}
 assert source['rustc'].startswith('rustc 1.95.0 '),source['rustc']
 write('SOURCE_BEFORE.json',source)
 prior=json.loads((previous/'OUTER.json').read_bytes())
 write('PREVIOUS_ATTEMPT.json',{'path':str(previous),'outer_receipt_sha256':sha(previous/'OUTER.json'),'outer_wall_ns':prior['wall_ns'],'status':'failed: build command exceeded 180 seconds before output directory existed','native_build_receipt_present':(previous/'build/build-receipt.json').exists(),'failed_build_command_streams_status':'not retained by r1 outer timeout handler; unavailable, not empty','cost_scope':'earlier setup/test/build attempt, additional to this new attempt and excluded from build() receipt B; do not omit from enclosing preparation ledger'})
 write('INVOCATION.json',{'schema':'hepta.hia.raw-model.fresh-qualification-invocation.v1','source':str(root),'expected_head':expected,'upstream':str(upstream),'python':python,'cargo':cargo,'environment':{k:env[k] for k in ('RUSTUP_TOOLCHAIN','RUSTC','CARGO_NET_OFFLINE','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','PYTHONDONTWRITEBYTECODE','GIT_NO_LAZY_FETCH','GIT_TERMINAL_PROMPT')},'historical_binary_reused':False,'new_target_initially_absent':not (out/'target').exists(),'source_mirror_acquisition_cost':'preexisting input; not measured in this new build; no machine-cold/full-lifecycle claim'})
 def command(name,args,timeout):
  before=time.monotonic_ns();exc=None;process=None;timed_out=False
  stdout=out/(name+'.stdout.raw');stderr=out/(name+'.stderr.raw')
  with stdout.open('xb') as outlog,stderr.open('xb') as errlog:
   try:
    process=subprocess.Popen(args,cwd=root,env=env,stdout=outlog,stderr=errlog,start_new_session=True)
    process.wait(timeout=timeout)
   except BaseException as error:
    exc=error;timed_out=isinstance(error,subprocess.TimeoutExpired)
    if process is not None and process.poll() is None:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  row={'name':name,'argv':args,'returncode':process.returncode if process else None,'outer_wall_ns':time.monotonic_ns()-before,'timed_out':timed_out,'exception':None if exc is None else type(exc).__name__+': '+str(exc),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)};rows.append(row);write('COMMANDS.json',rows)
  if exc is not None:raise exc
  if process.returncode:raise RuntimeError(name+' failed with code '+str(process.returncode))
 command('build',[python,'-B','tools/build_hia_raw_model_bridge.py','--upstream',str(upstream),'--output',str(out/'build'),'--cargo',cargo],180)
 manifest=json.loads((out/'build/build-receipt.json').read_bytes());binary=out/'target/release/hia-ndu-bridge'
 assert manifest['upstream']['commit']==pin and manifest['rustc_version'].startswith('rustc 1.95.0 ')
 assert manifest['original_rust_sources_unchanged'] is True and manifest['all_original_non_manifest_inputs_unchanged'] is True
 assert manifest['binary_sha256']==sha(binary)
 assert manifest['build_cost']['completed'] is True and manifest['build_cost']['wall_ns']>0
 command('native-qualification',[python,'-B','tools/qualify_hia_raw_model.py','--binary',str(binary),'--build',str(out/'build/build-receipt.json'),'--output',str(out/'qualification'),'--include-stream'],120)
 q=json.loads((out/'qualification/qualification.json').read_bytes());assert q['status']=='passed' and q['tests']==22 and q['failures']==q['errors']==q['skipped']==0
 assert q['registered_random_models']==128 and q['completed_random_model_ids']==list(range(128)) and q['inputs_unchanged'] is True
 assert git(root,'rev-parse','HEAD')==expected and git(root,'status','--porcelain=v1')==''
 assert git(upstream,'rev-parse','--verify',pin+'^{commit}')==pin
 write('SOURCE_AFTER.json',source)
except BaseException as e:
 failure={'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()};write('ERROR.json',failure)
finally:
 result={'schema':'hepta.hia.raw-model.fresh-qualification-outer.v1','completed':failure is None,'source_head':expected,'wall_ns':time.monotonic_ns()-started,'commands':rows,'failure':failure,'performance_measured':False,'historical_results_reused':False,'previous_failed_attempt':str(previous),'scope':'new outer setup, clean source/tool admission, isolated Rust build and actual native correctness/refusal; preexisting source mirror/dependency cache preparation and r1 failure are separately recorded, not zero; excludes enclosing worker launch and final report write'};write('OUTER.json',result)
 print(json.dumps({'completed':result['completed'],'output':str(out),'source':expected,'commands':[{k:r[k] for k in ('name','returncode','outer_wall_ns')} for r in rows],'failure':failure},indent=2),flush=True)
if failure:raise SystemExit(1)
