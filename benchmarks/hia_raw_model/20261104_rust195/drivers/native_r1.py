import pathlib,subprocess,os,json,time,hashlib,traceback
root=pathlib.Path('/home/qian-qi/work/hia-seven-ndu-20261104')
out=pathlib.Path('/home/qian-qi/work/hia-seven-raw-native-20261104-r1')
upstream=pathlib.Path('/home/qian-qi/work/hia-ndu-native-20261103')
python='/home/qian-qi/work/hia-tools-20261103/venv/bin/python'
cargo='/home/qian-qi/.cargo/bin/cargo'
expected='99d4cb5942755ba12e1d3006558bb53d435734d8'
started=time.monotonic_ns(); out.mkdir(exist_ok=False)
def write(name,value): (out/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def git(path,*args):return subprocess.check_output(['git',*args],cwd=path,text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
env=dict(os.environ);env.update(RUSTUP_TOOLCHAIN='1.95.0',RUSTC='/home/qian-qi/.cargo/bin/rustc',CARGO_NET_OFFLINE='true',CARGO_TARGET_DIR=str(out/'target'),CARGO_BUILD_JOBS='2',PYTHONDONTWRITEBYTECODE='1')
rows=[]; failure=None
try:
 assert git(root,'rev-parse','HEAD')==expected
 assert git(root,'status','--porcelain=v1')==''
 assert git(upstream,'rev-parse','HEAD')=='8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
 assert git(upstream,'status','--porcelain=v1')==''
 source={'head':expected,'tree':git(root,'rev-parse','HEAD^{tree}'),'ndu_head':git(upstream,'rev-parse','HEAD'),'python_planner_sha256':sha(root/'hepta/hia_ndu_cost.py'),'rustc':subprocess.check_output([env['RUSTC'],'-vV'],env=env,text=True),'cargo':subprocess.check_output([cargo,'--version'],env=env,text=True)}
 assert source['rustc'].startswith('rustc 1.95.0 '),source['rustc']
 write('SOURCE_BEFORE.json',source)
 inv={'schema':'hepta.hia.raw-model.fresh-qualification-invocation.v1','source':str(root),'expected_head':expected,'upstream':str(upstream),'python':python,'cargo':cargo,'environment':{k:env[k] for k in ('RUSTUP_TOOLCHAIN','RUSTC','CARGO_NET_OFFLINE','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','PYTHONDONTWRITEBYTECODE')},'historical_binary_reused':False,'new_target_initially_absent':not (out/'target').exists()}
 write('INVOCATION.json',inv)
 def command(name,args,timeout):
  before=time.monotonic_ns();p=subprocess.run(args,cwd=root,env=env,capture_output=True,timeout=timeout)
  duration=time.monotonic_ns()-before
  (out/(name+'.stdout.raw')).write_bytes(p.stdout);(out/(name+'.stderr.raw')).write_bytes(p.stderr)
  row={'name':name,'argv':args,'returncode':p.returncode,'outer_wall_ns':duration,'stdout_sha256':sha(out/(name+'.stdout.raw')),'stderr_sha256':sha(out/(name+'.stderr.raw'))};rows.append(row);write('COMMANDS.json',rows)
  if p.returncode:raise RuntimeError(name+' failed with code '+str(p.returncode))
 command('unit-protocols',[python,'-B','-m','unittest','tests.test_hia_ndu_build_cost','tests.test_hia_raw_session_cost','tests.test_hia_ndu_bridge_isolation','-v'],120)
 command('build',[python,'-B','tools/build_hia_raw_model_bridge.py','--upstream',str(upstream),'--output',str(out/'build'),'--cargo',cargo],180)
 manifest=json.loads((out/'build/build-receipt.json').read_bytes()); binary=out/'target/release/hia-ndu-bridge'
 assert manifest['upstream']['commit']==source['ndu_head']
 assert manifest['rustc_version'].startswith('rustc 1.95.0 ')
 assert manifest['original_rust_sources_unchanged'] is True
 assert manifest['all_original_non_manifest_inputs_unchanged'] is True
 assert manifest['binary_sha256']==sha(binary)
 assert manifest['build_cost']['completed'] is True and manifest['build_cost']['wall_ns']>0
 command('native-qualification',[python,'-B','tools/qualify_hia_raw_model.py','--binary',str(binary),'--build',str(out/'build/build-receipt.json'),'--output',str(out/'qualification'),'--include-stream'],120)
 q=json.loads((out/'qualification/qualification.json').read_bytes());assert q['status']=='passed' and q['tests']==22 and q['failures']==q['errors']==q['skipped']==0
 assert q['registered_random_models']==128 and q['completed_random_model_ids']==list(range(128)) and q['inputs_unchanged'] is True
 assert git(root,'rev-parse','HEAD')==expected and git(root,'status','--porcelain=v1')==''
 assert git(upstream,'rev-parse','HEAD')==source['ndu_head'] and git(upstream,'status','--porcelain=v1')==''
 write('SOURCE_AFTER.json',source)
except BaseException as e:
 failure={'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()};write('ERROR.json',failure)
finally:
 result={'schema':'hepta.hia.raw-model.fresh-qualification-outer.v1','completed':failure is None,'source_head':expected,'wall_ns':time.monotonic_ns()-started,'commands':rows,'failure':failure,'performance_measured':False,'historical_results_reused':False,'scope':'outer setup, clean source/tool admission, protocol tests, isolated Rust build and actual native correctness/refusal; excludes enclosing runtime worker launch and final report write'};write('OUTER.json',result)
 print(json.dumps({'completed':result['completed'],'output':str(out),'source':expected,'commands':[{k:r[k] for k in ('name','returncode','outer_wall_ns')} for r in rows],'failure':failure},indent=2),flush=True)
if failure:raise SystemExit(1)
