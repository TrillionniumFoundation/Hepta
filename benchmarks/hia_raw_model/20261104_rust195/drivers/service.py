import pathlib,subprocess,os,json,time,hashlib,traceback,signal
root=pathlib.Path('/home/qian-qi/work/hia-seven-ndu-20261104')
output=pathlib.Path('/home/qian-qi/work/hia-seven-raw-service-cost-20261104-r1')
driver=pathlib.Path('/home/qian-qi/work/hia-seven-raw-service-cost-driver-20261104-r1')
buildroot=pathlib.Path('/home/qian-qi/work/hia-seven-raw-native-20261104-r2')
expected='99d4cb5942755ba12e1d3006558bb53d435734d8'
python='/home/qian-qi/work/hia-tools-20261103/venv/bin/python'
started=time.monotonic_ns();driver.mkdir(exist_ok=False)
def write(name,value):(driver/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=root,text=True,timeout=15).strip()
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RUSTUP_TOOLCHAIN='1.95.0')
rows=[];failure=None
try:
 assert git('rev-parse','HEAD')==expected and git('status','--porcelain=v1')==''
 binary=buildroot/'target/release/hia-ndu-bridge';receipt=buildroot/'build/build-receipt.json';manifest=json.loads(receipt.read_bytes())
 assert manifest['rustc_version'].startswith('rustc 1.95.0 ') and manifest['binary_sha256']==sha(binary)=='b44d1b2e83858cf379e3485f453c472e6d86d749b31d0f21e8921d5b53682198'
 invocation={'schema':'hepta.hia.raw-model.service-cost-outer-invocation.v1','source_head':expected,'source_tree':git('rev-parse','HEAD^{tree}'),'binary':str(binary),'binary_sha256':sha(binary),'build_receipt':str(receipt),'build_receipt_sha256':sha(receipt),'output':str(output),'protocol':'fixed four-arm v1: 24 models,31 rounds,2976 calls,744 quartets','attempt_policy':'single registered campaign; no retries or sample selection','host_context':'shared desktop host; root reports no concurrent performance benchmark or model inference, but small source tests/integration work and independent proof profiling may overlap; no exclusive-host, CPU pin, machine-cold or population inference claimed','prior_failed_build':str(pathlib.Path('/home/qian-qi/work/hia-seven-raw-native-20261104-r1')),'scope':'service comparison only; prior failed source extraction and preparation are separately retained and not erased or treated as zero'}
 write('INVOCATION.json',invocation)
 def command(name,args,timeout):
  before=time.monotonic_ns();exc=None;process=None
  so=driver/(name+'.stdout.raw');se=driver/(name+'.stderr.raw')
  with so.open('xb') as stdout,se.open('xb') as stderr:
   try:
    process=subprocess.Popen(args,cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
    process.wait(timeout=timeout)
   except BaseException as error:
    exc=error
    if process is not None and process.poll() is None:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  row={'name':name,'argv':args,'returncode':process.returncode if process else None,'outer_wall_ns':time.monotonic_ns()-before,'exception':None if exc is None else type(exc).__name__+': '+str(exc),'stdout_sha256':sha(so),'stderr_sha256':sha(se)};rows.append(row);write('COMMANDS.json',rows)
  if exc is not None:raise exc
  if process.returncode:raise RuntimeError(name+' failed with code '+str(process.returncode))
 command('freeze',[python,'-B','tools/measure_hia_raw_session_cost.py','freeze','--binary',str(binary),'--build',str(receipt),'--output',str(output)],30)
 command('run',[python,'-B','tools/measure_hia_raw_session_cost.py','run','--output',str(output)],180)
 result=json.loads((output/'RESULT.json').read_bytes())
 assert result['measurement_complete'] is True and result['attempted_calls']==2976 and result['failed_calls']==0 and result['error_count']==0 and result['completed_quartets']==744
 assert result['source_head']==expected and result['binary_sha256']==sha(binary)
 assert git('rev-parse','HEAD')==expected and git('status','--porcelain=v1')==''
except BaseException as error:
 failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()};write('ERROR.json',failure)
finally:
 final={'schema':'hepta.hia.raw-model.service-cost-outer.v1','completed':failure is None,'wall_ns':time.monotonic_ns()-started,'commands':rows,'failure':failure,'source_head':expected,'results':str(output),'scope':'registration plus single measured campaign and outer source checks; native build and prior failures separate; shared host, descriptive result only'};write('OUTER.json',final)
 print(json.dumps(final,indent=2),flush=True)
if failure:raise SystemExit(1)
