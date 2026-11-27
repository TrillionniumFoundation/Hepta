from pathlib import Path
import os,sys,json,time,hashlib,subprocess,shutil,traceback
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
for name,pin in spec['all_source_pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
assert hashlib.sha256(spec['c_source'].encode()).hexdigest()==spec['c_pin']['sha256']
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.environ['TMPDIR']='/home/qian-qi/hia-bootstrap-closure-20261127-2807/temporary'
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import read_originals
out=data/'source-diagnostics-v5-late-preload'
out.mkdir(mode=0o700)
build=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/native-late-preload-v1')
build.mkdir(mode=0o700)
before=s.source_snapshot();assert before==spec['all_source_pins']
(build/'late-observer.c').write_text(spec['c_source'])
s.write_json(out/'invocation.json',spec)
cc=shutil.which('cc');assert cc
command=[cc,'-std=gnu11','-O2','-fPIC','-shared','-Wall','-Wextra',
         str(build/'late-observer.c'),'-ldl','-o',str(build/'late-observer.so')]
with (out/'compile.stdout').open('xb') as stdout,(out/'compile.stderr').open('xb') as stderr:
 compiled=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=60)
assert compiled.returncode==0,compiled.returncode
s.write_json(out/'compile.json',{'command':command,'returncode':compiled.returncode,
 'source':s.file_pin(build/'late-observer.c'),'image':s.file_pin(build/'late-observer.so'),
 'stdout':s.file_pin(out/'compile.stdout'),'stderr':s.file_pin(out/'compile.stderr'),
 'development_observer_only':True,'native_source_authority':False})
def env(lane):
 value=os.environ.copy()
 value.update({'LD_PRELOAD':str(build/'late-observer.so'),
  'HIA_BOOTSTRAP_DIAG_LATE_FILE':str(out/lane/'late-events.jsonl'),
  'HIA_BOOTSTRAP_DIAG_TRACE_FILE':str(out/(lane+'-stack.jsonl'))})
 return value
smoke=out/'smoke';smoke.mkdir()
smoke_code="import os\ncurrent_id='smoke'\ndef run():\n current_id='smoke'\n with open(os.environ['HIA_BOOTSTRAP_DIAG_LATE_FILE'],'xb',buffering=0) as f:\n  f.write(b'{\"smoke\":true}\\n')\nrun()\n"
with (out/'smoke.stdout').open('xb') as stdout,(out/'smoke.stderr').open('xb') as stderr:
 smoked=subprocess.run([sys.executable,'-I','-B','-c',smoke_code],env=env('smoke'),stdout=stdout,stderr=stderr,timeout=15)
assert smoked.returncode==0,smoked.returncode
smoke_rows=[json.loads(line) for line in (out/'smoke-stack.jsonl').read_bytes().splitlines()]
assert len(smoke_rows)==1 and smoke_rows[0]['row']=={'smoke':True}
assert any(frame.get('current_id')=='smoke' for frame in smoke_rows[0]['stack'])
print(json.dumps({'event':'late_preload_compile_smoke','image':s.file_pin(build/'late-observer.so'),'stack':s.file_pin(out/'smoke-stack.jsonl')},sort_keys=True),flush=True)
original,raw,inputs,input_raw,captured,(expected_dir,expected_report)=read_originals(Path(spec['authority']),spec['authority_pin'])
assert original['base_count']==232 and original['count']==15830
record={'schema':'hepta.hia.bootstrap-native-late-stack-diagnostic.v1',
 'diagnostic_only':True,'original_source_suite_executed':False,
 'whole_native_stack_qualified':False,'native_source_authority':False,
 'observer_source_unchanged':True,'source_before':before,'lanes':{}}
started=time.monotonic()
try:
 for lane in ('original','unselected'):
  args=[sys.executable,'-I','-B','tests/hia_service_bootstrap_observer.py',
        '--lane',lane,'--inputs',str(Path(spec['authority']).parent/'complete-inputs.json'),'--output',str(out/lane)]
  if lane!='original':args+=['--expected',spec['authority'],'--expected-sha256',spec['authority_pin']['sha256'],'--expected-bytes',str(spec['authority_pin']['bytes'])]
  receipt,report,checkpoint=s.run_child(out,lane,args,seconds=600 if lane=='original' else 1800,env=env(lane))
  assert report['count']==15830 and report['ordered_ids']==original['ordered_ids'] and report['input']==original['complete_inputs']
  assert report['source_before']==before and report['source_after']==before
  assert report['native_or_VM_entries']==0 and report['unraisables']==[] and report['differences']==0
  assert receipt['stderr']['bytes']==0 and receipt['timeout'] is False and receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
  actual=s.file_pin(out/lane/'observations.jsonl')
  business=s.identical_files(expected_dir/'observations.jsonl',out/lane/'observations.jsonl',expected_report['files']['observations.jsonl'],actual)
  baseline=expected_dir if lane=='original' else data/'isolated-current-v2-full-unselected/unselected/candidate'
  actual_late=s.file_pin(out/lane/'late-events.jsonl')
  late=s.identical_files(baseline/'late-events.jsonl',out/lane/'late-events.jsonl',spec['baseline_late'][lane],actual_late)
  traces=[json.loads(row) for row in (out/(lane+'-stack.jsonl')).read_bytes().splitlines()]
  late_rows=[json.loads(row) for row in (out/lane/'late-events.jsonl').read_bytes().splitlines()]
  assert [row['row'] for row in traces]==late_rows
  record['lanes'][lane]={'business_baseline_exact':business,'late_baseline_exact':late,
    'late_events':actual_late,'stack':s.file_pin(out/(lane+'-stack.jsonl')),
    'traces':traces,'owned_receipt':s.file_pin(out/(lane+'.result.json'))}
  print(json.dumps({'event':'native_late_stack_lane_terminal','lane':lane,'business_baseline_exact':business,'late_baseline_exact':late,'stack_rows':len(traces),'seconds':time.monotonic()-started},sort_keys=True),flush=True)
 for path,content in captured:s.exact_reread(path,content)
 record['status']='DIAGNOSTIC_COMPLETE'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'native_late_stack_diagnostic_terminal','status':record['status'],'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='DIAGNOSTIC_COMPLETE' else 1)
