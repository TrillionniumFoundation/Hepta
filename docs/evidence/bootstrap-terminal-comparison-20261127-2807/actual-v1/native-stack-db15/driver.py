from pathlib import Path
import os,sys,json,time,hashlib,traceback
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-terminal-comparison-20261127-2807/src')
out=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-terminal-comparison-20261127-2807/c-stack-unselected-v1')
observer=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/native-late-preload-v1')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in spec['source_pins'].items():assert pin((root/name).read_bytes())==expected,name
for name,expected in spec['observer_pins'].items():assert pin((observer/name).read_bytes())==expected,name
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
out.mkdir(mode=0o700);temporary=out/'temporary';temporary.mkdir(mode=0o700)
os.environ['TMPDIR']=str(temporary);os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import read_originals
before=s.source_snapshot();assert before==spec['source_pins']
s.write_json(out/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-terminal-unselected-native-late-stack.v1',
 'source_before':before,'source_commit':spec['source_commit'],'diagnostic_only':True,
 'observer_source_unchanged':True,'original_source_suite_executed':False,
 'native_source_authority':False,'whole_native_stack_qualified':False,
 'observer_pins':spec['observer_pins'],'new_home_bytes':0}
started=time.monotonic()
try:
 authority,authority_raw,inputs,input_raw,captured,(original_dir,original_report)=read_originals(Path(spec['authority']),spec['authority_pin'])
 assert authority['base_count']==232 and authority['count']==15830
 baseline=Path(spec['baseline_unselected'])
 baseline_late=(baseline/'late-events.jsonl').read_bytes()
 assert pin(baseline_late)==spec['baseline_unselected_late']
 assert s.file_pin(original_dir/'observations.jsonl')==spec['business_pin']
 environment=os.environ.copy()
 environment.update({'LD_PRELOAD':str(observer/'late-observer.so'),
  'HIA_BOOTSTRAP_DIAG_LATE_FILE':str(out/'candidate/late-events.jsonl'),
  'HIA_BOOTSTRAP_DIAG_TRACE_FILE':str(out/'candidate-stack.jsonl')})
 command=[sys.executable,'-I','-B','tests/hia_service_bootstrap_observer.py',
  '--lane','unselected','--inputs',str(Path(spec['authority']).parent/'complete-inputs.json'),
  '--output',str(out/'candidate'),'--expected',spec['authority'],
  '--expected-sha256',spec['authority_pin']['sha256'],'--expected-bytes',str(spec['authority_pin']['bytes'])]
 receipt,report,raw=s.run_child(out,'candidate',command,seconds=1800,env=environment)
 assert report['count']==15830 and report['ordered_ids']==authority['ordered_ids'] and report['input']==authority['complete_inputs']
 assert report['source_before']==before and report['source_after']==before
 assert report['native_or_VM_entries']==0 and report['unraisables']==[]
 assert report['differences'] is None and report['status']=='CHECKPOINT_CANDIDATE_OBSERVED'
 assert report['business_comparison']=='PENDING_PARENT_PROCESS_TERMINAL'
 assert receipt['returncode']==0 and receipt['timeout'] is False and receipt['stderr']['bytes']==0
 assert receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
 actual=s.file_pin(out/'candidate/observations.jsonl')
 business=s.identical_files(original_dir/'observations.jsonl',out/'candidate/observations.jsonl',spec['business_pin'],actual)
 actual_late=(out/'candidate/late-events.jsonl').read_bytes()
 late=(actual_late==baseline_late and pin(actual_late)==spec['baseline_unselected_late'])
 traces=[json.loads(row) for row in (out/'candidate-stack.jsonl').read_bytes().splitlines()]
 late_rows=[json.loads(row) for row in actual_late.splitlines()]
 assert [row['row'] for row in traces]==late_rows
 record.update({'business_baseline_exact':business,'unselected_late_baseline_exact':late,
  'business':actual,'late_events':pin(actual_late),'traces':traces,
  'stack':s.file_pin(out/'candidate-stack.jsonl'),'owned_receipt':s.file_pin(out/'candidate.result.json'),
  'checkpoint':s.bytes_pin(raw),'candidate_seconds':receipt['elapsed_seconds']})
 assert business and late,'the C post-write observer changed a complete existing channel'
 for path,content in captured:s.exact_reread(path,content)
 assert (baseline/'late-events.jsonl').read_bytes()==baseline_late
 record['status']='DIAGNOSTIC_UNSELECTED_C_STACK_COMPLETE'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'terminal_unselected_native_late_stack_terminal','status':record['status'],
  'business_baseline_exact':record.get('business_baseline_exact'),
  'unselected_late_baseline_exact':record.get('unselected_late_baseline_exact'),
  'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='DIAGNOSTIC_UNSELECTED_C_STACK_COMPLETE' else 1)
