from pathlib import Path
import os,sys,json,time,hashlib,traceback,signal
begun=time.monotonic()
def deadline(signum,frame):
 raise TimeoutError('complete VM C-stack diagnostic reached original 1800-second total')
signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,1800)
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-source-custody-20261127-2807/src')
out=Path('/home/qian-qi/hia-bootstrap-vm-late-c-stack-20261127-2807')
observer=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/native-late-preload-v1')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in spec['source_pins'].items():assert pin((root/name).read_bytes())==expected,name
for name,expected in spec['observer_pins'].items():assert pin((observer/name).read_bytes())==expected,name
assert pin(Path(spec['authority']).read_bytes())==spec['authority_pin']
available=os.statvfs(out.parent).f_bavail*os.statvfs(out.parent).f_frsize
assert available>=2_000_000_000,available
out.mkdir(mode=0o700)
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
temporary=out/'temporary';temporary.mkdir(mode=0o700);os.environ['TMPDIR']=str(temporary)
if os.getpriority(os.PRIO_PROCESS,0)<10:os.setpriority(os.PRIO_PROCESS,0,10)
assert os.getpriority(os.PRIO_PROCESS,0)==10
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import read_originals,_seal_process_terminal
before=s.source_snapshot();assert before==spec['source_pins']
s.write_json(out/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-full-vm-postwrite-c-stack.v1',
 'diagnostic_only':True,'original_source_suite_executed':False,'complete_original_cases':15830,
 'native_source_authority':False,'whole_native_stack_qualified':False,
 'source_before':before,'source_commit':spec['source_commit'],'observer_pins':spec['observer_pins'],
 'original_total_seconds':1800,'cleanup_seconds':3,'home_available_before':available,
 'scope':'complete same-source VM sequence with post-write C stack observation, not Source8 qualification'}
print(json.dumps({'event':'vm_c_stack_started','output':str(out),'authority':spec['authority_pin'],
 'source_count':len(before),'complete_cases':15830,'total_seconds':1800},sort_keys=True),flush=True)
try:
 authority,authority_raw,inputs,input_raw,captured,(original_dir,original_report)=read_originals(Path(spec['authority']),spec['authority_pin'])
 assert authority['base_count']==232 and authority['count']==15830
 assert original_report['files']['observations.jsonl']==spec['business_pin']
 assert authority['source_before']==before
 environment=os.environ.copy()
 environment.update({'LD_PRELOAD':str(observer/'late-observer.so'),
  'HIA_BOOTSTRAP_DIAG_LATE_FILE':str(out/'candidate/late-events.jsonl'),
  'HIA_BOOTSTRAP_DIAG_TRACE_FILE':str(out/'candidate-stack.jsonl')})
 command=[sys.executable,'-I','-B',str(root/'tests/hia_service_bootstrap_observer.py'),
  '--lane','vm','--inputs',str(Path(spec['authority']).parent/'complete-inputs.json'),
  '--output',str(out/'candidate'),'--expected',spec['authority'],
  '--expected-sha256',spec['authority_pin']['sha256'],'--expected-bytes',str(spec['authority_pin']['bytes'])]
 receipt,report,raw=s.run_child(out,'candidate',command,seconds=1800,env=environment)
 assert report['count']==15830 and report['ordered_ids']==authority['ordered_ids'] and report['input']==authority['complete_inputs']
 assert report['source_before']==before and report['source_after']==before
 assert report['native_or_VM_entries']>0 and report['unraisables']==[]
 assert report['differences'] is None and report['status']=='CHECKPOINT_CANDIDATE_OBSERVED'
 assert report['business_comparison']=='PENDING_PARENT_PROCESS_TERMINAL'
 assert receipt['returncode']==0 and receipt['timeout'] is False and receipt['stderr']['bytes']==0
 assert receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
 start_raw,start,_=s.capture_json(out/'candidate.start.json')
 result_raw,result,_=s.capture_json(out/'candidate.result.json')
 terminal,terminal_pin,terminal_capture=_seal_process_terminal(out/'candidate','candidate','vm',raw,report,start_raw,start,result_raw,result)
 baseline=Path(spec['baseline_vm'])
 baseline_report_raw,baseline_report,_=s.capture_json(baseline/'report.json')
 baseline_terminal_raw,baseline_terminal,_=s.capture_json(baseline/'process-terminal.json')
 baseline_result_raw,baseline_result,_=s.capture_json(baseline.parent/'candidate.result.json')
 assert baseline_terminal['status']=='TERMINAL_COMPLETE' and baseline_terminal['natural_exit'] is True
 assert baseline_terminal['checkpoint_report']=={'relative':'report.json',**s.bytes_pin(baseline_report_raw)}
 assert baseline_terminal['result']=={'relative':'candidate.result.json',**s.bytes_pin(baseline_result_raw)}
 assert baseline_result['returncode']==0 and baseline_result['timeout'] is False
 assert baseline_result['cleanup']['signals']==[] and baseline_result['cleanup']['after']==[]
 assert baseline_report['count']==15830 and baseline_report['ordered_ids']==authority['ordered_ids']
 assert baseline_report['source_before']==before and baseline_report['source_after']==before
 assert baseline_terminal['files']['observations.jsonl']==spec['business_pin']
 baseline_late=(baseline/'late-events.jsonl').read_bytes()
 assert pin(baseline_late)==spec['baseline_late']==baseline_terminal['files']['late-events.jsonl']
 actual=terminal['files']['observations.jsonl']
 business=s.identical_files(original_dir/'observations.jsonl',out/'candidate/observations.jsonl',spec['business_pin'],actual)
 baseline_business=s.identical_files(baseline/'observations.jsonl',out/'candidate/observations.jsonl',spec['business_pin'],actual)
 actual_late=(out/'candidate/late-events.jsonl').read_bytes()
 late=actual_late==baseline_late and pin(actual_late)==spec['baseline_late']
 traces=[json.loads(row) for row in (out/'candidate-stack.jsonl').read_bytes().splitlines()]
 late_rows=[json.loads(row) for row in actual_late.splitlines()]
 assert len(traces)==8 and [row['row'] for row in traces]==late_rows
 record.update({'original_business_exact':business,'VM_baseline_business_exact':baseline_business,
  'VM_baseline_late_exact':late,'business':actual,'late_events':pin(actual_late),
  'traces':traces,'stack':s.file_pin(out/'candidate-stack.jsonl'),
  'owned_receipt':s.bytes_pin(result_raw),'checkpoint':s.bytes_pin(raw),'terminal':terminal_pin,
  'candidate_seconds':receipt['elapsed_seconds'],
  'baseline_report':s.bytes_pin(baseline_report_raw),'baseline_terminal':s.bytes_pin(baseline_terminal_raw),
  'baseline_result':s.bytes_pin(baseline_result_raw)})
 assert business and baseline_business and late,'C post-write observation changed a complete existing VM channel'
 for path,content in captured:s.exact_reread(path,content)
 for path,content in ((Path(spec['authority']),authority_raw),(baseline/'report.json',baseline_report_raw),
  (baseline/'process-terminal.json',baseline_terminal_raw),(baseline.parent/'candidate.result.json',baseline_result_raw),
  (baseline/'late-events.jsonl',baseline_late),terminal_capture):
  s.exact_reread(path,content)
 record['status']='DIAGNOSTIC_COMPLETE_FULL_VM_C_STACK_ONLY'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 try:
  record['source_after']=s.source_snapshot();assert record['source_after']==before
 except BaseException as error:
  record['status']='HOLD';record['error']={'type':type(error).__name__,'message':str(error)}
 record['seconds']=time.monotonic()-begun
 signal.setitimer(signal.ITIMER_REAL,0)
 if record['seconds']>1800 and record.get('status','').startswith('DIAGNOSTIC_COMPLETE'):
  record['status']='HOLD';record['error']={'type':'TimeoutError','message':'full readback exceeded original total'}
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'vm_c_stack_terminal','status':record['status'],
  'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='DIAGNOSTIC_COMPLETE_FULL_VM_C_STACK_ONLY' else 1)
