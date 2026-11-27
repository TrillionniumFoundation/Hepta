from pathlib import Path
import os,sys,json,time,hashlib,traceback,signal
started=time.monotonic();budget_start_ns=time.time_ns();spec=json.load(sys.stdin)
def complete_deadline(signum,frame):
 raise TimeoutError('complete Source8 admission, original suite and full readback reached 1800 seconds')
signal.signal(signal.SIGALRM,complete_deadline)
signal.setitimer(signal.ITIMER_REAL,max(0.001,1800-(time.monotonic()-started)))
initial_nice=os.getpriority(os.PRIO_PROCESS,0)
if initial_nice<10:os.setpriority(os.PRIO_PROCESS,0,10)
assert os.getpriority(os.PRIO_PROCESS,0)==10
root=Path('/home/qian-qi/hia-bootstrap-source-custody-20261127-2807/src')
scope=Path('/home/qian-qi/hia-bootstrap-source8-home-20261127-2807')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in spec['source_pins'].items():assert pin((root/name).read_bytes())==expected,name
for name,expected in spec['original_test_pins'].items():assert pin((root/name).read_bytes())==expected,name
home=Path('/home/qian-qi');fs=os.statvfs(home);available=fs.f_bavail*fs.f_frsize
assert available>=4_000_000_000,('insufficient independent local output budget',available)
scope.mkdir(mode=0o700)
data=scope/'evidence';data.mkdir(mode=0o700)
temporary=scope/'temporary';temporary.mkdir(mode=0o700)
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.environ['TMPDIR']=str(temporary);os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tests import hia_service_bootstrap_suite as suite
from tools import qualify_hia_service_bootstrap as producer
from tools.read_hia_service_bootstrap import read_suite
before=s.source_snapshot();assert before==spec['source_pins']
assert suite.COUNTS['source']==8
assert suite.SELECTIONS['source']==(
 'tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests',
 'tests.test_hia_service_bootstrap_qualification.ServiceBootstrapQualificationSourceTests')
s.write_json(data/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-original-source8-local-owner-observation.v1',
 'source_before':before,'original_outer_seconds':1800,'cleanup_seconds':3,
 'output_filesystem':{'path':str(scope),'device':scope.stat().st_dev,'available_bytes_before':available},
 'old_physical_observations_moved':False,'original_owner_entrypoint':'tools/qualify_hia_service_bootstrap.py',
 'complete_validation_seconds_limit':1800,
 'whole_native_stack_qualified':False,'matching_source_cold_qualified':False,
 'complete_budget_started_time_ns':budget_start_ns,
 'complete_budget_enforcement':'PARENT_1800_SECONDS_AND_UNCHANGED_ORIGINAL_CHILD_1800_PLUS_3',
 'nice':os.getpriority(os.PRIO_PROCESS,0),'affinity_unchanged':sorted(os.sched_getaffinity(0))}
print(json.dumps({'event':'original_source8_home_begin','available_bytes':available,
 'source_count':len(before),'source_commit':spec['source_commit'],'scope':str(scope),
 'complete_validation_seconds_limit':1800,'original_child_seconds':1800,'cleanup_seconds':3,
 'nice':record['nice'],'affinity':record['affinity_unchanged']},sort_keys=True),flush=True)
try:
 output=data/'source8'
 sys.argv=[str(root/'tools/qualify_hia_service_bootstrap.py'),'--suite','source','--output',str(output)]
 result=producer.main()
 assert result==0
 report_raw,report,_=s.capture_json(output/'report.json')
 receipt_raw,receipt,_=s.capture_json(output/'suite.result.json',report['outer_result'])
 suite_raw,suite_report,_=s.capture_json(output/'suite/report.json',report['suite_report'])
 assert receipt['timeout_seconds']==1800 and receipt['cleanup_seconds']==3 and receipt['timeout'] is False
 assert receipt['returncode']==0 and receipt['reaped'] is True
 assert receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
 assert suite_report['status']=='PASS_COMPLETE_SUITE'
 assert suite_report['run']==8 and suite_report['skips']==0 and suite_report['errors']==0 and suite_report['failures']==0
 assert suite_report['planned']==suite.declared_ids('source')
 record['original_source8_elapsed_seconds']=receipt['elapsed_seconds']
 record['original_source8_receipt']={'path':str(output/'suite.result.json'),**s.bytes_pin(receipt_raw)}
 record['original_suite_report']={'path':str(output/'suite/report.json'),**s.bytes_pin(suite_raw)}
 record['complete_owner_report']={'path':str(output/'report.json'),**s.bytes_pin(report_raw)}
 record['independent_reader']=read_suite(output,s.bytes_pin(report_raw),require_cold=False)
 s.exact_reread(output/'report.json',report_raw)
 s.exact_reread(output/'suite.result.json',receipt_raw)
 s.exact_reread(output/'suite/report.json',suite_raw)
 elapsed=time.monotonic()-started
 record['complete_validation_elapsed_seconds']=elapsed
 if elapsed>1800:raise RuntimeError('original owner and complete independent readback exceeded 1800 seconds')
 record['status']='PASS_ORIGINAL_SOURCE8_AND_FULL_READBACK_WITHIN_1800_SECONDS_ONLY'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 try:
  record['source_after']=s.source_snapshot();assert record['source_after']==before
 except BaseException as error:
  record['status']='HOLD';record['error']={'type':type(error).__name__,'message':str(error)}
 record['complete_validation_elapsed_seconds']=time.monotonic()-started
 signal.setitimer(signal.ITIMER_REAL,0)
 record['complete_budget_ended_time_ns']=time.time_ns()
 if record['complete_validation_elapsed_seconds']>1800 and record['status'].startswith('PASS_'):
  record['status']='HOLD';record['error']={'type':'RuntimeError','message':'terminal source readback exceeded 1800 seconds'}
 s.write_json(data/'observation.json',record)
 print(json.dumps({'event':'original_source8_owner_terminal','status':record['status'],
  'seconds':record['complete_validation_elapsed_seconds'],'error':record.get('error'),
  'report':s.file_pin(data/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_ORIGINAL_SOURCE8_') else 1)
