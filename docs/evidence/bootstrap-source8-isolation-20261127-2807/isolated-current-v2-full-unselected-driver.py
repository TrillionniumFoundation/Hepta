from pathlib import Path
import sys,json,os,time,traceback,hashlib
spec=json.load(sys.stdin);scope=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807');root=scope/'src'
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
for name,pin in spec['pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
assert os.statvfs(data).f_bavail*os.statvfs(data).f_frsize>8_000_000_000
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON')):del os.environ[key]
os.environ['TMPDIR']=str(scope/'temporary')
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as support
from tools.qualify_hia_service_bootstrap_finite import originals,compare_candidate
from tools.read_hia_service_bootstrap import read_finite
out=data/'isolated-current-v2-full-unselected';out.mkdir(mode=0o700)
before=support.source_snapshot();start=time.monotonic();record={'schema':'hepta.hia.bootstrap-isolated-current-observation.v1','started_time_ns':time.time_ns(),'source_before':before,'original_inner_seconds':600,'candidate_inner_seconds':1800,'cleanup_seconds':3,'original_source_suite_executed':False,'whole_native_stack_qualified':False}
try:
 authority,pin=originals(out/'originals')
 record['authority']={'path':str(authority),**pin}
 print(json.dumps({'event':'complete_fresh_originals_terminal','authority':record['authority'],'seconds':time.monotonic()-start},sort_keys=True),flush=True)
 report=compare_candidate(authority,pin,out/'unselected',lane='unselected')
 record['comparison']={key:report[key] for key in ('status','count','full_raw_byte_equality','complete_late_byte_equality','terminal_late_difference_count','current_dispatch')}
 print(json.dumps({'event':'complete_unselected_comparison_terminal','comparison':record['comparison'],'seconds':time.monotonic()-start},sort_keys=True),flush=True)
 record['independent_reader']=read_finite(out/'unselected',authority,pin,'unselected')
 record['status']='PASS_FULL_UNSELECTED_AND_CURRENT_OWNED_PROCESS_ONLY'
except BaseException as error:
 record['status']='HOLD';record['error']={'type':type(error).__name__,'message':str(error)}
 traceback.print_exc()
finally:
 record['source_after']=support.source_snapshot();assert record['source_after']==before
 record['ended_time_ns']=time.time_ns();record['seconds']=time.monotonic()-start
 support.write_json(out/'observation.json',record)
 print(json.dumps({'event':'fresh_unselected_terminal','status':record['status'],'seconds':record['seconds'],'error':record.get('error'),'record':support.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_') else 1)
