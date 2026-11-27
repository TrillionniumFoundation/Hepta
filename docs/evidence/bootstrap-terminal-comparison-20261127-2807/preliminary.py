from pathlib import Path
import sys,os,json,time,traceback
root=Path('/home/qian-qi/hia-bootstrap-terminal-comparison-20261127-2807/src')
sys.path.insert(0,str(root));os.chdir(root)
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import originals,compare_candidate
from tools.read_hia_service_bootstrap import read_finite
out=Path(sys.argv[1]);out.mkdir(mode=0o700)
before=s.source_snapshot();started=time.monotonic()
record={'schema':'hepta.hia.bootstrap-symmetric-terminal-preliminary.v1',
 **s.child_identity(),'source_before':before,'original_source_suite_executed':False,
 'whole_native_stack_qualified':False,'original_inner_seconds':600,
 'candidate_inner_seconds':1800,'cleanup_seconds':3,'outer_seconds':1800,
 'all_admission_and_raw_late_comparison_inside_outer':True}
try:
 authority,pin=originals(out/'originals')
 record['authority']={'path':str(authority),**pin}
 print(json.dumps({'event':'fresh_symmetric_originals_terminal','authority':record['authority'],'seconds':time.monotonic()-started},sort_keys=True),flush=True)
 comparison=compare_candidate(authority,pin,out/'complete-unselected',lane='unselected')
 record['comparison']={k:comparison[k] for k in ('status','count','full_raw_byte_equality',
   'complete_late_byte_equality','terminal_business_difference_count','terminal_late_difference_count')}
 record['independent_reader']=read_finite(out/'complete-unselected',authority,pin,'unselected')
 record['status']='PASS_SYMMETRIC_UNSELECTED_FINITE_AND_READBACK_ONLY'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 path=out/'complete-unselected/report.json'
 if path.is_file():
  value=json.loads(path.read_bytes())
  record['comparison']={k:value[k] for k in ('status','count','full_raw_byte_equality',
   'complete_late_byte_equality','terminal_business_difference_count','terminal_late_difference_count')}
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'report.json',record)
 print(json.dumps({'event':'symmetric_preliminary_terminal','status':record['status'],
  'comparison':record.get('comparison'),'seconds':record['seconds'],'error':record.get('error')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_SYMMETRIC_') else 1)
