from pathlib import Path
import sys,os,json,time,hashlib,traceback
spec=json.load(sys.stdin)
scope=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807');root=scope/'src'
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
for name,pin in spec['all_source_pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.environ['TMPDIR']=str(scope/'temporary');os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import compare_candidate
out=data/'source-diagnostics-v6-complete-vm';out.mkdir(mode=0o700)
before=s.source_snapshot();assert before==spec['all_source_pins']
s.write_json(out/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-isolated-current-complete-vm.v1',
 'original_source_suite_executed':False,'whole_native_stack_qualified':False,
 'source_before':before,'candidate_timeout_seconds':1800,'cleanup_seconds':3}
started=time.monotonic()
try:
 report=compare_candidate(Path(spec['authority']),spec['authority_pin'],out/'comparison',lane='vm')
 record['comparison']={k:report[k] for k in ('status','count','full_raw_byte_equality','complete_late_byte_equality','terminal_late_difference_count','current_dispatch')}
 record['status']='PASS_COMPLETE_VM_FINITE_ONLY'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 candidate=out/'comparison/candidate'
 for filename in ('report.json','process-terminal.json','differences.jsonl','late-events.jsonl'):
  path=candidate/filename
  if path.is_file():record[filename]={'path':str(path),**s.file_pin(path)}
 if (candidate/'report.json').is_file():
  child=json.loads((candidate/'report.json').read_bytes())
  record['actual_child']={k:child[k] for k in ('status','count','differences','native_or_VM_entries','unraisables')}
 if (candidate/'differences.jsonl').is_file():
  record['actual_differences']=[json.loads(line) for line in (candidate/'differences.jsonl').read_bytes().splitlines()]
 reportpath=out/'comparison/report.json'
 if reportpath.is_file():
  report=json.loads(reportpath.read_bytes())
  record['comparison']={k:report[k] for k in ('status','count','full_raw_byte_equality','complete_late_byte_equality','terminal_late_difference_count','current_dispatch')}
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'isolated_current_complete_vm_terminal','status':record['status'],'actual_child':record.get('actual_child'),'comparison':record.get('comparison'),'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_') else 1)
