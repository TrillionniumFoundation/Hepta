from pathlib import Path
import sys,json,hashlib,os,time,traceback
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
for name,pin in spec['all_source_pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON')):del os.environ[key]
os.environ['TMPDIR']='/home/qian-qi/hia-bootstrap-closure-20261127-2807/temporary'
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tests import hia_service_bootstrap_oracle as oracle
from tools import read_hia_service_bootstrap as reader
out=data/'source-diagnostics-v4-vm-original232';out.mkdir(mode=0o700)
before=s.source_snapshot();assert before==spec['all_source_pins']
authority=Path(spec['authority']);authority_raw,value,pin=s.capture_json(authority,spec['authority_pin'])
captured=[]
lane=value['lanes'][0];assert lane['label']=='basis-first'
directory,original=reader.receipt(authority.parent,'basis-first',lane,captured,before,lane='original',seconds=600)
cases,domain=oracle.cases();assert len(cases)==232 and original['count']==232 and original['ordered_ids']==[c['id'] for c in cases]
expected=[row for _,_,row in s.json_lines(directory/'observations.jsonl',original['files']['observations.jsonl'])]
assert len(expected)==232 and [r['id'] for r in expected]==[c['id'] for c in cases]
from tests.hia_service_bootstrap_observer import Backend,seal_record
backend=Backend('vm',None,compatibility=True)
started=time.monotonic();differences=[];entries=0
record={'schema':'hepta.hia.bootstrap-vm-prefix232-diagnostic.v1','diagnostic_only':True,'complete_15830_qualification':False,'late_qualification':False,'whole_native_stack_qualified':False,'source_before':before,'original_authority':{'path':str(authority),**pin},'original_basis_report':lane['report']}
with (out/'observations.jsonl').open('xb',buffering=0) as observations,(out/'raw-tracebacks.jsonl').open('xb',buffering=0) as traces,(out/'late-events.jsonl').open('xb',buffering=0) as late:
 def sink(row):late.write(s.canonical(row)+b'\n')
 try:
  for ordinal,case in enumerate(cases):
   start=backend.image._entry.calls
   functions,namespace,builtin=backend.select(case)
   actual,trace=oracle.observe(case,functions=functions,namespace=namespace,captured_builtins=builtin)
   raw,frozen=seal_record(actual,sink)
   observations.write(raw+b'\n');traces.write(s.canonical(trace)+b'\n')
   if raw!=s.canonical(expected[ordinal]):differences.append({'id':case['id'],'ordinal':ordinal,'differences':s.differences(expected[ordinal],frozen)})
   entries+=backend.image._entry.calls-start
   del actual,trace,frozen
  assert not backend.poison_calls
  record.update({'status':'OBSERVED_PREFIX232_BUSINESS_EQUAL' if not differences else 'HOLD','count':232,'entries':entries,'differences':differences,'retained_poison_calls':backend.poison_calls,'seconds':time.monotonic()-started})
 except BaseException as error:
  record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
record['source_after']=s.source_snapshot();assert record['source_after']==before
reader.unchanged(captured);s.exact_reread(authority,authority_raw)
s.write_json(out/'observation.json',record)
print(json.dumps({'status':record['status'],'count':record.get('count'),'entries':entries,'differences':differences,'seconds':record.get('seconds'),'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='OBSERVED_PREFIX232_BUSINESS_EQUAL' else 1)
