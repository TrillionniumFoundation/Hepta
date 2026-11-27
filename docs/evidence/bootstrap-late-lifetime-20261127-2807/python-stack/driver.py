from pathlib import Path
import sys,json,hashlib,os,time,traceback
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
for name,pin in spec['all_source_pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
assert hashlib.sha256(spec['probe'].encode()).hexdigest()==spec['probe_sha256']
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON')):del os.environ[key]
os.environ['TMPDIR']='/home/qian-qi/hia-bootstrap-closure-20261127-2807/temporary'
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.qualify_hia_service_bootstrap_finite import read_originals
out=data/'source-diagnostics-v3-late-stack'
out.mkdir(mode=0o700)
before=s.source_snapshot();assert before==spec['all_source_pins']
original,raw,inputs,input_raw,captured,(expected_dir,expected_report)=read_originals(Path(spec['authority']),spec['authority_pin'])
assert original['base_count']==232 and original['count']==15830
(out/'probe-observer.py').write_text(spec['probe']);s.write_json(out/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-late-stack-diagnostic-result.v1','diagnostic_only':True,'original_source_suite_executed':False,'whole_native_stack_qualified':False,'source_before':before,'lanes':{}}
started=time.monotonic()
try:
 for lane in ('original','unselected'):
  receipt,report,checkpoint=s.run_child(out,lane,[sys.executable,'-I','-B',str(out/'probe-observer.py'),lane,str(out/lane)],seconds=600 if lane=='original' else 1800)
  assert report['schema']=='hepta.hia.bootstrap-late-stack-diagnostic.v1' and report['diagnostic_only'] is True
  assert report['count']==15830 and report['ordered_ids']==original['ordered_ids'] and report['input']==original['complete_inputs']
  assert report['source_before']==before and report['source_after']==before
  assert report['native_or_VM_entries']==0 and report['unraisables']==[] and report['differences']==0
  assert receipt['stderr']['bytes']==0 and receipt['timeout'] is False and receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
  actual=s.file_pin(out/lane/'observations.jsonl')
  business=s.identical_files(expected_dir/'observations.jsonl',out/lane/'observations.jsonl',expected_report['files']['observations.jsonl'],actual)
  baseline=expected_dir if lane=='original' else data/'isolated-current-v2-full-unselected/unselected/candidate'
  expected_late=spec['baseline_late'][lane]
  actual_late=s.file_pin(out/lane/'late-events.jsonl')
  late=s.identical_files(baseline/'late-events.jsonl',out/lane/'late-events.jsonl',expected_late,actual_late)
  traces=[row for _,_,row in s.json_lines(out/lane/'diagnostic-late-stack.jsonl',report['files']['diagnostic-late-stack.jsonl'])]
  record['lanes'][lane]={'business_baseline_exact':business,'late_baseline_exact':late,'late_events':actual_late,'stack':s.file_pin(out/lane/'diagnostic-late-stack.jsonl'),'traces':traces,'owned_receipt':s.file_pin(out/(lane+'.result.json'))}
  print(json.dumps({'event':'late_stack_lane_terminal','lane':lane,'business_baseline_exact':business,'late_baseline_exact':late,'stack_rows':len(traces),'seconds':time.monotonic()-started},sort_keys=True),flush=True)
 for path,content in captured:s.exact_reread(path,content)
 record['status']='DIAGNOSTIC_COMPLETE'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'late_stack_diagnostic_terminal','status':record['status'],'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='DIAGNOSTIC_COMPLETE' else 1)
