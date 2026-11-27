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
from tools.qualify_hia_service_bootstrap_finite import read_originals,_compare_terminal_late
out=data/'source-diagnostics-v2-no-live-comparison'
out.mkdir(mode=0o700)
source=s.source_snapshot();assert source==spec['all_source_pins']
authority=Path(spec['authority']);pin=spec['authority_pin']
original,raw,inputs,input_raw,captured,(expected_dir,expected_report)=read_originals(authority,pin)
assert original['base_count']==232 and original['count']==15830 and len(inputs['cases'])==15830
(out/'probe-observer.py').write_text(spec['probe'])
s.write_json(out/'invocation.json',spec)
started=time.monotonic();record={'schema':'hepta.hia.bootstrap-no-live-comparison-diagnostic-result.v1','source_before':source,'authority':{'path':str(authority),**pin},'diagnostic_only':True,'original_source_suite_executed':False,'whole_native_stack_qualified':False}
try:
 receipt,report,checkpoint=s.run_child(out,'candidate',[sys.executable,'-I','-B',str(out/'probe-observer.py'),str(out/'candidate')],seconds=1800)
 assert report['schema']=='hepta.hia.bootstrap-no-live-comparison-diagnostic.v1' and report['diagnostic_only'] is True and report['differences'] is None
 assert report['status']=='DIAGNOSTIC_OBSERVATIONS_COMPLETE' and report['lane']=='unselected'
 assert report['count']==15830 and report['ordered_ids']==original['ordered_ids']
 assert report['input']==original['complete_inputs'] and report['expected_authority']==pin
 assert report['native_or_VM_entries']==0 and report['unraisables']==[] and receipt['stderr']['bytes']==0 and receipt['timeout'] is False and receipt['cleanup']['signals']==[] and receipt['cleanup']['after']==[]
 for field in ('source_before','source_after'):assert report[field]==source
 for name,p in report['files'].items():
  if name!='late-events.jsonl':assert s.file_pin(out/'candidate'/name)==p,name
 actual=s.file_pin(out/'candidate'/'observations.jsonl')
 equal=s.identical_files(expected_dir/'observations.jsonl',out/'candidate'/'observations.jsonl',expected_report['files']['observations.jsonl'],actual)
 late=s.file_pin(out/'candidate'/'late-events.jsonl')
 differences,diffpin=_compare_terminal_late(out/'candidate'/'late-events.jsonl',expected_dir/'late-events.jsonl',late,expected_report['files']['late-events.jsonl'],out/'terminal-late-differences.jsonl')
 entries=0;entry_count=0
 for ordinal,_,row in s.json_lines(out/'candidate'/'entry-counts.jsonl',report['files']['entry-counts.jsonl']):
  assert row['id']==inputs['cases'][ordinal]['id'] and row['entries']==0 and row['explicit_unselected'] is True
  entry_count+=1
 assert entry_count==15830
 progress=[]
 for _,_,row in s.json_lines(out/'candidate'/'progress.jsonl',report['files']['progress.jsonl']):progress.append(row)
 assert progress==[{'event':event,'ordinal':i,'id':case['id']} for i,case in enumerate(inputs['cases']) for event in ('start','stop')]
 for path,content in (*captured,(authority,raw),(authority.parent/'complete-inputs.json',input_raw)):
  s.exact_reread(path,content)
 record.update({'status':'OBSERVED_COMPLETE_RAW_AND_LATE_EQUAL' if equal and differences==0 else 'HOLD','complete_business_raw_equal':equal,'complete_terminal_late_equal':differences==0,'terminal_late_differences':{'relative':'terminal-late-differences.jsonl',**diffpin},'terminal_late_difference_count':differences,'count':15830,'original_observations':expected_report['files']['observations.jsonl'],'candidate_observations':actual,'original_terminal_late':expected_report['files']['late-events.jsonl'],'candidate_terminal_late':late,'actual_owned_child_result':s.file_pin(out/'candidate.result.json'),'all_progress_and_entry_counts_checked':True})
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==source
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps(record,sort_keys=True),flush=True)
sys.exit(0 if record['status']=='OBSERVED_COMPLETE_RAW_AND_LATE_EQUAL' else 1)
