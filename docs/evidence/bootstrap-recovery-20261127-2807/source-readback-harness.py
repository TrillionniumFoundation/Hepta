from pathlib import Path
import sys,json,unittest,time,hashlib,os,subprocess
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src');out=root.parent/'source-readback-v2';out.mkdir(mode=0o700)
sys.path.insert(0,str(root))
from tools import hia_bootstrap_source_history as h
from tools.read_hia_service_bootstrap import _read_current_dispatch_control
raw=(root/h.SOURCE).read_bytes();expected=h.code_bindings(raw)
for lane in ('unselected','vm'):
 value=json.loads((root.parent/'recovered-controls-v2'/(lane+'.json')).read_bytes())
 _read_current_dispatch_control(value,expected,lane)
 import copy
 for mut in ('domain','complete_current_semantics_qualified','program_cases','case_order','getter','zero_entry','missing_option'):
  v=copy.deepcopy(value)
  if mut=='domain':v['domain']='HISTORICAL_FIVE_BODY_COMPATIBILITY'
  elif mut=='complete_current_semantics_qualified':v[mut]=True
  elif mut=='program_cases':v[mut]=11
  elif mut=='case_order':v['program_rows'][0],v['program_rows'][1]=v['program_rows'][1],v['program_rows'][0]
  elif mut=='getter':v['program_rows'][5]['current']['events'].pop(1)
  elif mut=='missing_option':v['init_rows'].pop()
  elif mut=='zero_entry':
   if lane=='unselected':v['init_rows'][0]['current']['entries']=1
   else:v['init_rows'][0]['current']['entries']=0
  try:_read_current_dispatch_control(v,expected,lane)
  except (ValueError,KeyError):pass
  else:raise AssertionError((lane,mut))
command=[sys.executable,'-I','-B','-c',"import sys,unittest;sys.path.insert(0,"+repr(str(root))+");s=unittest.defaultTestLoader.loadTestsFromNames(['tests.test_hia_service_bootstrap_sources','tests.test_hia_service_bootstrap_fixed_words']);r=unittest.TextTestRunner(verbosity=2).run(s);print('planned='+str(s.countTestCases())+' run='+str(r.testsRun)+' skips='+str(len(r.skipped)));raise SystemExit(not r.wasSuccessful() or bool(r.skipped))"]
env={k:v for k,v in os.environ.items() if not k.startswith(('HEPTA_HIA_','PYTHON'))};start=time.monotonic();p=subprocess.run(command,cwd=root,env=env,capture_output=True,timeout=180)
(out/'stdout').write_bytes(p.stdout);(out/'stderr').write_bytes(p.stderr)
report={'schema':'hepta.bootstrap-recovered-source-readback.v2','actual_current_readbacks':2,'negative_current_readbacks':14,'legacy_sources_and_fixed_word_returncode':p.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':{'bytes':len(p.stdout),'sha256':hashlib.sha256(p.stdout).hexdigest()},'stderr':{'bytes':len(p.stderr),'sha256':hashlib.sha256(p.stderr).hexdigest()},'qualification_inherited':False,'full_finite_qualified':False,'whole_native_stack_qualified':False}
(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
if p.returncode:raise RuntimeError('legacy exact source controls failed')
