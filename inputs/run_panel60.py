from pathlib import Path
import hashlib,json,os,sys,time,traceback,unittest
SCOPE=Path(__file__).resolve().parent;ROOT=Path(sys.argv[1]).resolve();OUT=SCOPE/'component-checker-r4'
OUT.mkdir(mode=0o700);sys.path.insert(0,str(ROOT));os.chdir(ROOT)
for key in tuple(os.environ):
 if key.startswith('HEPTA_HIA_') and (key.endswith('_MANIFEST') or key.endswith('_COLD_REPORT') or '_DEVELOPMENT' in key):os.environ.pop(key)
os.environ.update(HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST=str(SCOPE/'development-r1/core_lowering/manifest.json'),HEPTA_HIA_CORE_LOWERING_FIXTURE_EVIDENCE=str(OUT/'core'),HEPTA_HIA_MACHINE_PLAN_DEVELOPMENT_MANIFEST=str(SCOPE/'development-r1/machine_plan/manifest.json'),HEPTA_HIA_MACHINE_PLAN_FIXTURE_EVIDENCE=str(OUT/'plan'))
os.environ['HEPTA_HIA_CORE_LOWERING_COMPOSITION_MANIFESTS']=str(SCOPE/'composition-manifests-r1.json')
os.environ['HEPTA_HIA_MACHINE_FRAME_DEVELOPMENT_COMPILER']=str(SCOPE/'retained-development-compiler.bin')
os.environ['HEPTA_HIA_MACHINE_FRAME_EVIDENCE']=str(OUT/'shared-frame')
from tools.qualify_hia_core_lowering_callers import source_pins
from hepta.hia_machine_plan_control_native import PlanFrame
before=source_pins();frames={};original=PlanFrame._invoke
active=['outside-test']
def invoke(self,*args,**kwargs):
 result=original(self,*args,**kwargs)
 if '_mapping' in vars(self.image):
  key=('actual_native', self.image.image_sha256, active[0])
 else:
  import types
  from hepta.hia_machine_plan_control_native import NativeMachinePlanControl
  from hepta.hia_machine_plan_native import SOURCE
  entry=self.image._entry
  if (type(self.image) is not NativeMachinePlanControl or type(entry) is not types.FunctionType
      or entry.__module__ != 'tests.test_hia_machine_plan_native'
      or entry.__qualname__ != 'MachinePlanSourceTests.test_independent_vm_runs_complete_witness_and_refusal.<locals>.entry'):
   raise AssertionError('unreviewed non-native test execution owner')
  key=('ordinary_Core_VM', hashlib.sha256(SOURCE.read_bytes()).hexdigest(), active[0])
 frames[key]=frames.get(key,0)+1;return result
modules=['tests.test_hia_core_lowering_native','tests.test_hia_machine_plan_native','tests.test_hia_machine_plan_control_lifecycle','tests.test_hia_checker_identity','tests.test_hia_service_context_builder.ServiceContextAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope','tests.test_hia_service_context_builder.ServiceContextAdapterTests.test_serialized_or_duplicate_scope_cannot_select_a_held_executable','tests.test_hia_machine_frame_shared_native']
loader=unittest.TestLoader();suite=loader.loadTestsFromNames(modules)
def flatten(s):
 for x in s:
  if isinstance(x,unittest.TestSuite):yield from flatten(x)
  else:yield x
loaded=[t.id() for t in flatten(suite)];executed=[]
report={'scope':'NEW_R4_DEVELOPMENT_COMPONENT_AND_RETAINED_CHECKER_PANEL','python':sys.version,'source_before':before,'modules':modules,'loaded_ids':loaded,'loader_errors':loader.errors,'cold_qualified':False,'original_machine51_or_core50_callers_not_this_panel':True}
(OUT/'INTENT.json').write_text(json.dumps(report,indent=2)+'\n')
if loader.errors or len(loaded)!=60 or len(set(loaded))!=60:raise AssertionError('exact new panel inventory differs')
class Result(unittest.TextTestResult):
 def startTest(self,test):active[0]=test.id();executed.append(test.id());super().startTest(test)
start=time.monotonic();PlanFrame._invoke=invoke
try:
 with (OUT/'unittest.log').open('x') as log:result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
 report.update(tests_run=result.testsRun,executed_ids=executed)
 for name in ('errors','failures','skipped','expectedFailures'):report[name]=[[t.id(),detail] for t,detail in getattr(result,name)]
 report['unexpectedSuccesses']=[t.id() for t in result.unexpectedSuccesses]
 report['status']='PASS' if result.testsRun==60 and executed==loaded and not any(report[n] for n in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses')) else 'FAIL'
except BaseException:report.update(status='FAIL',exception=traceback.format_exc())
finally:
 PlanFrame._invoke=original;report['seconds']=time.monotonic()-start;report['source_after']=source_pins();report['inputs_unchanged']=before==report['source_after'];report['actual_returned_frames']=[dict({'execution':kind,'test':test,'count':count}, **({'image_sha256':identity} if kind=='actual_native' else {'source_sha256':identity})) for (kind,identity,test),count in sorted(frames.items())]
 if not report['inputs_unchanged']:report['status']='FAIL'
 (OUT/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'seconds':report['seconds'],'tests_run':report.get('tests_run'),'inputs_unchanged':report['inputs_unchanged'],'failed_ids':[x[0] for key in ('errors','failures') for x in report.get(key,[])],'actual_native_frames':sum(n for (kind,_,_),n in frames.items() if kind=='actual_native'),'ordinary_VM_frames':sum(n for (kind,_,_),n in frames.items() if kind=='ordinary_Core_VM')},indent=2),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)
