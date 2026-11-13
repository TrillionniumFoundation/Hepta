"""Six unchanged original cases, two selected-owner combinations, development.

This targeted group is not either full namespace35/ledger48 qualification.
Original bodies, budgets, poisoned owner routes and the Evaluation qualifier's
complete native entry observer remain unchanged. External sampled section profiler; every original admission remains fresh.
"""
from __future__ import annotations
import argparse,ast,ctypes,importlib.metadata,importlib.util,json,os,struct,sys,time,traceback,unittest
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

BASE=Path(__file__).resolve().parent
ORIGINAL_BUDGETS={
 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner': {'max_total_wall_ms':3000,'max_native_wall_ms':1000},
 'test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline': {'max_total_wall_ms':3000,'max_native_wall_ms':1000},
 'test_native_timeout_is_incomplete_terminated_and_not_adoptable': {'max_total_wall_ms':600000,'max_native_wall_ms':1,'evaluate_wall_seconds_less_than':5}}
METHODS=(
 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner',
 'test_native_timeout_is_incomplete_terminated_and_not_adoptable',
 'test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline')
IDS=tuple('tests.test_hia_agent_native_tools.NativeLifecycleTests.'+name for name in METHODS)

def wire(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def write(path,value):
 with Path(path).open('xb') as stream:stream.write(wire(value))
def file_record(path):
 raw=Path(path).read_bytes()
 return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mode':oct(Path(path).stat().st_mode&0o7777)}
def snapshot(root):
 return {p.relative_to(root).as_posix():file_record(p) for p in sorted(root.rglob('*'))
         if p.is_file() and '__pycache__' not in p.parts and '.git' not in p.parts}
def _require(value,message):
 if not value:raise AssertionError(message)
def _function_ast(raw,name):
 found=[node for node in ast.walk(ast.parse(raw)) if isinstance(node,ast.FunctionDef) and node.name==name]
 _require(len(found)==1,'ambiguous reviewed observer '+name)
 return ast.dump(found[0],include_attributes=False)

def child(args):
    source=args.source.resolve(strict=True);output=args.output.resolve();output.mkdir(mode=0o700)
    compiler=args.compiler.resolve(strict=True);manifest_path=args.evaluation_manifest.resolve(strict=True)
    sys.path.insert(0,str(source))
    if any(name.startswith('HEPTA_') for name in os.environ):raise ValueError('targeted child needs explicit empty HEPTA environment')
    from tools import qualify_hia_service_evaluation as qualification
    from tools import hia_selfhost_contract as contract
    from hepta import hia_service_evaluation_native as evaluation
    from hepta import hia_agent_service as service_api
    from hepta import hia_agent_store as store_api
    from hepta import hia_execution_budget as budget
    from hepta.hia_service_evaluation_native import NativeEvaluationImage,EvaluationFrame,_mapped_evaluation
    from hepta.hia_machine_plan_control_native import MAGIC
    from tests import test_hia_agent_native_tools as original_tests
    own=Path(__file__).read_text();original=(source/'tools/qualify_hia_service_evaluation.py').read_text()
    for name in ('counted_init','counted_frame'):
        _require(_function_ast(own,name)==_function_ast(original,name),'original ABI observer AST changed')
    _require(_mapped_evaluation.cache_info().currsize==0,'fresh child image custody required')
    prerequisites=qualification._prerequisites(os.environ)
    before=snapshot(source);write(output/'SOURCE-BEFORE.json',before)
    manifest=json.loads(manifest_path.read_bytes());image_path=manifest_path.parent/manifest['image_path']
    inputs={str(path):file_record(path) for path in (compiler,manifest_path,image_path,Path(__file__))}
    _require(inputs[str(compiler)]['sha256']=='81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109','compiler identity differs')
    report={'schema':'hepta.hia.evaluation.original-budget-six-targeted.v1','scope':'INSTRUMENTED_DEVELOPMENT_DIAGNOSTIC_NOT_QUALIFICATION',
        'group':args.group,'python':sys.version,'prerequisites':prerequisites,'loaded_ids':list(IDS),
        'original_budgets_by_method': ORIGINAL_BUDGETS,
        'test_bodies_changed':False,'original_complete_entry_observer_AST_equal':True,'per_source_scan_instrumentation':True,
        'current_cold':False,'whole_native':False,'full_namespace_35_qualified':False,'full_ledger_48_qualified':False,
        'old_results_reclassified':False,'reference_poison_scope':'test process; subprocesses inherit selectors only',
        'fresh_standard_protocol_admitted':contract._SOURCE_PATH_PROTOCOL is not None,
        'runtime_buffering':None if contract._SOURCE_PATH_PROTOCOL is None else contract._SOURCE_PATH_PROTOCOL[4]}
    references,images,executed,events=[],[],[],[]
    modes,entries,per_test=Counter(),Counter(),Counter();active=['outside-test']
    original_init,original_frame_init=NativeEvaluationImage.__init__,EvaluationFrame.__init__
    def counted_init(image, raw, expected, namespace=None):
        _require(expected == manifest['image_sha256'] and sha256(raw).hexdigest() == expected,
                 'caller image differs from its own fresh build')
        original_init(image, raw, expected, namespace)
        _require(sha256(image._mapping[:]).hexdigest() == expected, 'actual executable mapping differs')
        actual_entry = image._entry
        images.append(image)
    
        def counted_entry(source, size, result, result_size, state, state_size):
            returned = actual_entry(source, size, result, result_size, state, state_size)
            if size == len(image.table):
                _require(result_size == 2048 and state_size == image.workspace_bytes
                         and type(returned) is int and returned in (0, 1, 2, 3, 4, 5),
                         'actual evaluation machine entry did not return its complete ABI receipt')
                words = struct.unpack('<21Q', ctypes.string_at(state, 168))
                _require(words[16] == MAGIC and words[19] in range(1, image.function_count + 1)
                         and struct.unpack('<2Q', ctypes.string_at(result, 16)) == (MAGIC, words[17]),
                         'actual evaluation machine state/output identity differs')
                entries[words[19]] += 1
                per_test[active[0]] += 1
            return returned
        image._entry = counted_entry

    def counted_frame(frame, image, mode, arguments, captures=(), *, witness=None):
        original_frame_init(frame, image, mode, arguments, captures, witness=witness)
        modes[mode] += 1
    # observer block ends here
    def forbidden(*unused,**ignored):
        references.append(active[0]);raise AssertionError('selected original owner policy entered')
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            active[0]=test.id();executed.append(test.id());events.append(['start',test.id(),time.monotonic_ns()]);super().startTest(test)
        def stopTest(self,test):
            events.append(['stop',test.id(),time.monotonic_ns()]);super().stopTest(test)
    fixture=None;ready=False;result=None;start=time.monotonic_ns()
    try:
        if args.group=='namespace':
            from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests as fixture
            prefix='HEPTA_HIA_ARTIFACT_NAMESPACE'
        else:
            from tests.test_hia_slot_ledger_native import SlotLedgerNativeTests as fixture
            prefix='HEPTA_HIA_SLOT_LEDGER'
        with patch.dict(os.environ,{prefix+'_DEVELOPMENT_COMPILER':str(compiler),prefix+'_EVIDENCE':str(output/'fixture')}):
            started=time.monotonic_ns();fixture.setUpClass();ready=True;report['fixture_elapsed_ns']=time.monotonic_ns()-started
        holder=fixture(methodName=('test_actual_all_seven_apis_dedup_restart_and_original_namespace_authority'
                                                    if args.group=='namespace' else 'test_original_tools_campaign_buffers_and_lease_snapshot_with_four_native_owners'))
        dependencies=fixture if args.group=='namespace' else fixture.dependencies
        for path in (fixture.manifest,dependencies.manifest,dependencies.byte_manifest,dependencies.request_manifest,dependencies.budget_manifest):
            inputs[str(path)]=file_record(path)
        report['fixture_joint_build']=json.loads((fixture.folder/('joint-build.json' if args.group=='namespace' else 'ledger-joint-build.json')).read_bytes())
        write(output/'INPUTS.json',inputs)
        cases=[unittest.defaultTestLoader.loadTestsFromName(name) for name in IDS]
        _require(all(suite.countTestCases()==1 for suite in cases),'exact original cases did not collect')
        for name in METHODS:
            method=getattr(original_tests.NativeLifecycleTests,name)
            _require(method.__module__=='tests.test_hia_agent_native_tools','original method rebound')
        with ExitStack() as controls:
            controls.enter_context(holder.selected(joint=True) if args.group=='namespace' else holder.selected())
            if args.group=='namespace':controls.enter_context(holder.old_namespace_forbidden(hashing=False,payload_io=False))
            else:
                controls.enter_context(holder.old_ledger_forbidden())
                for name in ('put','json','get','get_json','resolve_uri','profile','check_profile','transaction'):
                    controls.enter_context(patch.object(store_api.AgentStore,'_'+name+'_reference',side_effect=forbidden))
                controls.enter_context(patch.object(store_api.AgentStore,'_ref',side_effect=forbidden))
            controls.enter_context(patch.object(service_api.HIAAgentService,'_call_reference',side_effect=forbidden))
            for cls in (budget._ReferenceExecutionBudgetStore,budget._ReferenceBudgetClaim):
                controls.enter_context(patch.object(cls,'__init__',side_effect=forbidden))
            controls.enter_context(patch.dict(os.environ,{evaluation.SELECTOR:str(manifest_path)}))
            controls.enter_context(patch.object(NativeEvaluationImage,'__init__',counted_init))
            controls.enter_context(patch.object(EvaluationFrame,'__init__',counted_frame))
            for name in qualification.REFERENCE_METHODS:controls.enter_context(patch.object(service_api.HIAAgentService,name,forbidden))
            for name in qualification.REFERENCE_FUNCTIONS:controls.enter_context(patch.object(service_api,name,forbidden))
            started=time.monotonic_ns()
            with (output/'ORIGINAL-TESTS.log').open('x') as stream:
                result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(unittest.TestSuite(cases))
            report['original_cases_elapsed_ns']=time.monotonic_ns()-started
        report.update(tests_run=result.testsRun,executed_ids=executed,
            failures=[(test.id(),trace) for test,trace in result.failures],errors=[(test.id(),trace) for test,trace in result.errors],
            skips=[(test.id(),why) for test,why in result.skipped],expected_failures=[(test.id(),trace) for test,trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        report['outcome']='PASS' if (result.wasSuccessful() and result.testsRun==len(IDS) and executed==list(IDS)
            and not any((result.skipped,result.expectedFailures,result.unexpectedSuccesses,references))) else 'FAIL'
        report['status']='OBSERVATION_COMPLETE'
    except BaseException:
        report.update(status='HOLD',traceback=traceback.format_exc())
    finally:
        if ready:fixture.tearDownClass()
        after=snapshot(source);write(output/'SOURCE-AFTER.json',after)
        report.update(source_files=len(before),source_unchanged=before==after,
            changed_source_paths=sorted(name for name in before.keys()|after.keys() if before.get(name)!=after.get(name)),
            input_bytes_unchanged=all(file_record(Path(path))==row for path,row in inputs.items()),
            actual_mappings=len(images),actual_machine_returns=sum(entries.values()),entries_by_mode=dict(entries),
            constructed_modes=dict(modes),machine_returns_per_test=dict(per_test),reference_entry_attempts=references,
            mapped_images_unchanged=all(sha256(image._mapping[:]).hexdigest()==manifest['image_sha256'] for image in images),
            events=events,total_elapsed_ns=time.monotonic_ns()-start)
        write(output/'FINAL-INPUTS.json',inputs);write(output/'REPORT.json',report)
    print(json.dumps({key:report.get(key) for key in ('group','status','outcome','tests_run','actual_machine_returns','source_unchanged','total_elapsed_ns')}),flush=True)
    return 0 if report['status']=='OBSERVATION_COMPLETE' and report['source_unchanged'] and report['input_bytes_unchanged'] and report['mapped_images_unchanged'] else 2

def main():
 global IDS
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True)
 p.add_argument('--evaluation-manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--group',choices=('namespace','ledger'));p.add_argument('--method',choices=METHODS);args=p.parse_args()
 if args.group:
  if args.method: IDS=('tests.test_hia_agent_native_tools.NativeLifecycleTests.'+args.method,)
  sys.path.insert(0,str(BASE))
  from budget_profiler import CostProbe
  with CostProbe(args): return child(args)
 out=args.output.resolve();out.mkdir(mode=0o700)
 original=BASE/'workflow_process.py'
 _require(sha256(original.read_bytes()).hexdigest()=='f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80','original supervisor differs')
 spec=importlib.util.spec_from_file_location('original_supervisor',original);supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
 env={name:value for name,value in os.environ.items() if not name.startswith('HEPTA_')}
 env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1')
 records=[]
 for group in ('namespace','ledger'):
  argv=[sys.executable,'-B',str(Path(__file__).resolve()),'--source',str(args.source.resolve()),'--compiler',str(args.compiler.resolve()),
        '--evaluation-manifest',str(args.evaluation_manifest.resolve()),'--output',str(out/group),'--group',group]
  row=supervisor.run_workflow_step(argv,cwd=args.source.resolve(),env=env,stdout_path=out/(group+'.stdout'),
   stderr_path=out/(group+'.stderr'),receipt_path=out/(group+'.terminal.json'),seconds=1800)
  records.append(row);print(json.dumps({'group':group,'status':row['status'],'seconds':row['seconds']}),flush=True)
 reports={group:json.loads((out/group/'REPORT.json').read_bytes()) if (out/group/'REPORT.json').is_file() else None for group in ('namespace','ledger')}
 complete=all(row['status']=='WORKFLOW_STEP_COMPLETED' for row in records) and all(r and r['status']=='OBSERVATION_COMPLETE' for r in reports.values())
 outcomes={group:None if r is None else r.get('outcome') for group,r in reports.items()}
 write(out/'REPORT.json',{'schema':'hepta.hia.evaluation.original-budget-six-outer.v1','records':records,
  'status':'OBSERVATION_COMPLETE' if complete else 'HOLD','original_method_outcomes':outcomes,
  'group_limits_seconds':1800,'compile_limits_seconds':20,'full_original_groups_run':False,'current_cold':False,'whole_native':False})
 return 0 if complete and all(value=='PASS' for value in outcomes.values()) else 1
if __name__=='__main__':raise SystemExit(main())
