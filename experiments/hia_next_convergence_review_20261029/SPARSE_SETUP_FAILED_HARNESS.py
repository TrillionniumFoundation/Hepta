import datetime,hashlib,io,json,os,pathlib,subprocess,sys,time,unittest
ROOT=pathlib.Path('/tmp/hepta-next-convergence-review-20261029')
sys.path.insert(0,str(ROOT)); os.chdir(ROOT)
PREFIX=pathlib.Path('/tmp/hepta-convergence-93b1c80-light-regression-01')
NAMES=['tests.test_hia_schema_unification','tests.test_hia_schema_binding_audit','tests.test_hia_schema_collision','tests.test_hia_json_preflight','tests.test_hia_program','tests.test_hia_heap_bound','tests.test_hia_static_budget','tests.test_hia_entry_payload_bound','tests.test_hia_prepared.PreparationReservationTests','tests.test_hia_round3_routes','tests.test_hia_ndu_prepared_reuse','tests.test_hia_ndu_activation.ActivationForecastTests','tests.test_hia_legacy_irpgo','tests.test_hia_agent_primitive_into','tests.test_hia_agent_repair','tests.test_migration_ir_identifier_guard','tests.test_migration_ir_literal_guard','tests.test_migration_ir_neg_payload_guard','tests.test_migration_ir_parser_budget','tests.test_migration_ir_structural_budget']
def git(*args):return subprocess.check_output(['git',*args],text=True).strip()
def snapshot(): return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1')}
before=snapshot(); assert before['commit']=='93b1c8002c2a41573080cca41a279a0a0fa4e915' and before['status']=='',before
commands=[]
def observe(event,args):
 if event=='subprocess.Popen': commands.append({'executable':str(args[0]),'argv':[str(x) for x in args[1]] if isinstance(args[1],(tuple,list)) else str(args[1])})
sys.addaudithook(observe)
started=time.monotonic_ns()
with PREFIX.with_suffix('.log').open('x') as log:
 result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
wall=time.monotonic_ns()-started
after=snapshot()
blocked_names=('clang','rustc','cargo','gcc','g++','clang++','llama','llvm-profdata','opt')
native=[r for r in commands if pathlib.Path(r['executable']).name.startswith(blocked_names)]
record={'schema':'hepta.hia.convergence-light-regression.v1','source':before,'source_unchanged':before==after,'command':[sys.executable,str(pathlib.Path(__file__).resolve())],'cwd':str(ROOT),'harness_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'python':{'executable':sys.executable,'version':sys.version,'sha256':hashlib.sha256(pathlib.Path(sys.executable).resolve().read_bytes()).hexdigest()},'suites':NAMES,'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'log_sha256':hashlib.sha256(PREFIX.with_suffix('.log').read_bytes()).hexdigest(),'elapsed_ns':wall,'subprocess_events':commands,'native_compiler_or_model_events':native,'performance_experiments':0,'environment':'shared-cloud-scratch-not-verified-user-dot','completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
PREFIX.with_suffix('.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:record[k] for k in ['tests','failures','errors','skips','source_unchanged','elapsed_ns','native_compiler_or_model_events']}))
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and before==after and not native else 1)
