from pathlib import Path
import hashlib,json,time,unittest,sys
root=Path(__file__).parent/'source';sys.path.insert(0,str(root))
out=Path(__file__).parent/'tests';out.mkdir(exist_ok=False)
manifest=json.loads((root.parent/'SOURCE_MANIFEST.json').read_bytes())
def stable():
 return all((root/n).is_file() and hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in manifest['files'].items())
assert stable()
modules=['tests.test_hia_semantics_contract','tests.test_hia_program','tests.test_hia_program_llvm','tests.test_hia_program_composite','tests.test_hia_call_expansion','tests.test_hia_planning','tests.test_hia_ndu','tests.test_hia_guarded_optimization','tests.test_hia_optimization','tests.test_hia_ndu_graph','tests.test_cpp_callback_project','tests.test_hia_planning_boundaries']
loaded=unittest.defaultTestLoader.loadTestsFromNames(modules)
def flatten(t):
 for x in t:
  if isinstance(x,unittest.TestSuite):yield from flatten(x)
  else:yield x
external='tests.test_cpp_callback_project.CallbackProjectTests.test_closed_callback_implementation_and_native_cleanup'
tests=[t for t in flatten(loaded) if t.id()!=external]
plan={'modules':modules,'test_ids':[t.id() for t in tests],'schema':'hepta.five-deliverables.integration-tests.v1','test_count':len(tests),'started_unix_ns':time.time_ns(),'external_gate':{'replaces_duplicate_native_test':external,'qualification_command':'python tools/qualify_cpp_callback_project.py --workdir ../callback --clang CLANG --clangxx CLANGXX --iterations 200000 --repeats 5','status':'required_separately'},'source_content_sha256':manifest['source_content_sha256']}
(out/'PLAN.json').write_text(json.dumps(plan,indent=2)+'\n');started=time.monotonic_ns()
with (out/'tests.log').open('w') as log:r=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.TestSuite(tests))
unchanged=stable()
result={**plan,'tests_run':r.testsRun,'failures':[(str(t),v) for t,v in r.failures],'errors':[(str(t),v) for t,v in r.errors],'skipped':[(str(t),v) for t,v in r.skipped],'elapsed_ns':time.monotonic_ns()-started,'sources_unchanged':unchanged,'passed':r.wasSuccessful() and not r.skipped and unchanged}
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in {'modules','test_ids'}}),flush=True)
raise SystemExit(0 if result['passed'] else 1)
