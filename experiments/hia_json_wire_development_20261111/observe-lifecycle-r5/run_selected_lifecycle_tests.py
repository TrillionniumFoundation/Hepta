import argparse,json,os,sys,unittest
from pathlib import Path
from hashlib import sha256
p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--existing-controls',action='store_true');a=p.parse_args()
if a.output.exists():raise FileExistsError(a.output)
for k in list(os.environ):
 if k.startswith('HEPTA_HIA_'):del os.environ[k]
sys.path.insert(0,str(a.source_root))
from hepta.hia_json_wire_native import installed_json_wire,SOURCE
from tests.test_hia_json_wire_native import WireNativeTests
assert SOURCE.resolve()==(a.source_root/'examples/hia_bootstrap/json_wire.hiaasm').resolve()
image=installed_json_wire(str(a.manifest))
class ExistingImageControls(WireNativeTests):
 @classmethod
 def setUpClass(cls):cls.image=image
 @classmethod
 def tearDownClass(cls):pass
names=['test_observations_are_once_per_request_and_never_after_terminal']
if a.existing_controls:names+=['test_protocol_sequence_extent_and_output_canaries','test_private_buffer_lifetime_after_observer_exceptions_and_reentry']
suite=unittest.TestSuite(ExistingImageControls(n) for n in names)
ids=[t.id() for t in suite]
paths={'adapter':a.source_root/'hepta/hia_json_wire_native.py','test':a.source_root/'tests/test_hia_json_wire_native.py','source':SOURCE,'manifest':a.manifest,'image':a.manifest.parent/json.loads(a.manifest.read_bytes())['image_path']}
pins={k:sha256(v.read_bytes()).hexdigest() for k,v in paths.items()}
r=unittest.TextTestRunner(verbosity=2).run(suite)
stable=all(sha256(v.read_bytes()).hexdigest()==pins[k] for k,v in paths.items())
report={'schema':'hepta.hia.wire-observe-lifecycle-tests.v1','scope':'EXPLICIT_EXISTING_R5_DEVELOPMENT_IMAGE_TEST_METHODS_NOT_CURRENT_COLD_BUILD','python':sys.version,'executable':sys.executable,'test_ids':ids,'tests_run':r.testsRun,'failures':[(t.id(),e) for t,e in r.failures],'errors':[(t.id(),e) for t,e in r.errors],'skipped':r.skipped,'expected_failures':[(t.id(),e) for t,e in r.expectedFailures],'unexpected_successes':[t.id() for t in r.unexpectedSuccesses],'pins_before':pins,'pins_stable':stable,'status':'PASS' if r.wasSuccessful() and stable and not(r.skipped or r.expectedFailures or r.unexpectedSuccesses) else 'HOLD'}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
raise SystemExit(0 if report['status']=='PASS' else 1)
