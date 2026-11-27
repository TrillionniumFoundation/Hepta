from pathlib import Path
from hashlib import sha256
import json,os,subprocess,sys,tempfile,time,unittest
root=Path("/dev/shm/hia-core-wiring-integrated-20261127-2807")
out=Path("/dev/shm/hia-core-wiring-integration-control-2807/validation-de14-v1")
out.mkdir(mode=0o700,exist_ok=False)
temporary=Path("/tmp/hia-core-wiring-de14-controls-2807");temporary.mkdir(mode=0o700,exist_ok=False);os.environ["TMPDIR"]=str(temporary);tempfile.tempdir=str(temporary)
sys.path.insert(0,str(root))
selectors=[
 "tests.test_hia_cold_compiler",
 "tests.test_hia_native_cold_ci",
 "tests.test_hia_component_input_custody",
 "tests.test_hia_native_cold_custody_readers",
 "tests.test_hia_cold_native_transport.ColdNativeTransportSourceTests",
 "tests.test_hia_cold_native_transport.ColdNativeTransportLibraryPathTests",
 "tests.test_hia_cold_native_transport_controls.ColdNativeTransportControlsSourceTests",
 "tests.test_hia_component_cold_readback",
 "tests.test_hia_store_file_capture_native_readback"]
def flatten(s):
 for v in s:
  if isinstance(v,unittest.TestSuite):yield from flatten(v)
  else:yield v.id()
suite=unittest.defaultTestLoader.loadTestsFromNames(selectors)
ids=list(flatten(suite));assert len(ids)==len(set(ids))
start=time.monotonic()
with (out/"strict-controls.log").open("w") as log:
 result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
summary={"selectors":selectors,"ids":ids,"planned":len(ids),"run":result.testsRun,
 "failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),
 "elapsed_seconds":time.monotonic()-start,"python":sys.version,
 "scope":"structural admission, real temporary Git and physical bytes; no native campaign executed",
 "temporary_directory":str(temporary),
 "log_sha256":sha256((out/"strict-controls.log").read_bytes()).hexdigest(),
 "failure_details":[[str(t),e] for t,e in result.failures+result.errors]}
(out/"summary.json").write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
print(json.dumps(summary,sort_keys=True),flush=True)
if not result.wasSuccessful() or result.skipped or result.testsRun!=len(ids):raise SystemExit(1)
