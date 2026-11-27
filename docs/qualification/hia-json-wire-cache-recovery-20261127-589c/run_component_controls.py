from pathlib import Path
from hashlib import sha256
import json,sys,os,unittest,time,subprocess,contextlib
ROOT=Path('/tmp/hepta-6ddb-recovery-589c')
D=Path('/workspace/scratch/589c0a6dd85b/runtime-6ddb-wire-controls-589c');D.mkdir(exist_ok=False)
paths=subprocess.check_output(['git','diff','--name-only'],cwd=ROOT).decode().splitlines()+['tools/generate_hia_sha256_stream.py','examples/hia_bootstrap/sha256_stream.hepta','docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_NATIVE_SOURCE_AUTHORITY.json']
def pins():return {path:{'bytes':(ROOT/path).stat().st_size,'sha256':sha256((ROOT/path).read_bytes()).hexdigest()} for path in paths}
before=pins()
from tools import qualify_hia_selfhost
old=Path('/tmp/hia-historical-p3-final-cold-589c.json').read_bytes();assert sha256(old).hexdigest()=='00ef3a2c17ec6424bc2fd61a87ea1b6c469341a6385464b3c7c9c172eb69c42e'
observer=bytes.fromhex(json.loads(old)['native_flat_observer_hex']);qualify_hia_selfhost.NATIVE_OBSERVER=observer
os.environ['HEPTA_HIA_JSON_WIRE_DEVELOPMENT_MANIFEST']='/workspace/scratch/589c0a6dd85b/runtime-6ddb-wire-development-589c/manifest.json'
os.environ['HEPTA_HIA_JSON_WIRE_CACHE_FIXTURE_EVIDENCE']=str(D/'cache-fixture')
classes=['tests.test_hia_json_wire_cache.WireCacheNativeTests','tests.test_hia_json_wire_native.WireSourceTests','tests.test_hia_selfhost_chain.ChainAllocatorChildBoundaryTests']
suite=unittest.defaultTestLoader.loadTestsFromNames(classes);started=time.monotonic()
with (D/'stdout').open('w') as stdout,(D/'stderr').open('w') as stderr,contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):result=unittest.TextTestRunner(stream=stderr,verbosity=2).run(suite)
after=pins();record={'schema':'hepta.hia.json-wire-cache-recovery-controls.v1','base_commit':'06d21f6032d7b3a946b1d6581a13c5cfd5fa4375','historical_feature_commit':'6ddb7d4bda799befdaf9c92f5e9586c71042cda9','source_before':before,'source_after':after,'source_unchanged':before==after,'classes':classes,'tests':result.testsRun,'errors':[(str(test),detail) for test,detail in result.errors],'failures':[(str(test),detail) for test,detail in result.failures],'skipped':result.skipped,'elapsed_seconds':time.monotonic()-started,'python':sys.version,'native_compile_observer_sha256':sha256(observer).hexdigest(),'scope':'EXPLICIT_DEVELOPMENT_ONLY; real historical native B1 and observer, no current cold qualification','installed_complete_release_qualified':False,'whole_stack_native':False}
(D/'receipt.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({key:record[key] for key in ('tests','errors','failures','skipped','elapsed_seconds','source_unchanged')},sort_keys=True))
if not result.wasSuccessful() or before!=after:sys.exit(1)
