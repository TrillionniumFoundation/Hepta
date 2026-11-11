"""Fresh actual eleven-image integration observation; no qualification claim."""
from contextlib import ExitStack
from hashlib import sha256
import json, os
from pathlib import Path
import resource, sys, time, unittest
from unittest.mock import patch

ROOT=Path('/workspace/scratch/9acdfa9f5639/native-v64-integration')
OUT=Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(ROOT))
os.chdir(ROOT)
from tests.hia_composite_function_fixture import DEVELOPMENT_KEYS,COLD_KEYS
from tools.hia_selfhost_contract import validate_contract
from tools.build_hia_json_preflight import current_sources
from hepta.hia_json_preflight_native import NativeHiaJsonImage

scope='BOOTSTRAP_DEVELOPMENT_ONLY'
selectors=('COMPOSITE_TYPES','TASK_HELPERS','COMPOSITE_FUNCTIONS','COMPOSITE_CONSTRUCTOR','COMPOSITE_OUTER')
for key in (*DEVELOPMENT_KEYS,*COLD_KEYS,*('HEPTA_HIA_'+name+'_MANIFEST' for name in selectors)):
 os.environ.pop(key,None)
temporary=Path(sys.argv[2]).resolve()
temporary.mkdir(parents=True,exist_ok=False)
(temporary/'tmp').mkdir()
os.environ['TMPDIR']=str(temporary/'tmp')
import tempfile
tempfile.tempdir=str(temporary/'tmp')
os.environ['HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE']=str(temporary/'fixture')
os.environ['HEPTA_HIA_FUNCTION_TERMS_EVIDENCE']=str(temporary/'terms')
os.environ['HEPTA_HIA_CONSTRUCTOR_EVIDENCE']=str(temporary/'constructor')
os.environ['HEPTA_HIA_CONSTRUCTOR_INTEGRATION_EVIDENCE']=str(temporary/'constructor-integration')
os.environ['HEPTA_HIA_OUTER_EVIDENCE']=str(temporary/'outer')
os.environ['HEPTA_HIA_OUTER_INTEGRATION_EVIDENCE']=str(temporary/'outer-integration')

before=current_sources()
(OUT/'source-before.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
contract=validate_contract()
names=contract['composite_complete_elaboration']['required_test_modules']
entries={}
original=NativeHiaJsonImage.__init__
def observe_image(instance,image,expected_sha256):
 original(instance,image,expected_sha256)
 delegate=instance._entry
 def invoke(*args):
  entries[expected_sha256]=entries.get(expected_sha256,0)+1
  return delegate(*args)
 instance._entry=invoke
started=time.monotonic()
result=None
try:
 with patch.object(NativeHiaJsonImage,'__init__',new=observe_image):
  result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))
finally:
 after=current_sources()
 (OUT/'source-after.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
 (OUT/'native-entry-ledger.json').write_text(json.dumps(entries,indent=2,sort_keys=True)+'\n')
 value={'scope':scope,'whole_stack_qualification':False,'source_preserved':before==after,'modules':names,'seconds':time.monotonic()-started,'python':sys.version,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'actual_parent_image_entries':sum(entries.values()),'image_entry_counts':entries,'raw_evidence_directory':str(temporary),'tests_run':result.testsRun if result else None}
 if result is not None:
  value.update(failures=[{'test':str(t),'traceback':s} for t,s in result.failures],errors=[{'test':str(t),'traceback':s} for t,s in result.errors],skipped=[{'test':str(t),'reason':s} for t,s in result.skipped],expected_failures=[{'test':str(t),'traceback':s} for t,s in result.expectedFailures],unexpected_successes=[str(t) for t in result.unexpectedSuccesses])
 value['passed']=bool(result and result.testsRun and result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and before==after)
 (OUT/'summary.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
 print(json.dumps({key:value[key] for key in ('scope','tests_run','seconds','source_preserved','passed','actual_parent_image_entries','max_rss_kib')}),flush=True)
if not value['passed']:raise SystemExit(1)
