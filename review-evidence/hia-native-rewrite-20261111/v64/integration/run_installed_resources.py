"""Actual installed-resource class, including the v63 shared-source regression."""
from hashlib import sha256
import json, os
from pathlib import Path
import resource, shutil, sys, tempfile, time, unittest
from unittest.mock import patch

ROOT=Path('/workspace/scratch/9acdfa9f5639/native-v64-integration')
OUT=Path(sys.argv[1]).resolve();OUT.mkdir(parents=True,exist_ok=False)
RAW=Path(sys.argv[2]).resolve();RAW.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(ROOT));os.chdir(ROOT)
( RAW/'tmp').mkdir();os.environ['TMPDIR']=str(RAW/'tmp');tempfile.tempdir=str(RAW/'tmp')
from tools.build_hia_json_preflight import current_sources
from tests.test_hia_agent_installed_resources import AgentInstalledResourceTests
from hepta.hia_json_preflight_native import NativeHiaJsonImage
before=current_sources();(OUT/'source-before.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
images={};init=NativeHiaJsonImage.__init__
def initialize(instance,image,digest):
 init(instance,image,digest);entry=instance._entry
 def observed(*args):
  images[digest]=images.get(digest,0)+1
  return entry(*args)
 instance._entry=observed
cleanup=AgentInstalledResourceTests.tearDownClass.__func__
def preserve(cls):
 try:
  folder=cls.folder
  shutil.copytree(folder,RAW/'installed-originals')
  rows=[]
  for p in sorted(folder.rglob('*')):
   if p.is_file():
    raw=p.read_bytes();copy=RAW/'installed-originals'/p.relative_to(folder)
    if copy.read_bytes()!=raw:raise AssertionError('installed original copy differs')
    rows.append({'path':p.relative_to(folder).as_posix(),'bytes':len(raw),'sha256':sha256(raw).hexdigest()})
  (RAW/'installed-original-custody.json').write_text(json.dumps({'schema':'hepta.hia.installed-resource-originals.v1','scope':'ACTUAL_DEVELOPMENT_BUILD_NOT_COLD','files':rows},indent=2)+'\n')
 finally:
  cleanup(cls)
started=time.monotonic();result=None
try:
 with patch.object(NativeHiaJsonImage,'__init__',new=initialize),patch.object(AgentInstalledResourceTests,'tearDownClass',new=classmethod(preserve)):
  result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AgentInstalledResourceTests))
finally:
 after=current_sources();(OUT/'source-after.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
 value={'schema':'hepta.hia.actual-installed-resource-observation.v1','scope':'DEVELOPMENT_ONLY_NOT_COLD','source_preserved':before==after,'seconds':time.monotonic()-started,'python':sys.version,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'actual_parent_image_entries':images,'tests_run':result.testsRun if result else None,'raw_evidence_directory':str(RAW)}
 if result is not None:
  value.update(failures=[{'test':str(t),'traceback':s} for t,s in result.failures],errors=[{'test':str(t),'traceback':s} for t,s in result.errors],skipped=[{'test':str(t),'reason':s} for t,s in result.skipped],expected_failures=[{'test':str(t),'traceback':s} for t,s in result.expectedFailures],unexpected_successes=[str(t) for t in result.unexpectedSuccesses])
 value['passed']=bool(result and result.testsRun and result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and before==after)
 (OUT/'summary.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
 print(json.dumps({key:value[key] for key in ('tests_run','seconds','passed','source_preserved')}),flush=True)
if not value['passed']:raise SystemExit(1)
