"""Retain the complete new native CI module group against one matching cold."""
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import json, os, resource, shutil, sys, tempfile, time, unittest
from unittest.mock import patch

ROOT=Path('/workspace/scratch/9acdfa9f5639/native-agent-state-integration')
OUT=ROOT.parent/'hia-agent-state-integration-development'/'native-stage3-attempt1'
RAW=Path('/dev/shm/hia-v65-state-native-r1')
COLD=Path('/dev/shm/hia-v65-stage3-cold/cold.json')
frozen=json.loads((OUT.parent/'draft-stage3-source.json').read_bytes())['source_closure']
def sources():return {name:sha256((ROOT/name).read_bytes()).hexdigest() for name in frozen}
before=sources();assert before==frozen
cold=json.loads(COLD.read_bytes())
assert cold['status']=='COLD_SELFHOST_REPLAY_PASS' and cold['source_manifest']==before
assert cold['qualification_wall_limit_seconds']==180 and len(cold['checks'])==11 and all(cold['checks'].values())
OUT.mkdir();RAW.mkdir(mode=0o700);(RAW/'tmp').mkdir(mode=0o700);(RAW/'preserved').mkdir()
sys.path.insert(0,str(ROOT));os.chdir(ROOT)
os.environ['TMPDIR']=str(RAW/'tmp');tempfile.tempdir=str(RAW/'tmp')
for component in ('WORKER_REQUEST','AGENT_JOURNAL','RELEASE_INSTALL','COMPOSITE_TYPES','TASK_HELPERS'):
    os.environ.pop('HEPTA_HIA_'+component+'_DEVELOPMENT_MANIFEST',None)
    os.environ['HEPTA_HIA_'+component+'_COLD_REPORT']=str(COLD)
os.environ['HEPTA_HIA_RELEASE_INSTALL_OBSERVATIONS']=str(RAW/'release-observations')
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tests.test_hia_worker_request_native import WorkerRequestNativeTests
from tests.test_hia_worker_request_review import WorkerRequestAdversarialTests
from tests.test_hia_agent_journal_native import JournalNativeTests
from tests.test_hia_composite_native_composition import NativeTests as CompositionNativeTests

modules=('tests.test_hia_worker_request_native','tests.test_hia_worker_request_review',
         'tests.test_hia_release_install','tests.test_hia_agent_journal_native',
         'tests.test_hia_composite_native_composition')
suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
def flatten(s):
    for item in s:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item
chosen_ids=[t.id() for t in flatten(suite)];executed=[]
assert chosen_ids and len(chosen_ids)==len(set(chosen_ids))
images=Counter();per_case={};current=['outside-test'];image_init=NativeHiaJsonImage.__init__
def initialize(instance,image,digest):
    image_init(instance,image,digest);entry=instance._entry
    def observe(*args):
        images[digest]+=1;per_case.setdefault(current[0],Counter())[digest]+=1
        return entry(*args)
    instance._entry=observe
class Result(unittest.TextTestResult):
    def startTest(self,test):
        current[0]=test.id();executed.append(test.id());super().startTest(test)
    def stopTest(self,test):
        super().stopTest(test);current[0]='outside-test'

def preserve_teardown(cls):
    original=cls.tearDownClass.__func__
    def finish(owner):
        temporary=getattr(owner,'temporary',None) or getattr(owner,'temp',None)
        if temporary:
            folder=Path(temporary.name);destination=RAW/'preserved'/owner.__name__
            if folder.exists():
                shutil.copytree(folder,destination,symlinks=True)
                records={}
                for source in sorted(folder.rglob('*')):
                    target=destination/source.relative_to(folder)
                    if source.is_symlink():assert target.is_symlink() and os.readlink(source)==os.readlink(target)
                    elif source.is_file():
                        data=source.read_bytes();assert target.read_bytes()==data
                        assert source.stat().st_mode&0o777==target.stat().st_mode&0o777
                        records[source.relative_to(folder).as_posix()]={'bytes':len(data),'sha256':sha256(data).hexdigest(),'mode':source.stat().st_mode&0o777}
                (OUT/(owner.__name__+'-preserved.json')).write_text(json.dumps({'original':str(folder),'retained':str(destination),'files':records},indent=2,sort_keys=True)+'\n')
        original(owner)
    return classmethod(finish)

started=time.monotonic_ns();result=None
(OUT/'source-before.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
try:
    with ExitStack() as stack:
        stack.enter_context(patch.object(NativeHiaJsonImage,'__init__',initialize))
        # The adversarial class delegates teardown to WorkerRequestNativeTests;
        # patch its shared owner once so each original folder is copied once.
        for cls in (WorkerRequestNativeTests,JournalNativeTests,CompositionNativeTests):
            stack.enter_context(patch.object(cls,'tearDownClass',preserve_teardown(cls)))
        result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,resultclass=Result).run(suite)
finally:
    after=sources();(OUT/'source-after.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
    value={'schema':'hepta.hia.v65-state-native-module-group.v1','scope':'MATCHING_FROZEN_SOURCE_COLD_BUILD','modules':modules,'cold_report_sha256':sha256(COLD.read_bytes()).hexdigest(),'chosen_test_ids':chosen_ids,'executed_test_ids':executed,'tests_loaded':len(chosen_ids),'tests_run':result.testsRun if result else None,'seconds':(time.monotonic_ns()-started)/1e9,'source_preserved':before==after,'raw_directory':str(RAW),'python':sys.version,'executable':sys.executable,'actual_parent_native_image_entries':dict(images),'native_entry_counts_exclude_isolated_children':True,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'whole_stack_closed':False}
    if result:
        value.update(errors=[{'test':str(t),'traceback':s} for t,s in result.errors],failures=[{'test':str(t),'traceback':s} for t,s in result.failures],skipped=[{'test':str(t),'reason':s} for t,s in result.skipped],expected_failures=[{'test':str(t),'traceback':s} for t,s in result.expectedFailures],unexpected_successes=[str(t) for t in result.unexpectedSuccesses])
    value['passed']=bool(result and result.testsRun==len(chosen_ids) and executed==chosen_ids and result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and before==after)
    (OUT/'summary.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    (OUT/'native-entry-ledger.json').write_text(json.dumps(per_case,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:value[k] for k in ('passed','tests_run','tests_loaded','seconds','source_preserved','max_rss_kib')}),flush=True)
raise SystemExit(0 if value['passed'] else 1)
