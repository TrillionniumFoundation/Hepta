import cProfile,json,os,pstats,sys,time,unittest
from pathlib import Path
from collections import Counter
from unittest.mock import patch
sys.path.insert(0,'/workspace/scratch/e26ed3e2edcf/hia-native-wire-entry')
from hepta.hia_json_wire_native import NativeJsonWire,WireSession,SELECTOR
from hepta.hia_agent_service import HIAAgentService
os.environ[SELECTOR]='/workspace/scratch/e26ed3e2edcf/wire-entry-development-r1/manifest.json'
profile=cProfile.Profile()
original=HIAAgentService._hia_evaluate
summaries=[]
def evaluate(self,args):
 start=time.monotonic();profile.enable()
 try:return original(self,args)
 finally:
  profile.disable();summaries.append({'tool':'_hia_evaluate','wall_seconds':time.monotonic()-start})
name='tests.test_hia_agent_native_tools.NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'
with patch.object(HIAAgentService,'_hia_evaluate',evaluate):
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromName(name))
root=Path('/workspace/scratch/e26ed3e2edcf')
profile.dump_stats(str(root/'wire-entry-native-timeout-profile-r1.pstats'))
with (root/'wire-entry-native-timeout-profile-r1.txt').open('w') as out:
 stats=pstats.Stats(profile,stream=out);stats.sort_stats('cumulative').print_stats(65);stats.sort_stats('tottime').print_stats(45)
report={'scope':'DIAGNOSTIC_PROFILER_OVERHEAD_NOT_QUALIFICATION','test_id':name,'tests_run':result.testsRun,'failures':[{'test':t.id(),'trace':trace} for t,trace in result.failures],'errors':[{'test':t.id(),'trace':trace} for t,trace in result.errors],'evaluation':summaries}
(root/'wire-entry-native-timeout-profile-r1.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
