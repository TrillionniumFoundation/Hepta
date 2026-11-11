"""Run the three original budget regressions with selected wire and retained owners forbidden."""
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
parser=argparse.ArgumentParser()
parser.add_argument('--source-root',required=True,type=Path)
parser.add_argument('--manifest',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args()
if args.output.exists():raise FileExistsError(args.output)
sys.path.insert(0,str(args.source_root))
from hepta import hia_program_tools as program_tools
from hepta.hia_json_wire_native import NativeJsonWire,WireSession,SELECTOR,installed_json_wire
ids=['tests.test_hia_agent_native_tools.NativeLifecycleTests.'+name for name in ('test_expired_evaluation_is_rejected_before_any_reference_or_native_runner','test_native_timeout_is_incomplete_terminated_and_not_adoptable','test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline')]
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in ids)
image=installed_json_wire(str(args.manifest))
sources={name:sha256((args.source_root/name).read_bytes()).hexdigest() for name in ('hepta/hia_json_wire_native.py','hepta/hia_program_tools.py','hepta/hia_agent_store.py','tests/test_hia_agent_native_tools.py','examples/hia_bootstrap/json_wire.hiaasm')}
executed=[];current=[None];calls=Counter();steps=Counter();retained=[];encoders=[]
original_encode=NativeJsonWire.encode_ordinary;original_step=WireSession.step

def no_retained(*values,**options):
 retained.append(current[0]);raise AssertionError('retained wire decision owner entered')

def no_encoder(*values,**options):
 encoders.append(current[0]);raise AssertionError('host encoder entered native wire')

def encode(owner,*values,**options):
 assert owner.image_sha256==image.image_sha256
 calls[current[0]]+=1
 with patch.object(json.JSONEncoder,'iterencode',no_encoder):return original_encode(owner,*values,**options)

def step(session,packet=None):
 result=original_step(session,packet);steps[str(result)]+=1;return result

class Result(unittest.TextTestResult):
 def startTest(self,test):
  current[0]=test.id();executed.append(test.id());super().startTest(test)
 def stopTest(self,test):super().stopTest(test);current[0]=None

started=time.monotonic()
with patch.dict(os.environ,{SELECTOR:str(args.manifest)}),patch.object(program_tools,'_reference_bounded_json_wire',no_retained),patch.object(NativeJsonWire,'encode_ordinary',encode),patch.object(WireSession,'step',step):
 result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
stable=all(sha256((args.source_root/name).read_bytes()).hexdigest()==value for name,value in sources.items())
anomalies=(result.failures,result.errors,result.skipped,result.expectedFailures,result.unexpectedSuccesses)
passed=(executed==ids and result.testsRun==len(ids) and not any(anomalies) and not retained and not encoders and all(calls[name]>0 for name in ids) and stable)
report={'schema':'hepta.hia.json-wire-original-budget-recheck.v1','scope':'DEVELOPMENT_FOCUSED_ORIGINAL_TESTS_NOT_COLD_QUALIFICATION','status':'PASS' if passed else 'FAIL','python':sys.version,'executable':sys.executable,'loaded_test_ids':ids,'executed_test_ids':executed,'tests_run':result.testsRun,'failures':[{'test':test.id(),'trace':trace} for test,trace in result.failures],'errors':[{'test':test.id(),'trace':trace} for test,trace in result.errors],'skipped':[{'test':test.id(),'reason':reason} for test,reason in result.skipped],'expected_failures':[{'test':test.id(),'trace':trace} for test,trace in result.expectedFailures],'unexpected_successes':[test.id() for test in result.unexpectedSuccesses],'source_sha256':sources,'source_stable':stable,'per_test_native_wire_calls':dict(calls),'native_return_counts':dict(steps),'retained_owner_entries':retained,'host_encoder_entries':encoders,'manifest_path':str(args.manifest),'manifest':json.loads(args.manifest.read_bytes()),'wall_seconds':time.monotonic()-started,'original_budget_and_assertions_unchanged':True,'whole_89_qualification_claimed':False}
args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'tests_run':result.testsRun,'report':str(args.output)}))
raise SystemExit(0 if passed else 1)
