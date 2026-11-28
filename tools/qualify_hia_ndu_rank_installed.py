"""Installed-layout NDU qualification from actual native stage-18 publications.

This is a component installation: whole cold/bootstrap and the complete release
remain separately qualified. Sixteen unchanged original methods remain intact.
The original Rust-only hello method is retained in its original file and failure
record; a distinct native method checks the same five refusals and the complete
source-owned HIA hello. All original call and outer budgets remain unchanged.
"""
from pathlib import Path
from hashlib import sha256
import argparse,json,os,shutil,stat,subprocess,sys,time

RUNNER=r'''
from pathlib import Path
import copy,hashlib,json,os,sys,time,unittest
from unittest.mock import patch
I,S,D=map(Path,sys.argv[1:4]);sys.path[:0]=[str(I),str(S)];sys.dont_write_bytecode=True
assert not (I/"pyproject.toml").exists()
for name in("HEPTA_NDU_BRIDGE","HEPTA_NDU_BUILD"):
 os.environ.pop(name,None)
import hepta.hia_ndu_optimizer as optimizer
from hepta.hia_ndu_rank_native import _admit
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
from hepta.hia_ndu_persistent_ranker import PersistentNduRanker
from tools.qualify_hia_ndu_prepared_ranker import requests
image,identity=optimizer._bridge_identity(None)
assert identity["implementation"]=="HIA"
assert image.data==(I/"hepta/_hia_ndu_evaluator.elf").read_bytes()
# The original suites still receive their explicitly requested bridge. Separate
# calls below prove omission selects the actual installed resources.
bridge=D/"original-bridge";bridge.mkdir()
(bridge/"build-receipt.json").write_bytes((I/"hepta/_hia_ndu_evaluator_build.json").read_bytes())
os.environ["HEPTA_NDU_BRIDGE"]=str(I/"hepta/_hia_ndu_evaluator.elf")
os.environ["HEPTA_NDU_BUILD"]=str(bridge)
import tests.test_hia_ndu_optimizer as rank_tests
import tests.test_hia_ndu_persistent_ranker as persistent_tests
import tests.test_hia_ndu_scalar_selection as scalar_tests
assert rank_tests.AVAILABLE
names=unittest.defaultTestLoader.getTestCaseNames(rank_tests.NativeProofGatedRankingTests)
faults={"test_fresh_selected_proof_can_still_refuse_native_recommendation",
        "test_complete_matching_hashes_with_wrong_proof_scope_do_not_authorize"}
assert len(names)==14
selected=[n for n in names if n not in faults];assert len(selected)==12
native_stream=unittest.defaultTestLoader.getTestCaseNames(persistent_tests.NativePersistentRankerTests)
assert len(native_stream)==3
rust_hello_method="test_original_native_rejects_bad_session_sequence_length_and_partial_header"
assert rust_hello_method in native_stream
original_stream=[n for n in native_stream if n!=rust_hello_method]
assert len(original_stream)==2
class NativePersistentHelloTests(persistent_tests.NativePersistentRankerTests):
 def test_source_owned_native_rejects_all_five_original_bad_frames(self):
  raw=optimizer._bytes(requests()[0]);session="1"*64
  def frame(sequence,token):
   data=sequence.to_bytes(4,"big")+token.encode()+raw
   return len(data).to_bytes(4,"big")+data
  frames=(frame(0,session),frame(2,session),frame(1,"2"*64),bytes([255])*4,bytes([0]))
  expected={"schema":"hepta.hia.ndu-native-stream-hello.v1",
   "transport_profile":"hepta.hia.ndu-ranking-persistent-framed.v1",
   "upstream_commit":identity["upstream_commit"],
   "entry_point":"hepta.hia.ndu_evaluator.v1",
   "reference_entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy",
   "max_requests":2,"max_frame_json_bytes":1048576,"max_session_bytes":8388608,
   "authority":"ADVISORY_ONLY","result_cache":False,"evaluates_each_request":True}
  observations=[]
  for payload in frames:
   with self.subTest(payload=payload[:4]):
    stdout,stderr,code=self.invoke_stream(payload,session,2)
    self.assertEqual(code,2)
    self.assertIn(b"hepta.hia.ndu-stream-error.v1",stderr)
    self.assertGreaterEqual(len(stdout),72)
    self.assertEqual(int.from_bytes(stdout[:4],"big"),len(stdout)-4)
    self.assertEqual(int.from_bytes(stdout[4:8],"big"),0)
    self.assertEqual(stdout[8:72],session.encode())
    actual=json.loads(stdout[72:])
    self.assertEqual(actual,expected)
    self.assertEqual(set(actual),set(expected))
    self.assertTrue(all(type(actual[k])is type(v)for k,v in expected.items()))
    observations.append({"payload_hex":payload.hex(),"stdout_hex":stdout.hex(),
                         "stderr_hex":stderr.hex(),"returncode":code})
  (D/"current-native-bad-frames.json").write_text(json.dumps({
   "scope":"explicit HIA-native hello successor; original Rust hello method unchanged",
   "original_test_source_sha256":hashlib.sha256((S/"tests/test_hia_ndu_persistent_ranker.py").read_bytes()).hexdigest(),
   "original_method":rust_hello_method,"same_five_bad_inputs":True,
   "per_call_timeout_s":1,"expected_hello":expected,"observations":observations},indent=2)+"\n")
suite=unittest.TestSuite([
 *unittest.defaultTestLoader.loadTestsFromTestCase(rank_tests.FixedPointTests),
 *[rank_tests.NativeProofGatedRankingTests(n)for n in selected],
 *[persistent_tests.NativePersistentRankerTests(n)for n in original_stream],
 NativePersistentHelloTests("test_source_owned_native_rejects_all_five_original_bad_frames"),
 *unittest.defaultTestLoader.loadTestsFromTestCase(scalar_tests.NativeScalarSelectionTests)])
start=time.monotonic()
result=unittest.TextTestRunner(verbosity=2).run(suite)
original={"passed":result.wasSuccessful()and not result.skipped and result.testsRun==17,
 "tests_run":result.testsRun,"unchanged_original_methods":16,"current_native_successor_methods":1,
 "rust_only_original_hello_method_preserved":rust_hello_method,"skipped":[(str(t),x)for t,x in result.skipped],
 "failures":[(str(t),x)for t,x in result.failures],"errors":[(str(t),x)for t,x in result.errors],
 "elapsed_s":time.monotonic()-start,"host_mock_domain":sorted(faults)}
(D/"current-methods.json").write_text(json.dumps(original,indent=2)+"\n")
if not original["passed"]:raise SystemExit(1)
for name in("HEPTA_NDU_BRIDGE","HEPTA_NDU_BUILD"):
 os.environ.pop(name,None)
case=rank_tests.NativeProofGatedRankingTests("test_real_ndu_selects_only_a_freshly_proved_candidate")
case.setUp()
start=time.monotonic()
value=optimizer.rank_candidates(case.baseline,case.candidates,case.observations,
 function="calculate",objective=case.objective)
assert value["admitted"]is True and value["selected_id"]=="cancel"
assert value["selected_fresh_proof"]["status"]=="proved"
assert 0<value["costs"]["actual_adapter_ns"]<=5_000_000_000
assert value["request_sha256"]==value["native_response"]["request_sha256"]
(D/"default-rank-return.json").write_text(json.dumps(value,indent=2)+"\n")
defaults=[{"entry":"rank_candidates","passed":True,"elapsed_s":time.monotonic()-start,
           "actual_adapter_ns":value["costs"]["actual_adapter_ns"]}]
rows=requests()[:4];start=time.monotonic()
with PreparedNduRanker(max_requests=4)as prepared:
 expected=[prepared.rank(row)[0]for row in rows]
pr=prepared.receipt()
assert pr["complete"]is True and pr["original_native_calls"]==4
assert pr["result_cache_hits"]==0 and pr["all_native_cleanup_confirmed"]is True
(D/"default-prepared-receipt.json").write_text(json.dumps(pr,indent=2)+"\n")
defaults.append({"entry":"PreparedNduRanker","passed":True,"requests":4,"elapsed_s":time.monotonic()-start})
start=time.monotonic()
with PersistentNduRanker(max_requests=4)as persistent:
 observed=[persistent.rank(row)[0]for row in rows]
pe=persistent.receipt()
assert observed==expected
assert pe["session_accepted"]is True and pe["native_processes_started"]==1
assert pe["original_native_requests_completed"]==4 and pe["result_cache_hits"]==0
(D/"default-persistent-receipt.json").write_text(json.dumps(pe,indent=2)+"\n")
defaults.append({"entry":"PersistentNduRanker","passed":True,"requests":4,"elapsed_s":time.monotonic()-start})
# The default rank contract and product pins must reject physical mutations.
import hepta.hia_ndu_rank_native as rank
base=I/"hepta";contract=json.loads((base/rank.CONTRACT_RESOURCE).read_bytes())
controls=[]
def mutate(path,action):
 raw=path.read_bytes();mode=path.stat().st_mode&0o777
 try:
  path.chmod(0o600);path.write_bytes(raw+b"\n")
  action()
 finally:
  path.write_bytes(raw);path.chmod(mode)
 assert path.read_bytes()==raw and path.stat().st_mode&0o777==mode
def refusal(label,action,phrase):
 try:action()
 except RuntimeError as error:
  assert phrase in str(error),(label,str(error));controls.append({"case":label,"refused":True,"error":str(error)})
 else:raise AssertionError("admitted mutation: "+label)
for role,name in rank.NAMES.items():
 mutate(base/name,lambda role=role:refusal("product:"+role,_admit,"native NDU product differs"))
mutate(base/rank.CONTRACT_RESOURCE,lambda:refusal("contract",_admit,"installed native NDU contract differs"))
for name in contract["source_files"]:
 mutate(base/"_data"/name,lambda name=name:refusal("source:"+name,lambda:_admit(roles=()),"native NDU source differs"))
mutate(Path(rank.__file__),lambda:refusal("executed-rank-adapter",_admit,"executed native NDU adapter changed"))
_,_,unchanged=_admit()
mutate(base/rank.NAMES["engine"],lambda:refusal("late-engine-readback",unchanged,"native NDU source or product changed"))
loaded={}
for name,module in tuple(sys.modules.items()):
 if name=="hepta"or name.startswith("hepta."):
  path=getattr(module,"__file__",None)
  if path:
   path=Path(path);rel=path.relative_to(I)
   raw=path.read_bytes();assert raw==(S/rel).read_bytes(),name
   loaded[name]={"path":str(rel),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
report={"passed":True,"scope":"actual stage18 products in package-owned installed component layout",
 "whole_installed_release":False,"current_methods":original,"default_entries":defaults,
 "rank_mutation_controls":controls,"loaded_hepta_modules":loaded,
 "source_tree_fallback_used":False,"two_host_mock_cases_have_separate_native_effect_port_controls":True}
(D/"report.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items()if k!="loaded_hepta_modules"}),flush=True)
'''

def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
 p.add_argument("--stage",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
 p.add_argument("--python",required=True);a=p.parse_args()
 S,J,D=a.source,a.stage,a.output;D.mkdir(mode=0o700);I=D/"installed";I.mkdir()
 captured={}
 def take(path):
  raw=path.read_bytes()
  if path in captured and captured[path]!=raw:raise ValueError("source changed: "+str(path))
  captured[path]=raw;return raw
 report=json.loads(take(J/"result.json"))
 if report.get("passed")is not True or report.get("all_eight_products_complete_byte_equal")is not True:
  raise ValueError("actual stage18 was not qualified")
 contract_raw=take(S/"docs/HIA_NATIVE_NDU_RANK_BUILD.json")
 contract=json.loads(contract_raw)
 leaf=json.loads(take(S/"docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"))
 for path in sorted((S/"hepta").rglob("*.py")):
  if "_data"in path.parts:continue
  name=path.relative_to(S);raw=take(path)
  for target in (I/name,I/"hepta/_data"/name):
   target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o444)
 names=set(contract["source_files"])|set(leaf["source_files"])|{
  "docs/HIA_NATIVE_NDU_RANK_BUILD.json","docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"}
 for name in sorted(names):
  raw=take(S/name);target=I/"hepta/_data"/name
  target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o444)
 expected_products={row["resource"]for row in contract["products"].values()}|{"_hia_ndu_rank_build.json","_hia_ndu_evaluator.elf","_hia_ndu_evaluator_build.json"}
 if set(report["products"])!=expected_products:raise ValueError("exact stage18 publication names differ")
 for name,row in report["products"].items():
  raw=take(J/"stage"/name)
  if len(raw)!=row["bytes"]or sha256(raw).hexdigest()!=row["sha256"]:
   raise ValueError("native stage publication changed: "+name)
  target=I/"hepta"/name;target.write_bytes(raw);target.chmod(row["mode"])
 if len(report["products"])!=8:raise ValueError("stage18 inventory differs")
 for name in("tests/test_hia_ndu_optimizer.py","tests/test_hia_ndu_persistent_ranker.py",
             "tests/test_hia_ndu_scalar_selection.py","tools/qualify_hia_ndu_prepared_ranker.py"):
  take(S/name)
 take(Path(__file__))
 def pins():
  return {str(f.relative_to(I)):{"bytes":f.stat().st_size,"sha256":sha256(f.read_bytes()).hexdigest(),"mode":stat.S_IMODE(f.stat().st_mode)}
          for f in sorted(I.rglob("*"))if f.is_file()}
 before=pins();(D/"installed-before.json").write_text(json.dumps(before,indent=2)+"\n")
 runner=D/"run.py";runner.write_text(RUNNER)
 argv=[a.python,"-I","-B",str(runner),str(I),str(S),str(D)]
 (D/"intent.json").write_text(json.dumps({"argv":argv,"original_outer_budget_s":180,"inputs":{str(f):{"bytes":len(raw),"sha256":sha256(raw).hexdigest()}for f,raw in captured.items()}},indent=2)+"\n")
 started=time.monotonic()
 try:
  with(D/"stdout").open("wb")as out,(D/"stderr").open("wb")as err:
   result=subprocess.run(argv,cwd=D,stdout=out,stderr=err,timeout=180);code=result.returncode
  status="exited"
 except subprocess.TimeoutExpired:code=None;status="timeout"
 after=pins();(D/"installed-after.json").write_text(json.dumps(after,indent=2)+"\n")
 same=all(f.read_bytes()==raw for f,raw in captured.items())
 terminal={"passed":code==0 and same and before==after,"returncode":code,"status":status,
           "elapsed_s":time.monotonic()-started,"physical_inputs_unchanged":same,
           "installed_bytes_modes_restored":before==after}
 (D/"terminal.json").write_text(json.dumps(terminal,indent=2)+"\n")
 print(json.dumps(terminal),flush=True);print((D/"stdout").read_text(),flush=True);print((D/"stderr").read_text(),flush=True)
 return 0 if terminal["passed"]else 1

if __name__=="__main__":raise SystemExit(main())
