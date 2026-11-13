"""The six original selected methods, with their fixtures and source-only effect denial."""
from __future__ import annotations
import argparse,ctypes,mmap,os,socket,subprocess,sys,time,traceback,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_common as common
def flatten(suite):
 for test in suite:
  if isinstance(test,unittest.TestSuite):yield from flatten(test)
  else:yield test
def main():
 p=argparse.ArgumentParser();p.add_argument("--request",type=Path,required=True);p.add_argument("--sha256",required=True);a=p.parse_args()
 os.umask(0o077);r,m,rp=common.load_request(a.request,a.sha256);out=Path(r["output_root"]);root=Path(r["source_root"])
 report={"schema":"hia.core39.snapshot-revision.source6.v1","status":"HOLD","request_sha256":rp["sha256"],"actual_wrapper_argv":list(sys.argv),"expected_ids":r["selected_ids"],"loaded_ids":[],"executed_ids":[],"success_ids":[],"failures":[],"errors":[],"skipped":[],"expected_failures":[],"unexpected_successes":[],"loader_errors":[],"forbidden_attempts":[],"exception":None}
 start=time.monotonic_ns()
 def forbidden(label):
  def refuse(*args,**kwargs):
   report["forbidden_attempts"].append(label);raise AssertionError("source-only forbidden entry: "+label)
  return refuse
 def audit(event,args):
  if event in {"subprocess.Popen","os.system","os.posix_spawn","os.fork","ctypes.dlopen","mmap.__new__","socket.__new__"}:forbidden("audit:"+event)()
 sys.addaudithook(audit)
 class Result(unittest.TextTestResult):
  def startTest(self,test):report["executed_ids"].append(test.id());super().startTest(test)
  def addSuccess(self,test):report["success_ids"].append(test.id());super().addSuccess(test)
  def addFailure(self,test,err):report["failures"].append({"id":test.id(),"traceback":self._exc_info_to_string(err,test)});super().addFailure(test,err)
  def addError(self,test,err):report["errors"].append({"id":test.id(),"traceback":self._exc_info_to_string(err,test)});super().addError(test,err)
  def addSkip(self,test,reason):report["skipped"].append({"id":test.id(),"reason":reason});super().addSkip(test,reason)
  def addExpectedFailure(self,test,err):report["expected_failures"].append(test.id());super().addExpectedFailure(test,err)
  def addUnexpectedSuccess(self,test):report["unexpected_successes"].append(test.id());super().addUnexpectedSuccess(test)
 try:
  common.require(len(r["selected_ids"])==len(set(r["selected_ids"]))==6,"six original unique IDs")
  common.require(not any(k.startswith("HEPTA_HIA_") and v for k,v in os.environ.items()),"ambient selector")
  sys.path.insert(0,str(root))
  with ExitStack() as stack:
   for module,name in ((subprocess,"Popen"),(os,"system"),(os,"fork"),(ctypes,"CDLL"),(ctypes,"PyDLL")):
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=forbidden(module.__name__+"."+name)))
   from hepta import hia_json_preflight_native as image_module
   common.require(Path(image_module.__file__).resolve().is_relative_to(root),"import escaped")
   stack.enter_context(patch.object(image_module.NativeHiaJsonImage,"__init__",side_effect=forbidden("NativeHiaJsonImage.__init__")))
   loader=unittest.TestLoader();suite=unittest.TestSuite()
   for name in r["selected_ids"]:suite.addTests(loader.loadTestsFromName(name))
   report["loaded_ids"]=[test.id() for test in flatten(suite)];report["loader_errors"]=list(loader.errors)
   common.require(report["loaded_ids"]==r["selected_ids"] and not loader.errors,"original selected method loading differs")
   result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,resultclass=Result).run(suite)
   common.require(result.testsRun==6 and report["executed_ids"]==r["selected_ids"] and report["success_ids"]==r["selected_ids"],"complete selected methods")
   common.require(not any(report[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes","loader_errors","forbidden_attempts")) and result.wasSuccessful(),"zero anomalies required")
  report["status"]="SOURCE6_PASS_ONLY"
 except BaseException as error:
  report["exception"]={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()};traceback.print_exc()
 finally:
  report["seconds"]=(time.monotonic_ns()-start)/1e9;common.save_json(out/"source6-report.json",report)
 return 0 if report["status"]=="SOURCE6_PASS_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
