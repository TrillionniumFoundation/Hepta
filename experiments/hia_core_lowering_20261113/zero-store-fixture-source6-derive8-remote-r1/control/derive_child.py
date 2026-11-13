"""Run one unchanged document-generation command with the source-only effect boundary."""
from __future__ import annotations
import argparse,ctypes,mmap,os,runpy,socket,subprocess,sys,time,traceback
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_common as common

def main():
 p=argparse.ArgumentParser();p.add_argument("--request",type=Path,required=True);p.add_argument("--sha256",required=True);p.add_argument("--index",type=int,required=True);a=p.parse_args()
 os.umask(0o077);r,m,rp=common.load_request(a.request,a.sha256)
 common.require(0<=a.index<8,"command index")
 spec=r["commands"][a.index];out=Path(r["output_root"])/"commands";root=Path(r["source_root"])
 report={"schema":"hia.pc-forwarding.derive-command.v1","status":"HOLD","request_sha256":rp["sha256"],"index":a.index,"target":spec,"actual_wrapper_argv":list(sys.argv),"forbidden_attempts":[],"exception":None}
 started=time.monotonic_ns()
 def forbidden(label):
  def refuse(*args,**kwargs):
   report["forbidden_attempts"].append(label);raise AssertionError("source-only forbidden entry: "+label)
  return refuse
 def audit(event,args):
  if event in {"subprocess.Popen","os.system","os.posix_spawn","os.fork","ctypes.dlopen","mmap.__new__","socket.__new__"}:forbidden("audit:"+event)()
 sys.addaudithook(audit)
 try:
  common.require(not any(k.startswith("HEPTA_HIA_") and v for k,v in os.environ.items()),"ambient selector")
  common.require(spec["path"] in ("tools/generate_hia_selfhost_contract.py","tests/test_hia_selfhost_language_coverage.py"),"fixed target")
  sys.path.insert(0,str(root))
  with ExitStack() as stack:
   for module,name in ((subprocess,"Popen"),(os,"system"),(os,"fork"),(ctypes,"CDLL"),(ctypes,"PyDLL")):
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=forbidden(module.__name__+"."+name)))
   from hepta import hia_json_preflight_native as image_module
   common.require(Path(image_module.__file__).resolve().is_relative_to(root),"import escaped")
   stack.enter_context(patch.object(image_module.NativeHiaJsonImage,"__init__",side_effect=forbidden("NativeHiaJsonImage.__init__")))
   target=root/spec["path"];sys.argv=[str(target),*spec["args"]]
   try:runpy.run_path(str(target),run_name="__main__")
   except SystemExit as e:
    if e.code not in (None,0):raise
   common.require(not report["forbidden_attempts"],"forbidden attempts")
  report["status"]="SOURCE_COMMAND_PASS"
 except BaseException as e:
  report["exception"]={"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()}
  traceback.print_exc()
 finally:
  report["seconds"]=(time.monotonic_ns()-started)/1e9
  common.save_json(out/("%02d.report.json"%a.index),report)
 return 0 if report["status"]=="SOURCE_COMMAND_PASS" else 1
if __name__=="__main__":raise SystemExit(main())
