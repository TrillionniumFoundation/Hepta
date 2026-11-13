"""Six selected original methods, then four original derivations and four idempotence commands."""
from __future__ import annotations
import argparse,os,subprocess,sys,time,traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_common as common

def same_bytes(a,b):
 common.require(set(a)==set(b),"idempotence population")
 for p in a:
  common.require(a[p]["bytes"]==b[p]["bytes"] and a[p]["sha256"]==b[p]["sha256"] and a[p]["identity"]["mode"]==b[p]["identity"]["mode"],"idempotence byte/mode: "+p)

def main():
 p=argparse.ArgumentParser();p.add_argument("--request",type=Path,required=True);p.add_argument("--sha256",required=True);a=p.parse_args()
 os.umask(0o077);r,m,rp=common.load_request(a.request,a.sha256);out=Path(r["output_root"]);start=time.monotonic_ns()
 report={"schema":"hia.pc-forwarding.derive8-result.v1","status":"HOLD","request_sha256":rp["sha256"],"expected_commands":r["commands"],"commands":[],"forbidden_attempts":[],"exception":None,"native_or_compiler_executed":False,"source_tests_executed":False,"expected_source_ids":r["selected_ids"],"source6":None}
 before=common.source_snapshot(r,m);common.require_source_before(r,m,before);common.save_json(out/"source-before.json",before)
 (out/"commands").mkdir(mode=0o700);(out/"derived").mkdir(mode=0o700)
 try:
  argv=[r["runtime"]["path"],"-I","-S","-B",str(Path(__file__).parent/"source6_child.py"),"--request",str(a.request),"--sha256",a.sha256]
  so=out/"source6.stdout";se=out/"source6.stderr"
  invocation={"argv":argv,"cwd":r["source_root"],"environment":r["environment"],"expected_ids":r["selected_ids"],"within_single_owner_180_seconds":True}
  common.save_json(out/"source6.request.json",invocation);t=time.monotonic_ns()
  with so.open("xb") as stream_out,se.open("xb") as stream_err:
   proc=subprocess.run(argv,cwd=r["source_root"],env=r["environment"],stdout=stream_out,stderr=stream_err,check=False)
   stream_out.flush();os.fsync(stream_out.fileno());stream_err.flush();os.fsync(stream_err.fileno())
  row={**invocation,"returncode":proc.returncode,"seconds":(time.monotonic_ns()-t)/1e9,"stdout":common.read_regular(so)[1],"stderr":common.read_regular(se)[1]}
  common.save_json(out/"source6.receipt.json",row);report["source6"]=row;report["source_tests_executed"]=True
  selected=common.decode(common.read_regular(out/"source6-report.json")[0])
  report["forbidden_attempts"].extend(selected["forbidden_attempts"])
  common.require(proc.returncode==0 and selected["status"]=="SOURCE6_PASS_ONLY" and selected["request_sha256"]==a.sha256 and all(selected[k]==r["selected_ids"] for k in ("expected_ids","loaded_ids","executed_ids","success_ids")) and selected["exception"] is None and not any(selected[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes","loader_errors","forbidden_attempts")),"six original selected methods failed")
  after_tests=common.source_snapshot(r,m);common.require(after_tests==before,"selected methods changed source");common.save_json(out/"source-after-six.json",after_tests)
  for i,spec in enumerate(r["commands"]):
   argv=[r["runtime"]["path"],"-I","-S","-B",str(Path(__file__).parent/"derive_child.py"),"--request",str(a.request),"--sha256",a.sha256,"--index",str(i)]
   stdout=out/"commands"/("%02d.stdout"%i);stderr=out/"commands"/("%02d.stderr"%i)
   invocation={"index":i,"argv":argv,"cwd":r["source_root"],"environment":r["environment"],"target":spec,"within_single_owner_180_seconds":True}
   common.save_json(out/"commands"/("%02d.request.json"%i),invocation)
   t=time.monotonic_ns()
   with stdout.open("xb") as so,stderr.open("xb") as se:
    proc=subprocess.run(argv,cwd=r["source_root"],env=r["environment"],stdout=so,stderr=se,check=False)
    so.flush();os.fsync(so.fileno());se.flush();os.fsync(se.fileno())
   row={**invocation,"returncode":proc.returncode,"seconds":(time.monotonic_ns()-t)/1e9,"stdout":common.read_regular(stdout)[1],"stderr":common.read_regular(stderr)[1]}
   report["commands"].append(row);common.save_json(out/"commands"/("%02d.receipt.json"%i),row)
   command_report=common.decode(common.read_regular(out/"commands"/("%02d.report.json"%i))[0])
   report["forbidden_attempts"].extend(command_report["forbidden_attempts"])
   common.require(proc.returncode==0 and command_report["status"]=="SOURCE_COMMAND_PASS" and command_report["request_sha256"]==a.sha256 and command_report["index"]==i and command_report["target"]==spec and not command_report["forbidden_attempts"] and command_report["exception"] is None,"original document command failed: "+str(i))
   if i==3:
    derived=common.source_snapshot(r,m);report["changed_paths"]=common.require_source_after(r,before,derived);common.save_json(out/"source-derived.json",derived)
    for rel in r["generated_write_paths"]:
     raw,pin=common.read_regular(Path(r["source_root"])/rel);common.save(out/"derived"/Path(rel).name,raw)
    report["derived_snapshot_complete"]=True
  after=common.source_snapshot(r,m);common.require_source_after(r,before,after);same_bytes(derived,after);common.save_json(out/"source-after.json",after)
  for pin in r["inputs"]:common.read_regular(pin["path"],pin)
  common.require(len(report["commands"])==8 and all(x["returncode"]==0 for x in report["commands"]) and not report["forbidden_attempts"],"complete eight commands required")
  report["whole_source_idempotent"]=True;report["status"]="SOURCE6_DERIVE8_PASS_ONLY"
 except BaseException as e:
  report["exception"]={"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()}
 finally:
  report["seconds"]=(time.monotonic_ns()-start)/1e9;common.save_json(out/"derive8-report.json",report)
 return 0 if report["status"]=="SOURCE6_DERIVE8_PASS_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
