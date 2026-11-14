"""Four original derivations and four idempotence commands; no source test rerun."""
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
 report={"schema":"hia.json-wire-leaf05.derive8-result.v1","status":"HOLD","request_sha256":rp["sha256"],"expected_commands":r["commands"],"commands":[],"forbidden_attempts":[],"exception":None,"native_or_compiler_executed":False,"source_tests_executed":False}
 before=common.source_snapshot(r,m);common.require_source_before(r,m,before);common.save_json(out/"source-before.json",before)
 (out/"commands").mkdir(mode=0o700);(out/"derived").mkdir(mode=0o700)
 try:
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
  report["whole_source_idempotent"]=True;report["status"]="DERIVE8_PASS_ONLY"
 except BaseException as e:
  report["status"]="HOLD"
  report["exception"]={"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()}
 finally:
  report["seconds"]=(time.monotonic_ns()-start)/1e9;common.save_json(out/"derive8-report.json",report)
 return 0 if (report["status"]=="DERIVE8_PASS_ONLY" and report["exception"] is None and not report["forbidden_attempts"]) else 1
if __name__=="__main__":raise SystemExit(main())
