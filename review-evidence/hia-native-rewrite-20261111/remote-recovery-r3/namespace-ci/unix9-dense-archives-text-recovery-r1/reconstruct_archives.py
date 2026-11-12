"""Rebuild two exact preserved archives from full-GET Git text parts; zero target execution."""
from __future__ import annotations
import argparse,base64,hashlib,json,os,stat,sys,traceback
from pathlib import Path
MANIFEST_SHA="174ab9d6887f937f168bef827d00c1bc9c6d9fe2273797e358208077e725949a"
MANIFEST_GIT="bff8eaed513e2adacc294d0ddadc2871e7bac5b7"
def digest(raw):
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
  blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def read_regular(path):
 mode=path.lstat().st_mode
 if not stat.S_ISREG(mode) or path.is_symlink():raise ValueError("not regular: "+str(path))
 raw=path.read_bytes();return raw,dict(digest(raw),mode=stat.S_IMODE(mode))
def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True)
 p.add_argument("--parts-root",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 pins={};report=dict(scope="ZERO_TARGET_TEXT_TRANSPORT_RECONSTRUCTION",status="INCOMPLETE",archives=[],after_errors=[],target_entries=0)
 primary=None
 def pin(path,expected=None):
  raw,row=read_regular(path);key=str(path.absolute())
  if expected:
   for k in ("blob","bytes","sha256"):
    if row[k]!=expected[k]:raise ValueError("identity mismatch "+key+" "+k)
  if key in pins and pins[key]!=row:raise ValueError("input drift "+key)
  pins[key]=row;return raw
 try:
  pin(Path(__file__))
  data=pin(a.manifest)
  assert hashlib.sha256(data).hexdigest()==MANIFEST_SHA and digest(data)["blob"]==MANIFEST_GIT
  manifest=json.loads(data)
  assert manifest["schema"]=="hia.namespace.archive.base64-text-recovery.v1"
  seen=set()
  for archive in manifest["archives"]:
   name=archive["id"];assert name in ("follow55B-original","dense-ssa-development") and name not in seen;seen.add(name)
   expected=archive["archive"];target=a.output/(name+".tar.xz")
   item=dict(id=name,status="PARTIAL",path=str(target),completed_parts=0,bytes=0)
   report["archives"].append(item)
   with target.open("xb") as stream:
    os.chmod(target,0o644)
    for index,part in enumerate(archive["parts"]):
     assert part["index"]==index and part["raw_offset"]==item["bytes"]
     rel=Path(part["path"]);assert not rel.is_absolute() and ".." not in rel.parts and rel.parts[0]==name
     text=pin(a.parts_root/rel,part["text"])
     assert text.endswith(b"\n") and len(text)==part["base64_characters"]+1
     encoded=text[:-1];decoded=base64.b64decode(encoded,validate=True)
     assert base64.b64encode(decoded)==encoded
     assert len(decoded)==part["raw_bytes"] and hashlib.sha256(decoded).hexdigest()==part["raw_sha256"]
     stream.write(decoded);item["bytes"]+=len(decoded);item["completed_parts"]+=1
    stream.flush();os.fsync(stream.fileno())
   actual=pin(target,expected);assert len(actual)==item["bytes"]
   item.update(status="FULL_RAW_LENGTH_SHA256_GIT_MATCH",identity=digest(actual))
  assert seen=={"follow55B-original","dense-ssa-development"}
  report["status"]="PASS_RAW_RECONSTRUCTION_ONLY"
 except BaseException as error:
  primary=error;report.update(status="FAIL",error_type=type(error).__name__,error=str(error),traceback=traceback.format_exc())
 finally:
  for path,before in pins.items():
   try:
    _,after=read_regular(Path(path))
    assert after==before
   except BaseException as error:
    report["after_errors"].append(dict(path=path,type=type(error).__name__,error=str(error)))
    if primary is None:primary=error
    else:primary.add_note("independent after-check "+path+": "+repr(error))
  if primary is not None:report["status"]="FAIL"
  report["before"]=pins;report["all_registered_inputs_and_outputs_after_checked"]=not report["after_errors"]
  data=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
  (a.output/"reconstruction.json").write_bytes(data)
  assert (a.output/"reconstruction.json").read_bytes()==data
  print(json.dumps(report,sort_keys=True),flush=True)
 if primary is not None:raise primary
if __name__=="__main__":main()
