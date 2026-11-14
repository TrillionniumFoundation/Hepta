"""One source generation; no test, VM, machine compiler or native qualification."""
from __future__ import annotations
import argparse, ctypes, gzip, hashlib, os, shutil, subprocess, sys, time, traceback, zipfile
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as C
CAPS={"source_bytes":1048576,"source_lines":16384,"functions":128,"blocks":1536,
      "ops_and_terms":8192,"function_blocks":256,"parameters":16,
      "operation_arguments":16,"unique_ssa":2048}

def counts(doc):
    fs=doc["functions"];bs=[b for f in fs for b in f["blocks"]];ds=[]
    for f in fs:
        names={p["name"] for p in f["params"]}
        for b in f["blocks"]:
            names.update(p["name"] for p in b["params"])
            for op in b["ops"]:names.update(p["name"] for p in op["out"])
        ds.append(len(names))
    return {"functions":len(fs),"blocks":len(bs),
        "ops_and_terms":sum(len(b["ops"])+1 for b in bs),
        "function_blocks":max(len(f["blocks"]) for f in fs),
        "parameters":max(len(f["params"]) for f in fs),
        "operation_arguments":max((len(op.get("args",[])) for b in bs for op in b["ops"]),default=0),
        "unique_ssa":max(ds)}

def main():
    p=argparse.ArgumentParser();p.add_argument("--request",type=Path,required=True)
    p.add_argument("--sha256",required=True);a=p.parse_args()
    os.umask(0o077);r,m,rp=C.load_request(a.request,a.sha256)
    root=Path(r["source_root"]);out=Path(r["output_root"]);started=time.monotonic_ns()
    report={"schema":"hia.core-balanced-dispatch.generation-result.v1","status":"HOLD",
        "request_sha256":rp["sha256"],"generation_attempts":0,"generation_completed":0,
        "document_order":[],"caps":[],"outputs":[],"source_write_attempts":[],
        "forbidden_attempts":[],"errors":[],"source_tests_executed":False,
        "VM_executed":False,"machine_compiler_or_native_executed":False,
        "assembly_roundtrip_executed":False,"transport_is_qualification":False}
    before=C.source_snapshot(r,m);C.require_source_before(r,m,before)
    C.save_json(out/"source-before.json",before);(out/"generated").mkdir(mode=0o700)
    asm=r["assembly_paths"];mods=[Path(x).stem for x in asm];paths=r["generated_write_paths"]
    sw={str(root/x) for x in paths}
    ew={str(out/x) for x in ("source-after.json","generation-report.json","generated40.zip","generated40.zip.gz")}
    ew.update(str(out/"generated"/Path(x).name) for x in paths)
    writing_source=False;graphs={}
    def deny(label):
        def fail(*args,**kw):
            report["forbidden_attempts"].append(label)
            raise RuntimeError("source-only forbidden entry: "+label)
        return fail
    def audit(event,args):
        if event in {"subprocess.Popen","os.system","os.posix_spawn","os.fork","os.exec",
                     "ctypes.dlopen","ctypes.dlsym","ctypes.call_function","mmap.__new__"} or event.startswith("socket."):
            deny("audit:"+event)()
        if event=="import" and args[0] in {"hepta.hia_program_runtime","hepta.hia_program_native"}:
            deny("import:"+args[0])()
        if event=="open":
            path,mode,flags=args
            write=(isinstance(mode,str) and any(x in mode for x in "wax+")) or (
                isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            if write:
                fd=isinstance(path,int)
                name=os.readlink("/proc/self/fd/"+str(path)) if fd else os.fspath(path)
                name=os.path.abspath(name)
                if name not in ew and not(writing_source and name in sw):deny("write:"+name)()
                if not fd and name in sw:report["source_write_attempts"].append(name)
        if event=="os.mkdir" and os.path.abspath(os.fspath(args[0]))!=str(root/"examples/hia_bootstrap"):
            deny("mkdir")()
        if event in {"os.remove","os.rmdir","os.rename","os.link","os.symlink","os.chmod","os.chown","os.utime","os.truncate"}:
            deny("mutation:"+event)()
    sys.addaudithook(audit)
    try:
        C.require(len(asm)==len(set(asm))==39 and len(paths)==len(set(paths))==40,"fixed40")
        C.require(not any(k.startswith("HEPTA_HIA_") and v for k,v in os.environ.items()),"ambient selector")
        sys.path.insert(0,str(root))
        with ExitStack() as stack:
            for module,name in ((subprocess,"Popen"),(os,"system"),(os,"fork"),(ctypes,"CDLL"),(ctypes,"PyDLL")):
                if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=deny(module.__name__+"."+name)))
            from hepta import hia_json_preflight_native as image
            C.require(Path(image.__file__).resolve().is_relative_to(root),"image origin")
            stack.enter_context(patch.object(image.NativeHiaJsonImage,"__init__",side_effect=deny("NativeHiaJsonImage.__init__")))
            from tools import generate_hia_core_lowering as author
            C.require(Path(author.__file__).resolve()==root/"tools/generate_hia_core_lowering.py","author origin")
            original=author.document
            def observe(source,module):
                C.require(module in mods and module not in graphs,"document population")
                doc=original(source,module)
                graphs[module]=counts(doc);report["document_order"].append(module)
                return doc
            stack.enter_context(patch.object(author,"document",observe))
            report["generation_attempts"]+=1;writing_source=True
            try:returned=author.write(root/"examples/hia_bootstrap",root/"hepta/hia_core_lowering_abi.json")
            finally:writing_source=False
            C.require(returned==[str(root/x) for x in asm] and report["document_order"]==mods,"exact39 order")
            C.require(Counter(report["source_write_attempts"])==Counter({str(root/x):1 for x in paths}),"exact40 writes")
            report["generation_completed"]=1
        for rel in paths:
            path=root/rel;C.require(path.lstat().st_size<=1048576,"source size")
            raw,pin=C.read_regular(path);raw.decode("utf-8")
            if rel in asm:
                row=dict(graphs[Path(rel).stem]);row.update(source_bytes=len(raw),source_lines=len(raw.splitlines()))
                C.require(set(row)==set(CAPS) and all(row[k]<=CAPS[k] for k in CAPS),"original nine caps")
                report["caps"].append({"path":rel,"counts":row,"passed":True})
            copy=C.save(out/"generated"/Path(rel).name,raw)
            report["outputs"].append({"path":rel,"source":pin,"copy":copy,
                "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()})
        after=C.source_snapshot(r,m);report["changed_paths"]=C.require_source_after(r,before,after)
        C.require(set(report["changed_paths"])==set(asm)-set(r["unchanged_generated_paths"]),
            "exact38 numbered outputs changed")
        C.save_json(out/"source-after.json",after)
        for pin in r["inputs"]:C.read_regular(pin["path"],pin)
        C.require(len(report["caps"])==39 and len(report["outputs"])==40 and not report["forbidden_attempts"],"complete generation")
        # Passive data transport from the40 saved originals, with no second author call.
        zp=out/"generated40.zip"
        fd=os.open(zp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as dest:
            with zipfile.ZipFile(dest,"w",compression=zipfile.ZIP_STORED,allowZip64=False) as z:
                for row in report["outputs"]:
                    raw,_=C.read_regular(row["copy"]["path"],row["copy"])
                    info=zipfile.ZipInfo(row["path"],date_time=(1980,1,1,0,0,0))
                    info.create_system=3;info.external_attr=0o100600<<16
                    z.writestr(info,raw,compress_type=zipfile.ZIP_STORED)
            dest.flush();os.fsync(dest.fileno())
        C.require(zp.lstat().st_size<=40<<20,"ZIP transport bound")
        zip_pin=C.read_regular(zp)[1]
        gp=out/"generated40.zip.gz"
        fd=os.open(gp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as dest:
            with gzip.GzipFile(filename="",mode="wb",fileobj=dest,compresslevel=6,mtime=0) as gz:
                with zp.open("rb") as src:shutil.copyfileobj(src,gz,length=65536)
            dest.flush();os.fsync(dest.fileno())
        C.require(gp.lstat().st_size<=64<<20,"gzip transport bound")
        C.read_regular(zp,zip_pin)
        report["transport"]={"members":40,"zip":zip_pin,"gzip":C.read_regular(gp)[1],
            "format":"ZIP_STORED inside gzip","gzip_mtime":0,"gzip_filename":"",
            "qualification":False,"independent_inverse":"PENDING_ROOT_OWNER_ADMISSION"}
        report["status"]="SOURCE_GENERATION_CAPS_ONLY"
    except BaseException as e:
        report["errors"].append({"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()})
        traceback.print_exc()
    finally:
        report["elapsed_ns"]=time.monotonic_ns()-started
        C.save_json(out/"generation-report.json",report)
    print(report["status"])
    return 0 if report["status"]=="SOURCE_GENERATION_CAPS_ONLY" and not report["errors"] else 1
if __name__=="__main__":raise SystemExit(main())
