"""Exact-base CLI development gate; never current-cold or whole-native authority."""
from pathlib import Path, PurePosixPath
from hashlib import sha256, sha1
import argparse, base64, json, os, signal, stat, subprocess, sys, time, zlib

BASE_HEAD="4b19af89a766593f7d5f1cc2db256e81aba7afcb"
BASE_TREE="1bc7c90996e1910ad66ba771b0bfee1d5bfa655c"
COMPILER_PACKET_SHA="df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b"
COMPILER_SHA="81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109"
COMPILER_BYTES=669494
OWNER_PATHS=("tools/hia_cli_control_phases.py","examples/hia_bootstrap/cli_control.hiaasm",
             "tests/test_hia_cli_continuation_native.py")
def digest(b):return sha256(b).hexdigest()
def meta(raw,mode):
    return {"bytes":len(raw),"sha256":digest(raw),
            "git_blob":sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),"mode":mode}
def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as stream:stream.write(raw)
    assert path.read_bytes()==raw
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def git(root,*args):
    return subprocess.run(["git","-C",str(root),*args],check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=20).stdout
def snapshot(root,names):
    rows={}
    for name,mode in names.items():
        p=root/name
        st=p.lstat()
        if not stat.S_ISREG(st.st_mode):raise ValueError("non-regular source: "+name)
        actual_mode="100755" if st.st_mode&0o111 else "100644"
        if actual_mode!=mode:raise ValueError("source mode differs: "+name)
        rows[name]=meta(p.read_bytes(),mode)
    return rows
def run(root,out,label,argv,env,limit):
    start=time.monotonic();timed_out=False
    with (out/(label+".stdout")).open("xb") as stdout,(out/(label+".stderr")).open("xb") as stderr:
        p=subprocess.Popen([str(x) for x in argv],cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        try:p.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL);p.wait()
    result={"argv":[str(x) for x in argv],"cwd":str(root),"limit_seconds":limit,"cleanup_seconds":3,
            "timed_out":timed_out,"returncode":p.returncode,"seconds":time.monotonic()-start}
    write(out/(label+".process.json"),encoded(result))
    return result
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True);p.add_argument("--inputs",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args();root=args.source.resolve(strict=True);inputs=args.inputs.resolve(strict=True)
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    report={"schema":"hia.v77.cli-development-gate.v1","scope":"EXACT_BASE_OVERLAY_RETAINED_COMPILER_DEVELOPMENT_ONLY",
            "base_head":BASE_HEAD,"base_tree":BASE_TREE,"current_source_cold_qualified":False,
            "whole_native_delivery_qualified":False,"legacy_deleted":False,"default_changed":False,
            "expected_tests":39,"status":"STARTED"}
    try:
        if sys.implementation.name!="cpython" or tuple(sys.version_info[:3])!=(3,14,4):
            raise ValueError("exact CPython 3.14.4 required")
        if git(root,"rev-parse","HEAD").decode().strip()!=BASE_HEAD:raise ValueError("base head differs")
        if git(root,"rev-parse","HEAD^{tree}").decode().strip()!=BASE_TREE:raise ValueError("base tree differs")
        if git(root,"status","--porcelain=v1"):raise ValueError("base source must be clean")
        names={}
        blobs={}
        for item in git(root,"ls-tree","-r","-z","HEAD").split(b"\0"):
            if not item:continue
            head,rawname=item.split(b"\t",1)
            mode,kind,blob=head.decode("ascii").split();name=rawname.decode("utf-8")
            if kind!="blob" or mode not in ("100644","100755"):raise ValueError("non-regular tracked source")
            if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:raise ValueError("invalid source path")
            names[name]=mode;blobs[name]=blob
        if len(names)!=3153:raise ValueError("base file count differs")
        original=snapshot(root,names)
        if any(original[n]["git_blob"]!=blobs[n] for n in names):raise ValueError("actual base bytes differ from Git")
        packet_raw=(inputs/"overlay.json").read_bytes()
        manifest=json.loads((inputs/"MANIFEST.json").read_bytes())
        for name,row in manifest["inputs"].items():
            if name=="MANIFEST.json":raise ValueError("self-referential manifest")
            raw=(inputs/name).read_bytes()
            if len(raw)!=row["bytes"] or digest(raw)!=row["sha256"]:raise ValueError("harness input differs: "+name)
        packet=json.loads(packet_raw)
        if packet["base_head"]!=BASE_HEAD or set(packet["files"])!=set(OWNER_PATHS):raise ValueError("overlay identity differs")
        for name,row in packet["files"].items():
            if row["before"]!=original[name]:raise ValueError("overlay parent differs: "+name)
            raw=row["content"].encode("utf-8")
            if meta(raw,row["after"]["mode"])!=row["after"]:raise ValueError("overlay bytes differ: "+name)
            (root/name).write_bytes(raw)
        candidate=snapshot(root,names)
        if [n for n in names if candidate[n]!=original[n]]!=[n for n in names if n in OWNER_PATHS]:
            raise ValueError("overlay changed unexpected paths")
        saved_raw=(inputs/"retained-compiler.json").read_bytes()
        if digest(saved_raw)!=COMPILER_PACKET_SHA:raise ValueError("compiler packet differs")
        saved=json.loads(saved_raw);compressed=base64.b64decode(saved["compiler_zlib_base64"],validate=True)
        if len(compressed)!=saved["compressed_bytes"] or digest(compressed)!=saved["compressed_sha256"]:
            raise ValueError("compiler compressed bytes differ")
        dec=zlib.decompressobj()
        compiler_raw=dec.decompress(compressed,COMPILER_BYTES+1)
        if len(compiler_raw)!=COMPILER_BYTES or not dec.eof or dec.unused_data or dec.unconsumed_tail:
            raise ValueError("compiler framing differs")
        if digest(compiler_raw)!=COMPILER_SHA:raise ValueError("compiler image differs")
        receipt_raw=saved["original_receipt_utf8"].encode()
        if digest(receipt_raw)!=saved["original_receipt_sha256"]:raise ValueError("compiler original receipt differs")
        compiler=out/"retained-B3.image.bin";write(compiler,compiler_raw);compiler.chmod(0o444)
        write(out/"SOURCE-ADMISSION.json",encoded({"base_head":BASE_HEAD,"base_tree":BASE_TREE,
             "base":original,"candidate":candidate,"compiler_sha256":COMPILER_SHA,
             "overlay_sha256":digest(packet_raw),"python":sys.version,"current_source_cold_qualified":False}))
        env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_HIA_")}
        env["PYTHONDONTWRITEBYTECODE"]="1";env["PYTHONPATH"]=str(root)
        env["HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST"]=str(out/"build/manifest.json")
        env["HEPTA_HIA_CLI_FIXTURE_EVIDENCE"]=str(out/"fixtures")
        env["CLI_V77_TERMINAL"]=str(out/"TERMINAL.json")
        begun=time.monotonic()
        commands=[
          ("regenerate",[sys.executable,"-B","-m","tools.generate_hia_cli_control"]),
          ("build",[sys.executable,"-B","-m","tools.build_hia_cli_native","--development","--compiler",compiler,"--output",out/"build"]),
          ("suite",[sys.executable,"-B",inputs/"run_cli_suite.py"])]
        report["commands"]=[]
        for label,argv in commands:
            if snapshot(root,names)!=candidate:raise ValueError("source drift before "+label)
            result=run(root,out,label,argv,env,max(0.001,240-(time.monotonic()-begun)))
            report["commands"].append(result)
            if snapshot(root,names)!=candidate or compiler.read_bytes()!=compiler_raw:
                raise ValueError("frozen source/compiler changed during "+label)
            if result["timed_out"] or result["returncode"]!=0:raise ValueError("actual command failed: "+label)
        terminal=json.loads((out/"TERMINAL.json").read_bytes())
        if terminal!={"expected":39,"tests_run":39,"failures":0,"errors":0,"skips":0,
                      "expected_failures":0,"unexpected_successes":0,"passed":True}:
            raise ValueError("complete component terminal differs")
        if git(root,"ls-files","--others","--exclude-standard"):raise ValueError("unexpected untracked source files")
        git(root,"add","--",*OWNER_PATHS)
        candidate_tree=git(root,"write-tree").decode().strip()
        changed=git(root,"diff","--cached","--name-only").decode().splitlines()
        if set(changed)!=set(OWNER_PATHS):raise ValueError("candidate Git tree changed unexpected files")
        report.update({"status":"COMPLETE_CLI_DEVELOPMENT_PASS","python":sys.version,"terminal":terminal,
                       "candidate_tree":candidate_tree,"tracked_files":len(names),"source_and_compiler_unchanged":True,
                       "outer_seconds":time.monotonic()-begun})
    except BaseException as error:
        report.update({"status":"DEVELOPMENT_FAIL","exception_type":type(error).__name__,"exception_message":str(error)})
        raise
    finally:
        write(out/"REPORT.json",encoded(report));print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()

