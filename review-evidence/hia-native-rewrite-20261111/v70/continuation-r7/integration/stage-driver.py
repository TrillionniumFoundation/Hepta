"""Stage exact 673 source plus the frozen heap r8 delta and narrow fixture fix."""
from __future__ import annotations
import hashlib, io, json, os, pathlib, subprocess, sys, tarfile, time, traceback, zipfile
P=json.loads(sys.stdin.read())
BASE=pathlib.Path(P["base"]); OUT=pathlib.Path(P["out"]); SRC=OUT/"source"
HEAD=P["head"]; TREE=P["tree"]
def sha(b): return hashlib.sha256(b).hexdigest()
def git(root,*args,input=None):
    r=subprocess.run(["git","-c","core.autocrlf=false","-C",str(root),*args],input=input,capture_output=True,timeout=90)
    if r.returncode: raise RuntimeError("git failed "+repr(args)+" "+r.stderr.decode("utf-8","backslashreplace"))
    return r.stdout
def state(root):
    return {"head":git(root,"rev-parse","HEAD").decode().strip(),"tree":git(root,"rev-parse","HEAD^{tree}").decode().strip(),
            "status":git(root,"status","--porcelain=v1","--untracked-files=all").decode()}
def regular_name(name):
    q=pathlib.PurePosixPath(name)
    if q.is_absolute() or any(x in ("", ".", "..", ".git") for x in name.split("/")): raise ValueError("unsafe member "+name)
    return q
def record(path):
    b=path.read_bytes()
    return {"bytes":len(b),"sha256":sha(b)}
before=state(BASE)
if before!={"head":HEAD,"tree":TREE,"status":""}: raise RuntimeError("base is not exact clean source")
commit=git(BASE,"cat-file","commit",HEAD)
if hashlib.sha1(b"commit "+str(len(commit)).encode()+b"\0"+commit).hexdigest()!=HEAD: raise RuntimeError("base commit bytes differ")
zip_bytes=pathlib.Path(P["packet_path"]).read_bytes()
if len(zip_bytes)!=P["packet_bytes"] or sha(zip_bytes)!=P["packet_sha256"]: raise RuntimeError("packet identity differs")
zf=zipfile.ZipFile(io.BytesIO(zip_bytes)); names=zf.namelist()
if len(names)!=len(set(names)) or zf.testzip() is not None: raise RuntimeError("packet CRC or duplicate failure")
manifest=json.loads(zf.read("SOURCE_MANIFEST.json"))
if manifest["base_commit"]!=HEAD or manifest["base_tree"]!=TREE: raise RuntimeError("packet base identity differs")
if set(names)!={"source/"+x for x in manifest["changed"]}|{"SOURCE_MANIFEST.json"}: raise RuntimeError("packet member set differs")
delta={}
for name,meta in manifest["changed"].items():
    regular_name(name); b=zf.read("source/"+name)
    if len(b)!=meta["bytes"] or sha(b)!=meta["sha256"]: raise RuntimeError("delta member differs "+name)
    if meta["before"] is None:
        if name in P["base_files"]: raise RuntimeError("addition overwrites base "+name)
    elif meta["before"]["sha256"]!=P["base_files"].get(name): raise RuntimeError("delta old source differs "+name)
    delta[name]=b
fixture=P["fixture"]; fb=fixture["text"].encode("utf-8"); regular_name(fixture["path"])
if len(fb)!=fixture["bytes"] or sha(fb)!=fixture["sha256"]: raise RuntimeError("fixture identity differs")
if fixture["path"] in delta: raise RuntimeError("fixture overlaps owner delta")
if OUT.exists(): raise RuntimeError("new exclusive integration root already exists")
OUT.mkdir(mode=0o700)
(OUT/"request-public.json").write_text(json.dumps({k:v for k,v in P.items() if k not in ("base_files","fixture")},indent=2,sort_keys=True)+"\n")
(OUT/"source-base.json").write_text(json.dumps(P["base_files"],indent=2,sort_keys=True)+"\n")
started=time.time(); result={"scope":"SOURCE_ONLY_STAGING_NO_GENERATION_NO_TESTS","base_before":before,"started":started,
 "whole_native":False,"default_native":False,"live_migration":False,"legacy_deletion":False}
try:
    tree={}
    for row in git(BASE,"ls-tree","-r","-z",HEAD).split(b"\0"):
        if not row: continue
        head,path=row.split(b"\t",1); mode,kind,obj=head.decode().split()
        name=path.decode("utf-8"); regular_name(name)
        if kind!="blob" or mode not in ("100644","100755"): raise RuntimeError("nonregular base tree "+name)
        tree[name]={"mode":mode,"blob":obj}
    if set(tree)!=set(P["base_files"]): raise RuntimeError("base path set differs")
    archive=OUT/"base-source.tar"
    with archive.open("xb") as f:
        cp=subprocess.run(["git","-C",str(BASE),"archive","--format=tar",HEAD],stdout=f,stderr=subprocess.PIPE,timeout=90)
    if cp.returncode: raise RuntimeError("base archive failed "+cp.stderr.decode("utf-8","backslashreplace"))
    SRC.mkdir(mode=0o700)
    seen=set()
    with tarfile.open(archive,"r:") as tf:
        for member in tf:
            if member.isdir(): continue
            if not member.isfile(): raise RuntimeError("archive nonregular "+member.name)
            q=regular_name(member.name)
            if member.name in seen or member.name not in tree: raise RuntimeError("base duplicate/unexpected "+member.name)
            b=tf.extractfile(member).read()
            expect=tree[member.name]
            if sha(b)!=P["base_files"][member.name]: raise RuntimeError("base SHA256 mismatch "+member.name)
            if hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()!=expect["blob"]: raise RuntimeError("base Git blob mismatch "+member.name)
            if bool(member.mode&0o111)!=(expect["mode"]=="100755"): raise RuntimeError("base mode mismatch "+member.name)
            dest=SRC/q; dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with dest.open("xb") as f:f.write(b)
            dest.chmod(0o755 if expect["mode"]=="100755" else 0o644);seen.add(member.name)
    if seen!=set(tree): raise RuntimeError("base archive incomplete")
    git(SRC,"init","-q","-b","integration-v71")
    git(SRC,"add","--all")
    rebuilt=git(SRC,"write-tree").decode().strip()
    if rebuilt!=TREE: raise RuntimeError("reconstructed original Git tree differs")
    imported=git(SRC,"hash-object","-t","commit","-w","--stdin",input=commit).decode().strip()
    if imported!=HEAD: raise RuntimeError("imported original commit differs")
    git(SRC,"update-ref","refs/heads/integration-v71",HEAD)
    if state(SRC)!=before: raise RuntimeError("clean reconstructed source differs")
    for name,b in delta.items():
        dest=SRC/regular_name(name); dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        old=manifest["changed"][name]["before"]
        if old is not None and (record(dest)["sha256"]!=old["sha256"] or git(SRC,"hash-object",str(dest)).decode().strip()!=old["git_blob"]): raise RuntimeError("old delta custody differs "+name)
        if old is None and dest.exists(): raise RuntimeError("addition already exists "+name)
        if old is None:
            with dest.open("xb") as f:f.write(b)
        else:dest.write_bytes(b)
        dest.chmod(0o644)
    target=SRC/fixture["path"]
    if record(target)["sha256"]!=P["base_files"][fixture["path"]]: raise RuntimeError("fixture base differs")
    target.write_bytes(fb); target.chmod(0o644)
    expected={name:{"bytes":len(b),"sha256":sha(b)} for name,b in delta.items()}
    expected[fixture["path"]]={"bytes":len(fb),"sha256":sha(fb)}
    for name,meta in expected.items():
        if record(SRC/name)!=meta:raise RuntimeError("staged readback differs "+name)
    result.update({"status":"STAGED_NOT_QUALIFIED","source":str(SRC),"base_archive":record(archive),
       "base_files_verified":len(tree),"base_tree_reconstructed":rebuilt,"base_commit_imported":imported,
       "changed_paths":sorted(expected),"changed":expected,"source_status":state(SRC)})
except BaseException as e:
    result.update({"status":"FAIL","error":{"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()}})
finally:
    result["base_after"]=state(BASE);result["base_unchanged"]=result["base_after"]==before
    result["finished"]=time.time();result["elapsed_seconds"]=result["finished"]-started
    if not result["base_unchanged"]:result["status"]="FAIL"
    (OUT/"stage-RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":result["status"],"source":str(SRC),"changed":len(result.get("changed_paths",[])),"report":str(OUT/"stage-RESULT.json"),"report_identity":record(OUT/"stage-RESULT.json")},sort_keys=True),flush=True)
sys.exit(0 if result["status"]=="STAGED_NOT_QUALIFIED" else 1)
