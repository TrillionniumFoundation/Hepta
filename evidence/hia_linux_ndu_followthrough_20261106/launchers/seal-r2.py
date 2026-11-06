import pathlib,json,hashlib,subprocess,tarfile,gzip,io,statistics,time,sys
root=pathlib.Path("/data/hepta-hia-linux-followthrough-20261106-bedaafad8a2f")
repo=root/"repo"
expected="96d01c50ef1920e5b39c52f62b43ef8746d2c621"
def git(*a):return subprocess.check_output(["git","--no-replace-objects","-C",str(repo),*a],text=True).strip()
assert git("rev-parse","HEAD")==expected and not git("status","--porcelain","--untracked-files=all")
export=root/"export-r2"
export.mkdir(exist_ok=False)
bindings={}
def walk(value,origin):
    if isinstance(value,dict):
        if isinstance(value.get("path"),str) and isinstance(value.get("sha256"),str) and len(value["sha256"])==64:
            path=pathlib.Path(value["path"])
            if path.is_absolute() and str(path).startswith(str(root)+"/"):
                key=(str(path),value["sha256"])
                bindings[key]=origin
        for v in value.values():walk(v,origin)
    elif isinstance(value,list):
        for v in value:walk(v,origin)
for path in sorted((root/"results").rglob("*.json")):
    walk(json.loads(path.read_text()),str(path.relative_to(root)))
checked=[]
for (name,wanted),origin in sorted(bindings.items()):
    path=pathlib.Path(name)
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    if actual!=wanted:raise RuntimeError("binding changed: "+name+" from "+origin)
    checked.append({"path":name,"sha256":actual})
r=json.loads((root/"results/native-pilot-r2/RESULT.json").read_text())
assert r["status"]=="PASS" and len(r["cells"])==96 and all(c["status"]=="PASS" for c in r["cells"])
assert r["source_before"]==r["source_after"] and r["source_after"]["commit"]==expected
assert r["ndu_calls"]==0
assert r["negative_control"]["command_receipt"]["exit_code"]==1
assert r["negative_control"]["observation"]["failures"]==270334
assert r["linked_route_inspection"]["status"]=="PASS" and r["arithmetic"]["verdict"]=="unsat"
descriptive={"schema":"hepta.hia.native-pilot-descriptive-summary.v1","source":expected,"method":"Descriptive summaries of every frozen cell in the first timing run. No population or whole-kernel inference.","timed_calls_total":sum(c["observation"]["calls"] for c in r["cells"]),"timed_wall_ns_total":sum(c["observation"]["wall_ns"] for c in r["cells"]),"arms":{}}
for arm,summary in r["summary"].items():
    rows=[c for c in r["cells"] if c["arm"]==arm]
    vals=[c["observation"]["wall_ns"]/c["observation"]["calls"] for c in rows]
    ratios=[c["observation"]["wall_ns"]/next(s["observation"]["wall_ns"] for s in r["cells"] if s["block"]==c["block"] and s["arm"]=="linux-software-asm") for c in rows]
    descriptive["arms"][arm]={**summary,"wall_ns_per_call_min":min(vals),"wall_ns_per_call_max":max(vals),"paired_wall_ratio_vs_stock_median":statistics.median(ratios),"paired_wall_ratio_vs_stock_min":min(ratios),"paired_wall_ratio_vs_stock_max":max(ratios),"blocks_slower_than_stock":sum(x>1 for x in ratios),"blocks_faster_than_stock":sum(x<1 for x in ratios)}
tests=[]
for rel in ["results/qualification-r2/linux-regressions.json","results/qualification-r2/ndu-regressions.json","results/pilot-launch-r2/ndu-policy-regressions.json"]:
    obj=json.loads((root/rel).read_text())
    assert obj["status"]=="PASS" and obj["source_before"]["commit"]==expected and obj["source_after"]["commit"]==expected
    assert obj["tests_planned"]==obj["tests_executed"] and not obj["errors"] and not obj["failures"] and not obj["skipped"]
    tests.append({"path":rel,"planned":obj["tests_planned"],"executed":obj["tests_executed"],"sha256":hashlib.sha256((root/rel).read_bytes()).hexdigest()})
assert sum(x["executed"] for x in tests)==220
files=[]
for folder in ["results","launchers","inputs"]:
    files.extend(p for p in (root/folder).rglob("*") if p.is_file())
files.extend([root/"OWNER.json",root/"llvm20/PROVENANCE.json"])
files=sorted(set(files),key=lambda p:str(p.relative_to(root)))
manifest=[]
for p in files:
    assert p.is_relative_to(root) and not p.is_symlink()
    data=p.read_bytes()
    manifest.append({"path":str(p.relative_to(root)),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"git_blob_sha1":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()})
seal={"schema":"hepta.hia.linux-ndu-evidence-seal.v1","status":"PASS","source":{"commit":expected,"tree":git("rev-parse","HEAD^{tree}"),"dirty":git("status","--porcelain","--untracked-files=all")},"verified_binding_count":len(checked),"verified_bindings":checked,"regressions":tests,"total_final_tests":220,"all_96_timing_cells_passed":True,"retained_failed_attempt":"02e421c: initial83+96 passed, extension40 executed with9errors, no timing started","files":manifest,"scope":"Evidence sealing only; not a new execution, not kernel qualification, not a native NDU campaign"}
for name,value in [("SEAL.json",seal),("DESCRIPTIVE_SUMMARY.json",descriptive)]:
    (export/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
archive=export/"raw-evidence.tar.gz"
with archive.open("xb") as stream:
    with gzip.GzipFile(filename="",mode="wb",fileobj=stream,mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode="w") as tar:
            for p in files+[export/"SEAL.json",export/"DESCRIPTIVE_SUMMARY.json"]:
                data=p.read_bytes()
                name=str(p.relative_to(root)) if not p.is_relative_to(export) else p.name
                info=tarfile.TarInfo(name)
                info.size=len(data);info.mode=p.stat().st_mode&0o777;info.mtime=0;info.uid=0;info.gid=0;info.uname="";info.gname=""
                tar.addfile(info,io.BytesIO(data))
data=archive.read_bytes()
metadata={"path":str(archive),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"git_blob_sha1":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest(),"file_count":len(files)+2,"verified_binding_count":len(checked),"source":expected,"total_final_tests":220}
(export/"ARCHIVE.json").write_text(json.dumps(metadata,sort_keys=True,indent=2)+"\n")
print(json.dumps(metadata),flush=True)
