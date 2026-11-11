"""Restore exact 0ef reference and inventory frozen candidate dependencies without rewriting evidence."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,shutil,stat,subprocess,tarfile,time
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
SOURCE=BASE/"source";ROOT=BASE/"root-recovery";WORK=ROOT/"workspace"
REF=ROOT/"reference-0ef-r2";REF.mkdir(mode=0o700)
commit="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
raw=subprocess.check_output(["/usr/bin/git","ls-tree","-rz","--long",commit],cwd=SOURCE)
expected={}
for line in raw.split(b"\0"):
    if not line:continue
    meta,path=line.split(b"\t",1);mode,kind,sha,size=meta.split()
    assert kind==b"blob" and mode in (b"100644",b"100755")
    expected[os.fsdecode(path)]={"git_sha":sha.decode(),"bytes":int(size),"mode":int(mode,8)&0o777}
seen=set();start=time.monotonic();rows=[]
with (ROOT/"reference-git-archive-r2.stderr.log").open("xb") as err:
    proc=subprocess.Popen(["/usr/bin/git","-c","tar.umask=0022","archive","--format=tar",commit],cwd=SOURCE,stdout=subprocess.PIPE,stderr=err)
    with tarfile.open(fileobj=proc.stdout,mode="r|") as tar:
        for item in tar:
            pp=PurePosixPath(item.name)
            assert not pp.is_absolute() and ".." not in pp.parts
            if item.isdir():continue
            assert item.isfile() and item.name not in seen
            seen.add(item.name);want=expected[item.name]
            p=REF.joinpath(*pp.parts);p.parent.mkdir(parents=True,exist_ok=True)
            data=tar.extractfile(item).read()
            assert len(data)==want["bytes"] and item.mode&0o777==want["mode"], (item.name,len(data),item.mode,want)
            got=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            assert got==want["git_sha"]
            p.write_bytes(data);p.chmod(want["mode"])
            assert p.read_bytes()==data and stat.S_IMODE(p.stat().st_mode)==want["mode"]
            rows.append({"path":item.name,**want,"sha256":hashlib.sha256(data).hexdigest()})
    assert proc.wait(timeout=60)==0
assert seen==set(expected)
copied=0;same=0;different=[]
for row in rows:
    dst=WORK/"Hepta-agent-edit-native"/row["path"]
    if dst.exists():
        assert dst.is_file() and not dst.is_symlink()
        current=hashlib.sha256(dst.read_bytes()).hexdigest()
        if current!=row["sha256"] or stat.S_IMODE(dst.stat().st_mode)!=row["mode"]:
            different.append({"path":row["path"],"restored_archive_sha256":current,"reference_sha256":row["sha256"],"action":"retained_archive_version_reference_separate"})
        else:same+=1
    else:
        dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(REF/row["path"],dst);dst.chmod(row["mode"]);copied+=1
(ROOT/"reference-0ef-r2-index.json").write_text(json.dumps(rows,indent=2,sort_keys=True)+"\n")
(ROOT/"reference-overlay-differences-r2.json").write_text(json.dumps(different,indent=2,sort_keys=True)+"\n")
bundle_path=WORK/"native-edit-candidate-next/development/build-r1/bundle.json"
bundle=json.loads(bundle_path.read_text())
OLD="/workspace/scratch/9acdfa9f5639/"
dependencies=[];checked=0
for role,row in bundle["components"].items():
    for label in ("source","image"):
        old=row[label+"_path"]
        p=WORK/old[len(OLD):] if old.startswith(OLD) else Path(old)
        status="missing"
        if p.is_file():
            got=hashlib.sha256(p.read_bytes()).hexdigest()
            assert got==row[label+"_sha256"],(role,label,old)
            status="exact";checked+=1
        dependencies.append({"role":role,"kind":label,"original_path":old,"mapped_path":str(p),"sha256":row[label+"_sha256"],"status":status})
exe_old=bundle["executable"]["path"]
exe=WORK/exe_old[len(OLD):] if exe_old.startswith(OLD) else Path(exe_old)
assert exe.is_file() and hashlib.sha256(exe.read_bytes()).hexdigest()==bundle["executable"]["sha256"]
dep={"schema":"hia-restored-candidate-dependencies-v1","bundle":str(bundle_path),"executable":str(exe),"executable_sha256":bundle["executable"]["sha256"],"dependencies":dependencies,"exact":checked,"missing":len(dependencies)-checked}
(ROOT/"candidate-dependencies-r2.json").write_text(json.dumps(dep,indent=2,sort_keys=True)+"\n")
receipt={"schema":"hia-reference-restore-v2","tar_umask":"0022","first_attempt":"r1 failed archive mode/size assertion; original script and log retained","status":"PASS","commit":commit,"reference":str(REF),"files":len(rows),"bytes":sum(r["bytes"] for r in rows),"all_git_bytes_modes_sizes_verified":True,"filled_workspace_missing":copied,"existing_equal":same,"existing_difference_count":len(different),"all_differences_retained":True,"candidate_dependencies_exact":checked,"candidate_dependencies_missing":len(dependencies)-checked,"candidate_executable":str(exe),"candidate_executable_sha256":bundle["executable"]["sha256"],"elapsed_seconds":time.monotonic()-start}
(ROOT/"REFERENCE_RECEIPT-r2.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
print(json.dumps(receipt),flush=True)
