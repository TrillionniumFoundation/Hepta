"""Restore the exact worker dependencies for a NEW independent CI execution.

All archived bytes/modes are checked before use. Historical raw observations stay
in snapshots and are never imported as a test result. No namespace is executed.
"""
from __future__ import annotations
import ast
from hashlib import sha1, sha256
import json, lzma, os, shutil, stat, subprocess, sys, tarfile
from pathlib import Path, PurePosixPath

CONTEXT=Path(sys.argv[1])
INDEX=Path(sys.argv[2])
C=json.loads(CONTEXT.read_bytes())
D=json.loads(INDEX.read_bytes())
BASE=Path(C["base"])/"worker-recovery"
WORK=BASE/"work-r2"
REPO=Path(C["repo"])
SOURCE=Path(C["source"])
REFERENCE=Path(C["reference"])
OUTPUT=Path(C["output"])/"worker-restore"
OUTPUT.mkdir(parents=True,exist_ok=False)
WORK.mkdir(parents=True,exist_ok=False)
def digest(b): return sha256(b).hexdigest()
def gitsha(b): return sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def info(path):
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
def exact(raw,row):
    assert len(raw)==row["bytes"] and digest(raw)==row["sha256"],row
def install(raw,target,mode=0o644):
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        assert target.is_file() and not target.is_symlink()
        target.write_bytes(raw)
    else:
        with target.open("xb") as h: h.write(raw)
    target.chmod(mode)
    assert target.read_bytes()==raw
def restore(row):
    archive=SOURCE/row["path"]
    data=archive.read_bytes()
    exact(data,row)
    manifest_raw=(SOURCE/row["members_path"]).read_bytes()
    assert digest(manifest_raw)==row["members_sha256"]
    if row["members_path"].endswith(".xz"): manifest_raw=lzma.decompress(manifest_raw)
    manifest=json.loads(manifest_raw)
    if isinstance(manifest,dict): manifest=manifest["members"]
    assert isinstance(manifest,list) and len(manifest)==row["members"]
    expected={}
    for item in manifest:
        name=item.get("path",item.get("name"))
        assert type(name) is str and name not in expected
        parts=PurePosixPath(name)
        assert not parts.is_absolute() and parts.parts and not any(p in ("..","") for p in parts.parts)
        expected[name]=item
    dest=BASE/"snapshots"/row["name"]
    dest.mkdir(parents=True,exist_ok=False)
    seen=set()
    with tarfile.open(archive,"r:xz") as tf:
        for member in tf:
            assert not member.issym() and not member.islnk()
            parts=PurePosixPath(member.name)
            assert not parts.is_absolute() and not any(p in ("..","") for p in parts.parts)
            if member.isdir(): continue
            assert member.isfile() and member.name in expected and member.name not in seen
            item=expected[member.name]
            raw=tf.extractfile(member).read()
            mode=item["mode"]
            if isinstance(mode,str): mode=int(mode,8)
            assert (len(raw),digest(raw),member.mode)==(item["bytes"],item["sha256"],mode),member.name
            install(raw,dest/member.name,mode)
            assert info(dest/member.name)["sha256"]==item["sha256"]
            seen.add(member.name)
    assert seen==set(expected)
    save(OUTPUT/(row["name"]+".json"),dict(archive=info(archive),member_index_sha256=digest(manifest_raw),
        members=len(seen),all_original_tar_and_restored_bytes_modes_sha256_equal=True,
        historical_observations_not_counted=True,root=str(dest)))
    return dest
snapshots={row["name"]:restore(row) for row in D["archives"]}

# Own reference copy. Never edit the common immutable source/reference/workspace.
ref=WORK/"Hepta-agent-edit-native"
shutil.copytree(REFERENCE,ref,symlinks=False,ignore=shutil.ignore_patterns(".git","__pycache__","*.pyc"))
overlay=[]
report=snapshots["worker-report-r1"]
for row in D["reference_overlay_paths"]:
    raw=(report/row["path"]).read_bytes(); exact(raw,row)
    target=ref/row["target"]
    old=info(target) if target.exists() else None
    install(raw,target,row["mode"])
    overlay.append(dict(source=row["path"],target=str(target),before=old,after=info(target)))

# Working authoring and mechanical helpers only; old run directories stay separate.
def top_files(snapshot,target):
    for directory in ("tools","examples","docs"):
        p=snapshot/directory
        if p.exists():
            for source in sorted(p.rglob("*")):
                if source.is_file():
                    install(source.read_bytes(),target/source.relative_to(snapshot),stat.S_IMODE(source.stat().st_mode))
    p=snapshot/"development"
    if p.exists():
        for source in sorted(p.glob("*.py")):
            install(source.read_bytes(),target/"development"/source.name,stat.S_IMODE(source.stat().st_mode))
worker=WORK/"native-agent-worker-next"
top_files(report,worker)
top_files(snapshots["worker-request-r1"],worker)
render=WORK/"native-agent-edit-render-next"
top_files(snapshots["graph-wire-r3"],render)
for row in D["peer_sources"]: exact((render/row["path"]).read_bytes(),row)
mechanical=worker/D["expected_request_mechanics"]["path"]
assert digest(mechanical.read_bytes())==D["expected_request_mechanics"]["sha256"]

# The compiler is the exact f50 B3 originally bound to these components.
compiler=WORK/"dependencies/f50-B3.image.bin"
raw=(snapshots["graph-wire-r3"]/"dependencies/f50-B3.image.bin").read_bytes()
exact(raw,D["original_compiler"])
assert raw==(report/"development/report-compile-r1/source/4/f50-B3.image.bin").read_bytes()
install(raw,compiler)

def from_git(row,target):
    expected=row.get("gitsha",row.get("blob"))
    raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",expected],cwd=REPO)
    assert gitsha(raw)==expected
    exact(raw,row)
    if target.suffix==".py": ast.parse(raw,filename=str(target))
    install(raw,target)
    return dict(**info(target),gitsha=expected)
records=WORK/"native-agent-service-controller-next"
new=[]
for row in D["records_authoring"]+D["new_records_source"]:
    new.append(from_git(row,records/row["path"]))
bridge=WORK/"native-agent-service-call-next"
for row in D["bridge_source"]:
    new.append(from_git(row,bridge/row["path"]))
(bridge/"examples/hia_bootstrap").mkdir(parents=True,exist_ok=True)
(bridge/"development").mkdir(parents=True,exist_ok=True)
# Check all compiler/authoring prerequisites against the previous exact input set.
for row in D["reference_overlays"]:
    if row["name"]=="generate_hia_worker_report.py": p=worker/"tools"/row["name"]
    elif row["name"]=="hia_agent_assembly.py": p=ref/"hepta"/row["name"]
    else: p=ref/"tools"/row["name"]
    exact(p.read_bytes(),row)
assert digest((ref/"hepta/hia_program.py").read_bytes())=="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"

pins=[]
for component in (ref,worker,render,records,bridge):
    for path in sorted(component.rglob("*")):
        if path.is_file() and path.suffix in (".py",".hiaasm",".json",".toml"):
            pins.append(info(path))
save(OUTPUT/"input-pins.json",pins)
save(OUTPUT/"reference-overlays.json",overlay)
save(OUTPUT/"new-blob-inputs.json",new)
save(OUTPUT/"summary.json",dict(status="PASS",scope="EXACT_DEPENDENCY_RESTORE_ONLY_NO_NATIVE_TEST",
    work=str(WORK),compiler=info(compiler),historical_tests_inherited=False,
    archives=len(snapshots),restored_members=sum(r["members"] for r in D["archives"])))
print(json.dumps(dict(status="PASS",work=str(WORK),compiler_sha256=digest(raw)),sort_keys=True),flush=True)
