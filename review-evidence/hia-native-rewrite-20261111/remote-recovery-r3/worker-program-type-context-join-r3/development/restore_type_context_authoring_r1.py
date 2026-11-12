"""Restore exact original program authoring from the complete published archive.

Every archive part, metadata file and all 8,355 original members are verified.
Only six selected immutable dependencies are materialized. No original tests
or source modules are imported or executed by this restoration function.
"""
from __future__ import annotations
import hashlib,json,stat,subprocess,tarfile
from pathlib import Path,PurePosixPath

def digest(raw):return hashlib.sha256(raw).hexdigest()
def gitsha(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def restore(repo,project,out):
    repo=Path(repo);project=Path(project);out=Path(out)
    out.mkdir(parents=True,exist_ok=False)
    source=project/"resources/exact-diagnostic-authoring-restoration.json"
    source_raw=source.read_bytes();plan=json.loads(source_raw)
    assert plan["schema"]=="hia-type-context-exact-program-authoring-restoration-r1"
    status="FAIL";failure=None;checked=[];selected=[];raw_total=0;frozen={}
    def fetch(row):
        raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",row["git_sha"]],cwd=repo,timeout=30)
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["git_sha"]),row
        return raw
    try:
        metadata={}
        for name in ("original_members","original_custody"):
            raw=fetch(plan[name]);path=out/(name+".json")
            path.write_bytes(raw);path.chmod(0o644);frozen[path]=raw
            metadata[name]=json.loads(raw)
        rows=metadata["original_members"]
        assert isinstance(rows,list) and len(rows)==8355
        byname={r["name"]:r for r in rows};assert len(byname)==len(rows)
        custody=metadata["original_custody"];arc=plan["original_archive"]
        assert custody["members"]==arc["members"]==8355
        assert custody["raw_bytes"]==arc["original_bytes"]==99770153
        assert (custody["bytes"],custody["sha256"])==(arc["bytes"],arc["sha256"])
        assert custody["members_index_sha256"]==plan["original_members"]["sha256"]
        archive=out/"original-diagnostics.tar.xz"
        gh=hashlib.sha256();total=0
        with archive.open("xb") as stream:
            for part in arc["ordered_parts"]:
                raw=fetch(part);stream.write(raw);gh.update(raw);total+=len(raw)
                checked.append(dict(kind="original_archive_part",path=part["path"],
                    bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw)))
        assert (total,gh.hexdigest())==(arc["bytes"],arc["sha256"])
        want={r["name"]:r for r in plan["requested"]};assert len(want)==6
        for name,row in want.items():
            assert name in byname
            assert all(row[k]==byname[name][k] for k in ("bytes","mode","sha256"))
        target=project/"restored-type-context-reference";target.mkdir(exist_ok=False)
        seen=set();full=[]
        with tarfile.open(archive,"r|xz") as tf:
            for member in tf:
                relative=PurePosixPath(member.name)
                assert member.name and not relative.is_absolute() and ".." not in relative.parts
                assert member.name not in seen and member.name in byname
                assert member.isfile() and not member.mode&0o7000
                row=byname[member.name]
                assert (member.size,member.mode)==(row["bytes"],row["mode"])
                seen.add(member.name);hasher=hashlib.sha256();n=0
                raw_parts=[] if member.name in want else None
                handle=tf.extractfile(member);assert handle is not None
                with handle:
                    for chunk in iter(lambda:handle.read(1<<20),b""):
                        hasher.update(chunk);n+=len(chunk)
                        if raw_parts is not None:raw_parts.append(chunk)
                assert (n,hasher.hexdigest())==(row["bytes"],row["sha256"]),member.name
                raw_total+=n
                full.append(dict(name=member.name,bytes=n,sha256=hasher.hexdigest(),mode=member.mode))
                if raw_parts is not None:
                    raw=b"".join(raw_parts);selected_row=want[member.name]
                    name=Path(selected_row["target"])
                    assert len(name.parts)==1 and name.name not in ("","..",".")
                    destination=target/name
                    with destination.open("xb") as stream:stream.write(raw)
                    destination.chmod(member.mode)
                    assert destination.read_bytes()==raw and stat.S_IMODE(destination.stat().st_mode)==member.mode
                    frozen[destination]=raw
                    selected.append(dict(original_member=member.name,path=str(destination),
                        bytes=n,sha256=digest(raw),gitsha=gitsha(raw),mode=member.mode))
        assert seen==set(byname) and len(selected)==6 and raw_total==99770153
        assert source.read_bytes()==source_raw
        assert all(path.read_bytes()==raw for path,raw in frozen.items())
        before=hashlib.sha256()
        with archive.open("rb") as stream:
            for chunk in iter(lambda:stream.read(1<<20),b""):before.update(chunk)
        assert before.hexdigest()==arc["sha256"]
        save(out/"all-original-member-readback.json",full)
        status="PASS"
        return {Path(row["path"]).name:Path(row["path"]) for row in selected}
    except BaseException as exc:
        import traceback
        failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        raise
    finally:
        save(out/"restoration-receipt.json",dict(
            schema="hia-type-context-original-authoring-restoration-receipt-r1",status=status,
            plan_bytes=len(source_raw),plan_sha256=digest(source_raw),plan_gitsha=gitsha(source_raw),
            original_archive=plan["original_archive"],parts_checked=checked,selected=selected,
            original_member_bytes_checked=raw_total,failure=failure,
            every_original_member_verified_before_dependency_use=status=="PASS",
            no_original_code_or_tests_executed=True,whole_program_qualification_claimed=False))
