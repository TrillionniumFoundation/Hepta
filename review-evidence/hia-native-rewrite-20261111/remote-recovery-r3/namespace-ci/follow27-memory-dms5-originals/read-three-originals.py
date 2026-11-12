"""Verify three exact follow27 inner archives; export original full JSON before interpretation.
This reader performs no target generation, compilation, VM or native execution.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,json,os,resource,signal,stat,tarfile,time,traceback
from pathlib import Path,PurePosixPath
SPECS=json.loads("{\"memory\":{\"archive\":{\"bytes\":5736712,\"sha256\":\"e5bb750cce638385ba2db8b73dc33d6ae2e7afe46636344819dc9ffd4a08fafe\"},\"index\":{\"bytes\":37444,\"sha256\":\"e8a679b73fd0a294122f3b8f3bb99849d31cecc38b8865ba4ecd2e4be648a688\"},\"members\":109,\"raw_bytes\":43966610,\"zip\":{\"artifact_id\":13913923606,\"run_id\":43151734029,\"job_id\":130962281503,\"bytes\":49548281,\"sha256\":\"e9eec4ac832205e1d7ba985dbc987b1db6d9f85327ba32d27e4259966dea4def\"}},\"dms5\":{\"archive\":{\"bytes\":6683684,\"sha256\":\"36f4fe56c7153e894073dccc019657b217ff297aa6449cd891192e8d5c1f436d\"},\"index\":{\"bytes\":40634,\"sha256\":\"1492bf362ebd9b0d1a37bd8ffd433562ce672190b5caed50b0641050581ef378\"},\"members\":124,\"raw_bytes\":49058727,\"zip\":{\"artifact_id\":13913519303,\"run_id\":43151734029,\"job_id\":130962283535,\"bytes\":58875380,\"sha256\":\"ae540dd10cff1e913949cf03713cfb114c665083ca59975c6b97202b115f85ec\"}},\"db2\":{\"archive\":{\"bytes\":6889764,\"sha256\":\"fa6737eecad13e292194361b18300ed7d2a468b38cb711b52b1c57c95c0538e6\"},\"index\":{\"bytes\":39805,\"sha256\":\"16aa515ca5bdbac940597cfccb726736f3d41bd6e91c63dcf88a8be0a15353cb\"},\"members\":121,\"raw_bytes\":45679995,\"zip\":{\"artifact_id\":13915165562,\"run_id\":43151734029,\"job_id\":130962283526,\"bytes\":55889156,\"sha256\":\"e2fa27412039ca3567264440cb0b6e4b2c7cd60672460e22304b2db51b752dd7\"}}}")
for _spec in SPECS.values():
    _spec["zip"]["provenance"]="Original upload-artifact successful finalization log; outer ZIP is not available in the decompressed directory and is not byte/CRC verified here."
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    value=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1<<20),b""):value.update(block)
    return dict(bytes=st.st_size,sha256=value.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def emit(label,raw):
    print("HIA_NAMESPACE_COMPONENT_ORIGINAL_META "+json.dumps(dict(name=label,bytes=len(raw),
        sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for offset in range(0,len(raw),6144):
        block=raw[offset:offset+6144]
        print("HIA_NAMESPACE_COMPONENT_ORIGINAL_CHUNK "+json.dumps(dict(name=label,offset=offset,
            bytes=len(block),sha256=sha(block),base64=base64.b64encode(block).decode("ascii")),
            sort_keys=True),flush=True)
    print("HIA_NAMESPACE_COMPONENT_ORIGINAL_END "+json.dumps(dict(name=label,bytes=len(raw),sha256=sha(raw)),
        sort_keys=True),flush=True)

def read_component(label,root,output,spec):
    output.mkdir(mode=0o700,exist_ok=False)
    (output/"selected-originals").mkdir()
    report=dict(status="INCOMPLETE",scope="READ_ONLY_FOLLOW27_COMPONENT_ORIGINAL",component=label,
        declared_zip=spec["zip"],outer_zip_CRC_or_bytes_read=False,
        HIA_generation=0,B3_compilations=0,VM_entries=0,native_entries=0,
        target_reexecuted=False,old_failure_changed=False,whole_store_closed=False)
    try:
        matches=[]
        for directory,dirs,files in os.walk(root,followlinks=False):
            for d in dirs:assert not (Path(directory)/d).is_symlink()
            if "evidence.tar.xz" in files and "evidence-members.json" in files and "custody.json" in files:
                candidate=Path(directory)
                if pin(candidate/"evidence.tar.xz")["sha256"]==spec["archive"]["sha256"]:matches.append(candidate)
        assert len(matches)==1,("exact archive candidates",len(matches))
        directory=matches[0];archive=directory/"evidence.tar.xz"
        index_path=directory/"evidence-members.json";custody_path=directory/"custody.json"
        before={str(p):pin(p) for p in (archive,index_path,custody_path)}
        assert {k:before[str(archive)][k] for k in spec["archive"]}==spec["archive"]
        assert {k:before[str(index_path)][k] for k in spec["index"]}==spec["index"]
        index_raw=index_path.read_bytes();custody_raw=custody_path.read_bytes()
        rows=json.loads(index_raw);custody=json.loads(custody_raw)
        assert isinstance(rows,list) and len(rows)==spec["members"]
        expected={}
        for row in rows:
            name=row["name"];p=PurePosixPath(name)
            assert not p.is_absolute() and all(x not in ("",".","..") for x in p.parts)
            assert p.as_posix()==name and name not in expected
            assert isinstance(row["bytes"],int) and row["bytes"]>=0
            assert isinstance(row["mode"],int) and 0<=row["mode"]<=0o7777
            expected[name]=row
        assert sum(r["bytes"] for r in rows)==spec["raw_bytes"]
        assert custody["members"]==spec["members"] and custody["original_bytes"]==spec["raw_bytes"]
        assert custody["bytes"]==spec["archive"]["bytes"] and custody["sha256"]==spec["archive"]["sha256"]
        assert custody["member_index_bytes"]==spec["index"]["bytes"] and custody["member_index_sha256"]==spec["index"]["sha256"]
        assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        selected={};seen=set();actual_bytes=0;member_readback=[]
        with tarfile.open(archive,"r:xz") as tf:
            for member in tf:
                assert member.isfile() and member.name in expected and member.name not in seen
                row=expected[member.name]
                assert member.size==row["bytes"] and member.mode==row["mode"]
                assert member.uid==member.gid==member.mtime==0
                stream=tf.extractfile(member);assert stream is not None
                base=PurePosixPath(member.name).name
                pick=(base.endswith(".json") or base.endswith((".stdout",".stderr"))
                    or base in ("stdout.log","stderr.log","tests.stderr.log","tests.stdout.log"))
                h=hashlib.sha256();count=0;chunks=[]
                for block in iter(lambda:stream.read(1<<20),b""):
                    count+=len(block);h.update(block)
                    if pick:chunks.append(block)
                assert count==row["bytes"] and h.hexdigest()==row["sha256"],member.name
                seen.add(member.name);actual_bytes+=count
                member_readback.append(dict(name=member.name,bytes=count,sha256=h.hexdigest(),mode=member.mode))
                if pick:selected[member.name]=b"".join(chunks)
        assert seen==set(expected) and actual_bytes==spec["raw_bytes"]
        # Export verified originals BEFORE interpreting nested summary fields.
        # Even an unexpected old report schema cannot hide the real traceback.
        originals={"control/evidence-members.json":index_raw,"control/custody.json":custody_raw,**selected}
        for number,(name,raw) in enumerate(sorted(originals.items())):
            target=output/"selected-originals"/str(number)
            target.write_bytes(raw);assert target.read_bytes()==raw
            emit(label+'/'+name,raw)
        save(output/"verified-member-readback.json",member_readback)
        report.update(full_archive_members_verified=len(seen),full_archive_raw_bytes=actual_bytes,
            selected_originals=[dict(name=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(originals.items())],
            source_before=before,all_member_bytes_sha256_mode_equal=True)
        # These are the complete original documents, never normalized into
        # new qualification counts. Print all selected bytes before parsing.
        summaries=[]
        for name,raw in sorted(selected.items()):
            if PurePosixPath(name).name in ("summary.json","result.json","process.json"):
                value=json.loads(raw)
                summaries.append(dict(name=name,bytes=len(raw),sha256=sha(raw),value=value))
        report["complete_original_summaries"]=summaries
        report["original_custody_status"]=custody["status"]
        assert custody["status"]=="PASS"
        assert summaries, "no original summary documents"
        after={str(p):pin(p) for p in (archive,index_path,custody_path)}
        assert before==after
        report.update(status="PASS_READBACK_ONLY",source_after=after,archive_and_controls_unchanged=True,
            native_entry_counts_reexecuted=False,target_semantics_revalidated=False)
    except BaseException as error:
        report.update(status="READBACK_FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        save(output/"summary.json",report)
        print("HIA_NAMESPACE_COMPONENT_ORIGINAL_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    return report
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda signum,frame:(_ for _ in ()).throw(TimeoutError("reader wall180")))
    deadline=time.monotonic()+180
    signal.alarm(180)
    output=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    roots={label:Path(os.environ["HIA_NAMESPACE_"+label.upper()+"_ORIGINAL_DIR"]).resolve(strict=True)
        for label in SPECS}
    assert all(not output.is_relative_to(root) for root in roots.values())
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    results={}
    try:
        for label,spec in SPECS.items():
            if time.monotonic()>=deadline:raise TimeoutError("reader total wall180")
            results[label]=read_component(label,roots[label],output/label,spec)
        passed=all(row["status"]=="PASS_READBACK_ONLY" for row in results.values())
        summary=dict(status="PASS_READBACK_ONLY" if passed else "READBACK_FAIL",
            component_statuses={name:row["status"] for name,row in results.items()},
            members=sum(row.get("full_archive_members_verified",0) for row in results.values()),
            raw_bytes=sum(row.get("full_archive_raw_bytes",0) for row in results.values()),
            new_HIA_generations=0,new_B3_compilations=0,new_VM_entries=0,new_native_entries=0,
            ordinary_store_closed=False,old_qualification_changed=False)
        if passed:assert summary["members"]==354 and summary["raw_bytes"]==138705332
        save(output/"summary.json",summary)
        print("HIA_NAMESPACE_THREE_COMPONENTS_READBACK "+json.dumps(summary,sort_keys=True),flush=True)
        return 0 if passed else 1
    finally:signal.alarm(0)
if __name__=="__main__":raise SystemExit(main())
