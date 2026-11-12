"""Read the exact failed follow27 six-role artifact. No HIA generation or execution."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,json,os,resource,signal,stat,tarfile,time,traceback
from pathlib import Path,PurePosixPath
ARCHIVE=dict(bytes=5395348,sha256="224fbee74411c11a09c20b95d377297926dcc64dcc5ca86a1ac700ebb7120821")
INDEX=dict(bytes=23696,sha256="943503433d120fdc49c0c83a4b676bcee2ff8db400963940303f34c7f79e7d05")
EXPECTED_MEMBERS=72
EXPECTED_RAW_BYTES=40548863
DECLARED_ZIP=dict(artifact_id=13914581685,run_id=43151734029,job_id=130962283519,
    bytes=49260395,sha256="1c6005f5f43606d124ceab4705d4ec8ccd692368be3d8ceba528c3a07eaaedf6",
    provenance="original GitHub upload-artifact successful finalization log; outer ZIP not present in this directory readback")
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
    print("HIA_NAMESPACE_JOIN_ORIGINAL_META "+json.dumps(dict(name=label,bytes=len(raw),
        sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for offset in range(0,len(raw),6144):
        block=raw[offset:offset+6144]
        print("HIA_NAMESPACE_JOIN_ORIGINAL_CHUNK "+json.dumps(dict(name=label,offset=offset,
            bytes=len(block),sha256=sha(block),base64=base64.b64encode(block).decode("ascii")),
            sort_keys=True),flush=True)
    print("HIA_NAMESPACE_JOIN_ORIGINAL_END "+json.dumps(dict(name=label,bytes=len(raw),sha256=sha(raw)),
        sort_keys=True),flush=True)
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda signum,frame:(_ for _ in ()).throw(TimeoutError("reader wall180")))
    signal.alarm(180)
    root=Path(os.environ["HIA_NAMESPACE_JOIN_ORIGINAL_DIR"]).resolve(strict=True)
    output=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    assert not output.is_relative_to(root)
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    (output/"selected-originals").mkdir()
    report=dict(status="INCOMPLETE",scope="READ_ONLY_FOLLOW27_SIX_ROLE_ORIGINAL_FAILURE",
        declared_zip=DECLARED_ZIP,outer_zip_CRC_or_bytes_read=False,
        HIA_generation=0,B3_compilations=0,VM_entries=0,native_entries=0,
        target_reexecuted=False,old_failure_changed=False,whole_store_closed=False)
    try:
        matches=[]
        for directory,dirs,files in os.walk(root,followlinks=False):
            for d in dirs:assert not (Path(directory)/d).is_symlink()
            if "evidence.tar.xz" in files and "evidence-members.json" in files and "custody.json" in files:
                candidate=Path(directory)
                if pin(candidate/"evidence.tar.xz")["sha256"]==ARCHIVE["sha256"]:matches.append(candidate)
        assert len(matches)==1,("exact archive candidates",len(matches))
        directory=matches[0];archive=directory/"evidence.tar.xz"
        index_path=directory/"evidence-members.json";custody_path=directory/"custody.json"
        before={str(p):pin(p) for p in (archive,index_path,custody_path)}
        assert {k:before[str(archive)][k] for k in ARCHIVE}==ARCHIVE
        assert {k:before[str(index_path)][k] for k in INDEX}==INDEX
        index_raw=index_path.read_bytes();custody_raw=custody_path.read_bytes()
        rows=json.loads(index_raw);custody=json.loads(custody_raw)
        assert isinstance(rows,list) and len(rows)==EXPECTED_MEMBERS
        expected={}
        for row in rows:
            name=row["name"];p=PurePosixPath(name)
            assert not p.is_absolute() and all(x not in ("",".","..") for x in p.parts)
            assert p.as_posix()==name and name not in expected
            assert isinstance(row["bytes"],int) and row["bytes"]>=0
            assert isinstance(row["mode"],int) and 0<=row["mode"]<=0o7777
            expected[name]=row
        assert sum(r["bytes"] for r in rows)==EXPECTED_RAW_BYTES
        assert custody["members"]==EXPECTED_MEMBERS and custody["original_bytes"]==EXPECTED_RAW_BYTES
        assert custody["bytes"]==ARCHIVE["bytes"] and custody["sha256"]==ARCHIVE["sha256"]
        assert custody["member_index_bytes"]==INDEX["bytes"] and custody["member_index_sha256"]==INDEX["sha256"]
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
                pick=(base in ("summary.json","result.json","process.json","steps.json","stdout.log","stderr.log")
                    or base.endswith((".stdout",".stderr")) or "/generation-frontier/" in member.name)
                h=hashlib.sha256();count=0;chunks=[]
                for block in iter(lambda:stream.read(1<<20),b""):
                    count+=len(block);h.update(block)
                    if pick:chunks.append(block)
                assert count==row["bytes"] and h.hexdigest()==row["sha256"],member.name
                seen.add(member.name);actual_bytes+=count
                member_readback.append(dict(name=member.name,bytes=count,sha256=h.hexdigest(),mode=member.mode))
                if pick:selected[member.name]=b"".join(chunks)
        assert seen==set(expected) and actual_bytes==EXPECTED_RAW_BYTES
        # Export verified originals BEFORE interpreting nested summary fields.
        # Even an unexpected old report schema cannot hide the real traceback.
        originals={"control/evidence-members.json":index_raw,"control/custody.json":custody_raw,**selected}
        for number,(name,raw) in enumerate(sorted(originals.items())):
            target=output/"selected-originals"/str(number)
            target.write_bytes(raw);assert target.read_bytes()==raw
            emit(name,raw)
        save(output/"verified-member-readback.json",member_readback)
        report.update(full_archive_members_verified=len(seen),full_archive_raw_bytes=actual_bytes,
            selected_originals=[dict(name=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(originals.items())],
            source_before=before,all_member_bytes_sha256_mode_equal=True)
        build_names=[n for n in selected if n.endswith("/db-join-build-r1/summary.json")]
        assert len(build_names)==1,build_names
        build=json.loads(selected[build_names[0]])
        report["complete_original_build_summary"]=build
        report["complete_original_build_summary_pin"]=dict(name=build_names[0],
            bytes=len(selected[build_names[0]]),sha256=sha(selected[build_names[0]]))
        assert build["status"]=="FAIL" and build["error_class"]=="AssertionError"
        assert build["fresh_role_compiles"]==0 and build["packer_entries"]==0 and build["actual_carrier_processes"]==0
        assert build["source_pins_unchanged"] is True
        generated=build["generated_roles"];keys=[int(x) for x in generated]
        assert sorted(keys)==list(range(1,len(keys)+1)) and len(keys)<6
        report["last_completed_generation_role"]=max(keys) if keys else None
        report["next_role_at_failed_profile_inferred_from_original_fixed_loop"]=len(keys)+1
        report["failed_profile_numeric_value_recorded_in_original"]=False
        report["inference_scope"]="Original builder processes roles1..6 in order and stores generated_roles only after profile checks; the failed profile itself was not serialized."
        after={str(p):pin(p) for p in (archive,index_path,custody_path)}
        assert before==after
        report.update(status="PASS_READBACK_OF_ORIGINAL_FAIL",source_after=after,archive_and_controls_unchanged=True)
    except BaseException as error:
        report.update(status="READBACK_FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        signal.alarm(0)
        save(output/"summary.json",report)
        print("HIA_NAMESPACE_JOIN_ORIGINAL_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_READBACK_OF_ORIGINAL_FAIL" else 1
if __name__=="__main__":raise SystemExit(main())
