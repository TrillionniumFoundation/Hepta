"""Read exact physical FOLLOW37 evidence; never run its assembler, VM or native ELF."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,io,json,os,resource,shutil,signal,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
ARCHIVE_BYTES=20585932
ARCHIVE_SHA="ca72b80abe463797e7e8c65a7915585c4009f2966c829bc5bf1c4c2d008725e5"
INDEX_BYTES=1140352
INDEX_SHA="b2e54a00e55c695e2f9263dc8462191f0f45bdb0c1121ab63039e3542155b948"
MEMBERS=2280
RAW_BYTES=259051592
REPORTS={
 "/db-join-build-r1/summary.json":(129724,"3ea8b9fff2e13835cfc7697a9000f22fff8c1b1708d057dbe2f94ecf3920a156"),
 "/db-join-native-r1/summary.json":(678746,"00afd2787cdee947fcce02130d7e26b197fbf5df3a959fbfee0a97f18de482aa"),
 "/packer-differential-r1/summary.json":(22052,"944a7e907adfaec947dc7cbf1283daaa87a075a3257211d47eec20f94edfd4dd")}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1<<20),b""):h.update(block)
    return dict(bytes=st.st_size,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def emit(name,raw):
    print("HIA_NAMESPACE_PHYSICAL37_RAW_META "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for at in range(0,len(raw),6144):
        block=raw[at:at+6144]
        print("HIA_NAMESPACE_PHYSICAL37_RAW_CHUNK "+json.dumps(dict(name=name,offset=at,bytes=len(block),sha256=sha(block),base64=base64.b64encode(block).decode("ascii")),sort_keys=True),flush=True)
    print("HIA_NAMESPACE_PHYSICAL37_RAW_END "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw)),sort_keys=True),flush=True)
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("readback wall180")))
    signal.alarm(180)
    root=Path(os.environ["HIA_NAMESPACE_PHYSICAL37_DIR"]).resolve(strict=True)
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False,mode=0o700)
    report=dict(status="INCOMPLETE",artifact_id=13926453573,run_id=43180758618,job_id=131055866693,
        head_sha="e3ea7f33f1d7bf3350e4b54a9a8d3522746223c7",
        new_B3_compilations=0,new_VM_entries=0,new_native_entries=0,
        outer_ZIP_bytes_or_CRC_read=False,ordinary_Store_closed=False,whole_unixOpen_closed=False)
    try:
        matches=[]
        for directory,dirs,files in os.walk(root,followlinks=False):
            for name in dirs:assert not (Path(directory)/name).is_symlink()
            if all(name in files for name in ("evidence.tar.xz","evidence-members.json","custody.json")):
                d=Path(directory)
                if pin(d/"evidence.tar.xz")["sha256"]==ARCHIVE_SHA:matches.append(d)
        assert len(matches)==1,("unique exact sealed original",len(matches))
        d=matches[0];ap=d/"evidence.tar.xz";ip=d/"evidence-members.json";cp=d/"custody.json"
        before={str(p):pin(p) for p in (ap,ip,cp)}
        assert before[str(ap)]["bytes"]==ARCHIVE_BYTES
        assert before[str(ip)]["bytes"]==INDEX_BYTES and before[str(ip)]["sha256"]==INDEX_SHA
        ir=ip.read_bytes();cr=cp.read_bytes();rows=json.loads(ir);custody=json.loads(cr)
        assert isinstance(rows,list) and len(rows)==MEMBERS
        expected={}
        for row in rows:
            name=row["name"];path=PurePosixPath(name)
            assert not path.is_absolute() and ".." not in path.parts and path.as_posix()==name and name not in expected
            expected[name]=row
        assert sum(r["bytes"] for r in rows)==RAW_BYTES
        assert custody["status"]=="PASS" and custody["members"]==MEMBERS and custody["original_bytes"]==RAW_BYTES
        assert custody["bytes"]==ARCHIVE_BYTES and custody["sha256"]==ARCHIVE_SHA
        assert custody["member_index_bytes"]==INDEX_BYTES and custody["member_index_sha256"]==INDEX_SHA
        assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        selected={};canonical={};seen=set();total=0;verified=[]
        with tarfile.open(ap,"r:xz") as tf:
            for member in tf:
                assert member.isfile() and member.name in expected and member.name not in seen
                row=expected[member.name]
                assert member.size==row["bytes"] and member.mode==row["mode"]
                assert member.uid==member.gid==member.mtime==0
                name=member.name;base=PurePosixPath(name).name
                original=any(name.endswith(suffix) for suffix in REPORTS)
                original=original or base in ("stdout.log","stderr.log") or base.endswith((".stdout",".stderr"))
                frozen=("/db-join-build-r1/" in name and base.endswith((".hiaasm",".image.bin",".receipt.json",".request.json")))
                frozen=frozen or name.endswith("/compiler/B3.image.bin")
                h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0;chunks=[]
                stream=tf.extractfile(member);assert stream is not None
                for block in iter(lambda:stream.read(1<<20),b""):
                    n+=len(block);h.update(block);g.update(block)
                    if original or frozen:chunks.append(block)
                assert n==row["bytes"] and h.hexdigest()==row["sha256"],name
                seen.add(name);total+=n
                verified.append(dict(name=name,bytes=n,mode=member.mode,sha256=h.hexdigest(),git_blob_sha1=g.hexdigest()))
                if original or frozen:
                    raw=b"".join(chunks)
                    if original:selected[name]=raw
                    if frozen:canonical[name]=(raw,member.mode)
        assert seen==set(expected) and total==RAW_BYTES
        # Emit original bytes before any nested semantic assertions.
        shutil.copyfile(ap,out/"original-evidence.tar.xz")
        assert pin(out/"original-evidence.tar.xz")["sha256"]==ARCHIVE_SHA
        originals={"control/evidence-members.json":ir,"control/custody.json":cr,**selected}
        exported=[]
        for i,(name,raw) in enumerate(sorted(originals.items())):
            path=out/"selected-originals"/str(i);path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw);assert path.read_bytes()==raw
            exported.append(dict(name=name,bytes=len(raw),sha256=sha(raw),path=str(path.relative_to(out))))
            emit(name,raw)
        save(out/"selected-originals.json",exported)
        save(out/"verified-members.json",verified)
        def one(suffix):
            got=[(n,b) for n,b in selected.items() if n.endswith(suffix)]
            assert len(got)==1,(suffix,len(got))
            name,raw=got[0];expected_size,expected_sha=REPORTS[suffix]
            assert len(raw)==expected_size and sha(raw)==expected_sha
            return json.loads(raw)
        build=one("/db-join-build-r1/summary.json")
        physical=one("/db-join-native-r1/summary.json")
        packer=one("/packer-differential-r1/summary.json")
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
        assert build["fresh_role_compiles"]==6 and build["packer_entries"]==33
        assert len(build["packer_controls"])==33
        assert set(build["exact_roles"])==set(build["compiled_roles"])==set(build["generated_roles"])==set("123456")
        assert all(r["actual_return"]==r["expected_return"] and r["exact_output_equal"] and r["source_unchanged"] and r["workspace_unchanged"] and r["guards"] for r in build["packer_controls"])
        assert packer["status"]=="PASS" and packer["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
        assert packer["source_before_after_equal"] and packer["no_masks"] and packer["complete_buffers_equal"]
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        tests=physical["tests"]
        assert tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==len(set(tests["test_ids"]))==18
        assert not any(tests[key] for key in ("errors","failures","skipped","expected_failures","unexpected_successes"))
        assert physical["native_entries"]==physical["vm_entries"]==2562
        assert physical["actual_primitive_acks"]==266
        assert physical["entries_by_role"]=={"1":561,"2":26,"3":24,"4":602,"5":372,"6":977}
        assert physical["process_traces"]==len(physical["replay"])==len(physical["process_limit_readbacks"])==22
        assert physical["actual_DB_retirements"]==28 and physical["actual_inner_retirements"]==2
        assert physical["all_actual_trace_processes_fully_replayed"]
        assert physical["abort_cleanup_pure_control_count"]==len(physical["abort_cleanup_pure_controls"])==3
        for entry in physical["process_limit_readbacks"]:
            assert entry["actual"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert entry["limits"]["wall_seconds"]==180 and entry["returncode"]==0
            assert os.WIFEXITED(entry["wait_status"]) and os.WEXITSTATUS(entry["wait_status"])==0
        for entry in physical["replay"]:
            assert entry["status"]=="PASS" and entry["no_masks"] and entry["no_inherited_counts"]
            assert entry["all_original_records_partitioned_exactly_once"] and entry["all_input_output_workspace_return_bytes_equal"]
            assert entry["native_entries"]==entry["vm_entries"]>0 and entry["original_trace_before"]==entry["original_trace_after"]
            assert entry["no_OS_primitive_executed_by_replayer"]
        canonical_rows=[]
        for name,(raw,mode) in sorted(canonical.items()):
            canonical_rows.append(dict(name=name,bytes=len(raw),mode=mode,sha256=sha(raw),
                git_blob_sha1=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()))
        assert canonical_rows
        for role,row in build["exact_roles"].items():
            for kind in ("source","image"):
                target=row[kind]
                found=[r for r in canonical_rows if r["bytes"]==target["bytes"] and r["sha256"]==target["sha256"]]
                assert found,(role,kind,target)
        canonical_path=out/"canonical-HIA-images-and-receipts.tar.xz"
        with tarfile.open(canonical_path,"w:xz",format=tarfile.PAX_FORMAT,preset=1) as tf:
            for name,(raw,mode) in sorted(canonical.items()):
                member=tarfile.TarInfo(name);member.size=len(raw);member.mode=mode
                member.uid=member.gid=member.mtime=0
                tf.addfile(member,io.BytesIO(raw))
        reread=set()
        with tarfile.open(canonical_path,"r:xz") as tf:
            for member in tf:
                assert member.isfile() and member.name in canonical and member.name not in reread
                raw,mode=canonical[member.name]
                assert member.mode==mode and member.size==len(raw)
                stream=tf.extractfile(member);assert stream is not None and stream.read()==raw
                reread.add(member.name)
        assert reread==set(canonical)
        save(out/"canonical-members.json",canonical_rows)
        after={str(p):pin(p) for p in (ap,ip,cp)};assert after==before
        report.update(status="PASS_READBACK_ONLY",members=len(seen),raw_bytes=total,
            complete_members_bytes_modes_SHA_Git_verified=True,source_before=before,source_after=after,
            archive_controls_unchanged=True,selected_originals=exported,
            original_physical_counts=dict(tests=18,native_entries=2562,VM_entries=2562,
                primitive_acks=266,fixed_processes=22,DB_retirements=28,inner_retirements=2),
            original_B3_counts=dict(roles=6,packer=1),original_native_packer_controls=33,
            original_three_way=packer["counts"],canonical_archive=pin(canonical_path),
            canonical_members=canonical_rows,
            all_complete_original_report_bytes_emitted=True,whole_stack_closed=False)
    except BaseException as error:
        report.update(status="READBACK_FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        signal.alarm(0);save(out/"summary.json",report)
        print("HIA_NAMESPACE_PHYSICAL37_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
