"""Read only exact follow35 physical failure and completed follow34 readback.

No target code, compiler, assembler, VM, child process or syscall test is run.
Whole original tar/member identity is checked before interpreting target reports.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,json,os,resource,shutil,signal,stat,struct,tarfile,time,traceback
from pathlib import Path,PurePosixPath
PHYSICAL=dict(artifact=13920641096,run=43165373215,job=131005901231,
 archive_bytes=19226512,archive_sha="27996bd31956c6fe43aec60dfd86f860b0b29ec0daaf74f3eed777c920b25ef9",
 index_bytes=604294,index_sha="1974992536366133ed9859692c12ecf5bca8b63f1cfd3bb7f94f3901be2221b9",
 members=1283,raw_bytes=222488303)
PREDECESSORS={
 "physical":dict(archive_bytes=6939000,archive_sha="fd9556b23ee9144d39fab66c038db5f1d3828fa0f948e4abc3eae0326b034a10",
 index_bytes=76424,index_sha="c561b3140924caca6233b2534a3e5964c65ba84979b2d7198c2fc95238649b34",members=211,raw_bytes=57844918),
 "robust":dict(archive_bytes=5848768,archive_sha="2f847906196b50a0f0d87e0c8b1afab191042fc6a36c289fb5470008c433ecce",
 index_bytes=26525,index_sha="3f31a18e65b745f42d62c1787343e731746ea9290370aa1416875b4890e32b1e",members=82,raw_bytes=44209189)}
MAGICS={int.from_bytes(value,"little"):role for value,role in
 [(b"HIANFT03",1),(b"HIASMT01",2),(b"HIANMT01",3),(b"HIANDT03",4),(b"HIADBT01",5),(b"HIADJT01",6)]}
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda:stream.read(1<<20),b""):h.update(raw)
    return dict(bytes=st.st_size,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def emit(name,raw):
    header=dict(name=name,bytes=len(raw),sha256=sha(raw),encoding="base64",chunk_bytes=6144)
    print("HIA_NAMESPACE_F35_RAW_META "+json.dumps(header,sort_keys=True),flush=True)
    for start in range(0,len(raw),6144):
        part=raw[start:start+6144]
        print("HIA_NAMESPACE_F35_RAW_CHUNK "+json.dumps(dict(name=name,offset=start,
            bytes=len(part),sha256=sha(part),base64=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
    print("HIA_NAMESPACE_F35_RAW_END "+json.dumps(header,sort_keys=True),flush=True)
def walk(root):
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        for name in files:
            path=Path(directory)/name
            assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(),str(path)
            yield path
def safe_name(name):
    path=PurePosixPath(name)
    assert not path.is_absolute() and ".." not in path.parts and path.as_posix()==name and name
    return path
def sealed_archive(archive,index_raw,model,out):
    before=pin(archive)
    assert before["bytes"]==model["archive_bytes"] and before["sha256"]==model["archive_sha"]
    assert len(index_raw)==model["index_bytes"] and sha(index_raw)==model["index_sha"]
    rows=json.loads(index_raw);assert isinstance(rows,list) and len(rows)==model["members"]
    expected={}
    for row in rows:
        name=row["name"];safe_name(name);assert name not in expected
        assert type(row["bytes"]) is int and row["bytes"]>=0
        assert type(row["mode"]) is int and 0<=row["mode"]<=0o7777
        expected[name]=row
    assert sum(row["bytes"] for row in rows)==model["raw_bytes"]
    selected={};seen=set();total=0
    with tarfile.open(archive,"r:xz") as original:
        for member in original:
            assert member.isfile() and member.name in expected and member.name not in seen
            row=expected[member.name]
            assert member.size==row["bytes"] and member.mode==row["mode"]
            assert member.uid==member.gid==member.mtime==0
            name=member.name;base=PurePosixPath(name).name
            pick=(base.endswith((".json",".stdout",".stderr",".log",".strace",".maps"))
                and not base.endswith(".document.json"))
            pick=pick or base in ("trace.bin","executor.o") or base.endswith((".hiaasm",".image.bin"))
            target=out/"members"/safe_name(name) if pick else None
            if target is not None:target.parent.mkdir(parents=True,exist_ok=True)
            sink=target.open("xb") if target is not None else None
            stream=original.extractfile(member);assert stream is not None
            digest=hashlib.sha256();size=0
            try:
                for raw in iter(lambda:stream.read(1<<20),b""):
                    digest.update(raw);size+=len(raw)
                    if sink is not None:sink.write(raw)
            finally:
                if sink is not None:sink.close()
            assert size==row["bytes"] and digest.hexdigest()==row["sha256"],name
            if target is not None:
                target.chmod(row["mode"]);assert pin(target)==dict(bytes=size,sha256=digest.hexdigest(),mode=row["mode"])
                selected[name]=target
            seen.add(name);total+=size
    assert seen==set(expected) and total==model["raw_bytes"]
    after=pin(archive);assert before==after
    save(out/"complete-original-member-index.json",rows)
    shutil.copyfile(archive,out/"original-evidence.tar.xz")
    assert pin(out/"original-evidence.tar.xz")["sha256"]==model["archive_sha"]
    return dict(members=len(seen),raw_bytes=total,all_member_bytes_modes_sha256_verified=True,
        archive_before=before,archive_after=after,outer_ZIP_read=False),selected,expected
def one(selected,suffix):
    found=[(name,path) for name,path in selected.items() if name.endswith(suffix)]
    assert len(found)==1,(suffix,len(found));return found[0]
def raw_export(name,path):
    raw=path.read_bytes();emit(name,raw);return dict(name=name,path=str(path),**pin(path))
def trace_scan(path):
    """Describe original complete framing only; this is not semantic replay."""
    identity=pin(path);limit=identity["bytes"];offset=0;counts={};last=[];status="COMPLETE_FRAMING_ONLY";error=None
    try:
        with path.open("rb") as stream:
            while offset<limit:
                start=offset
                if limit-offset<96:raise ValueError("incomplete original header")
                raw=stream.read(96);offset+=96;words=struct.unpack("<12Q",raw)
                if words[0] not in MAGICS:raise ValueError("unknown original trace magic")
                role=MAGICS[words[0]];kind=words[1]
                if kind==1:parts=words[3:6]
                elif kind==2:parts=words[4:6]
                elif kind==3:parts=(words[3],)
                elif kind==4:parts=()
                else:raise ValueError("unknown original trace kind")
                size=sum(parts)
                if size>limit-offset:raise ValueError("incomplete original payload")
                digest=hashlib.sha256();first=b"";remaining=size
                while remaining:
                    chunk=stream.read(min(65536,remaining))
                    if not chunk:raise ValueError("unexpected original EOF")
                    if len(first)<256:first+=(chunk[:256-len(first)])
                    digest.update(chunk);remaining-=len(chunk);offset+=len(chunk)
                key=str(role)+":"+str(kind);counts[key]=counts.get(key,0)+1
                last.append(dict(offset=start,end=offset,role=role,kind=kind,header=list(words),
                    payload_bytes=size,payload_sha256=digest.hexdigest(),payload_first256_hex=first.hex()))
                last=last[-8:]
    except (ValueError,struct.error) as exc:
        status="INCOMPLETE_OR_UNRECOGNIZED_ORIGINAL_FRAMING"
        error=dict(error_class=type(exc).__name__,error=str(exc),offset=offset)
    assert pin(path)==identity
    return dict(identity=identity,status=status,complete_record_counts=counts,last_complete_records=last,error=error,
        new_VM_entries=0,new_native_entries=0,semantic_replay_performed=False)
def read_physical(root,out):
    root=root.resolve(strict=True);out.mkdir()
    candidates=[]
    for path in walk(root):
        if path.name=="evidence.tar.xz" and pin(path)["sha256"]==PHYSICAL["archive_sha"]:
            candidates.append(path)
    assert len(candidates)==1
    archive=candidates[0];index=archive.with_name("evidence-members.json");custody_path=archive.with_name("custody.json")
    index_raw=index.read_bytes();custody_raw=custody_path.read_bytes()
    before={str(path):pin(path) for path in (archive,index,custody_path)}
    seal,selected,expected=sealed_archive(archive,index_raw,PHYSICAL,out)
    (out/"original-custody.json").write_bytes(custody_raw)
    (out/"original-index.json").write_bytes(index_raw)
    # Full raw principal diagnostics are emitted before their schema is interpreted.
    principals={}
    for label,suffix in (("build","/db-join-build-r1/summary.json"),
        ("physical","/db-join-native-r1/summary.json"),("packer-differential","/packer-differential-r1/summary.json"),
        ("tests-stderr","/db-join-native-r1/tests.stderr.log")):
        name,path=one(selected,suffix);principals[label]=dict(member=name,**raw_export("physical35/"+label,path))
    process_rows=[];trace_rows=[];other_diagnostics=[]
    for name,path in sorted(selected.items()):
        base=PurePosixPath(name).name
        if "/db-join-native-r1/" not in name:continue
        if base in ("process.json","abort.json","start.json","requests.json","native-identity.json"):
            raw=path.read_bytes()
            try:value=json.loads(raw)
            except (ValueError,UnicodeError) as exc:value=dict(parse_error=repr(exc))
            if base=="requests.json":
                view=dict(records=len(value),last=value[-3:]) if isinstance(value,list) else value
            else:view=value
            process_rows.append(dict(member=name,identity=pin(path),value=view))
        if base=="trace.bin" and "/four-role-original-partition/" not in name:
            trace_rows.append(dict(member=name,**trace_scan(path)))
        if base.endswith(".strace"):
            raw=path.read_bytes()
            other_diagnostics.append(dict(member=name,identity=pin(path),
                complete_original_preserved=True,last40lines=raw.decode("utf-8","backslashreplace").splitlines()[-40:]))
    custody=json.loads(custody_raw)
    assert custody["status"]=="FAIL" and custody["members"]==1283 and custody["original_bytes"]==222488303
    assert custody["bytes"]==19226512 and custody["sha256"]==PHYSICAL["archive_sha"]
    assert custody["member_index_bytes"]==604294 and custody["member_index_sha256"]==PHYSICAL["index_sha"]
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    build=json.loads(one(selected,"/db-join-build-r1/summary.json")[1].read_bytes())
    physical=json.loads(one(selected,"/db-join-native-r1/summary.json")[1].read_bytes())
    differential=json.loads(one(selected,"/packer-differential-r1/summary.json")[1].read_bytes())
    assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_role_compiles"]==6 and build["packer_entries"]==33
    assert build["profile_frontiers"]["packer"]["profile"]["max_block_params"]==6
    assert differential["status"]=="PASS" and differential["cases"]==84
    assert differential["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
    assert physical["status"]=="INCOMPLETE"
    canonical=[]
    for role,row in sorted(build["compiled_roles"].items()):
        for kind in ("source","image"):
            original=row[kind];marker="/db-join-build-r1/"
            assert marker in original["path"]
            suffix=marker+original["path"].split(marker,1)[1]
            name,path=one(selected,suffix);identity=pin(path)
            assert identity["bytes"]==original["bytes"] and identity["sha256"]==original["sha256"]
            canonical.append(dict(role=role,kind=kind,member=name,identity=identity))
        receipt=row["compile_receipt"]
        assert receipt["source_sha256"]==row["source"]["sha256"] and receipt["produced_sha256"]==row["image"]["sha256"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert len(canonical)==12 and build["source_pins_unchanged"] is True
    packer_receipt=build["compile_receipt"]
    packer_name,packer_source=one(selected,"/db-join-build-r1/packer.hiaasm")
    assert pin(packer_source)["sha256"]==packer_receipt["source_sha256"]==packer_receipt["input_sha256"]
    packer_images=[(name,path) for name,path in selected.items()
        if "/db-join-build-r1/compile/namespace-db-join-packer/" in name and name.endswith(".image.bin")]
    assert len(packer_images)==1
    packer_image_name,packer_image=packer_images[0]
    assert pin(packer_image)["sha256"]==packer_receipt["produced_sha256"]==build["packer_image_sha256"]
    assert pin(packer_image)["bytes"]==packer_receipt["produced_bytes"]
    assert packer_receipt["artifact_sha256"]==packer_receipt["image_sha256"]==B3
    assert packer_receipt["limits"]["cpu_seconds"]==10 and packer_receipt["limits"]["address_bytes"]==256<<20
    canonical_packer=dict(source=dict(member=packer_name,identity=pin(packer_source)),
        image=dict(member=packer_image_name,identity=pin(packer_image)),compile_receipt=packer_receipt)
    producer_processes=[]
    for name,path in sorted(selected.items()):
        if not name.endswith(".json"):continue
        try:value=json.loads(path.read_bytes())
        except (ValueError,UnicodeError):continue
        if isinstance(value,dict) and value.get("label")=="six-role-actual-physical-and-complete-original-trace-replay":
            producer_processes.append(dict(member=name,identity=pin(path),original=value))
    # Other source copies remain indexed separately from exact role receipts.
    canonical_other=[dict(member=name,identity=pin(path)) for name,path in sorted(selected.items())
        if ("/db-join-build-r1/" in name and name.endswith((".hiaasm",".image.bin"))
            and name not in {row["member"] for row in canonical})]
    after={str(path):pin(path) for path in (archive,index,custody_path)};assert before==after
    report=dict(status="PASS_READBACK_ONLY",scope="FOLLOW35_PHYSICAL_FAILURE_ORIGINALS",
        model=PHYSICAL,seal=seal,principals=principals,originals_before=before,originals_after=after,
        original_qualification_status="FAIL",actual_physical_summary_status=physical["status"],
        original_full_physical_summary_keys=sorted(physical),
        completed_replay_reports=physical.get("replay"),actual_processes=process_rows,original_trace_frontiers=trace_rows,
        strace_frontiers=other_diagnostics,canonical_compiled_roles=canonical,canonical_packer=canonical_packer,canonical_other=canonical_other,
        producer_processes=producer_processes,
        actual_tests=physical.get("tests"),tests_completed_not_inferred=True,
        new_VM_entries=0,new_native_entries=0,new_B3_compiles=0,whole_store_closed=False)
    save(out/"summary.json",report)
    emit("physical35/readback-summary", (out/"summary.json").read_bytes())
    return report
def read_predecessor(root,out):
    """Recover the already-completed reader output, not rerun its native targets."""
    root=root.resolve(strict=True);out.mkdir()
    found={}
    for path in walk(root):
        if path.name=="summary.json" and path.parent.name in PREDECESSORS:
            raw=path.read_bytes()
            try:value=json.loads(raw)
            except (ValueError,UnicodeError):continue
            model=value.get("model")
            if isinstance(model,dict) and model.get("name")==path.parent.name and value.get("status")=="PASS_READBACK_ONLY":
                key=path.parent.name;assert key not in found;found[key]=(path,raw,value)
    assert set(found)==set(PREDECESSORS)
    reports={}
    for key,(path,raw,value) in sorted(found.items()):
        base=path.parent;index_path=base/"selected-originals.json";index_raw=index_path.read_bytes()
        exports=json.loads(index_raw)
        matches=[row for row in exports if row["name"]=="control/evidence-members.json"];assert len(matches)==1
        item=matches[0];safe_name(item["path"]);member_index=(base/item["path"]).read_bytes()
        assert len(member_index)==item["bytes"] and sha(member_index)==item["sha256"]
        model=PREDECESSORS[key];destination=out/key;destination.mkdir()
        seal,selected,expected=sealed_archive(base/"original-evidence.tar.xz",member_index,model,destination)
        (destination/"prior-reader-summary.json").write_bytes(raw);(destination/"prior-reader-exports.json").write_bytes(index_raw)
        # Preserve all prior selected diagnostics by original bytes plus exact index.
        for row in exports:
            safe_name(row["path"]);p=base/row["path"];b=p.read_bytes()
            assert len(b)==row["bytes"] and sha(b)==row["sha256"]
            dest=destination/"prior-reader-selected"/safe_name(row["path"]);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
        assert value["members"]==model["members"] and value["raw_bytes"]==model["raw_bytes"]
        assert value["all_member_bytes_modes_sha256_verified"] is True
        assert value["new_VM_entries"]==value["new_native_entries"]==value["new_B3_compiles"]==0
        assert value["producer_original_status"]=="FAIL"
        emit("prior-follow34-reader/"+key+"/complete-summary",raw)
        reports[key]=dict(status="PASS_READBACK_ONLY",prior_summary=pin(path),archive_seal=seal,
            prior_ledger_prefixes=value.get("ledger_prefixes"),original_qualification_status="FAIL")
    save(out/"summary.json",reports)
    return reports
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("readback wall180")));signal.alarm(180)
    started=time.monotonic_ns();cpu=time.process_time_ns()
    output=Path(os.environ["HIA_CI_OUTPUT"]).absolute();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    inputs={key:Path(os.environ[key]).resolve(strict=True) for key in
        ("HIA_NAMESPACE_PHYSICAL35_DIR","HIA_NAMESPACE_FOLLOW34_READBACK_DIR")}
    assert all(not output.is_relative_to(path) for path in inputs.values())
    report=dict(status="INCOMPLETE",new_native_entries=0,new_VM_entries=0,new_B3_compiles=0,results={})
    try:
        report["results"]["physical35"]=read_physical(inputs["HIA_NAMESPACE_PHYSICAL35_DIR"],output/"physical35")
        save(output/"summary.json",report)
        report["results"]["follow34_reader"]=read_predecessor(inputs["HIA_NAMESPACE_FOLLOW34_READBACK_DIR"],output/"prior-follow34")
        report["status"]="PASS_READBACK_ONLY"
    except BaseException as exc:
        report.update(status="FAIL_READBACK",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        signal.alarm(0)
        report.update(reader_elapsed_ns=time.monotonic_ns()-started,reader_cpu_ns=time.process_time_ns()-cpu)
        save(output/"summary.json",report)
        print("HIA_NAMESPACE_F35_READBACK_TERMINAL "+json.dumps({k:v for k,v in report.items() if k!="results"},sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
