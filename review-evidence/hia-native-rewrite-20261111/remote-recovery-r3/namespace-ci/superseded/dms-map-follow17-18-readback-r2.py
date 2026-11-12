"""Read the two exact DMS/SHM-map original artifacts without executing HIA.
The Actions download step owns outer ZIP download verification. This reader
replays every inner tar member, preserves modes and raw diagnostic bytes, and
counts every complete ledger line. It never reruns a test or changes a source.
"""
import sys
sys.dont_write_bytecode=True
import base64,gzip,hashlib,io,json,os,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
SPECS=[
 dict(label="dms-follow17",env="HIA_NAMESPACE_DMS_ARTIFACT_DIR",run=43129195254,artifact=13906529297,
      zip_bytes=50735063,zip_sha256="201e78b906158581f317ff1ed8ea38f0bf98400653a010bac31844534dc1553e",
      bytes=5979324,sha256="be6ff511cdf029a0ef5160d4d8b54f516ae6e3c89efaa566db161776b48620c5",
      index_bytes=34602,index_sha256="debf13f27d4458634f7fc33aedffa2ecfd2bc2bfe62e9f3cb603e6f1c7503b91",
      members=108,raw_bytes=45158182,status="FAIL",tests=28),
 dict(label="map-follow18",env="HIA_NAMESPACE_MAP_ARTIFACT_DIR",run=43130809110,artifact=13907333148,
      zip_bytes=49950331,zip_sha256="9af9b8fab981dbc563e40e951fcfede8069f832e75b3da1eccc9b0576664cc45",
      bytes=5884920,sha256="67ca9ca4ebfe1957eabd4ad524ab169d31460c0c7b05fbf33390eec1e4753d61",
      index_bytes=36217,index_sha256="075c30154c6fecdce1c223775170c67b4ea59d1e69d8dc7b05007198f5621430",
      members=110,raw_bytes=44236080,status="PASS",tests=24)]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
def read_regular(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);assert stat.S_ISREG(info.st_mode)
        with os.fdopen(os.dup(fd),"rb") as f:raw=f.read()
        after=os.fstat(fd)
        identity=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns,stat.S_IMODE(q.st_mode))
        assert identity(info)==identity(after) and len(raw)==info.st_size
        row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode),
                 dev=info.st_dev,inode=info.st_ino,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
        return raw,row
    finally:os.close(fd)
def safe_name(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and "." not in p.parts
    assert p.as_posix()==name and "\\" not in name
    return name
def emit_raw(label,name,raw,mode):
    row=dict(label=label,name=name,bytes=len(raw),sha256=sha(raw),mode=mode)
    print(json.dumps(dict(kind="namespace_raw_original",**row),sort_keys=True),flush=True)
    for at in range(0,len(raw),6144):
        print(json.dumps(dict(kind="namespace_raw_original_chunk",label=label,name=name,
            offset=at,total_bytes=len(raw),base64=base64.b64encode(raw[at:at+6144]).decode("ascii")),sort_keys=True),flush=True)
    return row
def clean_test(row,expected):
    assert row["tests_loaded"]==row["tests_run"]==len(row["test_ids"])==expected>0
    assert len(set(row["test_ids"]))==expected
    assert row["passed"] and not any(row[k] for k in
        ("failures","errors","skipped","expected_failures","unexpected_successes"))
def read_one(spec,out):
    root=Path(os.environ[spec["env"]]).resolve()
    assert root.is_dir()
    candidates=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:assert not Path(directory,name).is_symlink()
        for name in files:
            p=Path(directory,name);assert not p.is_symlink()
            if name=="evidence.tar.xz":candidates.append(p)
    assert len(candidates)==1,(spec["label"],"ambiguous inner archive",len(candidates))
    archive=candidates[0];index=archive.parent/"evidence-members.json";custody=archive.parent/"custody.json"
    a,ap=read_regular(archive);ix,ip=read_regular(index);cu,cp=read_regular(custody)
    assert (len(a),sha(a))==(spec["bytes"],spec["sha256"])
    assert (len(ix),sha(ix))==(spec["index_bytes"],spec["index_sha256"])
    original_custody=json.loads(cu);rows=json.loads(ix)
    assert original_custody["status"]==spec["status"]
    assert original_custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    for key,value in (("bytes",spec["bytes"]),("sha256",spec["sha256"]),("members",spec["members"]),
                      ("original_bytes",spec["raw_bytes"]),("member_index_bytes",spec["index_bytes"]),
                      ("member_index_sha256",spec["index_sha256"])):
        assert original_custody[key]==value,(key,original_custody.get(key),value)
    assert not original_custody["whole_stack_closed"]
    expected={}
    for row in rows:
        name=safe_name(row["name"]);assert name not in expected
        assert type(row["bytes"]) is int and row["bytes"]>=0 and type(row["mode"]) is int
        assert 0<=row["mode"]<=0o7777 and len(row["sha256"])==64
        expected[name]=row
    assert len(expected)==spec["members"] and sum(r["bytes"] for r in rows)==spec["raw_bytes"]
    checked=set();exports={};ledgers={}
    with tarfile.open(fileobj=io.BytesIO(a),mode="r:xz") as tf:
        for member in tf:
            name=safe_name(member.name)
            assert member.isfile() and not member.issym() and not member.islnk() and name not in checked
            row=expected[name];assert member.size==row["bytes"] and member.mode==row["mode"]
            with tf.extractfile(member) as f:raw=f.read()
            assert len(raw)==row["bytes"] and sha(raw)==row["sha256"],name
            checked.add(name)
            selected=(name=="run/summary.json" or
                ("/validation-r1/" in name and name.rsplit("/",1)[-1] in
                 ("result.json","vm.json","paired.json","vm.stdout.log","paired.stdout.log")) or
                name.endswith("/generation-r1/result.json") or
                (name.startswith("run/steps/") and name.rsplit("/",1)[-1] in ("stdout.log","stderr.log","process.json")))
            if selected:exports[name]=(raw,member.mode)
            if name.endswith("/validation-r1/invocations.jsonl.gz"):ledgers[name]=raw
    assert checked==set(expected) and len(ledgers)==1
    def one(suffix):
        names=[n for n in exports if n.endswith(suffix)];assert len(names)==1,(suffix,names)
        return json.loads(exports[names[0]][0])
    top=json.loads(exports["run/summary.json"][0])
    report=one("/validation-r1/result.json")
    assert top["status"]==report["status"]==spec["status"]
    assert top["frozen_source_and_reference_before_after_equal"] and top["submitted_script_pins_before_after_equal"]
    assert report["source_unchanged"] and report["source_before"]==report["source_after"]
    assert report["actual_physical_syscalls"]==0
    assert not report["whole_store_closed"] and not report["DMS_mapping_closed"] and not report["ordinary_AgentStore_closed"]
    counts=dict(vm=0,native=0,synthetic_kernel=0);roles={role:dict(vm=0,native=0) for role in report["entries_by_role"]};ledger_lines=0
    with gzip.GzipFile(fileobj=io.BytesIO(next(iter(ledgers.values()))),mode="rb") as stream:
        for line in stream:
            ledger_lines+=1;record=json.loads(line);phase=record["phase"]
            if phase in ("vm","paired_vm"):
                counts["vm"]+=1;role=record["role"];roles.setdefault(role,dict(vm=0,native=0))["vm"]+=1
            elif phase=="paired_native":
                counts["native"]+=1;role=record["role"];roles.setdefault(role,dict(vm=0,native=0))["native"]+=1
                assert record["source_unchanged"] and record["source_mapping_readonly"]
                assert record["guards"]==dict(input=True,output=True,workspace=True)
                assert record["expected_return"]==record["actual_return"]
                assert record["expected_output_hex"]==record["actual_output_hex"]
                assert record["expected_workspace_hex"]==record["actual_workspace_hex"]
            elif phase=="synthetic_kernel":
                counts["synthetic_kernel"]+=1;assert record["actual_syscalls_executed"]==0
            else:raise AssertionError(("unknown ledger phase",phase))
    assert counts["vm"]==report["vm_entries"] and counts["native"]==report["native_entries"]
    assert counts["synthetic_kernel"]==report["synthetic_kernel_acks"] and roles==report["entries_by_role"]
    if spec["status"]=="PASS":
        assert set(report["tests"])=={"vm","paired"}
        for row in report["tests"].values():clean_test(row,spec["tests"])
        assert counts["vm"]==2*counts["native"]>0 and counts["synthetic_kernel"]>0
        assert set(report["images"])==set(report["compile_receipts"])=={"map"}
        assert report["produced_images_unchanged"]=={"map":True}
        for receipt in report["compile_receipts"].values():
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["artifact_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    else:
        assert set(report["tests"])=={"vm"} and report["tests"]["vm"]["tests_run"]==spec["tests"]
        assert report["native_entries"]==0 and report["images"]==report["compile_receipts"]=={}
        assert not report["tests"]["vm"]["passed"]
    exports["control/evidence-members.json"]=(ix,ip["mode"])
    exports["control/custody.json"]=(cu,cp["mode"])
    export_rows=[]
    for name,(raw,mode) in sorted(exports.items()):
        target=out/"originals"/spec["label"]/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(mode)
        copied,pin=read_regular(target);assert copied==raw and pin["mode"]==mode
        export_rows.append(emit_raw(spec["label"],name,raw,mode))
    for name,raw in ledgers.items():
        target=out/"originals"/spec["label"]/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(expected[name]["mode"])
        assert target.read_bytes()==raw
    assert read_regular(archive)[1]==ap and read_regular(index)[1]==ip and read_regular(custody)[1]==cp
    observed=dict(status=report["status"],vm_entries=counts["vm"],native_entries=counts["native"],
        synthetic_kernel_acks=counts["synthetic_kernel"],actual_physical_syscalls=0,
        entries_by_role=roles,tests=report["tests"],ledger_lines=ledger_lines,
        images=report["images"],compile_receipts=report["compile_receipts"])
    result=dict(schema="hia-namespace-original-artifact-readback-v1",spec=spec,readback_status="PASS",
        authority_original_status=report["status"],all_inner_members_bytes_modes_sha256_verified=True,
        checked_members=len(checked),checked_bytes=sum(r["bytes"] for r in rows),
        outer_zip_locally_read=False,outer_zip_identity_source="GitHub artifact declaration and pinned Actions download step",
        before_after_controls_identical=True,controls=[ap,ip,cp],original_custody=original_custody,
        observed=observed,exports=export_rows,native_or_vm_executions_in_this_reader=0,whole_store_closed=False)
    save(out/(spec["label"]+".json"),result)
    print(json.dumps(dict(kind="namespace_observed_counts",label=spec["label"],observed=observed),sort_keys=True),flush=True)
    return result
def main():
    out=Path(os.environ["HIA_CI_OUTPUT"]);out.mkdir(parents=True,exist_ok=True)
    results=[];status="FAIL"
    try:
        for spec in SPECS:results.append(read_one(spec,out))
        status="PASS"
    except BaseException as error:
        save(out/"reader-error.json",dict(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc()))
        traceback.print_exc()
    finally:
        save(out/"readback-summary.json",dict(status=status,results=results,read_only_originals=True,
            native_or_vm_executions=0,original_dms_failure_preserved=True,whole_store_closed=False))
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
