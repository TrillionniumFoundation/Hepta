"""Read only the sealed c442 inode policy artifact; execute no HIA/test image."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,os,pathlib,resource,shutil,stat,tarfile,traceback

RUN=43113333444
ARTIFACT=13896704251
EXPECTED_INNER=(17993304,"fd17fddc5c8e54ccf33bc73e52396e0560f5f369aea0de32c1953067cfaf226c")
EXPECTED_INDEX=(288075,"7b71ec69df2e3022c55b86a40ea9899bd775c8abbabff678d8b925cd41af1b72")
MEMBERS=680
RAW_BYTES=59896581
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
SELECTED={
 "inode-generation-original.json":"run/namespace-inode-r2/generation-r1/result.json",
 "inode-protocol-original.json":"run/namespace-inode-r2/validation-r1/result.json",
 "inode-physical-original.json":"run/namespace-inode-r2/physical-r1/summary.json",
 "inode-context-original.json":"run/namespace-inode-r2/context.json",
 "inode-run-original.json":"run/summary.json",
}

def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    h=hashlib.sha256();size=0
    with path.open("rb") as source:
        while True:
            block=source.read(1<<20)
            if not block:break
            size+=len(block);h.update(block)
    assert size==info.st_size
    return dict(bytes=size,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def fixed_root():
    supplied=pathlib.Path(os.environ["HIA_NAMESPACE_INODE_READBACK_DIR"]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    name="hia-namespace-inode-recovery"
    wrapper="hia-namespace-inode-recovery-43113333444-1"
    candidates=[supplied/name,supplied/wrapper/name]
    if supplied.name==name:candidates.append(supplied)
    found=[]
    for candidate in candidates:
        if not (candidate/"evidence.tar.xz").exists():continue
        for p in [candidate,*candidate.parents]:
            if p==supplied.parent:break
            assert not p.is_symlink()
        found.append(candidate)
    assert len(found)==1,("ambiguous or missing fixed artifact layout",len(found))
    return found[0]

def main():
    assert sys.version_info[:3]==(3,12,14)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    root=fixed_root()
    out=pathlib.Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False)
    source_raw=pathlib.Path(__file__).read_bytes()
    (out/"readback-source.py").write_bytes(source_raw)
    report=dict(schema="hia.namespace-inode-independent-readback.v1",status="INCOMPLETE",
        run_id=RUN,artifact_id=ARTIFACT,head="c4424483c586a7f91f3311cae6107966cdcf4d4a",
        native_entries_executed_by_this_reader=0,vm_entries_executed_by_this_reader=0,
        tests_reexecuted_by_this_reader=0,ordinary_AgentStore_closed=False,
        original_ROG_full="FAIL/HOLD unchanged",
        compressed_zip_scope="GitHub artifact declaration/download action only; this reader verifies downloaded members and pinned inner archive, not ZIP bytes.",
        compressed_zip=dict(bytes=78427128,sha256="a03c3a386d3a0930c4d9684ceabec347e013cf7b43b6eb3a7e6f04b12f32e679"),
        script=dict(bytes=len(source_raw),sha256=digest(source_raw)))
    before={};checked=[];outer_before={};selected={}
    try:
        for name in ("evidence.tar.xz","evidence-members.json","custody.json"):
            before[name]=pin(root/name)
        assert (before["evidence.tar.xz"]["bytes"],before["evidence.tar.xz"]["sha256"])==EXPECTED_INNER
        assert (before["evidence-members.json"]["bytes"],before["evidence-members.json"]["sha256"])==EXPECTED_INDEX
        index=json.loads((root/"evidence-members.json").read_bytes())
        custody=json.loads((root/"custody.json").read_bytes())
        assert len(index)==MEMBERS and sum(r["bytes"] for r in index)==RAW_BYTES
        assert custody["status"]=="PASS" and custody["scope"]=="namespace-inode-policy-component"
        assert custody["members"]==MEMBERS and custody["original_bytes"]==RAW_BYTES
        assert (custody["bytes"],custody["sha256"])==EXPECTED_INNER
        assert (custody["member_index_bytes"],custody["member_index_sha256"])==EXPECTED_INDEX
        assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        expected={}
        for row in index:
            rel=pathlib.PurePosixPath(row["name"])
            assert not rel.is_absolute() and rel.parts and rel.parts[0]=="run"
            assert ".." not in rel.parts and "." not in rel.parts and rel.as_posix()==row["name"]
            assert row["name"] not in expected
            assert type(row["bytes"]) is int and row["bytes"]>=0
            assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
            expected[row["name"]]=row
        wanted=set(SELECTED.values());seen=set()
        with tarfile.open(root/"evidence.tar.xz","r:xz") as archive:
            for item in archive:
                assert item.isfile() and not item.issym() and not item.islnk()
                assert item.name in expected and item.name not in seen
                row=expected[item.name]
                assert item.size==row["bytes"] and item.mode==row["mode"]
                stream=archive.extractfile(item);assert stream is not None
                raw=stream.read()
                assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
                rel=pathlib.PurePosixPath(item.name)
                outer=root.joinpath(*rel.parts[1:])
                for p in [outer,*outer.parents]:
                    assert not p.is_symlink()
                    if p==root:break
                observed=pin(outer)
                assert (observed["bytes"],observed["sha256"])==(row["bytes"],row["sha256"])
                outer_before[str(outer)]=observed
                checked.append(dict(name=item.name,bytes=len(raw),sha256=digest(raw),
                    tar_mode=item.mode,download_mode=observed["mode"]))
                if item.name in wanted:selected[item.name]=raw
                seen.add(item.name)
        assert seen==set(expected) and set(selected)==wanted and len(checked)==MEMBERS
        save(out/"independent-member-readback.json",checked)
        for filename,member in SELECTED.items():
            (out/filename).write_bytes(selected[member])
            assert (out/filename).read_bytes()==selected[member]
        generation=json.loads(selected[SELECTED["inode-generation-original.json"]])
        protocol=json.loads(selected[SELECTED["inode-protocol-original.json"]])
        physical=json.loads(selected[SELECTED["inode-physical-original.json"]])
        context=json.loads(selected[SELECTED["inode-context-original.json"]])
        top=json.loads(selected[SELECTED["inode-run-original.json"]])
        assert top["status"]=="PASS" and top["scope"]=="namespace-inode-policy-component"
        assert top["frozen_source_and_reference_before_after_equal"] is True
        assert top["submitted_script_pins_before_after_equal"] is True
        assert top["whole_stack_closed"] is False
        assert generation["status"]=="GENERATED" and generation["source_unchanged"]
        assert generation["source_before"]==generation["source_after"]
        profile=generation["profile"]
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_block_params"]<=16
        generator_rows=[row for path,row in generation["source_before"].items()
                        if pathlib.Path(path).name=="generate_hia_agent_namespace_inode.py"]
        assert len(generator_rows)==1 and generator_rows[0]["sha256"]=="3c51180bb529f8913b8b19ba7693406ad43b1cd860f776384dd2ec2dfeb943a7"
        assert protocol["status"]=="PASS" and protocol["source_unchanged"]
        assert protocol["source_before"]==protocol["source_after"] and protocol["produced_image_before_after_equal"] is True
        assert protocol["source_sha256"]==generation["generated"]["sha256"]
        receipt=protocol["compile_receipt"]
        assert receipt["source_sha256"]==receipt["input_sha256"]==protocol["source_sha256"]
        assert receipt["artifact_sha256"]==B3 and receipt["limits"]["cpu_seconds"]==10
        assert receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["produced_sha256"]==protocol["image"]["sha256"]
        assert receipt["produced_bytes"]==protocol["image"]["bytes"]
        assert set(protocol["tests"])=={"vm","paired"}
        def clean_tests(tests,count):
            assert tests["passed"] and 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==count
            assert len(set(tests["test_ids"]))==count
            assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        for row in protocol["tests"].values():clean_tests(row,18)
        assert protocol["vm_entries"]>=protocol["native_entries"]>0
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        assert physical["source_before"]==physical["source_after"]
        clean_tests(physical["tests"],9)
        assert physical["native_inode_entries"]==physical["vm_inode_entries"]>0
        assert len(physical["fs_replays"])==10 and all(r["status"]=="PASS" for r in physical["fs_replays"])
        assert physical["fs_native_entries"]==physical["fs_vm_entries"]>0
        assert sum(r["native_entries"] for r in physical["fs_replays"])==physical["fs_native_entries"]
        assert sum(r["vm_entries"] for r in physical["fs_replays"])==physical["fs_vm_entries"]
        assert sum(r["actual_primitive_acks"] for r in physical["fs_replays"])==physical["fs_actual_primitive_acks"]>0
        assert physical["actual_provider_commands"]>0
        for key in ("deferred_alias_preserves_lock_and_lifo","shared_holder_reference_counts",
                    "local_conflict_and_inode_separation","actual_foreign_busy_and_release",
                    "actual_sqlite_wal_writer_both_directions","two_actual_sessions_contend","actual_ebadf_maps_busy",
                    "deliberate_unknown_after_real_reply_poisoned","unknown_control_is_not_claimed_actual_lost_syscall",
                    "actual_dynamic_inode_growth"):
            assert physical["observations"][key] is True
        assert not physical["fixed_namespace_coordinator_closed"] and not physical["ordinary_store_closed"]
        assert not physical["migration_closed"] and not physical["prior_kernel_carrier_counts_inherited"]
        assert physical["private_python_router_is_development_only"] is True
        original_output=pathlib.Path(context["output"])
        relative=pathlib.Path(protocol["image"]["path"]).relative_to(original_output)
        image_row=expected["run/"+relative.as_posix()]
        assert (image_row["bytes"],image_row["sha256"],image_row["mode"])==(
            protocol["image"]["bytes"],protocol["image"]["sha256"],protocol["image"]["mode"])
        request_path="run/namespace-inode-r2/validation-r1/compile/namespace-inode-r2.request.json"
        assert request_path in expected
        # Its complete bytes were already verified above. Re-read the downloaded
        # regular member to inspect the exact original output/workspace limits.
        request=json.loads(root.joinpath(*pathlib.PurePosixPath(request_path).parts[1:]).read_bytes())
        assert request["capacity"]==request["workspace_size"]==1<<20
        summaries={}
        for filename in ("inode-generation-original.json","inode-protocol-original.json","inode-physical-original.json"):
            raw=(out/filename).read_bytes();summaries[filename]=dict(bytes=len(raw),sha256=digest(raw))
        for name in ("evidence.tar.xz","evidence-members.json","custody.json"):
            shutil.copyfile(root/name,out/("original-"+name))
            copied=pin(out/("original-"+name))
            assert (copied["bytes"],copied["sha256"])==(before[name]["bytes"],before[name]["sha256"])
        report.update(status="PASS",members_replayed=MEMBERS,raw_bytes_replayed=RAW_BYTES,
            original_summary_files=summaries,artifact_test_observations=dict(
                protocol_tests={k:{"test_ids":v["test_ids"],"tests_run":v["tests_run"]} for k,v in protocol["tests"].items()},
                protocol_native_entries=protocol["native_entries"],protocol_vm_entries=protocol["vm_entries"],
                physical_tests=physical["tests"],physical_inode_native_entries=physical["native_inode_entries"],
                physical_inode_vm_entries=physical["vm_inode_entries"],physical_FS_native_entries=physical["fs_native_entries"],
                physical_FS_vm_entries=physical["fs_vm_entries"],actual_FS_acks=physical["fs_actual_primitive_acks"],
                process_traces=len(physical["fs_replays"]),actual_provider_commands=physical["actual_provider_commands"],
                sqlite=physical["sqlite"],observations=physical["observations"],image=protocol["image"],profile=profile),
            provenance_boundary="Actual issued FS provider plus private Python test router; fixed native coordinator and ordinary namespace are still open.")
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        (out/"failure.traceback.txt").write_text(traceback.format_exc())
        traceback.print_exc()
    finally:
        after={}
        after_errors=[]
        for name in before:
            try:after[name]=pin(root/name)
            except BaseException as error:after_errors.append(dict(path=name,error=repr(error)))
        drift=[]
        for path,row in outer_before.items():
            try:
                now=pin(pathlib.Path(path))
                if now!=row:drift.append(dict(path=path,before=row,after=now))
            except BaseException as error:drift.append(dict(path=path,error=repr(error)))
        report.update(original_seal_before=before,original_seal_after=after,after_errors=after_errors,
            downloaded_member_drift=drift,original_seal_unchanged=bool(before) and before==after and not after_errors,
            downloaded_members_unchanged=not drift,reader_source_unchanged=pathlib.Path(__file__).read_bytes()==source_raw)
        if not report["original_seal_unchanged"] or drift or not report["reader_source_unchanged"]:report["status"]="FAIL"
        save(out/"readback.json",report)
        print(json.dumps(report,sort_keys=True),flush=True)
        for filename in ("inode-generation-original.json","inode-protocol-original.json","inode-physical-original.json"):
            path=out/filename
            if path.exists():
                raw=path.read_bytes()
                print("BEGIN_ORIGINAL_JSON "+filename+" "+str(len(raw))+" "+digest(raw),flush=True)
                sys.stdout.write(raw.decode("utf-8"));sys.stdout.flush()
                print("END_ORIGINAL_JSON "+filename,flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
