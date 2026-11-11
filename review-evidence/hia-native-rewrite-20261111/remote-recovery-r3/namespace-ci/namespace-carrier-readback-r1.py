"""Read only the sealed 408 namespace carrier artifact; execute no HIA/test image."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,os,pathlib,resource,shutil,stat,tarfile,traceback

RUN=43105934854
ARTIFACT=13893997012
EXPECTED_INNER=(11695096,"497b7f8fb97085e6c20953180d05afacd0846f0f30eed2111196cc3f17108ccf")
EXPECTED_INDEX=(258697,"5f9cf8136f94a70adbdb463c0cc638dda64bbd170c20d6037074fc9f0e46da68")
MEMBERS=616
RAW_BYTES=54360446
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
SELECTED={
 "carrier-build-original.json":"run/namespace-fixed-carrier/carrier-build-r1/summary.json",
 "carrier-native-original.json":"run/namespace-fixed-carrier/carrier-native-r1/summary.json",
 "carrier-context-original.json":"run/namespace-fixed-carrier/context.json",
 "carrier-run-original.json":"run/summary.json",
 "prior-597-original.json":"run/namespace-fixed-carrier/predecessor-597/original-validation-result.json",
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
    supplied=pathlib.Path(os.environ["HIA_NAMESPACE_CARRIER_READBACK_DIR"]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    name="hia-namespace-carrier-recovery"
    wrapper="hia-namespace-carrier-recovery-43105934854-1"
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
    report=dict(schema="hia.namespace-carrier-independent-readback.v1",status="INCOMPLETE",
        run_id=RUN,artifact_id=ARTIFACT,head="408c130d129992b7d1ef31d3e1e625b1c56af422",
        native_entries_executed_by_this_reader=0,vm_entries_executed_by_this_reader=0,
        tests_reexecuted_by_this_reader=0,ordinary_AgentStore_closed=False,
        original_ROG_full="FAIL/HOLD unchanged",
        compressed_zip_scope="GitHub artifact declaration/download action only; this reader verifies downloaded members and pinned inner archive, not ZIP bytes.",
        compressed_zip=dict(bytes=66539778,sha256="ba4cdad194fb9a6cccf0cbed20250c32513746bde155502c8d999f56cd54fae8"),
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
        assert custody["status"]=="PASS" and custody["scope"]=="namespace-filesystem-fixed-carrier-component"
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
        build=json.loads(selected[SELECTED["carrier-build-original.json"]])
        native=json.loads(selected[SELECTED["carrier-native-original.json"]])
        context=json.loads(selected[SELECTED["carrier-context-original.json"]])
        top=json.loads(selected[SELECTED["carrier-run-original.json"]])
        prior=json.loads(selected[SELECTED["prior-597-original.json"]])
        assert top["status"]=="PASS" and top["scope"]=="namespace-filesystem-fixed-carrier-component"
        assert top["frozen_source_and_reference_before_after_equal"] is True
        assert top["submitted_script_pins_before_after_equal"] is True
        assert top["whole_stack_closed"] is False
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"] is True
        assert build["source_before"]==build["source_after"]
        assert build["packer_entries"]==len(build["packer_controls"])==8
        assert build["actual_carrier_processes"]==0
        assert all(r["exact_output_equal"] and r["source_unchanged"] and r["workspace_unchanged"] and r["guards"]
                   and r["actual_return"]==r["expected_return"] for r in build["packer_controls"])
        assert build["compile_receipt"]["limits"]["cpu_seconds"]==10
        assert build["compile_receipt"]["limits"]["address_bytes"]==256<<20
        assert build["compile_receipt"]["artifact_sha256"]==B3
        assert native["status"]=="PASS" and native["source_pins_unchanged"] is True
        assert native["source_before"]==native["source_after"]
        tests=native["tests"]
        assert 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==10
        assert len(set(tests["test_ids"]))==10
        assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert native["native_entries"]==native["vm_entries"]>0
        assert native["process_traces_replayed"]==len(native["replay"])>0
        assert all(r["status"]=="PASS" for r in native["replay"])
        assert sum(r["native_entries"] for r in native["replay"])==native["native_entries"]
        assert sum(r["vm_entries"] for r in native["replay"])==native["vm_entries"]
        assert sum(r["actual_primitive_acks"] for r in native["replay"])==native["actual_primitive_acks"]>0
        for key in ("all22_actual_primitives","actual_raw_fd_zero","truncated_transport_process_lock_released",
                    "actual_wal_byte120_both_directions","actual_alias_close_drops_lock","parent_death_child_termination"):
            assert native["observations"][key] is True
        assert not native["physical_store_closed"] and not native["migration_closed"] and not native["public_root_policy_closed"]
        original_output=pathlib.Path(context["output"])
        relative=pathlib.Path(build["executable"]["path"]).relative_to(original_output)
        elf_row=expected["run/"+relative.as_posix()]
        assert (elf_row["bytes"],elf_row["sha256"],elf_row["mode"])==(build["executable"]["bytes"],build["executable"]["sha256"],0o755)
        assert prior["status"]=="PASS" and prior["native_entries"]==519 and prior["vm_entries"]==1038
        assert digest(selected[SELECTED["prior-597-original.json"]])=="bad895907fc8f3432849078389b4c00270548bf6f9aeb1860535798f00240b95"
        summaries={}
        for filename in ("carrier-build-original.json","carrier-native-original.json"):
            raw=(out/filename).read_bytes()
            summaries[filename]=dict(bytes=len(raw),sha256=digest(raw))
        for name in ("evidence.tar.xz","evidence-members.json","custody.json"):
            shutil.copyfile(root/name,out/("original-"+name))
            copied=pin(out/("original-"+name))
            assert (copied["bytes"],copied["sha256"])==(before[name]["bytes"],before[name]["sha256"])
        report.update(status="PASS",members_replayed=MEMBERS,raw_bytes_replayed=RAW_BYTES,
            original_summary_files=summaries,artifact_test_observations=dict(
                packer_entries=8,tests=tests,native_entries=native["native_entries"],vm_replay_entries=native["vm_entries"],
                actual_primitive_acks=native["actual_primitive_acks"],process_traces=native["process_traces_replayed"],
                sqlite=native["sqlite"],observations=native["observations"],executable=build["executable"]),
            predecessor_observations=dict(native_entries=519,vm_entries=1038,inherited_as_new=False))
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
        for filename in ("carrier-build-original.json","carrier-native-original.json"):
            path=out/filename
            if path.exists():
                raw=path.read_bytes()
                print("BEGIN_ORIGINAL_JSON "+filename+" "+str(len(raw))+" "+digest(raw),flush=True)
                sys.stdout.write(raw.decode("utf-8"));sys.stdout.flush()
                print("END_ORIGINAL_JSON "+filename,flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
