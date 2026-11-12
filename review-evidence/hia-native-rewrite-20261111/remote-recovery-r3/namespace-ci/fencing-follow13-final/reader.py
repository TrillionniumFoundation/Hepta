"""Read the exact follow13 fencing artifact; no test, compiler or native execution."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,os,shutil,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
RUN=43121313060
JOB=130862204691
ARTIFACT=13900534166
HEAD="6c2e4763371bc079d14779cf3880e61c50b08188"
OUTPUT_NAME="hia-namespace-fencing-recovery"
WRAPPER="hia-namespace-fencing-recovery-43121313060-1"
SEALS={
 "evidence.tar.xz":(44842508,"9633775fd2fa0405eeda29c25b089aafb2222bfa3ddc16d8e241dabf7295c3dd"),
 "evidence-members.json":(320660,"13f653feaa1357b512e8e035fcf4e47dfa310b2649bf3c3c73a10fd319b28482"),
 "custody.json":(585,"f6ca912f552268e6fb8d680d81c1df20a7591af5fa897a0dbd35d1a7c6d1364b")}
SOURCES=[{"name":"namespace-fencing-r2-generator.py","bytes":23333,"sha256":"9814243708821565cac54d09a0911118534fcd945eac62ccd9df96cd6f58d509","blob":"65df8a50f30ab5574c36d5fedaab91d78939f64c"},{"name":"namespace-fencing-r2-protocol.py","bytes":15890,"sha256":"9a3aa2135d3d2d29217f0f6847b8542c9ee9a3af25ad6e2ee6d7075f2cb4fd00","blob":"79850e57b62f8edc5755388065c31c75311bd985"},{"name":"namespace-fencing-r2-validate.py","bytes":13866,"sha256":"402a8bead3ba00a1398864f55a2a29fa42e958f95fbcf451f01e4fe2a5d05f4f","blob":"f5799794fd0d8fa42afe003bcfcc905e9b6d9306"},{"name":"namespace-fencing-r2-executor.S","bytes":26882,"sha256":"61337d78257e1a4c468b629e81eb0a499233ff9d14e19b6b9eee9d07ea4965ab","blob":"ff2293f024374c7f4fa6352587b1246cba979839"},{"name":"namespace-fencing-r2-packer.py","bytes":4846,"sha256":"3903b0b640fa8970a892a5065f960b7b03e2e7d83b59dda01228262340c7a906","blob":"4ebd06ced997b0a39f4ce315372e260c998b6abb"},{"name":"namespace-fencing-r2-build.py","bytes":18246,"sha256":"5e80de4423811f42c5374541ed802e345e450e96dfaf731aee479e3b371aba99","blob":"2d559a1c7fba20072aea7ae52b72508a5fc8ce1c"},{"name":"namespace-fencing-r2-client.py","bytes":11264,"sha256":"666936f0f00b7ce0758005c50ad49bf344bd24839989f5942ee19d7b41119362","blob":"c05a39acab04c4884d41c8654ee08bc2358d9959"},{"name":"namespace-fencing-r2-replay.py","bytes":11268,"sha256":"9f7c2bf8ffa4c666ecae9b784161fdff55b3844971f4397dec517056797d60c2","blob":"78fc0b42b0a742c90193a949a474e5870a832286"},{"name":"namespace-fencing-r2-physical.py","bytes":27621,"sha256":"0fa5df850577a38b543a290f7528a2d35222955ce8a08d3722f4ba8142fe65a1","blob":"917507331f4904f0072c7d0d0e9e27e99a4668a7"},{"name":"namespace-fencing-r2-abi.json","bytes":8641,"sha256":"a3bfbf46ed3690bd8b706d039423383a924ebe8a68f22d89f199078ce0b6ed92","blob":"8ff0b24863315333502abf8368361f38a383e2bb"},{"name":"namespace-fencing-r2-ci.py","bytes":26290,"sha256":"8113f15231aa9ccb7d49758f2190591f5cca6888927c25dccc3e3822f6225fb3","blob":"5be0703eac623eeb0f91d700029b9d63b3e991ff"}]
JSONS={
 "generation":"run/namespace-fencing-r2/generation-r1/result.json",
 "protocol":"run/namespace-fencing-r2/validation-r1/result.json",
 "build":"run/namespace-fencing-r2/carrier-build-r1/summary.json",
 "physical":"run/namespace-fencing-r2/carrier-native-r1/summary.json",
 "qualification":"run/summary.json"}
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path);info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def clean(value,count,passed=False):
    assert 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==count
    assert len(set(value["test_ids"]))==count
    assert not any(value[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    if passed:assert value["passed"] is True
def root_path():
    supplied=Path(os.environ["HIA_NAMESPACE_FENCING_READBACK_DIR"]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    possible=[supplied/OUTPUT_NAME,supplied/WRAPPER/OUTPUT_NAME]
    if supplied.name==OUTPUT_NAME:possible.append(supplied)
    found=[]
    for p in possible:
        if not (p/"evidence.tar.xz").exists():continue
        for q in [p,*p.parents]:
            if q==supplied.parent:break
            assert not q.is_symlink()
        found.append(p)
    assert len(found)==1,("original artifact missing/ambiguous",len(found))
    return found[0]
def main():
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    out.mkdir(parents=True,exist_ok=False)
    script=pin(__file__);(out/"reader.py").write_bytes(Path(__file__).read_bytes())
    before={};after={};downloads={};json_raw={};selected={};checked=[];status="FAIL"
    report=dict(schema="hia-fencing-independent-readback-v1",status="INCOMPLETE",
        run_id=RUN,job_id=JOB,artifact_id=ARTIFACT,head=HEAD,script=script,
        compressed_zip=dict(bytes=161441188,sha256="92d12654a95d85d8154d12d82ef78067174bfc6d7abd7280510172b2ee9955c8"),
        compressed_zip_scope="GitHub upload/download-action digest declaration; this reader does not read the outer compressed ZIP.",
        native_entries_executed_by_this_reader=0,vm_entries_executed_by_this_reader=0,
        tests_reexecuted_by_this_reader=0,ordinary_AgentStore_closed=False,
        DMS_lifetime_closed=False,migration_closed=False,original_ROG_full="FAIL/HOLD unchanged")
    root=None
    try:
        root=root_path()
        for name,wanted in SEALS.items():
            row=pin(root/name);assert (row["bytes"],row["sha256"])==wanted
            before[name]=row
            shutil.copyfile(root/name,out/name)
            copy=pin(out/name);assert (copy["bytes"],copy["sha256"])==wanted
        index=json.loads((root/"evidence-members.json").read_bytes())
        custody=json.loads((root/"custody.json").read_bytes())
        assert len(index)==771 and sum(r["bytes"] for r in index)==116000336
        assert custody["scope"]=="namespace-fixed-fencing-component" and custody["status"]=="PASS"
        assert custody["members"]==771 and custody["original_bytes"]==116000336
        assert custody["bytes"]==SEALS["evidence.tar.xz"][0] and custody["sha256"]==SEALS["evidence.tar.xz"][1]
        assert custody["member_index_bytes"]==SEALS["evidence-members.json"][0]
        assert custody["member_index_sha256"]==SEALS["evidence-members.json"][1]
        assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] and not custody["whole_stack_closed"]
        expected={}
        for row in index:
            p=PurePosixPath(row["name"])
            assert p.parts and p.parts[0]=="run" and not p.is_absolute() and ".." not in p.parts and "." not in p.parts
            assert p.as_posix()==row["name"] and row["name"] not in expected
            assert type(row["bytes"]) is int and row["bytes"]>=0
            assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
            expected[row["name"]]=row
        wanted_sources={"run/namespace-fencing-r2/source/"+r["name"]:r for r in SOURCES}
        source_seen=set();seen=set();fixture_custody={};special={}
        with tarfile.open(root/"evidence.tar.xz","r:xz") as archive:
            for item in archive:
                assert item.isfile() and not item.issym() and not item.islnk()
                assert item.name in expected and item.name not in seen
                row=expected[item.name]
                assert (item.size,item.mode)==(row["bytes"],row["mode"])
                stream=archive.extractfile(item);assert stream is not None;raw=stream.read()
                assert (len(raw),sha(raw))==(row["bytes"],row["sha256"])
                rel=PurePosixPath(item.name);actual=root.joinpath(*rel.parts[1:])
                for p in [actual,*actual.parents]:
                    assert not p.is_symlink()
                    if p==root:break
                actual_pin=pin(actual)
                assert (actual_pin["bytes"],actual_pin["sha256"])==(row["bytes"],row["sha256"])
                downloads[item.name]=dict(path=str(actual),**actual_pin)
                checked.append(dict(name=item.name,bytes=len(raw),sha256=sha(raw),tar_mode=item.mode,download_mode=actual_pin["mode"]))
                if item.name in wanted_sources:
                    wanted=wanted_sources[item.name]
                    assert (len(raw),sha(raw),item.mode)==(wanted["bytes"],wanted["sha256"],0o644)
                    source_seen.add(item.name)
                for label,name in JSONS.items():
                    if item.name==name:json_raw[label]=raw
                if item.name.endswith("/fixture-custody.json"):
                    fixture_custody[item.name]=json.loads(raw)
                if item.name.endswith("/strace.log") or item.name.endswith("/death-observation.json"):
                    special[item.name]=raw
                seen.add(item.name)
        assert seen==set(expected) and source_seen==set(wanted_sources) and set(json_raw)==set(JSONS)
        save(out/"member-readback.json",checked)
        for label,raw in json_raw.items():
            target=out/(label+"-original.json");target.write_bytes(raw)
            assert target.read_bytes()==raw
            selected[label]=dict(bytes=len(raw),sha256=sha(raw),path=str(target),member=JSONS[label])
        gen=json.loads(json_raw["generation"]);protocol=json.loads(json_raw["protocol"])
        build=json.loads(json_raw["build"]);physical=json.loads(json_raw["physical"])
        final=json.loads(json_raw["qualification"])
        assert gen["status"]=="GENERATED" and gen["source_unchanged"] and gen["source_before"]==gen["source_after"]
        assert protocol["status"]=="PASS" and protocol["source_unchanged"] and protocol["source_before"]==protocol["source_after"]
        assert protocol["produced_image_before_after_equal"] and protocol["source_sha256"]==gen["generated"]["sha256"]
        assert set(protocol["tests"])=={"vm","paired"}
        for row in protocol["tests"].values():clean(row,16,True)
        assert protocol["vm_entries"]>0 and protocol["native_entries"]>0
        receipt=protocol["compile_receipt"]
        assert receipt["artifact_sha256"]==B3 and receipt["input_sha256"]==receipt["source_sha256"]==protocol["source_sha256"]
        assert receipt["produced_sha256"]==protocol["image"]["sha256"] and receipt["produced_bytes"]==protocol["image"]["bytes"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"] and build["source_before"]==build["source_after"]
        assert build["packer_entries"]==len(build["packer_controls"])==14 and build["actual_carrier_processes"]==0
        assert build["coordinator_source_sha256"]==protocol["source_sha256"] and build["coordinator_image_sha256"]==protocol["image"]["sha256"]
        for row in build["packer_controls"]:
            assert row["actual_return"]==row["expected_return"] and row["exact_output_equal"]
            assert row["source_unchanged"] and row["workspace_unchanged"] and row["guards"]
        assert set(build["exact_roles"])=={"1","2","3"}
        peer_expected={"1":("31d1edeb1ce78271be610eaf486cfb16e19d5f08e512066b3ca55416becca0e2","c90d3b239420b28d4e07f505913669371e14a8cb1b8306523942e1287c54d133"),
                       "2":("ea3e6ba9ad56f677cf41f927ee968cf54dd33fc000744151b2fed6e31b53a066","c8fa89d7e3f0112a3efb2dbedd4c9c0be3332544675523108e41daf75efee1e8"),
                       "3":(protocol["source_sha256"],protocol["image"]["sha256"])}
        def present(size,digest,mode=None):
            rows=[r for r in expected.values() if r["bytes"]==size and r["sha256"]==digest and (mode is None or r["mode"]==mode)]
            assert rows,(size,digest,mode)
            return [r["name"] for r in rows]
        for role,row in build["exact_roles"].items():
            for index,key in enumerate(("source","image")):
                assert row[key]["sha256"]==peer_expected[role][index]
                present(row[key]["bytes"],row[key]["sha256"],0o644)
        present(protocol["image"]["bytes"],protocol["image"]["sha256"],0o644)
        present(gen["generated"]["bytes"],gen["generated"]["sha256"],0o644)
        present(669556,B3,0o644)
        present(build["executable"]["bytes"],build["executable"]["sha256"],0o755)
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"] and physical["source_before"]==physical["source_after"]
        clean(physical["tests"],12)
        assert physical["native_entries"]==physical["vm_entries"]>0 and physical["actual_primitive_acks"]>0
        assert physical["process_traces"]==len(physical["replay"])>0
        assert set(physical["entries_by_role"])=={"1","2","3"}
        assert all(v>0 for v in physical["entries_by_role"].values())
        operations={};growth={str(k):0 for k in (1,2,3)};fatal=[];signals=0
        for row in physical["replay"]:
            assert row["status"]=="PASS" and row["native_entries"]==row["vm_entries"]>0
            assert row["all_return_output_workspace_bytes_equal"] and row["no_field_masks"]
            assert row["all_child_replies_bound_to_actual_original_source_output_workspace"] and row["no_primitive_executed_by_replayer"]
            present(row["trace_bytes"],row["trace_sha256"])
            present(row["ledger_bytes"],row["ledger_sha256"])
            for key,value in row["primitive_operation_counts"].items():operations[key]=operations.get(key,0)+value
            for key,value in row["growth_by_role"].items():growth[key]+=value
            fatal.extend(row["fatal_records"]);signals+=int(row["explicit_signal_termination"])
        assert physical["native_entries"]==sum(r["native_entries"] for r in physical["replay"])
        assert physical["vm_entries"]==sum(r["vm_entries"] for r in physical["replay"])
        assert physical["actual_primitive_acks"]==sum(r["actual_primitive_acks"] for r in physical["replay"])==sum(operations.values())
        assert physical["actual_child_reply_links"]==sum(len(r["exact_completed_child_links"]) for r in physical["replay"])
        for role,count in physical["entries_by_role"].items():assert count==sum(r["entries_by_role"][role] for r in physical["replay"])
        for key in ("actual_fs_inode_coordinator_chain","actual_raw_fd_zero","no_writable_executable_maps",
            "actual_deferred_alias_lifo_preserves_process_lock","actual_shared_refcount","actual_foreign_busy_then_success",
            "local_busy_has_no_syscall","two_actual_native_sessions","actual_sqlite_writer_bidirectional",
            "actual_dynamic_all_three_growth","external_bytes_cannot_issue_child_channel","transport_failure_releases_actual_locks",
            "actual_injected_stat_orphan_preserves_held_lock","actual_injected_close_error_not_retried","actual_parent_death_unlock"):
            assert physical["observations"][key] is True
        assert not any(physical[k] for k in ("ordinary_store_closed","root_policy_closed","DMS_lifetime_closed","migration_closed","python_router_used"))
        assert len(fixture_custody)==12
        cas_count=0;fixture_records=0
        for name,row in fixture_custody.items():
            assert row["status"]=="COMPLETE_CONTENT_AND_MODE_SNAPSHOT_LIVE_INODES_RETAINED"
            assert row["original_bytes_modes_inode_links_verified_after_relocation"]
            for item in row["members"]:
                fixture_records+=1
                if item["type"]==stat.S_IFREG:
                    key="run/namespace-fencing-r2/carrier-native-r1/cas/"+item["sha256"]
                    assert key in expected
                    assert expected[key]["bytes"]==item["content_bytes"] and expected[key]["sha256"]==item["sha256"]
                    assert type(item["mode"]) is int and 0<=item["mode"]<=0o7777
                    cas_count+=1
        for test,words in (("test_10_actual_injected_stat_failure_defers_orphan_close_under_lock",("INJECTED","EBADF")),
                           ("test_11_actual_injected_close_error_is_consumed_once",("INJECTED","EBADF","EINTR"))):
            key="run/namespace-fencing-r2/carrier-native-r1/"+test+"/strace.log"
            raw=special[key]
            assert all(word.encode() in raw for word in words)
        death_key="run/namespace-fencing-r2/carrier-native-r1/test_12_parent_death_terminates_native_child_and_releases_lock/death-observation.json"
        death=json.loads(special[death_key])
        assert death["status"]=="OWNED_CHILD_DEATH_AND_UNLOCK_OBSERVED"
        assert death["parent_returncode"]==-9 and death["native_exit_code"]=="NOT_READ_NOT_OUR_CHILD"
        assert death["pidfd_events"] and signals==1
        assert len(fatal)==1 and fatal[0]["code"]==111
        assert final["status"]=="PASS" and final["scope"]=="namespace-fixed-fencing-component"
        assert final["frozen_source_and_reference_before_after_equal"] and final["submitted_script_pins_before_after_equal"]
        assert not final["whole_stack_closed"] and not final["production_activated"] and not final["inherited_test_counts"]
        details=final["details"]
        assert details["inputs_unchanged"] and details["working_source_unchanged"] and details["status"]=="PASS"
        assert details["new_protocol_validation"]==protocol and details["new_fixed_build"]==build and details["new_actual_physical"]==physical
        assert details["new_protocol_native_entries"]==protocol["native_entries"] and details["new_protocol_vm_entries"]==protocol["vm_entries"]
        assert details["new_physical_native_entries"]==physical["native_entries"] and details["new_physical_vm_entries"]==physical["vm_entries"]
        assert details["new_actual_acks"]==physical["actual_primitive_acks"] and details["new_actual_child_reply_links"]==physical["actual_child_reply_links"]
        report.update(status="PASS",members_replayed=771,raw_bytes_replayed=116000336,
            original_summary_files=selected,original_source_files_checked=len(source_seen),
            artifact_test_observations=dict(
                generation_profile=gen["profile"],coordinator_source=gen["generated"],coordinator_image=protocol["image"],
                protocol_tests=protocol["tests"],protocol_vm_entries=protocol["vm_entries"],protocol_native_entries=protocol["native_entries"],
                actual_packer_entries=build["packer_entries"],executable=build["executable"],
                physical_tests=physical["tests"],physical_native_entries=physical["native_entries"],physical_vm_entries=physical["vm_entries"],
                actual_primitive_acks=physical["actual_primitive_acks"],actual_child_reply_links=physical["actual_child_reply_links"],
                actual_process_traces=physical["process_traces"],entries_by_role=physical["entries_by_role"],
                primitive_operation_counts=operations,growth_by_role=growth,expected_fatal_transport_records=fatal,
                explicit_parent_death_controls=signals,observations=physical["observations"],sqlite=physical["sqlite"],
                fixture_custody_files=12,fixture_snapshot_records=fixture_records,fixture_regular_file_records=cas_count,
                live_inode_boundary="Original runner verified all inodes/links after relocation; this reader validates archived full CAS bytes and metadata, and does not inspect the expired live runner filesystem."))
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        drift=[];after_errors=[]
        if root is not None:
            for name,row in before.items():
                try:
                    after[name]=pin(root/name)
                    if after[name]!=row:drift.append(name)
                except BaseException as error:after_errors.append(dict(path=name,error=repr(error)))
            for name,row in downloads.items():
                try:
                    actual=pin(row["path"])
                    if actual!={key:row[key] for key in ("bytes","sha256","mode")}:drift.append(name)
                except BaseException as error:after_errors.append(dict(path=name,error=repr(error)))
        reader_unchanged=pin(__file__)==script
        report.update(original_seal_before=before,original_seal_after=after,original_seal_unchanged=bool(before) and before==after,
            downloaded_member_drift=drift,downloaded_members_unchanged=bool(downloads) and not drift and not after_errors,
            after_errors=after_errors,reader_source_unchanged=reader_unchanged)
        if not reader_unchanged or not report["original_seal_unchanged"] or not report["downloaded_members_unchanged"]:
            status="FAIL";report["status"]="FAIL"
        save(out/"readback.json",report)
        print(json.dumps(report,sort_keys=True),flush=True)
        for label,raw in sorted(json_raw.items()):
            print("BEGIN_FENCING_ORIGINAL "+label+" "+str(len(raw))+" "+sha(raw),flush=True)
            sys.stdout.buffer.write(raw)
            if not raw.endswith(b"\n"):sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
            print("END_FENCING_ORIGINAL "+label,flush=True)
        raw=(out/"readback.json").read_bytes()
        print(json.dumps(dict(status=status,readback_bytes=len(raw),readback_sha256=sha(raw),native_entries_executed_by_reader=0,tests_reexecuted_by_reader=0),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
