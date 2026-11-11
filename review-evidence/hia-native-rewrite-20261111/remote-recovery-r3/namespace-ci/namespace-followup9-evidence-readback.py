"""Read sealed follow9 GETLK and installed-resource evidence; execute no tests/images."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,os,pathlib,resource,shutil,stat,tarfile,traceback,zipfile

HEAD="fc4579420727cfcca72b59e226a6f3af885679f4"
RUN=43115476503
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
CONFIGS={
 "getlk":dict(env="HIA_NAMESPACE_GETLK_READBACK_DIR",root="hia-namespace-getlk-recovery",
    wrapper="hia-namespace-getlk-recovery-43115476503-1",artifact=13898836544,job=130842226286,
    zip_bytes=84219830,zip_sha="d5a2eb5d89558b1bdfba12db1a63ef9cc43bec976671134bbdd328e02383103f",
    archive="evidence.tar.xz",index="evidence-members.json",prefix="run/",
    inner=(18107424,"424673c5db8731b8da750ce859484a49e37acb8a18444b51c30b94127f223e10"),
    index_pin=(309012,"4bc3d2d6be4c75231ada306332f219cd20302626e545e4bc0e375ee29cd6c1f8"),
    members=740,raw=65536739,scope="namespace-filesystem-r4-getlk-component",
    selected={"getlk-generation-original.json":"run/namespace-filesystem-r4/generation-r1/result.json",
      "getlk-protocol-original.json":"run/namespace-filesystem-r4/validation-r1/result.json",
      "getlk-build-original.json":"run/namespace-filesystem-r4/carrier-build-r1/summary.json",
      "getlk-physical-original.json":"run/namespace-filesystem-r4/carrier-native-r1/summary.json",
      "getlk-context-original.json":"run/namespace-filesystem-r4/context.json",
      "getlk-run-original.json":"run/summary.json"}),
 "installed":dict(env="HIA_INSTALLED_READBACK_DIR",root="hia-installed-resource-followup",
    wrapper="hia-installed-resource-followup-43115476503-1",artifact=13897658842,job=130842225906,
    zip_bytes=51882956,zip_sha="6478d717e010e422ddfd6cfde0d5ad174e4fed31a94dea00c913f6b202598411",
    archive="raw.tar.xz",index="members.json",prefix="",
    inner=(8313656,"7e7f18835644eb13e2623a0e2c5b331c0958b439bbbd6e3e496d26e2a2459e5d"),
    index_pin=(163412,"441e08243de16822d45749a11fdc24d0aa88258bf344c413016d2d797cc46cad"),
    members=732,raw=43171716,
    scope="COMPLETE_EXISTING20_TEST_MODULE_WITH_REAL_SDIST_WHEEL_AND_INSTALLED_NATIVE_WORKER",
    selected={"installed-summary-original.json":"summary.json","installed-unittest-original.json":"unittest.json",
      "installed-expected-ids-original.json":"expected-test-ids.json",
      "installed-source-before-original.json":"source-before.json",
      "installed-fixture-members-original.json":"fixture-members.json"})
}
PATCHES={
 "MANIFEST.in":(2356,"be75342d4545f7e8213bd5da0c16a6c085bd46a924bec8f955e850584728de52"),
 "tools/hia_selfhost_contract.py":(66312,"ee4c52cc2078df94264e2aff989fd8cff7cad80df0f511e46e08bb69c78a149d"),
 "tests/test_hia_agent_installed_resources.py":(30676,"0c85a50e6cd26c81624b68535a4911a20d64566a229dec92ae44d9f4fefd029e"),
 "docs/HIA_SELFHOST_CORE_SUPPORT.json":(107840,"67d98a62b6cdd7f1226426fdb42b24dbe7a3f549c05200d19f764315cd8b4721")
}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    h=hashlib.sha256();count=0
    with path.open("rb") as handle:
        while True:
            block=handle.read(1<<20)
            if not block:break
            count+=len(block);h.update(block)
    assert count==info.st_size
    return dict(bytes=count,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def fixed_root(config):
    supplied=pathlib.Path(os.environ[config["env"]]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    candidates=[supplied/config["root"],supplied/config["wrapper"]/config["root"]]
    if supplied.name==config["root"]:candidates.append(supplied)
    found=[]
    for root in candidates:
        if not (root/config["archive"]).exists():continue
        for path in [root,*root.parents]:
            if path==supplied.parent:break
            assert not path.is_symlink()
        found.append(root)
    assert len(found)==1,("missing or ambiguous fixed artifact layout",config["env"],len(found))
    return found[0]
def clean_tests(value,count,passed=False):
    assert 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==count
    assert len(set(value["test_ids"]))==count
    assert not any(value[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    if passed:assert value["passed"] is True
def getlk_checks(root,selected,index):
    objects={name:json.loads(raw) for name,raw in selected.items()}
    generation=objects["getlk-generation-original.json"];protocol=objects["getlk-protocol-original.json"]
    build=objects["getlk-build-original.json"];physical=objects["getlk-physical-original.json"]
    top=objects["getlk-run-original.json"];context=objects["getlk-context-original.json"]
    assert top["status"]=="PASS" and top["scope"]==CONFIGS["getlk"]["scope"]
    assert top["frozen_source_and_reference_before_after_equal"] is True
    assert top["submitted_script_pins_before_after_equal"] is True
    assert top["whole_stack_closed"] is False and top["production_activated"] is False
    assert top["inherited_test_counts"] is False
    detail=top["details"]
    assert detail["status"]=="PASS" and detail["inputs_unchanged"] and detail["working_source_unchanged"]
    assert not detail["prior_counts_inherited"] and not detail["ordinary_namespace_closed"]
    assert not detail["fixed_namespace_coordinator_closed"] and not detail["sqlite_migration_closed"]
    assert generation["status"]=="GENERATED" and generation["source_unchanged"]
    assert generation["source_before"]==generation["source_after"]
    profile=generation["profile"]
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
    assert profile["ops"]<=8192 and profile["max_block_params"]<=16
    generator=[row for name,row in generation["source_before"].items()
        if pathlib.Path(name).name=="generate_hia_agent_namespace_filesystem_r4.py"]
    assert len(generator)==1 and generator[0]["sha256"]=="06d4b13cf61d3ad8b8f02892b6259653e6b71b089fbf5f665c7b73dbad95bfc7"
    assert protocol["status"]=="PASS" and protocol["source_unchanged"]
    assert protocol["source_before"]==protocol["source_after"] and protocol["produced_image_before_after_equal"]
    assert protocol["source_sha256"]==generation["generated"]["sha256"]
    receipt=protocol["compile_receipt"]
    assert receipt["source_sha256"]==receipt["input_sha256"]==protocol["source_sha256"]
    assert receipt["artifact_sha256"]==B3 and receipt["limits"]["cpu_seconds"]==10
    assert receipt["limits"]["address_bytes"]==256<<20
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["produced_sha256"]==protocol["image"]["sha256"] and receipt["produced_bytes"]==protocol["image"]["bytes"]
    assert set(protocol["tests"])=={"vm","paired"}
    for tests in protocol["tests"].values():clean_tests(tests,18,True)
    assert protocol["vm_entries"]>=protocol["native_entries"]>0
    assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
    assert build["source_before"]==build["source_after"]
    assert build["kernel_source_sha256"]==protocol["source_sha256"]
    assert build["kernel_image_sha256"]==protocol["image"]["sha256"]
    assert build["packer_entries"]==len(build["packer_controls"])==8
    assert build["actual_carrier_processes"]==0
    for row in build["packer_controls"]:
        assert row["source_unchanged"] and row["workspace_unchanged"] and row["guards"] and row["exact_output_equal"]
    assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
    assert physical["source_before"]==physical["source_after"]
    clean_tests(physical["tests"],12)
    assert physical["native_entries"]==physical["vm_entries"]>0
    replays=physical["replay"]
    assert physical["process_traces_replayed"]==len(replays)>0
    for replay in replays:
        assert replay["status"]=="PASS" and replay["native_entries"]==replay["vm_entries"]>0
        assert replay["all_return_output_workspace_bytes_equal"] and replay["no_field_masks"]
        assert replay["actual_syscall_payloads_are_observed_not_synthetic"]
    for key in ("native_entries","vm_entries","actual_primitive_acks"):
        assert sum(row[key] for row in replays)==physical[key]>0
    operations=set()
    for replay in replays:operations.update(int(key) for key,value in replay["primitive_operation_counts"].items() if value)
    assert operations==set(range(1,24))
    observed=physical["observations"]
    for key in ("all22_actual_primitives","all23_actual_primitives","actual_raw_fd_zero",
      "truncated_transport_process_lock_released","actual_wal_byte120_both_directions","actual_alias_close_drops_lock",
      "parent_death_child_termination","actual_getlk_is_query_not_acquire","actual_getlk_own_process_is_invisible"):
        assert observed[key] is True
    assert observed["actual_getlk_foreign_writer_pid"]>0 and observed["actual_getlk_invalid_kind_errno"]>0
    assert not physical["physical_store_closed"] and not physical["migration_closed"] and not physical["public_root_policy_closed"]
    assert physical["legacy_sqlite3461_claimed"] is False
    assert detail["new_protocol_vm_entries"]==protocol["vm_entries"]
    assert detail["new_protocol_native_entries"]==protocol["native_entries"]
    assert detail["new_packer_entries"]==8 and detail["new_actual_carrier_entries"]==physical["native_entries"]
    assert detail["new_actual_acks"]==physical["actual_primitive_acks"]
    for actual in (protocol["image"],build["executable"]):
        relative=pathlib.Path(actual["path"]).relative_to(pathlib.Path(context["output"]))
        row=index["run/"+relative.as_posix()]
        assert (row["bytes"],row["sha256"],row["mode"])==(actual["bytes"],actual["sha256"],actual["mode"])
    request_path="namespace-filesystem-r4/validation-r1/compile/namespace-filesystem-r4.request.json"
    request=json.loads((root/request_path).read_bytes())
    assert "run/"+request_path in index and request["capacity"]==request["workspace_size"]==1<<20
    return dict(protocol_tests=protocol["tests"],protocol_vm_entries=protocol["vm_entries"],
        protocol_native_entries=protocol["native_entries"],packer_entries=build["packer_entries"],
        physical_tests=physical["tests"],physical_native_entries=physical["native_entries"],
        physical_vm_entries=physical["vm_entries"],actual_primitive_acks=physical["actual_primitive_acks"],
        process_traces=physical["process_traces_replayed"],primitive_operations=sorted(operations),
        image=protocol["image"],executable=build["executable"],profile=profile,observations=observed,
        sqlite=physical["sqlite"],ordinary_store_closed=False,DMS_lifetime_closed=False,migration_closed=False)
def installed_checks(root,selected,index):
    summary=json.loads(selected["installed-summary-original.json"])
    tests=json.loads(selected["installed-unittest-original.json"])
    ids=json.loads(selected["installed-expected-ids-original.json"])
    before=json.loads(selected["installed-source-before-original.json"])
    fixture=json.loads(selected["installed-fixture-members-original.json"])
    assert summary["status"]=="PASS" and summary["scope"]==CONFIGS["installed"]["scope"] and summary["head"]==HEAD
    assert summary["source_before_after_equal"] and summary["source_identity_before_after_equal"]
    assert summary["source_before"]==summary["source_after"]==before
    assert summary["source_identity_before"]==summary["source_identity_after"]
    assert summary["tests"]==tests and tests["test_ids"]==ids
    assert summary["all_test_ids_preserved"] and summary["original_compile_limits_unchanged"]
    assert summary["whole_native_delivery_qualified"] is False and summary["actual_native_entry_count"] is None
    assert summary["python"].startswith("3.14.10 ")
    clean_tests(tests,20)
    assert sum(".AgentInstalledResourceSourceTests." in name for name in ids)==3
    assert sum(".AgentInstalledResourceTests." in name for name in ids)==17
    for path,wanted in PATCHES.items():
        row=before[path]
        assert (row["bytes"],row["sha256"])==wanted
    assert len(summary["raw_captures"])==1 and summary["raw_captures"][0]["captured_regular_copies_independently_readback"]
    capture=root/"original-installed-resource-fixture"
    manifest=(capture/"source/MANIFEST.in").read_bytes()
    assert (len(manifest),digest(manifest))==PATCHES["MANIFEST.in"]
    resources=[line[8:] for line in manifest.decode().splitlines() if line.startswith("include ")]
    assert len(resources)==len(set(resources))==45
    omitted=["examples/hia_bootstrap/composite_function_"+part+".hiaasm" for part in ("admit","records","advanced","terms","render")]
    assert set(omitted)<=set(resources)
    regular=[row for row in fixture if row["kind"]==stat.S_IFREG]
    for row in regular:
        path=capture/row["relative"];p=pin(path)
        assert (p["bytes"],p["sha256"])==(row["bytes"],row["sha256"])
        inner=index["original-installed-resource-fixture/"+row["relative"]]
        assert inner["mode"]==row["mode"]
    sdist_names=[name for name in index if name.startswith("original-installed-resource-fixture/sdist/") and name.endswith(".tar.gz")]
    wheel_names=[name for name in index if name.startswith("original-installed-resource-fixture/wheels/") and name.endswith(".whl")]
    assert len(sdist_names)==len(wheel_names)==1
    resource_rows=[]
    with tarfile.open(root/sdist_names[0],"r:gz") as sdist,zipfile.ZipFile(root/wheel_names[0]) as wheel:
        members=sdist.getmembers()
        all_tar_names=[m.name for m in members];all_zip_names=wheel.namelist()
        assert len(all_tar_names)==len(set(all_tar_names)) and len(all_zip_names)==len(set(all_zip_names))
        prefixes={m.name.split("/")[0] for m in members}
        assert len(prefixes)==1;prefix=next(iter(prefixes))
        for name in resources:
            raw=(capture/"source"/name).read_bytes()
            expected=before[name]
            assert (len(raw),digest(raw))==(expected["bytes"],expected["sha256"])
            member=sdist.getmember(prefix+"/"+name);assert member.isfile() and not member.issym() and not member.islnk()
            assert sdist.extractfile(member).read()==raw
            assert wheel.read("hepta/_data/"+name)==raw
            assert (capture/"installed/hepta/_data"/name).read_bytes()==raw
            resource_rows.append(dict(path=name,bytes=len(raw),sha256=digest(raw),
                source_sdist_wheel_installed_equal=True))
    return dict(tests=tests,resources_verified=resource_rows,resource_count=len(resources),
        source_identity_count=len(summary["source_identity_before"]),
        frozen_patch_pins=PATCHES,source_before_after_equal=True,source_identity_before_after_equal=True,
        actual_native_entry_count=None,raw_fixture_members=len(fixture),raw_fixture_regular_members=len(regular),
        python=summary["python"],whole_native_delivery_qualified=False,original_failures_preserved=True)
def read_one(kind,config,out,source_raw):
    out.mkdir()
    report=dict(schema="hia.namespace-followup9-independent-readback.v1",kind=kind,status="INCOMPLETE",
        run_id=RUN,head=HEAD,artifact_id=config["artifact"],job_id=config["job"],
        native_entries_executed_by_this_reader=0,vm_entries_executed_by_this_reader=0,tests_reexecuted_by_this_reader=0,
        compressed_zip=dict(bytes=config["zip_bytes"],sha256=config["zip_sha"]),
        compressed_zip_scope="GitHub artifact declaration/download action only; no compressed ZIP byte claim.",
        script=dict(bytes=len(source_raw),sha256=digest(source_raw)),whole_stack_closed=False,original_ROG_full="FAIL/HOLD unchanged")
    root=None;before={};originals={};selected={};checked=[]
    try:
        root=fixed_root(config)
        assert not out.is_relative_to(root) and not root.is_relative_to(out)
        for name in (config["archive"],config["index"],"custody.json"):before[name]=pin(root/name)
        for name,wanted in ((config["archive"],config["inner"]),(config["index"],config["index_pin"])):
            assert (before[name]["bytes"],before[name]["sha256"])==wanted
        index=json.loads((root/config["index"]).read_bytes());custody=json.loads((root/"custody.json").read_bytes())
        assert len(index)==config["members"] and sum(row["bytes"] for row in index)==config["raw"]
        assert custody["status"]=="PASS" and custody["scope"]==config["scope"] and custody["members"]==config["members"]
        if kind=="getlk":
            assert custody["original_bytes"]==config["raw"]
            assert (custody["bytes"],custody["sha256"])==config["inner"]
            assert (custody["member_index_bytes"],custody["member_index_sha256"])==config["index_pin"]
            assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] and not custody["whole_stack_closed"]
        else:
            assert custody["raw_bytes"]==config["raw"] and custody["all_member_bytes_sha256_modes_verified"]
            assert custody["original_failed_run_unchanged"]
            assert (custody["archive"]["bytes"],custody["archive"]["sha256"])==config["inner"]
            assert (custody["member_index"]["bytes"],custody["member_index"]["sha256"])==config["index_pin"]
        expected={}
        for row in index:
            path=pathlib.PurePosixPath(row["name"])
            assert path.parts and not path.is_absolute() and path.as_posix()==row["name"]
            assert ".." not in path.parts and "." not in path.parts
            assert row["name"].startswith(config["prefix"])
            assert row["name"] not in expected and type(row["bytes"]) is int and row["bytes"]>=0
            assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
            expected[row["name"]]=row
        wanted={value:key for key,value in config["selected"].items()};seen=set()
        with tarfile.open(root/config["archive"],"r:xz") as archive:
            for member in archive:
                assert member.isfile() and not member.issym() and not member.islnk()
                assert member.name in expected and member.name not in seen
                row=expected[member.name]
                assert (member.size,member.mode)==(row["bytes"],row["mode"])
                handle=archive.extractfile(member);assert handle is not None
                h=hashlib.sha256();count=0;parts=[]
                while True:
                    block=handle.read(1<<20)
                    if not block:break
                    h.update(block);count+=len(block)
                    if member.name in wanted:parts.append(block)
                assert (count,h.hexdigest())==(row["bytes"],row["sha256"])
                relative=member.name[len(config["prefix"]):]
                path=root/pathlib.PurePosixPath(relative)
                for ancestor in [path,*path.parents]:
                    assert not ancestor.is_symlink()
                    if ancestor==root:break
                actual=pin(path);assert (actual["bytes"],actual["sha256"])==(row["bytes"],row["sha256"])
                originals[str(path)]=actual
                checked.append(dict(name=member.name,bytes=count,sha256=h.hexdigest(),tar_mode=member.mode,download_mode=actual["mode"]))
                if member.name in wanted:selected[wanted[member.name]]=b"".join(parts)
                seen.add(member.name)
        assert seen==set(expected) and set(selected)==set(config["selected"])
        save(out/"member-readback.json",checked)
        for filename,raw in selected.items():
            (out/filename).write_bytes(raw);assert (out/filename).read_bytes()==raw
        observations=(getlk_checks if kind=="getlk" else installed_checks)(root,selected,expected)
        for name in before:
            destination=out/("original-"+name);shutil.copyfile(root/name,destination)
            assert (pin(destination)["bytes"],pin(destination)["sha256"])==(before[name]["bytes"],before[name]["sha256"])
        report.update(status="PASS",members_replayed=len(checked),raw_bytes_replayed=sum(row["bytes"] for row in checked),
            original_summaries={name:dict(bytes=len(raw),sha256=digest(raw)) for name,raw in selected.items()},
            original_observations=observations)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        (out/"failure.traceback.txt").write_text(traceback.format_exc());traceback.print_exc()
    finally:
        after={};errors=[];drift=[]
        if root is not None:
            for name in before:
                try:after[name]=pin(root/name)
                except BaseException as error:errors.append(dict(path=name,error=repr(error)))
        for path,row in originals.items():
            try:
                observed=pin(pathlib.Path(path))
                if observed!=row:drift.append(dict(path=path,before=row,after=observed))
            except BaseException as error:drift.append(dict(path=path,error=repr(error)))
        report.update(original_seal_before=before,original_seal_after=after,after_errors=errors,
            downloaded_member_drift=drift,original_seal_unchanged=bool(before) and before==after and not errors,
            downloaded_members_unchanged=not drift,reader_source_unchanged=pathlib.Path(__file__).read_bytes()==source_raw)
        if not report["original_seal_unchanged"] or drift or not report["reader_source_unchanged"]:report["status"]="FAIL"
        save(out/"readback.json",report);print(json.dumps(report,sort_keys=True),flush=True)
        for filename,raw in selected.items():
            print("BEGIN_ORIGINAL_JSON "+filename+" "+str(len(raw))+" "+digest(raw),flush=True)
            sys.stdout.write(raw.decode("utf-8"));sys.stdout.flush()
            if not raw.endswith(b"\n"):print(flush=True)
            print("END_ORIGINAL_JSON "+filename,flush=True)
    return report
def main():
    assert sys.version_info[:3]==(3,12,14)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    out=pathlib.Path(os.environ["HIA_CI_OUTPUT"]).absolute();out.mkdir(parents=True,exist_ok=False)
    source=pathlib.Path(__file__).read_bytes();(out/"readback-source.py").write_bytes(source)
    reports={kind:read_one(kind,config,out/kind,source) for kind,config in CONFIGS.items()}
    summary=dict(status="PASS" if all(row["status"]=="PASS" for row in reports.values()) else "FAIL",
        schema="hia.namespace-followup9-complete-readback.v1",reports=reports,
        native_entries_executed=0,vm_entries_executed=0,tests_reexecuted=0,whole_stack_closed=False)
    save(out/"summary.json",summary);print(json.dumps(dict(status=summary["status"],
        reports={name:row["status"] for name,row in reports.items()},new_execution=0),sort_keys=True),flush=True)
    return 0 if summary["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
