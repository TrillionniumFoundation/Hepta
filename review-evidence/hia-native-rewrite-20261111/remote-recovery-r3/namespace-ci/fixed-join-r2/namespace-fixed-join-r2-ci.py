"""Independent new actual DMS7 / Map3 / memory1 / FS5 fixed join gate.

All four semantic images and the new publisher are compiled with the original
B3 limits. No predecessor image, correctness result or entry count is reused.
The raw physical traces and exact whole-state VM replay remain separate from
the earlier DMS4 failure, the Map3 result and ordinary Store qualification.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-fs5-generator.py\",\"blob\":\"8dd0e6557cdbd1b42b932f682c2c6c396e57e598\",\"bytes\":22419,\"sha256\":\"d1bc8721c3cd5f3276024c239a11060a005161b8d9f23114495cec04d68c48a6\",\"target\":\"tools/generate_hia_agent_namespace_filesystem_r5.py\"},{\"name\":\"namespace-shm-map-r3-generator.py\",\"blob\":\"58f0b8db47774ac75d073336b9fc1160d34d3fd2\",\"bytes\":23289,\"sha256\":\"1ac940af6b31b8e7cc02ada063a46fc5a28ee04f524bb60d5bfeb5fde109fcde\",\"target\":\"tools/generate_hia_agent_namespace_shm_map_r3.py\"},{\"name\":\"namespace-memory-lease-r1-generator.py\",\"blob\":\"660eb5e54344c3007a984ccd609c06e0b8ab4a20\",\"bytes\":22379,\"sha256\":\"353f2ec8e9e95ce4186ea404893ea2f599e6963a29d541894e0613740ebef2c7\",\"target\":\"tools/generate_hia_agent_namespace_memory_leases.py\"},{\"name\":\"namespace-dms-map-r7-generator.py\",\"blob\":\"a35ef1c3c859bacd8240da59eb52422e94a824e7\",\"bytes\":72233,\"sha256\":\"ccbcaca8c9e4f4054419fee69efd55db81c48367fee410317a0cb04284f4f8fa\",\"target\":\"tools/generate_hia_agent_namespace_dms_map_join_r7.py\"},{\"name\":\"namespace-dms-map-r1-executor.S\",\"blob\":\"5a64e9d2d51bd991077c9ee0607be62a8a4c5d5b\",\"bytes\":52928,\"sha256\":\"308b3b0f9d785e71493def82a43ceb4d8aa2891e79ef73e63a4d620657900406\",\"target\":null},{\"name\":\"namespace-dms-map-r1-packer.py\",\"blob\":\"41b9007465dbba83ce4a9fbb9b88368fe595d565\",\"bytes\":5135,\"sha256\":\"0bb8c8f223947256f3dba5b69ff2508c656def2a28dc5c272a840e456c5eb1a3\",\"target\":null},{\"name\":\"namespace-dms-map-r2-build.py\",\"blob\":\"beaa6955fc3468398f565aa79b4751f9a009d620\",\"bytes\":22599,\"sha256\":\"d381914842bc0299e074efda29107cbd95262131f154ef667a39cb7a4295f886\",\"target\":null},{\"name\":\"namespace-dms-map-r3-client.py\",\"blob\":\"2bc6a6541cf6ce1947cddcaea3b3810f6594143e\",\"bytes\":20630,\"sha256\":\"a6f897be5011dc0aff46d68f6242bf703a833f705a34e4d1ea956b13b0b558be\",\"target\":null},{\"name\":\"namespace-dms-map-r1-replay.py\",\"blob\":\"96762602378d98db79755759b4ad3f4e6a8662bf\",\"bytes\":20780,\"sha256\":\"0b9bab8e16b0174c54062d56c5042afdaea35a1e936932bbd31ade04f06436a6\",\"target\":null},{\"name\":\"namespace-dms-map-r4-physical.py\",\"blob\":\"1fde7f42849cbea52634cb9f6ba8b1dcb5a671eb\",\"bytes\":38901,\"sha256\":\"27b1ca0b97ddcc770972d9eb8d436fe675be225d9d2da7f8254b1eea51e9710e\",\"target\":null},{\"name\":\"namespace-dms-map-r2-abi.json\",\"blob\":\"ec1d0fb9e035e5ef6019249e1d49013c232ebd10\",\"bytes\":11853,\"sha256\":\"d0e5fc8c40af5f7d505749dab39a81304ac2a5932d56769995f69a0a1c4b5865\",\"target\":\"docs/HIA_AGENT_NAMESPACE_DMS_MAP_FIXED_JOIN_ABI.json\"},{\"name\":\"namespace-dms-map-r2-authoring-notes.json\",\"blob\":\"ddac243e9399637c42fc723f5c901e9b5a6d73a3\",\"bytes\":3946,\"sha256\":\"c6539102740eecf4d8ac5f737e4212f94ea76b1569062344fa080f6b2c5a28cf\",\"target\":null}]")
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
EXPECTED_TESTS=22
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except (OSError,AssertionError):return False
def module(name,path):
    path=Path(path);raw=path.read_bytes()
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value
def clean_tests(value):
    assert 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==EXPECTED_TESTS
    assert len(set(value["test_ids"]))==EXPECTED_TESTS
    assert not any(value[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    raw=common_path.read_bytes();assert git(raw)==COMMON
    common=module("namespace_dms_map_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};working=[];status="FAIL";context=None;evidence=None
    details=dict(status="INCOMPLETE",scope="NEW_ACTUAL_FOUR_ROLE_DMS_MAP_MEMORY_FS_FIXED_COMPONENT",
        ordinary_namespace_closed=False,complete_31_SQL_operations_closed=False,
        DB_inode_deferred_close_closed=False,root_policy_closed=False,migration_closed=False,
        all_prior_failures_preserved=True,prior_counts_inherited=False,
        python_namespace_router_used=False,old_fixed_fencing_binary_reused=False,
        DMS4_previous_failure_cause="UNKNOWN_PENDING_ORIGINAL_READBACK",
        process_budget_revision="r2: actual90CPU/180wall per physical process and whole builder; aggregate900wall is separate",
        supersedes_unexecuted_delivery="ef0ad3fc99a4711efba208f3f8066779368e85fe",
        original_ROG_full="FAIL/HOLD unchanged; NDU deletion actor UNKNOWN")
    try:
        location=Path(__file__).resolve().parent
        inputs[str(Path(__file__).resolve())]=pin(__file__)
        paths={}
        for item in FILES:
            path=location/item["name"]
            source=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(source),sha(source))==(item["bytes"],item["sha256"])
            if path.suffix==".py":ast.parse(source,filename=str(path))
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        context=common.prepare()
        for tool in ("as","readelf","nm","objcopy","strace"):
            assert shutil.which(tool) is not None,("required existing tool absent",tool)
        base=Path(context["base"]);ns=base/"namespace-ci-fixed-join-r1";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-fixed-join-r1"
        evidence.mkdir();(evidence/"source").mkdir()
        for path in [Path(__file__),*paths.values()]:
            target=evidence/"source"/path.name
            with target.open("xb") as handle:handle.write(path.read_bytes())
            target.chmod(stat.S_IMODE(path.stat().st_mode))
            assert target.read_bytes()==path.read_bytes()
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as handle:handle.write(paths[item["name"]].read_bytes())
                target.chmod(0o644)
                assert (len(target.read_bytes()),sha(target.read_bytes()))==(item["bytes"],item["sha256"])
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)==B3
        (evidence/"compiler").mkdir();(evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence),
            namespace_fixtures=str(ns/"live-physical-fixtures"),namespace_predecessor=None)
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        details["helper_provenance"]=dict(
            source_kind="exact immutable authoring helper byte copies",
            source_pins=FILES[:2],used_only_for_HIA_authoring=True,
            previous_image_or_execution_results_used=False)
        details["compiler_source"]=dict(original_path=str(compiler),
            bytes=len(compiler_raw),sha256=B3,new_copy=pin(evidence/"compiler/B3.image.bin"))
        env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"]}
        build_step=common.run("new-four-role-generate-b3-and-fixed-HIA-publication",
            [context["python"],"-B",paths["namespace-dms-map-r2-build.py"],"--context",context_path,
             "--executor",paths["namespace-dms-map-r1-executor.S"],
             "--packer",paths["namespace-dms-map-r1-packer.py"]],
            cwd=context["reference"],timeout=180,env=env)
        assert build_step["timeout_seconds"]==180 and build_step["returncode"]==0 and not build_step["timed_out"]
        build=json.loads((evidence/"join-build-r1/summary.json").read_bytes())
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
        assert build["fresh_role_compiles"]==4
        assert build["process_limits"]["cpu_seconds"]==90 and build["process_limits"]["wall_seconds"]==180
        assert build["actual_process_limits"]==dict(cpu=[90,90],address=[1 << 30,1 << 30],core=[0,0])
        assert build["process_elapsed_ns"]<=180_000_000_000
        assert build["packer_entries"]==len(build["packer_controls"])==25
        assert build["actual_carrier_processes"]==0 and not build["inherited_test_counts"]
        assert set(build["generated_roles"])==set(build["compiled_roles"])==set(build["exact_roles"])=={"1","2","3","4"}
        for role,row in build["exact_roles"].items():
            receipt=row["compile_receipt"]
            assert receipt["source_sha256"]==receipt["input_sha256"]==row["source"]["sha256"]
            assert receipt["produced_sha256"]==row["image"]["sha256"]
            assert receipt["produced_bytes"]==row["image"]["bytes"]
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["limits"]["cpu_seconds"]==10
            assert receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        details["new_fixed_build"]=build
        details["actual_builder_supervision"]=build_step
        common.run("new-four-role-actual-physical-and-complete-VM-replay",
            [context["python"],"-B",paths["namespace-dms-map-r4-physical.py"],"--context",context_path,
             "--client",paths["namespace-dms-map-r3-client.py"],
             "--replay",paths["namespace-dms-map-r1-replay.py"]],
            cwd=context["reference"],timeout=900,env=env)
        physical=json.loads((evidence/"join-native-r1/summary.json").read_bytes())
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        clean_tests(physical["tests"])
        assert physical["native_entries"]==physical["vm_entries"]>0
        assert physical["actual_primitive_acks"]>0 and physical["actual_child_reply_links"]>0
        assert physical["actual_retirements"]>0
        assert physical["process_traces"]==len(physical["replay"])>0
        assert len(physical["process_limit_readbacks"])==len(physical["replay"])
        for process in physical["process_limit_readbacks"]:
            assert process["actual"]==dict(cpu=[90,90],address=[1 << 30,1 << 30],core=[0,0])
            assert process["limits"]["cpu_seconds"]==90 and process["limits"]["wall_seconds"]==180
        assert set(physical["entries_by_role"])=={"1","2","3","4"}
        assert all(value>0 for value in physical["entries_by_role"].values())
        for row in physical["replay"]:
            assert row["status"]=="PASS" and row["all_return_output_workspace_bytes_equal"]
            assert row["all_child_replies_bound_to_actual_original_source_output_workspace"]
            assert row["no_field_masks"] and row["no_inherited_entry_counts"]
            assert row["native_entries"]==row["vm_entries"]>0
            assert row["no_primitive_executed_by_replayer"] and row["actual_auxv_page_bytes"]==4096
        for key in ("actual_initial_fs_issued_no_syscall_and_fd_zero",
                    "actual_existing_SQLite_writer_fenced",
                    "actual_failed_unmap_quarantine_until_exit",
                    "actual_injected_close_unknown_until_exit"):
            assert physical["observations"][key] is True
        for key in ("ordinary_store_closed","DB_inode_deferred_close_closed",
                    "root_policy_closed","migration_closed","python_router_used","counts_inherited"):
            assert physical[key] is False
        details.update(status="PASS",new_actual_physical=physical,
            new_actual_native_entries=physical["native_entries"],
            new_complete_VM_replay_entries=physical["vm_entries"],
            new_actual_packer_entries=build["packer_entries"],
            new_actual_primitive_acks=physical["actual_primitive_acks"],
            new_actual_child_reply_links=physical["actual_child_reply_links"],
            new_actual_retirements=physical["actual_retirements"])
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc())
        traceback.print_exc()
        if evidence is not None:
            for key,relative in (("build","join-build-r1/summary.json"),("physical","join-native-r1/summary.json")):
                path=evidence/relative
                if path.exists():
                    try:details[key+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[key+"_partial_read_error"]=repr(read_error)
    finally:
        details["input_pins"]=list(inputs.values())
        details["inputs_unchanged"]=all(equal(row) for row in inputs.values())
        details["working_source_before"]=working
        details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        # Live hardlink/symlink fixtures remain outside OUTPUT. Exact snapshots
        # record their complete regular bytes, modes and original topology.
        # No special fixture is followed or presented as a regular tar member.
        roots={"join-working-source":Path(context["namespace_working"])} if context and "namespace_working" in context else {}
        common.finish("namespace-fixed-DMS-map-memory-join",status,details,roots=roots)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
