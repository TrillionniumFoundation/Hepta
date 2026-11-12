"""Fresh six-image physical DB inode / shared-FS / DMS / map / memory gate.

Every source is pinned and every role and packer is generated and B3-compiled
anew. The fixed ELF owns all service calls. Python only authors test fixtures,
observes independent POSIX/SQLite behavior and replays the complete raw trace.
No earlier target test count, native image, full qualification or cold is reused.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-fs5-generator.py\",\"blob\":\"8dd0e6557cdbd1b42b932f682c2c6c396e57e598\",\"bytes\":22419,\"sha256\":\"d1bc8721c3cd5f3276024c239a11060a005161b8d9f23114495cec04d68c48a6\",\"target\":\"tools/generate_hia_agent_namespace_filesystem_r5.py\"},{\"name\":\"namespace-shm-map-r3-generator.py\",\"blob\":\"58f0b8db47774ac75d073336b9fc1160d34d3fd2\",\"bytes\":23289,\"sha256\":\"1ac940af6b31b8e7cc02ada063a46fc5a28ee04f524bb60d5bfeb5fde109fcde\",\"target\":\"tools/generate_hia_agent_namespace_shm_map_r3.py\"},{\"name\":\"namespace-memory-r2-generator.py\",\"blob\":\"7711bad8273121820a1fa169250acf9f6d43a726\",\"bytes\":22372,\"sha256\":\"e9f5e580bbd69149f51f577f9246fb3f553b1574726e945bd0af0a31f7996560\",\"target\":\"tools/generate_hia_agent_namespace_memory_leases.py\"},{\"name\":\"namespace-dms-map-join-r8-generator.py\",\"blob\":\"5a63a53fb9fe1c221c1b7092c40414425695ba06\",\"bytes\":72759,\"sha256\":\"1e687d80d69d4ea69a5be15add0a41f18c0119ee721d6dda1e8dcd7450d0ea8d\",\"target\":\"tools/generate_hia_agent_namespace_dms_map_join_r8.py\"},{\"name\":\"namespace-db-node-r2-generator.py\",\"blob\":\"a63842ae07fa8769b585705ae100d7181a4d6084\",\"bytes\":31678,\"sha256\":\"cd51f698ba9e522b0b2411bdaa1e2fb9f9308f95503b78f35d7f28d21995ae52\",\"target\":\"tools/generate_hia_agent_namespace_db_node_r2.py\"},{\"name\":\"namespace-db-join-r1-generator.py\",\"blob\":\"92f06c473bd42fe5f3f16666c4e9aa9b3cebadcf\",\"bytes\":40272,\"sha256\":\"c2d2d5f522febe4956db2ccd5d7b8003014fedb16b915c751c0e3a810008ba7b\",\"target\":\"tools/generate_hia_agent_namespace_db_fixed_join_r1.py\"},{\"name\":\"four-role-base.S\",\"blob\":\"5a64e9d2d51bd991077c9ee0607be62a8a4c5d5b\",\"bytes\":52928,\"sha256\":\"308b3b0f9d785e71493def82a43ceb4d8aa2891e79ef73e63a4d620657900406\",\"target\":null},{\"name\":\"compose-namespace-db-join-r1.py\",\"blob\":\"793ec691a910b642fc4f448f757af5b1052232d0\",\"bytes\":13823,\"sha256\":\"4d15a5913e37770577265b74a21b75e7e8c0f1da15b5a31a2674a346c727d976\",\"target\":null},{\"name\":\"namespace-db-join-r1-executor.S\",\"blob\":\"d1dc951159eb0a940fe2b2c22254ac3482b56bd2\",\"bytes\":63587,\"sha256\":\"733baf89f39e859bccb20c812c85412ab7d0cee49c7544a0e635879dbff90862\",\"target\":null},{\"name\":\"namespace-db-join-r1-packer.py\",\"blob\":\"05e2ac0ffb2ad6b1261ed1fef74f28090073c6d1\",\"bytes\":5631,\"sha256\":\"c2fc592a6cff96082994e702bdc59c835f6d056bb19a34c78e19b4ee3023e9ff\",\"target\":null},{\"name\":\"namespace-db-join-r3-build.py\",\"blob\":\"1c4dc4bf74248cdcb931fa80285a24e69a11f3c8\",\"bytes\":24014,\"sha256\":\"2467daf69eb9e05f9b58846788d3b16c314bae6347322ffe66dcd77edd5ac69e\",\"target\":null},{\"name\":\"namespace-db-join-r1-client.py\",\"blob\":\"c489da3fc832d9caecaa271069bfc3608746ffec\",\"bytes\":22281,\"sha256\":\"e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270\",\"target\":null},{\"name\":\"four-role-original-replay.py\",\"blob\":\"96762602378d98db79755759b4ad3f4e6a8662bf\",\"bytes\":20780,\"sha256\":\"0b9bab8e16b0174c54062d56c5042afdaea35a1e936932bbd31ade04f06436a6\",\"target\":null},{\"name\":\"namespace-db-join-r1-replay.py\",\"blob\":\"38b7813e00ddf13f047cff6fdd9b407d1d2acce1\",\"bytes\":17457,\"sha256\":\"3886e4af2d36ec42c7db076e954dd4ab7459f065c64e5847e83bb470b83db570\",\"target\":null},{\"name\":\"namespace-db-join-r1-physical.py\",\"blob\":\"4d22804b3daeabf28fea5066aaec46e50c04f273\",\"bytes\":44590,\"sha256\":\"a14f0e30c22399c2868d273c157c8aa0c07ccb290e6fd0a70e0bb1640054c20b\",\"target\":null},{\"name\":\"namespace-db-join-r3-abi.json\",\"blob\":\"11d61218756b56ebaa15428b8aa991057610ee10\",\"bytes\":11567,\"sha256\":\"22e1d2c47af9cd7c82dcbeb60a8be1b6217ee4b8cdd8db8f89dae35b47bff00d\",\"target\":\"docs/HIA_AGENT_NAMESPACE_DB_PHYSICAL_JOIN_ABI.json\"}]")
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
EXPECTED_TESTS=18
EXPECTED_PACKER_CONTROLS=33
ROLES={"1","2","3","4","5","6"}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except BaseException:return False
def module(name,path):
    path=Path(path);raw=path.read_bytes()
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value

def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    common_raw=common_path.read_bytes();assert git(common_raw)==COMMON
    common=module("namespace_six_role_physical_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==common_raw
    inputs={};working=[];context=None;evidence=None;status="FAIL"
    details=dict(status="INCOMPLETE",
        scope="NEW_FIXED_SIX_ROLE_DB_DMS_MAP_MEMORY_SHARED_FILESYSTEM_PRIVATE_PREDECESSOR",
        source_revisions={"FS":5,"Map":3,"memory":2,"DMS_join":8,"DB_node":2,"outer":1},
        prior_execution_counts_inherited=False,prior_images_reused=False,Python_business_router=False,
        complete_31_SQL_operations_closed=False,ordinary_AgentStore_closed=False,
        full_unixOpen_and_findReusableFd_closed=False,migration_closed=False,
        original_ROG_full="FAIL/HOLD unchanged; NDU deletion actor UNKNOWN",
        process_limits=dict(
            HIA_B3_cpu_seconds=10,HIA_B3_wall_seconds=20,HIA_B3_address_bytes=256<<20,
            HIA_B3_output_bytes=1<<20,HIA_B3_workspace_bytes=1<<20,
            builder_cpu_seconds=90,builder_wall_seconds=180,builder_address_bytes=1<<30,
            each_actual_ELF_cpu_seconds=90,each_actual_ELF_wall_seconds=180,
            each_actual_ELF_address_bytes=1<<30,each_actual_ELF_core_bytes=0,
            native_mandatory_exact_wait4=True,physical_aggregate_wall_seconds=900,
            VM_per_original_entry_steps=4000000,VM_arena_bytes=32<<20),
        execution_counts="UNKNOWN_UNTIL_ACTUAL_REPORTS")
    try:
        location=Path(__file__).resolve().parent;paths={}
        inputs[str(Path(__file__).resolve())]=pin(__file__)
        for item in FILES:
            path=location/item["name"]
            raw=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(raw),sha(raw))==(item["bytes"],item["sha256"])
            if path.suffix==".py":ast.parse(raw,filename=str(path))
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        context=common.prepare()
        assert sys.version_info[:3]==(3,12,14)
        assert os.sysconf("SC_PAGE_SIZE")==4096,"this fixed x86-64 ABI requires the recorded actual 4096-byte page"
        required={}
        for name in ("as","readelf","nm","objcopy","strace"):
            path=shutil.which(name)
            assert path is not None,("required physical tool is absent",name)
            path=Path(path).resolve();required[name]=pin(path)
        details["actual_required_tools"]=required
        # strace is mandatory. A ptrace failure remains a real test failure.
        common.run("six-role-strace-version",[required["strace"]["path"],"--version"],
            cwd=context["reference"],timeout=10)
        base=Path(context["base"]);ns=base/"namespace-ci-db-physical-join-r1";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-db-physical-join-r1";evidence.mkdir()
        (evidence/"source").mkdir();(evidence/"compiler").mkdir()
        for path in [Path(__file__).resolve(),*paths.values()]:
            raw=path.read_bytes();target=evidence/"source"/path.name
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(stat.S_IMODE(path.stat().st_mode))
            assert target.read_bytes()==raw
        for item in FILES:
            if item["target"] is None:continue
            target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
            raw=paths[item["name"]].read_bytes()
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(0o644)
            assert (len(raw),sha(raw))==(item["bytes"],item["sha256"])
            assert target.read_bytes()==raw
        compiler=Path(context["compiler"]);raw=compiler.read_bytes()
        assert len(raw)==669556 and sha(raw)==B3
        copied=evidence/"compiler/B3.image.bin";copied.write_bytes(raw)
        copied.chmod(stat.S_IMODE(compiler.stat().st_mode));assert copied.read_bytes()==raw
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence),
            namespace_fixtures=str(ns/"live-physical-fixtures"))
        assert context.get("namespace_predecessor") is None
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        environment={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"]}
        composed=evidence/"namespace-db-join-actual-composed.S"
        composition=common.run("six-role-source-composition",
            [context["python"],"-B",paths["compose-namespace-db-join-r1.py"],
             paths["four-role-base.S"],composed],
            cwd=context["reference"],timeout=30,env=environment)
        assert composed.read_bytes()==paths["namespace-db-join-r1-executor.S"].read_bytes()
        assert all(equal(row) for row in inputs.values())
        details["mechanical_composition"]=dict(process=composition,
            exact_composed_source=pin(composed),four_declared_edits=True,
            original_four_role_base_reversed_exactly=True,assembler_or_native_execution=False)
        builder=common.run("six-role-fresh-B3-and-actual-HIA-packer",
            [context["python"],"-B",paths["namespace-db-join-r3-build.py"],
             "--context",context_path,"--executor",composed,
             "--packer",paths["namespace-db-join-r1-packer.py"]],
            cwd=context["reference"],timeout=180,env=environment)
        details["builder_process"]=builder
        build_path=evidence/"db-join-build-r1/summary.json";build=json.loads(build_path.read_bytes())
        details["build"]=build;details["build_pin"]=pin(build_path)
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
        assert build["fresh_role_compiles"]==6
        assert build["packer_entries"]==len(build["packer_controls"])==EXPECTED_PACKER_CONTROLS
        assert all(row["exact_output_equal"] and row["source_unchanged"] and
            row["workspace_unchanged"] and row["guards"] and
            row["actual_return"]==row["expected_return"] for row in build["packer_controls"])
        assert set(build["exact_roles"])==set(build["generated_roles"])==set(build["compiled_roles"])==ROLES
        assert build["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert build["process_limits"]["wall_seconds"]==180
        assert builder["timeout_seconds"]==180 and not builder["timed_out"]
        for role,row in build["exact_roles"].items():
            receipt=row["compile_receipt"]
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==row["source"]["sha256"]
            assert receipt["produced_sha256"]==row["image"]["sha256"]
            assert receipt["produced_bytes"]==row["image"]["bytes"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        receipt=build["compile_receipt"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["produced_sha256"]==build["packer_image_sha256"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        physical_process=common.run("six-role-actual-physical-and-complete-original-trace-replay",
            [context["python"],"-B",paths["namespace-db-join-r1-physical.py"],
             "--context",context_path,"--client",paths["namespace-db-join-r1-client.py"],
             "--replay",paths["namespace-db-join-r1-replay.py"],
             "--inner-replay",paths["four-role-original-replay.py"]],
            cwd=context["reference"],timeout=900,env=environment)
        details["physical_process"]=physical_process
        physical_path=evidence/"db-join-native-r1/summary.json"
        physical=json.loads(physical_path.read_bytes())
        details["physical"]=physical;details["physical_pin"]=pin(physical_path)
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        tests=physical["tests"]
        assert tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==EXPECTED_TESTS>0
        assert len(set(tests["test_ids"]))==EXPECTED_TESTS
        assert not any(tests[k] for k in
            ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert physical["native_entries"]==physical["vm_entries"]>0
        assert physical["actual_primitive_acks"]>0
        assert set(physical["entries_by_role"])==ROLES
        assert all(v>0 for v in physical["entries_by_role"].values())
        assert sum(physical["entries_by_role"].values())==physical["native_entries"]
        assert physical["all_actual_trace_processes_fully_replayed"]
        assert physical["process_traces"]==len(physical["replay"])==len(physical["process_limit_readbacks"])>0
        assert physical["actual_DB_retirements"]>0 and physical["actual_inner_retirements"]>0
        assert physical["abort_cleanup_pure_control_count"]==3
        assert len(physical["abort_cleanup_pure_controls"])==3
        for entry in physical["process_limit_readbacks"]:
            assert entry["actual"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert entry["limits"]["wall_seconds"]==180 and entry["returncode"]==0
            assert os.WIFEXITED(entry["wait_status"]) and os.WEXITSTATUS(entry["wait_status"])==0
        for entry in physical["replay"]:
            assert entry["status"]=="PASS" and entry["no_masks"] and entry["no_inherited_counts"]
            assert entry["all_original_records_partitioned_exactly_once"]
            assert entry["all_input_output_workspace_return_bytes_equal"]
            assert entry["native_entries"]==entry["vm_entries"]>0
            assert entry["original_trace_before"]==entry["original_trace_after"]
            assert entry["no_OS_primitive_executed_by_replayer"]
        assert not any(physical[k] for k in
            ("ordinary_store_closed","full_sql31_closed","root_policy_closed",
             "unixOpen_and_findReusableFd_closed","migration_closed","python_router_used","counts_inherited"))
        details["execution_counts"]=dict(
            fresh_HIA_role_compiles=6,fresh_HIA_packer_compiles=1,
            direct_HIA_packer_controls=EXPECTED_PACKER_CONTROLS,
            physical_tests=tests["tests_run"],actual_fixed_processes=physical["process_traces"],
            target_native_entries=physical["native_entries"],full_trace_VM_entries=physical["vm_entries"],
            primitive_acks_including_memory=physical["actual_primitive_acks"],
            entries_by_role=physical["entries_by_role"],
            DB_context_retirements=physical["actual_DB_retirements"],
            inner_context_retirements=physical["actual_inner_retirements"],
            pure_abort_cleanup_controls=3,prior_counts_inherited=False)
        details["status"]="PASS";status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        # Read and expose any genuine partial results before sealing. Never
        # invent zeros or PASS for a stage that did not complete.
        if evidence is not None:
            for name,relative in (
                ("build","db-join-build-r1/summary.json"),
                ("physical","db-join-native-r1/summary.json")):
                path=evidence/relative
                if path.exists():
                    try:
                        raw=path.read_bytes()
                        details[name+"_original_report"]=json.loads(raw)
                        details[name+"_original_report_pin"]=pin(path)
                        observed=details[name+"_original_report"]
                        selected={key:observed[key] for key in (
                            "status","scope","error_class","error","traceback","tests",
                            "fresh_role_compiles","packer_entries","actual_carrier_processes","profile_frontiers",
                            "native_entries","vm_entries","entries_by_role","actual_primitive_acks",
                            "process_traces","actual_DB_retirements","actual_inner_retirements",
                            "source_pins_unchanged","all_actual_trace_processes_fully_replayed")
                            if key in observed}
                        print("HIA_NAMESPACE_SIX_ROLE_ORIGINAL_"+name.upper()+" "+
                            json.dumps(dict(original_pin=details[name+"_original_report_pin"],
                                selected_original_fields=selected,
                                complete_original_bytes_preserved_in_artifact=True),sort_keys=True),flush=True)
                    except BaseException as read_error:
                        details[name+"_report_read_error"]=repr(read_error)
        details["input_pins"]=list(inputs.values())
        details["inputs_unchanged"]=bool(inputs) and all(equal(row) for row in inputs.values())
        details["working_source_before"]=working
        details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        # OUTPUT already contains every raw output. The extra root contains
        # only immutable working source under BASE, never live fixture links.
        common.finish("NAMESPACE_SIX_ROLE_PHYSICAL_DB_SHARED_FS_JOIN",status,details,
            roots={"six-role-working-source":context["namespace_working"]}
            if context and "namespace_working" in context else {})
        print(json.dumps(dict(status=status,scope=details["scope"],
            execution_counts=details["execution_counts"],whole_store_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
