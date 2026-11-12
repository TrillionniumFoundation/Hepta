"""Fresh selected SQLite create-mode and URI HIA policy with real FS8 controlled-return gate."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-fs8-generator.py\",\"blob\":\"5c64683dff44a779a8f1217c37f565e625b10910\",\"bytes\":23046,\"sha256\":\"465014690a19e3910448769a90c38b2b10acbfb4d52ed5e13e91e28d6f409520\",\"target\":\"tools/generate_hia_agent_namespace_filesystem_r8.py\"},{\"name\":\"namespace-create-mode-r1-generator.py\",\"blob\":\"5be027860d59b408a9768610da93693e09b37464\",\"bytes\":17834,\"sha256\":\"31f6d7822682fd4c6081a9d649ae8167bdc08da8313304c86113f64f6d3fb356\",\"target\":\"tools/generate_hia_agent_namespace_create_mode_r1.py\"},{\"name\":\"create-mode-reference.c\",\"blob\":\"ae602fda1bccd7adc00260dc723d94521df9c064\",\"bytes\":19371,\"sha256\":\"3b3e5b303b3e87c950a1b0e1b5d0a05409ac0637aec2f4e804c7f42963d91f8f\",\"target\":\"oracle/create_mode_reference.c\"},{\"name\":\"selected-originals.json\",\"blob\":\"b6719c2d9929080deabdab525298fd0cd10eeea3\",\"bytes\":3030,\"sha256\":\"970b5ef2b0d6d70c8e23e65a9dd823aabd950881c48058d419d1f320664b682f\",\"target\":\"oracle/selected-originals.json\"},{\"name\":\"build-create-mode-r1.py\",\"blob\":\"422e417817634019e292110262d245e2b4fa21b7\",\"bytes\":14830,\"sha256\":\"20d322ec45417d19a2488ee85d70b44e93f979a825d39510b14d0b002c7e6a6a\",\"target\":null},{\"name\":\"validate-create-mode-r1.py\",\"blob\":\"21b316ccbd1d067d66f7c44b41631feb026fc1e7\",\"bytes\":19933,\"sha256\":\"dda809b0483667a715eb8e862a70eb048e6d8d3653c319f76f51f0141521814c\",\"target\":null},{\"name\":\"create-mode-semantic-corpus-r1.json\",\"blob\":\"5aebe0d438d776081359c51ffd94689ab32663ff\",\"bytes\":82356,\"sha256\":\"331be470ee7d44eec2ec5a7dc12270044c322a9571a4761d71fe8d8860a414c5\",\"target\":null},{\"name\":\"original-global.c\",\"blob\":\"121b3f6d6bb59b93635f0a363f049c93d78ce0cb\",\"bytes\":17359,\"sha256\":\"f575d9ab7af86fe0f6397adc4ca4b3a393ff22da32f2543d068d28fb2b994816\",\"target\":\"oracle/originals/global.c\"},{\"name\":\"original-main.c\",\"blob\":\"bff801a87df602d85ce671f5f78a8238ea875bf1\",\"bytes\":167222,\"sha256\":\"737c8f425acc046b1ca76fbbf6474cb4b5a68c3def652a982d4a1fef0ccb431e\",\"target\":\"oracle/originals/main.c\"},{\"name\":\"original-util.c\",\"blob\":\"3b10ba60ada646c6e5f4ceca358fa09a59263eb4\",\"bytes\":51716,\"sha256\":\"93318efdd7140bbb7cba31f341b29eff558d9efd7f4543e001d043e73ca733eb\",\"target\":\"oracle/originals/util.c\"},{\"name\":\"original-pragma.c\",\"blob\":\"a8045aab1eaf821b6da3caba9fe8fdcf4653e89a\",\"bytes\":109773,\"sha256\":\"4df5a8173084abac72c0fc973e39809f418246877ab13b557edf8c6c1daee52b\",\"target\":\"oracle/originals/pragma.c\"},{\"name\":\"original-os_unix.c\",\"blob\":\"9e7ba05d6882b1f3c310b99102e8ecbf7f830af2\",\"bytes\":283843,\"sha256\":\"83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9\",\"target\":\"oracle/originals/os_unix.c\"}]")
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"

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
    except BaseException:return False
def module(name,path):
    path=Path(path);raw=path.read_bytes()
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    common_raw=common_path.read_bytes();assert git(common_raw)==COMMON
    common=module("namespace_create_mode_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==common_raw
    context=None;evidence=None;working=[];inputs=[];status="FAIL"
    details=dict(status="INCOMPLETE",scope="NEW_SELECTED_SQLITE_CREATE_MODE_URI_AND_FS8_CONTROLLED_PROVIDER",
        source_revisions={"FS":8,"create_mode":1},
        prior_execution_counts_inherited=False,prior_images_reused=False,
        full_unixOpen_closed=False,ordinary_AgentStore_closed=False,
        complete_31_SQL_operations_closed=False,migration_closed=False,
        actual_physical_policy_syscalls=0,original_ROG_full="FAIL/HOLD unchanged; deletion actor UNKNOWN",
        execution_counts="UNKNOWN_UNTIL_ACTUAL_RESULTS",
        expected_planned_counts=dict(semantic_C_cases=222,private_protocol_controls=389,direct_boundary_controls=8),
        limits=dict(B3_cpu_seconds=10,B3_wall_seconds=20,B3_address_bytes=256<<20,
            B3_output_bytes=1<<20,B3_workspace_bytes=1<<20,
            C_compiler_cpu_seconds=10,C_compiler_wall_seconds=20,C_compiler_address_bytes=256<<20,
            builder_cpu_seconds=90,builder_wall_seconds=180,builder_address_bytes=1<<30,
            paired_cpu_seconds=90,paired_wall_seconds=180,paired_address_bytes=1<<30,
            VM_step_limit=4000000,VM_arena_bytes=32<<20))
    try:
        location=Path(__file__).resolve().parent;paths={}
        inputs.append(pin(__file__))
        for item in FILES:
            path=location/item["name"]
            raw=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert len(raw)==item["bytes"] and sha(raw)==item["sha256"]
            if path.suffix==".py":ast.parse(raw,filename=str(path))
            inputs.append(pin(path));paths[item["name"]]=path
        context=common.prepare()
        assert sys.version_info[:3]==(3,12,14)
        assert os.sysconf("SC_PAGE_SIZE")==4096
        compiler=shutil.which("cc");assert compiler is not None
        details["C_compiler_binary"]=pin(Path(compiler).resolve())
        root=Path(context["base"])/"namespace-ci-create-mode-r1";root.mkdir()
        tree=root/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-create-mode-r1";evidence.mkdir()
        (evidence/"source").mkdir();(evidence/"compiler").mkdir()
        for path in [Path(__file__).resolve(),*paths.values()]:
            raw=path.read_bytes();target=evidence/"source"/path.name
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(stat.S_IMODE(path.stat().st_mode));assert target.read_bytes()==raw
        for item in FILES:
            if item["target"] is None:continue
            target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
            raw=paths[item["name"]].read_bytes()
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(0o644);assert target.read_bytes()==raw
        raw=Path(context["compiler"]).read_bytes()
        assert len(raw)==669556 and sha(raw)==B3
        target=evidence/"compiler/B3.image.bin";target.write_bytes(raw);target.chmod(0o644)
        assert target.read_bytes()==raw
        context.update(create_mode_working=str(tree),create_mode_evidence=str(evidence))
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"]}
        process=common.run("create-mode-fresh-two-role-B3-and-exact-C-oracle",
            [context["python"],"-B",paths["build-create-mode-r1.py"],context_path],
            cwd=context["reference"],timeout=180,env=env)
        details["build_process"]=process
        report=json.loads((evidence/"build-r1/summary.json").read_bytes())
        details["build"]=report
        assert report["status"]=="PASS_BUILD_ONLY" and report["source_pins_unchanged"]
        assert report["fresh_HIA_B3_compiles"]==2 and report["C_reference_compiles"]==1
        assert report["actual_native_policy_entries"]==report["actual_physical_policy_syscalls"]==0
        assert report["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert process["timeout_seconds"]==180 and not process["timed_out"]
        assert len(report["exact_reference_policy"]["selected_members"])==15
        assert all(x["entire_selected_source_byte_identical"] for x in report["exact_reference_policy"]["selected_members"])
        assert len(report["exact_reference_policy"]["whole_original_sources"])==5
        assert set(report["compiled_roles"])=={"create_mode","fs"}
        for role,value in report["compiled_roles"].items():
            receipt=value["compile_receipt"]
            assert receipt["status"]=="returned" and receipt["abi_status"]==0
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==value["source"]["sha256"]
            assert receipt["produced_sha256"]==value["image"]["sha256"]
            assert receipt["produced_bytes"]==value["image"]["bytes"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        paired_environment=dict(env,HIA_CREATE_MODE_BUNDLE=str(evidence/"build-r1/bundle.json"),
            HIA_CREATE_MODE_OUTPUT=str(evidence/"paired-r1"),
            HIA_CREATE_MODE_CORPUS=str(paths["create-mode-semantic-corpus-r1.json"]))
        paired_process=common.run("create-mode-complete-original-C-VM-native-policy-and-private-controls",
            [context["python"],"-B",paths["validate-create-mode-r1.py"]],
            cwd=context["reference"],timeout=180,env=paired_environment)
        details["paired_process"]=paired_process
        paired=json.loads((evidence/"paired-r1/summary.json").read_bytes())
        assert paired["status"]=="PASS" and paired["source_before_after_equal"]
        assert paired["semantic_cases"]==len(paired["semantic_results"])==222
        assert len({x["name"] for x in paired["semantic_results"]})==222 and all(x["equal"] for x in paired["semantic_results"])
        assert paired["protocol_controls"]==len(paired["protocol_control_ids"])==len(set(paired["protocol_control_ids"]))==389
        assert paired["direct_controls"]==len(paired["direct_control_ids"])==len(set(paired["direct_control_ids"]))==8
        assert paired["native_entries"]==paired["VM_entries"]>0
        assert set(paired["entries_by_role"])=={"create_mode","fs"}
        assert all(x["vm"]==x["native"]>0 for x in paired["entries_by_role"].values())
        assert sum(x["native"] for x in paired["entries_by_role"].values())==paired["native_entries"]
        assert paired["whole_buffers_equal"] and paired["canaries"] and paired["immutable_sources_unchanged"]
        assert paired["actual_physical_syscalls"]==0
        assert not paired["ordinary_Store_closed"] and not paired["full_unixOpen_closed"]
        assert paired["limits"]==dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20)
        assert paired["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert paired_process["timeout_seconds"]==180 and not paired_process["timed_out"]
        details["paired"]=paired
        details["execution_counts"]=dict(fresh_HIA_B3_compiles=2,C_reference_compiles=1,
            semantic_C_cases=paired["semantic_cases"],private_protocol_controls=paired["protocol_controls"],
            direct_boundary_controls=paired["direct_controls"],native_entries=paired["native_entries"],
            VM_entries=paired["VM_entries"],entries_by_role=paired["entries_by_role"],
            controlled_C_policy_events=sum(x["events"] for x in paired["semantic_results"]),
            actual_physical_policy_syscalls=0)
        details["status"]="PASS";status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if evidence is not None:
            for label,relative in (("build","build-r1/summary.json"),("paired","paired-r1/summary.json")):
                path=evidence/relative
                if path.exists():
                    try:
                        value=json.loads(path.read_bytes());details[label+"_original_report"]=value
                        details[label+"_original_report_pin"]=pin(path)
                        print("HIA_NAMESPACE_CREATE_MODE_ORIGINAL_"+label.upper()+" "+json.dumps(value,sort_keys=True),flush=True)
                    except BaseException as error:details[label+"_read_error"]=repr(error)
        details["input_pins"]=inputs;details["working_source_before"]=working
        details["inputs_unchanged"]=bool(inputs) and all(equal(x) for x in inputs)
        details["working_source_unchanged"]=bool(working) and all(equal(x) for x in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            details["status"]=status="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        common.finish("NAMESPACE_SELECTED_CREATE_MODE_URI_C_VM_NATIVE_CONTROLLED_PROVIDER",status,details,
            roots={"create-mode-working-source":context["create_mode_working"]}
            if context and "create_mode_working" in context else {})
        print(json.dumps(dict(status=status,scope=details["scope"],execution_counts=details["execution_counts"],
            ordinary_Store_closed=False,full_unixOpen_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
