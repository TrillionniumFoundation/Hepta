"""Fresh complete selected robust_open HIA policy and raw FS7 owner gate."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-fs7-r2-generator.py\",\"blob\":\"ccddae25e9187a30c30b4af7631f054f37a1ba3b\",\"bytes\":23500,\"sha256\":\"e457bad764e6bf33eca22e7ca947c7d7457f57cb0ac944b033bf199bea32c0b8\",\"target\":\"tools/generate_hia_agent_namespace_filesystem_r7.py\"},{\"name\":\"namespace-robust-open-r1-generator.py\",\"blob\":\"135f27cb100ebbf92608fb2c7d0e67285f4db51c\",\"bytes\":14601,\"sha256\":\"59cb04f502512dd0ec35a89f2fab0b113b70c73cf04396898712f381d36ba3ef\",\"target\":\"tools/generate_hia_agent_namespace_robust_open_r1.py\"},{\"name\":\"robust-open-reference.c\",\"blob\":\"199de4de793c4eff9288c1e66d0896dadefe3503\",\"bytes\":5497,\"sha256\":\"bf5f89d5d721f7e9350fa0a25cc3a7292ed71f18bb3fb1377bc75a13cff1b3b2\",\"target\":\"oracle/robust_open_reference.c\"},{\"name\":\"os_unix_3461_original.c\",\"blob\":\"9e7ba05d6882b1f3c310b99102e8ecbf7f830af2\",\"bytes\":283843,\"sha256\":\"83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9\",\"target\":\"oracle/os_unix_3461_original.c\"},{\"name\":\"build-robust-open-r1.py\",\"blob\":\"7010763ec922b07b625cb0d94568628a9fb35a27\",\"bytes\":13415,\"sha256\":\"deec9b5ad25f75016416424919137d5df89a2c57a2d78432049b4392ff89981b\",\"target\":null},{\"name\":\"validate-robust-open-r1.py\",\"blob\":\"51f236ba98b7fc12ed4f71d7d2a07d44d9abc0fe\",\"bytes\":23959,\"sha256\":\"61e0a55782050f95b147c9768094b4c674551ae3584d66640f6dbec81b9a624d\",\"target\":null},{\"name\":\"robust-open-abi-r2.json\",\"blob\":\"f89d863b72dd0636590e24c65cca668e8b9c89b8\",\"bytes\":6558,\"sha256\":\"ae0d23ad3bbd37f1f43aa666636ece259898c66581c02e41bb26bbee998fa68f\",\"target\":\"docs/HIA_AGENT_NAMESPACE_ROBUST_OPEN_ABI.json\"}]")

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
    common=module("namespace_robust_open_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==common_raw
    context=None;evidence=None;working=[];inputs=[];status="FAIL"
    details=dict(status="INCOMPLETE",scope="NEW_COMPLETE_SELECTED_LINUX_ROBUST_OPEN_POLICY_AND_FS7_CONTROLLED_PROVIDER",
        source_revisions={"FS":7,"FS_slot_ack_revision":2,"robust_open":1},
        prior_execution_counts_inherited=False,prior_images_reused=False,
        full_unixOpen_closed=False,ordinary_AgentStore_closed=False,
        complete_31_SQL_operations_closed=False,migration_closed=False,
        actual_physical_policy_syscalls=0,original_ROG_full="FAIL/HOLD unchanged; deletion actor UNKNOWN",
        execution_counts="UNKNOWN_UNTIL_ACTUAL_RESULTS",
        expected_planned_counts=dict(semantic_C_cases=117,private_protocol_controls=542,direct_FS_controls=16),
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
        root=Path(context["base"])/"namespace-ci-robust-open-r1";root.mkdir()
        tree=root/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-robust-open-r1";evidence.mkdir()
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
        context.update(robust_working=str(tree),robust_evidence=str(evidence))
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"]}
        process=common.run("robust-open-fresh-two-role-B3-and-exact-C-oracle",
            [context["python"],"-B",paths["build-robust-open-r1.py"],context_path],
            cwd=context["reference"],timeout=180,env=env)
        details["build_process"]=process
        report=json.loads((evidence/"build-r1/summary.json").read_bytes())
        details["build"]=report
        assert report["status"]=="PASS_BUILD_ONLY" and report["source_pins_unchanged"]
        assert report["fresh_HIA_B3_compiles"]==2 and report["C_reference_compiles"]==1
        assert report["actual_native_policy_entries"]==report["actual_physical_policy_syscalls"]==0
        assert report["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert process["timeout_seconds"]==180 and not process["timed_out"]
        assert report["exact_reference_policy"]["entire_function_byte_identical"]
        assert set(report["compiled_roles"])=={"robust","fs"}
        for role,value in report["compiled_roles"].items():
            receipt=value["compile_receipt"]
            assert receipt["status"]=="returned" and receipt["abi_status"]==0
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==value["source"]["sha256"]
            assert receipt["produced_sha256"]==value["image"]["sha256"]
            assert receipt["produced_bytes"]==value["image"]["bytes"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        paired_environment=dict(env,HIA_ROBUST_BUNDLE=str(evidence/"build-r1/bundle.json"),
            HIA_ROBUST_OUTPUT=str(evidence/"paired-r1"))
        paired_process=common.run("robust-open-complete-original-C-VM-native-policy-and-private-controls",
            [context["python"],"-B",paths["validate-robust-open-r1.py"]],
            cwd=context["reference"],timeout=180,env=paired_environment)
        details["paired_process"]=paired_process
        paired=json.loads((evidence/"paired-r1/summary.json").read_bytes())
        assert paired["status"]=="PASS" and paired["source_before_after_equal"]
        assert paired["semantic_cases"]==len(paired["semantic_results"])==117
        assert len({x["name"] for x in paired["semantic_results"]})==117 and all(x["equal"] for x in paired["semantic_results"])
        assert paired["protocol_controls"]==len(paired["protocol_control_ids"])==len(set(paired["protocol_control_ids"]))==542
        assert paired["direct_FS_controls"]==len(paired["direct_FS_control_ids"])==len(set(paired["direct_FS_control_ids"]))==16
        assert paired["native_entries"]==paired["VM_entries"]>0
        assert set(paired["entries_by_role"])=={"robust","fs"}
        assert all(x["vm"]==x["native"]>0 for x in paired["entries_by_role"].values())
        assert sum(x["native"] for x in paired["entries_by_role"].values())==paired["native_entries"]
        assert paired["whole_buffers_and_canaries_equal"]
        assert paired["actual_physical_syscalls"]==0
        assert not paired["ordinary_Store_closed"] and not paired["full_unixOpen_closed"]
        assert paired["limits"]==dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,VM_steps=4000000,VM_arena_bytes=32<<20)
        assert paired_process["timeout_seconds"]==180 and not paired_process["timed_out"]
        details["paired"]=paired
        details["execution_counts"]=dict(fresh_HIA_B3_compiles=2,C_reference_compiles=1,
            semantic_C_cases=paired["semantic_cases"],private_protocol_controls=paired["protocol_controls"],
            direct_FS_controls=paired["direct_FS_controls"],native_entries=paired["native_entries"],
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
                        print("HIA_NAMESPACE_ROBUST_ORIGINAL_"+label.upper()+" "+json.dumps(value,sort_keys=True),flush=True)
                    except BaseException as error:details[label+"_read_error"]=repr(error)
        details["input_pins"]=inputs;details["working_source_before"]=working
        details["inputs_unchanged"]=bool(inputs) and all(equal(x) for x in inputs)
        details["working_source_unchanged"]=bool(working) and all(equal(x) for x in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            details["status"]=status="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        common.finish("NAMESPACE_SELECTED_ROBUST_OPEN_C_VM_NATIVE_CONTROLLED_PROVIDER",status,details,
            roots={"robust-open-working-source":context["robust_working"]}
            if context and "robust_working" in context else {})
        print(json.dumps(dict(status=status,scope=details["scope"],execution_counts=details["execution_counts"],
            ordinary_Store_closed=False,full_unixOpen_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
