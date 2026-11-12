"""Fresh DMS4/FS5 generation, original B3 compilation and complete-byte differential.
This independent component uses explicit synthetic syscall replies; it is not
the fixed physical DMS dispatcher or ordinary namespace qualification.
"""
import sys
sys.dont_write_bytecode=True
import argparse,ast,hashlib,importlib.util,json,os,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=[{"name":"namespace-values-reference.py","blob":"3d45466a68eca7a88d2352879ea1979848318f63","bytes":11623,"sha256":"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50","target":"tools/generate_hia_agent_namespace_store.py"},{"name":"namespace-objects-reference.py","blob":"a188e9553b61ffc4293950908a71a93a3a9a27bb","bytes":27802,"sha256":"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de","target":"tools/generate_hia_agent_namespace_objects.py"},{"name":"namespace-fs5-generator.py","blob":"8dd0e6557cdbd1b42b932f682c2c6c396e57e598","bytes":22419,"sha256":"d1bc8721c3cd5f3276024c239a11060a005161b8d9f23114495cec04d68c48a6","target":"tools/generate_hia_agent_namespace_filesystem_r5.py"},{"name":"namespace-dms-r4-generator.py","blob":"9019897acff302041b93eba78184c89556cad4d4","bytes":36715,"sha256":"84a96dd71ed2c7ab2102ea3e59078b53d378d920be9284e33d20d926ff6ec507","target":"tools/generate_hia_agent_namespace_dms_lifetime.py"},{"name":"namespace-dms-r4-protocol.py","blob":"4eda5bccabff7619f472cdbd5e2c60f6e4d73ee8","bytes":24517,"sha256":"9e5e30080038e3007cb6a0372ebc88ada6179ce281498cbffba93464df1191ea","target":"tests/test_hia_agent_namespace_dms_lifetime.py"},{"name":"namespace-dms-r4-validate.py","blob":"d8a64e102880b441bffb0556c23a9a1fc8d0449a","bytes":14640,"sha256":"deb43bd34709d0b73cc8f84954b2338ac2a9c76a6f45fa26420e8b8aab12e478","target":None},{"name":"namespace-dms-r4-abi.json","blob":"b614e190f3463dbeb6d835c381bbc9c48dee469d","bytes":11960,"sha256":"4229d7271452d938011f6c42061b8c9646ab397860799ca7c1c5552c92427488","target":"docs/HIA_AGENT_NAMESPACE_DMS_LIFETIME_ABI.json"},{"name":"namespace-fs5-executor-unexecuted.S","blob":"34b083be49780f35b6d409e2d0cf850a83894a3b","bytes":21195,"sha256":"042c831b8a8dcd46bcbaa500cf75b4719d04d4a4374be7cd665043b9d385df14","target":None}]
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
EXPECTED_TESTS=28
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path);info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except OSError:return False
def module(name,path,expected=None):
    path=Path(path);raw=path.read_bytes()
    if expected is not None:assert sha(raw)==expected
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value
def source_profile(document):
    assert document["functions"]
    value=dict(functions=len(document["functions"]),blocks=sum(len(f["blocks"]) for f in document["functions"]),
        max_blocks=max(len(f["blocks"]) for f in document["functions"]),
        ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
        max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
    assert value["functions"]<=128 and value["blocks"]<=1536 and value["max_blocks"]<=256
    assert value["ops"]<=8192 and value["max_block_params"]<=16
    return value
def generation(context_path):
    context_path=Path(context_path).resolve();context_raw=context_path.read_bytes()
    context=json.loads(context_raw);tree=Path(context["namespace_working"]);ref=Path(context["reference"])
    out=Path(context["namespace_evidence"])/"generation-r1";out.mkdir()
    before={};report=dict(status="INCOMPLETE",scope="NEW_DMS4_FS5_GENERATION_ONLY",
        generated={},profiles={},reference_commit="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5",
        inherited_test_counts=False,actual_native_entries=0,actual_VM_entries=0)
    try:
        for p in sorted(tree.rglob("*")):
            if p.is_file():before[str(p)]=pin(p)
        before[str(context_path)]=pin(context_path);before[str(Path(__file__).resolve())]=pin(Path(__file__).resolve())
        sys.path.insert(0,str(ref))
        for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects"):
            module("tools."+name,tree/"tools"/(name+".py"),before[str(tree/"tools"/(name+".py"))]["sha256"])
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        import hepta.hia_agent_assembly
        assert Path(hepta.hia_agent_assembly.__file__).resolve()==ref/"hepta/hia_agent_assembly.py"
        for role,author,filename in (
            ("fs","generate_hia_agent_namespace_filesystem_r5","agent_namespace_filesystem_r5.hiaasm"),
            ("dms","generate_hia_agent_namespace_dms_lifetime","agent_namespace_dms_lifetime_r4.hiaasm")):
            path=tree/"tools"/(author+".py")
            m=module("tools."+author,path,before[str(path)]["sha256"])
            document=m.document();save(out/(role+"-document.json"),document)
            profile=source_profile(document);source=render_assembly(document).encode("utf-8")
            assemble_program(source)
            target=tree/"examples/hia_bootstrap"/filename;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as handle:handle.write(source)
            target.chmod(0o644);assert target.read_bytes()==source
            (out/filename).write_bytes(source)
            report["generated"][role]=pin(target);report["profiles"][role]=profile
        assert set(report["generated"])=={"fs","dms"}
        assert context_path.read_bytes()==context_raw
        report["status"]="GENERATED"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        after={}
        for path in before:
            try:after[path]=pin(path)
            except BaseException as error:after[path]={"read_error":repr(error)}
        report.update(source_before=before,source_after=after,source_unchanged=before==after)
        if before!=after:report["status"]="FAIL"
        save(out/"result.json",report);print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="GENERATED" else 1
def clean_tests(value):
    assert value["passed"] is True
    assert 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==EXPECTED_TESTS
    assert len(set(value["test_ids"]))==EXPECTED_TESTS
    assert not any(value[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes();assert git(raw)==COMMON
    common=module("namespace_dms_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};working=[];status="FAIL";context=None;evidence=None
    details=dict(status="INCOMPLETE",scope="NEW_DMS4_FS5_SYNTHETIC_KERNEL_TWO_REAL_IMAGES",
        ordinary_namespace_closed=False,DMS_mapping_closed=False,root_policy_closed=False,migration_closed=False,
        physical_DMS_dispatcher_closed=False,actual_physical_syscalls=0,
        prior_counts_inherited=False,old_fixed_fencing_binary_reused=False,
        original_ROG_full="FAIL/HOLD unchanged; NDU deletion actor UNKNOWN")
    try:
        location=Path(__file__).resolve().parent;inputs[str(Path(__file__).resolve())]=pin(Path(__file__).resolve())
        paths={}
        for item in FILES:
            path=location/item["name"];source=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(source),sha(source))==(item["bytes"],item["sha256"])
            if path.suffix==".py":ast.parse(source,filename=str(path))
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        context=common.prepare()
        base=Path(context["base"]);ns=base/"namespace-ci-dms-r4";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-dms-r4";evidence.mkdir();(evidence/"source").mkdir()
        for path in [Path(__file__),*paths.values()]:
            target=evidence/"source"/path.name
            with target.open("xb") as handle:handle.write(path.read_bytes())
            target.chmod(stat.S_IMODE(path.stat().st_mode));assert target.read_bytes()==path.read_bytes()
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as handle:handle.write(paths[item["name"]].read_bytes())
                target.chmod(0o644);assert (len(target.read_bytes()),sha(target.read_bytes()))==(item["bytes"],item["sha256"])
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)==B3
        (evidence/"compiler").mkdir();(evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence))
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        details["helper_provenance"]=dict(
            source_kind="two exact authoring helper byte copies from fully replayed original fencing archive",
            previous_run=43121313060,previous_artifact=13900534166,
            archive_sha256="9633775fd2fa0405eeda29c25b089aafb2222bfa3ddc16d8e241dabf7295c3dd",
            source_members=[
                "run/namespace-fencing-r2/carrier-build-r1/source/11/generate_hia_agent_namespace_store.py",
                "run/namespace-fencing-r2/carrier-build-r1/source/12/generate_hia_agent_namespace_objects.py"],
            used_only_for_HIA_authoring=True,previous_image_or_execution_results_used=False,
            source_pins=FILES[:2])
        details["not_executed_FS5_executor"]=dict(source=FILES[-1],as_or_native_executions=0)
        common.run("dms-r4-fs5-source-generation",
            [context["python"],"-B",Path(__file__),"--generation",context_path],
            cwd=context["reference"],timeout=180)
        generated=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generated["status"]=="GENERATED" and generated["source_unchanged"]
        assert set(generated["generated"])=={"fs","dms"}
        working.extend(generated["generated"].values());details["generation"]=generated
        common.run("dms-r4-fs5-vm-b3-paired",
            [context["python"],"-B",paths["namespace-dms-r4-validate.py"]],
            cwd=context["reference"],timeout=900,env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)})
        protocol=json.loads((evidence/"validation-r1/result.json").read_bytes())
        assert protocol["status"]=="PASS" and protocol["source_unchanged"] and protocol["source_before"]==protocol["source_after"]
        assert set(protocol["tests"])=={"vm","paired"}
        for row in protocol["tests"].values():clean_tests(row)
        assert set(protocol["produced_images_unchanged"])=={"fs","dms"} and all(protocol["produced_images_unchanged"].values())
        assert set(protocol["images"])==set(protocol["compile_receipts"])==set(protocol["entries_by_role"])=={"fs","dms"}
        assert protocol["vm_entries"]==2*protocol["native_entries"]>0
        for row in protocol["entries_by_role"].values():assert row["vm"]==2*row["native"]>0
        assert protocol["synthetic_kernel_acks"]>0 and protocol["actual_physical_syscalls"]==0
        for role,receipt in protocol["compile_receipts"].items():
            assert receipt["input_sha256"]==receipt["source_sha256"]==generated["generated"][role]["sha256"]
            assert receipt["produced_sha256"]==protocol["images"][role]["sha256"]
            assert receipt["artifact_sha256"]==B3
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert not protocol["whole_store_closed"] and not protocol["DMS_mapping_closed"] and not protocol["ordinary_AgentStore_closed"]
        details.update(status="PASS",new_protocol_validation=protocol,
            new_VM_entries=protocol["vm_entries"],new_actual_native_entries=protocol["native_entries"],
            new_synthetic_kernel_acks=protocol["synthetic_kernel_acks"],entries_by_role=protocol["entries_by_role"])
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
        if evidence is not None:
            for key,relative in (("generation","generation-r1/result.json"),("protocol","validation-r1/result.json")):
                path=evidence/relative
                if path.exists():
                    try:details[key+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[key+"_partial_read_error"]=repr(read_error)
    finally:
        details["input_pins"]=list(inputs.values());details["inputs_unchanged"]=all(equal(row) for row in inputs.values())
        details["working_source_before"]=working;details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        common.finish("namespace-dms-lifetime-component",status,details,
            roots={"dms-working-source":Path(context["namespace_working"])} if context and "namespace_working" in context else {})
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--generation",type=Path);args=parser.parse_args()
    raise SystemExit(generation(args.generation) if args.generation is not None else main())
