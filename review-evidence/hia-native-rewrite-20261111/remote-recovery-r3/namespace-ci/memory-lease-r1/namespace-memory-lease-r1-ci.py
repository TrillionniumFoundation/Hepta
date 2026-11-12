"""Fresh memory-lease generation, original B3 compilation and complete-byte differential.
This independent component uses explicit synthetic memory primitive replies; it is not
the fixed physical memory dispatcher or ordinary namespace qualification.
"""
import sys
sys.dont_write_bytecode=True
import argparse,ast,hashlib,importlib.util,json,os,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=[{"name":"namespace-values-reference.py","blob":"3d45466a68eca7a88d2352879ea1979848318f63","bytes":11623,"sha256":"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50","target":"tools/generate_hia_agent_namespace_store.py"},{"name":"namespace-objects-reference.py","blob":"a188e9553b61ffc4293950908a71a93a3a9a27bb","bytes":27802,"sha256":"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de","target":"tools/generate_hia_agent_namespace_objects.py"},{"name":"namespace-memory-lease-r1-generator.py","blob":"7711bad8273121820a1fa169250acf9f6d43a726","bytes":22372,"sha256":"e9f5e580bbd69149f51f577f9246fb3f553b1574726e945bd0af0a31f7996560","target":"tools/generate_hia_agent_namespace_memory_leases.py"},{"name":"namespace-memory-lease-r1-protocol.py","blob":"b7492f359c9c32ad95a3ee74f1b7310b69bb4e8e","bytes":16810,"sha256":"9090401cfe13156fdd9589423adab8b5c8d22aea90937e4b0525eb3b07e9332c","target":"tests/test_hia_agent_namespace_memory_leases.py"},{"name":"namespace-memory-lease-r1-validate.py","blob":"6ad9d621be3ddf04dd6eab07884f0c72a91a5a97","bytes":14615,"sha256":"691c2395175892396c54d44c33c36582953d23ba2127838123d5e755fa03403d","target":None},{"name":"namespace-memory-lease-r1-abi.json","blob":"b90d33af1855c8a6a610b701770e83cc362d516d","bytes":11880,"sha256":"a3263cdfbcfebb95fad4c57dc1c1f236b281132085e03636feb7d85ecb555edf","target":"docs/HIA_AGENT_NAMESPACE_MEMORY_LEASE_ABI.json"}]
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
    before={};report=dict(status="INCOMPLETE",scope="NEW_MEMORY_LEASE_R1_GENERATION_ONLY",
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
            ("memory","generate_hia_agent_namespace_memory_leases","agent_namespace_memory_leases_r1.hiaasm"),):
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
        assert set(report["generated"])=={"memory"}
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
    common=module("namespace_memory_lease_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};working=[];status="FAIL";context=None;evidence=None
    details=dict(status="INCOMPLETE",scope="NEW_MEMORY_LEASE_R1_SYNTHETIC_PRIMITIVE_ONE_REAL_IMAGE",
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
        base=Path(context["base"]);ns=base/"namespace-ci-memory-lease-r1";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-memory-lease-r1";evidence.mkdir();(evidence/"source").mkdir()
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
        common.run("memory-lease-r1-source-generation",
            [context["python"],"-B",Path(__file__),"--generation",context_path],
            cwd=context["reference"],timeout=180)
        generated=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generated["status"]=="GENERATED" and generated["source_unchanged"]
        assert set(generated["generated"])=={"memory"}
        working.extend(generated["generated"].values());details["generation"]=generated
        common.run("memory-lease-r1-vm-b3-paired",
            [context["python"],"-B",paths["namespace-memory-lease-r1-validate.py"]],
            cwd=context["reference"],timeout=900,env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)})
        protocol=json.loads((evidence/"validation-r1/result.json").read_bytes())
        assert protocol["status"]=="PASS" and protocol["source_unchanged"] and protocol["source_before"]==protocol["source_after"]
        assert set(protocol["tests"])=={"vm","paired"}
        for row in protocol["tests"].values():clean_tests(row)
        assert set(protocol["produced_images_unchanged"])=={"memory"} and all(protocol["produced_images_unchanged"].values())
        assert set(protocol["images"])==set(protocol["compile_receipts"])==set(protocol["entries_by_role"])=={"memory"}
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
        common.finish("namespace-memory-lease-component",status,details,
            roots={"memory-lease-working-source":Path(context["namespace_working"])} if context and "namespace_working" in context else {})
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--generation",type=Path);args=parser.parse_args()
    raise SystemExit(generation(args.generation) if args.generation is not None else main())
