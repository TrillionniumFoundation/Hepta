"""Independent fresh three-image fencing component CI; no old count inheritance."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json,os,shutil,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=[{"name":"namespace-fencing-r2-generator.py","blob":"65df8a50f30ab5574c36d5fedaab91d78939f64c","bytes":23333,"sha256":"9814243708821565cac54d09a0911118534fcd945eac62ccd9df96cd6f58d509","target":"tools/generate_hia_agent_namespace_fencing.py"},{"name":"namespace-fencing-r2-protocol.py","blob":"79850e57b62f8edc5755388065c31c75311bd985","bytes":15890,"sha256":"9a3aa2135d3d2d29217f0f6847b8542c9ee9a3af25ad6e2ee6d7075f2cb4fd00","target":"tests/test_hia_agent_namespace_fencing.py"},{"name":"namespace-fencing-r2-validate.py","blob":"f5799794fd0d8fa42afe003bcfcc905e9b6d9306","bytes":13866,"sha256":"402a8bead3ba00a1398864f55a2a29fa42e958f95fbcf451f01e4fe2a5d05f4f","target":None},{"name":"namespace-fencing-r2-executor.S","blob":"ff2293f024374c7f4fa6352587b1246cba979839","bytes":26882,"sha256":"61337d78257e1a4c468b629e81eb0a499233ff9d14e19b6b9eee9d07ea4965ab","target":None},{"name":"namespace-fencing-r2-packer.py","blob":"4ebd06ced997b0a39f4ce315372e260c998b6abb","bytes":4846,"sha256":"3903b0b640fa8970a892a5065f960b7b03e2e7d83b59dda01228262340c7a906","target":None},{"name":"namespace-fencing-r2-build.py","blob":"2d559a1c7fba20072aea7ae52b72508a5fc8ce1c","bytes":18246,"sha256":"5e80de4423811f42c5374541ed802e345e450e96dfaf731aee479e3b371aba99","target":None},{"name":"namespace-fencing-r2-client.py","blob":"c05a39acab04c4884d41c8654ee08bc2358d9959","bytes":11264,"sha256":"666936f0f00b7ce0758005c50ad49bf344bd24839989f5942ee19d7b41119362","target":None},{"name":"namespace-fencing-r2-replay.py","blob":"78fc0b42b0a742c90193a949a474e5870a832286","bytes":11268,"sha256":"9f7c2bf8ffa4c666ecae9b784161fdff55b3844971f4397dec517056797d60c2","target":None},{"name":"namespace-fencing-r2-physical.py","blob":"917507331f4904f0072c7d0d0e9e27e99a4668a7","bytes":27621,"sha256":"0fa5df850577a38b543a290f7528a2d35222955ce8a08d3722f4ba8142fe65a1","target":None},{"name":"namespace-fencing-r2-abi.json","blob":"8ff0b24863315333502abf8368361f38a383e2bb","bytes":8641,"sha256":"a3bfbf46ed3690bd8b706d039423383a924ebe8a68f22d89f199078ce0b6ed92","target":"docs/HIA_AGENT_NAMESPACE_FENCING_ABI.json"}]
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
PREDECESSORS={
 "getlk":dict(env="HIA_NAMESPACE_GETLK_PREDECESSOR_DIR",root="hia-namespace-getlk-recovery",
    wrapper="hia-namespace-getlk-recovery-43115476503-1",run=43115476503,artifact=13898836544,
    head="fc4579420727cfcca72b59e226a6f3af885679f4",scope="namespace-filesystem-r4-getlk-component",
    inner=(18107424,"424673c5db8731b8da750ce859484a49e37acb8a18444b51c30b94127f223e10"),
    index=(309012,"4bc3d2d6be4c75231ada306332f219cd20302626e545e4bc0e375ee29cd6c1f8"),
    custody=(588,"da30e96b5b64ee25d060fafccfa4e5543d5b10dba5cf4c904e96c9a64172774f"),
    members=740,raw=65536739,
    selected={"values":("generate_hia_agent_namespace_store.py",11623,"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50","tools/generate_hia_agent_namespace_store.py"),
      "objects":("generate_hia_agent_namespace_objects.py",27802,"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de","tools/generate_hia_agent_namespace_objects.py"),
      "source":("agent_namespace_filesystem_r4.hiaasm",123055,"31d1edeb1ce78271be610eaf486cfb16e19d5f08e512066b3ca55416becca0e2","examples/hia_bootstrap/agent_namespace_filesystem_r4.hiaasm"),
      "image":("namespace-filesystem-r4.image.bin",182406,"c90d3b239420b28d4e07f505913669371e14a8cb1b8306523942e1287c54d133",None)},
    jsons={"generation":"run/namespace-filesystem-r4/generation-r1/result.json",
      "protocol":"run/namespace-filesystem-r4/validation-r1/result.json",
      "build":"run/namespace-filesystem-r4/carrier-build-r1/summary.json",
      "physical":"run/namespace-filesystem-r4/carrier-native-r1/summary.json","top":"run/summary.json"}),
 "inode":dict(env="HIA_NAMESPACE_INODE_PREDECESSOR_DIR",root="hia-namespace-inode-recovery",
    wrapper="hia-namespace-inode-recovery-43113333444-1",run=43113333444,artifact=13896704251,
    head="c4424483c586a7f91f3311cae6107966cdcf4d4a",scope="namespace-inode-policy-component",
    inner=(17993304,"fd17fddc5c8e54ccf33bc73e52396e0560f5f369aea0de32c1953067cfaf226c"),
    index=(288075,"7b71ec69df2e3022c55b86a40ea9899bd775c8abbabff678d8b925cd41af1b72"),
    custody=(581,"e11f5979fcaca144db2f48b695228bd5bf31c63a7673bad8817fdfb472525bbe"),
    members=680,raw=59896581,
    selected={"source":("agent_namespace_inode_r2.hiaasm",132728,"ea3e6ba9ad56f677cf41f927ee968cf54dd33fc000744151b2fed6e31b53a066","examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm"),
      "image":("namespace-inode-r2.image.bin",200565,"c8fa89d7e3f0112a3efb2dbedd4c9c0be3332544675523108e41daf75efee1e8",None)},
    jsons={"generation":"run/namespace-inode-r2/generation-r1/result.json",
      "protocol":"run/namespace-inode-r2/validation-r1/result.json",
      "physical":"run/namespace-inode-r2/physical-r1/summary.json","top":"run/summary.json"})
}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path);info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except OSError:return False
def module(name,path):
    raw=Path(path).read_bytes();spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value
def generation(context_path):
    context=json.loads(context_path.read_bytes());tree=Path(context["namespace_working"])
    ref=Path(context["reference"]);out=Path(context["namespace_evidence"])/"generation-r1";out.mkdir()
    before={};report=dict(status="INCOMPLETE",scope="NEW_FENCING_R2_GENERATION_ONLY")
    try:
        for p in sorted(tree.rglob("*")):
            if p.is_file():before[str(p)]=pin(p)
        sys.path.insert(0,str(ref))
        for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_fencing"):
            m=module("tools."+name,tree/"tools"/(name+".py"))
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        document=m.document();save(out/"generated-document.json",document)
        source=render_assembly(document).encode()
        profile=dict(functions=len(document["functions"]),blocks=sum(len(f["blocks"]) for f in document["functions"]),
            max_blocks=max(len(f["blocks"]) for f in document["functions"]),
            ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
            max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_block_params"]<=16
        assemble_program(source)
        target=tree/"examples/hia_bootstrap/agent_namespace_fencing_r2.hiaasm"
        with target.open("xb") as h:h.write(source)
        target.chmod(0o644);assert target.read_bytes()==source
        (out/target.name).write_bytes(source)
        report.update(status="GENERATED",profile=profile,generated=dict(path=str(target),bytes=len(source),sha256=sha(source)),
            files=[pin(target)])
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        after={path:pin(path) for path in before}
        report.update(source_before=before,source_after=after,source_unchanged=before==after)
        if before!=after:report["status"]="FAIL"
        save(out/"result.json",report);print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="GENERATED" else 1
def fixed_root(config):
    supplied=Path(os.environ[config["env"]]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    candidates=[supplied/config["root"],supplied/config["wrapper"]/config["root"]]
    if supplied.name==config["root"]:candidates.append(supplied)
    found=[]
    for root in candidates:
        if not (root/"evidence.tar.xz").exists():continue
        for path in [root,*root.parents]:
            if path==supplied.parent:break
            assert not path.is_symlink()
        found.append(root)
    assert len(found)==1,("missing or ambiguous original artifact layout",config["env"],len(found))
    return found[0]
def clean_tests(value,count,passed=False):
    assert 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==count
    assert len(set(value["test_ids"]))==count
    assert not any(value[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    if passed:assert value["passed"] is True
def restore(kind,config,context,tree,evidence,inputs):
    root=fixed_root(config);saved=evidence/("predecessor-"+kind);saved.mkdir()
    seal={}
    for name,wanted in (("evidence.tar.xz",config["inner"]),("evidence-members.json",config["index"]),("custody.json",config["custody"])):
        row=pin(root/name);assert (row["bytes"],row["sha256"])==wanted
        inputs[str(root/name)]=row;seal[name]=row
        shutil.copyfile(root/name,saved/name)
        copy=pin(saved/name);assert (copy["bytes"],copy["sha256"])==wanted
    index=json.loads((root/"evidence-members.json").read_bytes());custody=json.loads((root/"custody.json").read_bytes())
    assert len(index)==config["members"] and sum(row["bytes"] for row in index)==config["raw"]
    assert custody["status"]=="PASS" and custody["scope"]==config["scope"]
    assert custody["members"]==config["members"] and custody["original_bytes"]==config["raw"]
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] and not custody["whole_stack_closed"]
    expected={}
    for row in index:
        rel=PurePosixPath(row["name"])
        assert rel.parts and rel.parts[0]=="run" and not rel.is_absolute()
        assert ".." not in rel.parts and "." not in rel.parts and rel.as_posix()==row["name"]
        assert row["name"] not in expected and type(row["bytes"]) is int and row["bytes"]>=0
        assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
        expected[row["name"]]=row
    selected={};selected_json={};matches={key:[] for key in config["selected"]};checked=[];seen=set()
    with tarfile.open(root/"evidence.tar.xz","r:xz") as archive:
        for item in archive:
            assert item.isfile() and not item.issym() and not item.islnk()
            assert item.name in expected and item.name not in seen
            row=expected[item.name];assert (item.size,item.mode)==(row["bytes"],row["mode"])
            stream=archive.extractfile(item);assert stream is not None;raw=stream.read()
            assert (len(raw),sha(raw))==(row["bytes"],row["sha256"])
            rel=PurePosixPath(item.name);outer=root.joinpath(*rel.parts[1:])
            for path in [outer,*outer.parents]:
                assert not path.is_symlink()
                if path==root:break
            actual=pin(outer);assert (actual["bytes"],actual["sha256"])==(row["bytes"],row["sha256"])
            inputs[str(outer)]=actual
            checked.append(dict(name=item.name,bytes=len(raw),sha256=sha(raw),tar_mode=item.mode,download_mode=actual["mode"]))
            for label,name in config["jsons"].items():
                if item.name==name:selected_json[label]=raw
            for label,(basename,size,digest,target) in config["selected"].items():
                if rel.name==basename and len(raw)==size and sha(raw)==digest:
                    assert item.mode==0o644
                    if label in selected:assert selected[label]==raw
                    else:selected[label]=raw
                    matches[label].append(item.name)
            seen.add(item.name)
    assert seen==set(expected) and set(selected)==set(config["selected"]) and set(selected_json)==set(config["jsons"])
    generation=json.loads(selected_json["generation"]);protocol=json.loads(selected_json["protocol"])
    physical=json.loads(selected_json["physical"]);top=json.loads(selected_json["top"])
    assert top["status"]=="PASS" and top["scope"]==config["scope"]
    assert top["frozen_source_and_reference_before_after_equal"] and top["submitted_script_pins_before_after_equal"]
    assert not top["whole_stack_closed"] and not top["production_activated"]
    assert generation["status"]=="GENERATED" and generation["source_unchanged"]
    assert generation["source_before"]==generation["source_after"]
    assert protocol["status"]=="PASS" and protocol["source_unchanged"]
    assert protocol["source_before"]==protocol["source_after"] and protocol["produced_image_before_after_equal"]
    assert protocol["source_sha256"]==generation["generated"]["sha256"]==sha(selected["source"])
    assert protocol["image"]["sha256"]==sha(selected["image"]) and protocol["image"]["bytes"]==len(selected["image"])
    receipt=protocol["compile_receipt"]
    assert receipt["artifact_sha256"]==B3 and receipt["input_sha256"]==receipt["source_sha256"]==protocol["source_sha256"]
    assert receipt["produced_sha256"]==protocol["image"]["sha256"] and receipt["produced_bytes"]==len(selected["image"])
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert set(protocol["tests"])=={"vm","paired"}
    for row in protocol["tests"].values():clean_tests(row,18,True)
    assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
    assert physical["source_before"]==physical["source_after"]
    if kind=="getlk":
        clean_tests(physical["tests"],12)
        assert (protocol["vm_entries"],protocol["native_entries"])==(1406,703)
        assert (physical["native_entries"],physical["vm_entries"],physical["actual_primitive_acks"],physical["process_traces_replayed"])==(238,238,101,14)
        assert physical["observations"]["all23_actual_primitives"] is True
        assert physical["observations"]["actual_getlk_is_query_not_acquire"] is True
        assert physical["observations"]["actual_getlk_own_process_is_invisible"] is True
        build=json.loads(selected_json["build"])
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_before"]==build["source_after"]
        assert build["packer_entries"]==len(build["packer_controls"])==8
        assert build["kernel_image_sha256"]==protocol["image"]["sha256"]
        role=1
    else:
        clean_tests(physical["tests"],9)
        assert (protocol["vm_entries"],protocol["native_entries"])==(1082,541)
        assert (physical["native_inode_entries"],physical["vm_inode_entries"])==(191,191)
        assert (physical["fs_native_entries"],physical["fs_vm_entries"],physical["fs_actual_primitive_acks"])==(270,270,114)
        assert physical["private_python_router_is_development_only"] and not physical["fixed_namespace_coordinator_closed"]
        assert physical["observations"]["actual_sqlite_wal_writer_both_directions"] is True
        role=2
    written={}
    for label,raw in selected.items():
        basename,size,digest,target=config["selected"][label]
        destination=tree/target if target is not None else saved/"runtime"/basename
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open("xb") as handle:handle.write(raw)
        destination.chmod(0o644);assert destination.read_bytes()==raw
        written[label]=pin(destination)
    for label,raw in selected_json.items():(saved/(label+"-original.json")).write_bytes(raw)
    save(saved/"member-readback.json",checked)
    context["fencing_peers"][str(role)]=dict(actual_original_status="PASS",
        source_and_image_bound_to_sealed_member=True,source=written["source"],image=written["image"],
        original_artifact=config["artifact"],original_run=config["run"],original_head=config["head"])
    result=dict(status="VERIFIED_PINNED_ACTUAL_PREDECESSOR",kind=kind,role=role,run_id=config["run"],
        artifact_id=config["artifact"],head=config["head"],members=config["members"],raw_bytes=config["raw"],
        seal=seal,selected=written,original_matches=matches,all_members_bytes_sha256_modes_verified=True,
        new_native_entries_from_restore=0,new_vm_entries_from_restore=0,old_counts_inherited=False,
        compressed_zip_scope="GitHub download-action declaration only; this code hashes the exact pinned inner archives.")
    save(saved/"verified.json",result);return result
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes();assert git(raw)==COMMON
    common=module("namespace_fencing_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};status="FAIL";context=None;evidence=None;working=[]
    details=dict(status="INCOMPLETE",scope="NEW_FIXED_THREE_IMAGE_FENCING_COMPONENT",
        ordinary_namespace_closed=False,DMS_lifetime_closed=False,root_policy_closed=False,migration_closed=False,
        prior_counts_inherited=False,python_namespace_router_used=False,original_ROG_full="FAIL/HOLD unchanged")
    try:
        location=Path(__file__).resolve().parent;inputs[str(Path(__file__).resolve())]=pin(__file__)
        paths={}
        for item in FILES:
            path=location/item["name"];source=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(source),sha(source))==(item["bytes"],item["sha256"])
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        context=common.prepare();context["fencing_peers"]={}
        base=Path(context["base"]);ns=base/"namespace-ci-fencing-r2";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-fencing-r2";evidence.mkdir();(evidence/"source").mkdir()
        for path in [Path(__file__),*paths.values()]:
            target=evidence/"source"/path.name;target.write_bytes(path.read_bytes());target.chmod(stat.S_IMODE(path.stat().st_mode))
        details["predecessors"]={kind:restore(kind,config,context,tree,evidence,inputs) for kind,config in PREDECESSORS.items()}
        assert set(context["fencing_peers"])=={"1","2"}
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as handle:handle.write(paths[item["name"]].read_bytes())
                target.chmod(0o644);assert sha(target.read_bytes())==item["sha256"]
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)==B3
        (evidence/"compiler").mkdir();(evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence))
        assert "namespace_predecessor" not in context
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(path) for path in sorted(tree.rglob("*")) if path.is_file()]
        for peer in context["fencing_peers"].values():working.append(pin(peer["image"]["path"]))
        common.run("fencing-r2-generation",[context["python"],"-B",Path(__file__),"--generation",context_path],
            cwd=context["reference"],timeout=180)
        generation_report=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generation_report["status"]=="GENERATED" and generation_report["source_unchanged"]
        working.extend(generation_report["files"]);details["generation"]=generation_report
        env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)}
        common.run("fencing-r2-vm-b3-paired",[context["python"],"-B",paths["namespace-fencing-r2-validate.py"]],
            cwd=context["reference"],timeout=900,env=env)
        protocol=json.loads((evidence/"validation-r1/result.json").read_bytes())
        assert protocol["status"]=="PASS" and protocol["source_before"]==protocol["source_after"]
        assert protocol["produced_image_before_after_equal"] and protocol["native_entries"]>0
        assert set(protocol["tests"])=={"vm","paired"}
        for row in protocol["tests"].values():clean_tests(row,16,True)
        details["new_protocol_validation"]=protocol
        common.run("fencing-r2-fixed-carrier-build",
            [context["python"],"-B",paths["namespace-fencing-r2-build.py"],"--context",context_path,
             "--executor",paths["namespace-fencing-r2-executor.S"],"--packer",paths["namespace-fencing-r2-packer.py"]],
            cwd=context["reference"],timeout=180)
        build=json.loads((evidence/"carrier-build-r1/summary.json").read_bytes())
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
        assert build["packer_entries"]==len(build["packer_controls"])==14 and build["actual_carrier_processes"]==0
        assert build["coordinator_image_sha256"]==protocol["image"]["sha256"]
        assert build["coordinator_source_sha256"]==protocol["source_sha256"]
        details["new_fixed_build"]=build
        common.run("fencing-r2-actual-physical",
            [context["python"],"-B",paths["namespace-fencing-r2-physical.py"],"--context",context_path,
             "--client",paths["namespace-fencing-r2-client.py"],"--replay",paths["namespace-fencing-r2-replay.py"]],
            cwd=context["reference"],timeout=900)
        physical=json.loads((evidence/"carrier-native-r1/summary.json").read_bytes())
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        clean_tests(physical["tests"],12)
        assert physical["native_entries"]==physical["vm_entries"]>0 and physical["actual_primitive_acks"]>0
        assert physical["process_traces"]==len(physical["replay"])>0
        assert physical["actual_child_reply_links"]>0 and set(physical["entries_by_role"])=={"1","2","3"}
        assert all(value>0 for value in physical["entries_by_role"].values())
        for row in physical["replay"]:
            assert row["status"]=="PASS" and row["all_return_output_workspace_bytes_equal"]
            assert row["all_child_replies_bound_to_actual_original_source_output_workspace"] and row["no_field_masks"]
        for key in ("actual_fs_inode_coordinator_chain","actual_raw_fd_zero","no_writable_executable_maps",
            "actual_deferred_alias_lifo_preserves_process_lock","actual_shared_refcount","actual_foreign_busy_then_success",
            "local_busy_has_no_syscall","two_actual_native_sessions","actual_sqlite_writer_bidirectional",
            "actual_dynamic_all_three_growth","external_bytes_cannot_issue_child_channel",
            "transport_failure_releases_actual_locks","actual_injected_stat_orphan_preserves_held_lock",
            "actual_injected_close_error_not_retried","actual_parent_death_unlock"):
            assert physical["observations"][key] is True
        assert not any(physical[key] for key in ("ordinary_store_closed","root_policy_closed","DMS_lifetime_closed","migration_closed","python_router_used"))
        fixture_custody=sorted((evidence/"carrier-native-r1").glob("test_*/fixture-custody.json"))
        assert len(fixture_custody)==12
        for path in fixture_custody:
            record=json.loads(path.read_bytes())
            assert record["status"]=="COMPLETE_CONTENT_AND_MODE_SNAPSHOT_LIVE_INODES_RETAINED"
            assert record["original_bytes_modes_inode_links_verified_after_relocation"]
        details["new_actual_physical"]=physical
        details["fixture_custody_files"]=[pin(path) for path in fixture_custody]
        details.update(status="PASS",new_protocol_vm_entries=protocol["vm_entries"],new_protocol_native_entries=protocol["native_entries"],
            new_packer_entries=build["packer_entries"],new_physical_native_entries=physical["native_entries"],
            new_physical_vm_entries=physical["vm_entries"],new_actual_acks=physical["actual_primitive_acks"],
            new_actual_child_reply_links=physical["actual_child_reply_links"])
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
        if evidence is not None:
            for key,relative in (("generation","generation-r1/result.json"),("protocol","validation-r1/result.json"),
                ("build","carrier-build-r1/summary.json"),("physical","carrier-native-r1/summary.json")):
                path=evidence/relative
                if path.exists():
                    try:details[key+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[key+"_partial_read_error"]=repr(read_error)
    finally:
        details["input_pins"]=list(inputs.values());details["inputs_unchanged"]=all(equal(row) for row in inputs.values())
        details["working_source_before"]=working;details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        common.finish("namespace-fixed-fencing-component",status,details)
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--generation",type=Path);args=parser.parse_args()
    raise SystemExit(generation(args.generation) if args.generation is not None else main())
