"""NEW inode/WAL policy CI, retaining exact completed FS provider provenance.

No old kernel/carrier corpus is rerun. Newly executed inode and provider entries
are counted separately. This job does not close AgentStore/migration/worker.
"""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json,os,shutil,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=[{"name":"namespace-inode-r2-generator.py","blob":"1de42ee81c2f39a67e8623dc5cc9332ffc203bb6","bytes":24752,"sha256":"3c51180bb529f8913b8b19ba7693406ad43b1cd860f776384dd2ec2dfeb943a7","target":"tools/generate_hia_agent_namespace_inode.py"},{"name":"namespace-inode-r2-protocol.py","blob":"ac776d974ac07df69f68fb5db8894fc56c434e1c","bytes":16416,"sha256":"179609bbb21e650ca8233147ed415b616f3477b2ce8e7830358c1a7903353497","target":"tests/test_hia_agent_namespace_inode.py"},{"name":"namespace-inode-r2-abi.json","blob":"89d2bcdd886015719dbec8ac4ef2dabab7003e00","bytes":11609,"sha256":"883d53ccad65f48531c3d45202a8da7543359e87bd285a3c217bd6e947b37600","target":"docs/HIA_AGENT_NAMESPACE_INODE_ABI.json"},{"name":"namespace-inode-r2-validate.py","blob":"2e712c56ab88b037c8dfb2845df7c78d16b903da","bytes":13814,"sha256":"8c356067291b253de64dc15ab9353fe50b8ebb1515ac99d1f72908bd2d8489db","target":None},{"name":"namespace-inode-r2-physical.py","blob":"79080feb118acf38cc3b4c59f91d5ab9c4f42a66","bytes":26525,"sha256":"77684c5c08a44902beee07968e8076502c4fc2c41e9b88b33a695db934f2e4f2","target":None}]
PRIOR_HEAD="408c130d129992b7d1ef31d3e1e625b1c56af422"
PRIOR_RUN=43105934854
PRIOR_ARTIFACT=13893997012
INNER=(11695096,"497b7f8fb97085e6c20953180d05afacd0846f0f30eed2111196cc3f17108ccf")
INDEX=(258697,"5f9cf8136f94a70adbdb463c0cc638dda64bbd170c20d6037074fc9f0e46da68")
CUSTODY=(595,"4552563916a3da9a868364b300cedc8f1cb18619b74d84f32f4c29f4bfa468ae")
SELECTED={
 "store":("generate_hia_agent_namespace_store.py",11623,"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50","tools/generate_hia_agent_namespace_store.py"),
 "objects":("generate_hia_agent_namespace_objects.py",27802,"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de","tools/generate_hia_agent_namespace_objects.py"),
 "fs_source":("agent_namespace_filesystem_r3.hiaasm",119707,"7e19f56989fda5170b42e045701707cd771b2cd184f8e47b904a7df5070086c8","examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm"),
 "fs_image":("namespace-filesystem-r3.image.bin",177609,"f1d81566c18556fcdddafb84546f4f6208b7a83f9351583e999e5ecb6379618c",None),
 "fs_elf":("hia-namespace-filesystem",181257,"1a83b401f48b03f36cc9fb7da2fac8fc28a3ea5f8c5c364dffbd2787eac8f7f6",None),
}
OLD_SCRIPTS=[
 ("namespace-filesystem-carrier-client.py","e2ad618d57469727d46d04dbdba7c8f85b4f973c",11458,"00981a3f7bbd195dd5522858d6c032e19a4789900317ff8637be1d811a77893d"),
 ("namespace-filesystem-carrier-replay.py","de55990f1f5837c7ab5b9a85c4cfed5b9e30dde3",7961,"d81356c9bdee5889f562720048b1ac654cfd74f02cb16bb61ff55f1e675c3881")]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def module(name,path):
    raw=path.read_bytes();spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(path),"exec"),m.__dict__);return m
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except OSError:return False
def generation(context_path):
    context=json.loads(context_path.read_bytes());tree=Path(context["namespace_working"])
    ref=Path(context["reference"]);out=Path(context["namespace_evidence"])/"generation-r1"
    out.mkdir();before={};report=dict(status="INCOMPLETE",scope="NEW_INODE_SOURCE_GENERATION_ONLY")
    source=None
    try:
        for p in sorted(tree.rglob("*")):
            if p.is_file():before[str(p)]=pin(p)
        sys.path.insert(0,str(ref))
        for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_inode"):
            m=module("tools."+name,tree/"tools"/(name+".py"))
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        doc=m.document();save(out/"generated-document.json",doc)
        source=render_assembly(doc).encode()
        (out/"agent_namespace_inode_r2.hiaasm").write_bytes(source)
        profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
            max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
            ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
            max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]))
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_block_params"]<=16
        assemble_program(source)
        target=tree/"examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm"
        with target.open("xb") as h:h.write(source)
        target.chmod(0o644);assert target.read_bytes()==source
        (out/target.name).write_bytes(source)
        report.update(status="GENERATED",profile=profile,generated=dict(path=str(target),bytes=len(source),sha256=sha(source)),
            files=[pin(target)])
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        after={p:pin(p) for p in before}
        report.update(source_before=before,source_after=after,source_unchanged=before==after)
        if before!=after:report["status"]="FAIL"
        save(out/"result.json",report);print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="GENERATED" else 1
def predecessor_root():
    supplied=Path(os.environ["HIA_NAMESPACE_PREDECESSOR_DIR"]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    name="hia-namespace-carrier-recovery";wrapper="hia-namespace-carrier-recovery-43105934854-1"
    candidates=[supplied/name,supplied/wrapper/name]
    if supplied.name==name:candidates.append(supplied)
    found=[]
    for p in candidates:
        if not (p/"evidence.tar.xz").exists():continue
        for q in [p,*p.parents]:
            if q==supplied.parent:break
            assert not q.is_symlink()
        found.append(p)
    assert len(found)==1,("expected exactly one fixed artifact layout",len(found));return found[0]
def restore_predecessor(context,tree,out,inputs):
    root=predecessor_root();saved=out/"predecessor-408";saved.mkdir()
    seal={}
    for name,wanted in [("evidence.tar.xz",INNER),("evidence-members.json",INDEX),("custody.json",CUSTODY)]:
        row=pin(root/name);assert (row["bytes"],row["sha256"])==wanted
        inputs[str(root/name)]=row;seal[name]=row
        shutil.copyfile(root/name,saved/name)
        assert (pin(saved/name)["bytes"],pin(saved/name)["sha256"])==wanted
    index=json.loads((root/"evidence-members.json").read_bytes())
    custody=json.loads((root/"custody.json").read_bytes())
    assert len(index)==616 and sum(r["bytes"] for r in index)==54360446
    assert custody["status"]=="PASS" and custody["scope"]=="namespace-filesystem-fixed-carrier-component"
    assert custody["members"]==616 and custody["original_bytes"]==54360446
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True and custody["whole_stack_closed"] is False
    expected={}
    for row in index:
        rel=PurePosixPath(row["name"]);assert rel.parts and rel.parts[0]=="run" and not rel.is_absolute()
        assert ".." not in rel.parts and "." not in rel.parts and rel.as_posix()==row["name"]
        assert row["name"] not in expected and type(row["bytes"]) is int and row["bytes"]>=0
        assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
        expected[row["name"]]=row
    results={};matches={k:[] for k in SELECTED};checked=[];seen=set();selected_json={}
    json_names={"build":"run/namespace-fixed-carrier/carrier-build-r1/summary.json",
        "native":"run/namespace-fixed-carrier/carrier-native-r1/summary.json","top":"run/summary.json",
        "prior":"run/namespace-fixed-carrier/predecessor-597/original-validation-result.json"}
    with tarfile.open(root/"evidence.tar.xz","r:xz") as archive:
        for item in archive:
            assert item.isfile() and not item.issym() and not item.islnk()
            assert item.name in expected and item.name not in seen
            row=expected[item.name];assert (item.size,item.mode)==(row["bytes"],row["mode"])
            handle=archive.extractfile(item);assert handle is not None;raw=handle.read()
            assert len(raw)==row["bytes"] and sha(raw)==row["sha256"]
            rel=PurePosixPath(item.name);outer=root.joinpath(*rel.parts[1:])
            for p in [outer,*outer.parents]:
                assert not p.is_symlink()
                if p==root:break
            observed=pin(outer);assert (observed["bytes"],observed["sha256"])==(row["bytes"],row["sha256"])
            inputs[str(outer)]=observed
            checked.append(dict(name=item.name,bytes=len(raw),sha256=sha(raw),tar_mode=item.mode,download_mode=observed["mode"]))
            for label,name in json_names.items():
                if item.name==name:selected_json[label]=raw
            for label,(basename,size,digest,target) in SELECTED.items():
                if rel.name==basename and len(raw)==size and sha(raw)==digest:
                    if label in results:assert results[label][0]==raw and results[label][1]==item.mode
                    else:results[label]=(raw,item.mode)
                    matches[label].append(item.name)
            seen.add(item.name)
    assert seen==set(expected) and set(results)==set(SELECTED) and set(selected_json)==set(json_names)
    build=json.loads(selected_json["build"]);native=json.loads(selected_json["native"]);top=json.loads(selected_json["top"])
    prior=json.loads(selected_json["prior"])
    assert sha(selected_json["build"])=="48e33d786e4c61e055b37320a6e50592edbffa5907cf8151e94b1922664af713"
    assert sha(selected_json["native"])=="50ea2284915059a42ae68e924103d7e2db015cf92d0e745d5c61668f98138543"
    assert top["status"]=="PASS" and top["frozen_source_and_reference_before_after_equal"] and top["submitted_script_pins_before_after_equal"]
    assert not top["whole_stack_closed"] and not top["production_activated"]
    assert build["status"]=="PASS_BUILD_ONLY" and build["source_before"]==build["source_after"]
    assert build["packer_entries"]==len(build["packer_controls"])==8
    assert native["status"]=="PASS" and native["source_before"]==native["source_after"]
    assert (native["native_entries"],native["vm_entries"],native["actual_primitive_acks"],native["process_traces_replayed"])==(208,208,89,12)
    tests=native["tests"]
    assert 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==10
    assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    assert prior["status"]=="PASS" and (prior["vm_entries"],prior["native_entries"])==(1038,519)
    assert not native["physical_store_closed"] and not native["migration_closed"]
    selected=[]
    for label,(raw,mode) in results.items():
        target=SELECTED[label][3]
        destination=tree/target if target is not None else saved/"runtime"/SELECTED[label][0]
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open("xb") as f:f.write(raw)
        destination.chmod(mode);assert destination.read_bytes()==raw
        row=pin(destination);row["label"]=label;row["original_members"]=matches[label];selected.append(row)
        if label=="fs_elf":assert mode==0o755;context["filesystem_executable"]=str(destination)
        if label=="fs_image":context["filesystem_image"]=str(destination)
    for label,raw in selected_json.items():(saved/(label+"-original.json")).write_bytes(raw)
    save(saved/"members-readback.json",checked)
    result=dict(status="VERIFIED_PINNED_PREDECESSOR",head=PRIOR_HEAD,run_id=PRIOR_RUN,artifact_id=PRIOR_ARTIFACT,
        members=616,raw_bytes=54360446,seal=seal,selected=selected,
        original_all_member_bytes_sha256_and_inner_modes_verified=True,
        outer_zip_scope="Download-action declaration only; no compressed ZIP hash claim by this reader.",
        original_pack_entries=8,original_carrier_entries=208,original_acks=89,
        new_execution_from_this_restore=0,old_counts_inherited=False)
    save(saved/"verified.json",result)
    return result
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes()
    assert git(raw)==COMMON
    common=module("namespace_inode_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};status="FAIL";details=dict(status="INCOMPLETE",scope="NEW_INODE_WAL_POLICY_WITH_ACTUAL_FS_PROVIDER",
        ordinary_namespace_closed=False,fixed_namespace_coordinator_closed=False,sqlite_migration_closed=False,
        old_kernel_or_carrier_corpus_reexecuted=False,original_ROG_full="FAIL/HOLD unchanged")
    evidence=None;working=[];context=None
    try:
        location=Path(__file__).resolve().parent;inputs[str(Path(__file__).resolve())]=pin(__file__)
        new_paths={}
        for item in FILES:
            path=location/item["name"];data=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(data),sha(data))==(item["bytes"],item["sha256"])
            inputs[str(path)]=pin(path);new_paths[item["name"]]=path
        scripts={}
        for name,blob,size,digest in OLD_SCRIPTS:
            path=location/name;data=common.pinned(path.relative_to(common.REPO).as_posix(),blob)
            assert (len(data),sha(data))==(size,digest)
            inputs[str(path)]=pin(path);scripts[name]=path
        context=common.prepare();base=Path(context["base"])
        ns=base/"namespace-inode-r2-ci";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-inode-r2";evidence.mkdir()
        (evidence/"source").mkdir()
        for path in [Path(__file__),*new_paths.values(),*scripts.values()]:
            target=evidence/"source"/path.name;target.write_bytes(path.read_bytes());target.chmod(stat.S_IMODE(path.stat().st_mode))
        details["predecessor"]=restore_predecessor(context,tree,evidence,inputs)
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as handle:handle.write(new_paths[item["name"]].read_bytes())
                target.chmod(0o644);assert sha(target.read_bytes())==item["sha256"]
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
        (evidence/"compiler").mkdir();(evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence),
            carrier_client=str(scripts["namespace-filesystem-carrier-client.py"]),
            carrier_replay=str(scripts["namespace-filesystem-carrier-replay.py"]))
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        common.run("inode-generation",[context["python"],"-B",Path(__file__),"--generation",context_path],
            cwd=context["reference"],timeout=180)
        generated=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generated["status"]=="GENERATED" and generated["source_unchanged"]
        working.extend(generated["files"]);details["generation"]=generated
        env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)}
        common.run("inode-vm-b3-paired",[context["python"],"-B",new_paths["namespace-inode-r2-validate.py"]],
            cwd=context["reference"],timeout=900,env=env)
        paired=json.loads((evidence/"validation-r1/result.json").read_bytes())
        assert paired["status"]=="PASS" and paired["source_before"]==paired["source_after"]
        assert paired["produced_image_before_after_equal"] and paired["native_entries"]>0
        for row in paired["tests"].values():
            assert row["passed"] and 0<row["tests_loaded"]==row["tests_run"]==len(row["test_ids"])==18
            assert not any(row[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        details["new_protocol_validation"]=paired
        common.run("inode-actual-physical-provider",[context["python"],"-B",new_paths["namespace-inode-r2-physical.py"]],
            cwd=context["reference"],timeout=900,env=env)
        physical=json.loads((evidence/"physical-r1/summary.json").read_bytes())
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        tests=physical["tests"];assert 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==9
        assert tests["passed"] and not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert physical["native_inode_entries"]==physical["vm_inode_entries"]>0
        assert physical["fs_native_entries"]==physical["fs_vm_entries"]>0 and physical["fs_actual_primitive_acks"]>0
        assert physical["actual_provider_commands"]>0 and not physical["fixed_namespace_coordinator_closed"]
        assert not physical["ordinary_store_closed"] and not physical["migration_closed"]
        details["new_physical_validation"]=physical
        details["status"]="PASS";status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
        if evidence is not None:
            for key,rel in [("generation","generation-r1/result.json"),("protocol","validation-r1/result.json"),("physical","physical-r1/summary.json")]:
                path=evidence/rel
                if path.exists():
                    try:details[key+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[key+"_partial_read_error"]=repr(read_error)
    finally:
        details["input_pins"]=list(inputs.values());details["inputs_unchanged"]=all(equal(row) for row in inputs.values())
        details["working_source_before"]=working;details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        common.finish("namespace-inode-policy-component",status,details)
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--generation",type=Path);args=parser.parse_args()
    raise SystemExit(generation(args.generation) if args.generation is not None else main())
