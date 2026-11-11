"""NEW complete FS-r4 F_GETLK extension gate with fresh VM/B3/actual ELF.

All fourteen old protocol methods and ten actual physical methods are retained.
Four new protocol and two new real-process methods cover F_GETLK. Prior r3
archive is read back, never counted as new execution. Whole Store remains open.
"""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json,os,shutil,stat,tarfile,traceback
from pathlib import Path,PurePosixPath
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=[{"name":"namespace-filesystem-r4-generator.py","target":"tools/generate_hia_agent_namespace_filesystem_r4.py","blob":"76f06947a0127878740f4fcd97401be1830295c5","bytes":22300,"sha256":"06d4b13cf61d3ad8b8f02892b6259653e6b71b089fbf5f665c7b73dbad95bfc7"},{"name":"namespace-filesystem-r4-protocol.py","target":"tests/test_hia_agent_namespace_filesystem_r4.py","blob":"474bf61af7fab0c69f938f948fbcce4823f9d7c3","bytes":21478,"sha256":"afcb7a6ed3f51db56deeade0094b38983b4dc94d59f6c78f2e40ed38a40f0315"},{"name":"namespace-filesystem-r4-abi.json","target":"docs/HIA_AGENT_NAMESPACE_FILESYSTEM_R4_ABI.json","blob":"02266a61416a719c7e0327a058bad5e18dc54a19","bytes":3537,"sha256":"c55fd2d2027d264629c16f55719fe4f982eef82f759db90acea94493651dc3ef"},{"name":"namespace-filesystem-r4-validate.py","target":None,"blob":"059e856fcdf23d27a1bdb577d20bfdcaf2d1a1d6","bytes":11901,"sha256":"d1fc34b1f4af890995f114943a827e41272951884e66c49eb3e7c890d611af21"},{"name":"namespace-filesystem-r4-executor.S","target":None,"blob":"acb98d8b4b7dc6a52de790288d0c15d705980acb","bytes":20874,"sha256":"b2389a0528c5a22960d978c95aaf97c32bc1f829fe49ac80e70f8a31fa6228cb"},{"name":"namespace-filesystem-r4-packer.py","target":None,"blob":"4fcc35ed36568f592251e458052ed891b003defe","bytes":4505,"sha256":"32d433607cb544f00113a5de1a36add37934667b49f3ee012a733d4470f46a8a"},{"name":"namespace-filesystem-r4-build.py","target":None,"blob":"63fce5dc4713399b0531de82e9ed98a1a7de66b8","bytes":16510,"sha256":"e1e75271aed34ffa44cad32945aef2792f4135487ab1745555a18c5e730d56bf"},{"name":"namespace-filesystem-r4-native.py","target":None,"blob":"00742a2204780501456091f74339797740e19db5","bytes":31800,"sha256":"f6156010bf69c326ea08c0cab0402235cd1f8be0735a3f2d6b0e45684ec67b07"},{"name":"namespace-filesystem-r4-replay.py","target":None,"blob":"b1c4ec8f6bdca8bfadd1fd0e58ec55de891ffb8d","bytes":7977,"sha256":"74513037d67aae79d0d53b951689584feae21ec93756bf91ebedb4d4d79d9ef6"}]
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
OLD_SCRIPTS=[("namespace-filesystem-carrier-client.py","e2ad618d57469727d46d04dbdba7c8f85b4f973c",11458,"00981a3f7bbd195dd5522858d6c032e19a4789900317ff8637be1d811a77893d")]
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
    out.mkdir();before={};report=dict(status="INCOMPLETE",scope="NEW_FS_R4_SOURCE_GENERATION_ONLY")
    source=None
    try:
        for p in sorted(tree.rglob("*")):
            if p.is_file():before[str(p)]=pin(p)
        sys.path.insert(0,str(ref))
        for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_filesystem_r4"):
            m=module("tools."+name,tree/"tools"/(name+".py"))
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        doc=m.document();save(out/"generated-document.json",doc)
        source=render_assembly(doc).encode()
        (out/"agent_namespace_filesystem_r4.hiaasm").write_bytes(source)
        profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
            max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
            ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
            max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]))
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_block_params"]<=16
        assemble_program(source)
        target=tree/"examples/hia_bootstrap/agent_namespace_filesystem_r4.hiaasm"
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
    common=module("namespace_fs_r4_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    inputs={};status="FAIL";details=dict(status="INCOMPLETE",scope="NEW_FS_R4_F_GETLK_EXTENSION_ALL_RETAINED_AND_NEW_COMPONENT_GATES",
        ordinary_namespace_closed=False,fixed_namespace_coordinator_closed=False,sqlite_migration_closed=False,
        prior_counts_inherited=False,retained_protocol_methods_reexecuted=14,retained_carrier_methods_reexecuted=10,
        original_ROG_full="FAIL/HOLD unchanged")
    evidence=None;working=[];context=None
    try:
        location=Path(__file__).resolve().parent;inputs[str(Path(__file__).resolve())]=pin(__file__)
        paths={}
        for item in FILES:
            path=location/item["name"];data=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(data),sha(data))==(item["bytes"],item["sha256"])
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        for name,blob,size,digest in OLD_SCRIPTS:
            path=location/name;data=common.pinned(path.relative_to(common.REPO).as_posix(),blob)
            assert (len(data),sha(data))==(size,digest)
            inputs[str(path)]=pin(path);paths[name]=path
        context=common.prepare();base=Path(context["base"])
        ns=base/"namespace-ci-fs-r4";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-filesystem-r4";evidence.mkdir()
        (evidence/"source").mkdir()
        for path in [Path(__file__),*paths.values()]:
            target=evidence/"source"/path.name;target.write_bytes(path.read_bytes());target.chmod(stat.S_IMODE(path.stat().st_mode))
        details["historical_predecessor"]=restore_predecessor(context,tree,evidence,inputs)
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as handle:handle.write(paths[item["name"]].read_bytes())
                target.chmod(0o644);assert sha(target.read_bytes())==item["sha256"]
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
        (evidence/"compiler").mkdir();(evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence))
        assert "namespace_predecessor" not in context
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        common.run("filesystem-r4-generation",[context["python"],"-B",Path(__file__),"--generation",context_path],
            cwd=context["reference"],timeout=180)
        generated=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generated["status"]=="GENERATED" and generated["source_unchanged"]
        working.extend(generated["files"]);details["generation"]=generated
        env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)}
        common.run("filesystem-r4-vm-b3-paired",[context["python"],"-B",paths["namespace-filesystem-r4-validate.py"]],
            cwd=context["reference"],timeout=900,env=env)
        paired=json.loads((evidence/"validation-r1/result.json").read_bytes())
        assert paired["status"]=="PASS" and paired["source_before"]==paired["source_after"]
        assert paired["produced_image_before_after_equal"] and paired["native_entries"]>0
        assert set(paired["tests"])=={"vm","paired"}
        for row in paired["tests"].values():
            assert row["passed"] and 0<row["tests_loaded"]==row["tests_run"]==len(row["test_ids"])==18
            assert not any(row[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        details["new_protocol_validation"]=paired
        common.run("filesystem-r4-fixed-carrier-build",
            [context["python"],"-B",paths["namespace-filesystem-r4-build.py"],
             "--context",context_path,"--executor",paths["namespace-filesystem-r4-executor.S"],
             "--packer",paths["namespace-filesystem-r4-packer.py"]],cwd=context["reference"],timeout=180)
        built=json.loads((evidence/"carrier-build-r1/summary.json").read_bytes())
        assert built["status"]=="PASS_BUILD_ONLY" and built["source_pins_unchanged"]
        assert built["packer_entries"]==len(built["packer_controls"])==8 and built["actual_carrier_processes"]==0
        assert built["kernel_image_sha256"]==paired["image"]["sha256"]
        assert built["kernel_source_sha256"]==paired["source_sha256"]
        details["new_fixed_carrier_build"]=built
        common.run("filesystem-r4-actual-physical",
            [context["python"],"-B",paths["namespace-filesystem-r4-native.py"],
             "--context",context_path,"--client",paths["namespace-filesystem-carrier-client.py"],
             "--replay",paths["namespace-filesystem-r4-replay.py"]],cwd=context["reference"],timeout=900)
        native=json.loads((evidence/"carrier-native-r1/summary.json").read_bytes())
        assert native["status"]=="PASS" and native["source_pins_unchanged"]
        tests=native["tests"];assert 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==12
        assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert native["native_entries"]==native["vm_entries"]>0 and native["actual_primitive_acks"]>0
        assert native["process_traces_replayed"]==len(native["replay"])>0
        for key in ("all22_actual_primitives","all23_actual_primitives","actual_raw_fd_zero",
                    "truncated_transport_process_lock_released","actual_wal_byte120_both_directions",
                    "actual_alias_close_drops_lock","parent_death_child_termination",
                    "actual_getlk_is_query_not_acquire","actual_getlk_own_process_is_invisible"):
            assert native["observations"][key] is True
        assert native["observations"]["actual_getlk_foreign_writer_pid"]>0
        assert native["observations"]["actual_getlk_invalid_kind_errno"]>0
        assert not native["physical_store_closed"] and not native["migration_closed"] and not native["public_root_policy_closed"]
        details["new_physical_validation"]=native
        details.update(status="PASS",new_protocol_vm_entries=paired["vm_entries"],
            new_protocol_native_entries=paired["native_entries"],new_packer_entries=built["packer_entries"],
            new_actual_carrier_entries=native["native_entries"],new_actual_acks=native["actual_primitive_acks"])
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
        if evidence is not None:
            for key,rel in [("generation","generation-r1/result.json"),("protocol","validation-r1/result.json"),
                            ("build","carrier-build-r1/summary.json"),("physical","carrier-native-r1/summary.json")]:
                path=evidence/rel
                if path.exists():
                    try:details[key+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[key+"_partial_read_error"]=repr(read_error)
    finally:
        details["input_pins"]=list(inputs.values());details["inputs_unchanged"]=all(equal(row) for row in inputs.values())
        details["working_source_before"]=working;details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        common.finish("namespace-filesystem-r4-getlk-component",status,details)
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--generation",type=Path);args=parser.parse_args()
    raise SystemExit(generation(args.generation) if args.generation is not None else main())
