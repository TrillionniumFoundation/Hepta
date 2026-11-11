"""NEW fixed filesystem carrier-only CI using exact previously sealed kernel bytes.

The original 597 kernel VM/native groups are read back, never rerun or counted
as new entries. New packer controls and actual static-ELF operations are separate.
This is a component development gate, not an ordinary AgentStore qualification.
"""
import sys
sys.dont_write_bytecode=True
import argparse,base64,hashlib,importlib.util,json,os,pathlib,sqlite3,stat,tarfile,traceback
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
BUNDLE_GIT="4a9ac654e496f2bbe2e4067cbec5129ee81b45dc"
BUNDLE_SHA="2a5010afba63239e641af4ddad21cb8799baba857131e443f1aa48901808275d"
VALIDATOR_GIT="546fd4a8418e50b8f2a3ecb619d90013ff232276"
VALIDATOR_SHA="d88e50137c509ad9290e016271d669b1dd04f95b12a29d55520f0387fedfd4c5"
CARRIER_FILES=[["namespace-filesystem-executor.S","2c12d781ef6d3948d3d4a0ccfb863388b1142cf0","fb28a7a44448c06fb12654ae8bf6b06fb19be30a4fb7556cf0a7c038b522b90e",20200],["namespace-filesystem-packer.py","dfe670251cbd2aacd3ead14ea215ce51aee8c806","f3c1d1208f59bdecd97075c339fbb3093bc01940d639d3ecde2bea9ab397b0bb",4507],["namespace-filesystem-carrier-build.py","62610ead5d17aec50b19866cdecc45fc44e11bdb","512589f00c0c9bcdc95b06001ec87c350d3d3a5949ea6efbece9af6254fa520e",17349],["namespace-filesystem-carrier-client.py","e2ad618d57469727d46d04dbdba7c8f85b4f973c","00981a3f7bbd195dd5522858d6c032e19a4789900317ff8637be1d811a77893d",11458],["namespace-filesystem-carrier-replay.py","de55990f1f5837c7ab5b9a85c4cfed5b9e30dde3","d81356c9bdee5889f562720048b1ac654cfd74f02cb16bb61ff55f1e675c3881",7961],["namespace-filesystem-carrier-native.py","c598b4b4b10b16a2b3bfd218b95006e4857522ca","791b61c98d2a7e365cf681b3e3837786dd8e808ba31fef6e33aced23b980399c",27798]]
def digest(raw):return hashlib.sha256(raw).hexdigest()
def git_blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def dump(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load_common():
    path=pathlib.Path(os.environ["HIA_CI_COMMON"]).resolve()
    raw=path.read_bytes();assert git_blob(raw)==COMMON_GIT
    spec=importlib.util.spec_from_file_location("hia_namespace_ci_common",path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__)
    assert module.pinned(path.relative_to(module.REPO).as_posix(),COMMON_GIT)==raw
    return module

PREDECESSOR_HEAD="597f5b2f3772d0b4b85cec86492643f71a60966f"
PREDECESSOR_RUN=43103197988
PREDECESSOR_ARTIFACT=13893575504
PREDECESSOR_INNER_BYTES=5824848
PREDECESSOR_INNER_SHA="cc7b386d09e17ef4b11f486642394b8aab50346bd2586f72fae1260d553eb728"
PREDECESSOR_INDEX_BYTES=46391
PREDECESSOR_INDEX_SHA="e91720af6af64293f32e1e289898479c1621a4f538a50d8417c3ed69e5280e31"
PREDECESSOR_MEMBERS=145
PREDECESSOR_RAW_BYTES=43466360

def predecessor_directory():
    """Accept the direct single-artifact layout or one literal artifact-name wrapper.
    Do not search unrelated paths or recursively discover arbitrary archives.
    """
    supplied=pathlib.Path(os.environ["HIA_NAMESPACE_PREDECESSOR_DIR"]).absolute()
    assert supplied.is_dir() and not supplied.is_symlink()
    label="hia-namespace-recovery-43103197988-1"
    candidates=[supplied/"hia-namespace-recovery",
                supplied/label/"hia-namespace-recovery"]
    if supplied.name=="hia-namespace-recovery":
        candidates.append(supplied)
    existing=[]
    for path in candidates:
        if not (path/"evidence.tar.xz").exists():
            continue
        assert path.is_dir() and not path.is_symlink()
        for parent in [path,*path.parents]:
            if parent==supplied.parent:
                break
            assert not parent.is_symlink(),str(parent)
        existing.append(path)
    assert len(existing)==1,("expected exactly one fixed predecessor layout",len(existing))
    return existing[0]

def verified_predecessor(context,tree,evidence,immutable,captured,bundle_raw,validator_raw,input_pin):
    root=predecessor_directory()
    archive_path=root/"evidence.tar.xz"
    index_path=root/"evidence-members.json"
    custody_path=root/"custody.json"
    archive_raw=input_pin(archive_path)
    index_raw=input_pin(index_path)
    custody_raw=input_pin(custody_path)
    assert len(archive_raw)==PREDECESSOR_INNER_BYTES and digest(archive_raw)==PREDECESSOR_INNER_SHA
    assert len(index_raw)==PREDECESSOR_INDEX_BYTES and digest(index_raw)==PREDECESSOR_INDEX_SHA
    index=json.loads(index_raw);custody=json.loads(custody_raw)
    assert isinstance(index,list) and len(index)==PREDECESSOR_MEMBERS
    assert custody["schema"]=="hia-independent-ci-artifact-custody-v1"
    assert custody["scope"]=="namespace-filesystem-r3-component" and custody["status"]=="PASS"
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    assert custody["bytes"]==PREDECESSOR_INNER_BYTES and custody["sha256"]==PREDECESSOR_INNER_SHA
    assert custody["member_index_bytes"]==PREDECESSOR_INDEX_BYTES
    assert custody["member_index_sha256"]==PREDECESSOR_INDEX_SHA
    assert custody["members"]==PREDECESSOR_MEMBERS and custody["original_bytes"]==PREDECESSOR_RAW_BYTES
    assert custody["whole_stack_closed"] is False
    expected={}
    for row in index:
        name=row["name"];rel=pathlib.PurePosixPath(name)
        assert not rel.is_absolute() and rel.parts and rel.parts[0]=="run"
        assert ".." not in rel.parts and "." not in rel.parts and rel.as_posix()==name
        assert name not in expected
        assert type(row["bytes"]) is int and row["bytes"]>=0
        assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
        assert isinstance(row["sha256"],str) and len(row["sha256"])==64
        expected[name]=row
    assert sum(r["bytes"] for r in expected.values())==PREDECESSOR_RAW_BYTES
    restored=immutable/"verified-predecessor-597"
    restored.mkdir(mode=0o700,exist_ok=False)
    checked=[];seen=set()
    with tarfile.open(archive_path,"r:xz") as archive:
        for entry in archive:
            assert entry.isfile() and not entry.issym() and not entry.islnk()
            assert entry.name in expected and entry.name not in seen
            row=expected[entry.name]
            assert entry.size==row["bytes"] and entry.mode==row["mode"]
            stream=archive.extractfile(entry);assert stream is not None
            raw=stream.read();assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
            rel=pathlib.PurePosixPath(entry.name)
            outer=root.joinpath(*rel.parts[1:])
            for part in [outer,*outer.parents]:
                assert not part.is_symlink(),str(part)
                if part==root:
                    break
            external=input_pin(outer)
            assert external==raw
            target=restored.joinpath(*rel.parts)
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as output:output.write(raw)
            target.chmod(entry.mode)
            assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==entry.mode
            checked.append(dict(name=entry.name,bytes=len(raw),sha256=digest(raw),
                tar_mode=entry.mode,download_mode=stat.S_IMODE(outer.stat().st_mode),
                restored_path=str(target),restored_mode=stat.S_IMODE(target.stat().st_mode)))
            seen.add(entry.name)
    assert seen==set(expected) and len(seen)==PREDECESSOR_MEMBERS
    assert digest(archive_path.read_bytes())==PREDECESSOR_INNER_SHA
    assert digest(index_path.read_bytes())==PREDECESSOR_INDEX_SHA
    saved=evidence/"predecessor-597"
    saved.mkdir()
    for name,raw in [("evidence.tar.xz",archive_raw),("evidence-members.json",index_raw),("custody.json",custody_raw)]:
        destination=saved/name
        destination.write_bytes(raw)
        assert destination.read_bytes()==raw
    dump(saved/"independent-member-readback.json",checked)
    prior_root=restored/"run/namespace-fs-r3"
    prior_context=json.loads((prior_root/"context.json").read_bytes())
    prior_summary=json.loads((restored/"run/summary.json").read_bytes())
    generation=json.loads((prior_root/"generation-r1/result.json").read_bytes())
    prior_result_path=prior_root/"validation-r1/result.json"
    prior_raw=prior_result_path.read_bytes();prior=json.loads(prior_raw)
    assert prior_summary["schema"]=="hia-independent-ci-qualification-v1"
    assert prior_summary["scope"]=="namespace-filesystem-r3-component" and prior_summary["status"]=="PASS"
    assert prior_summary["prepared"] is True
    assert prior_summary["frozen_source_and_reference_before_after_equal"] is True
    assert prior_summary["submitted_script_pins_before_after_equal"] is True
    assert prior_summary["whole_stack_closed"] is False and prior_summary["production_activated"] is False
    assert generation["status"]=="GENERATED" and generation["source_unchanged"] is True
    assert generation["source_before"]==generation["source_after"]
    assert prior["status"]=="PASS" and prior["source_unchanged"] is True
    assert prior["source_before"]==prior["source_after"]
    assert prior["produced_image_before_after_equal"] is True
    assert prior["reference_commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
    assert prior["vm_entries"]>prior["native_entries"]>0
    assert set(prior["tests"])=={"vm","paired"}
    for row in prior["tests"].values():
        assert row["passed"] is True
        assert 0<row["tests_loaded"]==row["tests_run"]==len(row["test_ids"])==14
        assert len(set(row["test_ids"]))==14
        assert not any(row[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    assert (prior_root/"source/namespace-filesystem-r3-input.json").read_bytes()==bundle_raw
    assert (prior_root/"source/namespace-filesystem-r3-validate.py").read_bytes()==validator_raw
    old_launcher=(prior_root/"source/namespace-filesystem-r3-ci.py").read_bytes()
    assert git_blob(old_launcher)=="b714a9b5d5b98038f8c0c0377f56b130d57dd0dd"
    old_tree=pathlib.Path(prior_context["namespace_working"])
    for row in captured:
        original=prior["source_before"][str(old_tree/row["relative"])]
        assert (original["bytes"],original["sha256"],original["mode"])==(row["bytes"],row["sha256"],row["mode"])
        assert digest(pathlib.Path(row["path"]).read_bytes())==row["sha256"]
    source=(prior_root/"generation-r1/agent_namespace_filesystem_r3.hiaasm").read_bytes()
    assert digest(source)==generation["generated"]["sha256"]==prior["source_sha256"]
    assert len(source)==generation["generated"]["bytes"]
    target=tree/"examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm"
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as output:output.write(source)
    original=prior["source_before"][str(old_tree/"examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm")]
    assert (original["bytes"],original["sha256"])==(len(source),digest(source))
    target.chmod(original["mode"]);assert target.read_bytes()==source
    old_evidence=pathlib.Path(prior_context["namespace_evidence"])
    image_row=prior["image"]
    old_image=pathlib.Path(image_row["path"])
    image_relative=old_image.relative_to(old_evidence)
    assert image_relative.parts[:2]==("validation-r1","compile")
    image=prior_root/image_relative
    raw_image=image.read_bytes()
    assert len(raw_image)==image_row["bytes"] and digest(raw_image)==image_row["sha256"]
    assert stat.S_IMODE(image.stat().st_mode)==image_row["mode"]
    assert 0<len(raw_image)<=1<<20
    receipt=prior["compile_receipt"]
    assert receipt["input_sha256"]==receipt["source_sha256"]==digest(source)
    assert receipt["artifact_sha256"]==prior["compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    assert receipt["produced_sha256"]==digest(raw_image)
    assert receipt["produced_bytes"]==len(raw_image)
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert receipt["runner_sha256"]==digest((pathlib.Path(context["reference"])/"tools/hia_selfhost_child.py").read_bytes())
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    compile_request=json.loads((prior_root/"validation-r1/compile/namespace-filesystem-r3.request.json").read_bytes())
    assert compile_request["capacity"]==compile_request["workspace_size"]==1<<20
    ledger_relative=pathlib.Path(prior["ledger"]["path"]).relative_to(old_evidence)
    ledger=prior_root/ledger_relative
    assert ledger.stat().st_size==prior["ledger"]["bytes"] and digest(ledger.read_bytes())==prior["ledger"]["sha256"]
    source_pin=dict(path=str(target),bytes=len(source),sha256=digest(source),mode=stat.S_IMODE(target.stat().st_mode))
    verified=dict(status="VERIFIED_ORIGINAL_ARTIFACT",head=PREDECESSOR_HEAD,run_id=PREDECESSOR_RUN,
        artifact_id=PREDECESSOR_ARTIFACT,inner_sha256=PREDECESSOR_INNER_SHA,inner_bytes=PREDECESSOR_INNER_BYTES,
        members=PREDECESSOR_MEMBERS,raw_bytes=PREDECESSOR_RAW_BYTES,
        validation_result=dict(path=str(prior_result_path),bytes=len(prior_raw),sha256=digest(prior_raw)),
        image=dict(path=str(image),bytes=len(raw_image),sha256=digest(raw_image),mode=image_row["mode"]),
        kernel_source=source_pin,original_report_path=str(old_image),
        prior_observations=dict(vm_entries=prior["vm_entries"],native_entries=prior["native_entries"],
            tests=prior["tests"]),
        new_kernel_test_entries=0,prior_counts_are_not_new_execution=True,
        inner_all_member_bytes_sha256_modes_independently_replayed=True,
        downloaded_outer_member_bytes_match_inner=True,downloaded_outer_modes_are_not_source_modes=True,
        source_mode_authority="pinned inner tar plus pinned complete member index",
        compressed_zip_bytes=49378081,compressed_zip_sha256="48e38fb3c2a57b586a77b132ebe17f1dcd72307f4514cb07e33bcc5de9da52a2",
        compressed_zip_digest_scope="GitHub upload declaration; this directory-based reader did not obtain or verify ZIP bytes",
        transport="actions/download-artifact fixed run_id/artifact_id; download directory is not independently an authenticity claim",
        copied_exact_inner_archive=str(saved/"evidence.tar.xz"))
    dump(saved/"verified.json",verified)
    (saved/"original-validation-result.json").write_bytes(prior_raw)
    (saved/"original-generation-result.json").write_bytes((prior_root/"generation-r1/result.json").read_bytes())
    (saved/"original-summary.json").write_bytes((restored/"run/summary.json").read_bytes())
    print(json.dumps(dict(scope="PRIOR_597_OBSERVATIONS_NOT_NEW_ENTRIES",
        run_id=PREDECESSOR_RUN,artifact_id=PREDECESSOR_ARTIFACT,
        vm_entries=prior["vm_entries"],native_entries=prior["native_entries"],
        tests={k:dict(tests_loaded=v["tests_loaded"],tests_run=v["tests_run"],passed=v["passed"]) for k,v in prior["tests"].items()},
        image=image_row,source_sha256=prior["source_sha256"],
        inner_members_replayed=PREDECESSOR_MEMBERS,inner_raw_bytes=PREDECESSOR_RAW_BYTES,
        original_result_sha256=digest(prior_raw)),sort_keys=True),flush=True)
    return verified

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--input-bundle",type=pathlib.Path,default=pathlib.Path(__file__).with_name("namespace-filesystem-r3-input.json"))
    parser.add_argument("--validator",type=pathlib.Path,default=pathlib.Path(__file__).with_name("namespace-filesystem-r3-validate.py"))
    args=parser.parse_args()
    common=load_common()
    details=dict(status="INCOMPLETE",scope="NEW_FIXED_CARRIER_ACTUAL_COMPONENT_WITH_SEALED_597_KERNEL",
        ordinary_namespace_closed=False,physical_syscall_executor_tested=False,sqlite_migration_tested=False,
        restored_historical_counts_inherited=False,original_ROG_prepare_authority_resolved=False,
        new_kernel_VM_entries=0,new_kernel_native_entries=0,
        new_packer_entries=0,new_carrier_VM_entries=0,new_carrier_native_entries=0)
    status="FAIL";inputs={};namespace_evidence=None;working_pins=[]
    def input_pin(path,raw=None):
        path=pathlib.Path(path).absolute()
        assert path.is_file() and not path.is_symlink()
        if raw is None:raw=path.read_bytes()
        row=dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
        if str(path) in inputs:assert inputs[str(path)]==row
        inputs[str(path)]=row
        return raw
    try:
        bundle_path=args.input_bundle.resolve();validator_path=args.validator.resolve()
        bundle_raw=common.pinned(bundle_path.relative_to(common.REPO).as_posix(),BUNDLE_GIT)
        validator_raw=common.pinned(validator_path.relative_to(common.REPO).as_posix(),VALIDATOR_GIT)
        assert digest(bundle_raw)==BUNDLE_SHA and digest(validator_raw)==VALIDATOR_SHA
        input_pin(bundle_path,bundle_raw);input_pin(validator_path,validator_raw);input_pin(__file__)
        carrier_paths={}
        for filename,blob,wanted_sha,wanted_bytes in CARRIER_FILES:
            path=pathlib.Path(__file__).resolve().with_name(filename)
            raw=common.pinned(path.relative_to(common.REPO).as_posix(),blob)
            assert len(raw)==wanted_bytes and digest(raw)==wanted_sha
            input_pin(path,raw);carrier_paths[filename]=path
        bundle=json.loads(bundle_raw)
        assert bundle["schema"]=="hia.namespace.filesystem-ci-input.v1"
        assert len(bundle["archives"])==9 and len(bundle["files"])==3
        context=common.prepare()
        base=pathlib.Path(context["base"]);source=pathlib.Path(context["source"]);ref=pathlib.Path(context["reference"])
        ns=base/"namespace-ci-fs-r3";ns.mkdir(mode=0o700,exist_ok=False)
        tree=ns/"working-source";tree.mkdir()
        immutable=ns/"immutable";immutable.mkdir()
        namespace_evidence=pathlib.Path(context["output"])/"namespace-fixed-carrier";namespace_evidence.mkdir()
        (namespace_evidence/"source").mkdir()
        for path in [pathlib.Path(__file__),bundle_path,validator_path,*carrier_paths.values()]:
            raw=input_pin(path)
            destination=namespace_evidence/"source"/path.name
            destination.write_bytes(raw);destination.chmod(stat.S_IMODE(path.stat().st_mode))
            assert destination.read_bytes()==raw
        connection=sqlite3.connect(":memory:")
        try:sqlite_source_id=connection.execute("SELECT sqlite_source_id()").fetchone()[0]
        finally:connection.close()
        details["ci_sqlite_observation"]=dict(version=sqlite3.sqlite_version,source_id=sqlite_source_id,
            scope="This interpreter only; no ROG or old3.46.1 behavior is inherited.")
        restored=[];by_archive={}
        for expected in bundle["archives"]:
            archive_path=source/expected["path"];raw=input_pin(archive_path)
            assert len(raw)==expected["bytes"] and digest(raw)==expected["sha256"] and git_blob(raw)==expected["git_blob"]
            destination=immutable/expected["label"];destination.mkdir()
            members=[];seen=set()
            with tarfile.open(archive_path,"r:xz") as archive:
                for entry in archive:
                    relative=pathlib.PurePosixPath(entry.name)
                    assert not relative.is_absolute() and relative.parts and ".." not in relative.parts
                    canonical=relative.as_posix();assert canonical not in seen;seen.add(canonical)
                    target=destination/pathlib.Path(*relative.parts)
                    if entry.isdir():
                        target.mkdir(parents=True,exist_ok=True)
                        continue
                    assert entry.isfile() and not entry.issym() and not entry.islnk()
                    handle=archive.extractfile(entry);assert handle is not None
                    content=handle.read();assert len(content)==entry.size
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open("xb") as output:output.write(content)
                    target.chmod(entry.mode)
                    assert target.read_bytes()==content and stat.S_IMODE(target.stat().st_mode)==entry.mode
                    members.append(dict(name=entry.name,path=str(target),bytes=len(content),mode=entry.mode,sha256=digest(content)))
            assert len(members)==expected["regular_members"] and sum(row["bytes"] for row in members)==expected["raw_bytes"]
            assert digest(archive_path.read_bytes())==expected["sha256"]
            restored.append(dict(**expected,members=members));by_archive[expected["label"]]=members
        assert sum(len(row["members"]) for row in restored)==646
        assert sum(item["bytes"] for row in restored for item in row["members"])==67455469
        dump(namespace_evidence/"restored-members.json",restored)
        details["restored_regular_members"]=646
        details["restored_raw_bytes"]=67455469
        captured=[]
        def install(relative,content,mode=0o644):
            target=tree/relative;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as output:output.write(content)
            target.chmod(mode)
            assert target.read_bytes()==content and stat.S_IMODE(target.stat().st_mode)==mode
            evidence=namespace_evidence/"source"/relative;evidence.parent.mkdir(parents=True,exist_ok=True)
            evidence.write_bytes(content);evidence.chmod(mode)
            row=dict(path=str(target),relative=relative,bytes=len(content),mode=mode,sha256=digest(content))
            captured.append(row);return row
        for dependency in bundle["source_dependencies"]:
            rows=by_archive[dependency["archive"]]
            if "member" in dependency:
                matches=[r for r in rows if r["name"]==dependency["member"]]
            else:
                matches=[r for r in rows if pathlib.PurePosixPath(r["name"]).name==dependency["basename"] and r["sha256"]==dependency["sha256"]]
            assert matches
            assert all(row["sha256"]==dependency["sha256"] for row in matches)
            raw=pathlib.Path(matches[0]["path"]).read_bytes();assert digest(raw)==dependency["sha256"]
            install(dependency["target"],raw,matches[0]["mode"])
        new_files=[]
        for entry in bundle["files"]:
            relative=pathlib.PurePosixPath(entry["path"])
            assert not relative.is_absolute() and relative.parts and ".." not in relative.parts
            raw=base64.b64decode(entry["data_base64"],validate=True)
            assert len(raw)==entry["bytes"] and digest(raw)==entry["sha256"] and git_blob(raw)==entry["git_blob"]
            row=install(relative.as_posix(),raw,entry["mode"]);row["git_sha"]=entry["git_blob"]
            new_files.append(row)
        dump(namespace_evidence/"materialized-source.json",captured)
        compiler=pathlib.Path(context["compiler"]);compiler_raw=input_pin(compiler)
        assert len(compiler_raw)==bundle["compiler"]["bytes"]==669556
        assert digest(compiler_raw)==bundle["compiler"]["sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
        (namespace_evidence/"compiler").mkdir()
        copied=namespace_evidence/"compiler/B3.image.bin";copied.write_bytes(compiler_raw)
        assert copied.read_bytes()==compiler_raw

        predecessor=verified_predecessor(context,tree,namespace_evidence,immutable,captured,bundle_raw,validator_raw,input_pin)
        details["prior_597"]=predecessor
        working_pins=captured+[predecessor["kernel_source"]]
        context.update(namespace_working=str(tree),namespace_evidence=str(namespace_evidence),
            namespace_new_files=new_files,namespace_ci_scope=details["scope"],
            namespace_bundle_sha256=BUNDLE_SHA,namespace_predecessor=predecessor)
        context_path=namespace_evidence/"context.json";dump(context_path,context)
        common.run("namespace-fixed-carrier-build",
            [context["python"],"-B",carrier_paths["namespace-filesystem-carrier-build.py"],
             "--context",context_path,"--executor",carrier_paths["namespace-filesystem-executor.S"],
             "--packer",carrier_paths["namespace-filesystem-packer.py"]],cwd=ref,timeout=180)
        built=json.loads((namespace_evidence/"carrier-build-r1/summary.json").read_bytes())
        assert built["status"]=="PASS_BUILD_ONLY" and built["source_pins_unchanged"]
        assert built["packer_entries"]==len(built["packer_controls"])==8
        assert built["actual_carrier_processes"]==0
        details["new_fixed_carrier_build"]=built
        common.run("namespace-fixed-carrier-actual",
            [context["python"],"-B",carrier_paths["namespace-filesystem-carrier-native.py"],
             "--context",context_path,"--client",carrier_paths["namespace-filesystem-carrier-client.py"],
             "--replay",carrier_paths["namespace-filesystem-carrier-replay.py"]],cwd=ref,timeout=600)
        native=json.loads((namespace_evidence/"carrier-native-r1/summary.json").read_bytes())
        assert native["status"]=="PASS" and native["source_pins_unchanged"]
        tests=native["tests"]
        assert 0<tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==10
        assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert native["native_entries"]==native["vm_entries"]>0 and native["actual_primitive_acks"]>0
        assert native["process_traces_replayed"]==len(native["replay"])>0
        for key in ("all22_actual_primitives","actual_raw_fd_zero","truncated_transport_process_lock_released",
                    "actual_wal_byte120_both_directions","actual_alias_close_drops_lock","parent_death_child_termination"):
            assert native["observations"][key] is True
        assert not native["physical_store_closed"] and not native["migration_closed"] and not native["public_root_policy_closed"]
        details.update(new_fixed_carrier_execution=native,physical_syscall_executor_tested=True,
            new_fixed_carrier_native_entries=native["native_entries"],
            new_fixed_carrier_actual_primitive_acks=native["actual_primitive_acks"],
            sqlite_fencing_runtime=native["sqlite"],sqlite_migration_tested=False,
            ordinary_namespace_closed=False)

        details.update(status="PASS",new_packer_entries=built["packer_entries"],
            new_carrier_VM_entries=native["vm_entries"],new_carrier_native_entries=native["native_entries"])
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if namespace_evidence is not None:
            for label,relative in [("new_build","carrier-build-r1/summary.json"),("new_execution","carrier-native-r1/summary.json")]:
                path=namespace_evidence/relative
                if path.exists():
                    try:details[label+"_partial"]=json.loads(path.read_bytes())
                    except BaseException as read_error:details[label+"_partial_read_error"]=str(read_error)
    finally:
        details["input_pins"]=list(inputs.values())
        checks=[]
        for row in inputs.values():
            p=pathlib.Path(row["path"])
            checks.append(p.is_file() and not p.is_symlink() and p.stat().st_size==row["bytes"] and
                stat.S_IMODE(p.stat().st_mode)==row["mode"] and digest(p.read_bytes())==row["sha256"])
        details["all_input_pins_unchanged"]=all(checks)
        materialized=[]
        for row in working_pins:
            p=pathlib.Path(row["path"])
            materialized.append(dict(path=str(p),unchanged=p.is_file() and not p.is_symlink() and
                p.stat().st_size==row["bytes"] and stat.S_IMODE(p.stat().st_mode)==row["mode"] and digest(p.read_bytes())==row["sha256"]))
        details["materialized_source_after"]=materialized
        details["materialized_source_unchanged"]=bool(materialized) and all(r["unchanged"] for r in materialized)
        if not all(checks) or not details["materialized_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        common.finish("namespace-filesystem-fixed-carrier-component",status,details)
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    raise SystemExit(main())
