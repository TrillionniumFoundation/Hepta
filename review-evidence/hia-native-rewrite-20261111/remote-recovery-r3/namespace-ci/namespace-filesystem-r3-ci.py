"""Independent GitHub CI startup for reconstructed namespace filesystem r3.
Restored historical artifacts are custody inputs, never new execution counts.
The new HIA image is compiled by the exact retained B3 and executed against
all private syscall-frame controls. This is not an ordinary storage service.
"""
import sys
sys.dont_write_bytecode=True
import argparse,base64,hashlib,importlib.util,json,os,pathlib,shutil,sqlite3,stat,tarfile,traceback
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
BUNDLE_GIT="4a9ac654e496f2bbe2e4067cbec5129ee81b45dc"
BUNDLE_SHA="2a5010afba63239e641af4ddad21cb8799baba857131e443f1aa48901808275d"
VALIDATOR_GIT="105d4a8bd7a05ee37052dada24ddde8dc487710d"
VALIDATOR_SHA="02460a84978d0d218506b0a6b21def854ca070de63624486e284012c4a65f3c0"
GENERATOR_SCRIPT = r'''
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,pathlib,stat,time,traceback
context=json.loads(pathlib.Path(sys.argv[1]).read_bytes())
TREE=pathlib.Path(context["namespace_working"])
REF=pathlib.Path(context["reference"])
OUT=pathlib.Path(context["namespace_evidence"])/"generation-r1"
OUT.mkdir(exist_ok=False)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
pins={}
def pin(p):
    p=pathlib.Path(p).resolve();raw=p.read_bytes()
    pins[str(p)]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(p.stat().st_mode))
    return raw
report=dict(status="INCOMPLETE",scope="NEW_GITHUB_CI_GENERATION_ONLY",native_entries=0,vm_entries=0)
try:
    sys.path.insert(0,str(REF))
    import hepta.hia_agent_assembly,tools.generate_hia_selfhost
    assert pathlib.Path(hepta.hia_agent_assembly.__file__).resolve()==REF/"hepta/hia_agent_assembly.py"
    assert pathlib.Path(tools.generate_hia_selfhost.__file__).resolve()==REF/"tools/generate_hia_selfhost.py"
    module=None
    for name in ["generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_filesystem_r3"]:
        p=TREE/"tools"/(name+".py");raw=pin(p);fullname="tools."+name
        spec=importlib.util.spec_from_file_location(fullname,p)
        module=importlib.util.module_from_spec(spec);sys.modules[fullname]=module
        exec(compile(raw,str(p),"exec"),module.__dict__)
    files=[]
    for row in context["namespace_new_files"]:
        p=pathlib.Path(row["path"]);raw=pin(p)
        assert len(raw)==row["bytes"] and sha(raw)==row["sha256"]
        files.append(row)
    pin(TREE/"docs/HIA_AGENT_NAMESPACE_STORE_ABI.json");pin(__file__)
    for item in tuple(sys.modules.values()):
        filename=getattr(item,"__file__",None)
        if filename:
            p=pathlib.Path(filename).resolve()
            if p.is_relative_to(REF) and p.suffix==".py":pin(p)
    for index,(path,row) in enumerate(pins.items()):
        p=pathlib.Path(path);q=OUT/"source"/str(index)/p.name;q.parent.mkdir(parents=True,exist_ok=True)
        q.write_bytes(p.read_bytes());q.chmod(row["mode"]);assert sha(q.read_bytes())==row["sha256"]
    dump(OUT/"source-before.json",pins)
    started=time.monotonic_ns();doc=module.document()
    profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
        max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
        operations=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
        max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]))
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256 and profile["operations"]<=8192 and profile["max_block_params"]<=16
    source=hepta.hia_agent_assembly.render_assembly(doc).encode()
    target=TREE/"examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm"
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as handle:handle.write(source)
    target.chmod(0o644);(OUT/target.name).write_bytes(source)
    report.update(status="GENERATED",files=files,profile=profile,elapsed_ns=time.monotonic_ns()-started,
                  generated=dict(path=str(target),bytes=len(source),sha256=sha(source)))
except BaseException as error:
    report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    after={p:dict(bytes=len(pathlib.Path(p).read_bytes()),sha256=sha(pathlib.Path(p).read_bytes()),mode=stat.S_IMODE(pathlib.Path(p).stat().st_mode)) for p in pins}
    report.update(source_before=pins,source_after=after,source_unchanged=pins==after)
    if pins!=after:report["status"]="FAIL"
    dump(OUT/"result.json",report)
    print(json.dumps({k:v for k,v in report.items() if k not in ("source_before","source_after","traceback")},sort_keys=True),flush=True)
raise SystemExit(0 if report["status"]=="GENERATED" else 1)
'''
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
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--input-bundle",type=pathlib.Path,default=pathlib.Path(__file__).with_name("namespace-filesystem-r3-input.json"))
    parser.add_argument("--validator",type=pathlib.Path,default=pathlib.Path(__file__).with_name("namespace-filesystem-r3-validate.py"))
    args=parser.parse_args()
    common=load_common()
    details=dict(status="INCOMPLETE",scope="NEW_INDEPENDENT_GITHUB_CI_FS_OWNER_COMPONENT",
        ordinary_namespace_closed=False,physical_syscall_executor_tested=False,sqlite_migration_tested=False,
        restored_historical_counts_inherited=False,original_ROG_prepare_authority_resolved=False,
        new_VM_entries=None,new_actual_native_entries=None)
    status="FAIL";inputs={};namespace_evidence=None
    def input_pin(path,raw=None):
        path=pathlib.Path(path).resolve()
        if raw is None:raw=path.read_bytes()
        assert path.is_file() and not path.is_symlink()
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
        bundle=json.loads(bundle_raw)
        assert bundle["schema"]=="hia.namespace.filesystem-ci-input.v1"
        assert len(bundle["archives"])==9 and len(bundle["files"])==3
        context=common.prepare()
        base=pathlib.Path(context["base"]);source=pathlib.Path(context["source"]);ref=pathlib.Path(context["reference"])
        ns=base/"namespace-ci-fs-r3";ns.mkdir(mode=0o700,exist_ok=False)
        tree=ns/"working-source";tree.mkdir()
        immutable=ns/"immutable";immutable.mkdir()
        namespace_evidence=pathlib.Path(context["output"])/"namespace-fs-r3";namespace_evidence.mkdir()
        (namespace_evidence/"source").mkdir()
        (namespace_evidence/"source"/pathlib.Path(__file__).name).write_bytes(pathlib.Path(__file__).read_bytes())
        (namespace_evidence/"source"/validator_path.name).write_bytes(validator_raw)
        (namespace_evidence/"source"/bundle_path.name).write_bytes(bundle_raw)
        connection=sqlite3.connect(":memory:")
        try:sqlite_source_id=connection.execute("SELECT sqlite_source_id()").fetchone()[0]
        finally:connection.close()
        details["ci_sqlite_observation"]=dict(version=sqlite3.sqlite_version,source_id=sqlite_source_id,
            scope="identity only; no SQLite behavior from ROG is inherited")
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
        context.update(namespace_working=str(tree),namespace_evidence=str(namespace_evidence),namespace_new_files=new_files,
            namespace_ci_scope=details["scope"],namespace_bundle_sha256=BUNDLE_SHA)
        context_path=namespace_evidence/"context.json";dump(context_path,context)
        generation_script=namespace_evidence/"source/generate-ci-r1.py";generation_script.write_text(GENERATOR_SCRIPT)
        common.run("namespace-fs-r3-generate",[context["python"],"-B",generation_script,context_path],cwd=ref,timeout=300)
        generation=json.loads((namespace_evidence/"generation-r1/result.json").read_bytes())
        assert generation["status"]=="GENERATED" and generation["source_unchanged"]
        details["generated"]=generation["generated"];details["profile"]=generation["profile"]
        common.run("namespace-fs-r3-vm-b3-native",[context["python"],"-B",validator_path],cwd=ref,timeout=1800,
                   env={"HIA_NAMESPACE_CI_CONTEXT":str(context_path)})
        report=json.loads((namespace_evidence/"validation-r1/result.json").read_bytes())
        assert report["status"]=="PASS" and report["source_unchanged"] and report["produced_image_before_after_equal"]
        assert report["native_entries"]>0 and report["vm_entries"]>report["native_entries"]
        for label in ("vm","paired"):
            group=report["tests"][label]
            assert group["passed"] and 0<group["tests_run"]==group["tests_loaded"]==len(group["test_ids"])
            assert not any(group[name] for name in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        details.update(status="PASS",new_VM_entries=report["vm_entries"],new_actual_native_entries=report["native_entries"],
            tests={name:dict(tests_run=row["tests_run"],test_ids=row["test_ids"],passed=row["passed"]) for name,row in report["tests"].items()},
            image=report["image"],compile_receipt=report["compile_receipt"],
            full_output_workspace_return_guards_equal=True)
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if namespace_evidence is not None:
            report_path=namespace_evidence/"validation-r1/result.json"
            if report_path.exists():
                report=json.loads(report_path.read_bytes())
                details.update(new_VM_entries=report.get("vm_entries"),new_actual_native_entries=report.get("native_entries"),
                    validation_status=report.get("status"),tests=report.get("tests"),validation_error=report.get("error"))
    finally:
        details["input_pins"]=list(inputs.values())
        checks=[]
        for row in inputs.values():
            p=pathlib.Path(row["path"])
            checks.append(p.is_file() and not p.is_symlink() and p.stat().st_size==row["bytes"] and
                stat.S_IMODE(p.stat().st_mode)==row["mode"] and digest(p.read_bytes())==row["sha256"])
        details["all_input_pins_unchanged"]=all(checks)
        if not all(checks):status="FAIL";details["status"]="FAIL"
        common.finish("namespace-filesystem-r3-component",status,details)
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    raise SystemExit(main())
