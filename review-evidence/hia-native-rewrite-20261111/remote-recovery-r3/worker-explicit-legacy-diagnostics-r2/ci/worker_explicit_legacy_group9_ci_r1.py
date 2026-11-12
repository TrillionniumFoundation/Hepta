"""First independent complete explicit legacy Group9 diagnostic integration.

Original R9 restoration is a read-only dependency gate. Four fresh original-limit
B3 images and two actual HIA packing entries precede seven new runtime groups.
Each public oracle is the unchanged explicit import_legacy_composite_v2; code4
is private-only. No ordinary P16, namespace or installed selector is activated.
"""
from __future__ import annotations
import ast,importlib.util,json,os,stat,subprocess,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
COMMON_SHA="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
INDEX_PIN={"path":"sources.json","mode":"100644","bytes":10224,"sha256":"8063d71f42b397ff911b398d5ce35d01cc78ee4c687776d624854ba120ece304","gitsha":"64483be9c624971ce69c4a5aa5f8e27cea544d9f"}
COMMON_PATH=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def mode(path):return stat.S_IMODE(path.lstat().st_mode)
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n");path.chmod(0o644)
common_raw=COMMON_PATH.read_bytes();common_mode=mode(COMMON_PATH)
assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("legacy_Group9_exact_common",COMMON_PATH)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_path=Path(__file__).resolve();self_raw=self_path.read_bytes();self_mode=mode(self_path)
context=None;project=None;own=None;original_root=None;submitted={};oracle={};status="FAIL"
failures=[];details=dict(schema="hia-explicit-legacy-complete-group9-ci-r1",
    scope="FIRST_EXPLICIT_IMPORTER_COMPLETE_GROUP9_HIA_AND_FIXED_ELF_DEVELOPMENT",
    status="INCOMPLETE",groups={},planned_cases=70,planned_public_ELF=22,
    planned_private_cases=48,planned_private_entries=130,planned_old_entries=4,
    planned_new_entries=126,planned_B3=4,planned_packer_entries=2,
    completed_cases=0,actual_public_processes=0,actual_private_entries=0,
    code4_public_reachability_claimed=False,ordinary_P16_changed=False,
    old_tests_reexecuted=False,old_case_counts_inherited=False,
    namespace_authority=False,whole_Worker_closed=False,installed_activation=False)
def materialize(row,target):
    assert row["mode"]=="100644" and len(row["gitsha"])==40
    raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",row["gitsha"]],cwd=context["repo"])
    assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),row["path"]
    if target.suffix==".py":ast.parse(raw,filename=str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as f:f.write(raw)
    target.chmod(0o644);submitted[target]=(raw,0o644)
    return target
def verify_plain(path,raw,permissions):
    assert path.is_file() and not path.is_symlink() and mode(path)==permissions
    assert path.read_bytes()==raw
def import_inventory(reference,index):
    # Parse original and submitted Python imports, without importing a target.
    # Embedded HIA strings contain no Python module execution.
    visited={};external=set();pending=[]
    for row in index["files"]:
        if row["path"].endswith(".py"):
            rel=Path(row["path"]);name=".".join(rel.with_suffix("").parts)
            if rel.parts[0]=="development":name=rel.stem
            pending.append((name,project/rel))
    def resolve(name):
        relative=Path(*name.split("."))
        candidates=[project/relative.with_suffix(".py"),reference/relative.with_suffix(".py")]
        if "." not in name:candidates.insert(0,project/"development"/(name+".py"))
        for path in candidates:
            if path.is_file():return path
        for base in (project,reference):
            path=base/relative/"__init__.py"
            if path.is_file():return path
        if name in ("tools","hepta"):return None
        raise AssertionError(("unresolved project import",name))
    while pending:
        name,path=pending.pop();path=path.resolve()
        if path in visited:continue
        raw=path.read_bytes();permissions=mode(path);assert not path.is_symlink()
        tree=ast.parse(raw,filename=str(path));visited[path]=dict(
            module=name,path=str(path),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=permissions)
        oracle[path]=(raw,permissions)
        pkg=name if path.name=="__init__.py" else name.rpartition(".")[0]
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.extend(alias.name for alias in node.names)
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    parts=pkg.split(".") if pkg else []
                    assert node.level<=len(parts)+1,(name,node.level)
                    base=".".join(parts[:len(parts)+1-node.level])
                    module=".".join(v for v in (base,node.module) if v)
                else:module=node.module or ""
                if module:imports.append(module)
                if module in ("tools","hepta") or node.module is None:
                    for alias in node.names:
                        full=".".join(v for v in (module,alias.name) if v)
                        if alias.name!="*" and any(p.is_file() for p in (
                                project/Path(*full.split(".")).with_suffix(".py"),
                                reference/Path(*full.split(".")).with_suffix(".py"))):
                            imports.append(full)
        for module in imports:
            root=module.split(".")[0]
            if root in ("tools","hepta") or (project/"development"/(root+".py")).is_file():
                found=resolve(module)
                if found is not None:pending.append((module,found))
            else:external.add(root)
    return dict(status="PASS",sources=sorted(visited.values(),key=lambda r:r["path"]),
        external_module_roots=sorted(external),project_imports_executed=0,new_B3_at_gate=0,
        new_target_entries_at_gate=0,all_actual_static_project_imports_resolved=True,
        complete_original_reference_tree_independently_verified_by_common=True)
def panel(label,args,summary,timeout=180,env=None,runtime=False,reader=False):
    good=False;report={"status":"MISSING_TERMINAL_SUMMARY"};process=None
    try:common.run(label,args,timeout=timeout,env=env);good=True
    except BaseException as exc:
        failures.append(dict(label=label,type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        traceback.print_exc()
    try:
        if summary.is_file():report=json.loads(summary.read_bytes())
        process_path=Path(context["output"])/"steps"/label/"process.json"
        if process_path.is_file():process=json.loads(process_path.read_bytes())
        if good:
            assert report["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
            if runtime or reader:
                assert 0<=process["child_cpu_seconds"]<90
                assert 0<=process["elapsed_ns"]<180_000_000_000
            if runtime:
                assert report["original_limits"]==dict(cpu=90,wall=180,address=1<<30)
                assert 0<=report["aggregate_cpu_seconds"]<90
                assert report["source_image_executable_before_after_equal"] is True
                assert report["complete_original_inputs_outputs_retained"] is True
                assert report["errors"]==[] and report["primary"] is None
    except BaseException as exc:
        good=False;failures.append(dict(label=label,type="ActualResultOrBudgetMismatch",
            original_exception=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        traceback.print_exc()
    row=dict(actual_successful_process=good,original_summary=report,original_process=process)
    details["groups"][label]=row
    print("HIA_EXPLICIT_LEGACY_PANEL "+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
    return good
try:
    context=common.prepare();output=Path(context["output"])
    project=Path(context["base"])/"worker-explicit-legacy-group9-r1";project.mkdir()
    own=Path(context["base"])/"worker-explicit-legacy-ci-source-r1";own.mkdir()
    original_root=Path(context["base"])/"worker-explicit-legacy-R9-originals-r1"
    index_path=materialize(INDEX_PIN,project/"sources.json");index=json.loads(index_path.read_bytes())
    assert index["schema"]=="hia-explicit-legacy-group9-source-index-r2" and len(index["files"])==15
    assert index["planned"]==dict(fresh_B3=4,actual_HIA_packer=2,public_ELF=22,
        private_cases=48,total_cases=70,public_groups=6,private_groups=1,nonzero_roles=37,retained_roles=36)
    assert sum(r["cases"] for r in index["groups"])==70 and len(index["groups"])==7
    assert [r["name"] for r in index["groups"]]==["exact-fields","wrong-profile","accepted-small",
        "renamed-byte-equal","renamed-byte-over-one","renamed-byte-over-two","private-continuations"]
    for row in index["files"]:
        relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
        materialize(row,project/relative)
    for row in index["original_oracle"]:
        relative=Path(row["path"]);assert relative.parts[0]=="hepta" and ".." not in relative.parts
        path=Path(context["reference"])/relative;raw=path.read_bytes();permissions=mode(path)
        assert not path.is_symlink() and permissions==0o644
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
        ast.parse(raw,filename=str(path));oracle[path]=(raw,permissions)
        target=project/"reference"/relative.name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(permissions);submitted[target]=(raw,permissions)
    external={}
    for row in index["external_restore"]:
        external[Path(row["path"]).name]=materialize(row,own/row["path"])
    closure=import_inventory(Path(context["reference"]),index)
    save(output/"all-authoring-and-oracle-static-imports-before-B3.json",closure)
    save(output/"submitted-sources.json",dict(index=INDEX_PIN,contents=index,
        self=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),
        common_gitsha=COMMON_SHA,source_before=closure))
    common.run("legacy-group9-exact-worker-dependency-restore",
        [sys.executable,"-B",external["worker_ci_restore_r2.py"],output/"context.json",
         external["worker_ci_dependencies_r4.json"]],timeout=300)
    compiler=Path(context["base"])/"worker-recovery/work-r2/dependencies/f50-B3.image.bin"
    raw=compiler.read_bytes()
    assert (len(raw),digest(raw))==(index["compiler"]["bytes"],index["compiler"]["sha256"])
    submitted[compiler]=(raw,mode(compiler))
    restored=panel("legacy-group9-complete-R9-original-restoration",
        [sys.executable,"-B",project/index["restore"],"--repo",context["repo"],"--out",original_root],
        original_root/"summary.json",reader=True)
    assert restored
    original=json.loads((original_root/"portable-original-bundle.json").read_bytes())
    assert original["status"]=="VERIFIED_ORIGINAL_BYTES_ONLY"
    assert (original["original_members"],original["original_files"],original["original_raw_file_bytes"])==(2949,2389,71724847)
    assert original["new_B3"]==original["new_native"]==0
    restoration=details["groups"]["legacy-group9-complete-R9-original-restoration"]["original_summary"]
    assert restoration["complete_original_members_retained_and_verified"] is True
    assert restoration["pending"]==[] and restoration["after_errors"]==[] and restoration["primary"] is None
    build=project/"development/build-r1"
    built=panel("legacy-group9-four-B3-and-two-complete-HIA-packers",
        [sys.executable,"-B",project/index["build"],"--project",project,
         "--reference",context["reference"],"--original",original_root/"portable-original-bundle.json",
         "--compiler",compiler,"--out",build],build/"summary.json",timeout=300)
    if built:
        built_summary=details["groups"]["legacy-group9-four-B3-and-two-complete-HIA-packers"]["original_summary"]
        assert built_summary["actual_compiles"]==built_summary["actual_compile_attempts"]==4
        assert built_summary["actual_native_packer_entries"]==2 and built_summary["source_and_image_before_after_equal"]
        bundle=json.loads((build/"bundle.json").read_bytes())
        assert bundle["status"]=="BUILT_ONLY" and bundle["original_whole_ELF_reproduced"]
        assert bundle["original_role46_exact_HIA_image_reproduced"] and bundle["original_packer_exact_HIA_image_reproduced"]
        assert len(bundle["components"])==37 and len(bundle["compiled"])==4
        details["original37_source_image_and_whole_ELF_binding"]=True
        details["fresh_actual_B3"]=4;details["fresh_actual_packer_entries"]=2
        for group in index["groups"]:
            name=group["name"];label="legacy-group9-runtime-"+name
            destination=project/"development"/("actual-"+name+"-r1")
            env=dict(os.environ,HIA_ACCOUNTING_OUTPUT=str(output/(name+"-accounting.json")))
            good=panel(label,[sys.executable,"-B",external["accounted_full_initializer_r4.py"],
                project/index["test"],"--bundle",build/"bundle.json","--reference",context["reference"],
                "--out",destination,"--group",name],destination/"summary.json",env=env,runtime=True)
            report=details["groups"][label]["original_summary"]
            for key in ("completed_cases","actual_public_processes","actual_private_entries"):
                number=report.get(key,0);assert type(number) is int and number>=0
                details[key]+=number
            if good:
                try:
                    assert report["completed_cases"]==group["cases"]
                    assert report["actual_public_processes"]==group["public_ELF"]
                    assert report["actual_private_entries"]==group.get("actual_private_entries",0)
                    assert report["actual_private_original_entries"]==group.get("actual_old_entries",0)
                    assert report["failed_public_cases"]==0
                except BaseException as exc:
                    failures.append(dict(label=label,type="CountMismatch",error=str(exc),traceback=traceback.format_exc()))
        if not failures:
            assert len(details["groups"])==9
            assert all(r["actual_successful_process"] for r in details["groups"].values())
            assert details["completed_cases"]==70 and details["actual_public_processes"]==22
            assert details["actual_private_entries"]==130
            status="PASS"
    else:details["runtime_groups_not_run"]="BUILD_DID_NOT_PASS"
except BaseException as exc:
    failures.append(dict(label="driver",type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    after=[]
    for path,(raw,permissions) in {**submitted,**oracle,
            self_path:(self_raw,self_mode),COMMON_PATH:(common_raw,common_mode)}.items():
        try:verify_plain(path,raw,permissions)
        except BaseException as exc:after.append(dict(path=str(path),type=type(exc).__name__,error=str(exc)))
    if context is not None:
        worker_pins=Path(context["output"])/"worker-restore/input-pins.json"
        try:
            rows=json.loads(worker_pins.read_bytes()) if worker_pins.is_file() else []
            assert type(rows) is list
            for row in rows:
                path=Path(row["path"]);raw=path.read_bytes()
                assert not path.is_symlink() and mode(path)==row["mode"]
                assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
        except BaseException as exc:after.append(dict(phase="worker-restoration-after",type=type(exc).__name__,error=str(exc)))
        if original_root is not None and (original_root/"all-inputs-and-materialized-pins.json").is_file():
            try:
                table=json.loads((original_root/"all-inputs-and-materialized-pins.json").read_bytes())
                for collection in table.values():
                    for row in collection.values():
                        path=Path(row["path"]);raw=path.read_bytes()
                        assert not path.is_symlink() and mode(path)==row["mode"]
                        assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
            except BaseException as exc:after.append(dict(phase="all-R9-originals-after",type=type(exc).__name__,error=str(exc)))
    if after:status="FAIL";failures.append(dict(label="source-custody",after_errors=after))
    details["all_available_source_dependency_oracle_bytes_modes_unchanged"]=not after
    details["failures"]=failures;details["status"]=status
    roots={}
    if project is not None and project.exists():roots["explicit-legacy-group9"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    if original_root is not None and original_root.exists():roots["complete-R9-originals"]=original_root
    common.finish("explicit-legacy-group9-full-native-diagnostics-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
