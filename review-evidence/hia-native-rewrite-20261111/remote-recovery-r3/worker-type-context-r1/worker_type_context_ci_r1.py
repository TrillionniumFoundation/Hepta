"""Fresh type-context first-error owner and actual public-oracle comparison.

This gate does not activate or claim the full P16/public/namespace route.
All seven groups are attempted independently after three original-budget B3s.
"""
from __future__ import annotations
import ast,importlib.util,json,os,stat,subprocess,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
COMMON_SHA="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
INDEX_PIN={
  "path": "sources.json",
  "mode": "100644",
  "bytes": 7066,
  "sha256": "fa120d308c135f71e55f0731f0c9febdbd6e38f6b988b19318cc3c23e4d0c7cb",
  "gitsha": "13d4316df9c4cf8762d51f696aecd8973b4946db",
  "classification": "NEW_R3_0_AST_0_GENERATION_0_B3_0_NATIVE"
}
COMMON_PATH=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON_PATH.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("worker_type_context_common",COMMON_PATH)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;project=None;own=None;submitted={};failures=[];status="FAIL"
details=dict(schema="hia-worker-type-context-ci-r1",
 scope="THREE_ACTUAL_NATIVE_IMAGES_PUBLIC_TYPE_ERROR_CONTEXT_NOT_WHOLE_P16",
 fresh_compiles_required=3,groups={},completed_cases=0,actual_entries=0,
 original_public_oracle_not_native_enum_table=True,
 type_name_prefix_priority_is_an_explicit_semantic_correction=True,
 old_pass_counts_inherited=False,actual_program_joined=False,
 whole_public_diagnostics_closed=False,whole_worker_closed=False,namespace_issued=False,
 limits=dict(compiler_cpu=10,compiler_wall=20,compiler_address=268435456,
             group_cpu=90,group_wall=180,group_address=1073741824,
             measured_aggregate_cpu_below90=True))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def materialize(row,target):
    assert row["mode"]=="100644"
    raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",row["gitsha"]],cwd=context["repo"])
    assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),row["path"]
    if target.suffix==".py":ast.parse(raw,filename=str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as stream:stream.write(raw)
    target.chmod(0o644);submitted[target]=(raw,0o644)
    return target
def panel(label,args,summary,timeout=180,env=None):
    good=False;report={"status":"MISSING_TERMINAL_SUMMARY"};process=None
    try:common.run(label,args,timeout=timeout,env=env);good=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    try:
        if summary.is_file():report=json.loads(summary.read_bytes())
        path=Path(context["output"])/"steps"/label/"process.json"
        if path.is_file():process=json.loads(path.read_bytes())
        if good:
            assert report["status"]=="PASS"
            if label.startswith("worker-type-context-group-"):
                cpu=process["child_cpu_seconds"]
                assert isinstance(cpu,(int,float)) and 0<=cpu<90,("aggregate process tree CPU",cpu)
                assert report["source_image_before_after_equal"] is True
                assert 0<=report["aggregate_cpu_seconds"]<90
                assert report["original_limits"]==dict(cpu=90,wall=180,address=1<<30)
    except BaseException as exc:
        good=False;failures.append(dict(label=label,error_class="OriginalResultOrBudgetMismatch",
            exception_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        traceback.print_exc()
    row=dict(actual_successful_process=good,original_summary=report,original_process=process)
    details["groups"][label]=row
    print("HIA_WORKER_TYPE_CONTEXT_PANEL "+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
    return good
try:
    context=common.prepare();output=Path(context["output"])
    own=Path(context["base"])/"worker-type-context-ci-source-r1";own.mkdir()
    project=Path(context["base"])/"worker-type-context-native-r1";project.mkdir()
    index_path=materialize(INDEX_PIN,project/"sources.json")
    index=json.loads(index_path.read_bytes())
    assert index["schema"]=="hia-native-type-context-source-index-v1"
    assert len(index["files"])==8 and len(index["groups"])==7
    assert sum(row["cases"] for row in index["groups"])==118 and index["fresh_compiles"]==3
    for row in index["files"]:
        relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
        materialize(row,project/relative)
    external={}
    for row in index["external_restore"]:
        external[Path(row["path"]).name]=materialize(row,own/row["path"])
    save(output/"type-context-submitted-source.json",dict(
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),
        common_gitsha=COMMON_SHA,index=INDEX_PIN,submitted=index))
    common.run("worker-type-context-exact-worker-restore",
        [sys.executable,"-B",external["worker_ci_restore_r2.py"],output/"context.json",
         external["worker_ci_dependencies_r4.json"]],timeout=300)
    work=Path(context["base"])/"worker-recovery/work-r2"
    compiler=work/"dependencies/f50-B3.image.bin";raw=compiler.read_bytes()
    assert (len(raw),digest(raw))==(668608,index["compiler"]["sha256"])
    build=project/"development/build-r1"
    label="worker-type-context-old-new-reader-three-B3"
    built=panel(label,[sys.executable,"-B",project/index["build"],
        "--project",project,"--reference",context["reference"],"--workspace",context["workspace"],
        "--compiler",compiler,"--out",build],build/"summary.json",timeout=300)
    observed_contexts=set();observed_ops=set()
    if built:
        report=details["groups"][label]["original_summary"]
        assert report["actual_compiles"]==3 and report["actual_compile_attempts"]==3
        bundle=json.loads((build/"bundle.json").read_bytes())
        inventory=json.loads(Path(bundle["inventory"]).read_bytes())
        expected_contexts={(row["code"],row["where"],row["mask"]) for row in inventory["rows"]}
        assert len(expected_contexts)==33
        for group in index["groups"]:
            name=group["name"];target=project/"development"/("actual-"+name+"-r1")
            label="worker-type-context-group-"+name
            env=dict(os.environ,HIA_ACCOUNTING_OUTPUT=str(output/(name+"-accounting.json")))
            good=panel(label,[sys.executable,"-B",external["accounted_full_initializer_r4.py"],
                project/index["test"],"--project",project,"--bundle",build/"bundle.json",
                "--reference",context["reference"],"--out",target,"--group",name],
                target/"summary.json",env=env)
            actual=details["groups"][label]["original_summary"]
            for key in ("completed_cases","actual_entries"):
                value=actual.get(key,0);assert type(value) is int and value>=0
                details[key]+=value
            if good:
                try:
                    assert actual["completed_cases"]==group["cases"]
                    assert actual["original_oracle_predeclared_before_native"] is True
                    assert actual["actual_entries"]>0
                    observed_contexts.update(tuple(row) for row in actual["actual_context_tuples"])
                    observed_ops.update(actual["actual_type_operations"])
                except BaseException as exc:
                    failures.append(dict(label=label,error_class="ActualCoverageMismatch",
                        exception_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
                    traceback.print_exc()
        details["actual_context_tuples"]=[list(row) for row in sorted(observed_contexts)]
        details["actual_type_operations"]=sorted(observed_ops)
    else:details["runtime_groups"]="NOT_RUN_BUILD_FAILED"
    assert all(path.is_file() and path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
               for path,(raw,mode) in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON_PATH.read_bytes()==common_raw
    restore=json.loads((output/"worker-restore/input-pins.json").read_bytes())
    assert all(Path(row["path"]).is_file() and Path(row["path"]).stat().st_size==row["bytes"]
               and digest(Path(row["path"]).read_bytes())==row["sha256"]
               and stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"] for row in restore)
    details["all_submitted_and_restore_sources_unchanged"]=True
    if built and not failures:
        assert len(details["groups"])==8 and details["completed_cases"]==118
        assert observed_contexts==expected_contexts,(sorted(observed_contexts),sorted(expected_contexts))
        assert observed_ops==set(range(1,7)),observed_ops
        assert all(row["actual_successful_process"] for row in details["groups"].values())
        status="PASS"
except BaseException as exc:
    failures.append(dict(label="driver",error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    details["failures"]=failures;roots={}
    if project is not None and project.exists():roots["worker-type-context"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    common.finish("worker-type-context-original-public-oracle-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
