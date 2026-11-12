"""Fresh P16 actual catalog route, strict original public-text qualification.

All ten groups are attempted independently after a successful seven-B3 build.
Known public contextual-text differences must fail; they are never converted
into expected successes or replaced by the native-adapter enum table.
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
  "bytes": 12465,
  "sha256": "97278cbae63467ad411317421e8b84a5a4385960b63bc3699d970d3775ad35be",
  "gitsha": "a11d4f2dea26e677fd03ba66f8024fbf36d57f79"
}
COMMON_PATH=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON_PATH.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("worker_program_diagnostic_ci_common",COMMON_PATH)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;project=None;own=None;work=None;submitted={};failures=[];status="FAIL"
details=dict(schema="hia-worker-program-fixed-diagnostic-ci-r1",
 scope="NEW_ACTUAL_P16_FIXED_ENUM_ROUTE_WITH_STRICT_ORIGINAL_PUBLIC_TEXT_TESTS",
 fresh_compiles_required=7,retained_source_bound_images=36,nonzero_images=42,
 actual_native_processes=0,actual_private_kernel_entries=0,
 completed_cases=0,failed_case_comparisons=0,attempted_case_results=0,
 public_oracle_is_unselected_original=True,known_public_context_text_open=True,
 native_adapter_table_is_not_public_oracle=True,
 old_pass_counts_inherited=False,ordinary_worker_closed=False,
 initializer_registry_adapter_closed=False,actual_namespace_entries=0,
 groups6_and9_diagnostics_open=True,whole_public_diagnostics_closed=False,
 limits=dict(compiler_cpu=10,compiler_wall=20,compiler_address=268435456,
             group_cpu=90,group_wall=180,group_address=1073741824,
             measured_group_aggregate_cpu_below90=True),groups={})
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
    success=False
    try:
        common.run(label,args,timeout=timeout,env=env);success=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    report=dict(status="MISSING_TERMINAL_SUMMARY");process=None
    try:
        if summary.is_file():report=json.loads(summary.read_bytes())
        path=Path(context["output"])/"steps"/label/"process.json"
        if path.is_file():process=json.loads(path.read_bytes())
    except BaseException as exc:
        failures.append(dict(label=label,error_class="OriginalReportReadFailure",
                             exception_class=type(exc).__name__,error=str(exc)))
        success=False;traceback.print_exc()
    if success and label.startswith("worker-program-diagnostic-group-"):
        actual=process["child_cpu_seconds"]
        if not isinstance(actual,(int,float)) or not 0<=actual<90:
            failures.append(dict(label=label,error_class="AggregateCpuBudgetObservation",
                                 actual_cpu_seconds=actual));success=False
    if success and report.get("status")!="PASS":
        failures.append(dict(label=label,error_class="TerminalSummaryMismatch",
                             summary_status=report.get("status")));success=False
    row=dict(actual_successful_process=success,original_summary=report,original_process=process)
    details["groups"][label]=row
    print("HIA_WORKER_PROGRAM_DIAGNOSTIC_PANEL "+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
    return success
try:
    context=common.prepare();output=Path(context["output"])
    own=Path(context["base"])/"worker-program-diagnostic-ci-source-r1";own.mkdir()
    project=Path(context["base"])/"worker-program-diagnostic-fixed-r1";project.mkdir()
    index_path=materialize(INDEX_PIN,project/"sources.json")
    index=json.loads(index_path.read_bytes())
    assert index["schema"]=="hia-worker-program-diagnostic-source-index-v1" and len(index["files"])==26
    assert index["compiler"]["bytes"]==668608 and index["compiler"]["sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
    assert (index["fresh_compiles"],index["retained_images"],index["nonzero_images"])==(7,36,42)
    assert [row["name"] for row in index["groups"]]==[
       "semantic","assembly-boundary","object-boundary","private-protocol","example-chain",
       "public-fixed","public-helper-budget","public-late-inventory","public-context","diagnostic-protocol"]
    assert sum(row["cases"] for row in index["groups"])==281
    for row in index["files"]:
        relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
        materialize(row,project/relative)
    external={}
    for row in index["external_restore"]:
        external[Path(row["path"]).name]=materialize(row,own/row["path"])
    save(output/"worker-program-diagnostic-submitted-source.json",dict(
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),
        common_gitsha=COMMON_SHA,index=INDEX_PIN,submitted=index))
    common.run("worker-program-diagnostic-exact-worker-dependency-restore",
        [sys.executable,"-B",external["worker_ci_restore_r2.py"],output/"context.json",
         external["worker_ci_dependencies_r4.json"]],timeout=300)
    work=Path(context["base"])/"worker-recovery/work-r2"
    compiler=work/"dependencies/f50-B3.image.bin";raw=compiler.read_bytes()
    assert (len(raw),digest(raw))==(668608,index["compiler"]["sha256"])
    build=project/"development/build-r1"
    build_label="worker-program-diagnostic-fresh-seven-B3-and-HIA-packer"
    built=panel(build_label,
        [sys.executable,"-B",project/index["build"],"--project",project,
         "--reference",context["reference"],"--workspace",context["workspace"],
         "--compiler",compiler,"--out",build],build/"summary.json",timeout=300)
    if built:
        report=details["groups"][build_label]["original_summary"]
        assert report["actual_compiles"]==7 and report["actual_packer_entries"]==1
        bundle=json.loads((build/"bundle.json").read_bytes())
        assert bundle["status"]=="BUILT_ONLY" and bundle["fresh_compiles"]==7
        assert bundle["compiler_sha256"]==index["compiler"]["sha256"]
        assert bundle["whole_public_diagnostics_closed"] is False
        accounted=external["accounted_full_initializer_r4.py"]
        for group in index["groups"]:
            name=group["name"];target=project/"development"/("actual-"+name+"-r1")
            label="worker-program-diagnostic-group-"+name
            env=dict(os.environ,HIA_ACCOUNTING_OUTPUT=str(output/(name+"-accounting.json")))
            good=panel(label,
                [sys.executable,"-B",accounted,project/index["test"],"--bundle",build/"bundle.json",
                 "--reference",context["reference"],"--out",target,"--group",name],
                target/"summary.json",env=env)
            result=details["groups"][label]["original_summary"]
            for result_name,total_name in (
                 ("completed_cases","completed_cases"),("failed_cases","failed_case_comparisons"),
                 ("attempted_case_results","attempted_case_results"),
                 ("actual_native_processes","actual_native_processes"),
                 ("actual_private_kernel_entries","actual_private_kernel_entries")):
                count=result.get(result_name,0)
                assert type(count) is int and count>=0,(label,result_name,count)
                details[total_name]+=count
            if good:
                try:
                    assert result["completed_cases"]==group["cases"]
                    assert result["actual_native_processes"]==group["actual_processes"]
                    wanted=group.get("actual_kernel_entries",0)
                    if wanted=="observed_positive":assert result["actual_private_kernel_entries"]>0
                    else:assert result["actual_private_kernel_entries"]==wanted
                    assert result["source_image_executable_before_after_equal"] is True
                except BaseException as exc:
                    failures.append(dict(label=label,error_class="ActualCountOrIdentityMismatch",
                                         exception_class=type(exc).__name__,error=str(exc)))
                    traceback.print_exc()
    else:
        details["runtime_groups"]="NOT_RUN_BUILD_DID_NOT_PASS"
    assert all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode
               for p,(raw,mode) in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON_PATH.read_bytes()==common_raw
    restore_rows=json.loads((output/"worker-restore/input-pins.json").read_bytes())
    assert all(Path(row["path"]).is_file() and Path(row["path"]).stat().st_size==row["bytes"]
               and digest(Path(row["path"]).read_bytes())==row["sha256"]
               and stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"] for row in restore_rows)
    details["all_submitted_restore_sources_unchanged"]=True
    if built and not failures:
        assert len(details["groups"])==11
        assert all(row["actual_successful_process"] and row["original_summary"]["status"]=="PASS"
                   for row in details["groups"].values())
        assert details["completed_cases"]==281 and details["actual_native_processes"]==151
        assert details["failed_case_comparisons"]==0 and details["actual_private_kernel_entries"]>38
        status="PASS"
except BaseException as exc:
    failures.append(dict(label="driver",error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    details["failures"]=failures;roots={}
    if project is not None and project.exists():roots["worker-program-diagnostic-fixed"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    common.finish("worker-program-fixed-diagnostic-route-strict-public-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
