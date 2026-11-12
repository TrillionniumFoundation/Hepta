"""Thirteen-image P16 actual type-context propagation, original full oracle.

r3 repairs the scoped reader50 executor dispatch and exact test-module resolution.
The original failed FOLLOW50 and all original fourteen groups remain separate.
All fourteen groups are newly executed, with independent original budgets.
No passing historical count or private foreign capsule supplies public proof.
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
  "bytes": 26697,
  "sha256": "ec257fbfdc0a3bd153cb5627ad0b02ce78d7f3c14589e851f1052ef6e5945b0f",
  "gitsha": "fc53c06792b0e2d3ed26835ac2bdec16b2aee572",
  "classification": "NEW_R3_0_AST_0_GENERATION_0_B3_0_NATIVE"
}
COMMON_PATH=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON_PATH.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("worker_type_context_join_common",COMMON_PATH)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;project=None;own=None;submitted={};oracle={};restored={};failures=[];status="FAIL"
details=dict(schema="hia-worker-native-type-context-propagation-ci-r1",
 scope="ACTUAL_TYPES_VALIDATOR_READER_LOWER_PROGRAM_P16_ORIGINAL_FULL_TEXT",
 groups={},fresh_compiles_required=13,retained_images=31,nonzero_images=43,
 selected_planned_cases=413,selected_groups=14,all_retained281_reexecuted=True,
 completed_cases=0,failed_case_comparisons=0,attempted_case_results=0,
 actual_native_processes=0,actual_private_kernel_entries=0,
 actual_expected_native_processes=251,old_counts_inherited=False,
 original_public_oracle_not_native_enum_or_context_table=True,
 exact_old_driver_reproduction_before_new_B3_required=True,
 namespace_issued=False,whole_worker_closed=False,installed_activation=False,
 whole_public_diagnostics_closed=False,groups6_and9_diagnostics_open=True,
 limits=dict(compiler_cpu=10,compiler_wall=20,compiler_address=268435456,
             group_cpu=90,group_wall=180,group_address=1073741824,
             aggregate_group_process_tree_cpu_below90=True))
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
            if label.startswith("worker-type-context-join-group-"):
                cpu=process["child_cpu_seconds"]
                assert isinstance(cpu,(int,float)) and 0<=cpu<90,("aggregate CPU",cpu)
                assert report["source_image_executable_before_after_equal"] is True
                assert 0<=report["aggregate_cpu_seconds"]<90
                assert report["original_limits"]==dict(cpu=90,wall=180,address=1<<30)
    except BaseException as exc:
        good=False;failures.append(dict(label=label,error_class="OriginalResultOrBudgetMismatch",
            exception_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        traceback.print_exc()
    row=dict(actual_successful_process=good,original_summary=report,original_process=process)
    details["groups"][label]=row
    print("HIA_WORKER_TYPE_CONTEXT_JOIN_PANEL "+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
    return good
try:
    context=common.prepare();output=Path(context["output"])
    own=Path(context["base"])/"worker-type-context-join-ci-source-r3";own.mkdir()
    project=Path(context["base"])/"worker-type-context-join-native-r3";project.mkdir()
    index_path=materialize(INDEX_PIN,project/"sources.json")
    index=json.loads(index_path.read_bytes())
    assert index["schema"]=="hia-worker-program-native-type-context-source-index-r1"
    assert len(index["files"])==48 and len(index["groups"])==14
    assert (index["fresh_compiles"],index["retained_images"],index["nonzero_images"])==(13,31,43)
    assert sum(row["cases"] for row in index["groups"])==413
    assert sum(row["actual_processes"] for row in index["groups"])==251
    assert [r["name"] for r in index["groups"]]==[
       "semantic","assembly-boundary","object-boundary","private-protocol","example-chain",
       "public-fixed","public-helper-budget","public-late-inventory","public-context",
       "diagnostic-protocol","public-type-names","public-type-shapes","public-type-order",
       "context-protocol"]
    for row in index["files"]:
        relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
        materialize(row,project/relative)
    oracle_rows=[]
    for name,row in index["original_oracle"].items():
        relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
        path=Path(context["reference"])/relative
        assert path.is_file() and not path.is_symlink() and row["mode"]=="100644"
        raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
        assert (len(raw),digest(raw),gitsha(raw),mode)==(row["bytes"],row["sha256"],row["gitsha"],0o644)
        ast.parse(raw,filename=str(path));oracle[path]=(raw,mode)
        target=output/"exact-original-public-oracle"/relative
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(mode)
        oracle_rows.append(dict(name=name,path=str(path),bytes=len(raw),sha256=digest(raw),
                               gitsha=gitsha(raw),mode=mode,frozen=str(target)))
    save(output/"pre-B3-public-oracle-readback.json",dict(status="PASS",sources=oracle_rows))
    external={}
    for row in index["external_restore"]:
        external[Path(row["path"]).name]=materialize(row,own/row["path"])
    save(output/"worker-type-context-join-submitted.json",dict(index=INDEX_PIN,sources=index,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),
        common_gitsha=COMMON_SHA))
    common.run("worker-type-context-join-exact-worker-dependency-restore",
        [sys.executable,"-B",external["worker_ci_restore_r2.py"],output/"context.json",
         external["worker_ci_dependencies_r4.json"]],timeout=300)
    compiler=Path(context["base"])/"worker-recovery/work-r2/dependencies/f50-B3.image.bin"
    raw=compiler.read_bytes()
    assert (len(raw),digest(raw))==(668608,"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8")
    assert index["compiler"]["bytes"]==len(raw) and index["compiler"]["sha256"]==digest(raw)
    restore_path=project/index["restore"]
    spec=importlib.util.spec_from_file_location("worker_type_context_exact_original_restorer",restore_path)
    restoration=importlib.util.module_from_spec(spec);spec.loader.exec_module(restoration)
    dependencies=restoration.restore(context["repo"],project,output/"exact-diagnostic-authoring-restore")
    assert len(dependencies)==6
    for path in dependencies.values():
        raw=path.read_bytes();restored[path]=(raw,stat.S_IMODE(path.stat().st_mode))
    restore_receipt=json.loads((output/"exact-diagnostic-authoring-restore/restoration-receipt.json").read_bytes())
    assert restore_receipt["status"]=="PASS" and restore_receipt["every_original_member_verified_before_dependency_use"]
    assert restore_receipt["original_member_bytes_checked"]==99770153
    details["all_8355_original_diagnostic_archive_members_verified"]=True
    build=project/"development/build-r1"
    build_label="worker-type-context-join-thirteen-B3-and-native-HIA-packer"
    built=panel(build_label,
        [sys.executable,"-B",project/index["build"],"--project",project,
         "--reference",context["reference"],"--workspace",context["workspace"],
         "--compiler",compiler,"--out",build],build/"summary.json",timeout=300)
    if built:
        report=details["groups"][build_label]["original_summary"]
        assert report["actual_compiles"]==13 and report["actual_compile_attempts"]==13
        assert report["actual_packer_entries"]==1 and report["source_and_image_before_after_equal"]
        bundle=json.loads((build/"bundle.json").read_bytes())
        assert (bundle["status"],bundle["fresh_compiles"],bundle["nonzero_images"])==("BUILT_ONLY",13,43)
        assert bundle["compiler_sha256"]==index["compiler"]["sha256"]
        assert bundle["native_type_context_capture_roles"]==[8,40,41,43,46,50,56]
        proof=json.loads(Path(bundle["exact_retained_driver_reproduction"]).read_bytes())
        assert proof["status"]=="PASS" and set(proof["retained_source_proofs"])=={"8","40","41","43","46"}
        assert all(r["generated_HIA_bytes_equal_retained"] for r in proof["retained_source_proofs"].values())
        details["exact_five_old_sources_reproduced_before_new_images"]=True
        mask=json.loads(Path(bundle["diagnostic_mask_proof"]).read_bytes())
        assert mask["schema"]=="hia-worker-type-context-fixed-executor-r2"
        assert mask["allowed_new_child_component"]==50 and mask["allowed_child_kind"]==0
        assert mask["allowed_reader_calling_drivers"]==[41,43]
        for field in ("exact_reverse_restoration_equal","all_other_instruction_text_exact",
                      "original_parent_kind2_component_range_unchanged",
                      "original_program_kind1_reader50_refusal_preserved",
                      "all_other_child_controllers_still_refuse_reader50",
                      "two_read_mask_unchanged_from_fixed_diagnostic_P16"):
            assert mask[field] is True,field
        closure=json.loads((build/"context-authoring/exact-original-import-closure.json").read_bytes())
        assert closure["status"]=="PASS" and closure["schema"]=="hia-type-context-authoring-import-closure-r3"
        assert closure["new_B3_entries_at_this_gate"]==0 and closure["project_business_functions_executed"]==0
        assert closure["full_group_test_static_import_inventory_checked"]
        assert closure["test_module_not_loaded_via_implicit_sys_path"]
        fixtures=closure["exact_runpy_test_sibling_import_closure"]
        assert [row["module"] for row in fixtures]==["type_context_original_corpus_r1","type_context_public_plans_r2"]
        assert all(row["actual_module_loaded_before_B3"] and not row["oracle_case_functions_executed"] for row in fixtures)
        details["scoped_reader50_dispatch_and_original_test_import_preflight"]=dict(
            exact_executor_proof=mask,pre_B3_test_imports=fixtures,
            original_413_group_case_plan_not_reduced=True,old_follow50_counts_inherited=False)
        accounted=external["accounted_full_initializer_r4.py"]
        for group in index["groups"]:
            name=group["name"];label="worker-type-context-join-group-"+name
            target=project/"development"/("actual-"+name+"-r1")
            env=dict(os.environ,HIA_ACCOUNTING_OUTPUT=str(output/(name+"-accounting.json")))
            good=panel(label,
                [sys.executable,"-B",accounted,project/index["test"],"--bundle",build/"bundle.json",
                 "--reference",context["reference"],"--out",target,"--group",name],
                target/"summary.json",env=env)
            result=details["groups"][label]["original_summary"]
            for key in ("completed_cases","attempted_case_results","actual_native_processes","actual_private_kernel_entries"):
                count=result.get(key,0);assert type(count) is int and count>=0
                details[key]+=count
            count=result.get("failed_cases",0);assert type(count) is int and count>=0
            details["failed_case_comparisons"]+=count
            if good:
                try:
                    assert result["completed_cases"]==group["cases"]
                    assert result["actual_native_processes"]==group["actual_processes"]
                    entries=result["actual_private_kernel_entries"];wanted=group.get("actual_kernel_entries",0)
                    if wanted=="observed_positive":assert entries>0
                    else:assert entries==wanted
                except BaseException as exc:
                    failures.append(dict(label=label,error_class="ActualCountMismatch",
                                         exception_class=type(exc).__name__,error=str(exc)))
                    traceback.print_exc()
        if not failures:
            assert len(details["groups"])==15
            assert all(row["actual_successful_process"] for row in details["groups"].values())
            assert details["completed_cases"]==413 and details["actual_native_processes"]==251
            assert details["failed_case_comparisons"]==0 and details["actual_private_kernel_entries"]>38
            status="PASS"
    else:details["runtime_groups"]="NOT_RUN_BUILD_DID_NOT_PASS"
except BaseException as exc:
    failures.append(dict(label="driver",error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    same=all(p.is_file() and not p.is_symlink() and p.read_bytes()==raw
             and stat.S_IMODE(p.stat().st_mode)==mode
             for p,(raw,mode) in {**submitted,**oracle,**restored}.items())
    same=same and Path(__file__).read_bytes()==self_raw and COMMON_PATH.read_bytes()==common_raw
    if context is not None:
        restore_pins=Path(context["output"])/"worker-restore/input-pins.json"
        if restore_pins.is_file():
            for row in json.loads(restore_pins.read_bytes()):
                path=Path(row["path"])
                same=same and path.is_file() and path.stat().st_size==row["bytes"]
                same=same and digest(path.read_bytes())==row["sha256"] and stat.S_IMODE(path.stat().st_mode)==row["mode"]
    if not same:
        status="FAIL";failures.append(dict(label="source-custody",error_class="SourceOrModeChanged"))
    details["all_available_source_dependency_oracle_bytes_modes_unchanged"]=same
    details["failures"]=failures;roots={}
    if project is not None and project.exists():roots["worker-type-context-join"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    common.finish("worker-program-actual-native-type-context-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
