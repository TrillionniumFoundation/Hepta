"""Fixture-only remaining44 after complete immutable FOLLOW53 evidence readback.

No old result is counted as a new execution. A two-run union is allowed only
after the complete old six-case bytes and fresh43-role HIA/image/ELF bytes
have been checked. Original FOLLOW53 overall FAIL is preserved.
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
  "bytes": 27985,
  "sha256": "766832d21d77d3006126d3ccec4f2045756296f345595d3cb103747f4c44ffec",
  "gitsha": "8037442875bcfc76390facfb3e9db29978710d3d"
}
READER_PIN={
  "path": "read_group6_follow53_originals_r1.py",
  "mode": "100644",
  "bytes": 31978,
  "sha256": "0b5d8411290dae9bfe1c3899323325c324dd95721dae05bc0a92e0c6949378a0",
  "gitsha": "bda3bdd9c372f70da31e42f053a0d2a8e04e9f51"
}
SELECTED_GROUPS=("late-depth-and-order","late-private-protocol")

COMMON_PATH=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON_PATH.read_bytes();common_mode=stat.S_IMODE(COMMON_PATH.stat().st_mode)
assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("worker_late_Core_exact_common",COMMON_PATH)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes();self_mode=stat.S_IMODE(Path(__file__).stat().st_mode)
context=None;project=None;own=None;submitted={};oracle={};restored={};failures=[];status="FAIL"
details=dict(schema="hia-worker-ordinary-late-Core-remaining44-ci-r1",
 scope="SAME_PRODUCTION_REMAINING44_WITH_COMPLETE_FOLLOW53_SIX_CASE_READBACK",
 groups={},fresh_compiles_required=13,retained_images=31,nonzero_images=43,
 selected_planned_cases=44,selected_groups=2,planned_public_ELF_cases=6,
 original_50_case_census_unchanged=True,old_six_cases_counted_as_new=False,
 original_FOLLOW53_overall_status="FAIL",original_private_partial_entry_not_complete=True,
 planned_private_unissued_capsule_cases=38,
 completed_cases=0,failed_case_comparisons=0,attempted_case_results=0,
 actual_native_processes=0,actual_private_kernel_entries=0,
 old_counts_inherited=False,old_413_type_join_groups_reexecuted=False,
 original_public_oracle_not_enum_table=True,
 exact_retained_role23_reproduction_before_new_B3_required=True,
 public_late_depth_status1_reachability_claimed=False,
 group9_is_explicit_legacy_importer_not_ordinary_P16=True,
 namespace_issued=False,whole_worker_closed=False,installed_activation=False,
 whole_public_diagnostics_closed=False,
 limits=dict(compiler_cpu=10,compiler_wall=20,compiler_address=268435456,
             group_cpu=90,group_wall=180,group_address=1073741824,
             aggregate_group_process_tree_cpu_below90=True))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def materialize(row,target):
    assert row["mode"]=="100644" and len(row["gitsha"])==40
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
            if label.startswith("worker-late-Core-group-"):
                cpu=process["child_cpu_seconds"]
                assert isinstance(cpu,(int,float)) and 0<=cpu<90,("aggregate CPU",cpu)
                assert 0<=process["elapsed_ns"]<180_000_000_000,("complete receipt elapsed",process["elapsed_ns"])
                assert report["source_image_executable_before_after_equal"] is True
                assert 0<=report["aggregate_cpu_seconds"]<90
                assert report["original_limits"]==dict(cpu=90,wall=180,address=1<<30)
    except BaseException as exc:
        good=False;failures.append(dict(label=label,error_class="OriginalResultOrBudgetMismatch",
            exception_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        traceback.print_exc()
    row=dict(actual_successful_process=good,original_summary=report,original_process=process)
    details["groups"][label]=row
    print("HIA_WORKER_LATE_CORE_PANEL "+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
    return good
def identical_original_production(bundle,original,reader_out):
    proof=json.loads((reader_out/"verified-original-build.json").read_bytes())
    assert proof["status"]=="PASS" and proof["original_build_pass"]
    assert proof["compiler_sha256"]==bundle["compiler_sha256"]
    assert set(proof["role_bindings"])==set(bundle["role_bindings"])
    rows=[]
    def exact(path,old):
        raw=Path(path).read_bytes()
        key=old.get("frozen_member",old.get("member"))
        assert isinstance(key,str) and not Path(key).is_absolute() and ".." not in Path(key).parts
        frozen=reader_out/"members"/key
        prior=frozen.read_bytes()
        assert raw==prior,(str(path),"fresh versus complete original bytes")
        assert (len(raw),digest(raw),stat.S_IMODE(frozen.stat().st_mode))==(
            old["bytes"],old["sha256"],old["mode"])
        assert stat.S_IMODE(Path(path).stat().st_mode)==old["mode"]
        return dict(path=str(path),original_member=key,bytes=len(raw),sha256=digest(raw),
                    mode=old["mode"],full_bytes_equal=True)
    for role,current in bundle["role_bindings"].items():
        before=proof["role_bindings"][role]
        pair=dict(role=int(role))
        for which in ("source","image"):
            assert (current[which+"_bytes"],current[which+"_sha256"])==(
                before[which]["bytes"],before[which]["sha256"])
            pair[which]=exact(current[which+"_path"],before[which])
        rows.append(pair)
    executable=exact(bundle["executable_path"],proof["executable"])
    old_compiled=proof["compiled"]
    assert len(old_compiled)==len(bundle["compiled"])==13
    frozen_sources=json.loads((reader_out/"verified-original-source-pins.json").read_bytes())
    by_identity={}
    for r in frozen_sources:
        key=(r["bytes"],r["sha256"])
        by_identity.setdefault(key,[]).append(r)
    compiled=[]
    for old,new in zip(old_compiled,bundle["compiled"],strict=True):
        assert old["label"]==new["label"]
        entry=dict(label=new["label"])
        for which in ("source","image"):
            assert old[which+"_sha256"]==new[which+"_sha256"]
            matches=by_identity[(new[which+"_bytes"],new[which+"_sha256"])]
            # Multiple exact frozen aliases are permitted; all were fully read.
            bound=matches[0]
            entry[which]=exact(new[which+"_path"],dict(bound,frozen_member=bound["member"]))
        compiled.append(entry)
    assert original["facts"]["completed_original_public_cases"]==6
    assert original["facts"]["original_target_status"]=="FAIL"
    return dict(status="PASS",roles=rows,executable=executable,compiled=compiled,
        same_compiler=True,same_complete_ELF=True,same_complete_HIA_and_images=True,
        original_cases=6,new_completed_cases_at_this_gate=0,
        production_authoring_and_executor_unchanged=True,original_overall_FAIL_preserved=True)

try:
    context=common.prepare();output=Path(context["output"])
    own=Path(context["base"])/"worker-late-Core-ci-source-remaining-r1";own.mkdir()
    project=Path(context["base"])/"worker-late-Core-native-r1";project.mkdir()
    index_path=materialize(INDEX_PIN,project/"sources.json")
    index=json.loads(index_path.read_bytes())
    assert index["continuation"]["selected_new_groups"]==list(SELECTED_GROUPS)
    assert index["continuation"]["selected_new_cases"]==44
    assert index["schema"]=="hia-worker-program-late-Core-source-index-r1"
    assert len(index["files"])==56 and len(index["groups"])==8
    assert (index["fresh_compiles"],index["retained_images"],index["nonzero_images"])==(13,31,43)
    assert sum(row["cases"] for row in index["groups"])==50
    assert sum(row["actual_processes"] for row in index["groups"])==12
    assert [r["name"] for r in index["groups"]]==[
        "late-node-below","late-node-equal","late-node-over",
        "late-byte-below","late-byte-equal","late-byte-over",
        "late-depth-and-order","late-private-protocol"]
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
    save(output/"worker-late-Core-submitted.json",dict(index=INDEX_PIN,sources=index,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),
        common_gitsha=COMMON_SHA))
    common.run("worker-late-Core-exact-worker-dependency-restore",
        [sys.executable,"-B",external["worker_ci_restore_r2.py"],output/"context.json",
         external["worker_ci_dependencies_r4.json"]],timeout=300)
    compiler=Path(context["base"])/"worker-recovery/work-r2/dependencies/f50-B3.image.bin"
    raw=compiler.read_bytes()
    assert (len(raw),digest(raw))==(668608,"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8")
    assert index["compiler"]["bytes"]==len(raw) and index["compiler"]["sha256"]==digest(raw)
    # Read the complete original artifact before any new target/build execution.
    reader_path=materialize(READER_PIN,own/READER_PIN["path"])
    reader_out=output/"follow53-complete-original-readback"
    archive=Path(os.environ["HIA_GROUP6_FOLLOW53_ZIP"]).resolve()
    process=common.run("worker-late-Core-original53-readback",
        [sys.executable,"-B",reader_path,"--zip",archive,"--out",reader_out,
         "--repo",context["source"]],timeout=180)
    assert 0<=process["child_cpu_seconds"]<90 and 0<=process["elapsed_ns"]<180_000_000_000
    original=json.loads((reader_out/"summary.json").read_bytes())
    assert original["status"]=="PASS" and original["original_target_status"]=="FAIL"
    assert original["complete_original_ZIP_retained_and_after_verified"] is True
    assert original["all_756_original_members_retained_and_after_verified"] is True
    assert original["new_target_entries"]==original["new_compiler_entries"]==0
    assert original["facts"]["completed_original_public_cases"]==6
    details["original53_full_readback"]=dict(status="PASS",artifact=13952974167,
        members=756,completed_cases=6,original_target_status="FAIL",new_target_entries=0,
        original_summary_sha256=digest((reader_out/"summary.json").read_bytes()))
    restore_path=project/index["restore"]
    spec=importlib.util.spec_from_file_location("worker_late_Core_exact_driver_restorer",restore_path)
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
    build_label="worker-late-Core-thirteen-B3-and-native-HIA-packer"
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
        assert bundle["inherited_composite_refusal_text_missing_groups"]==[9]
        proof=json.loads(Path(bundle["exact_retained_driver_reproduction"]).read_bytes())
        assert proof["status"]=="PASS" and set(proof["retained_source_proofs"])=={"8","40","41","43","46"}
        assert all(r["generated_HIA_bytes_equal_retained"] for r in proof["retained_source_proofs"].values())
        late=json.loads(Path(bundle["native_late_Core_adaptation"]).read_bytes())
        assert late["changed_original_methods"]==["prefix_failure"]
        assert late["added_methods"]==["worker_late_core_start","worker_late_core_text"]
        assert all(late[key] for key in ("every_other_method_AST_exact","assembly_service_bytes_exact",
          "constants_and_executor_masks_unchanged","original_snapshot_before_byte_order_unchanged",
          "no_new_early_Core_check_or_semantic_owner","all_text_written_by_HIA"))
        assert late["host_diagnostic_formatting"] is False
        assert [row["status"] for row in late["messages"]]==[1,2,3]
        assert all(row["code"]=="E_HIA_LIMIT" and row["bytes"]==len(row["text"].encode("ascii"))
                   for row in late["messages"])
        origin=json.loads(Path(bundle["exact_retained_late_Core_reproduction"]).read_bytes())
        assert origin["original_archive_gitsha"]=="abfc02df1513fff1b104924e8a496fea7de5230c"
        assert origin["original_custody_gitsha"]=="3d414f3b6ee9fcdaeb2b41c858e8f684e269693e"
        assert (origin["complete_original_members"],origin["complete_original_raw_bytes"])==(2981,218379198)
        assert origin["exact_role23_HIA_reproduced"] and origin["original_bytes_SHA256_modes_all_checked"]
        assert (origin["source_bytes"],origin["source_sha256"])==(140616,"34f0d66c4ffe19b286dab5ad5c07d3b11e69bf8cd6c9e27d4bd3ddb53cf87e66")
        assert (origin["image_bytes"],origin["image_sha256"])==(212690,"b210b6e1f8347c783273baf860e76a1e2462a7be4d38529c122dc722252e508e")
        assert origin["original_tests_reexecuted"]==origin["new_native_entries"]==origin["new_compiler_entries"]==0
        imports=json.loads(Path(bundle["exact_new_late_Core_import_closure"]).read_bytes())
        assert imports["status"]=="PASS" and imports["all_new_static_imports_resolved"]
        assert imports["new_B3_entries_at_this_gate"]==imports["new_target_entries_at_this_gate"]==0
        mask=json.loads(Path(bundle["diagnostic_mask_proof"]).read_bytes())
        assert mask["schema"]=="hia-worker-type-context-fixed-executor-r2"
        assert mask["allowed_new_child_component"]==50 and mask["allowed_child_kind"]==0
        assert mask["allowed_reader_calling_drivers"]==[41,43]
        assert mask["exact_reverse_restoration_equal"] and mask["all_other_instruction_text_exact"]
        details["actual_original_role23_reproduction"]=origin
        details["actual_native_late_Core_adaptation"]=late
        details["exact_new_import_closure"]=imports
        details["retained_scoped_type_reader_dispatch"]=mask
        identical=identical_original_production(bundle,original,reader_out)
        save(output/"fresh-versus-original-full-production-bytes.json",identical)
        details["complete_original_source_image_ELF_equality"]=dict(status="PASS",
            roles=43,fresh_compiles=13,actual_HIA_packer_entries=1,complete_byte_comparison=True)
        accounted=external["accounted_full_initializer_r4.py"]
        for group in index["groups"][-2:]:
            assert group["name"] in SELECTED_GROUPS
            name=group["name"];label="worker-late-Core-group-"+name
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
                    assert result["public_case_failures"]==[]
                    assert result["explicit_legacy_importer_group9_not_invoked"] is True
                    assert result["public_late_depth_status1_reachability_claimed"] is False
                except BaseException as exc:
                    failures.append(dict(label=label,error_class="ActualCountMismatch",
                                         exception_class=type(exc).__name__,error=str(exc)))
                    traceback.print_exc()
        if not failures:
            assert len(details["groups"])==3
            assert all(row["actual_successful_process"] for row in details["groups"].values())
            assert details["completed_cases"]==44 and details["actual_native_processes"]==6
            assert details["failed_case_comparisons"]==0 and details["actual_private_kernel_entries"]>38
            details["two_run_coverage_union"]=dict(status="PASS",
                old_follow53_completed_public_cases=6,new_completed_cases=44,total_cases=50,
                old_follow53_overall_status="FAIL",all_original_50_labels_and_order_preserved=True,
                original_six_whole_artifact_readback=True,production_bytes_identical=True,
                one_run_50_PASS_claimed=False,original_private_partial_entry_counted=False)
            status="PASS"
    else:details["runtime_groups"]="NOT_RUN_BUILD_DID_NOT_PASS"
except BaseException as exc:
    failures.append(dict(label="driver",error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    after_errors=[]
    available={**submitted,**oracle,**restored}
    available[Path(__file__).resolve()]=(self_raw,self_mode)
    available[COMMON_PATH]=(common_raw,common_mode)
    for path,(raw,mode) in available.items():
        try:
            assert path.is_file() and not path.is_symlink()
            assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
        except BaseException as exc:
            after_errors.append(dict(path=str(path),error_class=type(exc).__name__,error=str(exc)))
    if context is not None:
        restore_pins=Path(context["output"])/"worker-restore/input-pins.json"
        try:
            rows=json.loads(restore_pins.read_bytes()) if restore_pins.is_file() else []
            assert type(rows) is list
        except BaseException as exc:
            after_errors.append(dict(path=str(restore_pins),error_class=type(exc).__name__,error=str(exc)))
            rows=[]
        for row in rows:
            path=None
            try:
                path=Path(row["path"])
                assert path.is_file() and not path.is_symlink()
                raw=path.read_bytes()
                assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
                assert stat.S_IMODE(path.stat().st_mode)==row["mode"]
            except BaseException as exc:
                after_errors.append(dict(path=str(path),error_class=type(exc).__name__,error=str(exc)))
    same=not after_errors
    if not same:
        status="FAIL";failures.append(dict(label="source-custody",
            error_class="SourceOrModeChanged",after_errors=after_errors))
    details["all_available_source_dependency_oracle_bytes_modes_unchanged"]=same
    details["failures"]=failures;roots={}
    if project is not None and project.exists():roots["worker-late-Core"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    common.finish("worker-late-Core-same-production-remaining44-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
