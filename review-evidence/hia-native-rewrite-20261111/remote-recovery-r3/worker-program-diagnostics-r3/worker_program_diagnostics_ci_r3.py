"""Fresh P16 actual catalog route, strict original public-text qualification.

Only the remaining17 original private controls are selected after a fresh seven-B3 build
whose source/image identities must equal actual FOLLOW44. Its 177 passing cases
and83 FOLLOW45 private successes are not reexecuted or inherited; four public contextual-text failures remain open.
"""
from __future__ import annotations

# BEGIN HIA EXPLICIT SOURCE ENTRY ROUTE R1
if __name__ == "__main__":
    def _hia_explicit_source_entry_r1():
        import hashlib as _hashlib
        import json as _json
        import os as _os
        from pathlib import Path as _Path
        import stat as _stat
        import types as _types
        if _os.environ.get("GITHUB_EVENT_NAME") != "push":
            return
        _event_raw = _Path(_os.environ["GITHUB_EVENT_PATH"]).read_bytes()
        _event = _json.loads(_event_raw)
        if "[hia-ci:worker-explicit-legacy-diagnostics]" not in _event.get("head_commit", {}).get("message", ""):
            return
        _root = _Path(_os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        _helper = _root / "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci/explicit_gate_entry_router_r1.py"
        _mode = _helper.lstat().st_mode
        if _helper.is_symlink() or not _stat.S_ISREG(_mode) or _stat.S_IMODE(_mode) != 0o644:
            raise RuntimeError("explicit entry helper must be regular mode 100644")
        _raw = _helper.read_bytes()
        if (len(_raw), _hashlib.sha1(b"blob " + str(len(_raw)).encode("ascii") + b"\0" + _raw).hexdigest(), _hashlib.sha256(_raw).hexdigest()) != (7494, "25282eda1b7b97627d7791a47fe2c2bc21bcd6a3", "662bc010dd5893a046b9353b528902e33b6fd8d79b4a76e5e6cea99843c742c1"):
            raise RuntimeError("explicit entry helper full pin mismatch")
        _module = _types.ModuleType("hia_explicit_source_entry_router_r1")
        _module.__file__ = str(_helper)
        exec(compile(_raw, str(_helper), "exec"), _module.__dict__)
        _module.dispatch({"job":"worker_program_diagnostics_r1","selector":"[hia-ci:worker-explicit-legacy-diagnostics]","scope":"Explicit legacy Group9 original import diagnostics; four fresh B3 images, 22 public cases and 48 private controls","caller_path":"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/worker-program-diagnostics-r3/worker_program_diagnostics_ci_r3.py","target":{"path":"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/worker-explicit-legacy-diagnostics-r2/ci/worker_explicit_legacy_group9_ci_r1.py","mode":"100644","bytes":17276,"gitsha":"50a4bcb675817653dd599c7fe27faf4d11a079a4","sha256":"e80de7346870ca6b9ed82f2e53e9b13a660c1c5dde79ea186c167b6b7886dee2"}}, __file__, _event_raw, _raw)
        raise RuntimeError("selected explicit route returned without an exit")
    _hia_explicit_source_entry_r1()
    del _hia_explicit_source_entry_r1
# END HIA EXPLICIT SOURCE ENTRY ROUTE R1

import ast,importlib.util,json,os,stat,subprocess,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
COMMON_SHA="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
INDEX_PIN={
  "path": "sources.json",
  "mode": "100644",
  "bytes": 13558,
  "sha256": "a16735bbef99f7ce32f8b878fdd2b3d7540008eac557ce8aaac9e656cc300826",
  "gitsha": "356a0118a80f35a80fee1d46b44fe273c63dd64c",
  "classification": "NEW_R3_0_AST_0_GENERATION_0_B3_0_NATIVE"
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
 scope="REMAINING_17_PRIVATE_CONTROLS_ONLY_AFTER_ERROR999_EXPECTATION_FIX",
 selected_groups=["diagnostic-protocol"],selected_planned_cases=17,
 original_follow45_job=131126029053,prior_83_not_reexecuted_or_inherited=True,
 original_follow44_job=131116461128,original_177_passes_not_reexecuted=True,
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
        expected_build=[
          {
            "label": "worker-program-root",
            "source_bytes": 240159,
            "source_sha256": "b7fd8d4f40aadcdb544c0b53d4b92275442b6ec9ab9db4dea1b5d62f340c7c77",
            "image_bytes": 319512,
            "image_sha256": "cd0c365edbb18524c94eeb4cf46f5f03046c0b42f5694beecf6d3cc3f0749138"
          },
          {
            "label": "worker-assembly-control",
            "source_bytes": 228681,
            "source_sha256": "a16bba533d9bbd72c8a3da797e5c5677b1387d18d1673abebea0c65129efbea7",
            "image_bytes": 307451,
            "image_sha256": "e79637b8485a723e91c4c69a4a267ea3d9eae6b5f61f5624ff6933ff57dfcc8f"
          },
          {
            "label": "worker-assembly-syntax",
            "source_bytes": 251938,
            "source_sha256": "f567ecf6ff7148f32328f42100656f55c29094dfcae6c4df72b1ff831016ecbc",
            "image_bytes": 355192,
            "image_sha256": "2397fae88d366b3ab74c07dad9b9707e150e89ad5e8be336ef3afda78025b297"
          },
          {
            "label": "worker-assembly-render",
            "source_bytes": 231290,
            "source_sha256": "b81c8377660b73661774ce563c7c655ff850db366bccdb0f7500a7362432fc20",
            "image_bytes": 334259,
            "image_sha256": "291ac2e77017d17623550870c04fa89ceac5475a705fa07c78e3aedf83e0486b"
          },
          {
            "label": "worker-object-prefix",
            "source_bytes": 153786,
            "source_sha256": "7362f885a9da0cc26a52e2930c02dc633ac7e50080e0ad0f622f62da53ffaf9c",
            "image_bytes": 226229,
            "image_sha256": "f6300b41f981399e5db47a98eb2e30585c61e528df610bdde7d29d1709e29255"
          },
          {
            "label": "worker-fixed-diagnostic-catalog",
            "source_bytes": 219809,
            "source_sha256": "d8ed94b524eb761fccf3f048d6cd2fdeadc1995ae07b305012ca54d16d59ba74",
            "image_bytes": 213653,
            "image_sha256": "c967761c207c4205e076f7a15f8dc9304087e05ae5611a65ca3a3366f1784496"
          },
          {
            "label": "worker-program-ELF-packer",
            "source_bytes": 141058,
            "source_sha256": "14f201657c4b1748ca2e9b58cc6a293c1b0d3637cd9ac9ea8b3e96b70a286b51",
            "image_bytes": 152191,
            "image_sha256": "1b00ec6cd0a05a735720f26eb3796bbd3da262130ec009a110afb109ebbb1822"
          }
        ]
        actual_build=[{key:row[key] for key in ("label","source_bytes","source_sha256","image_bytes","image_sha256")} for row in report["compiled"]]
        assert actual_build==expected_build,(actual_build,expected_build)
        details["all_seven_fresh_source_images_equal_follow44_actual"]=True
        for group in index["groups"]:
            if group["name"]!="diagnostic-protocol":continue
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
                    assert result["completed_cases"]==17 and group["cases"]==100
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
        assert len(details["groups"])==2
        assert all(row["actual_successful_process"] and row["original_summary"]["status"]=="PASS"
                   for row in details["groups"].values())
        assert details["completed_cases"]==17 and details["actual_native_processes"]==0
        assert details["failed_case_comparisons"]==0 and details["actual_private_kernel_entries"]>0
        status="PASS"
except BaseException as exc:
    failures.append(dict(label="driver",error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc()))
    traceback.print_exc()
finally:
    details["failures"]=failures;roots={}
    if project is not None and project.exists():roots["worker-program-diagnostic-fixed"]=project
    if own is not None and own.exists():roots["submitted-ci-source"]=own
    common.finish("worker-program-diagnostic-private-remaining17-r3",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
