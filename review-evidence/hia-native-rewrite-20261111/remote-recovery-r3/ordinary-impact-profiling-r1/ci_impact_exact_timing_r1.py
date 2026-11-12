"""Independent bounded mechanical timing diagnosis of original impact41 images."""
from __future__ import annotations
import base64,hashlib,importlib.util,json,os,stat,sys,traceback
from pathlib import Path
sys.dont_write_bytecode=True
assert sys.version_info[:3]==(3,12,14)
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def gitsha(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON.read_bytes()
assert gitsha(common_raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("impact_timing_diagnostic_common",COMMON)
common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common;spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw
common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
PREFIX="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-profiling-r1"
INDEX_GIT="b874e6af7c106563a6979e6d985eee8491e29984"
INDEX_SHA="a676905e792c566ff2f57f88ab4acf31804a5e393518bda43702f2e424e7bfe7"
FILES=json.loads("[{\"path\":\"add_mechanical_timing_trace_r1.py\",\"bytes\":5379,\"gitsha\":\"bce0fc69dbd381f21f4b37c885e6ac32ee8d5677\",\"sha256\":\"3c8a4a5dbf78c21f1b95b4c96635531c3ffa49d9eae2b3d57a0fa256c747298e\",\"mode\":\"100644\"},{\"path\":\"build_timed_exact_impact_r1.py\",\"bytes\":11675,\"gitsha\":\"5f64b81801e56585a098fb0bc889f8c470016a44\",\"sha256\":\"14143efb7ff04f1e1212d1e4f8f9c273d426202d4c97837cf46061c4f32aad3e\",\"mode\":\"100644\"},{\"path\":\"capture_timed_exact_impact_r1.py\",\"bytes\":15818,\"gitsha\":\"17ebe4ec4b33f11a0f04d0a3148d9eec2c658509\",\"sha256\":\"77d8fcd5257ee43cb0a29a4678268618b08324de8fff58a83b9074eec1ea8887\",\"mode\":\"100644\"},{\"path\":\"analyze_timed_exact_impact_r1.py\",\"bytes\":12526,\"gitsha\":\"7508b9cf83743809290a107fb0096e37c7813811\",\"sha256\":\"7a6c3eb13391ae489868ef02f0bf90ea541aebc110ca3a54acc000e400bcdbaf\",\"mode\":\"100644\"}]")
DEPENDENCY=json.loads("{\"path\":\"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci-followup-r44/read_impact41_originals.py\",\"bytes\":12206,\"gitsha\":\"d1686000317ea5be4d4f61936505353e560bfcb5\",\"sha256\":\"f699ba99f9936bc2c37a06b34c05aa1f2a19e211ac94916ee1d4906a501f3c44\"}")
ROOT=common.BASE/"root-recovery/workspace/native-original-impact-timing-r1"
SOURCES=common.BASE/"ordinary-impact-timing-submitted-source"
READBACK=ROOT/"original-readback";BUILD=ROOT/"build";CAPTURE=ROOT/"capture";ANALYSIS=ROOT/"analysis"
status="FAIL";failures=[];context=None
details=dict(scope="MECHANICAL_TIMING_DIAGNOSTIC_EXACT_ORIGINAL_IMPACT41_NOT_QUALIFICATION",
    original_large_valid_failure_unchanged=True,whole_stack_closed=False,
    semantic_qualification=False,production_activation=False,original_qualification_rerun=False,
    all_63_semantic_HIA_images_unchanged_required=True,
    child_diagnostic_CPU_may_be_stricter_to_preserve_whole90_budget=True,
    before_to_after_timings_include_before_hook_sampling_write_and_layout_overhead=True,
    original_limits=dict(B3_CPU_seconds=10,B3_wall_seconds=20,B3_address_bytes=268435456,
        group_CPU_seconds=90,group_wall_seconds=180,group_address_bytes=1073741824))
def load_summary(path):
    raw=path.read_bytes();return json.loads(raw)
def observed_summary(label,path):
    if not path.is_file():return
    raw=path.read_bytes()
    common.PINS[path]=raw
    value=json.loads(raw)
    details[label]=dict(path=str(path),bytes=len(raw),sha256=sha(raw),
        status=value.get("status"),build_status=value.get("build_status"),
        error_class=value.get("error_class"),error=value.get("error"),
        actual_ELF_processes_started=value.get("actual_ELF_processes_started"),
        actual_fresh_B3=value.get("actual_fresh_B3"),
        parent_plus_children_CPU_seconds=value.get("parent_plus_children_CPU_seconds"),
        parent_CPU_seconds=value.get("parent_CPU_seconds"))
    print("HIA_IMPACT_TIMING_ORIGINAL_SUMMARY_PIN "+json.dumps(details[label],sort_keys=True),flush=True)
try:
    context=common.prepare();ROOT.mkdir(parents=True,exist_ok=False);SOURCES.mkdir()
    index_path=common.materialize(PREFIX+"/sources.json",INDEX_GIT,SOURCES/"sources.json")
    index_raw=index_path.read_bytes();assert sha(index_raw)==INDEX_SHA
    index=json.loads(index_raw);assert index["files"]==FILES and index["dependencies"]==[DEPENDENCY]
    for row in FILES:
        path=common.materialize(PREFIX+"/"+row["path"],row["gitsha"],SOURCES/row["path"])
        raw=path.read_bytes()
        assert (len(raw),sha(raw),stat.S_IMODE(path.stat().st_mode))==(row["bytes"],row["sha256"],int(row["mode"],8)&0o777)
    reader=common.materialize(DEPENDENCY["path"],DEPENDENCY["gitsha"],SOURCES/"read_original_impact41.py")
    reader_raw=reader.read_bytes();assert (len(reader_raw),sha(reader_raw))==(DEPENDENCY["bytes"],DEPENDENCY["sha256"])
    common.run("timing-read-all3090-original-impact-members",[context["python"],"-B",reader],timeout=180,
        env=dict(HIA_CI_OUTPUT=str(READBACK),HIA_IMPACT41_DIR=os.environ["HIA_IMPACT41_DIR"]))
    readback=load_summary(READBACK/"summary.json")
    assert readback["status"]=="PASS_READ_ONLY" and readback["pinned_inputs_before_after_equal"]
    assert readback["new_HIA"]==readback["new_B3"]==readback["new_VM"]==readback["new_native"]==0
    original=readback["observations"]["impact"]
    assert original["members"]==3090 and original["original_bytes"]==150697441
    assert original["every_indexed_byte_and_mode_verified"]
    details["complete_original_readback"]=dict(members=3090,bytes=150697441,subject_execution=False)
    common.run("timing-exact63-images-one-fresh-bounded-HIA-packer",
        [context["python"],"-B",SOURCES/"build_timed_exact_impact_r1.py",
         "--original-readback",READBACK,"--reference",context["reference"],
         "--trace-author",SOURCES/"add_mechanical_timing_trace_r1.py","--out",BUILD],
        cwd=context["reference"],timeout=180)
    built=load_summary(BUILD/"summary.json")
    assert built["build_status"]=="PASS" and built["actual_fresh_B3"]==1
    assert built["actual_native_packer_entries"]==1 and built["actual_semantic_processes"]==0
    assert built["source_and_image_before_after_equal"] and built["retained_HIA_images"]==63
    assert built["parent_plus_children_CPU_seconds"]<90 and int(built["elapsed_ns"])<180000000000
    assert not built["semantic_qualification"]
    details["actual_new_B3_returned_images"]=1;details["actual_HIA_packer_entries"]=1
    try:
        common.run("timing-original-and-instrumented-calibration-then-large-valid",
            [context["python"],"-B",SOURCES/"capture_timed_exact_impact_r1.py",
             "--original-readback",READBACK,"--build",BUILD,"--out",CAPTURE],
            cwd=context["reference"],timeout=180)
    except BaseException as exc:
        failures.append(dict(phase="capture",error_class=type(exc).__name__,error=str(exc)))
    if (CAPTURE/"summary.json").is_file():
        captured=load_summary(CAPTURE/"summary.json")
        details["actual_ELF_processes_started"]=captured["actual_ELF_processes_started"]
        details["actual_processes_with_returned_record"]=captured["actual_processes_with_returned_record"]
        if captured.get("processes"):
            try:
                common.run("timing-read-complete-immutable-raw-traces",
                    [context["python"],"-B",SOURCES/"analyze_timed_exact_impact_r1.py",
                     "--capture",CAPTURE,"--build",BUILD,"--original-readback",READBACK,"--out",ANALYSIS],
                    cwd=context["reference"],timeout=180)
            except BaseException as exc:
                failures.append(dict(phase="analysis",error_class=type(exc).__name__,error=str(exc)))
    assert not failures,failures
    captured=load_summary(CAPTURE/"summary.json");analyzed=load_summary(ANALYSIS/"summary.json")
    assert captured["status"]=="PASS_DIAGNOSTIC_CAPTURE_ONLY"
    assert captured["actual_ELF_processes_started"]==captured["actual_processes_with_returned_record"]==3
    assert captured["source_and_image_before_after_equal"] and captured["parent_plus_children_CPU_seconds"]<90
    assert captured["semantic_images_changed"]==0 and not captured["semantic_qualification"]
    assert all(x["complete_calibration_returncode_stdout_stderr_equal_original"] is True for x in captured["processes"][:2])
    assert analyzed["status"]=="PASS_TIMING_ANALYSIS_ONLY" and analyzed["complete_inputs_before_after_equal"]
    assert analyzed["actual_new_HIA"]==analyzed["actual_new_B3"]==analyzed["actual_new_VM"]==analyzed["actual_new_native"]==0
    assert analyzed["parent_CPU_seconds"]<90 and int(analyzed["elapsed_ns"])<180000000000
    details["timing_observations"]=[{k:value[k] for k in
        ("label","original_process_returncode","full_frames","complete_entry_pairs","trailing_raw_bytes",
         "summed_complete_pair_CPU_ns","approximate_CPU_after_last_frame_ns","unmatched_before_frame",
         "unmatched_before_is_not_proof_of_exact_in_flight_HIA_call","by_role")} for value in analyzed["results"]]
    print("HIA_IMPACT_TIMING_OBSERVATIONS "+json.dumps(details["timing_observations"],sort_keys=True),flush=True)
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    details["failures"]=failures
    for label,path in (("readback_original",READBACK/"summary.json"),("build_original",BUILD/"summary.json"),
                       ("capture_original",CAPTURE/"summary.json"),("analysis_original",ANALYSIS/"summary.json")):
        try:observed_summary(label,path)
        except BaseException as exc:
            status="FAIL";details.setdefault("summary_readback_errors",[]).append(dict(label=label,error=repr(exc)))
    roots={}
    if ROOT.exists():roots["impact-timing-complete"]=ROOT
    if SOURCES.exists():roots["impact-timing-submitted-source"]=SOURCES
    common.finish("impact-exact-images-mechanical-timing-diagnostic",status,details,roots)
if status!="PASS":raise SystemExit(1)
