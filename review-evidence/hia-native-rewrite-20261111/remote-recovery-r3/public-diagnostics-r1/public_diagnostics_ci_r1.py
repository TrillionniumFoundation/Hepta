"""Private native-adapter enum catalog qualification; public diagnostics remain open."""
from __future__ import annotations
import ast,importlib.util,json,os,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
PREFIX=R3+"public-diagnostics-r1/"
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
common_raw=COMMON.read_bytes()
assert gitsha(common_raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("fixed_public_diagnostic_ci_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw
common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
INDEX={"bytes":4030,"gitsha":"ce6d5e5f99d4f6119a2289d989e63779049fe98a","sha256":"baaf98716ec9a14dbeb419f610bb2c2917e69a0d85d20755c75039b960ab2962"}
context=None;mine=None;project=None;status="FAIL"
details=dict(scope="NATIVE_ADAPTER_FIXED_ENUM_CATALOG_ONLY_AND_A_ROUTING_BUILD",
  exact_public_API_error_text_equivalence_proved=False,
  native_adapter_enum_texts_are_not_complete_public_context=True,
  known_public_dynamic_name_and_field_context_gap=True,
  actual_compiles=0,actual_native_entries=0,actual_cases=0,
  required_compiles=2,required_private_cases=233,required_private_native_entries=595,
  actual_public_A_carrier_entries=0,actual_program_admission_entries=0,
  private_terminal_fixtures_explicit=True,old_successes_inherited=False,
  group6_and9_still_open=True,original_group7_8_10_unchanged=True,
  public_A_role51_RRW_mask_repair_and_physical_execution_still_required=True,
  whole_public_diagnostics_closed=False,installed_activation=False,whole_stack_closed=False)
try:
    context=common.prepare()
    base=Path(context["base"]);mine=base/"public-diagnostic-recovery-r1";mine.mkdir()
    project=mine/"source";project.mkdir()
    raw=common.pinned(PREFIX+"sources.json",INDEX["gitsha"])
    assert (len(raw),digest(raw))==(INDEX["bytes"],INDEX["sha256"])
    index=json.loads(raw);assert len(index["files"])==13
    for row in index["files"]:
        path=common.materialize(PREFIX+row["path"],row["gitsha"],project/row["path"])
        raw=path.read_bytes()
        assert (len(raw),digest(raw))==(row["bytes"],row["sha256"]),row["path"]
        if path.suffix==".py":ast.parse(raw,filename=str(path))
    build=mine/"build"
    record=common.run("fresh-two-diagnostic-B3-builds",
      [sys.executable,"-B",project/"development/build_public_diagnostics_r1.py",
       project,context["reference"],context["compiler"],build],timeout=180)
    assert record["child_cpu_seconds"]<90
    actual=json.loads((build/"summary.json").read_bytes())
    assert actual["status"]=="PASS" and actual["source_and_image_before_after_equal"]
    assert len(actual["compiled"])==2 and all(row["fresh_actual_B3"] for row in actual["compiled"])
    assert {row["label"] for row in actual["compiled"]}=={"fixed-catalog","program-diagnostic-route"}
    details["actual_compiles"]=2;details["build"]=actual
    results={}
    for group,cases,entries in (("all-fixed-messages",181,543),("capacity-u64",11,11),("protocol",41,41)):
        out=mine/("native-"+group)
        record=common.run("native-fixed-diagnostic-"+group,
          [sys.executable,"-B",project/"development/test_fixed_diagnostic_native_r1.py",
           "--source",project,"--reference",context["reference"],
           "--manifest",build/"fixed-catalog/manifest.json","--out",out,"--group",group],timeout=180)
        assert record["child_cpu_seconds"]<90
        raw=(out/"summary.json").read_bytes();observed=json.loads(raw)
        assert observed["status"]=="PASS" and observed["source_and_image_before_after_equal"]
        assert (observed["cases"],observed["native_entries"])==(cases,entries)
        assert observed["complete_expected_suite_bytes_compared"] and observed["all_source_readonly_and_guard_pages"]
        assert observed["limits"]==dict(CPU_seconds=90,wall_seconds=180,address_bytes=1<<30)
        assert observed["actual_A_carrier_entries"]==0 and observed["actual_program_admission_entries"]==0
        assert observed["controlled_private_terminal_fixtures"] is True
        results[group]=observed
        details["actual_cases"]+=cases;details["actual_native_entries"]+=entries
        print("HIA_FIXED_DIAGNOSTIC_GROUP "+json.dumps({k:v for k,v in observed.items() if k!="case_results"},sort_keys=True),flush=True)
    assert (details["actual_cases"],details["actual_native_entries"])==(233,595)
    details["groups"]=results;status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    roots={}
    if mine is not None:roots["public-diagnostics"]=mine
    common.finish("private-adapter-fixed-diagnostic-catalog",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
