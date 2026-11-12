"""Run a new bounded reference-cost experiment, not any original qualification."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,os,stat,traceback
from pathlib import Path
COMMON_SHA="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
PROFILER_SHA="638e2fd74f2a50619b9662918f95b0b859c8a99c1d0970a27bd71fd3c20b10e3"
READER_SHA="a2d0b36d9c739afc202785b2fc3acc488c55c126dac53b78e0a9f41c998b9866"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
 info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
 raw=path.read_bytes();return dict(path=str(path),bytes=len(raw),mode=stat.S_IMODE(info.st_mode),sha256=sha(raw))
def main():
 assert sys.version_info[:3]==(3,12,14)
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True);common_raw=common_path.read_bytes()
 assert sha(common_raw)==COMMON_SHA
 spec=importlib.util.spec_from_file_location("namespace_reference_cost_common",common_path)
 common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common
 exec(compile(common_raw,str(common_path),"exec"),common.__dict__)
 details=dict(status="INCOMPLETE",scope="COST_DIAGNOSIS_OF_RECORDED_WINDOWS_ONLY",
  original_900_suites_not_executed=True,original_failures_unchanged=True,
  new_B3_compiles=0,new_native_entries=0,new_VM_entries="UNKNOWN_UNTIL_RECORDED",
  actual_existing_native_results_are_comparison_inputs_not_new_native_execution=True,
  ordinary_Store_closed=False,whole_namespace_closed=False)
 status="FAIL";context=None;checks=[];output=None
 try:
  context=common.prepare()
  here=Path(__file__).resolve().parent
  profiler=here/"profile_recorded_reference_cost.py"
  reader=here.parent/"issued-fs-follow42-readback/read_issued_fs_follow42.py"
  for path,expected in ((common_path,COMMON_SHA),(profiler,PROFILER_SHA),(reader,READER_SHA)):
   row=pin(path);assert row["sha256"]==expected;checks.append(row)
  checks.append(pin(Path(__file__).resolve()))
  output=Path(context["output"])/"namespace-reference-cost"
  c=dict(context,cost_output=str(output),cost_work=str(Path(context["base"])/"namespace-reference-cost-expanded"))
  context_path=Path(context["output"])/"reference-cost-context.json";save(context_path,c)
  details["process"]=common.run("recorded-reference-cost",
   [context["python"],"-B",profiler,"--context",context_path,"--reader",reader],
   cwd=context["reference"],timeout=180)
  summary_path=output/"summary.json";raw=summary_path.read_bytes();result=json.loads(raw)
  assert result["status"]=="PASS_COST_DIAGNOSTIC_ONLY"
  assert result["original_members_verified"]==4272 and result["original_raw_bytes_verified"]==323619640
  assert result["new_B3_compiles"]==result["new_native_entries"]==result["original_tests_rerun"]==0
  assert 6<=len(result["cases"])<=18 and result["new_VM_entries"]==2*len(result["cases"])
  assert result["all_selected_full_outputs_workspaces_and_steps_equal"] and result["no_mutation_of_reference_VM_methods"]
  assert result["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall_seconds=180)
  assert not result["after_check_errors"]
  details.update(status="PASS_COST_DIAGNOSTIC_ONLY",new_VM_entries=result["new_VM_entries"],
   selected_recorded_windows=len(result["cases"]),stage_totals=result["stage_totals"],
   result=dict(bytes=len(raw),sha256=sha(raw)),
   interpretation="Only these recorded windows were measured. No full-suite pass, optimization benefit or in-flight causal inference is asserted.")
  status="PASS"
 except BaseException as error:
  details.update(status="FAIL_DIAGNOSTIC",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  after=[]
  for row in checks:
   try:
    got=pin(Path(row["path"]));assert got==row
   except BaseException as error:after.append(dict(before=row,error=repr(error)))
  details["input_pins"]=checks;details["after_errors"]=after
  if after:status="FAIL";details["status"]="FAIL_DIAGNOSTIC"
  if output is not None and (output/"summary.json").is_file():
   original=(output/"summary.json").read_bytes()
   details["complete_diagnostic_report"]=dict(bytes=len(original),sha256=sha(original))
   report=json.loads(original)
   projected={k:report[k] for k in ("status","scope","new_VM_entries","new_native_entries","new_B3_compiles","stage_totals","actual_limits","error_class","error","traceback","after_check_errors") if k in report}
   print("HIA_NAMESPACE_COST_ACTUAL_REPORT "+json.dumps(projected,sort_keys=True),flush=True)
  common.finish("RECORDED_REFERENCE_COST_DIAGNOSTIC_NOT_QUALIFICATION",status,details)
 return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
