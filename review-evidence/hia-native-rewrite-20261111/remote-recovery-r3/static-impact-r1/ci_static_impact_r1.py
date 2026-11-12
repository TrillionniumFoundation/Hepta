"""Fresh complete static-impact component and exact original observer comparisons."""
from pathlib import Path
from hashlib import sha1
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=COMMON.read_bytes()
assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("static_impact_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
ROOT=common.BASE/"root-recovery/workspace/native-static-impact-r1"
FILES=[
  [
    "generate_static_impact_r1.py",
    "10fd6493cece709385c661a18482b9bf481b254b"
  ],
  [
    "build_static_impact_ci_r1.py",
    "d5490db84132574313d2b5aff8404106108b7dd2"
  ],
  [
    "test_static_impact_ci_r1.py",
    "2660a8bb57da1469b70e88d62e8395b833404591"
  ]
]
GROUPS=("semantic","receipts","private","graph-1024","graph-dense","graph-long-report")
EXPECTED={"semantic":33,"receipts":44,"private":24,"graph-1024":1,"graph-dense":1,"graph-long-report":1}
status="FAIL";failures=[];groups={}
details=dict(scope="NEW_COMPLETE_STATIC_IMPACT_COMPONENT",
    actual_native_Core_admission_entries=0,actual_native_patch_entries=0,
    installed_activation=False,full_impact_qualified=False,whole_stack_closed=False,
    inherited_counts=False)
try:
    common.prepare()
    paths={}
    for name,pin in FILES:
        paths[name]=common.materialize(R3+"static-impact-r1/"+name,pin,common.BASE/name)
    common.materialize(R3+"assembly-object-prefix-r1/generate_assembly_object_prefix_r1.py",
        "90d7242bdc2ab328280b2c760f988cff3ad21d10",common.BASE/"issued_object_prefix_reference.py")
    common.run("static-impact-build",[sys.executable,"-B",paths[FILES[1][0]],paths[FILES[0][0]]],timeout=180)
    build=json.loads((ROOT/"development/build-r1/summary.json").read_bytes())
    assert build["status"]=="PASS" and build["actual_native_compiles"]==1
    assert build["source_and_image_before_after_equal"]
    details["build"]=build
    for group in GROUPS:
        try:
            common.run("static-impact-"+group,[sys.executable,"-B",paths[FILES[2][0]],group],timeout=180)
        except BaseException as exc:
            failures.append(dict(group=group,error_class=type(exc).__name__,error=str(exc)))
        finally:
            path=ROOT/"development"/("native-"+group)/"summary.json"
            if path.is_file():
                row=json.loads(path.read_bytes())
                groups[group]={k:v for k,v in row.items() if k!="case_results"}
                print("HIA_STATIC_IMPACT_OBSERVED "+json.dumps(groups[group],sort_keys=True),flush=True)
    assert not failures,failures
    assert set(groups)==set(GROUPS)
    for row in groups.values():
        assert row["status"]=="PASS" and row["source_and_image_before_after_equal"]
        assert row["full_source_and_guarded_buffers_recorded"]
        assert row["full_native_report_bytes_compared"] and row["cases"]==EXPECTED[row["group"]]
        assert row["actual_native_Core_admission_entries"]==row["actual_native_patch_entries"]==0
    assert groups["graph-long-report"]["maximum_report_bytes"]>8<<20
    assert sum(row["actual_reference_patch_calls"] for row in groups.values())==36
    assert sum(row["original_reference_oracle_calls"] for row in groups.values())==80
    details.update(actual_native_compiles=1,
        actual_native_entries=sum(row["native_entries"] for row in groups.values()),
        actual_cases=sum(row["cases"] for row in groups.values()))
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    details.update(groups=groups,failures=failures)
    common.finish("static-impact",status,details,{"static-impact":ROOT})
if status!="PASS":raise SystemExit(1)
