"""Fresh native interface policy and ordered receipt against exact original post-admission code."""
from pathlib import Path
from hashlib import sha1
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=COMMON.read_bytes()
assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("ordinary_patch_receipt_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
ROOT=common.BASE/"root-recovery/workspace/native-ordinary-patch-receipt-r1"
FILES=[
  [
    "generate_ordinary_patch_receipt_r1.py",
    "4a0aa657053f2a340ca431ab52c11e1e794b858a"
  ],
  [
    "build_ordinary_patch_receipt_ci_r1.py",
    "f1200834f78e04e0aee2de19cd51e72f1572ea7b"
  ],
  [
    "test_ordinary_patch_receipt_ci_r2.py",
    "b46ab779035810062e6c225a27892f01e4371ff0"
  ]
]
EXPECTED={"patches":99,"interfaces":57,"private":41,"union-2048":2,"large-bytes":1}
status="FAIL";failures=[];groups={}
details=dict(scope="NEW_ORDINARY_PATCH_INTERFACE_RECEIPT_LEAF",old_counts_inherited=False,
    actual_native_Core_admission_entries=0,actual_native_candidate_rechecks=0,
    actual_native_compiles=0,actual_native_entries=0,
    installed_activation=False,full_patch_qualified=False,whole_stack_closed=False)
try:
    common.prepare()
    paths={}
    for name,pin in FILES:
        paths[name]=common.materialize(R3+"ordinary-patch-receipt-r1/"+name,pin,common.BASE/name)
    common.materialize(R3+"assembly-object-prefix-r1/generate_assembly_object_prefix_r1.py",
        "90d7242bdc2ab328280b2c760f988cff3ad21d10",common.BASE/"issued_object_prefix_reference.py")
    try:
        common.run("ordinary-patch-receipt-build",
            [sys.executable,"-B",paths[FILES[1][0]],paths[FILES[0][0]]],timeout=180)
    finally:
        path=ROOT/"development/build-r1/summary.json"
        if path.is_file():
            details["build"]=json.loads(path.read_bytes())
            print("HIA_ORDINARY_PATCH_RECEIPT_BUILD_ORIGINAL "+json.dumps(details["build"],sort_keys=True),flush=True)
    build=details["build"]
    assert build["status"]=="PASS" and build["actual_native_compiles"]==1
    assert build["source_and_image_before_after_equal"]
    details["actual_native_compiles"]=1
    for group in EXPECTED:
        try:
            common.run("ordinary-patch-receipt-"+group,
                [sys.executable,"-B",paths[FILES[2][0]],group],timeout=180,
                env={"HIA_RECEIPT_RECOVERY_BASE":str(common.BASE)})
        except BaseException as exc:
            failures.append(dict(group=group,error_class=type(exc).__name__,error=str(exc)))
        finally:
            path=ROOT/"development"/("native-"+group)/"summary.json"
            if path.is_file():
                value=json.loads(path.read_bytes())
                groups[group]={k:v for k,v in value.items() if k not in ("case_results","expected_inventory")}
                print("HIA_ORDINARY_PATCH_RECEIPT_OBSERVED "+json.dumps(groups[group],sort_keys=True),flush=True)
    assert not failures,failures
    assert set(groups)==set(EXPECTED)
    for group,value in groups.items():
        assert value["status"]=="PASS" and value["cases"]==EXPECTED[group]
        assert value["source_and_image_before_after_equal"] and value["full_source_and_guarded_buffers_recorded"]
        assert value["full_native_ordered_receipt_or_error_bytes_compared"]
        assert value["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert value["actual_native_preparation_entries"]==0
        assert value["actual_native_Core_admission_entries"]==value["actual_native_candidate_rechecks"]==0
        assert not value["old_counts_inherited"] and not value["whole_stack_closed"] and not value["full_patch_qualified"]
    assert groups["union-2048"]["maximum_receipt_bytes"]>20000
    assert groups["large-bytes"]["maximum_envelope_bytes"]>16000000
    assert sum(value["independent_original_post_admission_calls"] for value in groups.values())==161
    assert sum(value["direct_actual_reference_Core_admissions"] for value in groups.values())==322
    assert sum(value["independent_full_apply_reference_calls"] for value in groups.values())==99
    assert sum(value["cases"] for value in groups.values())==200
    details.update(actual_native_entries=sum(value["native_entries"] for value in groups.values()),
        actual_cases=200,actual_reference_post_admission_calls=161,actual_reference_full_apply_calls=99)
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    details.update(groups=groups,failures=failures)
    common.finish("ordinary-patch-receipt",status,details,{"ordinary-patch-receipt":ROOT})
if status!="PASS":raise SystemExit(1)
