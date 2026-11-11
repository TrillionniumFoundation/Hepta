"""Fresh A-root generation, original-limit B3 compilation and private native controls."""
from pathlib import Path
from hashlib import sha1
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();common_raw=COMMON.read_bytes()
assert sha1(b"blob "+str(len(common_raw)).encode()+b"\0"+common_raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("program_service_ci_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
root=common.BASE/"root-recovery/workspace/native-program-service-root-r1"
status="FAIL";details=dict(scope="NEW_A_ROOT_COMPILE_AND_PRIVATE_NATIVE_CONTROLS",
    actual_program_admission_entries=0,actual_program_projector_entries=0,
    actual_publication_operations=0,actual_fixed_carrier_processes=0,
    inherited_test_counts=False,whole_stack_closed=False,installed_CLI_claim=False)
try:
    context=common.prepare()
    programs=[
      ("generate-A-service-root","generate_program_service_r1.py","7697d1b04b41955f230f61dc126f915301127ac2",root/"development/source-r1.json",300),
      ("compile-A-service-root","compile_program_service_r1.py","50b2f008e8d4b08fb4880ace05f371eec49c476c",root/"development/compile-r1/summary.json",120),
      ("native-A-private-controls","test_program_service_private_r1.py","077113930bad3488b4ca261554a18a2c7077bef6",root/"development/private-native-r1/summary.json",180)]
    for label,name,pin,report_path,timeout in programs:
        script=common.materialize(R3+"program-service/"+name,pin,common.BASE/name)
        try:
            common.run(label,[sys.executable,"-B",script],timeout=timeout)
        finally:
            if report_path.is_file():
                report=json.loads(report_path.read_bytes())
                print("HIA_A_SERVICE_STAGE "+json.dumps(dict(label=label,report={
                    k:v for k,v in report.items() if k!="case_results"}),sort_keys=True),flush=True)
    build=json.loads((root/"development/compile-r1/summary.json").read_bytes())
    native=json.loads((root/"development/private-native-r1/summary.json").read_bytes())
    assert build["status"]==native["status"]=="PASS"
    assert build["actual_compilations"]==1 and build["source_and_image_before_after_equal"]
    assert native["source_and_image_before_after_equal"] and native["all_source_readonly_and_guard_pages"]
    assert native["cases"]==56 and native["native_entries"]==134
    assert native["actual_program_admission_entries"]==native["actual_program_projector_entries"]==native["actual_publication_operations"]==native["actual_fixed_carrier_processes"]==0
    assert native["foreign_program_reply_fixtures"] is True and native["installed_CLI_claim"] is False
    details.update(build=build,native=native);status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
finally:
    common.finish("A-root-private-native",status,details,{"program-service":root})
if status!="PASS":raise SystemExit(1)
