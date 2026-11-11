"""Run new program projection compilation and actual guarded native tests only."""
import importlib.util,json,os,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
common_path=Path(os.environ["HIA_CI_COMMON"])
common_raw=common_path.read_bytes()
assert sha1(b"blob "+str(len(common_raw)).encode()+b"\0"+common_raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("program_ci_common",common_path)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[common_path]=common_raw
common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
root=common.BASE/"root-recovery/workspace/native-program-service-reconstructed-r1"
status="FAIL"
details=dict(scope="NEW_PRIVATE_REPORT_INSPECT_NORMALIZE_GRAPH_PROJECTION",
    actual_program_admission_is_separate_open_integration=True,
    installed_CLI_claim=False,inherited_test_counts=False,whole_stack_closed=False)
try:
    context=common.prepare()
    workspace=Path(context["workspace"])
    for relative in (
      "native-edit-candidate-next/development/build-r1/source/156/generate_hia_edit_json_main.py",
      "native-edit-candidate-next/development/build-r1/source/161/main_r4.py",
      "native-edit-json-next/development/main-compile-r3/source/8/hia_composite_lowering_driver_common.py",
      "native-edit-controller-next/tools/hia_edit_controller_common.py"):
        path=workspace/relative
        raw=path.read_bytes()
        print("HIA_PROGRAM_INTEGRATION_SOURCE "+json.dumps(dict(
            relative=relative,bytes=len(raw),sha256=sha256(raw).hexdigest(),
            git_sha=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
            text=raw.decode("utf-8")),sort_keys=True),flush=True)
    programs=[
      ("generate-program-projector",R3+"program/generate_program_inspection_r1.py",
       "e46461267b7e0ee3e8173d4713e19d14f559c876",common.BASE/"generate_program_inspection_r1.py",300),
      ("compile-program-projector",R3+"program/compile_program_inspection_r1.py",
       "9435a47a932061882b7940bff0baffdfe8b7ec28",common.BASE/"compile_program_inspection_r1.py",120),
      ("actual-native-program-projection",R3+"program/test_program_inspection_r1.py",
       "931645f910ffa029f587390d3bc0a681175d65e3",root/"development/test_program_inspection_r1.py",180),
    ]
    for label,relative,expected,destination,timeout in programs:
        script=common.materialize(relative,expected,destination)
        common.run(label,[sys.executable,"-B",script],timeout=timeout)
    build=json.loads((root/"development/compile-r1/summary.json").read_bytes())
    native=json.loads((root/"development/native-projection-r1/summary.json").read_bytes())
    assert build["status"]==native["status"]=="PASS"
    assert build["actual_compilations"]==1 and build["source_and_image_before_after_equal"]
    assert native["source_and_image_before_after_equal"] and native["actual_B3_compiled_image"]
    assert native["all_result_values_and_canonical_bytes_equal"]
    assert native["terminal_and_private_refusal_poisoning"]
    assert native["source_readonly_and_guard_pages"]
    assert set(native["full_core_schema_coverage"])=={"hepta.hia.program.v"+str(i) for i in range(1,9)}
    assert set(native["full_input_schema_coverage"])==(
        {"hepta.hia.program.v"+str(i) for i in range(1,9)}|
        {"hepta.hia.composite.v"+str(i) for i in range(1,5)})
    details.update(build=build,native=native)
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
finally:
    common.finish("private-program-projection",status,details,{"program":root})
if status!="PASS":raise SystemExit(1)
