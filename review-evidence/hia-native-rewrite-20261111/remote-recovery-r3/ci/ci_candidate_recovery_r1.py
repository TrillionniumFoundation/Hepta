"""Fresh remaining candidate gates after the exact 469 checkpoint passed 17+87.
This run executes private 44 and two whole byte boundaries; no counts are inherited.
"""
import importlib.util, json, os, sys, traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
common_path=Path(os.environ["HIA_CI_COMMON"])
common_raw=common_path.read_bytes()
assert sha1(b"blob "+str(len(common_raw)).encode()+b"\0"+common_raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("hia_ci_common",common_path)
common=importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
R2="review-evidence/hia-native-rewrite-20261111/remote-recovery-r2/candidate/"
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
status="FAIL"
details={}
root=common.BASE/"root-recovery/workspace/native-edit-candidate-snapshot-r2-next"
try:
    context=common.prepare()
    base=Path(context["base"])
    workspace=Path(context["workspace"])
    dependency=workspace/"native-edit-json-next/development/main-compile-r3/source/8/hia_composite_lowering_driver_common.py"
    dependency_raw=dependency.read_bytes()
    assert (len(dependency_raw),sha256(dependency_raw).hexdigest())==(17781,"fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")
    restored=workspace/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py"
    assert not restored.exists(),"Do not replace an existing original"
    restored.parent.mkdir(parents=True,exist_ok=True)
    restored.write_bytes(dependency_raw)
    assert restored.read_bytes()==dependency_raw
    common.PINS[restored]=dependency_raw
    common.save(common.OUTPUT/"private-common-dependency.json",dict(
        schema="hia-exact-original-helper-relocation-v1",source=str(dependency),restored=str(restored),
        bytes=len(dependency_raw),sha256=sha256(dependency_raw).hexdigest(),
        frozen_original_not_modified=True,semantics_changed=False))
    programs=[
        ("restore-retained-fixtures",R3+"candidate/restore_application_retained_r1.py",
         "14248c3662c53e1e9499339c2723d1307907e148",base/"restore_application_retained_r1.py",300),
        ("generate-candidate-owners",R2+"generate_candidate_snapshot_r3.py",
         "f9fe226543ab421f9265fe02c20f128baca8c8d9",base/"generate_candidate_snapshot_r3.py",300),
        ("compile-candidate-owners",R2+"compile_candidate_snapshot_r1.py",
         "0a08bc8e9de12a7efbacaacb7c80967b740376f3",base/"compile_candidate_snapshot_r1.py",180),
        ("build-complete-native-elf",R2+"build_candidate_snapshot_r2.py",
         "03a1d6b7439d45d176bf39c69121b912a4ad168f",base/"build_candidate_snapshot_r2.py",180),
        ("private-44-witness-cases",R3+"candidate/test_snapshot_limit_protocol_r1.py",
         "80533550364d339c9eccc0db1035df0a3de215c9",root/"development/test_snapshot_limit_protocol_r1.py",600),
        ("whole-8MiB-and-plus-one",R3+"candidate/test_snapshot_whole_boundary_r1.py",
         "1d634d00b005145980308089c57bb23a3eddf2d2",root/"development/test_snapshot_whole_boundary_r1.py",600),
    ]
    for label,relative,expected,destination,timeout in programs:
        script=common.materialize(relative,expected,destination)
        common.run(label,[sys.executable,"-B",script],timeout=timeout)
        if label=="compile-candidate-owners":
            report=json.loads((root/"development/compile-r1/summary.json").read_bytes())
            assert report["status"]=="PASS"
            expected_images={
                "59":"255a3ca76ffb8ccaf01cf01ee50fe22e328de06a60106a3408fe8b737703af50",
                "60":"3e1f812d62e2efe210c9f5f94cd55cc2374283eee7856e48da9279f2f552600d"}
            assert {role:row["image_sha256"] for role,row in report["components"].items()}==expected_images
    def report(name):
        return json.loads((root/"development"/name/"summary.json").read_bytes())
    private=report("snapshot-limit-protocol-r1")
    assert private["status"]=="PASS" and private["cases"]==44 and private["actual_entries"]==82
    assert private["production_source_and_image_unchanged"] and private["captured_original_metadata_unchanged"]
    boundary=report("snapshot-whole-boundary-r1")
    assert boundary["status"]=="PASS" and boundary["case_count"]==2 and boundary["source_before_after_equal"]
    assert all(row["status"]=="PASS" and row["cpu_s"]<=90 for row in boundary["results"])
    bundle=json.loads((root/"development/build-r2/bundle.json").read_bytes())
    executable=Path(bundle["executable"]["path"])
    assert sha256(executable.read_bytes()).hexdigest()==bundle["executable"]["sha256"]
    details=dict(scope="REMAINING_PRIVATE_AND_WHOLE_BYTE_BOUNDARY_GATES",
        private_cases=44,private_native_entries=82,whole_byte_boundary_cases=2,
        actual_public_cases_in_this_run=2,previous_public_case_counts_inherited=False,
        prior_17_and_87_are_separate_run=43101326649,executable=bundle["executable"],
        all_current_public_stdout_stderr_and_exitcodes_verified=True,
        private_witness_tests_do_not_establish_public_reachability=True,
        CPU_seconds_per_public_native_child=90,wall_seconds_per_public_native_child=180,
        address_space_bytes_per_native_child=1<<30,
        image_build_matches_prior_component_hashes=True,
        exact_missing_private_helper_restored=True,
        sqlite_not_used_as_a_namespace_oracle=True)
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
finally:
    common.finish("candidate",status,details,{
        "candidate":root,
        "restored-original-lowering-helper":common.BASE/"root-recovery/workspace/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
        "prior-application-fixtures":common.BASE/"root-recovery/application-reference-r1"})
if status!="PASS":raise SystemExit(1)
