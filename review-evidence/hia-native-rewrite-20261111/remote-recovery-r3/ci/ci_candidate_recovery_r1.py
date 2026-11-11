"""Fresh candidate qualification from immutable published source, on a new CI host."""
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
    executor_path=workspace/"native-edit-json-next/tools/edit_native_executor.S"
    executor_raw=executor_path.read_bytes()
    print("HIA_SOURCE_EXPORT "+json.dumps(dict(
        schema="hia-ci-recovered-text-export-v1",path=str(executor_path),
        bytes=len(executor_raw),sha256=sha256(executor_raw).hexdigest(),
        git_sha=sha1(b"blob "+str(len(executor_raw)).encode()+b"\0"+executor_raw).hexdigest(),
        text=executor_raw.decode("utf-8")),sort_keys=True),flush=True)
    programs=[
        ("restore-retained-fixtures",R3+"candidate/restore_application_retained_r1.py",
         "14248c3662c53e1e9499339c2723d1307907e148",base/"restore_application_retained_r1.py",300),
        ("generate-candidate-owners",R2+"generate_candidate_snapshot_r3.py",
         "f9fe226543ab421f9265fe02c20f128baca8c8d9",base/"generate_candidate_snapshot_r3.py",300),
        ("compile-candidate-owners",R2+"compile_candidate_snapshot_r1.py",
         "0a08bc8e9de12a7efbacaacb7c80967b740376f3",base/"compile_candidate_snapshot_r1.py",180),
        ("build-complete-native-elf",R2+"build_candidate_snapshot_r2.py",
         "03a1d6b7439d45d176bf39c69121b912a4ad168f",base/"build_candidate_snapshot_r2.py",180),
        ("fresh-original-reproduction",R2+"reproduce_candidate_snapshot_r1.py",
         "46a27c5f5e77566c916eaa763143ac724f7e78f2",base/"reproduce_candidate_snapshot_r1.py",900),
        ("review-and-fresh-fixed-replay",R2+"review_replay_candidate_snapshot_r1.py",
         "ef126aa913b52f5c947b301a00887130ffd7aa43",base/"review_replay_candidate_snapshot_r1.py",900),
        ("retained-87-complete-replay",R3+"candidate/test_retained_complete_replay_r1.py",
         "fecb061ff6c4379d489a9f02cf14c4f11f2982c9",root/"development/test_retained_complete_replay_r1.py",900),
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
            portable=json.loads((root/"development/compile-r1/portable-new-components.json").read_bytes())
            print("HIA_OWNER_MAP "+json.dumps(portable,sort_keys=True),flush=True)
            frozen=workspace/"native-edit-candidate-next/development/build-r1/source"
            inventory=[dict(path=str(p),bytes=p.stat().st_size,
                sha256=sha256(p.read_bytes()).hexdigest())
                for p in sorted(frozen.rglob("*")) if p.is_file()
                and p.suffix in (".py",".S",".md",".json")]
            print("HIA_FROZEN_SOURCE_INDEX "+json.dumps(inventory,sort_keys=True),flush=True)
    def report(name):
        return json.loads((root/"development"/name/"summary.json").read_bytes())
    fixed=report("complete-elf-replay-r1")
    assert fixed["status"]=="PASS" and fixed["cases"]==fixed["matched"]==17 and not fixed["differences"]
    original=report("original-review-r2")
    assert original["reviewed_cases"]==17 and original["matched"]==11 and original["success_controls_pass"]
    assert set(original["differences"])=={"depth-57","depth-58","depth-119","large-wide-only","large-deep-then-wide","large-wide-then-deep"}
    retained=report("retained-complete-replay-r1")
    assert retained["status"]=="PASS" and retained["case_count"]==87 and retained["source_before_after_equal"]
    private=report("snapshot-limit-protocol-r1")
    assert private["status"]=="PASS" and private["cases"]==44 and private["actual_entries"]==82
    assert private["production_source_and_image_unchanged"] and private["captured_original_metadata_unchanged"]
    boundary=report("snapshot-whole-boundary-r1")
    assert boundary["status"]=="PASS" and boundary["case_count"]==2 and boundary["source_before_after_equal"]
    assert all(row["status"]=="PASS" and row["cpu_s"]<=90 for row in boundary["results"])
    bundle=json.loads((root/"development/build-r2/bundle.json").read_bytes())
    executable=Path(bundle["executable"]["path"])
    assert sha256(executable.read_bytes()).hexdigest()==bundle["executable"]["sha256"]
    details=dict(new_fixed_cases=17,retained_cases=87,private_cases=44,private_native_entries=82,
        whole_byte_boundary_cases=2,original_true_differences=6,
        original_success_controls_pass=True,executable=bundle["executable"],
        public_cases=106,all_public_stdout_stderr_and_exitcodes_verified=True,
        private_witness_tests_do_not_establish_public_reachability=True,
        CPU_seconds_per_public_native_child=90,wall_seconds_per_public_native_child=180,
        address_space_bytes_per_native_child=1<<30,
        image_build_matches_ROG_component_hashes=True,
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
        "prior-application-fixtures":common.BASE/"root-recovery/application-reference-r1"})
if status!="PASS":raise SystemExit(1)
