"""New HIA edit terminal relay through the unchanged fixed 63-owner ELF.

The new protocol requires exactly one extra SWITCH sequence where a query or
apply owner returns to the root; full business and error bytes are unchanged.
Fresh three-owner generation/B3 compilation follows byte-exact original
regeneration. Replay the original full 87 cases and both 8MiB boundaries;
no historical execution count is inherited.
"""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();raw_common=COMMON.read_bytes()
assert sha1(b"blob "+str(len(raw_common)).encode()+b"\0"+raw_common).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("edit_terminal_relay_ci_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=raw_common;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R2="review-evidence/hia-native-rewrite-20261111/remote-recovery-r2/candidate/"
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
work=common.BASE/"root-recovery/workspace"
root=work/"native-edit-candidate-snapshot-r2-next"
relay=work/"native-edit-terminal-relay-r1"
status="FAIL";details=dict(scope="NEW_HIA_EDIT_TERMINAL_RELAY_ACTUAL_87_PLUS_TWO_FULL_BOUNDARIES",
    inherited_test_counts=False,public_CLI_service_closed=False,whole_stack_closed=False,
    old_owners_deleted=False,actual_program_filesystem_publications=0)
try:
    context=common.prepare();base=Path(context["base"])
    common.materialize(R3+"program-integration/retained-edit-source/native-edit-controller-next/development/query-compile-r1/source/0/generate_hia_edit_query_driver.py",
        "36db857a03d2353d77b241e9babd8bab3c703615",base/"edit-relay-query-original.py")
    programs=[
      ("restore-retained-fixtures",R3+"candidate/restore_application_retained_r1.py",
       "14248c3662c53e1e9499339c2723d1307907e148",base/"restore_application_retained_r1.py",300,None),
      ("regenerate-original-latest-candidate",R2+"generate_candidate_snapshot_r3.py",
       "f9fe226543ab421f9265fe02c20f128baca8c8d9",base/"generate_candidate_snapshot_r3.py",300,root/"development/source-r1.json"),
      ("compile-original-latest-candidate",R2+"compile_candidate_snapshot_r1.py",
       "0a08bc8e9de12a7efbacaacb7c80967b740376f3",base/"compile_candidate_snapshot_r1.py",180,root/"development/compile-r1/summary.json"),
      ("generate-new-edit-terminal-relay",R3+"edit-terminal-relay/generate_edit_terminal_relay_r1.py",
       "662ff3330723881a455a87a279a356b83ad7ebd6",base/"generate_edit_terminal_relay_r1.py",300,relay/"development/source-r1.json"),
      ("compile-three-new-edit-relay-owners",R3+"edit-terminal-relay/compile_edit_terminal_relay_r1.py",
       "46a3bda70e7e4f1a87fd352c4cb74a1d6e65dce0",base/"compile_edit_terminal_relay_r1.py",180,relay/"development/compile-r1/summary.json"),
      ("pack-actual-63-owner-relay-ELF",R3+"edit-terminal-relay/build_edit_terminal_relay_r1.py",
       "e6511390a9478934034e67c6107283574df2ab28",base/"build_edit_terminal_relay_r1.py",180,root/"development/build-r2/bundle.json"),
      ("actual-retained-all-87-edit-cases",R3+"edit-terminal-relay/test_edit_terminal_relay_retained_r1.py",
       "0c283ef70be8702e19baa3d2d21ce6f1bdee9e5a",root/"development/test_edit_terminal_relay_retained_r1.py",600,root/"development/relay-complete-replay-r1/summary.json"),
      ("actual-full-8MiB-and-plus-one",R3+"candidate/test_snapshot_whole_boundary_r1.py",
       "1d634d00b005145980308089c57bb23a3eddf2d2",root/"development/test_snapshot_whole_boundary_r1.py",600,root/"development/snapshot-whole-boundary-r1/summary.json")]
    for label,path,pin,destination,timeout,summary_path in programs:
        script=common.materialize(path,pin,destination)
        try:
            common.run(label,[sys.executable,"-B",script],timeout=timeout)
        finally:
            if summary_path is not None and summary_path.is_file():
                record=json.loads(summary_path.read_bytes())
                print("EDIT_RELAY_ACTUAL_STAGE "+json.dumps(dict(label=label,
                    original_summary={k:v for k,v in record.items() if k not in ("results","completed_cases","case_results","components","executable","packer_receipt")}),
                    sort_keys=True),flush=True)
        if label=="compile-original-latest-candidate":
            old=json.loads(summary_path.read_bytes());assert old["status"]=="PASS"
            assert {role:row["image_sha256"] for role,row in old["components"].items()}=={
                "59":"255a3ca76ffb8ccaf01cf01ee50fe22e328de06a60106a3408fe8b737703af50",
                "60":"3e1f812d62e2efe210c9f5f94cd55cc2374283eee7856e48da9279f2f552600d"}
    compiled=json.loads((relay/"development/compile-r1/summary.json").read_bytes())
    assert compiled["status"]=="PASS" and compiled["actual_compilations"]==3
    assert compiled["source_and_image_before_after_equal"]
    replay=json.loads((root/"development/relay-complete-replay-r1/summary.json").read_bytes())
    boundary=json.loads((root/"development/snapshot-whole-boundary-r1/summary.json").read_bytes())
    assert replay["status"]=="PASS" and replay["case_count"]==87 and replay["source_before_after_equal"]
    assert all(row["status"]=="PASS" and row["full_stdout_equal"] and row["complete_revised_stderr_equal"]
        and row["actual_exitcode"]==row["expected_exitcode"] for row in replay["results"])
    assert boundary["status"]=="PASS" and boundary["case_count"]==2 and boundary["source_before_after_equal"]
    assert all(row["status"]=="PASS" and row["cpu_s"]<=90 for row in boundary["results"])
    bundle=json.loads((root/"development/build-r2/bundle.json").read_bytes())
    assert bundle["status"]=="PASS" and bundle["source_before_after_equal"]
    assert bundle["replacement_roles"]==[56,57,59,60]
    assert sha256(Path(bundle["executable"]["path"]).read_bytes()).hexdigest()==bundle["executable"]["sha256"]
    details.update(compilation=compiled,actual_edit_cases=87,actual_whole_boundaries=2,
        actual_edit_native_processes=89,actual_HIA_ELF_packer_entries=1,
        executable=bundle["executable"],all_full_stdout_revised_terminal_and_error_bytes_exit_checks_pass=True,
        original_protocol_exact_stderr_test_claim=False,extra_terminal_switches=replay["extra_terminal_switches"],
        original_limits=dict(native_CPU_seconds=90,native_wall_seconds=180,native_address_bytes=1<<30,
            compiler_CPU_seconds=10,compiler_wall_seconds=20,compiler_address_bytes=256<<20))
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"harness-failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    common.finish("edit-terminal-relay-actual",status,details,roots={
        "edit-terminal-relay":relay,"composed-latest-editor":root,
        "prior-edit-original-fixtures":common.BASE/"root-recovery/application-reference-r1"})
if status!="PASS":raise SystemExit(1)
