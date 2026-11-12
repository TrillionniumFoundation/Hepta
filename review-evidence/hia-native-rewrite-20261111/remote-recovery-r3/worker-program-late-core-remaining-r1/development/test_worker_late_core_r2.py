"""Actual public late Core boundaries and separate private continuation controls.

Every public expected payload comes from the exact unselected original
verify_program before the fixed ELF starts. The private child-frame tests
do not establish public reachability or external issuer authentication.
"""
from __future__ import annotations
import argparse,ast,copy,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
GROUPS={"late-node-below":1,"late-node-equal":1,"late-node-over":1,
        "late-byte-below":1,"late-byte-equal":1,"late-byte-over":1,
        "late-depth-and-order":6,"late-private-protocol":38}
p=argparse.ArgumentParser()
p.add_argument("--bundle",type=Path,required=True)
p.add_argument("--reference",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
p.add_argument("--group",choices=tuple(GROUPS),required=True)
a=p.parse_args()
OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
REF=a.reference.resolve();PROJECT=Path(__file__).resolve().parents[1]
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
SELF_PARENT=os.getpid();START=time.monotonic_ns()
INITIAL_CPU=resource.getrusage(resource.RUSAGE_SELF)
INITIAL_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
PINS={};ROWS=[];PLAN=[];CASE_FAILURES=[]
NATIVE=0;KERNEL_ENTRIES=0;FAILED=None;STATUS="FAIL";PRIVATE=None
source_errors=[]
def fallback_save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def diagnostic_native_planned():
    for index,row in enumerate(PLAN):
        lease=0x575d0001+index*8;request=index+1
        packet=header(row["source"],row["mode"],lease,request,tree=row["tree"])+row["source"]
        process,stdout,stderr=actual(row["label"],packet)
        observation=dict(label=row["label"],process=process,
          actual_complete_stdout=cas(stdout),actual_complete_stderr=cas(stderr),
          expected_complete_payload=cas(row["expected"]["payload"]),
          public_original_oracle=True,enum_not_substituted=True)
        # Preserve the actual complete outputs before any semantic assertion.
        save(OUT/"cases"/row["label"]/"comparison-before-assert.json",observation)
        try:
            result=parse_result(process,stdout,stderr,row,lease,request)
            observation.update(status="PASS",result=cas(result),
               complete_payload_and_Core_bytes_equal=True,actual_receipt_digests_equal=True)
        except AssertionError as exc:
            failure=dict(label=row["label"],error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc())
            CASE_FAILURES.append(failure);observation.update(status="FAIL",failure=failure)
            traceback.print_exc()
        ROWS.append(observation);save(OUT/"cases-completed.json",ROWS)


try:
    original=PROJECT/"development/test_worker_program_service_r4.py"
    original_raw=original.read_bytes()
    assert len(original_raw)==27251
    assert sha256(original_raw).hexdigest()=="d10d9b4f2289a4e770a6680a2a10a81975d941bcec387cfd4fb59f3f23c37937"
    nodes=ast.parse(original_raw,filename=str(original)).body
    definitions=[node for node in nodes if isinstance(node,ast.FunctionDef)]
    assert len({node.name for node in definitions})==len(definitions)
    # Exact development helpers only. The old main, parser, groups and tests
    # are never executed as a runtime fallback or inherited result.
    exec(compile(ast.Module(body=definitions,type_ignores=[]),
                 str(original)+":exact-test-functions","exec"),globals())
    pin(original);pin(__file__)
    bundle_raw=pin(a.bundle);bundle=json.loads(bundle_raw)
    EXE=Path(bundle["executable_path"]);exe_raw=pin(EXE)
    assert (len(exe_raw),digest(exe_raw))==(bundle["executable_bytes"],bundle["executable_sha256"])
    assert bundle["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
    assert (bundle["fresh_compiles"],bundle["nonzero_images"])==(13,43)
    assert bundle["native_type_context_capture_roles"]==[8,40,41,43,46,50,56]
    assert bundle["inherited_composite_refusal_text_missing_groups"]==[9]
    assert bundle["fixed_diagnostic_groups"]==[1,2,3,4,5]
    late=json.loads(pin(bundle["native_late_Core_adaptation"]))
    origin=json.loads(pin(bundle["exact_retained_late_Core_reproduction"]))
    assert late["changed_original_methods"]==["prefix_failure"]
    assert late["every_other_method_AST_exact"] and late["assembly_service_bytes_exact"]
    assert late["constants_and_executor_masks_unchanged"]
    imports=json.loads(pin(bundle["exact_new_late_Core_import_closure"]))
    assert imports["status"]=="PASS" and imports["all_new_static_imports_resolved"]
    assert imports["new_B3_entries_at_this_gate"]==imports["new_target_entries_at_this_gate"]==0
    mask=json.loads(pin(bundle["diagnostic_mask_proof"]))
    assert mask["schema"]=="hia-worker-type-context-fixed-executor-r2"
    assert mask["allowed_new_child_component"]==50 and mask["allowed_child_kind"]==0
    assert mask["allowed_reader_calling_drivers"]==[41,43]
    assert mask["exact_reverse_restoration_equal"] and mask["all_other_instruction_text_exact"]
    assert origin["complete_original_members"]==2981 and origin["complete_original_raw_bytes"]==218379198
    assert origin["exact_role23_HIA_reproduced"] and origin["original_bytes_SHA256_modes_all_checked"]
    for row in bundle["role_bindings"].values():
        for key,sha,size in (("source_path","source_sha256","source_bytes"),("image_path","image_sha256","image_bytes")):
            raw=pin(row[key]);assert (len(raw),digest(raw))==(row[size],row[sha])
    sys.path.insert(0,str(REF))
    from hepta.hia_program import HIAProgramRejected,verify_program
    from hepta.hia_agent_assembly import HIAAssemblyRejected,render_assembly,assemble_program,diagnose_assembly
    if a.group!="late-private-protocol":
        path=PROJECT/"development/late_core_public_plans_r3.py"
        pin(path)
        spec=importlib.util.spec_from_file_location("worker_original_public_late_Core_plans",path)
        peer=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer)
        peer.plan(globals(),a.group)
        assert len(PLAN)==GROUPS[a.group]
        record_plan()
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename and Path(filename).suffix==".py":
            path=Path(filename).resolve()
            if path.is_relative_to(REF) or path.is_relative_to(PROJECT):pin(path)
    if a.group=="late-private-protocol":
        path=PROJECT/"development/late_core_private_controls_r2.py";pin(path)
        spec=importlib.util.spec_from_file_location("worker_private_late_Core_controls",path)
        peer=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer)
        PRIVATE=peer.run(globals())
        assert NATIVE==0 and KERNEL_ENTRIES>0 and PRIVATE["planned_cases"]==38
    else:
        diagnostic_native_planned()
        assert NATIVE==GROUPS[a.group] and KERNEL_ENTRIES==0
    assert len(ROWS)==GROUPS[a.group]
    if CASE_FAILURES:raise AssertionError(("public full-text mismatches",len(CASE_FAILURES)))
    assert all(row["status"]=="PASS" for row in ROWS)
    STATUS="PASS"
except BaseException as exc:
    FAILED=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    pin_rows=[]
    for path,(raw,mode) in PINS.items():
        try:
            assert path.is_file() and not path.is_symlink()
            assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
        except BaseException as exc:
            source_errors.append(dict(path=str(path),error_class=type(exc).__name__,error=str(exc)))
        pin_rows.append(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=mode))
    same=not source_errors
    if not same:STATUS="FAIL"
    fallback_save(OUT/"source-pins.json",pin_rows)
    current=resource.getrusage(resource.RUSAGE_SELF)
    children=resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu=(current.ru_utime+current.ru_stime-INITIAL_CPU.ru_utime-INITIAL_CPU.ru_stime+
         children.ru_utime+children.ru_stime-INITIAL_CHILD.ru_utime-INITIAL_CHILD.ru_stime)
    elapsed=time.monotonic_ns()-START
    if cpu>=90 or elapsed>=180000000000:
        STATUS="FAIL"
        FAILED=dict(error_class="OriginalAggregateBudgetObservation",actual_cpu_seconds=cpu,
                    actual_elapsed_ns=elapsed,earlier_failure=FAILED)
    report=dict(schema="hia-worker-late-Core-actual-r1",status=STATUS,group=a.group,
        planned_cases=GROUPS[a.group],planned_semantic_cases=len(PLAN),attempted_case_results=len(ROWS),
        completed_cases=sum(row["status"]=="PASS" for row in ROWS),
        failed_cases=sum(row["status"]=="FAIL" for row in ROWS),
        actual_native_processes=NATIVE,actual_private_kernel_entries=KERNEL_ENTRIES,
        aggregate_cpu_seconds=cpu,elapsed_ns=elapsed,failure=FAILED,
        source_after_errors=source_errors,public_case_failures=CASE_FAILURES,private_controls=PRIVATE,
        full_public_payload_required=True,public_oracle_is_unselected_original=True,
        enum_table_cannot_replace_public_oracle=True,
        source_image_executable_before_after_equal=same,
        old_case_counts_inherited=False,old_whole_type_join_cases_rerun=False,
        original_limits=dict(cpu=90,wall=180,address=1<<30),
        original_snapshot_before_primitive_and_byte_order_required=True,
        public_late_depth_status1_reachability_claimed=False,
        private_unissued_header_tests_not_public_authentication=True,
        explicit_legacy_importer_group9_not_invoked=True,
        whole_public_diagnostics_closed=False,namespace_issued=False,
        whole_worker_closed=False,installed_activation=False,cold_qualified=False)
    fallback_save(OUT/"summary.json",report)
    print("HIA_WORKER_LATE_CORE_GROUP "+json.dumps(report,sort_keys=True),flush=True)
if STATUS!="PASS":raise SystemExit(1)
