"""New bounded public fixed-ELF and private actual-HIA Group9 qualification.

Every public expected result is produced by the exact original explicit importer
before target execution. Complete stdout/stderr, source/image bytes, each private
ABI buffer, canaries and process receipts are retained. No installed route is
selected and no ordinary P16 behavior is substituted.
"""
from __future__ import annotations
import argparse,json,os,resource,signal,stat,struct,sys,time,traceback
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from legacy_diagnostic_test_support_r2 import Buffer,CAS,NativeCalls,fact,save,usage,run_elf
from legacy_group9_public_plans_r1 import GROUPS,prepare
from legacy_group9_private_controls_r1 import run as private_run
ROLES=tuple(range(1,30))+tuple(range(40,48))
def digest(raw):return sha256(raw).hexdigest()
def main():
    start=time.monotonic_ns()
    parser=argparse.ArgumentParser()
    for name in ("bundle","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",choices=tuple(GROUPS)+("private-continuations",),required=True)
    args=parser.parse_args();reference=args.reference.resolve();bundle_path=args.bundle.resolve()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def deadline(*_):raise TimeoutError("Explicit legacy group original180wall")
    signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,180)
    sys.path.insert(0,str(reference))
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    cas=CAS(out/"cas");pins={};pin_rows=[];errors=[];primary=None
    actual=[];private_rows=[];images=[];trace=None;status="FAIL"
    def pin(path):
        path=Path(path).resolve();row=fact(path);raw=path.read_bytes()
        value=(raw,row["mode"])
        if path in pins:assert pins[path]==value
        else:
            pins[path]=value
            pin_rows.append(dict(row,evidence=cas.keep(raw)))
        return raw
    def binding(row,kind):
        path=Path(row[kind+"_path"]);raw=pin(path)
        assert (len(raw),digest(raw))==(row[kind+"_bytes"],row[kind+"_sha256"])
        return raw
    summary=dict(schema="hia-explicit-legacy-group9-runtime-r1",status="FAIL",group=args.group,
        original_limits=dict(cpu=90,wall=180,address=1<<30),
        exact_original_public_importer=True,ordinary_P16_invoked=False,
        code4_public_reachability_claimed=False,private_capsules_are_unissued=True,
        namespace_authority=False,installed_activation=False,whole_Worker_closed=False,
        whole_public_diagnostics_closed=False,old_case_counts_inherited=False)
    try:
        bundle=json.loads(pin(bundle_path))
        assert bundle["status"]=="BUILT_ONLY" and bundle["fresh_B3"]==4 and bundle["actual_packer_entries"]==2
        assert bundle["source_and_image_before_after_equal"]
        assert bundle["original_role46_exact_HIA_image_reproduced"] and bundle["original_whole_ELF_reproduced"]
        assert bundle["only_semantic_owner_replaced"]==46 and bundle["all_other36_source_image_bytes_retained"]
        assert set(map(int,bundle["components"]))==set(ROLES)
        project=Path(__file__).resolve().parents[1]
        for directory in (project/"tools",project/"development",project/"reference"):
            for path in sorted(directory.rglob("*")):
                if path.is_file() and path.suffix in (".py",".S") and not path.is_relative_to(out):pin(path)
        for directory in (reference/"hepta",reference/"tools"):
            for path in sorted(directory.glob("*.py")):pin(path)
        for table in (bundle["components"],bundle["original_components"]):
            for role in ROLES:
                for kind in ("source","image"):binding(table[str(role)],kind)
        executable=Path(bundle["executable"]["path"]);exe=pin(executable)
        assert (len(exe),digest(exe),stat.S_IMODE(executable.stat().st_mode))==(
            bundle["executable"]["bytes"],bundle["executable"]["sha256"],0o755)
        for row in bundle["compiled"]:pin(row["receipt_path"])
        pin(bundle["HIA_derivation"]);pin(bundle["executor_derivation"])
        if args.group=="private-continuations":
            save(out/"reference-stage.json",dict(status="PRIVATE_UNISSUED_CONTINUATIONS_ONLY",
                planned_cases=48,original_and_new_actual_terminal_comparisons=4,
                actual_public_importer_cases=0,whole_public_oracle_replaced=False))
            trace=NativeCalls(out/"actual-native")
            old=bundle["original_components"]["46"];new=bundle["components"]["46"]
            a=NativeHiaJsonImage(binding(old,"image"),expected_sha256=old["image_sha256"]);images.append(a)
            b=NativeHiaJsonImage(binding(new,"image"),expected_sha256=new["image_sha256"]);images.append(b)
            private_rows=private_run(bundle,a,b,trace,out/"private")
            assert len(private_rows)==48 and len(trace.entries)==130
            assert sum("actual-old" in row["label"] for row in trace.entries)==4
        else:
            plans,reference_evidence=prepare(reference,args.group,pin)
            assert len(plans)==GROUPS[args.group]
            planned=[]
            for plan in plans:
                expected=plan["expected"]
                serialized={k:(cas.keep(v) if isinstance(v,bytes) else v) for k,v in expected.items()}
                planned.append(dict(label=plan["label"],input=cas.keep(plan["source"]),expected=serialized))
            save(out/"complete-original-reference-plans.json",dict(
                original=reference_evidence,plans=planned,actual_target_entries_at_this_point=0))
            empty=out/"empty-runtime";empty.mkdir()
            for plan in plans:
                label=plan["label"];expected=plan["expected"]
                save(out/"pending-public-case.json",dict(label=label,input=cas.keep(plan["source"])))
                row=dict(label=label,status="FAIL",expected_kind=expected["kind"])
                try:
                    stdout,stderr,process=run_elf(executable,plan["source"],empty,out/"cases"/label,cas)
                    row["process"]=process
                    assert not process["timed_out"]
                    if expected["kind"]=="success":
                        assert process["returncode"]==0 and stderr==b""
                        assert stdout==expected["combined"],(label,"complete Core/report/structured bytes differ")
                        row.update(full_combined_bytes_equal=True,full_Core_and_report_and_structured_expected_retained=True)
                    else:
                        assert process["returncode"]==2 and stdout==b""
                        assert len(stderr)>=192
                        terminal=struct.unpack_from("<16Q",stderr)
                        frame=struct.unpack_from("<8Q",stderr,128)
                        code={"E_HIA_FORMAT":1,"E_HIA_VERSION_COLLISION":2,"E_HIA_LIMIT":3}[expected["code"]]
                        assert terminal[0]==bundle["constants"]["EVENT_MAGIC"] and terminal[1]==7
                        assert terminal[2]>0 and terminal[3]>0 and terminal[4:7]==(9,code,0)
                        assert frame==(bundle["constants"]["LG_DIAGNOSTIC"],1,9,code,
                            terminal[2],terminal[3],len(stderr)-128,len(stderr)-192)
                        assert stderr[192:]==expected["text"],(label,"complete original public diagnostic differs")
                        row.update(actual_group=9,actual_error=code,original_code=expected["code"],
                            complete_original_text_equal=True,original_terminal=cas.keep(stderr[:128]),
                            actual_HIALDE01=cas.keep(stderr[128:]),
                            private_header_not_substituted_for_public_case=True)
                    row["status"]="PASS"
                except BaseException as exc:
                    row["failure"]=dict(type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
                    errors.append(dict(phase="public-case",label=label,**row["failure"]))
                    if primary is None:primary=exc
                    traceback.print_exc()
                finally:
                    actual.append(row);save(out/"cases-completed.json",actual)
                    save(out/"pending-public-case.json",dict(status="NO_PENDING_CASE",completed=len(actual)))
            assert len(actual)==GROUPS[args.group]
            assert all(row["status"]=="PASS" for row in actual)
        status="PASS"
    except BaseException as exc:
        if primary is None:primary=exc
        errors.append(dict(phase="runtime",type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        try:traceback.print_exc()
        except BaseException as diagnostic:errors.append(dict(phase="traceback",type=type(diagnostic).__name__))
    finally:
        def attempt(phase,fn):
            nonlocal primary,status
            try:return fn()
            except BaseException as exc:
                status="FAIL";errors.append(dict(phase=phase,type=type(exc).__name__,error=str(exc)))
                if primary is None:primary=exc
                return None
        for image in images:attempt("close-image",image._mapping.close)
        if trace is not None:
            attempt("private-full-evidence",trace.verify)
            path=out/"private/completed-cases.json"
            if path.is_file():
                def read_private():
                    nonlocal private_rows
                    private_rows=json.loads(path.read_bytes())
                attempt("private-completed-ledger",read_private)
        attempt("CAS-full-readback",cas.verify)
        changed=[]
        for path,(raw,mode) in pins.items():
            try:
                assert not path.is_symlink() and path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
            except BaseException as exc:
                changed.append(str(path));errors.append(dict(phase="source-image-after",path=str(path),type=type(exc).__name__))
                if primary is None:primary=exc
        attempt("source-pins-receipt",lambda:save(out/"source-image-pins.json",pin_rows))
        if errors or primary is not None:status="FAIL"
        def budgets():
            used=usage();elapsed=time.monotonic_ns()-start
            assert 0<=used<90 and 0<=elapsed<180_000_000_000,("aggregate original group budget",used,elapsed)
            return used,elapsed
        measured=attempt("complete-group-budget",budgets)
        def report():
            cpu,elapsed=measured if measured is not None else (usage(),time.monotonic_ns()-start)
            summary.update(status=status,completed_cases=sum(r["status"]=="PASS" for r in actual)+len(private_rows),
                attempted_public_cases=len(actual),failed_public_cases=sum(r["status"]!="PASS" for r in actual),
                planned_cases=48 if args.group=="private-continuations" else GROUPS[args.group],
                actual_public_processes=sum("process" in r for r in actual),
                actual_private_entries=0 if trace is None else len(trace.entries),
                actual_private_original_entries=0 if trace is None else sum("actual-old" in r["label"] for r in trace.entries),
                source_image_executable_before_after_equal=not changed,
                complete_original_inputs_outputs_retained=True,
                aggregate_cpu_seconds=cpu,elapsed_ns=elapsed,
                primary=None if primary is None else dict(type=type(primary).__name__,error=str(primary)),
                errors=errors)
            save(out/"summary.json",summary)
        attempt("summary-receipt",report)
        attempt("summary-output",lambda:print("HIA_EXPLICIT_LEGACY_RUNTIME "+json.dumps(summary,sort_keys=True),flush=True))
        measured=attempt("post-output-group-budget",budgets)
        if errors or primary is not None:status="FAIL"
        attempt("final-summary-receipt",report)
        attempt("post-final-receipt-budget",budgets)
        if primary is not None:
            status="FAIL";attempt("failure-summary-rewrite",report)
        attempt("cancel-alarm",lambda:signal.setitimer(signal.ITIMER_REAL,0))
    if primary is not None:raise primary
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
