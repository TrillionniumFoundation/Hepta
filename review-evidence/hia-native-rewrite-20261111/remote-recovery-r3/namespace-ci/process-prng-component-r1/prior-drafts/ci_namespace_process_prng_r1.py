"""Independent one-budget complete selected process PRNG development gate.

Fresh original C reference plus fresh B3 HIA, full VM/native windows, source
after-custody and the complete ledger stay inside one90CPU/180wall subject.
Physical initialization, mutex and VFS issuers remain OPEN.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,importlib.util,json,os,stat,time,traceback
from pathlib import Path
COMMON="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
INPUT_SHA="51892b86920f592576b2721fdaa8f44dfa36ac624fdd1eeebf11941a28179fa3"
INPUT_GIT="a2401f9ca3af0f9a1676f6ae4ded6e683f76775e"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def observed(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode)),raw
def main():
    assert sys.version_info[:3]==(3,12,14)
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True)
    common_pin,raw=observed(common_path);assert common_pin["sha256"]==COMMON
    spec=importlib.util.spec_from_file_location("namespace_prng_common",common_path)
    common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common
    exec(compile(raw,str(common_path),"exec"),common.__dict__)
    context=None;tree=None;subject=None;started=None;status="FAIL";working=[];pins={"common":common_pin}
    details=dict(schema="hia.namespace.process-prng.fresh-ci.v1",status="INCOMPLETE",
        scope="COMPLETE_SELECTED_SQLITE3461_PRNG_WITH_CONTROLLED_TYPED_PEERS",
        actual_counts="UNKNOWN_UNTIL_COMPLETE",whole_tree_CPU_seconds=90,whole_subject_wall_seconds=180,
        original_qualifications_reexecuted=False,counts_inherited=False,new_cold_qualification=False,
        installed_native_issuer_implemented=False,ordinary_unixOpen_closed=False,ordinary_Store_closed=False)
    try:
        context=common.prepare();here=Path(__file__).resolve().parent
        pins["launcher"],_=observed(Path(__file__))
        mp,mraw=observed(here/"inputs.json")
        assert mp["sha256"]==INPUT_SHA and mp["git"]==INPUT_GIT;pins["inputs"]=mp
        manifest=json.loads(mraw)
        assert manifest["reference_commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
        assert manifest["compiler_sha256"]==B3 and manifest["compiler_bytes"]==669556
        assert len(manifest["inputs"])==10
        tree=Path(context["base"])/"namespace-process-prng-r1-source";tree.mkdir(parents=False,exist_ok=False)
        for row in manifest["inputs"]:
            assert Path(row["path"]).name==row["path"]
            before,body=observed(here/row["path"])
            assert (before["bytes"],before["sha256"],before["git"],before["mode"])==(
                row["bytes"],row["sha256"],row["blob"],int(row["mode"][-3:],8))
            pins[row["path"]]=before
            target=tree/row["path"];target.write_bytes(body);target.chmod(before["mode"])
            after,copy=observed(target);assert copy==body
            assert (after["bytes"],after["sha256"],after["git"],after["mode"])==(
                before["bytes"],before["sha256"],before["git"],before["mode"])
            working.append(after)
        original_compiler,compiler_raw=observed(Path(context["compiler"]))
        assert original_compiler["sha256"]==B3 and original_compiler["bytes"]==669556
        pins["original-qualified-B3"]=original_compiler
        compiler_dir=tree/"compiler";compiler_dir.mkdir()
        compiler=compiler_dir/"B3.image.bin";compiler.write_bytes(compiler_raw);compiler.chmod(original_compiler["mode"])
        compiler_pin,copy=observed(compiler);assert copy==compiler_raw;working.append(compiler_pin)
        subject=Path(context["output"])/"process-prng-r1"
        local=dict(context,compiler=str(compiler),original_compiler=original_compiler,
                   prng_working=str(tree),prng_evidence=str(subject))
        context_path=Path(context["output"])/"prng-context.json";save(context_path,local)
        source_before=Path(context["output"])/"prng-source-before.json"
        save(source_before,dict(inputs=pins,working=working))
        started=time.monotonic_ns()
        details["subject_phase"]=dict(started_monotonic_ns=started,
            deadline_monotonic_ns=started+180_000_000_000,
            end_boundary="All original report/ledger/CAS and source-after checks, before common.finish sealing")
        receipt=common.run("complete-process-PRNG-originalC-VM-native-one-budget",
            [context["python"],"-B",str(tree/"validate_process_prng.py"),"--context",str(context_path),"--inputs",str(tree)],
            cwd=context["reference"],timeout=180,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"))
        details["whole_process_receipt"]=receipt
        cpu=receipt["child_cpu_seconds"]
        assert type(cpu) in (int,float) and 0<=cpu<90
        report_pin,report_raw=observed(subject/"summary.json");report=json.loads(report_raw)
        details["original_complete_report"]=report_pin
        assert report["status"]=="PASS_COMPONENT_ONLY"
        assert report["fresh_B3_compiles"]==report["reference_C_compiles"]==1
        assert report["semantic_scenarios"]==34 and report["original_C_calls"]==report["semantic_cases"]==122
        assert report["random_original_C_calls"]==103 and report["save_restore_original_C_calls"]==19
        assert report["protocol_controls"]==65 and report["private_positive_controls"]==1
        assert report["VM_entries"]==report["native_entries"]>0
        assert report["actual_namespace_OS_effects"]==0
        assert report["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert 0<=report["whole_tree_CPU_seconds"]<90 and 0<=report["elapsed_ns_including_source_after"]<180_000_000_000
        assert report["source_pins_unchanged"] and not report["after_errors"] and not report["cleanup_errors"]
        for key in ("all_reference_output_current_saved_and_callback_order_equal",
                    "all_complete_return_input_output_workspace_equal","no_masks",
                    "source_image_bound","all_CAS_files_rehashed","permanent_refusal_where_poison_storage_exists",
                    "original_full_positive_int_no_added_quota"):
            assert report[key] is True,key
        assert not report["ordinary_Store_closed"] and not report["actual_native_mutex_or_VFS_issuer"]
        for row in report["source_before"].values():
            actual,_=observed(row["path"]);assert actual==row
        cas=subject/"cas";checked=set()
        def verify_cas(value):
            if type(value) is dict:
                if set(("path","bytes","sha256"))<=set(value):
                    path=Path(value["path"])
                    if path.parent==cas:
                        assert path.name==value["sha256"]
                        if path.name not in checked:
                            actual,_=observed(path)
                            assert actual["bytes"]==value["bytes"] and actual["sha256"]==value["sha256"]
                            checked.add(path.name)
                        else:
                            assert path.stat().st_size==value["bytes"]
                for child in value.values():verify_cas(child)
            elif type(value) is list:
                for child in value:verify_cas(child)
        counts=dict(before=0,after=0,semantic=0,protocol=0,reference_C_completed=0,private_positive=0)
        semantic_names=set();protocol_names=set();last_before=None
        with gzip.open(subject/"complete-entries.jsonl.gz","rt",encoding="utf-8") as stream:
            for line in stream:
                row=json.loads(line);verify_cas(row);kind=row["kind"]
                if kind=="before":
                    assert last_before is None
                    counts["before"]+=1;assert row["index"]==counts["before"];last_before=row
                elif kind=="after":
                    assert last_before is not None and row["index"]==last_before["index"]
                    assert row["label"]==last_before["label"] and row["complete_equal"] and row["canaries"] and row["input_readonly"]
                    assert row["input"]==last_before["input"] and 0<row["VM_steps"]<=4000000
                    counts["after"]+=1;last_before=None
                elif kind=="semantic":
                    assert row["complete"] and row["name"] not in semantic_names
                    semantic_names.add(row["name"]);counts["semantic"]+=1
                elif kind=="protocol":
                    assert row["refused"] and row["name"] not in protocol_names
                    protocol_names.add(row["name"]);counts["protocol"]+=1
                elif kind=="reference-C-completed":
                    counts["reference_C_completed"]+=1
                    assert row["original_C_call"]==counts["reference_C_completed"]
                elif kind=="private-positive":
                    assert row["name"]=="max-positive-int-GROW" and row["returncode"]==2 and row["no_new_byte_quota"]
                    counts["private_positive"]+=1
                else:raise AssertionError(("unknown ledger record",kind))
        assert last_before is None
        assert counts["before"]==counts["after"]==report["native_entries"]
        assert counts["semantic"]==counts["reference_C_completed"]==122
        assert counts["protocol"]==65 and counts["private_positive"]==1
        actual_files=list(cas.iterdir())
        for path in actual_files:
            actual,_=observed(path);assert actual["sha256"]==path.name
        assert checked and checked==set(path.name for path in actual_files)
        expected_semantics={scenario["name"]+"/"+str(i)
            for scenario in json.loads((tree/"semantic-corpus.json").read_bytes())["scenarios"]
            for i in range(len(scenario["operations"]))}
        assert semantic_names==expected_semantics and len(semantic_names)==122
        details.update(status="PASS_COMPONENT_ONLY",actual_counts=dict(
            fresh_B3_compiles=1,reference_C_compiles=1,semantic_scenarios=34,original_C_calls=122,
            random_original_C_calls=103,save_restore_original_C_calls=19,protocol_refusals=65,
            private_positive_controls=1,VM_entries=report["VM_entries"],native_entries=report["native_entries"],
            actual_namespace_OS_effects=0),
            complete_ledger_counts=counts,complete_CAS_files=len(checked),all_original_ledger_and_CAS_verified=True)
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if subject is not None and (subject/"summary.json").is_file():
            try:
                pin,body=observed(subject/"summary.json")
                details["original_complete_report"]=pin
                # Emit the whole producer report, not a truncated selection.
                print("NAMESPACE_PRNG_ORIGINAL_REPORT "+body.decode("utf-8"),flush=True)
            except BaseException as error:
                details.setdefault("after_errors",[]).append(dict(scope="original-report",error=repr(error)));status="FAIL"
        after_errors=[]
        for row in list(pins.values())+working:
            try:actual,_=observed(row["path"]);assert actual==row
            except BaseException as error:after_errors.append(dict(path=row["path"],error=repr(error)))
        details.update(inputs=pins,working=working,source_pins_unchanged=not after_errors)
        if after_errors:
            details.setdefault("after_errors",[]).extend(after_errors);status="FAIL"
        if started is not None:
            elapsed=time.monotonic_ns()-started;details["subject_phase"].update(
                elapsed_ns=elapsed,source_after_checks_finished=True,within_original180=0<=elapsed<180_000_000_000)
            if not 0<=elapsed<180_000_000_000:
                details.setdefault("after_errors",[]).append(dict(scope="complete-subject-wall180",elapsed_ns=elapsed));status="FAIL"
        if status!="PASS":details["status"]="FAIL"
        common.finish("NAMESPACE_COMPLETE_SELECTED_PROCESS_PRNG",status,details,
            roots={"namespace-prng-working-source":tree} if tree is not None else {})
        print("NAMESPACE_PRNG_FINAL "+json.dumps(dict(status=status,actual_counts=details["actual_counts"],
            ordinary_Store_closed=False,actual_native_mutex_or_VFS_issuer=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
