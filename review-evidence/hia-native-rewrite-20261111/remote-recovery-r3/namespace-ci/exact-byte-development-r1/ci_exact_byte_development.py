"""Fresh development proof of exact eight-byte helper expansion.

No production owner, VM, original 42-case test or ten-control source proof is
changed. This new leaf generates two probes and requires all four full byte
comparisons. Counts below are requirements until the original reports exist.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,importlib.util,json,math,os,stat,time,traceback
from pathlib import Path
COMMON_SHA="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
INPUT_SHA="371a901f338e73ce8f6fef837c36e50e09134325c2110f54bf88f3ae3994fd04"
INPUT_GIT="9daae94bf7313367abfccbebaf3118e25dc51809"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def observed(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode)),raw
def main():
    assert sys.version_info[:3]==(3,12,14)
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True)
    common_pin,common_raw=observed(common_path);assert common_pin["sha256"]==COMMON_SHA
    spec=importlib.util.spec_from_file_location("namespace_exact_byte_common",common_path)
    common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common
    exec(compile(common_raw,str(common_path),"exec"),common.__dict__)
    context=None;tree=None;started_ns=None;subject=None;status="FAIL"
    inputs={"common":common_pin};working=[];phase=None
    details=dict(schema="hia.namespace.exact-byte-development.ci.v1",status="INCOMPLETE",
        scope="NEW_EXACT_HELPER_BOUNDARY_LEAF_ONLY",actual_counts="UNKNOWN_UNTIL_COMPLETE",
        original_VM_modified=False,production_owner_modified=False,old42_reexecuted=False,
        old42_complete900_gate_still_required=True,original10_source_proof_replaced=False,
        ordinary_Store_closed=False,namespace_external_issuer_closed=False,new_cold_qualification=False,
        inherited_counts=False,arbitrary_fuel_equivalence_claimed=False,
        limits=dict(subject_tree_cpu_seconds=90,subject_wall_seconds=180,address_bytes=1<<30,core_bytes=0,
            B3_cpu_seconds=10,B3_wall_seconds=20,B3_address_bytes=256<<20,B3_output_bytes=1<<20,
            B3_workspace_bytes=1<<20,VM_steps=4000000,VM_bytes=32<<20,VM_depth=64))
    try:
        context=common.prepare()
        here=Path(__file__).resolve().parent
        launcher_pin,launcher_raw=observed(__file__);inputs["launcher"]=launcher_pin
        index=here/"inputs.json";index_pin,index_raw=observed(index)
        assert (index_pin["git"],index_pin["sha256"])==(INPUT_GIT,INPUT_SHA)
        manifest=json.loads(index_raw);inputs["manifest"]=index_pin
        assert manifest["schema"]=="hia.namespace.exact-byte-development.inputs.v1"
        assert manifest["reference"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
        assert manifest["common"]["sha256"]==COMMON_SHA and manifest["common"]["blob"]==common_pin["git"]
        assert manifest["compiler"]==dict(bytes=669556,sha256=B3)
        assert manifest["source_only_before_first_CI"] is True
        assert manifest["interpreter_changed"] is False and manifest["production_owners_changed"] is False
        expected=dict(fresh_B3=2,cases=564,VM_old=564,VM_new=564,native_old=564,native_new=564,
            returning_cases=185,trapping_cases=379)
        assert manifest["expected_not_observed"]==expected
        assert len(manifest["inputs"])==6 and len({r["path"] for r in manifest["inputs"]})==6
        tree=Path(context["base"])/"namespace-exact-byte-r1-inputs";tree.mkdir(exist_ok=False)
        for row in manifest["inputs"]:
            assert Path(row["path"]).name==row["path"] and row["mode"]=="100644"
            pin,raw=observed(here/row["path"])
            assert (pin["bytes"],pin["sha256"],pin["git"],pin["mode"])==(
                row["bytes"],row["sha256"],row["blob"],0o644),row["path"]
            inputs[row["path"]]=pin;target=tree/row["path"]
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(0o644);copied,copied_raw=observed(target)
            assert copied_raw==raw and copied["git"]==row["blob"]
            working.append(copied)
        assert len(manifest["exact_reference_files"])==4
        reference=Path(context["reference"])
        for row in manifest["exact_reference_files"]:
            relative=Path(row["path"]);assert not relative.is_absolute() and ".." not in relative.parts
            pin,raw=observed(reference/relative)
            assert (pin["bytes"],pin["sha256"],pin["git"],pin["mode"])==(
                row["bytes"],row["sha256"],row["blob"],0o644),row["path"]
            inputs["reference:"+row["path"]]=pin
        compiler_pin,compiler_raw=observed(context["compiler"])
        assert (compiler_pin["bytes"],compiler_pin["sha256"])==(669556,B3)
        inputs["compiler"]=compiler_pin
        corpus=json.loads((tree/"boundary-corpus.json").read_bytes())
        assert len(corpus["cases"])==564 and len({r["label"] for r in corpus["cases"]})==564
        save(Path(context["output"])/"namespace-exact-byte-source-before.json",dict(inputs=inputs,working=working))
        subject=Path(context["output"])/"namespace-exact-byte-unroll-r1"
        started_ns=time.monotonic_ns()
        phase=dict(started_monotonic_ns=started_ns,limit_ns=180000000000,
            end_boundary="all subject reports, full ledger and final source identities checked; before common.finish")
        save(Path(context["output"])/"namespace-exact-byte-phase-budget.json",phase)
        receipt=common.run("namespace-exact-byte-full-boundary",
            [context["python"],"-B",tree/"test-exact-byte-boundary.py","--context",
             Path(context["output"])/"context.json","--inputs",tree],
            cwd=reference,timeout=180,env={"PYTHONDONTWRITEBYTECODE":"1"})
        details["original_process_receipt"]=receipt
        cpu=receipt["child_cpu_seconds"]
        assert type(cpu) in (int,float) and math.isfinite(cpu) and 0<=cpu<90,receipt
        assert 0<=receipt["elapsed_ns"]<180000000000 and receipt["returncode"]==0 and not receipt["timed_out"]
        summary_pin,summary_raw=observed(subject/"summary.json");summary=json.loads(summary_raw)
        details["original_subject_summary_pin"]=summary_pin
        assert summary["status"]=="PASS_DEVELOPMENT_BOUNDARY_ONLY"
        assert summary["actual_compiles"]==2
        assert summary["cases_completed"]==summary["VM_old"]==summary["VM_new"]==summary["native_old"]==summary["native_new"]==564
        assert summary["returned_cases"]==185 and summary["trapped_cases"]==379
        assert 0<summary["steps_new"]<summary["steps_old"]
        assert summary["source_pins_unchanged"] and not summary["source_changes"] and not summary["cleanup_errors"]
        assert summary["within_original_tree90"] and 0<=summary["full_process_tree_CPU_seconds"]<90
        assert summary["within_original_wall180"] and 0<=summary["wall_ns"]<180000000000
        assert summary["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
        assert summary["ordinary_Store_closed"] is False and summary["old42_qualification_reexecuted"] is False
        assert summary["reference_VM_modified"] is False and summary["arbitrary_fuel_equivalence_claimed"] is False
        assert summary["complete_return_and_operand_comparison"] and summary["partial_native_writes_observed"]
        ledger_pin,ledger_raw=observed(subject/"all-cases.jsonl.gz")
        complete=gzip.decompress(ledger_raw);lines=complete.splitlines()
        assert len(lines)==564 and complete.endswith(b"\n")
        rows=[json.loads(line) for line in lines]
        assert [r["index"] for r in rows]==list(range(564))
        assert [r["case"] for r in rows]==corpus["cases"]
        assert sum(r["old_VM"]["status"]=="returned" for r in rows)==185
        assert sum(r["old_VM"]["status"]=="trapped" for r in rows)==379
        assert sum(r["old_steps"] for r in rows)==summary["steps_old"]
        assert sum(r["new_steps"] for r in rows)==summary["steps_new"]
        cas_checked={}
        def check_cas(row):
            path=Path(row["path"]);assert path.parent==subject/"cas" and path.name==row["sha256"]
            if path not in cas_checked:
                pin,raw=observed(path);cas_checked[path]=pin
            pin=cas_checked[path]
            assert (pin["bytes"],pin["sha256"])==(row["bytes"],row["sha256"])
        for row in rows:
            assert row["complete_equal"] and row["no_masks"]
            assert row["old_VM"]==row["new_VM"] and row["old_resources"]==row["new_resources"]
            assert 0<row["new_steps"]<=row["old_steps"]<=4000000
            assert set(row["native"])=={"old","new"}
            vm_status={k:v for k,v in row["old_VM"].items() if k!="message"}
            assert len(row["full_bytes"])==3
            for item in row["full_bytes"]:check_cas(item)
            before_pin,before_raw=observed(subject/"cases"/("%04d"%row["index"])/"before.json")
            before=json.loads(before_raw)
            assert before["index"]==row["index"] and before["case"]==row["case"] and len(before["buffers"])==3
            for item in before["buffers"]:check_cas(item)
            for label,native in row["native"].items():
                assert native["outcome"]==vm_status and native["complete_buffers"]==row["full_bytes"]
                assert native["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
                assert native["guards"] and native["source_unchanged"] and native["pid"]>0 and native["parent_pid"]>0
                if vm_status["status"]=="returned":assert native["returncode"]==0
                else:assert native["returncode"]==-4
                check_cas(native["process_ready_bytes"])
                for name in ("stdout","stderr"):
                    item=native[name];pin,raw=observed(item["path"])
                    assert (pin["bytes"],pin["sha256"])==(item["bytes"],item["sha256"])
                    if name=="stdout":assert raw==b""
        details["actual_counts"]=dict(fresh_B3=2,cases=564,VM_old=564,VM_new=564,native_old=564,native_new=564,
            returning_cases=185,trapping_cases=379,steps_old=summary["steps_old"],steps_new=summary["steps_new"],
            complete_CASE_CAS_members_checked=len(cas_checked),original_counts_inherited=False)
        details.update(status="PASS_DEVELOPMENT_BOUNDARY_ONLY",
            original_ledger_pin=ledger_pin,original_ledger_decompressed_bytes=len(complete),
            original_ledger_decompressed_sha256=sha(complete),original_summary=summary)
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if subject is not None:
            original=subject/"summary.json"
            if original.exists():
                try:
                    pin,raw=observed(original)
                    details["original_subject_summary_pin"]=pin
                    details["original_subject_summary"]=json.loads(raw)
                except BaseException as error:details["original_summary_read_error"]=repr(error)
        errors=[]
        for label,row in list(inputs.items())+[("working:"+str(i),r) for i,r in enumerate(working)]:
            try:
                after,raw=observed(row["path"]);assert after==row
            except BaseException as error:errors.append(dict(label=label,path=row["path"],error=repr(error)))
        details.update(source_before=list(inputs.values()),working_source_before=working,
            source_after_equal=not errors,source_after_errors=errors)
        if errors:status="FAIL";details["status"]="FAIL"
        if started_ns is not None:
            ended_ns=time.monotonic_ns();elapsed_ns=ended_ns-started_ns
            phase.update(ended_monotonic_ns=ended_ns,elapsed_ns=elapsed_ns,source_after_checks_finished=True,
                within_original_wall180=0<=elapsed_ns<180000000000)
            details["phase_budget"]=phase
            if not phase["within_original_wall180"]:
                status="FAIL";details["status"]="FAIL"
                details["budget_violation"]="complete fresh leaf exceeded original180wall"
            save(Path(context["output"])/"namespace-exact-byte-phase-budget.json",phase)
        common.finish("NAMESPACE_EXACT_BYTE_DEVELOPMENT_BOUNDARY",status,details,
            roots={"namespace-exact-byte-inputs":tree} if tree is not None else {})
        print("NAMESPACE_EXACT_BYTE_FINAL "+json.dumps(dict(status=status,scope=details["scope"],
            actual_counts=details["actual_counts"],old42_reexecuted=False,
            production_owner_modified=False,ordinary_Store_closed=False)),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
