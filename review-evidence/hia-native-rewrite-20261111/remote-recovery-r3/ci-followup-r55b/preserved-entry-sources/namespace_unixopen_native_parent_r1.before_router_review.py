"""Fresh selected unixOpen parent component gate; all 18 effects are foreign.

The six original SQLite C bodies are the reference. This does not issue real
namespace leases, call SQLite for storage, or close the ordinary Store gap.
"""
from __future__ import annotations

# BEGIN HIA EXPLICIT SOURCE ENTRY ROUTE R1
if __name__ == "__main__":
    def _hia_explicit_source_entry_r1():
        import hashlib as _hashlib
        import json as _json
        import os as _os
        from pathlib import Path as _Path
        import stat as _stat
        import types as _types
        if _os.environ.get("GITHUB_EVENT_NAME") != "push":
            return
        _event_raw = _Path(_os.environ["GITHUB_EVENT_PATH"]).read_bytes()
        _event = _json.loads(_event_raw)
        if "[hia-ci:namespace-unixopen-actual-native-issuer]" not in _event.get("head_commit", {}).get("message", ""):
            return
        _root = _Path(_os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        _helper = _root / "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci/explicit_gate_entry_router_r1.py"
        _mode = _helper.lstat().st_mode
        if _helper.is_symlink() or not _stat.S_ISREG(_mode) or _stat.S_IMODE(_mode) != 0o644:
            raise RuntimeError("explicit entry helper must be regular mode 100644")
        _raw = _helper.read_bytes()
        if (len(_raw), _hashlib.sha1(b"blob " + str(len(_raw)).encode("ascii") + b"\0" + _raw).hexdigest(), _hashlib.sha256(_raw).hexdigest()) != (6744, "a5f7cc8cb780fb3fbbede532c2865c4a22f27999", "31508372f9385d98dc9367ebe9460043805cdd9c48b7c6838cffecb3df9777b8"):
            raise RuntimeError("explicit entry helper full pin mismatch")
        _module = _types.ModuleType("hia_explicit_source_entry_router_r1")
        _module.__file__ = str(_helper)
        exec(compile(_raw, str(_helper), "exec"), _module.__dict__)
        _module.dispatch({"job":"namespace_unixopen_native_parent_r1","selector":"[hia-ci:namespace-unixopen-actual-native-issuer]","scope":"Actual nine-role UnixOpen getpid prefix; 28 fresh physical processes and fixed continuation refusals","caller_path":"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/namespace-ci/unixopen-native-parent-r2/ci_namespace_unixopen_parent_r2.py","target":{"path":"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/namespace-ci/unixopen-actual-native-issuer-gate-r1/ci_actual_unixopen.py","mode":"100644","bytes":25390,"gitsha":"f3a704a39724c2467dae487718dcd03de7369220","sha256":"9f48a7d6bea74c476e37b11adb9001a69a46ed1eeb6a88264a61bc45042032ba"}}, __file__, _event_raw, _raw)
        raise RuntimeError("selected explicit route returned without an exit")
    _hia_explicit_source_entry_r1()
    del _hia_explicit_source_entry_r1
# END HIA EXPLICIT SOURCE ENTRY ROUTE R1

import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,os,stat,time,traceback
from pathlib import Path
COMMON_SHA="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
INPUT_SHA="a460b66767cc1bd65521ec8a33c8071de47f959dd718c647fe9493405ca33456"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode))
def same(row):return pin(Path(row["path"]))==row
def main():
    assert sys.version_info[:3]==(3,12,14)
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True)
    raw=common_path.read_bytes();assert sha(raw)==COMMON_SHA
    spec=importlib.util.spec_from_file_location("namespace_unixopen_ci_common",common_path)
    common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common
    exec(compile(raw,str(common_path),"exec"),common.__dict__)
    inputs={};working=[];context=None;evidence=None;status="FAIL"
    details=dict(schema="hia.namespace.unixopen.parent.fresh-ci.v1",status="INCOMPLETE",
        scope="NEW_SELECTED_ORIGINAL_C_PARENT_CONTROL_FLOW_EXPLICIT_FOREIGN_EFFECTS",
        actual_counts="UNKNOWN_UNTIL_RETURNED_REPORTS",actual_namespace_syscalls=0,
        actual_issued_namespace_authorities=0,ordinary_unixOpen_closed=False,
        ordinary_Store_closed=False,SQL31_closed=False,no_existing_target_rerun=True,
        original_900_seconds_failures_unchanged=True,inherited_counts=False,
        compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_bytes=256<<20,output_bytes=1<<20,workspace_bytes=1<<20),
        component_process_limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0),
        component_execution_aggregate_wall_seconds=900,VM_steps=4000000,VM_arena_bytes=32<<20,
        required_cases=85,required_protocol_controls=42)
    try:
        context=common.prepare()
        assert context["compiler"] and pin(Path(context["compiler"]))["sha256"]==B3
        here=Path(__file__).resolve().parent;inputs["launcher"]=pin(Path(__file__).resolve())
        manifest_path=here/"inputs.json";manifest_raw=manifest_path.read_bytes()
        assert sha(manifest_raw)==INPUT_SHA
        manifest=json.loads(manifest_raw);inputs["manifest"]=pin(manifest_path)
        assert len(manifest["inputs"])==7
        assert manifest["reference_commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
        assert manifest["compiler_sha256"]==B3 and manifest["compiler_bytes"]==669556
        base=Path(context["base"]);tree=base/"namespace-unixopen-parent-r2-source"
        tree.mkdir(parents=False,exist_ok=False);(tree/"tools").mkdir()
        paths={}
        for row in manifest["inputs"]:
            path=here/row["path"];actual=pin(path)
            assert (actual["bytes"],actual["sha256"],actual["git"],actual["mode"])==(row["bytes"],row["sha256"],row["blob"],int(row["mode"][-3:],8))
            inputs[row["path"]]=actual;target=tree/"inputs"/row["path"]
            target.parent.mkdir(parents=True,exist_ok=True)
            data=path.read_bytes();target.write_bytes(data);target.chmod(actual["mode"])
            assert target.read_bytes()==data
            paths[path.name]=str(target);working.append(pin(target))
        for name in ("generate_hia_agent_namespace_unixopen_parent.py",
                     "generate_hia_agent_namespace_store.py","generate_hia_agent_namespace_objects.py"):
            target=tree/"tools"/name;source=Path(paths[name])
            target.write_bytes(source.read_bytes());target.chmod(0o644)
            assert target.read_bytes()==source.read_bytes();working.append(pin(target))
        evidence=Path(context["output"])/"unixopen-native-parent-r2";evidence.mkdir()
        context=dict(context,namespace_working=str(tree),namespace_evidence=str(evidence),namespace_input_paths=paths)
        context_path=evidence/"context.json";save(context_path,context)
        environment=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
        save(evidence/"source-before.json",dict(inputs=inputs,working=working))
        deadline=time.monotonic()+900
        def run(label,args):
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError("unixOpen component original 900-second aggregate")
            return common.run(label,args,cwd=context["reference"],timeout=min(180,remaining),env=environment)
        validation=paths["namespace-unixopen-validate.py"]
        build_process=run("unixopen-parent-fresh-HIA-B3-and-original-six-body-C",
            [context["python"],"-B",validation,"--context",context_path,"--mode","build"])
        built=json.loads((evidence/"build/summary.json").read_bytes())
        details["build_process"]=build_process;details["build"]=built
        assert built["status"]=="PASS_BUILD_ONLY" and built["fresh_B3_compiles"]==1
        assert built["source_pins_unchanged"]
        assert built["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert built["original_c_build"]["all_bodies_copied_without_edits"]
        assert len(built["original_c_build"]["bodies"])==6
        assert built["original_c_build"]["actual_namespace_syscalls"]==0
        inventory_pin=pin(evidence/"build/case-inventory.json")
        batch_reports=[];names=[];total_VM=total_native=total_C=0
        for start in range(0,85,10):
            end=min(start+10,85)
            process=run("unixopen-parent-C-VM-native-"+str(start)+"-"+str(end),
                [context["python"],"-B",validation,"--context",context_path,"--mode","semantic","--start",str(start),"--end",str(end)])
            folder=evidence/f"semantic-{start:03d}-{end:03d}"
            report=json.loads((folder/"summary.json").read_bytes())
            assert report["status"]=="PASS" and report["source_pins_unchanged"]
            assert report["C_cases"]==end-start==len(report["cases_completed"])
            assert report["VM_entries"]==report["native_entries"]>0
            assert report["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert report["all_complete_return_output_workspace_bytes_equal"] and report["all_native_source_readonly_and_canaries"]
            assert not report["native_VM_byte_masking"] and not report["inherited_counts"]
            assert report["actual_namespace_syscalls"]==report["actual_issued_namespace_authorities"]==0
            assert pin(folder/"case-inventory.json")["sha256"]==inventory_pin["sha256"]
            assert report["fresh_B3_compiles"]==0
            names.extend(report["cases_completed"]);total_VM+=report["VM_entries"];total_native+=report["native_entries"];total_C+=report["C_cases"]
            batch_reports.append(dict(start=start,end=end,process=process,summary=pin(folder/"summary.json"),
                VM_entries=report["VM_entries"],native_entries=report["native_entries"],C_cases=report["C_cases"]))
        assert len(names)==len(set(names))==total_C==85
        details["semantic_batches"]=batch_reports
        protocol_process=run("unixopen-parent-42-private-protocol-controls",
            [context["python"],"-B",validation,"--context",context_path,"--mode","protocol"])
        protocol=json.loads((evidence/"protocol/summary.json").read_bytes())
        assert protocol["status"]=="PASS" and protocol["source_pins_unchanged"]
        assert protocol["protocol_controls"]==len(protocol["protocol_names"])==len(set(protocol["protocol_names"]))==42
        assert protocol["C_cases"]==3 and len(protocol["cases_completed"])==2
        assert protocol["VM_entries"]==protocol["native_entries"]>0
        assert protocol["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert protocol["all_complete_return_output_workspace_bytes_equal"] and protocol["all_native_source_readonly_and_canaries"]
        assert not protocol["native_VM_byte_masking"] and not protocol["inherited_counts"]
        assert protocol["actual_namespace_syscalls"]==protocol["actual_issued_namespace_authorities"]==protocol["fresh_B3_compiles"]==0
        assert pin(evidence/"protocol/case-inventory.json")["sha256"]==inventory_pin["sha256"]
        total_VM+=protocol["VM_entries"];total_native+=protocol["native_entries"];total_C+=protocol["C_cases"]
        assert total_VM==total_native>0 and total_C==88
        details.update(status="PASS_COMPONENT_ONLY",protocol_process=protocol_process,
            protocol_report=pin(evidence/"protocol/summary.json"),
            semantic_names=names,actual_counts=dict(fresh_HIA_B3_compiles=1,
                fresh_original_C_library_builds=1,complete_semantic_cases=85,
                original_C_returned_calls=88,protocol_setup_original_C_call=1,
                additional_protocol_full_semantic_cases=2,protocol_controls=42,
                fresh_VM_entries=total_VM,fresh_native_entries=total_native,namespace_syscalls=0))
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if evidence is not None:
            observed=[]
            for path in sorted(evidence.glob("*/summary.json")):
                data=path.read_bytes()
                try:
                    report=json.loads(data)
                    selected={k:report[k] for k in ("status","mode","scope","error_class","error","traceback",
                        "profile","function_profiles","C_cases","cases_completed","VM_entries","native_entries",
                        "protocol_controls","protocol_names","fresh_B3_compiles","source_pins_unchanged","limits","actual_limits") if k in report}
                    observed.append(dict(pin=pin(path),original_selected_fields=selected))
                    print("HIA_UNIXOPEN_ORIGINAL_REPORT "+json.dumps(observed[-1],sort_keys=True),flush=True)
                except BaseException as read_error:
                    observed.append(dict(path=str(path),original_bytes=len(data),original_sha256=sha(data),read_error=repr(read_error)))
            details["complete_original_reports_preserved"]=observed
        changes=[]
        for label,row in [*inputs.items(),*((str(i),r) for i,r in enumerate(working))]:
            try:
                if not same(row):changes.append(dict(label=label,before=row,after=pin(Path(row["path"]))))
            except BaseException as error:changes.append(dict(label=label,before=row,error=repr(error)))
        details.update(input_pins=inputs,working_source_pins=working,source_changes=changes,inputs_unchanged=bool(inputs) and not changes)
        if not details["inputs_unchanged"]:status="FAIL";details["status"]="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        common.finish("NEW_UNIXOPEN_PARENT_COMPONENT_FOREIGN_EFFECTS",status,details,
            roots={"unixopen-working-source":context["namespace_working"]} if context and "namespace_working" in context else {})
        print("HIA_UNIXOPEN_PARENT_CI "+json.dumps(dict(status=status,scope=details["scope"],
            actual_counts=details["actual_counts"],ordinary_Store_closed=False,original_failures_unchanged=True),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
