"""Independent fresh raw-FS framer component, not the old 42-case qualification.

All six HIA roles and the framer are generated/compiled anew. The original
33 native packer controls and 84 old-VM/new-VM/new-native comparisons stay exact.
Nineteen new physical windows plus seven same-context error continuations use
the real fixed ELF. Complete six-role traces and all framer buffers are replayed.
The old 42-case/900-second result is not replaced or inherited.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,os,stat,time,traceback
from pathlib import Path
COMMON_SHA="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
INPUT_SHA="946df29748d44b5e3ff80afa06968697fb06f4e12ece53f27928a4b2cebc3750"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode))
def unchanged(row):return pin(Path(row["path"]))==row
def main():
    assert sys.version_info[:3]==(3,12,14)
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True)
    raw=common_path.read_bytes();assert sha(raw)==COMMON_SHA
    spec=importlib.util.spec_from_file_location("namespace_raw_fs_common",common_path)
    common=importlib.util.module_from_spec(spec);sys.modules[spec.name]=common
    exec(compile(raw,str(common_path),"exec"),common.__dict__)
    context=None;evidence=None;inputs={};working=[];status="FAIL"
    details=dict(schema="hia.namespace.raw-fs-framer.fresh-ci.v1",status="INCOMPLETE",
        scope="NEW_REAL_SHARED_FS_AND_PRIVATE_FRAMER_COMPONENT_NOT_INSTALLED_ISSUER",
        actual_counts="UNKNOWN_UNTIL_COMPLETED_REPORTS",old_42_original_qualification_reexecuted=False,
        old_42_failures_unchanged=True,old_42_complete_gate_still_required=True,
        fixed_native_issuer_implemented=False,ordinary_unixOpen_closed=False,ordinary_Store_closed=False,
        new_cold_qualification=False,inherited_counts=False,aggregate_wall_seconds=900,
        B3_limits=dict(cpu_seconds=10,wall_seconds=20,address_bytes=256<<20,capacity=1<<20,workspace=1<<20),
        process_limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0),
        VM_limits=dict(steps=4000000,arena_bytes=32<<20,depth=64))
    try:
        context=common.prepare()
        compiler_source=Path(context["compiler"]);compiler_pin=pin(compiler_source)
        assert compiler_pin["sha256"]==B3 and compiler_pin["bytes"]==669556
        here=Path(__file__).resolve().parent
        inputs["launcher"]=pin(Path(__file__));inputs["common"]=pin(common_path)
        inputs["original-qualified-B3"]=compiler_pin
        source_index=here/"inputs.json";manifest_raw=source_index.read_bytes()
        assert sha(manifest_raw)==INPUT_SHA;inputs["manifest"]=pin(source_index)
        manifest=json.loads(manifest_raw);assert len(manifest["inputs"])==21
        assert manifest["reference_commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
        assert manifest["compiler_sha256"]==B3 and manifest["compiler_bytes"]==669556
        assert manifest["expected_physical_cases"]==19 and manifest["expected_raw_effects_completed"]==26
        assert manifest["expected_negative_protocol_controls"]==80 and manifest["private_positive_controls"]==1
        tree=Path(context["base"])/"namespace-raw-fs-framer-r1-source";tree.mkdir(parents=False,exist_ok=False)
        (tree/"inputs").mkdir();(tree/"tools").mkdir();paths={}
        for row in manifest["inputs"]:
            assert Path(row["path"]).name==row["path"]
            path=here/row["path"];observed=pin(path)
            assert (observed["bytes"],observed["sha256"],observed["git"],observed["mode"])==(
                row["bytes"],row["sha256"],row["blob"],int(row["mode"][-3:],8)),row["path"]
            inputs[row["path"]]=observed;target=tree/"inputs"/row["path"]
            original=path.read_bytes();target.write_bytes(original);target.chmod(observed["mode"])
            assert target.read_bytes()==original;paths[row["path"]]=str(target);working.append(pin(target))
            if row["working_alias"] is not None:
                relative=Path(row["working_alias"])
                assert not relative.is_absolute() and ".." not in relative.parts
                alias=tree/relative;alias.parent.mkdir(parents=True,exist_ok=True)
                alias.write_bytes(original);alias.chmod(observed["mode"]);assert alias.read_bytes()==original
                working.append(pin(alias))
        evidence=Path(context["output"])/"namespace-raw-fs-framer-r1";evidence.mkdir()
        compiler_directory=evidence/"compiler";compiler_directory.mkdir()
        compiler_raw=compiler_source.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)==B3 and pin(compiler_source)==compiler_pin
        compiler_copy=compiler_directory/"B3.image.bin"
        compiler_copy.write_bytes(compiler_raw);compiler_copy.chmod(compiler_pin["mode"])
        assert compiler_copy.read_bytes()==compiler_raw
        working.append(pin(compiler_copy))
        context=dict(context,namespace_working=str(tree),namespace_evidence=str(evidence),namespace_input_paths=paths)
        context_path=evidence/"context.json";save(context_path,context)
        save(evidence/"source-before.json",dict(inputs=inputs,working=working))
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1");deadline=time.monotonic()+900
        details["process_receipts"]=[]
        def run(label,argv):
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError("raw-FS new component original900 aggregate")
            receipt=common.run(label,argv,cwd=context["reference"],timeout=min(180,remaining),env=env)
            details["process_receipts"].append(dict(label=label,receipt=receipt));return receipt
        def report(relative):
            path=evidence/relative;raw=path.read_bytes();result=json.loads(raw)
            assert result["status"].startswith("PASS"),(relative,result)
            return result
        run("fresh-FS9-DMS10-registered-FSTAT-six-role-build-33-packer-controls",
            [context["python"],"-B",paths["namespace-fs9-build.py"],"--context",context_path,
             "--executor",paths["namespace-fixed-fs9.S"],"--packer",paths["namespace-fs9-packer.py"]])
        fixed=report("db-join-build-r1/summary.json")
        assert fixed["fresh_role_compiles"]==6 and fixed["packer_entries"]==33 and fixed["source_pins_unchanged"]
        assert set(fixed["exact_roles"])==set(map(str,range(1,7)))
        assert fixed["executable"]["layout"]["relocation_count"]==0
        assert fixed["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        for row in fixed["exact_roles"].values():
            receipt=row["compile_receipt"]
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==row["source"]["sha256"]
            assert receipt["produced_sha256"]==row["image"]["sha256"] and receipt["produced_bytes"]==row["image"]["bytes"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        run("original-84-packer-oldVM-newVM-newNative-full-bytes",
            [context["python"],"-B",paths["namespace-fs9-packer-three-way.py"],"--context",context_path,
             "--old-packer",paths["namespace-fs9-packer.reference.py"],
             "--new-packer",paths["namespace-fs9-packer.py"],"--executor",paths["namespace-fixed-fs9.S"]])
        comparison=report("packer-differential-r1/summary.json")
        assert comparison["cases"]==84 and comparison["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
        assert comparison["source_before_after_equal"] and comparison["no_masks"] and comparison["complete_buffers_equal"]
        assert comparison["old_profile_not_relaxed"] and comparison["old_native_compiles"]==0
        assert comparison["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        run("fresh-unixopen-raw-FS-framer-B3",
            [context["python"],"-B",paths["build-framer.py"],"--context",context_path])
        framer=report("framer-build/summary.json")
        assert framer["fresh_B3_compiles"]==1 and framer["source_pins_unchanged"]
        physical=[];protocol=[]
        for group in range(5):
            run("fresh-actual-raw-FS-framer-"+str(group),
                [context["python"],"-B",paths["test-raw-fs-framer.py"],"--context",context_path,
                 "--mode","physical","--group",str(group)])
            physical.append(report("physical-"+str(group)+"/summary.json"))
        for group in range(4):
            run("fresh-framer-complete-protocol-"+str(group),
                [context["python"],"-B",paths["test-raw-fs-framer.py"],"--context",context_path,
                 "--mode","protocol","--group",str(group)])
            protocol.append(report("protocol-"+str(group)+"/summary.json"))
        cases=[name for row in physical for name in row["physical_cases"]]
        controls=[name for row in protocol for name in row["protocol_controls"]]
        assert len(cases)==len(set(cases))==19
        assert sum(row["raw_effects_completed"] for row in physical)==26
        assert sum(len(row["error_followups"]) for row in physical)==7
        assert len(controls)==len(set(controls))==80
        assert all(set(row["all_protocol_control_names"])==set(controls) and row["protocol_total_inventory"]==80 for row in protocol)
        assert sum(len(row.get("private_positive_controls",[])) for row in protocol)==1
        groups=physical+protocol
        for row in groups:
            assert row["source_pins_unchanged"] and row["all_complete_return_peer_workspace_bytes_equal"] and row["no_masks"]
            assert row["actual_input_and_peer_mprotect_readonly"]
            assert row["framer_VM_entries"]==row["framer_native_entries"]>0
            assert row["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert not row["fixed_native_issuer_implemented"] and not row["ordinary_Store_closed"]
        for row in physical:
            assert row["fixed_native_entries"]==row["fixed_VM_entries"]>0 and row["actual_primitive_ACKs"]>0
            assert len(row["processes"])==len(row["physical_cases"])>0
        for row in protocol:
            assert row["fixed_native_entries"]==row["fixed_VM_entries"]==row["actual_primitive_ACKs"]==0
        details["actual_counts"]=dict(fresh_role_B3=6,fresh_packer_B3=1,fresh_framer_B3=1,
            original_native_packer_controls=33,original_packer_old_VM=84,original_packer_new_VM=84,original_packer_extra_native=84,
            physical_cases=19,raw_operations_completed=26,same_context_error_followups=7,
            negative_protocol_controls=80,private_UID_zero_positive_controls=1,
            framer_VM_entries=sum(x["framer_VM_entries"] for x in groups),
            framer_native_entries=sum(x["framer_native_entries"] for x in groups),
            fixed_native_entries=sum(x["fixed_native_entries"] for x in physical),
            fixed_VM_entries=sum(x["fixed_VM_entries"] for x in physical),
            actual_primitive_ACKs=sum(x["actual_primitive_ACKs"] for x in physical),
            actual_fixed_processes=sum(len(x["processes"]) for x in physical),counts_inherited=False)
        details.update(status="PASS_COMPONENT_ONLY",complete_source_and_image_pins_unchanged=True)
        status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if evidence is not None:
            partials=[]
            for path in sorted(evidence.rglob("summary.json")):
                if path==evidence/"summary.json":continue
                try:
                    raw=path.read_bytes();value=json.loads(raw)
                    partials.append(dict(path=str(path),pin=pin(path),status=value.get("status"),
                        counts={key:value[key] for key in ("framer_VM_entries","framer_native_entries","fixed_native_entries",
                          "fixed_VM_entries","actual_primitive_ACKs","fresh_role_compiles","packer_entries","fresh_B3_compiles",
                          "raw_effects_completed","profile") if key in value},
                        error_class=value.get("error_class"),error=value.get("error"),traceback=value.get("traceback")))
                except BaseException as error:partials.append(dict(path=str(path),read_error=repr(error)))
            details["partial_original_report_pins"]=partials
            print("NAMESPACE_RAW_FS_FRAMER_PARTIAL_ORIGINALS "+json.dumps(partials,sort_keys=True),flush=True)
        errors=[]
        for row in list(inputs.values())+working:
            try:assert unchanged(row)
            except BaseException as error:errors.append(dict(path=row["path"],error=repr(error)))
        details.update(inputs=list(inputs.values()),working_source_pins=working,source_pins_unchanged=not errors,after_errors=errors)
        if errors:status="FAIL";details["status"]="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        common.finish("NAMESPACE_RAW_FS_FRAMER_FRESH_COMPONENT",status,details,
            roots={"namespace-raw-fs-working-source":context["namespace_working"]}
            if context and "namespace_working" in context else {})
        print("NAMESPACE_RAW_FS_FRAMER_FINAL "+json.dumps(dict(status=status,actual_counts=details["actual_counts"],
            old_42_qualification_reexecuted=False,fixed_native_issuer_implemented=False,ordinary_Store_closed=False)),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
