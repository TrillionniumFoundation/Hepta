"""Fresh actual scalar / byte wrappers; old successful suites are not rerun."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"emitter-wrappers-r1/"
FILES=[
  {
    "path": "docs/HIA_EMITTER_WRAPPERS_NATIVE.md",
    "bytes": 11180,
    "sha256": "9a9377bb4fce8420228ef96d908688aff1d3c6a50849a8ef7d82f6da2750f78d",
    "gitsha": "62e94470a24c47f73fa09c2c42ebf0f5401c21f1"
  },
  {
    "path": "reference/hia_machine_plan.py",
    "gitsha": "61833e8bf8497089461bad9eb2347c82a233e8b2",
    "bytes": 13270,
    "sha256": "ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
  },
  {
    "path": "reference/hia_machine_x64.py",
    "gitsha": "8e87bd317c5f61e00993bb0bf8d803c5385d6556",
    "bytes": 11057,
    "sha256": "8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9"
  },
  {
    "path": "reference/hia_native_byte_abi.py",
    "gitsha": "4412810e9e6dfba82879dbb9ae19c19ce2de178c",
    "bytes": 5825,
    "sha256": "0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"
  },
  {
    "path": "reference/hia_program_native.py",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
  },
  {
    "path": "tests/function_code_test_reference.py",
    "gitsha": "18aa77e90c3047da6035e32f58725851286eca28",
    "bytes": 45704,
    "sha256": "61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
  },
  {
    "path": "tests/function_lowering_test_reference.py",
    "gitsha": "cb42b8e725bc16471c1cd9fd965c0bdd7f704405",
    "bytes": 48120,
    "sha256": "e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17"
  },
  {
    "path": "tests/test_hia_emitter_wrappers.py",
    "bytes": 28425,
    "sha256": "44f0d18c10623e06e59b5d4f332ebe033d028c008294750e764b5d07a3bf9768",
    "gitsha": "33629f052b85fd256c2892cfc431f940555ab955"
  },
  {
    "path": "tools/build_hia_emitter_wrappers.py",
    "bytes": 12717,
    "sha256": "3877b042793ef9c15b140d70b83fec085d22efc9b7102ad18fcb846eb1846daf",
    "gitsha": "d8ad58e3c94bce2bd7ede84552f72c232c23af70"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
  },
  {
    "path": "tools/hia_emitter_wrapper_issuer.py",
    "bytes": 5548,
    "sha256": "5eb9752617afea5af7ceddfedb9c309fcf7d88fa3da5f3895e7e1a1aae1d7ff8",
    "gitsha": "fad97e3489b06f128270ccc662a9f001ef2aa3b7"
  },
  {
    "path": "tools/hia_emitter_wrapper_tape.py",
    "bytes": 20087,
    "sha256": "332a8633a13f09fcc6021ebdf1f916e97b65b93f4b875b57264abf7eb93b0287",
    "gitsha": "2f4253bd3c56bda55a5e7d36928c6b8f53ca355a"
  },
  {
    "path": "tools/hia_function_code_issuer.py",
    "gitsha": "0309b3f34843287552778eefda7962a7f95f4f02",
    "bytes": 21712,
    "sha256": "f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219"
  },
  {
    "path": "tools/hia_function_frame_plan.py",
    "gitsha": "bb475cb50848f09dc4fda62ab1aa869bc0b9891d",
    "bytes": 32438,
    "sha256": "27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
  },
  {
    "path": "tools/hia_function_lowering_tape.py",
    "gitsha": "d5b590bb7c67c34e9f994ff550da99358371a281",
    "bytes": 54950,
    "sha256": "e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb"
  },
  {
    "path": "tools/hia_machine_x64_encoder.py",
    "gitsha": "817443cde4a81402e850086b80ac5de985b62183",
    "bytes": 51420,
    "sha256": "92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"
  }
]
SCHEDULE=[["scalars",0,26,0],["scalars",1,26,0],["scalars",2,26,0],["scalars",3,26,0],["scalars",4,26,0],["scalars",5,26,0],["scalars",6,26,0],["scalars",7,26,0],["scalars",8,26,0],["scalars",9,26,0],["scalars",10,26,0],["borrowed",0,9,0],["borrowed",1,9,0],["borrowed",2,9,0],["borrowed",3,9,0],["borrowed",4,9,0],["borrowed",5,9,0],["borrowed",6,9,0],["borrowed",7,9,0],["options",0,16,0],["reserved",0,32,0],["skipped",0,8,0],["stack",0,4,0],["budget",0,1,0],["budget",1,1,0],["protocol",0,82,79]]
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
EXPECTED_CATEGORIES={
 "ACTUAL_NATIVE_WRAPPER_CODE_CHAIN":378,
 "ORIGINAL_WRAPPER_SEMANTIC_REFUSAL":18,
 "ORIGINAL_WRAPPER_SKIPPED":24,
 "COMPLETE_NATIVE_WRAPPER_TAPE_ONLY":2,
 "PRIVATE_WRAPPER_TAPE_ABI":32,
 "PRIVATE_WRAPPER_ISSUER_POISON":47,
 "PURE_REPEAT_EXACT_BYTES":1}
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def original(path,label):
    raw=path.read_bytes()
    for at in range(0,len(raw),18000):
        part=raw[at:at+18000]
        print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
            offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def summary(directory,label):
    p=directory/"summary.json"
    if not p.exists():return None
    raw=p.read_bytes();value=json.loads(raw);print(label+" "+raw.decode().strip(),flush=True)
    return value
def cases(directory,value):
    rows=[json.loads(line) for line in (directory/"cases.jsonl").read_bytes().splitlines()]
    assert len(rows)==value["cases"] and all(r["status"]=="PASS" for r in rows)
    assert len({r["label"] for r in rows})==len(rows)
    counts={name:sum(r["kind"]==name for r in rows) for name in EXPECTED_CATEGORIES}
    assert sum(counts.values())==len(rows)
    for row in rows:
        if row["kind"]=="ACTUAL_NATIVE_WRAPPER_CODE_CHAIN":
            assert row["full_original_trace_equal"] and row["full_machine_bytes_and_registries_equal"]
            assert row["state"]["all_code_bytes_equal"] and row["state"]["all_registry_values_equal"]
            assert not row["whole_Emitter"]
        elif row["kind"]=="COMPLETE_NATIVE_WRAPPER_TAPE_ONLY":
            assert row["full_original_Code_trace_equal"] and row["admitted"] is False
        elif row["kind"]=="PRIVATE_WRAPPER_ISSUER_POISON":
            assert row["event"][2]==row["retry_event"][2]==3
            assert row["event"][15]>0 and row["retry_event"][15]>0
    return dict(counts=counts,actual_success=sum(r["kind"]=="ACTUAL_NATIVE_WRAPPER_CODE_CHAIN" and r["error"] is None for r in rows),
                actual_error=sum(r["kind"]=="ACTUAL_NATIVE_WRAPPER_CODE_CHAIN" and r["error"] is not None for r in rows))
def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("wrapper_ci_common",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    project=None;status="FAIL"
    report=dict(scope="NEW_ACTUAL_SCALAR_AND_BORROWED_WRAPPERS",status="INCOMPLETE",
        expected_groups=26,expected_cases=502,expected_private_controls=79,
        actual_new_compilations=0,actual_cases=0,actual_native_entries=0,actual_private_controls=0,groups={},
        old_test_results_inherited=False,old_Function_suite_rerun=False,old_x64_suite_rerun=False,
        runtime_host_instruction_selection=False,whole_Emitter=False,whole_backend=False,installed=False,cold=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"emitter-wrapper-recovery-r1";mine.mkdir()
        project=mine/"native-emitter-wrapper-next";project.mkdir()
        for row in FILES:
            source=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            raw=source.read_bytes();assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
        env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
        build=project/"development/build-r1"
        try:
            common.run("wrapper-four-fresh-generations-and-original-B3",[
                context["python"],"-B",project/"tools/build_hia_emitter_wrappers.py","--reference",context["reference"],
                "--compiler",context["compiler"],"--out",build],cwd=project,timeout=180,env=env)
        finally:
            value=summary(build,"HIA_WRAPPER_BUILD_ORIGINAL")
            if value is not None:
                report["build"]=value;report["actual_new_compilations"]=value["compilations"]
            if build.exists():
                for p in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
                    original(p,"HIA_WRAPPER_NESTED_STDERR")
                for p in sorted(build.glob("*/profile-before-gates.json")):
                    original(p,"HIA_WRAPPER_PROFILE_ORIGINAL")
        value=report["build"]
        assert value["status"]=="PASS_BUILD_ONLY" and value["source_pins_unchanged"]
        assert value["actual_limits"]==LIMITS and value["compilations"]==4 and value["native_semantic_entries"]==0
        owners={key:next(r["sha256"] for r in FILES if r["path"]=="tools/"+filename) for key,filename in(
            ("tape","hia_emitter_wrapper_tape.py"),("issuer","hia_emitter_wrapper_issuer.py"),
            ("encoder","hia_machine_x64_encoder.py"),("finalizer","hia_machine_x64_encoder.py"))}
        assert set(value["components"])==set(owners)
        for component,manifest in value["components"].items():
            assert manifest["schema"]=="hepta.hia.emitter-wrapper-development.v1"
            assert manifest["component"]==component and manifest["author_sha256"]==owners[component]
            assert manifest["status"]=="BUILT_ONLY" and not manifest["header_is_authentication"]
            profile=manifest["profile"];receipt=manifest["compile_receipt"]
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
            assert profile["max_blocks"]<=256 and profile["max_params"]<=16 and profile["max_ssa_index"]<2048
            assert profile["max_ssa_index"]==profile["max_function_values"]-1
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert 0<manifest["source_bytes"]<=1<<20 and 0<manifest["image_bytes"]<=1<<20
        assert len(SCHEDULE)==26 and sum(r[2] for r in SCHEDULE)==502 and sum(r[3] for r in SCHEDULE)==79
        for group,variant,count,controls in SCHEDULE:
            label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r1")
            try:
                common.run("wrapper-full-"+label,[context["python"],"-B",project/"tests/test_hia_emitter_wrappers.py",
                    "--bundle",build/"bundle.json","--reference",context["reference"],"--out",out,
                    "--group",group,"--variant",str(variant)],cwd=project,timeout=180,env=env)
            finally:
                value=summary(out,"HIA_WRAPPER_GROUP_ORIGINAL")
                if value is not None:
                    report["groups"][label]=value
                    for target,field in(("actual_cases","cases"),("actual_native_entries","native_entries"),
                                         ("actual_private_controls","private_controls")):
                        report[target]=sum(r.get(field,0) for r in report["groups"].values())
            value=report["groups"][label]
            assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
            assert (value["cases"],value["private_controls"])==(count,controls),(label,value)
            assert value["limits"]==LIMITS and value["native_entries"]==sum(value["by_component"].values())
            assert value["by_component"]["tape"]>0
            assert not any(value[k] for k in("whole_Emitter","whole_backend","installed","cold","runtime_host_instruction_selection"))
            custody=value["custody"]
            assert custody["status"]=="PASS" and custody["source_pins_unchanged"] and not custody["changed"]
            for key in("all_new_pages_decompressed_equal","all_final_pages_rehashed",
                       "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
                assert custody[key],(label,key)
            assert custody["complete_snapshot_descriptors"]==value["native_entries"]*6
            value["independent_case_counts"]=cases(out,value)
        assert len(report["groups"])==26 and (report["actual_cases"],report["actual_private_controls"])==(502,79)
        counts={name:sum(x["independent_case_counts"]["counts"][name] for x in report["groups"].values()) for name in EXPECTED_CATEGORIES}
        assert counts==EXPECTED_CATEGORIES
        assert sum(x["independent_case_counts"]["actual_success"] for x in report["groups"].values())==377
        assert sum(x["independent_case_counts"]["actual_error"] for x in report["groups"].values())==1
        assert sum(x["code_GROW"] for x in report["groups"].values())>0
        assert sum(x["issuer_GROW"] for x in report["groups"].values())>0
        assert sum(x["tape_GROW"] for x in report["groups"].values())>0
        report.update(status="PASS",case_categories=counts,actual_by_component={
            n:sum(x["by_component"][n] for x in report["groups"].values()) for n in owners},
            full_original_method_trace_bytes_serial_symbols_errors_equal=True,
            actual_source_bound_input_output_workspace_complete=True,
            private_immutable_Core_and_normalized_manifest_required=True,header_is_authentication=False)
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None and project.exists():roots["emitter-wrappers"]=project
        common.finish("emitter-wrappers-r1",status,report,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
