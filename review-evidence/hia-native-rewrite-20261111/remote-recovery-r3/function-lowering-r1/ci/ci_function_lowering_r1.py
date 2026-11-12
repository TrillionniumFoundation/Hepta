"""Five real HIA components: Function plan/tape/Code issuer/encoder/finalizer.
Fresh scope only; no inherited old test count, no host instruction lowering.
"""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"function-lowering-r1/"
FILES=[
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
    "path": "tools/hia_function_code_issuer.py",
    "gitsha": "0309b3f34843287552778eefda7962a7f95f4f02",
    "bytes": 21712,
    "sha256": "f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219"
  },
  {
    "path": "tools/hia_machine_x64_encoder.py",
    "gitsha": "817443cde4a81402e850086b80ac5de985b62183",
    "bytes": 51420,
    "sha256": "92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"
  },
  {
    "path": "tools/build_hia_function_lowering.py",
    "gitsha": "658e7b63221721226f634130b08bd9f6b5106947",
    "bytes": 11814,
    "sha256": "01ca4abf3dde0e62787f26935f16a51243a2b0ec21fd72a1faa388f50a9170dd"
  },
  {
    "path": "tests/test_hia_function_lowering.py",
    "gitsha": "cb42b8e725bc16471c1cd9fd965c0bdd7f704405",
    "bytes": 48120,
    "sha256": "e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
  },
  {
    "path": "tests/function_code_test_reference.py",
    "gitsha": "18aa77e90c3047da6035e32f58725851286eca28",
    "bytes": 45704,
    "sha256": "61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11"
  },
  {
    "path": "docs/HIA_FUNCTION_LOWERING_NATIVE.md",
    "gitsha": "e49c5b6f0f5a20f7e5752a039700f124f5d5a728",
    "bytes": 15271,
    "sha256": "7f92c533cd90402fc5e3133d01e9c62b7ca0dc63761c620028b26e7d480ad7de"
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
    "path": "reference/hia_program_native.py",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
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
    "path": "reference/hia_selfhost_child.py",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
  }
]
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
SCHEDULE=[["smoke",0,25,0],["scalars",0,24,0],["scalars",1,24,0],["scalars",2,24,0],["scalars",3,24,0],["scalars",4,24,0],["scalars",5,24,0],["scalars",6,24,0],["scalars",7,24,0],["scalars",8,24,0],["scalars",9,24,0],["casts",0,20,0],["casts",1,20,0],["casts",2,20,0],["casts",3,20,0],["casts",4,20,0],["casts",5,20,0],["casts",6,20,0],["casts",7,20,0],["casts",8,20,0],["casts",9,20,0],["booleans",0,32,0],["resources",0,30,0],["edges",0,21,0],["calls",0,12,0],["selection",0,16,0],["inventory",0,1,0],["inventory",1,1,0],["inventory",2,1,0],["inventory",3,1,0],["inventory",4,1,0],["budget",0,1,0],["budget",1,1,0],["budget",2,1,0],["budget",3,1,0],["budget",4,1,0],["budget",5,1,0],["tape-protocol",0,59,58],["issuer-protocol",0,72,71]]
EXPECTED_OPS=sorted(("const","int.cast","int.neg.checked","select","bool.not","bool.and","bool.or",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt","compare.le",
 "compare.gt","compare.ge","int.add.checked","int.sub.checked","int.mul.checked",
 "int.add.wrap","int.sub.wrap","int.mul.wrap","int.div.checked","int.rem.checked",
 "int.shl.checked","int.shr.checked","buffer.new","buffer.try_new","buffer.len","borrow.read",
 "borrow.mut","loan.end","owner.move","owner.drop","buffer.load","buffer.store","buffer.fill",
 "buffer.copy","buffer.move_within","buffer.swap","buffer.copy_range","buffer.fill_range",
 "chain.empty","chain.try_push","chain.pop","chain.is_empty","chain.head_read","chain.head_mut","call"))
EXPECTED_TYPES=sorted(("unit","bool","i8","u8","i16","u16","i32","u32","i64","u64","isize","usize",
 "buffer","readbuf","mutbuf","chain"))
KINDS={"ACTUAL_NATIVE_FUNCTION_CHAIN","FRAME_SEMANTIC_REFUSAL","COMPLETE_TAPE_ONLY",
 "PRIVATE_ABI_REJECTION","PURE_SAME_INPUT","ISSUER_PRIVATE_INITIAL_BAD","ISSUER_PRIVATE_ACK_BAD",
 "ISSUER_PRIVATE_SHORT_WORK","PRIVATE_FORMAT_PRESSURE_ONLY"}
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def print_original(path,label):
    raw=path.read_bytes()
    for at in range(0,len(raw),18000):
        part=raw[at:at+18000]
        print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
            offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def read_summary(directory,label):
    path=directory/"summary.json"
    if not path.exists():return None
    raw=path.read_bytes();value=json.loads(raw)
    print(label+" "+raw.decode("utf-8").strip(),flush=True)
    return value
def examine_cases(directory,value):
    raw=(directory/"cases.jsonl").read_bytes();cases=[json.loads(line) for line in raw.splitlines()]
    assert len(cases)==value["cases"] and all(c["status"]=="PASS" and c["kind"] in KINDS for c in cases)
    counts={name:sum(c["kind"]==name for c in cases) for name in sorted(KINDS)}
    assert counts["COMPLETE_TAPE_ONLY"]==value["tape_only_cases"]
    assert counts["FRAME_SEMANTIC_REFUSAL"]==value["original_frame_semantic_refusals"]
    for c in cases:
        if c["kind"]=="ACTUAL_NATIVE_FUNCTION_CHAIN":
            assert c["complete_command_prefix_equal"] and c["complete_machine_bytes_equal"]
            assert c["complete_labels_fixups_relocations_equal"]
            assert c["code_state"]["all_code_bytes_equal"] and c["code_state"]["all_registry_values_equal"]
            assert (c["error"] is None)==c["finalizer_equal"]==c["original_Function_symbol_and_frame_equal"]
            assert c["native_commands"]>0 and c["full_trace"]["bytes"]>0
        elif c["kind"]=="COMPLETE_TAPE_ONLY":
            assert c["original_full_Function_trace_equal"] and c["actual_Code_ack_chain_not_run_for_this_case"]
        elif c["kind"]=="FRAME_SEMANTIC_REFUSAL":assert c["code_unchanged"]
        elif c["kind"] in("ISSUER_PRIVATE_INITIAL_BAD","ISSUER_PRIVATE_ACK_BAD"):assert c["permanent_poison"]
    return dict(cases=counts,case_ledger_bytes=len(raw),case_ledger_sha256=digest(raw),
        actual_chain_successes=sum(c["kind"]=="ACTUAL_NATIVE_FUNCTION_CHAIN" and c["error"] is None for c in cases),
        actual_chain_errors=sum(c["kind"]=="ACTUAL_NATIVE_FUNCTION_CHAIN" and c["error"] is not None for c in cases))
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("function_lower_common_r1",common_path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[common_path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    project=None;status="FAIL"
    report=dict(scope="NEW_FIVE_COMPONENT_FUNCTION_LOWERING_ACTUAL_CODE_CHAIN",
        expected_groups=39,expected_cases=718,expected_private_controls=129,
        actual_new_compilations=0,actual_cases=0,actual_native_entries=0,actual_private_controls=0,
        groups={},old_test_results_inherited=False,old_frame_suite_rerun=False,old_x64_suite_rerun=False,
        private_admitted_Core_checked_plan_and_configured_Code_required=True,
        runtime_host_instruction_selection=False,whole_emitter=False,whole_backend=False,installed=False,cold=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"function-lowering-recovery-r1";mine.mkdir()
        project=mine/"native-function-lowering-next";project.mkdir()
        for row in FILES:
            path=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            data=path.read_bytes();assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        environment=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],
                         LC_ALL="C.UTF-8",LANG="C.UTF-8")
        build=project/"development/build-r1"
        try:
            common.run("function-lower-five-generations-and-original-B3",[
                context["python"],"-B",project/"tools/build_hia_function_lowering.py",
                "--reference",context["reference"],"--compiler",context["compiler"],"--out",build],
                cwd=project,timeout=180,env=environment)
        finally:
            value=read_summary(build,"HIA_FUNCTION_LOWER_BUILD_ORIGINAL")
            if value is not None:
                report["build"]=value;report["actual_new_compilations"]=value["compilations"]
            if build.exists():
                for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
                    print_original(path,"HIA_FUNCTION_LOWER_NESTED_STDERR")
                for path in sorted(build.glob("*/profile-before-gates.json")):
                    print_original(path,"HIA_FUNCTION_LOWER_PROFILE_ORIGINAL")
        value=report["build"]
        assert value["status"]=="PASS_BUILD_ONLY" and value["source_pins_unchanged"]
        assert value["compilations"]==5 and value["native_semantic_entries"]==0 and value["actual_limits"]==LIMITS
        owners={name:next(r["sha256"] for r in FILES if r["path"]=="tools/"+filename)
            for name,filename in (("frame","hia_function_frame_plan.py"),("tape","hia_function_lowering_tape.py"),
                ("issuer","hia_function_code_issuer.py"),("encoder","hia_machine_x64_encoder.py"),
                ("finalizer","hia_machine_x64_encoder.py"))}
        assert set(value["components"])==set(owners)
        for name,manifest in value["components"].items():
            assert manifest["author_sha256"]==owners[name]
            assert manifest["component"]==name and manifest["status"]=="BUILT_ONLY"
            assert manifest["private_immutable_actual_issuers_required"] and not manifest["header_is_authentication"]
            assert not any(manifest[k] for k in("whole_emitter","whole_backend","installed","cold"))
            receipt=manifest["compile_receipt"];profile=manifest["profile"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["runner_sha256"]==next(r["sha256"] for r in FILES if r["path"]=="reference/hia_selfhost_child.py")
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
            assert profile["max_blocks"]<=256 and profile["max_params"]<=16
            assert profile["max_ssa_index"]==profile["max_function_values"]-1 and profile["max_ssa_index"]<2048
            assert 0<manifest["source_bytes"]<=1<<20 and 0<manifest["image_bytes"]<=1<<20
        assert len(SCHEDULE)==39 and sum(r[2] for r in SCHEDULE)==718 and sum(r[3] for r in SCHEDULE)==129
        observed_ops=set();observed_types=set()
        for group,variant,cases,controls in SCHEDULE:
            label=group+"-"+str(variant);output=project/"development"/("native-"+label+"-r1")
            try:
                common.run("function-lower-full-"+label,[
                    context["python"],"-B",project/"tests/test_hia_function_lowering.py",
                    "--bundle",build/"bundle.json","--reference",context["reference"],"--out",output,
                    "--group",group,"--variant",str(variant)],
                    cwd=project,timeout=180,env=environment)
            finally:
                value=read_summary(output,"HIA_FUNCTION_LOWER_GROUP_ORIGINAL")
                if value is not None:
                    report["groups"][label]=value
                    for target,source in (("actual_cases","cases"),("actual_native_entries","native_entries"),
                                          ("actual_private_controls","private_controls")):
                        report[target]=sum(r.get(source,0) for r in report["groups"].values())
            value=report["groups"][label]
            assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
            assert (value["cases"],value["private_controls"])==(cases,controls),(label,value)
            assert value["limits"]==LIMITS and sum(value["by_component"].values())==value["native_entries"]
            assert value["by_component"]["frame"]>0
            if group=="inventory" and variant==4:
                assert value["original_frame_semantic_refusals"]==1
                assert all(value["by_component"][n]==0 for n in("tape","issuer","finalizer"))
            else:assert value["by_component"]["tape"]>0
            assert not any(value[k] for k in("whole_emitter","whole_backend","installed","cold","runtime_host_instruction_selection"))
            custody=value["custody"]
            assert custody["status"]=="PASS" and custody["source_pins_unchanged"] and not custody["changed"]
            for flag in("all_new_pages_decompressed_equal","all_final_pages_rehashed",
                        "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
                assert custody[flag],(label,flag)
            assert custody["complete_snapshot_descriptors"]==value["native_entries"]*6
            assert custody["cas_pages"]>0 and custody["logical_buffer_bytes"]>0
            value["independent_category_counts"]=examine_cases(output,value)
            observed_ops.update(value["source_opcodes"]);observed_types.update(value["source_types"])
        assert len(report["groups"])==39
        assert (report["actual_cases"],report["actual_private_controls"])==(718,129)
        assert sorted(observed_ops)==EXPECTED_OPS and len(EXPECTED_OPS)==50
        assert sorted(observed_types)==EXPECTED_TYPES and len(EXPECTED_TYPES)==16
        categories={name:sum(v["independent_category_counts"]["cases"][name] for v in report["groups"].values())
                    for name in sorted(KINDS)}
        assert categories["ACTUAL_NATIVE_FUNCTION_CHAIN"]==584
        assert categories["COMPLETE_TAPE_ONLY"]==2 and categories["FRAME_SEMANTIC_REFUSAL"]==1
        assert sum(v["independent_category_counts"]["actual_chain_successes"] for v in report["groups"].values())==580
        assert sum(v["independent_category_counts"]["actual_chain_errors"] for v in report["groups"].values())==4
        assert sum(v["issuer_GROW"] for v in report["groups"].values())>0
        assert sum(v["code_GROW"] for v in report["groups"].values())>0
        report.update(status="PASS",all_thirtynine_bounded_groups_passed=True,
            exact_original_Function_method_trace_and_actual_machine_bytes_equal=True,
            actual_Code_state_and_partial_errors_equal=True,category_counts=categories,
            actual_by_component={name:sum(v["by_component"][name] for v in report["groups"].values()) for name in owners},
            source_opcodes=sorted(observed_ops),source_types=sorted(observed_types),
            logical_buffer_bytes=sum(v["custody"]["logical_buffer_bytes"] for v in report["groups"].values()),
            original_function_input_domain=1024,original_block_input_domain=4096,original_frame_limit=65536,
            block_text_limit=16<<20,Code_limit=64<<20,
            single_Function_final_trap_may_exceed_block_limit_by_seven=True)
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None and project.exists():roots["function-lowering"]=project
        common.finish("function-lowering-r1",status,report,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
