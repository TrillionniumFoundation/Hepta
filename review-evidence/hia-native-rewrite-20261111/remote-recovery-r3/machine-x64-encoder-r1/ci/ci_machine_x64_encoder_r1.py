"""Two actual native Code images, complete operations and original ISA corpus."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"machine-x64-encoder-r1/"
FILES=[
  {
    "path": "tools/hia_machine_x64_encoder.py",
    "gitsha": "817443cde4a81402e850086b80ac5de985b62183",
    "bytes": 51420,
    "sha256": "92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"
  },
  {
    "path": "tools/build_hia_machine_x64_encoder.py",
    "gitsha": "d93628147205a793ca90c8b56635b1664077bc4c",
    "bytes": 8208,
    "sha256": "adfb7ef53197cf9911a8937bc74e315670f181fe9b5f17b19bce4c3d919d5c41"
  },
  {
    "path": "tests/test_hia_machine_x64_encoder.py",
    "gitsha": "18aa77e90c3047da6035e32f58725851286eca28",
    "bytes": 45704,
    "sha256": "61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11"
  },
  {
    "path": "docs/HIA_MACHINE_X64_ENCODER_NATIVE.md",
    "gitsha": "eeca0e0b9fc572a6d4160d265ae1493b00ce936e",
    "bytes": 10504,
    "sha256": "4373e54db4a532d7b289769278c44953aacaf4dee116c90c3839632a51d73e58"
  },
  {
    "path": "tools/x64_authoring_reference.py",
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
    "path": "reference/hia_machine_x64.py",
    "gitsha": "8e87bd317c5f61e00993bb0bf8d803c5385d6556",
    "bytes": 11057,
    "sha256": "8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9"
  },
  {
    "path": "reference/test_hia_machine_x64.py",
    "gitsha": "64bf109f7679197f57a29f13e94bb6ee103bac7d",
    "bytes": 14678,
    "sha256": "1ba1a51995c38ae93e5ce1a748a0b2bf3d2d6a19c0c48dfb9043c1ef639e094f"
  }
]
GROUPS={"constructor":54,"registers":5388,"memory":6404,"immediates":8004,
        "conditions":8710,"invalid":298,"labels":1599,"private":65,"execution":1}
BOUNDARIES=(7,5,5,5,5,5,7,5)
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
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
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("machine_x64_common_r1",common_path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[common_path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    mine=project=None;status="FAIL"
    report=dict(scope="NEW_STATEFUL_X64_ENCODER_AND_VALUE_FINALIZER",
        expected_groups=17,expected_cases=30567,expected_private_controls=106,
        expected_original_unittest_cases=7,expected_original_unittest_skips=0,
        actual_new_compilations=0,actual_native_entries=0,actual_cases=0,actual_private_controls=0,
        groups={},old_counts_inherited=False,ordinary_lowering_closed=False,
        production_ELF_join_closed=False,installed_closed=False,cold_qualified=False,
        arbitrary_foreign_callbacks_or_direct_internal_mutation_closed=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"machine-x64-encoder-recovery-r1";mine.mkdir()
        project=mine/"native-machine-x64-encoder-next";project.mkdir()
        for row in FILES:
            path=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            data=path.read_bytes()
            assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        environment=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],
                         LC_ALL="C.UTF-8",LANG="C.UTF-8")
        build=project/"development/build-r1"
        try:
            common.run("machine-x64-generate-and-two-original-B3",[
                context["python"],"-B",project/"tools/build_hia_machine_x64_encoder.py",
                "--reference",context["reference"],"--compiler",context["compiler"],"--out",build],
                cwd=project,timeout=180,env=environment)
        finally:
            value=read_summary(build,"HIA_MACHINE_X64_BUILD_ORIGINAL")
            if value is not None:
                report["build"]=value;report["actual_new_compilations"]=value["compilations"]
            if build.exists():
                for path in sorted(build.rglob("*.stderr")):
                    print_original(path,"HIA_MACHINE_X64_NESTED_STDERR")
        value=report["build"]
        assert value["status"]=="PASS_BUILD_ONLY" and value["source_pins_unchanged"]
        assert value["compilations"]==2 and value["native_semantic_entries"]==0
        assert value["actual_limits"]==LIMITS
        assert set(value["generations"])==set(value["manifests"])=={"encoder","finalizer"}
        for component,row in value["manifests"].items():
            assert row["component"]==component and row["compile_receipt"]["limits"]["cpu_seconds"]==10
            assert row["compile_receipt"]["limits"]["address_bytes"]==256<<20
            assert row["profile"]["functions"]<=128 and row["profile"]["blocks"]<=1536
            assert row["profile"]["max_blocks"]<=256 and row["profile"]["max_params"]<=16
            assert row["profile"]["ops"]<=8192 and row["source_bytes"]<=1<<20
        bundle=build/"bundle.json";errors=set();operations=set()
        schedules=[(name,name,0,count) for name,count in GROUPS.items()]
        schedules.extend(("boundary-"+str(i),"boundary",i,count) for i,count in enumerate(BOUNDARIES))
        for label,group,variant,expected in schedules:
            output=project/"development"/("native-"+label+"-r1")
            try:
                common.run("machine-x64-full-"+label,[
                    context["python"],"-B",project/"tests/test_hia_machine_x64_encoder.py",
                    "--bundle",bundle,"--reference",context["reference"],"--out",output,
                    "--group",group,"--variant",str(variant)],
                    cwd=project,timeout=180,env=environment)
            finally:
                value=read_summary(output,"HIA_MACHINE_X64_GROUP_ORIGINAL")
                if value is not None:
                    report["groups"][label]=value
                    report["actual_native_entries"]=sum(row["native_entries"] for row in report["groups"].values())
                    report["actual_cases"]=sum(row["cases"] for row in report["groups"].values())
                    report["actual_private_controls"]=sum(row["private_controls"] for row in report["groups"].values())
            value=report["groups"][label]
            assert value["status"]=="PASS" and value["group"]==group and value["variant"]==variant
            assert value["cases"]==expected,(label,value["cases"],expected)
            assert value["actual_limits"]==LIMITS
            assert value["source_custody"]["status"]=="PASS" and value["source_custody"]["source_pins_unchanged"]
            for flag in ("all_bytes_and_original_errors_equal","all_compared_state_equal",
                         "physical_readonly_inputs","all_canaries_intact","complete_buffers_recorded"):
                assert value[flag],(label,flag)
            for flag in ("all_new_pages_decompressed_equal","all_final_pages_rehashed",
                         "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
                assert value["source_custody"][flag],(label,flag)
            assert not value["old_counts_inherited"] and not value["ordinary_lowering_closed"]
            assert not value["installed_closed"] and not value["cold_qualified"]
            assert value["components"]["encoder"]+value["components"]["finalizer"]==value["native_entries"]
            expected_private=38 if group=="constructor" else 68 if group=="private" else 0
            assert value["private_controls"]==expected_private,(label,value["private_controls"])
            if group=="execution":
                rows=[json.loads(line) for line in (output/"cases.jsonl").read_text().splitlines()]
                assert len(rows)==1 and rows[0]["label"]=="exact-original-executable-tests"
                assert rows[0]["tests"]==7 and rows[0]["skipped"]==0
                assert rows[0]["original_test_source_sha256"]=="1ba1a51995c38ae93e5ce1a748a0b2bf3d2d6a19c0c48dfb9043c1ef639e094f"
                assert rows[0]["all_45_methods_native"] and rows[0]["reference_ELF_writer_used_only_as_test_link_container"]
                assert not rows[0]["production_lowering_and_ELF_join_closed"]
                report["original_unittest"]=rows[0]
            errors.update(value["error_ids"]);operations.update(value["operations"])
        assert len(report["groups"])==17 and report["actual_cases"]==30567
        assert report["actual_private_controls"]==106
        assert errors==set(range(1,18)),sorted(errors)
        assert operations==set(range(46)),sorted(operations)
        report.update(status="PASS",all_original_error_ids=sorted(errors),all_operation_ids=sorted(operations),
            original_code_limit=67108864,original_partial_finalized_copy_limit=67108868,
            all_seventeen_bounded_groups_passed=True,whole_bytes_and_persistent_state_differential=True)
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None and project.exists():roots["machine-x64-encoder"]=project
        common.finish("machine-x64-encoder-r1",status,report,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
