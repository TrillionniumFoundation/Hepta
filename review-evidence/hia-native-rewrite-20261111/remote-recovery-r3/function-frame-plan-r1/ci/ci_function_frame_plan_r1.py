"""Fresh CI identity for the complete private Function planner and its original-domain bounds."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"function-frame-plan-r1/"
FILES=[
  {
    "path": "tools/hia_function_frame_plan.py",
    "gitsha": "bb475cb50848f09dc4fda62ab1aa869bc0b9891d",
    "bytes": 32438,
    "sha256": "27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
  },
  {
    "path": "tools/build_hia_function_frame_plan.py",
    "gitsha": "649a5af778a0a11e4670ee2a425c36288d9a410c",
    "bytes": 9478,
    "sha256": "1bf04d2e64724602e76048bda84fabfebeffba2bb3f0063707e1cc8249247258"
  },
  {
    "path": "tests/test_hia_function_frame_plan.py",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
  },
  {
    "path": "tests/test_hia_function_frame_extents.py",
    "gitsha": "e7de610dbe5540e38c3fd78e0b3733d06ef09af5",
    "bytes": 4690,
    "sha256": "25d732cf33d2cb275a6f9595f6696d9b7ef92ac444c37d1e82bcade42f404cc4"
  },
  {
    "path": "docs/HIA_FUNCTION_FRAME_PLAN_NATIVE.md",
    "gitsha": "50c9f74b367a4cfee146a4be6efc8124c2b9f354",
    "bytes": 11600,
    "sha256": "f94f3762d782fec8def8f6e7069e13abb2db34359a7a14f0d19ba346869f635f"
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
    "path": "reference/hia_selfhost_child.py",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
  }
]
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
BASE_GROUPS=[
    ("smoke",25,66,25,0,0),
    ("edges",21,63,21,0,0),
    ("calls",33,99,8,25,0),
    ("inventories",16,40,15,1,0),
    ("private",61,81,0,0,55),
]
EXTENTS=[
    ("blocks",0,2),("edge",0,3),("edge",1,3),("edge",2,2),
    ("call",0,3),("call",1,2),("saved",0,2),("saved",1,2),("saved",2,2),
]
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
    spec=importlib.util.spec_from_file_location("function_frame_common_r1",common_path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[common_path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    project=None;status="FAIL"
    report=dict(scope="NEW_CI_FUNCTION_FRAME_AND_STAGING_PLAN",
        expected_groups=19,expected_cases=170,expected_native_entries=380,
        expected_admitted_core_cases=83,expected_private_constructor_pressure_cases=26,
        expected_private_controls=55,actual_new_compilations=0,actual_native_entries=0,
        actual_cases=0,actual_admitted_core_cases=0,actual_private_constructor_pressure_cases=0,
        actual_private_controls=0,groups={},old_counts_inherited=False,
        local_run_raw_currently_unavailable=True,local_run_result_not_inherited=True,
        checked_core_and_machine_plan_required=True,full_profile_admission_closed=False,
        whole_backend_closed=False,emitter_lowering_closed=False,installed_closed=False,cold_qualified=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"function-frame-plan-recovery-r1";mine.mkdir()
        project=mine/"native-function-plan-next";project.mkdir()
        for row in FILES:
            path=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            data=path.read_bytes()
            assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        environment=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],
                         LC_ALL="C.UTF-8",LANG="C.UTF-8")
        build=project/"development/build-r1"
        try:
            common.run("function-frame-generate-and-original-B3",[
                context["python"],"-B",project/"tools/build_hia_function_frame_plan.py",
                "--reference",context["reference"],"--compiler",context["compiler"],"--out",build],
                cwd=project,timeout=180,env=environment)
        finally:
            value=read_summary(build,"HIA_FUNCTION_FRAME_BUILD_ORIGINAL")
            if value is not None:
                report["build"]=value;report["actual_new_compilations"]=value["compilations"]
            if build.exists():
                for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
                    print_original(path,"HIA_FUNCTION_FRAME_NESTED_STDERR")
        value=report["build"]
        assert value["status"]=="PASS_BUILD_ONLY" and value["source_pins_unchanged"]
        assert value["compilations"]==1 and value["native_semantic_entries"]==0
        assert value["actual_limits"]==LIMITS
        manifest=value["manifest"];profile=manifest["profile"];receipt=manifest["compile_receipt"]
        assert manifest["author_sha256"]==FILES[0]["sha256"]
        assert manifest["reference_sha256"]==FILES[7]["sha256"]
        assert manifest["machine_plan_reference_sha256"]==FILES[8]["sha256"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["runner_sha256"]==FILES[9]["sha256"]
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_blocks"]<=256 and profile["max_params"]<=16
        assert (manifest["source_bytes"],manifest["source_sha256"])==(155401,
            "96962d9dab6f96c0e49a9e1e331587e0cc55e105839d93d7e827fefd3d6f2708")
        assert (manifest["image_bytes"],manifest["image_sha256"])==(227006,
            "eabb91f8faa0c0b89738b63c0e8b0fd00d41f9f50d869851b60014d2e2660e48")
        assert manifest["checked_core_and_machine_plan_required"] and not manifest["header_is_authentication"]
        assert not manifest["whole_backend_closed"] and not manifest["cold_qualified"]
        manifest_path=build/"function-frame.manifest.json"
        schedules=[]
        for group,cases,entries,admitted,pressure,controls in BASE_GROUPS:
            schedules.append((group,"test_hia_function_frame_plan.py",group,0,cases,entries,admitted,pressure,controls))
        for variant in range(5):
            schedules.append(("boundary-"+str(variant),"test_hia_function_frame_plan.py",
                "boundary",variant,1,2,1,0,0))
        for group,variant,entries in EXTENTS:
            schedules.append(("extent-"+group+"-"+str(variant),"test_hia_function_frame_extents.py",
                group,variant,1,entries,1,0,0))
        for label,test_name,group,variant,cases,entries,admitted,pressure,controls in schedules:
            output=project/"development"/("native-"+label+"-r1")
            try:
                common.run("function-frame-full-"+label,[
                    context["python"],"-B",project/"tests"/test_name,
                    "--manifest",manifest_path,"--reference",context["reference"],"--out",output,
                    "--group",group,"--variant",str(variant)],
                    cwd=project,timeout=180,env=environment)
            finally:
                value=read_summary(output,"HIA_FUNCTION_FRAME_GROUP_ORIGINAL")
                if value is not None:
                    report["groups"][label]=value
                    for target,source in (
                        ("actual_native_entries","native_entries"),("actual_cases","cases"),
                        ("actual_admitted_core_cases","admitted_core_cases"),
                        ("actual_private_constructor_pressure_cases","private_constructor_pressure_cases"),
                        ("actual_private_controls","private_controls")):
                        report[target]=sum(row.get(source,0) for row in report["groups"].values())
            value=report["groups"][label]
            assert value["status"]=="PASS" and value["group"]==group and value["variant"]==variant
            assert (value["cases"],value["native_entries"],value["admitted_core_cases"],
                value["private_constructor_pressure_cases"],value["private_controls"])==(
                cases,entries,admitted,pressure,controls),(label,value)
            assert value["limits"]==LIMITS
            assert not value["whole_backend_closed"] and not value["cold_qualified"]
            custody=value["custody"]
            assert custody["status"]=="PASS" and custody["source_pins_unchanged"] and not custody["changed"]
            for flag in ("all_new_pages_decompressed_equal","all_final_pages_rehashed",
                         "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
                assert custody[flag],(label,flag)
            assert custody["complete_snapshot_descriptors"]>=value["native_entries"]*6
            assert custody["cas_pages"]>0 and custody["logical_buffer_bytes"]>0
        assert len(report["groups"])==19
        assert (report["actual_cases"],report["actual_native_entries"],report["actual_admitted_core_cases"],
            report["actual_private_constructor_pressure_cases"],report["actual_private_controls"])==(170,380,83,26,55)
        report.update(status="PASS",all_nineteen_bounded_groups_passed=True,
            exact_original_constructor_layout_and_staging_traces_equal=True,
            original_function_domain_tested=1024,original_block_domain_tested=4096,
            original_frame_byte_limit=65536,
            logical_buffer_bytes=sum(v["custody"]["logical_buffer_bytes"] for v in report["groups"].values()))
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None and project.exists():roots["function-frame-plan"]=project
        common.finish("function-frame-plan-r1",status,report,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
