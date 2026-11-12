"""Fresh native machine ELF leaf, seven separately bounded test groups."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"machine-elf-writer-r1/"
FILES=[
  {
    "path": "tools/hia_machine_elf_writer.py",
    "gitsha": "ec262028c52d8f76ba1834212388c741d4ce3a7b",
    "bytes": 28952,
    "sha256": "4c93bc5fc97852bcd9c5fcc6c582ff79efa64af0124c01ee4b1054df95547458"
  },
  {
    "path": "tools/build_hia_machine_elf_writer.py",
    "gitsha": "8ced3a32755cf72c9f3101f13ebbf8e1227b14f6",
    "bytes": 7240,
    "sha256": "6e168fa5f155245ffc388344e7ec2d6776cc26fc836e2589bd7380f84eec2b60"
  },
  {
    "path": "tests/test_hia_machine_elf_writer.py",
    "gitsha": "bc9935e256fe3f9adef06417cf0caed4fe13829d",
    "bytes": 28616,
    "sha256": "fa2d20200efd993d79213c84248c5db4baac4d64d0976008193d1d5356de54a6"
  },
  {
    "path": "docs/HIA_MACHINE_ELF_WRITER_NATIVE.md",
    "gitsha": "62fa6f7c4c412c2c80cae5a6ab4d4a58bef1f89e",
    "bytes": 7204,
    "sha256": "30397ae124742e9d689204372b9109acfc5418c7f2e1cbfe210576836dbccac5"
  },
  {
    "path": "tools/elf_authoring_reference.py",
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
    "path": "reference/hia_machine_elf.py",
    "gitsha": "cad2e6d21dccc95ad3cfd368da42964ec52d4bb7",
    "bytes": 7026,
    "sha256": "c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"
  },
  {
    "path": "reference/graph_harness_r3.py",
    "gitsha": "eaf060c8c6870cad0a85a23f6b94ffa39308c45c",
    "bytes": 9783,
    "sha256": "75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c"
  }
]
GROUPS={"basic":81,"types":215,"order":55,"random":160,"symbols":7,"objects":5,"protocol":2}
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def print_original(path,label):
    raw=path.read_bytes()
    for at in range(0,len(raw),18000):
        part=raw[at:at+18000]
        print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
            offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=common_path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("machine_elf_common_r1",common_path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[common_path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    mine=project=None;status="FAIL"
    report=dict(scope="NEW_PURE_ELF64_ET_REL_HIA_LEAF",old_counts_inherited=False,
        ordinary_Core_lowering_closed=False,installed_closed=False,cold_qualified=False,
        expected_semantic_cases=sum(GROUPS.values()),expected_private_controls=45,
        actual_new_compilations=0,actual_native_entries=0,groups={})
    try:
        context=common.prepare()
        mine=Path(context["base"])/"machine-elf-writer-recovery-r1";mine.mkdir()
        project=mine/"native-machine-elf-writer-next";project.mkdir()
        for row in FILES:
            path=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            data=path.read_bytes()
            assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        build=project/"development/build-r1"
        try:
            common.run("machine-elf-source-generation-and-original-B3",[
                context["python"],"-B",project/"tools/build_hia_machine_elf_writer.py",
                "--reference",context["reference"],"--compiler",context["compiler"],
                "--helper",project/"tools/hia_agent_edit_source_views.py","--out",build],
                cwd=project,timeout=180,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8"))
        finally:
            if (build/"summary.json").exists():
                summary=json.loads((build/"summary.json").read_bytes());report["build"]=summary
                print("HIA_MACHINE_ELF_BUILD_ORIGINAL "+json.dumps(summary,sort_keys=True),flush=True)
            if build.exists():
                for path in sorted(build.rglob("*.stderr")):print_original(path,"HIA_MACHINE_ELF_NESTED_STDERR")
        assert report["build"]["status"]=="PASS_BUILD_ONLY" and report["build"]["source_pins_unchanged"]
        assert report["build"]["compilations"]==1 and report["build"]["native_semantic_entries"]==0
        report["actual_new_compilations"]=1
        manifest=build/"machine-elf-writer.manifest.json"
        count=0;errors=set()
        for group,expected in GROUPS.items():
            output=project/"development"/("native-"+group+"-r1")
            try:
                common.run("machine-elf-full-"+group,[
                    context["python"],"-B",project/"tests/test_hia_machine_elf_writer.py",
                    "--manifest",manifest,"--reference",context["reference"],"--out",output,"--group",group],
                    cwd=project,timeout=180,env=dict(PYTHONDONTWRITEBYTECODE="1",
                        PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8"))
            finally:
                if (output/"summary.json").exists():
                    value=json.loads((output/"summary.json").read_bytes())
                    report["groups"][group]=value
                    print("HIA_MACHINE_ELF_GROUP_ORIGINAL "+json.dumps({k:v for k,v in value.items() if k!="results"},sort_keys=True),flush=True)
            value=report["groups"][group]
            assert value["status"]=="PASS" and value["cases"]==expected
            assert value["source_custody"]["status"]=="PASS" and value["source_custody"]["source_pins_unchanged"]
            assert value["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert value["full_bytes_or_exact_error_equal"] and value["physical_inputs_readonly"]
            assert value["complete_buffers_and_canaries_recorded"]
            if group=="protocol":assert value["private_controls"]==45
            assert not value["old_counts_inherited"] and not value["installed_closed"] and not value["cold_qualified"]
            report["actual_native_entries"]+=value["native_entries"]
            count+=value["cases"];errors.update(value["error_ids"])
        assert count==525 and errors==set(range(1,13))
        report.update(status="PASS",actual_semantic_cases=count,actual_private_controls=45,
            all_original_error_ids=sorted(errors),whole_bytes_differential=True)
        status="PASS"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None and project.exists():
            roots["machine-elf-writer"]=project
        common.finish("machine-elf-writer-r1",status,report,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
