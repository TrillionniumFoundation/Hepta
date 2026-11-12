"""Fresh assembly renderer native component; no retained suite counts."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/assembly_render_owner.py",
    "blob": "030f921e725eaa1bc798f884f9801848e95c6f34",
    "bytes": 29652,
    "sha256": "8eaaf5a0b209f8a9e8a573fe2943912e45116414747ab6eef6c97b55384518d5"
  },
  {
    "path": "tests/test_hia_assembly_render_native.py",
    "blob": "ee7d90d4a0a66fd059dbf6355efa5b0c36289510",
    "bytes": 24983,
    "sha256": "91af9a3766822014634c49dc9e46b8c0008503188e47550ee2a59aea8c5aa861"
  },
  {
    "path": "docs/HIA_FULL_ASSEMBLY_RENDER_R1.md",
    "blob": "87cf582d4bed054a3b66db051d576ed71050c451",
    "bytes": 8378,
    "sha256": "5787c87b31e06f5e0770b88daf6b10b4c1a47290c4c2f57a7a6730a516edb804"
  }
]
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def show(out):
    for path in sorted(out.rglob("*.stderr")):
        raw=path.read_bytes()
        for at in range(0,len(raw),18000):
            part=raw[at:at+18000]
            print("HIA_ASSEMBLY_RENDER_ORIGINAL_STDERR "+json.dumps(dict(path=str(path.relative_to(out)),bytes=len(raw),
                sha256=digest(raw),offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    for name in ("profile.json","summary.json"):
        for path in sorted(out.rglob(name)):
            print("HIA_ASSEMBLY_ORIGINAL_JSON "+json.dumps(dict(path=str(path.relative_to(out)),
                value=json.loads(path.read_bytes())),sort_keys=True),flush=True)
def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("assembly_render_recovery_common",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    mine=project=None;status="FAIL";detail=dict(scope="NEW_COMPLETE_ASSEMBLY_RENDER_COMPONENT",
        native_Core_admission_qualified=False,native_roundtrip_qualified=False,public_cli_qualified=False,
        installed_activated=False,cold_qualified=False,old_suites_rerun=False,old_counts_inherited=False)
    try:
        c=common.prepare();mine=Path(c["base"])/"assembly-render-recovery";mine.mkdir()
        project=mine/"workspace/native-public-assembly-next";project.mkdir(parents=True)
        rows=[]
        for row in FILES:
            p=common.materialize(R3+"cli-assembly-render-r1/"+row["path"],row["blob"],project/row["path"])
            data=p.read_bytes();assert (len(data),digest(data))==(row["bytes"],row["sha256"])
            rows.append(row)
        common.materialize(R3+"cli/tools/cli_authoring.py","6f1bffe8bd815a068f9834489960006cbaad6fac",project/"tools/cli_authoring.py")
        source=Path(c["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
        data=source.read_bytes()
        assert (len(data),digest(data))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
        common.PINS[source.resolve()]=data
        target=project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py"
        target.parent.mkdir(parents=True)
        with target.open("xb") as f:f.write(data)
        assert target.read_bytes()==data
        rows.append(dict(source=str(source),target=str(target),bytes=len(data),sha256=digest(data)))
        save(mine/"materialization.json",rows)
        out=project/"development/render-native-r1"
        try:
            common.run("actual-complete-assembly-render-original-profile",
                [c["python"],"-B",project/"tests/test_hia_assembly_render_native.py",
                 "--reference",c["reference"],"--compiler",c["compiler"],"--out",out],
                cwd=project,timeout=180,env=dict(PYTHONDONTWRITEBYTECODE="1",
                 PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+c["reference"],
                 LANG="C.UTF-8",LC_ALL="C.UTF-8"))
        finally:
            if out.exists():show(out)
        actual=json.loads((out/"summary.json").read_bytes())
        assert actual["status"]=="PASS"
        assert actual["expected_public_cases"]==actual["actual_public_cases"]==309
        assert actual["expected_private_constructions"]==actual["private_constructions"]==69
        assert actual["private_controls"]==41 and actual["native_entries"]>=378
        assert actual["source_image_before_after"] and actual["complete_native_text_bytes_compared"]
        assert actual["all_reference_admissions_recorded"] and actual["private_constructions_separate"]
        assert actual["maximum_text_bytes"]>1048576 and actual["reference_late_roundtrip_refusals"]>=7
        assert not actual["native_Core_admission_qualified"] and not actual["native_roundtrip_qualified"]
        assert not actual["public_cli_qualified"] and not actual["old_counts_inherited"] and not actual["cold_qualified"]
        detail["actual"]=actual;status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if mine is not None and mine.exists():roots["assembly-render"]=mine
        common.finish("cli-full-assembly-render-r1",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
