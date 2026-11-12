"""Fresh assembly syntax native component; no retained suite counts."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/assembly_syntax_owner.py",
    "blob": "227e06a56e8da7091d72004c83daeea7d24ee884",
    "bytes": 37844,
    "sha256": "365d8460c6d502685815ad0039e0d5de5503326abf58db13cd922605d097d11e"
  },
  {
    "path": "tests/test_hia_assembly_syntax_native.py",
    "blob": "902d604e34dd9b8c7f1c33778a0477972a297e35",
    "bytes": 25881,
    "sha256": "b091a03a220233bbf4c4779b06756fec49afd266c9d3018cae0d67cbbc0ba8ad"
  },
  {
    "path": "docs/HIA_FULL_ASSEMBLY_SYNTAX_R1.md",
    "blob": "889b6f99468730fab9b9e0bed9530be1d037706c",
    "bytes": 8314,
    "sha256": "0d2c6b8e1e80521e2a7aef677962766592ead28de21f491f2d61f6f72da4f7f3"
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
            print("HIA_ASSEMBLY_ORIGINAL_STDERR "+json.dumps(dict(path=str(path.relative_to(out)),bytes=len(raw),
                sha256=digest(raw),offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    for name in ("profile.json","summary.json"):
        for path in sorted(out.rglob(name)):
            print("HIA_ASSEMBLY_ORIGINAL_JSON "+json.dumps(dict(path=str(path.relative_to(out)),
                value=json.loads(path.read_bytes())),sort_keys=True),flush=True)
def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("assembly_recovery_common",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    mine=project=None;status="FAIL";detail=dict(scope="NEW_FULL_PUBLIC_ASSEMBLY_SYNTAX_COMPONENT",
        renderer_qualified=False,whole_core_qualified=False,public_cli_qualified=False,
        installed_activated=False,cold_qualified=False,old_suites_rerun=False,old_counts_inherited=False)
    try:
        c=common.prepare();mine=Path(c["base"])/"assembly-syntax-recovery";mine.mkdir()
        project=mine/"workspace/native-public-assembly-next";project.mkdir(parents=True)
        rows=[]
        for row in FILES:
            p=common.materialize(R3+"cli-assembly-syntax-r1/"+row["path"],row["blob"],project/row["path"])
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
        out=project/"development/syntax-native-r1"
        try:
            common.run("actual-full-assembly-syntax-original-profile",
                [c["python"],"-B",project/"tests/test_hia_assembly_syntax_native.py",
                 "--reference",c["reference"],"--compiler",c["compiler"],"--out",out],
                cwd=project,timeout=900,env=dict(PYTHONDONTWRITEBYTECODE="1",
                 PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+c["reference"],
                 LANG="C.UTF-8",LC_ALL="C.UTF-8"))
        finally:
            if out.exists():show(out)
        actual=json.loads((out/"summary.json").read_bytes())
        assert actual["status"]=="PASS" and actual["expected_cases"]==actual["actual_cases"]>600
        assert actual["actual_entries"]>=actual["actual_cases"] and actual["private_controls"]>=20
        assert actual["source_image_before_after"] and actual["ordered_object_bytes_compared"] and actual["full_errors_compared"]
        assert actual["integer_value_budget_native"] and actual["entire_original_syntax_inventory_preserved"]
        assert not actual["core_semantics_qualified"] and not actual["renderer_qualified"]
        assert not actual["public_cli_qualified"] and not actual["old_results_inherited"] and not actual["cold_qualified"]
        detail["actual"]=actual;status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if mine is not None and mine.exists():roots["assembly-syntax"]=mine
        common.finish("cli-full-assembly-syntax-r1",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
