"""New public CLI A join only; old completed component suites are not rerun."""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "development/read_public_cli_a_assets_r1.py",
    "gitsha": "a21895ee8721432db9b0ec6945025c6bd19087f1",
    "bytes": 14449,
    "sha256": "2bdb3331e96db57c8b53b4a2b00df8676385bedb9240987c4060ebd63e93a2da"
  },
  {
    "path": "tests/test_public_cli_A_r1.py",
    "gitsha": "0b22d7b89e2b909f5746c765c0fdb926dc005d35",
    "bytes": 18066,
    "sha256": "92fee14ffe85457175658fc4f5a195dee80a766875b487448f041bce3574051d"
  },
  {
    "path": "docs/HIA_PUBLIC_CLI_A_R1.md",
    "gitsha": "0c1b165b86713a30c0854b79a19fffd56993bc3a",
    "bytes": 4234,
    "sha256": "b9e5d63702b604151b9f2e8cebce53793c647751178b16fc73e5790f394f2f5c"
  },
  {
    "path": "tools/cli_business_parent.py",
    "gitsha": "6722984f4fe4a2e5c77c06dec018caa8041927c4",
    "bytes": 15334,
    "sha256": "56680dca04f820cd23796f53d2f376a9604de03d79019316ad09d10c9dcc5809"
  }
]
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("public_A_common",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    context=mine=project=None;status="FAIL"
    detail=dict(scope="NEW_PUBLIC_CLI_A_ARGV_FILE_SERVICE_PRETTY_JOIN",
        historical_component_cases_inherited=False,old_967_reexecuted=False,
        old_193_reexecuted=False,old_private_parent_75_reexecuted=False,
        installed_activated=False,publication_closed=False,whole_cli_closed=False)
    try:
        context=common.prepare();base=Path(context["base"])
        mine=base/"cli-public-A-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-public-A-next";project.mkdir(parents=True)
        rows=[]
        for row in FILES:
            target=common.materialize(R3+"cli-public-A-r1/"+row["path"],row["gitsha"],project/row["path"])
            raw=target.read_bytes()
            assert (len(raw),sha256(raw).hexdigest())==(row["bytes"],row["sha256"])
            rows.append(row)
        for relative,blob in (
            ("tools/cli_entry_owner.py","3fa7143528736548118cb47801ed44102f03cee8"),
            ("tools/cli_authoring.py","6f1bffe8bd815a068f9834489960006cbaad6fac")):
            target=common.materialize(R3+"cli/"+relative,blob,project/relative)
            rows.append(dict(path=relative,gitsha=blob,bytes=target.stat().st_size,
                             sha256=sha256(target.read_bytes()).hexdigest()))
        frozen=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source"
        for source,target,size,expected in (
            (frozen/"6/hia_agent_edit_source_views.py",
             project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",23950,
             "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"),
            (frozen/"8/hia_composite_lowering_driver_common.py",
             project.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",17781,
             "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")):
            raw=source.read_bytes();assert (len(raw),sha256(raw).hexdigest())==(size,expected)
            common.PINS[source.resolve()]=raw;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as stream:stream.write(raw)
            assert target.read_bytes()==raw
            rows.append(dict(source=str(source),copy=str(target),bytes=size,sha256=expected))
        save(mine/"materialization.json",rows)
        common.run("read-exact-cli-and-A-archives",[
            context["python"],"-B",project/"development/read_public_cli_a_assets_r1.py",
            "--download-dir",os.environ["HIA_PUBLIC_A_DOWNLOAD_DIR"],"--out",mine/"assets"],timeout=300)
        raw=project/"development/actual-public-A-r1"
        try:
            common.run("new-public-cli-A-actual-join",[
                context["python"],"-B",project/"tests/test_public_cli_A_r1.py",
                "--assets",mine/"assets/assets.json","--reference",context["reference"],"--out",raw],
                cwd=project,timeout=900,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"]))
        finally:
            if (raw/"summary.json").is_file():
                value=json.loads((raw/"summary.json").read_bytes())
                print("HIA_PUBLIC_A_ATTEMPT_ORIGINAL "+json.dumps({k:v for k,v in value.items() if k!="cases"},sort_keys=True),flush=True)
        actual=json.loads((raw/"summary.json").read_bytes())
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
        assert tuple(actual[k] for k in ("exact_equivalence_cases","original_corpus_public_join_cases",
            "additional_public_join_cases","explicit_open_publication_cases","native_processes",
            "reference_processes","actual_packer_entries","new_parent_B3_compilations"))==(78,75,3,1,79,78,1,1)
        assert actual["real_A_service_bound"] and actual["public_argv_and_file_owner"]
        assert actual["complete_stdout_stderr_exit_equal"] and actual["publication_closed"] is False
        assert actual["old_cases_inherited"] is False and actual["installed_entry_activated"] is False
        detail["actual"]=actual;status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if project is not None:
            p=project/"development/actual-public-A-r1/summary.json"
            if p.exists():detail["actual"]=json.loads(p.read_bytes())
    finally:
        common.finish("public-cli-A-actual-join-r1",status,detail,
                      roots={"public-cli-A":mine} if mine is not None else {})
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
