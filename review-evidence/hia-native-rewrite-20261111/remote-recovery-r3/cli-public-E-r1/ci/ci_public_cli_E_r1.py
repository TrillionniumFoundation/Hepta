"""New public CLI E join with exact A/CLI originals and exact new E compile evidence.

No previous native case is inherited. The full public argv/file/error/pretty
contract is compared against the immutable original Python CLI in new processes.
Nonempty output-path publication remains a separately unclosed integration.
"""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "source_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/cli-public-A-r1/development/read_public_cli_a_assets_r1.py",
    "path": "development/read_public_cli_a_assets_r1.py",
    "gitsha": "a21895ee8721432db9b0ec6945025c6bd19087f1",
    "bytes": 14449,
    "sha256": "2bdb3331e96db57c8b53b4a2b00df8676385bedb9240987c4060ebd63e93a2da"
  },
  {
    "source_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/cli-public-E-r1/tests/test_public_cli_E_r3.py",
    "path": "tests/test_public_cli_E_r3.py",
    "bytes": 25753,
    "gitsha": "d34223dffcd99832be2ddd9566c76a10b09e50bf",
    "sha256": "79b2f6a610ec18b739aef67c75415d7c0be1dc68b1c6474844ec5f93c241e601"
  },
  {
    "source_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/cli-public-E-r1/development/read_public_cli_e_assets_r1.py",
    "path": "development/read_public_cli_e_assets_r1.py",
    "bytes": 10107,
    "gitsha": "c41a5dc3d5bf1af0d747f651c927b81de8f48b40",
    "sha256": "1caa1ae38c72ba85c9b26dc20a840fe3063669639e700c25403f782d87eeb1b8"
  },
  {
    "source_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/cli-public-A-r1/tools/cli_business_parent.py",
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
    spec=importlib.util.spec_from_file_location("public_E_common",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    context=mine=project=None;status="FAIL"
    detail=dict(scope="NEW_PUBLIC_CLI_E_ARGV_FILE_SERVICE_PRETTY_JOIN",
        historical_component_cases_inherited=False,old_967_reexecuted=False,
        old_193_reexecuted=False,old_private_parent_75_reexecuted=False,
        installed_activated=False,publication_closed=False,whole_cli_closed=False)
    try:
        context=common.prepare();base=Path(context["base"])
        mine=base/"cli-public-E-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-public-E-next";project.mkdir(parents=True)
        rows=[]
        for row in FILES:
            target=common.materialize(row["source_path"],row["gitsha"],project/row["path"])
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
            "--download-dir",os.environ["HIA_PUBLIC_E_DOWNLOAD_DIR"],"--out",mine/"assets"],timeout=300)
        edit_download=Path(os.environ["HIA_PUBLIC_E_NEW_ARTIFACT_DIR"])
        common.run("read-exact-E-development-and-original-archive",[
            context["python"],"-B",project/"development/read_public_cli_e_assets_r1.py",
            "--zip",edit_download/"new-E.zip","--metadata",edit_download/"artifact.json",
            "--job",edit_download/"job.json","--run",edit_download/"run.json",
            "--original-zip",edit_download/"original-E.zip",
            "--source-dir",Path(context["repo"])/R3/"edit-public-service-r1",
            "--out",mine/"edit-assets"],timeout=300)
        edit_readback=json.loads((mine/"edit-assets/readback.json").read_bytes())
        assert edit_readback["status"]=="PASS_READBACK_ONLY" and edit_readback["all_inputs_unchanged"]
        assert edit_readback["new_native_entries"]==0 and edit_readback["old_case_counts_inherited"] is False
        raw=project/"development/actual-public-E-r1"
        try:
            common.run("new-public-cli-E-actual-join",[
                context["python"],"-B",project/"tests/test_public_cli_E_r3.py",
                "--assets",mine/"assets/assets.json","--reference",context["reference"],"--out",raw,
                "--edit-development",mine/"edit-assets/development"],
                cwd=project,timeout=1200,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"]))
        finally:
            if (raw/"summary.json").is_file():
                value=json.loads((raw/"summary.json").read_bytes())
                print("HIA_PUBLIC_E_ATTEMPT_ORIGINAL "+json.dumps({k:v for k,v in value.items() if k!="cases"},sort_keys=True),flush=True)
        actual=json.loads((raw/"summary.json").read_bytes())
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
        assert tuple(actual[k] for k in ("exact_equivalence_cases","native_processes",
            "reference_processes","actual_packer_entries","new_parent_B3_compilations",
            "new_E_B3_images_reused_from_exact_generation"))==(82,82,82,1,1,2)
        assert actual["real_E_service_bound"] and actual["public_argv_and_file_owner"]
        assert actual["complete_stdout_stderr_exit_equal"] and actual["publication_closed"] is False
        assert actual["old_cases_inherited"] is False and actual["installed_entry_activated"] is False
        detail["new_E_assets_readback"]=edit_readback
        detail["actual"]=actual;status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if project is not None:
            p=project/"development/actual-public-E-r1/summary.json"
            if p.exists():detail["actual"]=json.loads(p.read_bytes())
    finally:
        common.finish("public-cli-E-actual-join-r1",status,detail,
                      roots={"public-cli-E":mine} if mine is not None else {})
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
