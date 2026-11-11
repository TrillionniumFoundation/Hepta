"""Independent finite-carrier CI, with no inherited CLI component counts."""
from pathlib import Path
from hashlib import sha256
import importlib.util,json,os,shutil,sys,traceback

DELIVERY=Path(__file__).resolve().parents[1]
FILES={
  "tools/cli_authoring.py": {
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  "tools/compose_cli_business_executor.py": {
    "bytes": 21032,
    "sha256": "38db577e4a95c06059ecf010eb770d7c3ca24dd47c355797e2069601bbfc64bb"
  },
  "tools/cli_business_executor.S": {
    "bytes": 56987,
    "sha256": "90cd4a88f9cd09674076f078d9d30b6b9a593ba5e369a43f5231ad2686ed828c"
  },
  "tools/generate_hia_cli_business_packer.py": {
    "bytes": 6690,
    "sha256": "5b2f167e569e60f80d5b8db662f2807c295fb6075716fe6679338ce319c5e654"
  },
  "tools/cli_business_fixture_owners.py": {
    "bytes": 15117,
    "sha256": "962c78206ee21c657d3b3641735829689fbfb5afa350c0c14a4d95a41a116c24"
  },
  "tests/test_hia_cli_finite_carrier.py": {
    "bytes": 21326,
    "sha256": "545b3bf99173124487866f46f946fb969c92e25f6517a2e0fb7f00845645dcd3"
  },
  "reference/cli-executor-r4.S": {
    "bytes": 14594,
    "sha256": "717f23a65686cabc8a2599e28079fa37645393eaa31e5e30cdc0cad6aef86c26"
  },
  "reference/program-executor.S": {
    "bytes": 32247,
    "sha256": "6c8e7c8dfdbbbe1da653834c67e19f733922937f86531c88179713c018770cac"
  },
  "reference/program-roles.json": {
    "bytes": 115895,
    "sha256": "a942f616655aeec0f047d66ed7ee6be83fa3a960d65a635bc4c849e29cf6f5df"
  },
  "docs/HIA_CLI_BUSINESS_CONTEXT_ABI.md": {
    "bytes": 16750,
    "sha256": "711ffce73e36df623cb5351118d2a5be276e319b03271b1a405ed25e66987c2a"
  }
}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

def main():
    common=module("finite_ci_common",Path(os.environ["HIA_CI_COMMON"]).resolve())
    context=None;mine=None;status="FAIL";details={
        "scope":"finite-carrier-only",
        "old_capture_wire_file_967_cases_repeated":False,
        "whole_cli_closed":False,"ordinary_businesses_qualified":False}
    try:
        context=common.prepare()
        base=Path(context["base"]);mine=base/"cli-business-recovery"
        mine.mkdir()
        project=mine/"workspace/native-cli-business-carrier-next"
        project.mkdir(parents=True)
        materialized=[]
        def exact_copy(original,target,expected=None):
            raw=original.read_bytes()
            if expected is not None:assert digest(raw)==expected,(original,digest(raw),expected)
            common.PINS[original.resolve()]=raw
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as out:out.write(raw)
            target.chmod(0o644)
            assert target.read_bytes()==raw
            materialized.append(dict(original=str(original),copy=str(target),bytes=len(raw),sha256=digest(raw)))
        for relative,pin in FILES.items():
            src=DELIVERY/relative;raw=src.read_bytes()
            assert len(raw)==pin["bytes"] and digest(raw)==pin["sha256"],relative
            exact_copy(src,project/relative,pin["sha256"])
        workspace=Path(context["workspace"])
        old=workspace/"native-edit-json-next/development/main-compile-r3/source"
        exact_copy(old/"6/hia_agent_edit_source_views.py",
            project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
            "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
        exact_copy(old/"8/hia_composite_lowering_driver_common.py",
            project.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
            "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")
        save(mine/"materialization.json",materialized)
        readback=project/"development/actual-r1"
        common.run("finite-carrier-actual-r1",[
            context["python"],"-B",project/"tests/test_hia_cli_finite_carrier.py",
            "--source",context["source"],"--reference",context["reference"],
            "--compiler",context["compiler"],
            "--roles",project/"reference/program-roles.json","--out",readback],
            cwd=project,timeout=600,
            env=dict(PYTHONDONTWRITEBYTECODE="1",
                PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["source"]))
        summary=json.loads((readback/"summary.json").read_bytes())
        assert summary["status"]=="PASS" and summary["source_pins_unchanged"]
        assert (summary["cases"],summary["private_mechanics_cases"],
                summary["issued_program_cases"],summary["native_processes"],
                summary["actual_packer_entries"])==(18,14,4,18,18)
        assert summary["accepted_programs"]==2 and summary["rejected_programs"]==2
        details["actual"]=summary;status="PASS"
    except BaseException as error:
        details.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        if mine is not None:
            p=mine/"workspace/native-cli-business-carrier-next/development/actual-r1/summary.json"
            if p.exists():details["actual"]=json.loads(p.read_bytes())
        traceback.print_exc()
    finally:
        roots={} if mine is None else {"finite-carrier":mine}
        common.finish("cli-finite-carrier-actual-r1",status,details,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
