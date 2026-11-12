"""Fresh native CLI publication Path-prefix proof; no completed suites rerun."""
from pathlib import Path
from hashlib import sha256
import importlib.util,json,os,sys,traceback
DELIVERY=Path(__file__).resolve().parents[1]
FILES={
  "tools/cli_authoring.py": {
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  "tools/cli_publication_path_owner.py": {
    "bytes": 24911,
    "sha256": "9a80eccc1267a9c112f2f6c5ae002114a7c9d0d1b3a1768cf0ebb9173faff24e"
  },
  "tools/generate_hia_cli_publication_path.py": {
    "bytes": 694,
    "sha256": "eb24fb29738850456a25fb1dcb5529ed45167dfbb39a70def23bbd2078f62e85"
  },
  "tests/test_hia_cli_publication_path.py": {
    "bytes": 16354,
    "sha256": "0d60332e148c7f4591ae7d2dd09c5cab303f3befbc8a0f84bd3cbb2730f0b3ca"
  },
  "docs/HIA_CLI_PUBLICATION_PATH_ABI.md": {
    "bytes": 7004,
    "sha256": "1eab8f6c318ec9de82593ed8f0b54b2951505d575e08a6fd4c33fd3750060875"
  }
}
def module(name,path):
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def main():
    common=module("path_prefix_common",Path(os.environ["HIA_CI_COMMON"]).resolve())
    ctx=None;project=None;mine=None;status="FAIL"
    detail=dict(scope="NEW_NATIVE_PATH_PREFIX",old_suites_rerun=False,whole_cli_publication_closed=False,
        temporary_staging_closed=False,over_PATH_MAX_getcwd_closed=False)
    try:
        ctx=common.prepare()
        mine=Path(ctx["base"])/"cli-publication-path-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-publication-path-next";project.mkdir(parents=True)
        rows=[]
        def cp(src,dst,pin):
            src=src.resolve();raw=src.read_bytes()
            assert (len(raw),sha256(raw).hexdigest())==(pin["bytes"],pin["sha256"]),(src,pin)
            common.PINS[src]=raw;dst.parent.mkdir(parents=True,exist_ok=True)
            with dst.open("xb") as f:f.write(raw)
            dst.chmod(0o644);assert dst.read_bytes()==raw;rows.append(dict(source=str(src),copy=str(dst),**pin))
        for path,pin in FILES.items():cp(DELIVERY/path,project/path,pin)
        cp(Path(ctx["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py",
            project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
            dict(bytes=23950,sha256="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"))
        common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
        save(mine/"records/materialization.json",rows)
        raw=project/"development/path-actual-r1"
        common.run("native-publication-path-prefix-r1",[
            ctx["python"],"-B",project/"tests/test_hia_cli_publication_path.py",
            "--source",ctx["source"],"--reference",ctx["reference"],
            "--compiler",ctx["compiler"],"--out",raw],cwd=project,timeout=300,
            env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+ctx["source"]))
        observed=json.loads((raw/"summary.json").read_bytes())
        assert observed["status"]=="PASS" and observed["cases"]==26 and observed["private_controls"]==10
        assert observed["native_entries"]>0 and observed["actual_fs_syscalls"]>0
        assert observed["source_pins_unchanged"] and observed["cas_readback"]["status"]=="PASS"
        detail["actual"]=observed;status="PASS"
    except BaseException as e:
        detail.update(error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc());traceback.print_exc()
        if project:
            p=project/"development/path-actual-r1/summary.json"
            if p.exists():detail["actual"]=json.loads(p.read_bytes())
    finally:
        roots={}
        if project:
            candidates={"path-tools":project/"tools","path-tests":project/"tests",
                "path-docs":project/"docs","path-raw":project/"development/path-actual-r1",
                "path-records":mine/"records","path-authoring-helper":project.parent/"Hepta-agent-edit-native"}
            roots={k:v for k,v in candidates.items() if v.exists()}
        common.finish("cli-publication-path-prefix-r1",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
