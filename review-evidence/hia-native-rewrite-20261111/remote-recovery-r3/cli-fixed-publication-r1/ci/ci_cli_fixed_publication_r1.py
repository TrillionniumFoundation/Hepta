"""Fresh fixed native publication runtime; completed old suites are not repeated."""
from pathlib import Path
from hashlib import sha256
import importlib.util,json,os,stat,sys,traceback,zlib
DELIVERY=Path(__file__).resolve().parents[1]
FILES={
  "tools/cli_authoring.py": {
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  "tools/cli_publication_verified_owner.py": {
    "bytes": 18791,
    "sha256": "e07b8888aeb1c70743e3119a56b9f4e4aa79e22e8e647b0a28f3249d5d315e44"
  },
  "tools/cli_publication_fixed_driver.py": {
    "bytes": 15423,
    "sha256": "0a953c31b252628d237f227290d3ad7c9833dc7330559ad94681c80c4af3267a"
  },
  "tools/cli_publication_filesystem_fixtures.py": {
    "bytes": 9203,
    "sha256": "5229eeb50b8d786d77f6de45757084e347d70e634b8407cabfcf72bc19216437"
  },
  "tools/compose_cli_publication_filesystem.py": {
    "bytes": 12812,
    "sha256": "925f97d39a30301dc035cc4e505a1533cde9da70a8b629b8ce3cbc2e6ecc5088"
  },
  "tools/generate_hia_cli_publication_packer.py": {
    "bytes": 6706,
    "sha256": "09fbb382843a30c7232b4f7d028e3948e29c50e485d0bf049c8f4f12c8d8e5f7"
  },
  "tests/test_hia_cli_fixed_publication.py": {
    "bytes": 23257,
    "sha256": "d189be02482e5c74e7eae662bf2e60f44c08505854797a8e01b4e424055fbcce"
  },
  "reference/finite-carrier-passed.S": {
    "bytes": 57060,
    "sha256": "f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
  },
  "reference/hia_composite_lowering_driver_common.py": {
    "bytes": 17781,
    "sha256": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
  },
  "docs/HIA_CLI_FIXED_PUBLICATION_ABI.md": {
    "bytes": 6838,
    "sha256": "3031932623fb7cc08d489aa25b80b0d63a62ed0e03b7b88103191ab9475f426a"
  }
}
def digest(raw):return sha256(raw).hexdigest()
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v);return v
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def preserve_physical(fixtures,raw):
    if not fixtures.exists():return dict(status="NO_FIXTURES")
    cas=raw/"cas";cas.mkdir(parents=True,exist_ok=True);rows=[]
    for folder,dirs,files in os.walk(fixtures,followlinks=False):
        for name in sorted(dirs+files):
            path=Path(folder)/name;info=path.lstat()
            row=dict(path=path.relative_to(fixtures).as_posix(),mode=stat.S_IMODE(info.st_mode),
                type=stat.S_IFMT(info.st_mode),dev=info.st_dev,inode=info.st_ino,
                links=info.st_nlink,bytes=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
            if stat.S_ISLNK(info.st_mode):row["target"]=os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                content=path.read_bytes();h=digest(content);target=cas/(h+".zlib")
                if not target.exists():target.write_bytes(zlib.compress(content,6))
                assert zlib.decompress(target.read_bytes())==content
                row["data"]=dict(path="cas/"+target.name,bytes=len(content),sha256=h,compression="zlib")
            rows.append(row)
    save(raw/"physical-filesystem-after-process.json",rows)
    return dict(status="ALL_REMAINING_PHYSICAL_OBJECTS_PRESERVED",objects=len(rows))
def main():
    common=module("fixed_publication_common",Path(os.environ["HIA_CI_COMMON"]).resolve())
    context=None;mine=None;project=None;status="FAIL"
    detail=dict(scope="NEW_FIXED_NATIVE_PUBLICATION_RUNTIME",old_967_reexecuted=False,
        old_193_reexecuted=False,old_40_component_suite_reexecuted=False,
        whole_cli_publication_closed=False,path_staging_owner_closed=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"cli-fixed-publication-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-fixed-publication-next";project.mkdir(parents=True)
        rows=[]
        def cp(src,dst,pin):
            src=src.resolve();raw=src.read_bytes()
            assert (len(raw),digest(raw))==(pin["bytes"],pin["sha256"]),(src,pin)
            common.PINS[src]=raw;dst.parent.mkdir(parents=True,exist_ok=True)
            with dst.open("xb") as f:f.write(raw)
            dst.chmod(0o644);assert dst.read_bytes()==raw
            rows.append(dict(source=str(src),copy=str(dst),**pin))
        for path,pin in FILES.items():cp(DELIVERY/path,project/path,pin)
        helper=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
        cp(helper,project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
            dict(bytes=23950,sha256="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"))
        common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
        save(mine/"records/materialization.json",rows)
        frozen=Path(context["workspace"])/"native-edit-candidate-next/development/build-r1/source"
        raw=project/"development/fixed-actual-r2";failure=None
        try:
            common.run("fixed-publication-actual-r2",[
                context["python"],"-B",project/"tests/test_hia_cli_fixed_publication.py",
                "--source",context["source"],"--reference",context["reference"],
                "--compiler",context["compiler"],"--sha-source",frozen/"135/source.hiaasm",
                "--sha-image",frozen/"136/word-unrolled.image.bin","--out",raw],
                cwd=project,timeout=300,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["source"]))
        except BaseException as error:
            failure=error
            raise
        finally:
            try:detail["filesystem"]=preserve_physical(project/"development/fixed-filesystem-fixtures",raw)
            except BaseException as error:
                detail["filesystem_preservation_error"]=traceback.format_exc()
                if failure is not None:failure.add_note("Physical preservation also failed: "+repr(error))
                else:raise
        actual=json.loads((raw/"summary.json").read_bytes())
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
        assert actual["publication_cases"]==24 and actual["utility_cases"]==2 and actual["private_controls"]==17
        assert actual["native_processes"]==43 and actual["native_packer_entries"]==20
        assert actual["all_22_fs_kinds_executed"] and actual["fd_zero_open_and_close_exact"]
        assert actual["sparse_live_fd_table_growth_executed"] and actual["original_finite_service_child_body_exact"]
        assert actual["cas_readback"]["status"]=="PASS"
        detail["actual"]=actual;status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if project is not None:
            path=project/"development/fixed-actual-r2/summary.json"
            if path.exists():detail["actual"]=json.loads(path.read_bytes())
    finally:
        roots={}
        if project is not None:
            candidates={"fixed-publication-tools":project/"tools","fixed-publication-tests":project/"tests",
                "fixed-publication-reference":project/"reference","fixed-publication-docs":project/"docs",
                "fixed-publication-raw":project/"development/fixed-actual-r2",
                "fixed-publication-records":mine/"records",
                "fixed-publication-dependency":project.parent/"Hepta-agent-edit-native"}
            roots={name:path for name,path in candidates.items() if path.exists()}
        common.finish("cli-fixed-publication-native-r2",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
