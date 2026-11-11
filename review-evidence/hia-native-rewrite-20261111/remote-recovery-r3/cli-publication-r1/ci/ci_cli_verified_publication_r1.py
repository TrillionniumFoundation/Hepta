"""New actual HIA verified-publication component, independent fresh evidence.

This job does not rerun the completed 967 CLI component or 193 entry calls.
It leaves Path.absolute/mkdir/resolve/staging and whole CLI publication open.
The physical fixture graph is preserved through metadata plus lossless CAS;
special files/hardlinks never enter the generic raw archive directly.
"""
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
  "tools/generate_hia_cli_verified_publication.py": {
    "bytes": 1265,
    "sha256": "3f75cad9055d44f5db353ba148a030dd9031bd8217ed7a7d00769b006d8bb0d9"
  },
  "tests/test_hia_cli_verified_publication.py": {
    "bytes": 21430,
    "sha256": "ed822559e0f6efc6aa54d9711b738ecf30f6fde345c05070daf7cf6e856106cc"
  },
  "docs/HIA_CLI_VERIFIED_PUBLICATION_ABI.md": {
    "bytes": 6156,
    "sha256": "2f16e0059566ae1458bb05ae2ba8029e55bb7d16791244fa0f501da4f1bd069a"
  }
}
def digest(raw):return sha256(raw).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
def freeze_filesystem(fixtures,out):
    if not fixtures.exists():return dict(status="NO_FIXTURES")
    cas=out/"cas";cas.mkdir(parents=True,exist_ok=True)
    rows=[]
    for folder,dirs,files in os.walk(fixtures,followlinks=False):
        for name in sorted(dirs+files):
            path=Path(folder)/name;info=path.lstat()
            row=dict(path=path.relative_to(fixtures).as_posix(),
                mode=stat.S_IMODE(info.st_mode),type=stat.S_IFMT(info.st_mode),
                dev=info.st_dev,inode=info.st_ino,links=info.st_nlink,
                uid=info.st_uid,gid=info.st_gid,bytes=info.st_size,
                mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
            if stat.S_ISLNK(info.st_mode):row["target"]=os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();h=digest(raw);where=cas/(h+".zlib")
                if not where.exists():where.write_bytes(zlib.compress(raw,6))
                assert zlib.decompress(where.read_bytes())==raw
                row["data"]=dict(bytes=len(raw),sha256=h,path="cas/"+where.name,compression="zlib")
            rows.append(row)
    save(out/"filesystem-after-process.json",rows)
    checked=0
    for path in sorted(cas.glob("*.zlib")):
        raw=zlib.decompress(path.read_bytes());assert path.stem==digest(raw);checked+=1
    return dict(status="ALL_FINAL_FILESYSTEM_OBJECTS_PRESERVED",objects=len(rows),cas_readback=checked)
def main():
    common=module("publication_ci_common",Path(os.environ["HIA_CI_COMMON"]).resolve())
    context=None;mine=None;project=None;status="FAIL";details={
        "scope":"new-verified-publication-transaction-component",
        "old_967_cases_repeated":False,"old_193_entry_calls_repeated":False,
        "whole_cli_closed":False,"native_path_and_staging_closed":False,
        "actual_fixed_publication_carrier":False,"raw_os_error_text_closed":False}
    try:
        context=common.prepare()
        mine=Path(context["base"])/"cli-publication-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-publication-next";project.mkdir(parents=True)
        rows=[]
        def exact_copy(src,dest,pin):
            src=src.resolve();raw=src.read_bytes()
            assert digest(raw)==pin["sha256"] and len(raw)==pin["bytes"],(src,pin)
            common.PINS[src]=raw
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as output:output.write(raw)
            dest.chmod(0o644);assert dest.read_bytes()==raw
            rows.append(dict(original=str(src),copy=str(dest),**pin))
        for relative,pin in FILES.items():exact_copy(DELIVERY/relative,project/relative,pin)
        source=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
        exact_copy(source,project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
            dict(bytes=23950,sha256="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"))
        rows.append(dict(driver=str(Path(__file__).resolve()),bytes=Path(__file__).stat().st_size,
            sha256=digest(Path(__file__).read_bytes())))
        common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
        save(mine/"records/materialization.json",rows)
        raw=project/"development/actual-r1"
        frozen=Path(context["workspace"])/"native-edit-candidate-next/development/build-r1/source"
        run_error=None
        try:
            common.run("verified-publication-actual-r1",[
                context["python"],"-B",project/"tests/test_hia_cli_verified_publication.py",
                "--source",context["source"],"--reference",context["reference"],
                "--compiler",context["compiler"],"--sha-source",frozen/"135/source.hiaasm",
                "--sha-image",frozen/"136/word-unrolled.image.bin","--out",raw],
                cwd=project,timeout=300,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["source"]))
        except BaseException as error:
            run_error=error
            raise
        finally:
            # Covers a test process killed before its own finally, without
            # rerunning any HIA or changing the observed physical filesystem.
            try:
                observed=freeze_filesystem(project/"development/publication-filesystem-fixtures",raw)
                details["physical_fixture_preservation"]=observed
            except BaseException as preserve_error:
                details["preservation_failure"]=traceback.format_exc()
                if run_error is not None:run_error.add_note("Filesystem preservation also failed: "+repr(preserve_error))
                else:raise
        summary=json.loads((raw/"summary.json").read_bytes())
        assert summary["status"]=="PASS" and summary["source_pins_unchanged"]
        assert summary["cases"]==29 and summary["private_controls"]==11
        assert summary["native_publication_entries"]>0 and summary["native_hash_entries"]>0
        assert summary["actual_filesystem_syscalls"]>0 and summary["cas_readback"]["status"]=="PASS"
        details["actual"]=summary;status="PASS"
    except BaseException as error:
        details.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        if project is not None:
            path=project/"development/actual-r1/summary.json"
            if path.exists():details["actual"]=json.loads(path.read_bytes())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None:
            choices={"publication-tools":project/"tools","publication-tests":project/"tests",
                "publication-docs":project/"docs","publication-raw":project/"development/actual-r1",
                "publication-dependency":project.parent/"Hepta-agent-edit-native",
                "publication-records":mine/"records"}
            roots={label:path for label,path in choices.items() if path.is_dir()}
        common.finish("cli-verified-publication-native-r1",status,details,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
