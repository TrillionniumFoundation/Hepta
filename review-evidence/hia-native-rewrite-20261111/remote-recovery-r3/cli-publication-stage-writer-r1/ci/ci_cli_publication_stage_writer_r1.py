"""Fresh HIA staging writer qualification; no old suites are executed."""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,stat,sys,traceback,zlib
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/cli_publication_stage_writer.py",
    "gitsha": "d6290f082405b44ec749f4ad33477ffc97187189",
    "bytes": 10255,
    "sha256": "072765abc369ebd933f708a5b5086de7a24e9e0876b9d98ccfd6022fef010732"
  },
  {
    "path": "tests/test_hia_cli_publication_stage_writer.py",
    "gitsha": "bf4e0e9fe10863253ca9b6955579f52a9b573a1a",
    "bytes": 15770,
    "sha256": "54fb54775f903a8b8092564ca98809715849fc73e24282ed59c2b775952c773a"
  },
  {
    "path": "docs/HIA_CLI_PUBLICATION_STAGE_WRITER.md",
    "gitsha": "cfac3b04015cb12510a254c3747d3f38bfc52dd8",
    "bytes": 4987,
    "sha256": "459eaeda736c969fd7490dbe6ec04656c71ad6f0b9dcf8c1a7fb0107c60d6182"
  }
]
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def preserved_physical(root,out):
    if not root.exists():return dict(status="NO_PHYSICAL_FIXTURES")
    rows=[];paths=[root]
    for folder,dirs,files in os.walk(root,followlinks=False):
        paths.extend(Path(folder)/name for name in sorted(dirs+files))
    for path in paths:
        before=path.lstat()
        row=dict(path=os.fsencode(os.path.relpath(path,root)).hex(),path_encoding="filesystem-bytes-hex",
                 mode=stat.S_IMODE(before.st_mode),type=stat.S_IFMT(before.st_mode),
                 bytes=before.st_size,dev=before.st_dev,inode=before.st_ino,nlink=before.st_nlink,
                 mtime_ns=before.st_mtime_ns,ctime_ns=before.st_ctime_ns)
        if stat.S_ISLNK(before.st_mode):row["symlink_target_hex"]=os.fsencode(os.readlink(path)).hex()
        elif stat.S_ISREG(before.st_mode):
            raw=path.read_bytes();h=digest(raw);dest=out/"cas"/(h+".zlib")
            dest.parent.mkdir(parents=True,exist_ok=True)
            if not dest.exists():dest.write_bytes(zlib.compress(raw,6))
            assert zlib.decompress(dest.read_bytes())==raw
            after=path.lstat()
            assert (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==(
                before.st_dev,before.st_ino,len(raw),before.st_mtime_ns)
            row["data"]=dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
        else:assert stat.S_ISDIR(before.st_mode)
        rows.append(row)
    save(out/"physical-fixture-objects.json",rows)
    return dict(status="COMPLETE_PHYSICAL_MANIFEST_AND_FILE_BYTES",objects=len(rows),
        symlinks_not_followed=True,physical_source_not_deleted=True)
def main():
    cp=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=cp.read_bytes()
    assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("stage_writer_common",cp)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[cp]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    context=project=mine=raw_out=None;status="FAIL"
    details=dict(scope="NEW_NATIVE_STAGE_WRITER",old_suites_rerun=False,
        whole_cli_publication_closed=False,tempdir_cleanup_closed=False,
        scripted_outcomes_are_physical_authority=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"cli-stage-writer-recovery";mine.mkdir()
        project=mine/"workspace/native-cli-stage-writer-next";project.mkdir(parents=True)
        for row in FILES:
            p=common.materialize(R3+"cli-publication-stage-writer-r1/"+row["path"],row["gitsha"],project/row["path"])
            data=p.read_bytes();assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        common.materialize(R3+"cli/tools/cli_authoring.py","6f1bffe8bd815a068f9834489960006cbaad6fac",
                           project/"tools/cli_authoring.py")
        helper=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
        data=helper.read_bytes();assert (len(data),digest(data))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
        common.PINS[helper.resolve()]=data
        target=project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py";target.parent.mkdir(parents=True)
        target.write_bytes(data);assert target.read_bytes()==data
        raw_out=project/"development/actual-r1"
        try:
            common.run("native-staging-writer-r1",[
                context["python"],"-B",project/"tests/test_hia_cli_publication_stage_writer.py",
                "--source",context["reference"],"--compiler",context["compiler"],"--out",raw_out],
                cwd=project,timeout=300,env=dict(PYTHONDONTWRITEBYTECODE="1",
                PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"]))
        finally:
            if raw_out.exists():
                details["physical_preservation"]=preserved_physical(raw_out/"physical",raw_out)
                summary=raw_out/"summary.json"
                if summary.exists():
                    details["actual"]=json.loads(summary.read_bytes())
                    print("HIA_STAGE_WRITER_ATTEMPT_ORIGINAL "+summary.read_text(),flush=True)
        actual=details["actual"]
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"] and actual["cas_readback"]["status"]=="PASS"
        assert (actual["scripted_cases"],actual["physical_cases"],actual["private_controls"])==(192,11,10)
        assert actual["native_entries"]>0
        status="PASS"
    except BaseException as error:
        details.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None:
            for label,path in (("stage-writer-tools",project/"tools"),("stage-writer-tests",project/"tests"),
                               ("stage-writer-docs",project/"docs"),("stage-writer-helper",project.parent/"Hepta-agent-edit-native")):
                if path.exists():roots[label]=path
        if raw_out is not None and raw_out.exists():
            # Exact physical objects are represented by the complete lstat/name/
            # symlink-target/content manifest. Live symlinks never enter the tar.
            for i,path in enumerate(sorted(raw_out.iterdir())):
                if path.name!="physical":roots["stage-writer-raw-"+str(i).zfill(3)]=path
        common.finish("cli-publication-stage-writer-r1",status,details,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
