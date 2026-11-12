"""New native TemporaryDirectory creation/cleanup CI; original suites stay frozen."""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,stat,sys,traceback,zlib
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/cli_publication_tempdir_owner.py",
    "gitsha": "430993d9dfac2a689269c12131e029afa5df9b1b",
    "bytes": 11488,
    "sha256": "decfb68f7965af1607f32c47c0000997e57dbbef0b9adce14c05e1746c3f5275"
  },
  {
    "path": "tools/cli_publication_cleanup_owner.py",
    "gitsha": "776161521c424afc2908cb9c667e7ec7d7bad4e3",
    "bytes": 28738,
    "sha256": "cf8a3f9b73c1dc1c18f0309fe311935856a73932fd4a7a57fe92e0bd512dd4e4"
  },
  {
    "path": "tests/test_hia_cli_temporary_directory.py",
    "gitsha": "f5a4055525c584f5e47e218a8be529f76c580341",
    "bytes": 26711,
    "sha256": "d5cb5e257b8d129383df1c7aa956f06ddb990de74d3ae6af29b67c4eabe86239"
  },
  {
    "path": "docs/HIA_CLI_TEMPORARY_DIRECTORY.md",
    "gitsha": "7e585883b96f885b696f9b47d1cdf953b8326f4b",
    "bytes": 8949,
    "sha256": "ae3cc8c31b73da36894ab9e660688427b8d22e3110c928f77f84c26f7fed48bb"
  }
]
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def preserve_physical(root,out):
    if not root.exists():return dict(status="NO_PHYSICAL_FIXTURES")
    paths=[root];errors=[];rows=[]
    def error(e):errors.append(dict(type=type(e).__name__,errno=e.errno,filename=None if e.filename is None else os.fsencode(e.filename).hex()))
    for folder,dirs,files in os.walk(root,followlinks=False,onerror=error):
        paths.extend(Path(folder)/name for name in sorted(dirs+files))
    for path in paths:
        st=path.lstat()
        row=dict(path=os.fsencode(os.path.relpath(path,root)).hex(),path_encoding="filesystem-bytes-hex",
                 mode=stat.S_IMODE(st.st_mode),type=stat.S_IFMT(st.st_mode),bytes=st.st_size,
                 dev=st.st_dev,inode=st.st_ino,nlink=st.st_nlink,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)
        if stat.S_ISLNK(st.st_mode):row["symlink_target_hex"]=os.fsencode(os.readlink(path)).hex()
        elif stat.S_ISREG(st.st_mode):
            try:raw=path.read_bytes()
            except OSError as e:
                row["read_error"]=dict(type=type(e).__name__,errno=e.errno)
            else:
                h=digest(raw);dest=out/"cas"/(h+".zlib");dest.parent.mkdir(exist_ok=True)
                if not dest.exists():dest.write_bytes(zlib.compress(raw,6))
                assert zlib.decompress(dest.read_bytes())==raw
                after=path.lstat();assert (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==(st.st_dev,st.st_ino,len(raw),st.st_mtime_ns)
                row["data"]=dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
        rows.append(row)
    save(out/"physical-fixture-objects.json",dict(objects=rows,enumeration_errors=errors))
    return dict(status="OBSERVED_PHYSICAL_MANIFEST_AND_REGULAR_FILE_BYTES",objects=len(rows),
                enumeration_errors=len(errors),symlinks_not_followed=True,physical_sources_not_deleted=True,
                pre_permission_change_inputs_preserved_separately=True)
def main():
    cp=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=cp.read_bytes()
    assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("temporary_directory_common_r2",cp)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[cp]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    project=raw_out=None;status="FAIL"
    details=dict(scope="NEW_NATIVE_TEMPDIR_COMPONENTS_R2_BODY_DELIMITER_REPAIR",old_suites_rerun=False,
                 original_failure_run=43132319705,original_failure_native_entries=0,
                 complete_fixed_parent_publication_closed=False,public_error_formatter_closed=False,
                 scripted_receipts_are_physical_authority=False)
    try:
        context=common.prepare()
        mine=Path(context["base"])/"cli-temporary-directory-recovery-r2";mine.mkdir()
        project=mine/"workspace/native-cli-temporary-directory-next";project.mkdir(parents=True)
        for row in FILES:
            prefix="cli-temporary-directory-r2/" if row["path"]=="tools/cli_publication_cleanup_owner.py" else "cli-temporary-directory-r1/"
            p=common.materialize(R3+prefix+row["path"],row["gitsha"],project/row["path"])
            data=p.read_bytes();assert (len(data),digest(data))==(row["bytes"],row["sha256"])
        common.materialize(R3+"cli/tools/cli_authoring.py","6f1bffe8bd815a068f9834489960006cbaad6fac",project/"tools/cli_authoring.py")
        helper=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
        data=helper.read_bytes()
        assert (len(data),digest(data))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
        common.PINS[helper.resolve()]=data
        target=project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py";target.parent.mkdir(parents=True)
        target.write_bytes(data);assert target.read_bytes()==data
        raw_out=project/"development/actual-r2"
        try:
            common.run("native-temporary-directory-r2",[
                context["python"],"-B",project/"tests/test_hia_cli_temporary_directory.py",
                "--source",context["reference"],"--compiler",context["compiler"],"--out",raw_out],
                cwd=project,timeout=300,env=dict(PYTHONDONTWRITEBYTECODE="1",
                PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"]))
        finally:
            if raw_out.exists():
                details["physical_preservation"]=preserve_physical(raw_out/"physical",raw_out)
                summary=raw_out/"summary.json"
                if summary.exists():
                    details["actual"]=json.loads(summary.read_bytes())
                    print("HIA_TEMPORARY_DIRECTORY_ATTEMPT_ORIGINAL "+summary.read_text(),flush=True)
        actual=details["actual"]
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"] and actual["cas_readback"]["status"]=="PASS"
        assert tuple(actual[k] for k in("physical_creation_cases","actual_entropy_cases","physical_cleanup_cases","private_protocol_controls","extra_control_cases"))==(12,2,18,21,3)
        assert actual["native_entries"]>0 and actual["actual_syscalls"]>0
        status="PASS"
    except BaseException as error:
        details.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if project is not None:
            for label,path in(("temporary-tools",project/"tools"),("temporary-tests",project/"tests"),
                               ("temporary-docs",project/"docs"),("temporary-helper",project.parent/"Hepta-agent-edit-native")):
                if path.exists():roots[label]=path
        if raw_out is not None and raw_out.exists():
            for i,path in enumerate(sorted(raw_out.iterdir())):
                if path.name!="physical":roots["temporary-raw-"+str(i).zfill(3)]=path
        common.finish("cli-temporary-directory-native-r2",status,details,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
