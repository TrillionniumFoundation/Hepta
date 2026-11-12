"""New complete native CLI publication join; no historical suite reruns."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,stat,sys,traceback,zlib
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/cli_publication_parent_owner.py",
    "gitsha": "31def95cfac9f8823e540411da8ee82c81a21ef0",
    "bytes": 39683,
    "sha256": "65ade06a5a5650120ec3c192e452f31db15dbbd0751c367040bb874d3d8af44c"
  },
  {
    "path": "tools/cli_publication_presentation_owner.py",
    "gitsha": "a827a9e70936c063bad3bc96c250b752197c8888",
    "bytes": 16836,
    "sha256": "76d89a33b8e09f3e58a70c13f44c73a165943a1c6ca34a369ac25b1d918dea98"
  },
  {
    "path": "tools/cli_publication_policy2_fixture.py",
    "gitsha": "b36c40dd918476c15c13b01506459c6d7bf5991c",
    "bytes": 5711,
    "sha256": "8722a23cb468a378e02759092be94d4c4da334289c07af15e251702f965ffdf7"
  },
  {
    "path": "tools/compose_cli_publication_filesystem_r3.py",
    "gitsha": "2fb867b4df3bfedcd4ab6aa7adf5815378c960a0",
    "bytes": 3234,
    "sha256": "a152dc2ef86e77263ffc6c1222888d4de0e6bab2ba5907774f2e951d9cedda6b"
  },
  {
    "path": "tools/generate_hia_cli_publication_packer_r3.py",
    "gitsha": "15a46334a1fb9c3b4bb2886e5231540d3440a62e",
    "bytes": 6715,
    "sha256": "d2f9900eb6dc180c7d6227b915e49d09a2751e06702b5a7ce586640fb0735bff"
  },
  {
    "path": "tests/test_hia_cli_full_publication.py",
    "gitsha": "64c2efb95524d3317c47c662cba80a2039637aa3",
    "bytes": 34987,
    "sha256": "0aa9653c66427105f273ee45b66033b0ac5a191227bf395bfd22fe1c5758f6e9"
  },
  {
    "path": "docs/HIA_CLI_FULL_PUBLICATION_PARENT_R1.md",
    "gitsha": "9fd94bd412d95e57d90d0ce901a4618da4363c0d",
    "bytes": 9681,
    "sha256": "8b4faabae3ab10ec75aabe77809ac9c833645afd7546a19bdcd02b4005df20a8"
  }
]
DEPS=[
  [
    "cli-public-A-r1/development/read_public_cli_a_assets_r1.py",
    "a21895ee8721432db9b0ec6945025c6bd19087f1",
    "development/read_public_cli_a_assets_r1.py"
  ],
  [
    "cli-public-A-r1/tools/cli_business_parent.py",
    "6722984f4fe4a2e5c77c06dec018caa8041927c4",
    "tools/cli_business_parent.py"
  ],
  [
    "cli/tools/cli_entry_owner.py",
    "3fa7143528736548118cb47801ed44102f03cee8",
    "tools/cli_entry_owner.py"
  ],
  [
    "cli/tools/cli_authoring.py",
    "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "tools/cli_authoring.py"
  ],
  [
    "cli-publication-r1/tools/cli_publication_verified_owner.py",
    "c9d9861c96c23e36ad996035f4f21f2f8147f9cb",
    "tools/cli_publication_verified_owner.py"
  ],
  [
    "cli-publication-path-r1/tools/cli_publication_path_owner.py",
    "8e56c87651b18e3f9b3191440062d61975517254",
    "tools/cli_publication_path_owner.py"
  ],
  [
    "cli-publication-stage-writer-r1/tools/cli_publication_stage_writer.py",
    "d6290f082405b44ec749f4ad33477ffc97187189",
    "tools/cli_publication_stage_writer.py"
  ],
  [
    "cli-temporary-directory-r1/tools/cli_publication_tempdir_owner.py",
    "430993d9dfac2a689269c12131e029afa5df9b1b",
    "tools/cli_publication_tempdir_owner.py"
  ],
  [
    "cli-temporary-directory-r2/tools/cli_publication_cleanup_owner.py",
    "29db0cf5cca88719117111a6401fdbd4f38c8669",
    "tools/cli_publication_cleanup_owner.py"
  ],
  [
    "cli-fixed-publication-r1/tools/compose_cli_publication_filesystem.py",
    "171b5c6983303a11836f5b6c2bf674b9ee6cd6f5",
    "tools/compose_cli_publication_filesystem_r2.py"
  ],
  [
    "cli-finite-carrier-r1/tools/cli_business_fixture_owners.py",
    "ef2f1d5c5334b9adab6461e893c381f97c0529d4",
    "tools/cli_business_fixture_owners.py"
  ]
]
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
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

def show_failures(out):
    for path in sorted(out.rglob("*.stderr")):
        raw=path.read_bytes()
        if not raw:continue
        for at in range(0,len(raw),18000):
            part=raw[at:at+18000]
            print("HIA_FULL_PUBLICATION_STDERR "+json.dumps(dict(path=str(path.relative_to(out)),
                bytes=len(raw),sha256=digest(raw),offset=at,part_bytes=len(part),
                base64=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
    for path in sorted(out.rglob("profile.json")):
        print("HIA_FULL_PUBLICATION_PROFILE "+json.dumps(dict(path=str(path.relative_to(out)),
            profile=json.loads(path.read_bytes())),sort_keys=True),flush=True)
def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("full_publication_common_r2",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    context=mine=project=raw_out=None;status="FAIL"
    detail=dict(scope="NEW_140_ENTRY_PUBLICATION_PARENT_REAL_A_PRIVATE_POLICY2",
        old_suites_rerun=False,historical_counts_inherited=False,whole_cli_closed=False,
        cleanup_revision="R2_BODY_DELIMITER_REPAIR",original_cleanup_failure_run=43132319705,
        installed_entry_activated=False,ordinary_E_semantics_qualified=False,
        planned_new_exact_public_A_cases=44,planned_private_policy2_cases=11,
        planned_presentation_cases=207,planned_private_presentation_controls=14)
    try:
        context=common.prepare();base=Path(context["base"])
        mine=base/"cli-full-publication-recovery-r2";mine.mkdir()
        project=mine/"workspace/native-cli-full-publication-next";project.mkdir(parents=True)
        materialized=[]
        for row in FILES:
            target=common.materialize(R3+"cli-full-publication-r1/"+row["path"],row["gitsha"],project/row["path"])
            data=target.read_bytes()
            assert (len(data),digest(data))==(row["bytes"],row["sha256"])
            materialized.append(dict(row,source="NEW_CURRENT_REVISION"))
        for source,blob,target in DEPS:
            target=common.materialize(R3+source,blob,project/target);data=target.read_bytes()
            materialized.append(dict(source=source,path=str(target.relative_to(project)),gitsha=blob,
                bytes=len(data),sha256=digest(data),source_scope="EXACT_RETAINED_AUTHORING"))
        frozen=Path(context["workspace"])/"native-edit-json-next/development/main-compile-r3/source"
        for source,target,size,expected in (
            (frozen/"6/hia_agent_edit_source_views.py",
             project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",23950,
             "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"),
            (frozen/"8/hia_composite_lowering_driver_common.py",
             project.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",17781,
             "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")):
            data=source.read_bytes();assert (len(data),digest(data))==(size,expected)
            common.PINS[source.resolve()]=data;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as stream:stream.write(data)
            assert target.read_bytes()==data
            materialized.append(dict(source=str(source),copy=str(target),bytes=size,sha256=expected))
        save(mine/"materialization.json",materialized)
        common.run("read-exact-cli-and-A-publication-assets",[
            context["python"],"-B",project/"development/read_public_cli_a_assets_r1.py",
            "--download-dir",os.environ["HIA_PUBLIC_A_DOWNLOAD_DIR"],"--out",mine/"assets"],timeout=300)
        old=Path(context["workspace"])/"native-edit-candidate-next/development/build-r1/source"
        sha_source=old/"135/source.hiaasm";sha_image=old/"136/word-unrolled.image.bin"
        for source,size,expected in (
            (sha_source,33683,"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a"),
            (sha_image,38349,"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274")):
            data=source.read_bytes();assert (len(data),digest(data))==(size,expected)
            common.PINS[source.resolve()]=data
        raw_out=project/"development/actual-full-publication-r2"
        try:
            common.run("new-real-native-full-publication",[
                context["python"],"-B",project/"tests/test_hia_cli_full_publication.py",
                "--assets",mine/"assets/assets.json","--reference",context["reference"],
                "--sha-source",sha_source,"--sha-image",sha_image,"--out",raw_out],
                cwd=project,timeout=900,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"],
                    LANG="C.UTF-8",LC_ALL="C.UTF-8"))
        finally:
            if raw_out.exists():
                show_failures(raw_out)
                detail["physical_preservation"]=preserve_physical(raw_out/"physical",raw_out)
                if (raw_out/"summary.json").exists():
                    actual=json.loads((raw_out/"summary.json").read_bytes());detail["actual"]=actual
                    print("HIA_FULL_PUBLICATION_ATTEMPT_ORIGINAL "+json.dumps(
                        {k:v for k,v in actual.items() if k!="cases"},sort_keys=True),flush=True)
        actual=detail["actual"]
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
        assert actual["cas_readback"]["status"]=="PASS" and actual["public_parent_publication_executed"]
        assert tuple(actual[k] for k in(
            "exact_public_A_publication_cases","private_policy2_publication_cases",
            "native_processes","reference_processes","actual_packer_entries",
            "new_B3_compilations","presentation_cases","presentation_private_controls"))==(44,11,55,55,1,9,207,14)
        assert actual["complete_stdout_stderr_exit_equal"] and actual["complete_filesystem_semantic_snapshot_equal"]
        assert actual["real_A_service_bound"] and actual["public_argv_and_file_owner"]
        assert not actual["ordinary_E_semantics_qualified"] and not actual["old_cases_inherited"]
        assert not actual["whole_cli_closed"] and not actual["installed_entry_activated"]
        status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if mine is not None:
            for name in("materialization.json","assets"):
                if (mine/name).exists():roots["publication-"+name.replace(".","-")]=mine/name
        if project is not None:
            for label,p in(("tools",project/"tools"),("tests",project/"tests"),("docs",project/"docs"),
                ("helper",project.parent/"Hepta-agent-edit-native"),
                ("common",project.parent/"native-composite-driver-reconstructed")):
                if p.exists():roots["publication-"+label]=p
        if raw_out is not None and raw_out.exists():
            for i,p in enumerate(sorted(raw_out.iterdir())):
                if p.name!="physical":roots["publication-raw-"+str(i).zfill(3)]=p
        common.finish("cli-full-native-publication-r2",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
