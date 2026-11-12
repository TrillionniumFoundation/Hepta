"""New actual complete public assembly CLI and exact publication composition."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,stat,sys,traceback,zlib
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
FILES=[
  {
    "path": "tools/assembly_service_control.py",
    "gitsha": "a1dd3d84ce16b7038cd28badefee00c4f714e75a",
    "bytes": 32542,
    "sha256": "2f7c3c02507b0dadb268618b204e1e8e0dbceda5fc7ced0f44bb48abb07893fe"
  },
  {
    "path": "tools/generate_hia_assembly_service.py",
    "gitsha": "57c7c8f9c5d006b20e57b4e239b16d328d649a6f",
    "bytes": 11510,
    "sha256": "2ff23251e65f46061abb329f09868855116de524ccd6a7f47458ab202e488914"
  },
  {
    "path": "tools/compose_cli_assembly_carrier.py",
    "gitsha": "e6cd8a84ccf39584b8934021bc11e946297332e4",
    "bytes": 4717,
    "sha256": "389ac96131a8e93bb11862fdf3b0e8c84cb416117dbf3e3e85def660a2e201ee",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tools/cli_publication_tempdir_owner.py",
    "gitsha": "64ebbf57364b46127d4579f836c701025821fa4f",
    "bytes": 12869,
    "sha256": "748b144ee9eb040e0cd7629248ebe27cc37d7fcf68eceaa6a9a85ba9a43071f1",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tools/cli_publication_presentation_owner.py",
    "gitsha": "258f415c0a98d461b269b61d573d20ddc2afb5dc",
    "bytes": 17103,
    "sha256": "16540795eb2ed5e004d6b01113c21cfcbd2a2e5552c4c24817521f2d45e6dc8f",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tools/cli_publication_parent_owner.py",
    "gitsha": "909e00b3c8e7f7fa0f50aa8374bba272c306c484",
    "bytes": 2697,
    "sha256": "000c23604104df0b31f5bb0d8977aadf7da9ec572dc66b023263a5fa994cd2ab",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tools/build_hia_assembly_cli.py",
    "gitsha": "04c2fd62a6764cc205eb255546a334e6a28daf17",
    "bytes": 13129,
    "sha256": "a4028086ee9f9d05307d2257b1b73fb386cb94d21d845e95863f386839008a67",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tests/test_hia_full_assembly_cli.py",
    "gitsha": "9f4f6f62a1a4fd5a07b0c4b43e6e8b8b35afcb3d",
    "bytes": 22677,
    "sha256": "328e9b270897a7712729bf9aa2a44a4473d401576ea0865f2abb465fe005ecf7",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "development/read_inactive_E_components.py",
    "gitsha": "a858717eada7f3b655bbcc985604bb99a8f3bade",
    "bytes": 8002,
    "sha256": "eea45838986247b1b06a5bdb104f1ba6f32ceadaa08e18582f2d2df368e8247e",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "docs/HIA_COMPLETE_ASSEMBLY_CLI_R1.md",
    "gitsha": "1302268c008f0a92a8b4b614496335a12d08acb2",
    "bytes": 9572,
    "sha256": "b86c492c3e9ab617bbf651de719c4938e66f88b0aba6db214e4fc0c2dc37e9b8",
    "scope": "NEW_AUTHORING_UNEXECUTED"
  },
  {
    "path": "tools/program_service_root_reference.py",
    "gitsha": "e572e1273fcd55518f7395071cc56534f2771fc6",
    "bytes": 33675,
    "sha256": "f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tools/cli_publication_parent_reference.py",
    "gitsha": "31def95cfac9f8823e540411da8ee82c81a21ef0",
    "bytes": 39683,
    "sha256": "65ade06a5a5650120ec3c192e452f31db15dbbd0751c367040bb874d3d8af44c",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tools/assembly_object_prefix.py",
    "gitsha": "90d7242bdc2ab328280b2c760f988cff3ad21d10",
    "bytes": 14115,
    "sha256": "e230b246ed2a410cc3a8f252525cff065b340606ba7cb168f70655bb02da7d4a",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "resources/inactive-E-role-map.json",
    "gitsha": "35202c1c5961923b60f6100e07fa696e2c8f84a0",
    "bytes": 115895,
    "sha256": "a942f616655aeec0f047d66ed7ee6be83fa3a960d65a635bc4c849e29cf6f5df",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tools/assembly_syntax_owner.py",
    "gitsha": "227e06a56e8da7091d72004c83daeea7d24ee884",
    "bytes": 37844,
    "sha256": "365d8460c6d502685815ad0039e0d5de5503326abf58db13cd922605d097d11e",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tools/assembly_render_owner.py",
    "gitsha": "030f921e725eaa1bc798f884f9801848e95c6f34",
    "bytes": 29652,
    "sha256": "8eaaf5a0b209f8a9e8a573fe2943912e45116414747ab6eef6c97b55384518d5",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tests/assembly_syntax_corpus_reference.py",
    "gitsha": "2f1ac120dc468c5f9a525c2f46313b3bd68ef460",
    "bytes": 25849,
    "sha256": "37ef03b33d0b37eebc3eb549324634bd948f5656900a9487fcab816ffce40694",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
  },
  {
    "path": "tests/assembly_render_corpus_reference.py",
    "gitsha": "8f72ce79164f1bb872e862554b15856bbfec1697",
    "bytes": 24951,
    "sha256": "7a66531cebba00eee7180494c9e784b2ee37fd6da770ae38528024b08eb51b2d",
    "scope": "EXACT_RETAINED_SOURCE_ALIAS_NO_RESULT_INHERITANCE"
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
    "cli-temporary-directory-r2/tools/cli_publication_cleanup_owner.py",
    "776161521c424afc2908cb9c667e7ec7d7bad4e3",
    "tools/cli_publication_cleanup_owner.py"
  ],
  [
    "cli-fixed-publication-r1/tools/compose_cli_publication_filesystem.py",
    "171b5c6983303a11836f5b6c2bf674b9ee6cd6f5",
    "tools/compose_cli_publication_filesystem_r2.py"
  ],
  [
    "cli-full-publication-r1/tools/compose_cli_publication_filesystem_r3.py",
    "2fb867b4df3bfedcd4ab6aa7adf5815378c960a0",
    "tools/compose_cli_publication_filesystem_r3.py"
  ],
  [
    "cli-full-publication-r1/tools/generate_hia_cli_publication_packer_r3.py",
    "15a46334a1fb9c3b4bb2886e5231540d3440a62e",
    "tools/generate_hia_cli_publication_packer_r3.py"
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
        for at in range(0,len(raw),18000):
            part=raw[at:at+18000]
            print("HIA_ASSEMBLY_CLI_ORIGINAL_STDERR "+json.dumps(dict(
                path=str(path.relative_to(out)),bytes=len(raw),sha256=digest(raw),offset=at,
                part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    for path in sorted(out.rglob("profile.json")):
        print("HIA_ASSEMBLY_CLI_PROFILE "+json.dumps(dict(path=str(path.relative_to(out)),
            value=json.loads(path.read_bytes())),sort_keys=True),flush=True)
    for path in sorted(out.rglob("summary.json")):
        value=json.loads(path.read_bytes())
        print("HIA_ASSEMBLY_CLI_SUMMARY "+json.dumps(dict(path=str(path.relative_to(out)),
            value={k:v for k,v in value.items() if k!="cases"}),sort_keys=True),flush=True)

def main():
    path=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=path.read_bytes()
    assert git_blob(raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
    spec=importlib.util.spec_from_file_location("complete_assembly_common_r1",path)
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.PINS[path]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
    mine=project=raw_out=None;status="FAIL"
    detail=dict(scope="NEW_PUBLIC_ASSEMBLY_SYNTAX_OBJECT_CORE_RENDER_PUBLICATION_CHAIN",
        old_counts_inherited=False,old_completed_suites_rerun=False,whole_CLI_closed=False,
        inactive_table2_E_qualified=False,installed_activated=False,cold_qualified=False,
        reference_version="3.12.14",new_image_capacity=140,new_nonzero_images=139)
    try:
        c=common.prepare();mine=Path(c["base"])/"cli-assembly-service-recovery-r1";mine.mkdir()
        project=mine/"workspace/native-cli-assembly-next";project.mkdir(parents=True)
        materialized=[]
        for row in FILES:
            target=common.materialize(R3+"cli-assembly-service-r1/"+row["path"],row["gitsha"],project/row["path"])
            raw=target.read_bytes();assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
            materialized.append(row)
        for source,blob,target in DEPS:
            destination=common.materialize(R3+source,blob,project/target);raw=destination.read_bytes()
            materialized.append(dict(source=source,gitsha=blob,path=target,bytes=len(raw),sha256=digest(raw)))
        frozen=Path(c["workspace"])/"native-edit-json-next/development/main-compile-r3/source"
        for source,target,size,expected in (
            (frozen/"6/hia_agent_edit_source_views.py",
             project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",23950,
             "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"),
            (frozen/"8/hia_composite_lowering_driver_common.py",
             project.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",17781,
             "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")):
            raw=source.read_bytes();assert (len(raw),digest(raw))==(size,expected)
            common.PINS[source.resolve()]=raw;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as f:f.write(raw)
            assert target.read_bytes()==raw
            materialized.append(dict(source=str(source),target=str(target),bytes=len(raw),sha256=digest(raw)))
        save(mine/"materialization.json",materialized)
        common.run("read-complete-original-CLI-and-A-assets",[
            c["python"],"-B",project/"development/read_public_cli_a_assets_r1.py",
            "--download-dir",os.environ["HIA_PUBLIC_A_DOWNLOAD_DIR"],"--out",mine/"assets"],timeout=300)
        inactive=mine/"inactive-E"
        common.run("read-complete-inactive-E63-exact-candidate-originals",[
            c["python"],"-B",project/"development/read_inactive_E_components.py",
            "--download-dir",os.environ["HIA_ASSEMBLY_CANDIDATE_DOWNLOAD_DIR"],
            "--manifest",project/"resources/inactive-E-role-map.json",
            "--workspace",c["workspace"],"--out",inactive],timeout=180)
        source=Path(c["workspace"])/"native-edit-candidate-next/development/build-r1/source"
        raw_out=project/"development/full-assembly-r1"
        try:
            common.run("new-complete-native-assembly-three-actions",[
                c["python"],"-B",project/"tests/test_hia_full_assembly_cli.py",
                "--assets",mine/"assets/assets.json","--reference",c["reference"],
                "--inactive-map",project/"resources/inactive-E-role-map.json",
                "--inactive-dir",inactive/"roles",
                "--sha-source",source/"135/source.hiaasm","--sha-image",source/"136/word-unrolled.image.bin",
                "--out",raw_out],cwd=project,timeout=900,env=dict(PYTHONDONTWRITEBYTECODE="1",
                    PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+c["reference"],
                    LANG="C.UTF-8",LC_ALL="C.UTF-8"))
        finally:
            if raw_out.exists():
                show_failures(raw_out)
                detail["physical_preservation"]=preserve_physical(raw_out/"physical",raw_out)
                if (raw_out/"summary.json").exists():detail["actual"]=json.loads((raw_out/"summary.json").read_bytes())
        actual=detail["actual"]
        assert actual["status"]=="PASS" and actual["custody"]["status"]=="PASS"
        assert actual["custody"]["source_pins_unchanged"]
        assert actual["public_cases"]==actual["expected_public_cases"]==actual["native_processes"]==actual["reference_processes"]
        assert actual["public_cases"]>500 and actual["expected_syntax_sources"]>80
        assert actual["private_controls"]==29 and actual["private_native_entries"]==61
        assert actual["actual_packer_entries"]==1 and actual["actual_new_B3_compilations"]==13
        for key in ("full_syntax_object_prefix_primitive_chain","actual_complete_render_roundtrip",
                    "canonical_roundtrip_compared_all_bytes","policy1_and_policy3_actual_publication",
                    "all_public_outputs_and_files_equal","table2_all_63_images_unchanged"):
            assert actual[key],key
        assert actual["inactive_E_executions"]==0 and not actual["inactive_E_qualified"]
        assert not actual["whole_CLI_closed"] and not actual["installed_activated"] and not actual["cold_qualified"]
        status="PASS"
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        roots={}
        if mine is not None:
            for name in("materialization.json","assets","inactive-E"):
                if (mine/name).exists():roots["assembly-"+name.replace(".","-")]=mine/name
        if project is not None:
            for name in("tools","tests","docs","resources"):
                if (project/name).exists():roots["assembly-"+name]=project/name
            for name in("Hepta-agent-edit-native","native-composite-driver-reconstructed"):
                p=project.parent/name
                if p.exists():roots["assembly-helper-"+name]=p
        if raw_out is not None and raw_out.exists():
            for number,path in enumerate(sorted(raw_out.iterdir())):
                if path.name!="physical":roots["assembly-raw-"+str(number).zfill(3)]=path
        common.finish("cli-complete-public-assembly-r1",status,detail,roots=roots)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
