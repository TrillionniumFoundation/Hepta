"""Fresh actual fixed-executable ordinary patch pipeline under original gates."""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();common_raw=COMMON.read_bytes()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
assert gitsha(common_raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("ordinary_impact_coordinator_ci_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-coordinator-r1/"
FILES=[
  {
    "path": "generate_ordinary_patch_packer_r1.py",
    "gitsha": "8be428f48fd6353daa52747eaeacdf569a3136c6",
    "bytes": 6392,
    "sha256": "7b15d7f5c48f7079b6f3c6f1b71fc4b7264f003611e79efd0aee2bc14770db71"
  },
  {
    "path": "ordinary_patch_executor.S",
    "gitsha": "aeaf61efa6fde911dd5a031adaa55b865e407518",
    "bytes": 32233,
    "sha256": "659afe0dc2dcb4975e823fe96c4c3287450cca9428929e7a7211fe023212757d"
  },
  {
    "path": "program_service_root_reference.py",
    "gitsha": "e572e1273fcd55518f7395071cc56534f2771fc6",
    "bytes": 33675,
    "sha256": "f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9"
  },
  {
    "path": "generate_ordinary_patch_prepare_r1.py",
    "gitsha": "572cc1f39841b9c142040ba8fba9ec99fc99d77e",
    "bytes": 19269,
    "sha256": "348965a5bbce5ca2f7eeb93e0033bf1ee58c9d52a0b71aa9452f30b6b1ef2726"
  },
  {
    "path": "generate_ordinary_patch_receipt_r1.py",
    "gitsha": "4a0aa657053f2a340ca431ab52c11e1e794b858a",
    "bytes": 18942,
    "sha256": "dcf63b505439e013e05b608cc3b9d1032c5d9f4dc48ab2a77ff9e86a4cfccca5"
  },
  {
    "path": "issued_object_prefix_reference.py",
    "gitsha": "90d7242bdc2ab328280b2c760f988cff3ad21d10",
    "bytes": 14115,
    "sha256": "e230b246ed2a410cc3a8f252525cff065b340606ba7cb168f70655bb02da7d4a"
  },
  {
    "path": "prepare_corpus_reference.py",
    "gitsha": "52f43c7c93bfef7fd1319591d616d1a2709f5b9c",
    "bytes": 31318,
    "sha256": "ef003cff6dfc4868505eb1e11e9dab6c4f4e050e67a6ded09df2efe65b74d8b0"
  },
  {
    "path": "receipt_corpus_reference.py",
    "gitsha": "b46ab779035810062e6c225a27892f01e4371ff0",
    "bytes": 26553,
    "sha256": "cdd836d045955e0f736b774f3848a11e3be9b8fdc055c289b829a1851ea7af8a"
  },
  {
    "path": "read_exact_63_role_inputs.py",
    "gitsha": "a858717eada7f3b655bbcc985604bb99a8f3bade",
    "bytes": 8002,
    "sha256": "eea45838986247b1b06a5bdb104f1ba6f32ceadaa08e18582f2d2df368e8247e"
  },
  {
    "path": "resources/original-role-map.json",
    "gitsha": "35202c1c5961923b60f6100e07fa696e2c8f84a0",
    "bytes": 115895,
    "sha256": "a942f616655aeec0f047d66ed7ee6be83fa3a960d65a635bc4c849e29cf6f5df"
  },
  {
    "path": "cli_authoring.py",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
  },
  {
    "path": "ordinary_patch_reference.py",
    "bytes": 20836,
    "gitsha": "1ec25d1a9e579fe077f680b7d34ff40e6db66ee1",
    "sha256": "f4ca14d8ead54a2461b3149c1a72a2e84c9bf191c95570c005d0ec1ad34854ce"
  },
  {
    "path": "generate_static_impact_r1.py",
    "bytes": 27281,
    "gitsha": "10fd6493cece709385c661a18482b9bf481b254b",
    "sha256": "95cdee2d444109f29240124a70956f1b384c80198a6382ba9a953d961436c481"
  },
  {
    "path": "static_impact_corpus_reference.py",
    "bytes": 26022,
    "gitsha": "2660a8bb57da1469b70e88d62e8395b833404591",
    "sha256": "30c4062417b04128f3489426803654e8116da5a4f4faf5df73e42490a107b184"
  },
  {
    "path": "generate_ordinary_impact_coordinator_r1.py",
    "bytes": 10921,
    "gitsha": "b28ca33f99a8f73abe5a6f53831301dbf3e1da72",
    "sha256": "944c3a0563ba4f327ed81c2f6bd27d14d9e199fa98a736368e78308a3ce353d1"
  },
  {
    "path": "build_ordinary_impact_coordinator_r1.py",
    "bytes": 15438,
    "gitsha": "b916f0a93f9364ef9ca917c74342d5aa2f307790",
    "sha256": "46461c0c7252a0d85329a93b3b1736d80f5dfc1559e0a8cbb64c5472fce8bcd4"
  },
  {
    "path": "test_ordinary_impact_coordinator_r1.py",
    "bytes": 19428,
    "gitsha": "350284e3a8ea5375156183d4c57c26b2cf0fa393",
    "sha256": "ccc4cf445baa6ab7bc29978c052b741432269d4f7b1ee525d99ee5106264072d"
  }
]
GROUPS=("semantic","errors","interfaces","input","identity","functions-1024","large-bytes","large-nodes","large-valid","impact-semantic","graph-1024","graph-dense","graph-long-report")
status="FAIL";groups={};failures=[];source=None;roles=None
ROOT=common.BASE/"root-recovery/workspace/native-ordinary-impact-coordinator-r1"
details=dict(scope="FRESH_THREE_ADMISSION_ORDINARY_IMPACT_NATIVE_FIXED_ELF_JOIN",old_counts_inherited=False,
    historical_prepare_and_receipt_case_counts_inherited=False,groups=list(GROUPS),
    full_impact_qualified=False,whole_stack_closed=False,public_CLI_installed=False,
    python_object_input_API_qualified=False,installed_activation=False,old_implementations_deleted=False,
    original_B3_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
    original_group_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1073741824))
def show_originals():
    for path in sorted(ROOT.rglob("*.stderr.log")):
        print("HIA_ORDINARY_IMPACT_ORIGINAL_STDERR "+json.dumps(dict(path=str(path),text=path.read_text()),sort_keys=True),flush=True)
try:
    c=common.prepare()
    source=common.BASE/"ordinary-impact-coordinator-submitted-source";source.mkdir()
    # Preserve exact existing authoring needed for the separate public
    # diagnostic closure. This is read-only, performs no target invocation,
    # and grants no semantic result to this impact gate.
    diagnostic_sources={}
    for dependency in sorted(Path(c["workspace"]).rglob("*.py")):
        if not ("diagnostic" in dependency.name or dependency.name in
            ("hia_composite_lowering_driver_main.py","generate_hia_program_driver.py")):
            continue
        raw=dependency.read_bytes();identity=sha256(raw).hexdigest()
        entry=diagnostic_sources.setdefault(identity,dict(bytes=len(raw),sha256=identity,
            gitsha=gitsha(raw),paths=[]))
        entry["paths"].append(str(dependency))
        target=source/"readonly-diagnostic-authoring"/identity/dependency.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        common.PINS[dependency]=raw
        if len(entry["paths"])==1:
            for offset in range(0,len(raw),12288):
                part=raw[offset:offset+12288]
                print("HIA_DIAGNOSTIC_AUTHORING_ORIGINAL "+json.dumps(dict(path=str(dependency),
                    offset=offset,part_bytes=len(part),base64=base64.b64encode(part).decode(),
                    bytes=len(raw),sha256=identity,gitsha=entry["gitsha"]),sort_keys=True),flush=True)
    details["readonly_diagnostic_authoring"]={"files":list(diagnostic_sources.values()),
        "subject_execution":False,"public_diagnostic_qualified":False}
    for row in FILES:
        path=common.materialize(R3+row["path"],row["gitsha"],source/row["path"])
        raw=path.read_bytes();assert (len(raw),sha256(raw).hexdigest())==(row["bytes"],row["sha256"])
    roles=common.BASE/"ordinary-impact-coordinator-original-role-readback"
    common.run("ordinary-impact-coordinator-complete-original-63-role-readback",
        [sys.executable,"-B",source/"read_exact_63_role_inputs.py",
         "--download-dir",os.environ["HIA_ORDINARY_CANDIDATE_DOWNLOAD_DIR"],
         "--manifest",source/"resources/original-role-map.json",
         "--workspace",c["workspace"],"--out",roles],timeout=180)
    role_summary=json.loads((roles/"summary.json").read_bytes())
    assert role_summary["status"]=="PASS_READBACK_ONLY" and role_summary["roles"]==63
    assert role_summary["all_sources_and_images_bound"] and role_summary["originals_unchanged"]
    details["dependency_readback"]=role_summary
    try:
        common.run("ordinary-impact-coordinator-six-fresh-B3-and-native-ELF-pack",
            [sys.executable,"-B",source/"build_ordinary_impact_coordinator_r1.py",source,roles/"roles",source/"resources/original-role-map.json"],timeout=180)
    finally:
        path=ROOT/"development/build-r1/summary.json"
        if path.is_file():
            details["build"]=json.loads(path.read_bytes())
            print("HIA_ORDINARY_IMPACT_BUILD_ORIGINAL "+json.dumps(details["build"],sort_keys=True),flush=True)
    build=details["build"]
    assert build["status"]=="PASS" and build["actual_native_compiles"]==6 and build["actual_packer_entries"]==1
    assert build["source_and_image_before_after_equal"]
    for group in GROUPS:
        try:
            common.run("ordinary-impact-coordinator-"+group,
                [sys.executable,"-B",source/"test_ordinary_impact_coordinator_r1.py",group,source],timeout=180)
        except BaseException as exc:
            failures.append(dict(group=group,error_class=type(exc).__name__,error=str(exc)))
        finally:
            path=ROOT/"development"/("native-"+group)/"summary.json"
            if path.is_file():
                raw=path.read_bytes();value=json.loads(raw)
                groups[group]={k:v for k,v in value.items() if k not in ("case_results","planned")}
                print("HIA_ORDINARY_IMPACT_GROUP "+json.dumps(groups[group],sort_keys=True),flush=True)
    assert not failures,failures
    assert set(groups)==set(GROUPS)
    for group,value in groups.items():
        assert value["status"]=="PASS" and value["cases"]==value["actual_native_processes"]==value["reference_full_impact_calls"]
        assert value["source_and_image_before_after_equal"] and value["complete_process_streams_preserved"]
        assert value["complete_CAS_verified"] and value["complete_result_and_error_bytes_equal"]
        assert value["parent_plus_children_cpu_seconds"]<=90 and value["elapsed_ns"]<180000000000
        assert value["original_limits"]==details["original_group_limits"]
        assert not value["old_counts_inherited"] and not value["whole_stack_closed"]
    assert groups["semantic"]["cases"]==113 and groups["errors"]["cases"]==58 and groups["interfaces"]["cases"]==48
    assert groups["identity"]["cases"]==3
    assert groups["input"]["cases"]==67 and groups["impact-semantic"]["cases"]==33
    assert all(groups[g]["cases"]==1 for g in ("graph-1024","graph-dense","graph-long-report"))
    assert all(groups[g]["cases"]==1 for g in ("functions-1024","large-bytes","large-nodes","large-valid"))
    assert sum(x["cases"] for x in groups.values())==329
    details.update(actual_native_processes=sum(x["actual_native_processes"] for x in groups.values()),
        complete_original_impact_cases=sum(x["cases"] for x in groups.values()),new_native_compiles=6,new_native_packer_entries=1,
        raw_json_path_complete_selected_differential=True,not_internal_entry_count_inference=True,
        success_requires_three_actual_admissions=True,impact_report_above_8MiB_boundary_included=True,
        public_cli_D_still_open=True)
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc();show_originals()
finally:
    details.update(groups=groups,failures=failures)
    roots={}
    if ROOT.exists():roots["ordinary-impact-coordinator"]=ROOT
    if source is not None and source.exists():roots["ordinary-impact-coordinator-submitted-source"]=source
    if roles is not None and roles.exists():roots["ordinary-impact-coordinator-original-roles"]=roles
    common.finish("ordinary-impact-coordinator",status,details,roots)
if status!="PASS":raise SystemExit(1)
