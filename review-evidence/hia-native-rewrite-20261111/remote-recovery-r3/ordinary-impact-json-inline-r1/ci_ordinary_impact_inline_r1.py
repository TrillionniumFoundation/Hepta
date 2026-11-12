"""Full original thirteen-group qualification of seven exact HIA inline sources."""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();common_raw=COMMON.read_bytes()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
assert gitsha(common_raw)=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("ordinary_impact_inline_ci_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
ORIGINAL_PREFIX="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-coordinator-r2/"
ORIGINAL_FILES=[
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
    "gitsha": "1ec25d1a9e579fe077f680b7d34ff40e6db66ee1",
    "bytes": 20836,
    "sha256": "f4ca14d8ead54a2461b3149c1a72a2e84c9bf191c95570c005d0ec1ad34854ce"
  },
  {
    "path": "generate_static_impact_r1.py",
    "gitsha": "48b35a89ea199d69271fd94e8f34c9e5e6fb1f74",
    "bytes": 27618,
    "sha256": "933cf209d6d079ab95236c984347d6423ba13def32c5ac251144e1fbe86ee480"
  },
  {
    "path": "static_impact_corpus_reference.py",
    "gitsha": "2660a8bb57da1469b70e88d62e8395b833404591",
    "bytes": 26022,
    "sha256": "30c4062417b04128f3489426803654e8116da5a4f4faf5df73e42490a107b184"
  },
  {
    "path": "generate_ordinary_impact_coordinator_r1.py",
    "gitsha": "b28ca33f99a8f73abe5a6f53831301dbf3e1da72",
    "bytes": 10921,
    "sha256": "944c3a0563ba4f327ed81c2f6bd27d14d9e199fa98a736368e78308a3ce353d1"
  },
  {
    "path": "build_ordinary_impact_coordinator_r1.py",
    "gitsha": "c6c6ad3248c09faa1153e9e754cd2d4943a7455c",
    "bytes": 15438,
    "sha256": "20931ae4ccb055db7edda46aa4af6d6e5ee56e809d40cc4ecb5526a2bde6a203"
  },
  {
    "path": "test_ordinary_impact_coordinator_r1.py",
    "gitsha": "67c81f1551350d56210fdb7758214935caec80d8",
    "bytes": 19430,
    "sha256": "8b4eb26c3f601558b3e6d0bd86bbe5ba1bc257d8580b7aa1bb362edc6bf28771"
  }
]
ADDITIONAL_FILES=[
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/build_ordinary_impact_inline_r1.py",
    "path": "build_ordinary_impact_inline_r1.py",
    "bytes": 18676,
    "gitsha": "c9da67c5ac99dcc42b388acb66e9cec82aa440c9",
    "sha256": "fb55cfd935672d28795fbfb63da591a5b6d51c8601aad8895fa163c5f94796ae"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/test_ordinary_impact_inline_r1.py",
    "path": "test_ordinary_impact_inline_r1.py",
    "bytes": 19431,
    "gitsha": "d545fb32db9c0e49f4a01f41abf1f09c0bfcf6e6",
    "sha256": "05cdbfca74851534bf2060f7b4f5de573853a25cf771f9a0db656afa9f1ce6a2"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/evidence/source-transform-proof.json",
    "path": "evidence/source-transform-proof.json",
    "bytes": 202873,
    "gitsha": "3cfa3d613205fb07db028fceee8d8ee1da3e2595",
    "sha256": "64faa076ecb678d671aae86ca67de191d8cf15dfc32309d213d3be85512b5d5f"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-24.hiaasm",
    "path": "sources/role-24.hiaasm",
    "bytes": 111822,
    "gitsha": "e0cfc7a7fbd276fc8fb2eadb1d6c0f1b58a281af",
    "sha256": "e29178124be2960c2e2dc237013c74527a6187cf2fb427f6d764103b226ff454"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-26.hiaasm",
    "path": "sources/role-26.hiaasm",
    "bytes": 136140,
    "gitsha": "f8d693b1059d31b6c8b0f0a7d2819f3c405d0325",
    "sha256": "83e61a4ee02225dd27f51aed6f3e3b2a82b9f3ab1d1df340be3674c526098f9a"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-27.hiaasm",
    "path": "sources/role-27.hiaasm",
    "bytes": 427257,
    "gitsha": "d4c2f5a68f43b5b43d65f2778803b463338b7e28",
    "sha256": "4effe0b91323ea0c66c5ae96b411e4c8188a0be73350cddc10cce322fe2cb389"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-57.hiaasm",
    "path": "sources/role-57.hiaasm",
    "bytes": 292082,
    "gitsha": "defc76f12fe168427235973a0025afe4a479e2a6",
    "sha256": "9cca13699ec5f6b96a7046806dd7d54c115bccd52d37ef2789273d26daedaa53"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-59.hiaasm",
    "path": "sources/role-59.hiaasm",
    "bytes": 252995,
    "gitsha": "9b0f788554bc5df28b00c7b56867486a24df81a2",
    "sha256": "59932d1c0fb853ba59033b6a0ff095ff2e0eab47fd707d1cfcdc4c842f664378"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-60.hiaasm",
    "path": "sources/role-60.hiaasm",
    "bytes": 295382,
    "gitsha": "1c3818b2351b393f965d180b8af7ad28e89e2fe1",
    "sha256": "2c947364a0496e013d18d95563d78349e1997b57f6577800701e267f58d6c754"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/sources/role-63.hiaasm",
    "path": "sources/role-63.hiaasm",
    "bytes": 176892,
    "gitsha": "9e1129d18f9a54320034843fffc8241fcb830b64",
    "sha256": "b72a2ca735372dfd954033608de93b2f00a3dbc5131a993e277eea863d534497"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-json-inline-r1/evidence/independent-inline-static-review.json",
    "path": "evidence/independent-inline-static-review.json",
    "bytes": 14032,
    "gitsha": "2d8bad7aaf6ced17f3234bba7e06e795b6791259",
    "sha256": "43670306773f6ddf2de79a7367d82ec6c6ee3bd724511a07b8b6362df8ec031c"
  },
  {
    "repository_path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ordinary-impact-timing47-readback-r1/actual-follow49/raw/build/manifest.json",
    "path": "resources/actual47-build-manifest.original.json",
    "bytes": 21225,
    "gitsha": "39d4f27505f651fba51171816d05eac3ad80f3e8",
    "sha256": "db45591a5df693a841eb032b7cc58d786d572391a6f0330f44f1d632c8796d73"
  }
]

GROUPS=("semantic","errors","interfaces","input","identity","functions-1024","large-bytes","large-nodes","large-valid","impact-semantic","graph-1024","graph-dense","graph-long-report")
OLD_ROOT=common.BASE/"root-recovery/workspace/native-ordinary-impact-coordinator-r2"
ROOT=common.BASE/"root-recovery/workspace/native-ordinary-impact-json-inline-r1"
status="FAIL";groups={};failures=[];source=None;submitted=None;roles=None
details=dict(scope="ORIGINAL_13_GROUPS_329_CASES_WITH_SEVEN_EXACT_HIA_INLINE_SOURCES",
    old_counts_inherited=False,groups=list(GROUPS),planned_cases=329,
    full_impact_qualified=False,whole_stack_closed=False,public_CLI_installed=False,
    python_object_input_API_qualified=False,installed_activation=False,old_implementations_deleted=False,
    original_B3_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
    original_group_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1073741824),
    evidence_storage_phase=dict(independent_CPU_or_wall_gate=False,parent_address_bytes=1073741824,
        existing_workflow_outer_minutes=50,subject_measurements_and_bounds_separate=True))
def bounded(label,args):
    result=common.run(label,args,timeout=180)
    assert result["child_cpu_seconds"]<=90,(label,"complete subprocess tree CPU",result["child_cpu_seconds"])
    assert result["elapsed_ns"]<180000000000,(label,"complete subprocess wall",result["elapsed_ns"])
    return result
def show_originals():
    for root in (OLD_ROOT,ROOT):
        if root.exists():
            for path in sorted(root.rglob("*.stderr.log")):
                print("HIA_ORDINARY_INLINE_ORIGINAL_STDERR "+json.dumps(dict(path=str(path),text=path.read_text()),sort_keys=True),flush=True)
def read_build(root,key,marker):
    path=root/"development/build-r1/summary.json"
    if path.is_file():
        details[key]=json.loads(path.read_bytes())
        print(marker+" "+json.dumps(details[key],sort_keys=True),flush=True)
try:
    c=common.prepare()
    source=common.BASE/"ordinary-inline-original-submitted-source";source.mkdir()
    submitted=common.BASE/"ordinary-inline-seven-submitted-source";submitted.mkdir()
    for row in ORIGINAL_FILES:
        path=common.materialize(ORIGINAL_PREFIX+row["path"],row["gitsha"],source/row["path"])
        raw=path.read_bytes()
        assert (len(raw),sha256(raw).hexdigest())==(row["bytes"],row["sha256"])
    for row in ADDITIONAL_FILES:
        path=common.materialize(row["repository_path"],row["gitsha"],submitted/row["path"])
        raw=path.read_bytes()
        assert (len(raw),sha256(raw).hexdigest())==(row["bytes"],row["sha256"])
    old_test=(source/"test_ordinary_impact_coordinator_r1.py").read_bytes()
    new_test=(submitted/"test_ordinary_impact_inline_r1.py").read_bytes()
    wanted=old_test
    for before,after in (
        (b'native-ordinary-impact-coordinator-r2"',b'native-ordinary-impact-json-inline-r1"'),
        (b'manifest["new_compiles"]==6',b'manifest["new_compiles"]==13')):
        assert wanted.count(before)==1
        wanted=wanted.replace(before,after)
    assert new_test==wanted
    reverse=new_test.replace(b'manifest["new_compiles"]==13',b'manifest["new_compiles"]==6')
    reverse=reverse.replace(b'native-ordinary-impact-json-inline-r1"',b'native-ordinary-impact-coordinator-r2"')
    assert reverse==old_test and gitsha(old_test)=="67c81f1551350d56210fdb7758214935caec80d8"
    details["test_delta"]=dict(exact_two_edits_full_inverse=True,original_test_gitsha=gitsha(old_test),
        selected_test_gitsha=gitsha(new_test),fixtures_oracles_errors_limits_unchanged=True)
    roles=common.BASE/"ordinary-inline-original-role-readback"
    details["original_role_readback_process"]=bounded("ordinary-inline-complete-original-63-role-readback",
        [sys.executable,"-B",source/"read_exact_63_role_inputs.py",
         "--download-dir",os.environ["HIA_ORDINARY_CANDIDATE_DOWNLOAD_DIR"],
         "--manifest",source/"resources/original-role-map.json",
         "--workspace",c["workspace"],"--out",roles])
    role_summary=json.loads((roles/"summary.json").read_bytes())
    assert role_summary["status"]=="PASS_READBACK_ONLY" and role_summary["roles"]==63
    assert role_summary["all_sources_and_images_bound"] and role_summary["originals_unchanged"]
    details["dependency_readback"]=role_summary
    try:
        details["baseline_build_process"]=bounded("ordinary-inline-original-six-fresh-B3-and-ELF-pack",
            [sys.executable,"-B",source/"build_ordinary_impact_coordinator_r1.py",source,roles/"roles",source/"resources/original-role-map.json"])
    finally:read_build(OLD_ROOT,"baseline_build","HIA_ORDINARY_INLINE_BASELINE_BUILD")
    baseline=details["baseline_build"]
    assert baseline["status"]=="PASS" and baseline["actual_native_compiles"]==6
    assert baseline["actual_packer_entries"]==1 and baseline["source_and_image_before_after_equal"]
    try:
        details["inline_build_process"]=bounded("ordinary-inline-seven-fresh-B3-and-new-ELF-pack",
            [sys.executable,"-B",submitted/"build_ordinary_impact_inline_r1.py",source,submitted])
    finally:read_build(ROOT,"inline_build","HIA_ORDINARY_INLINE_CANDIDATE_BUILD")
    build=details["inline_build"]
    assert build["status"]=="PASS" and build["actual_optimization_B3"]==7
    assert build["actual_optimization_packer_entries"]==1 and build["actual_public_semantic_processes"]==0
    assert build["source_and_image_before_after_equal"] and build["all_frozen_inputs_read_back"]
    assert build["complete_CAS_verified"] and build["parent_plus_children_cpu_seconds"]<=90
    assert build["elapsed_ns"]<180000000000 and build["original_builder_limits"]==details["original_group_limits"]
    manifest=json.loads((ROOT/"development/build-r1/manifest.json").read_bytes())
    assert manifest["new_compiles"]==13 and len(manifest["compiled"])==13
    assert manifest["baseline_new_compiles"]==6 and manifest["optimization_new_compiles"]==7
    assert manifest["actual_native_packer_entries"]==2
    assert manifest["baseline_packer_entries"]==manifest["optimization_packer_entries"]==1
    assert manifest["changed_roles"]==[24,26,27,57,59,60,63] and manifest["unchanged_roles"]==56
    assert manifest["original_all_63_source_and_image_pins_reproduced"] and manifest["actual_original_ELF_reproduced"]
    details.update(new_native_compiles=13,new_native_packer_entries=2,changed_roles=manifest["changed_roles"],
        actual_original_all_63_source_image_and_ELF_identity_equal=True)
    for group in GROUPS:
        try:
            bounded("ordinary-inline-"+group,
                [sys.executable,"-B",submitted/"test_ordinary_impact_inline_r1.py",group,source])
        except BaseException as exc:
            failures.append(dict(group=group,error_class=type(exc).__name__,error=str(exc)))
        finally:
            path=ROOT/"development"/("native-"+group)/"summary.json"
            if path.is_file():
                value=json.loads(path.read_bytes())
                groups[group]={k:v for k,v in value.items() if k not in ("case_results","planned")}
                print("HIA_ORDINARY_INLINE_GROUP "+json.dumps(groups[group],sort_keys=True),flush=True)
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
        complete_original_impact_cases=sum(x["cases"] for x in groups.values()),
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
    if OLD_ROOT.exists():roots["ordinary-inline-original-six-image-build"]=OLD_ROOT
    if ROOT.exists():roots["ordinary-impact-json-inline"]=ROOT
    if source is not None and source.exists():roots["ordinary-inline-original-submitted-source"]=source
    if submitted is not None and submitted.exists():roots["ordinary-inline-seven-submitted-source"]=submitted
    if roles is not None and roles.exists():roots["ordinary-inline-original-roles"]=roles
    common.finish("ordinary-impact-json-inline-r1",status,details,roots)
if status!="PASS":raise SystemExit(1)
