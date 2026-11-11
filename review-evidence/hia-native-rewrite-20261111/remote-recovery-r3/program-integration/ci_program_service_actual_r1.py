"""New A service integration through the actual fixed native context carrier."""
from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve()
common_raw=COMMON.read_bytes()
assert sha1(b"blob "+str(len(common_raw)).encode()+b"\0"+common_raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("A_real_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=common_raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
CARRIER=[
  {
    "path": "tools/cli_authoring.py",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  {
    "path": "tools/compose_cli_business_executor.py",
    "gitsha": "bf075234ad6bf9cd8327962c035b25f1ae97f4ec",
    "bytes": 21032,
    "sha256": "38db577e4a95c06059ecf010eb770d7c3ca24dd47c355797e2069601bbfc64bb"
  },
  {
    "path": "tools/cli_business_executor.S",
    "gitsha": "363a543e944fb20a41bde01785d11193d3571913",
    "bytes": 56987,
    "sha256": "90cd4a88f9cd09674076f078d9d30b6b9a593ba5e369a43f5231ad2686ed828c"
  },
  {
    "path": "tools/generate_hia_cli_business_packer.py",
    "gitsha": "9d0fd7f13805e1e645ffa3b31d6a08e37dd45578",
    "bytes": 6690,
    "sha256": "5b2f167e569e60f80d5b8db662f2807c295fb6075716fe6679338ce319c5e654"
  },
  {
    "path": "tools/cli_business_fixture_owners.py",
    "gitsha": "ef2f1d5c5334b9adab6461e893c381f97c0529d4",
    "bytes": 15621,
    "sha256": "fd66d47a9675567df0b1a2dc42cd33c40a3dba0ca85bfebfe9d29ec112703a67"
  },
  {
    "path": "reference/cli-executor-r4.S",
    "gitsha": "b53e3af30c3e877f9cc6d9f2b2faee6ea20466cd",
    "bytes": 14594,
    "sha256": "717f23a65686cabc8a2599e28079fa37645393eaa31e5e30cdc0cad6aef86c26"
  },
  {
    "path": "reference/program-executor.S",
    "gitsha": "8163cf41059b38260f66dbc5a89d5676b1f7f121",
    "bytes": 32247,
    "sha256": "6c8e7c8dfdbbbe1da653834c67e19f733922937f86531c88179713c018770cac"
  },
  {
    "path": "reference/program-roles.json",
    "gitsha": "35202c1c5961923b60f6100e07fa696e2c8f84a0",
    "bytes": 115895,
    "sha256": "a942f616655aeec0f047d66ed7ee6be83fa3a960d65a635bc4c849e29cf6f5df"
  },
  {
    "path": "docs/HIA_CLI_BUSINESS_CONTEXT_ABI.md",
    "gitsha": "d622017d542a2aa5dd92a7bac72af129971ed037",
    "bytes": 16750,
    "sha256": "711ffce73e36df623cb5351118d2a5be276e319b03271b1a405ed25e66987c2a"
  }
]
INPUTS={
  "parent": {
    "path": "program_service_real_parent.py",
    "gitsha": "89454281cf76c9b696756f344cf7648c3892f0d4",
    "bytes": 5908,
    "sha256": "4b38eeb115ba9d18b2410c7aa49802eaab2ee5aa250406b2cad8aa323533b033"
  },
  "assets": {
    "path": "read_program_service_assets_r1.py",
    "gitsha": "c09e8db8c36718068424285af795e77fbe8cecb3",
    "bytes": 7653,
    "sha256": "3ae67a1eddceddafc3aee8f39bb0eac24c6946a2b88a86e9b7ec35123d1ab228"
  },
  "test": {
    "path": "test_program_service_actual_r1.py",
    "gitsha": "0c3b89fa11a8675fe2b8b62a7d9eaebe85e390ae",
    "bytes": 25113,
    "sha256": "db907f8360975cdea1a02e5743ea5d781463f0db9ac8ea02c2fde2cb7c0a050b"
  },
  "generator": {
    "path": "generate_program_service_r1.py",
    "gitsha": "2a2609ec9f2d96980b70a777019b15506f65f5fa",
    "bytes": 33649,
    "sha256": "b0473ce106d0f614bdf21fa11cf887fac06193c2a63dbb9708d209a6e7d11f62"
  },
  "compile": {
    "path": "compile_program_service_r1.py",
    "gitsha": "50b2f008e8d4b08fb4880ace05f371eec49c476c",
    "bytes": 4332,
    "sha256": "dbcbb1426c796a1f3686e51269e60002e1255858d4e3f399ce82e2b5e9509d1f"
  }
}

status="FAIL";context=None;mine=None;service=None
details=dict(scope="ACTUAL_A_SERVICE_FIXED_CARRIER_ADMISSION_PROJECTION_WIRE",
    historical_case_count_inheritance=False,public_CLI_entry_claim=False,
    actual_publication_operations=0,ordinary_installed_activation=False,whole_stack_closed=False)
try:
    context=common.prepare()
    base=Path(context["base"]);workspace=Path(context["workspace"])
    mine=base/"program-integration-recovery";mine.mkdir()
    project=mine/"workspace/native-cli-program-service-integration-r1";project.mkdir(parents=True)
    for row in CARRIER:
        common.materialize(R3+"cli-finite-carrier-r1/"+row["path"],row["gitsha"],project/row["path"])
    for name,relative in (("parent","tools/program_service_real_parent.py"),("test","tests/test_program_service_actual_r1.py")):
        row=INPUTS[name]
        common.materialize(R3+"program-integration/"+row["path"],row["gitsha"],project/relative)
    frozen=workspace/"native-edit-json-next/development/main-compile-r3/source"
    for original,target,expected in [
      (frozen/"6/hia_agent_edit_source_views.py",project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
       "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"),
      (frozen/"8/hia_composite_lowering_driver_common.py",project.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
       "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1")]:
        raw=original.read_bytes();assert sha256(raw).hexdigest()==expected
        common.PINS[original.resolve()]=raw;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as stream:stream.write(raw)
        assert target.read_bytes()==raw
    assets=INPUTS["assets"]
    reader=common.materialize(R3+"program-integration/"+assets["path"],assets["gitsha"],mine/"read-assets.py")
    common.run("verify-original-wire-and-projector-full-archives",
        [sys.executable,"-B",reader,"--download-dir",os.environ["HIA_A_COMPONENT_DOWNLOAD_DIR"],
         "--out",mine/"assets"],timeout=180)
    service=workspace/"native-program-service-root-r1"
    for name in ("generator","compile"):
        row=INPUTS[name]
        script=common.materialize(R3+"program-service/"+row["path"],row["gitsha"],mine/row["path"])
        common.run("new-A-service-"+name,[sys.executable,"-B",script],timeout=300 if name=="generator" else 120)
    output=project/"development/actual-r1"
    common.run("real-A-native-context-integration",[
        sys.executable,"-B",project/"tests/test_program_service_actual_r1.py",
        "--source",context["source"],"--reference",context["reference"],
        "--compiler",context["compiler"],"--roles",project/"reference/program-roles.json",
        "--assets",mine/"assets/assets.json",
        "--service-manifest",service/"development/compile-r1/program-service.manifest.json",
        "--out",output],cwd=project,timeout=1200,
        env=dict(PYTHONDONTWRITEBYTECODE="1",
            PYTHONPATH=str(project.parent/"Hepta-agent-edit-native")+":"+context["reference"]))
    result=json.loads((output/"summary.json").read_bytes())
    assert result["status"]=="PASS" and result["source_pins_unchanged"]
    assert (result["cases"],result["accepted_cases"],result["rejected_cases"],
            result["native_processes"],result["actual_packer_entries"])==(75,51,24,75,75)
    assert result["complete_values_and_bytes_equal"] and result["real_native_decoder_projector_wire"]
    assert not result["public_CLI_entry_claim"] and result["publication_operations"]==0
    details["actual"]=result;status="PASS"
    print("HIA_A_REAL_INTEGRATION "+json.dumps({k:v for k,v in result.items() if k!="cases_detail"},sort_keys=True),flush=True)
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    roots={}
    if mine is not None:roots["program-integration"]=mine
    if service is not None:roots["program-service"]=service
    common.finish("real-A-service-fixed-carrier-integration",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
