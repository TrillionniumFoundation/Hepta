from pathlib import Path
import ast,base64,hashlib,json,shutil,zlib

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'v76-source-generation-r1'
JOINT=ROOT.parent/'v78-joint-integration-r2'
PACKET=JOINT/'source-packet-r2/SOURCE-PACKET.json'
BRANCH='codex/hia-joint-source-generation-v78-r1-20261112-dda7'
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def save(path,b):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.read_bytes()==b,str(path)
    else:path.write_bytes(b)
def replace(text,old,new):
    assert text.count(old)==1,old[:120]
    return text.replace(old,new,1)
raw=PACKET.read_bytes();assert sha(raw)=='477df75d8ef71a557e3d296521f729c566318962db2907f5e0d541e605a616a1'
p=json.loads(raw);assert len(p['files'])==51 and len(p['final_files'])==3181
assert p['base_commit']=='4b19af89a766593f7d5f1cc2db256e81aba7afcb'
before=(BASE/'tools/hia_source_integration_v76.py').read_text()
driver=before.replace('v76','v78').replace('V76','V78').replace('exact 5f7','exact 4b').replace('5f7 base','4b base').replace('5f7 tree','4b tree')
driver=replace(driver,'5f7f95367e8e395863801487e969d286b9091110',p['base_commit'])
driver=replace(driver,'4f4e58e06a6e03adcd6548bd8ea4ef591c20359f',p['base_tree'])
driver=replace(driver,'BASE_FILE_COUNT = 3120','BASE_FILE_COUNT = 3153\nFROZEN_CANDIDATE_TREE = "a9a2b5ec40d176a7684a03ca2859190abd982db0"\nEXPECTED_GENERATORS = 82\nEXPECTED_SELECTORS = 157\nEXPECTED_TESTS = 764')
driver=replace(driver,'    "examples/hia_bootstrap/heap_live_engine.hiaasm",','    "examples/hia_bootstrap/heap_live_engine.hiaasm",\n    "examples/hia_bootstrap/core_lowering.hiaasm",\n    "examples/hia_bootstrap/service_emission.hiaasm",')
driver=replace(driver,'                    "machine_elf", "machine_plan", "service_context")','                    "machine_elf", "machine_plan", "service_context", "core_lowering", "service_emission")')
new_controls=('tests.test_hia_core_lowering_native.CoreLoweringSourceTests','tests.test_hia_service_emission_native.ServiceEmissionSourceTests','tests.test_hia_service_emission_builder.ServiceEmissionAdapterTests','tests.test_hia_service_emission_qualifier.ServiceEmissionQualifierSourceTests','tests.test_hia_service_emission_lifetimes.ServiceEmissionLifetimeSourceTests')
driver=replace(driver,'MANDATORY_CONTROLS = (','MANDATORY_CONTROLS = (\n'+''.join('    '+repr(x)+',\n' for x in new_controls))
driver=replace(driver,'        "overlay": Path(REPORT["overlay_input"]["path"]),','        "overlay": Path(REPORT["overlay_input"]["path"]),\n        "expected_source_ids": Path(__file__).resolve().parents[1] / "overlay" / "expected-source-ids.json",')
driver=replace(driver,'            suffix = ".yml" if name == "workflow" else ".py"','            suffix = ".yml" if name == "workflow" else ".json" if name == "expected_source_ids" else ".py"')
driver=replace(driver,'    controls = source_controls(base_workflow, current_workflow, OVERLAY["extra_controls"])','    controls = source_controls(base_workflow, current_workflow, OVERLAY["extra_controls"])\n    require(len(generators) == EXPECTED_GENERATORS, "complete generator denominator differs")\n    require(len(controls["executed_selectors"]) == EXPECTED_SELECTORS\n            and controls["executed_selectors"] == controls["workflow_names"],\n            "all157 original and new selectors must be in the normal workflow")')
driver=replace(driver,'    stage_known("pre-inventory", allowed)','    stage_known("pre-inventory", allowed)\n    require(git_bytes("frozen-source-write-tree", "write-tree").decode().strip() == FROZEN_CANDIDATE_TREE,\n            "authentic regenerated source differs from the frozen3181-file joint candidate")')
driver=replace(driver,'    source, target = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])','    source, target = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])') if '    source, target = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])' in driver else driver
driver=replace(driver,'names = json.loads(sys.argv[3])','names = json.loads(sys.argv[3])\nexpected_ids = json.loads(Path(sys.argv[4]).read_text())["ordered_ids"]')
driver=replace(driver,'    record["status"] = "RUNNING"\n    save()','    if ids != expected_ids or len(ids) != 764:\n        raise AssertionError("complete764 ordered source test IDs differ from frozen original/current inventory")\n    record["status"] = "RUNNING"\n    save()')
driver=replace(driver,'        str(child_result), json.dumps(controls["executed_selectors"])], check=False)','        str(child_result), json.dumps(controls["executed_selectors"]),\n        str(Path(__file__).resolve().parents[1] / "overlay" / "expected-source-ids.json")], check=False)')
driver=replace(driver,'                  and type(value.get("tests_run")) is int and value["tests_run"] > 0','                  and type(value.get("tests_run")) is int and value["tests_run"] == EXPECTED_TESTS')
assert '5f7f953' not in driver and 'BASE_FILE_COUNT = 3120' not in driver
ast.parse(driver)
supervisor=(BASE/'tools/workflow_process.py').read_bytes();assert sha(supervisor)=='f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
save(ROOT/'tools/hia_source_integration_v78.py',driver.encode())
save(ROOT/'tools/workflow_process.py',supervisor)
module={};exec(compile(driver,str(ROOT/'tools/hia_source_integration_v78.py'),'exec'),{'__name__':'harness_static'}|{}) if False else None
tree=ast.parse(driver);values={}
for n in tree.body:
    if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('GENERATED_HIA','GENERATED_DOCS'):
        values[n.targets[0].id]=ast.literal_eval(n.value)
overlay={'schema':'hepta.hia.source-overlay.v1','base_commit':p['base_commit'],'base_tree':p['base_tree'],'files':[{k:r[k] for k in ('path','mode','bytes','sha256','blob','content')} for r in p['files']],'expected_generated_paths':list(values['GENERATED_HIA']+values['GENERATED_DOCS']),'extra_controls':[]}
overlay_raw=(json.dumps(overlay,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
packed=zlib.compress(overlay_raw,9);wrapper={'schema':'hia.source-overlay-zlib-wrapper.v1','bytes':len(overlay_raw),'sha256':sha(overlay_raw),'compressed_bytes':len(packed),'compressed_sha256':sha(packed),'data':base64.b64encode(packed).decode()}
save(ROOT/'overlay/source-overlay.wrapper.json',(json.dumps(wrapper,sort_keys=True,indent=2)+'\n').encode())
controls=json.loads((ROOT.parent/'v78-joint-integration-r1/generation-source-r1/source-controls.json').read_text())
ids=controls['loaded_ids'];assert len(ids)==len(set(ids))==764 and controls['status']=='PASS'
expected={'schema':'hia.v78-authentic-source-original-ids.v1','ordered_ids':ids,'count':764,'basis':'Original executed764 IDs from exact joint R1; R2 changes only normal selector registration and its support digest. Expected list is a denominator, not inherited outcome.','r1_original_complete_capsule_index':'ff38b4802dec2cf2953b268ef6dcc257d9da8c17'}
save(ROOT/'overlay/expected-source-ids.json',(json.dumps(expected,sort_keys=True,indent=2)+'\n').encode())
workflow=(BASE/'.github/workflows/hia-source-generation-v76.yml').read_text().replace('v76','v78').replace('V76','V78').replace('exact 5f7','exact 4b').replace('codex/hia-source-generation-v78-r1-20261112-dda7',BRANCH).replace('5f7f95367e8e395863801487e969d286b9091110',p['base_commit']).replace('4f4e58e06a6e03adcd6548bd8ea4ef591c20359f',p['base_tree']).replace('a72a605fde1edfe1eafae00ffa0daf5bea09155144c280afe6f9957d408f9aea',sha(overlay_raw))
workflow=replace(workflow,'name: HIA v78 r1 isolated source generation','name: HIA v78 authentic joint source generation')
save(ROOT/'.github/workflows/hia-source-generation-v78.yml',workflow.encode())
save(ROOT/'README.md',b'# HIA v78 authentic joint source generation\n\nThis independent harness checks out exact product4b, admits all3153 Git blobs/modes, applies the frozen51-file CoreR3/EmissionR6/CLI union, regenerates all82 modules, and requires its actual staged tree to equal the frozen3181-file candidate before inventory. It regenerates the unchanged inventory against genuine HEAD/index/worktree, then executes all157 normal-workflow selectors and exactly the original/current764 ordered source tests.\n\nOriginal1800-second child limits and source process supervision are unchanged. All source changes, intermediate observations, original failures and full output are retained. It does not create a product commit, qualify a current cold bootstrap, activate a native default, remove an old implementation, or claim whole-native closure. The separately discovered shared CALL/BoolOp lifetime gaps remain open and are being repaired in a separate R4.\n')
record={'schema':'hia.v78-authentic-joint-source-harness-authoring.v1','branch':BRANCH,'parent_product':p['base_commit'],'base_tree':p['base_tree'],'input_joint_source_wrapper':'0d2a9613a4aa37102448b5847bc4eab452a2573f','input_joint_source_sha256':sha(raw),'frozen_tree_before_inventory':p['candidate_tree_by_git_encoding'],'overlay_bytes':len(overlay_raw),'overlay_sha256':sha(overlay_raw),'driver_basis':{'path':'tools/hia_source_integration_v76.py','sha256':sha(before.encode()),'source_harness_commit':'46c559bf03a256e1a0999721d8ca82a0225c5bfe'},'source_child_seconds':1800,'base_files':3153,'final_source_files':3181,'overlay_paths':51,'generators':82,'source_selectors':157,'source_tests':764,'current_cold':False,'whole_native':False,'known_shared_lifetime_gap_not_closed':True}
save(ROOT/'AUTHORING.json',(json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
files=[]
for name in ('.github/workflows/hia-source-generation-v78.yml','tools/hia_source_integration_v78.py','tools/workflow_process.py','overlay/source-overlay.wrapper.json','overlay/expected-source-ids.json','AUTHORING.json','README.md'):
    b=(ROOT/name).read_bytes();files.append({'path':name,'bytes':len(b),'sha256':sha(b),'blob':blob(b),'mode':'100644'})
save(ROOT/'HARNESS-FILES.json',(json.dumps({'files':files},sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'status':'AUTHORED_NOT_EXECUTED','branch':BRANCH,'overlay':record['overlay_sha256'],'files':files},indent=2))
