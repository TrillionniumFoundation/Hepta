"""Fresh thirteen-image full P12 resources and initializer integration.

The original constructor/profiles/examples and original Store.json/profile
methods independently create the oracle. Actual namespace put/SQL outcomes
remain predeclared fixtures; no physical Store/ordinary Worker is claimed.
"""
from __future__ import annotations
import ast,importlib.util,json,os,stat,subprocess,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
PINS={
  "dependency_index": {
    "path": "worker_ci_dependencies_r4.json",
    "bytes": 12173,
    "sha256": "ac161a0eca2fc7de654a065099f1600909171125ec45e6deeb39dcdeced1fb9c",
    "gitsha": "6f6915dbb0b6b96796ae88a7febab4c1e9f80310"
  },
  "restore": {
    "path": "worker_ci_restore_r2.py",
    "bytes": 8761,
    "sha256": "bc44552bb7a61e983227b27da4adc321c435cf76e2d30ec4def6c1345bcafa10",
    "gitsha": "3c4b0e5b979f8107065a7e0144faaf5d9ca0668d"
  },
  "registry_compile": {
    "path": "compile_worker_init_registry_ci_r2.py",
    "bytes": 13599,
    "sha256": "43e026d9014261d121de37a45d64ead3884a9f4eef6d340b1b3a5b25507a99f1",
    "gitsha": "24b8b8fe7af6223513d48334caa063b32dc925ea"
  },
  "digest_compile": {
    "path": "compile_worker_digest_ci_r1.py",
    "bytes": 8523,
    "sha256": "478aa8179eb1e3b90d423ba6027cc563c01866314b451aeb271b4904f43c457d",
    "gitsha": "09b433f41bbd5cd019a258f86562ee1794696d51"
  },
  "harness": {
    "path": "development/digest_harness_r4.py",
    "bytes": 12674,
    "sha256": "4b7209e77778b5b80521815952731573385117fa2bafa08852977dc3faab92a5",
    "gitsha": "3d11424357d5c57fbfa1ca029f6887cd040bbae0"
  },
  "complete": {
    "path": "development/test_worker_resources_initializer_r2.py",
    "bytes": 71057,
    "sha256": "a7d2b4f3889165221ad2cb0d7eef0517e2c7eede3d17855ed6facbd088a1f7ea",
    "gitsha": "3c9fcd871519994649e2fca847e1e133426c694e"
  },
  "store_compile": {
    "path": "compile_worker_store_values_ci_r2.py",
    "bytes": 9672,
    "sha256": "5b9f7220213a4b43fce38024d97d39257a80eb23f2015896f8c0af8b18b234c1",
    "gitsha": "2ab54f0edcce4ef145869543d7c0d1c89463b837"
  },
  "store_harness": {
    "path": "development/store_values_harness_r1.py",
    "bytes": 15468,
    "sha256": "ee46468c8c5f41a3f35668a4b17e75686599536554c5924e0629223917c805e7",
    "gitsha": "49e7bc38ceacefad1d0cb055f3683de7c5b2ea6a"
  },
  "evidence_cache": {
    "path": "development/evidence_bytes_cache_r1.py",
    "bytes": 1543,
    "sha256": "f42cea6ef869631900628e88a38cf4db4ea08ca289c773b5c4cf7e25adab2934",
    "gitsha": "9836d7156be3d7a9d9536bce81459bf35178ace2"
  },
  "accounted": {
    "path": "development/accounted_full_initializer_r4.py",
    "bytes": 1680,
    "sha256": "7a4f18d7eadc93681ebc2e27a341f61a85bf2e1804c943229f39552df861484a",
    "gitsha": "843412424451d7c6df677c1cb9b97895dee1cb47"
  },
  "resources_compile": {
    "path": "compile_worker_init_resources_ci_r2.py",
    "bytes": 6651,
    "sha256": "52d7dec1d949e3a8def45d1690f63d2040ddeb807817d8eb44467f09041c3484",
    "gitsha": "cc832445ab9577e7f6879ad0e6c760b41139f88f"
  },
  "resources_helper": {
    "path": "development/resource_initializer_join_r2.py",
    "bytes": 15531,
    "sha256": "de635d2af3cdc21115480ac18faa7e6637e13ee7e1f107dec64f85d2051480b2",
    "gitsha": "6099821289137492d588674d18b6345cb4baea6b"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_digest_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes();context=None;work=None;project=None;store_project=None;resource_project=None;submitted={}
failures=[];status='FAIL'
GROUPS=('resource-semantic','resource-capacity','resource-protocol')
details=dict(scope='THIRTEEN_IMAGE_COMPLETE_P12_RESOURCES_INITIALIZER_DEVELOPMENT',
 groups=list(GROUPS),historical_pass_inheritance=False,
 original_FOLLOW36_semantic_failure_preserved=True,old_completed_other_groups_not_repeated=True,
 local_eight_case_95_352369_cpu_observation_is_not_a_budget_pass=True,
 evidence_cache_changes_no_native_call_or_case_function=True,aggregate_cpu_below90_required=True,
 new_P12_controller_owns_complete_resource_and_metadata_result_routing=True,
 planned_new_cases=dict(semantic=2,capacity=1,protocol=52),
 old_digest_component_cases=0,old_Store_component_cases=0,actual_namespace_entries=0,
 namespace_put_sql_result_issuer_is_foreign=True,remaining_initializer_foreign_peer_kinds=11,
 complete_original_Store_json_profile_methods_oracle=True,
 runtime_python_mechanical_transport=True,ordinary_worker_closed=False,
 ordinary_namespace_closed=False,production_activation=False,components={},
 limits=dict(compiler_cpu_seconds=10,compiler_wall_seconds=20,compiler_address_space_bytes=268435456,
 group_cpu_seconds=90,group_wall_seconds=180,group_address_space_bytes=1073741824))

def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def materialize(key,target):
 row=PINS[key];raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=context['repo'])
 assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha']),key
 if target.suffix=='.py':ast.parse(raw,filename=str(target))
 target.parent.mkdir(parents=True,exist_ok=True)
 with target.open('xb') as stream:stream.write(raw)
 submitted[target]=raw;return target
def panel(label,args,summary_path,timeout=180,env=None):
 success=False
 try:common.run(label,args,timeout=timeout,env=env);success=True
 except BaseException as exc:
  failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
 if success and label in ['worker-store-composition-'+g for g in GROUPS]:
  process=json.loads((Path(context['output'])/'steps'/label/'process.json').read_bytes())
  actual_cpu=process['child_cpu_seconds']
  details.setdefault('actual_group_cpu_seconds',{})[label]=actual_cpu
  if not isinstance(actual_cpu,(int,float)) or not 0<=actual_cpu<90:
   failures.append(dict(label=label,error_class='AggregateCpuBudgetObservation',
    error='exit zero does not establish aggregate CPU below 90',actual_cpu_seconds=actual_cpu))
   success=False
 result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
 details['components'][label]=result
 print('HIA_WORKER_STORE_COMPOSITION_PANEL '+json.dumps(dict(label=label,actual_successful_process=success,original_summary=result),sort_keys=True),flush=True)
 if success and result.get('status')!='PASS':
  failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)));return False
 return success
try:
 context=common.prepare();output=Path(context['output'])
 save(output/'worker-store-composition-submitted-source.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
  driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
 own=Path(context['base'])/'worker-resource-composition-ci-source'
 index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
 restore=materialize('restore',own/'worker_ci_restore_r2.py')
 registry_compile=materialize('registry_compile',own/'compile_worker_init_registry_ci_r2.py')
 digest_compile=materialize('digest_compile',own/'compile_worker_digest_ci_r1.py')
 store_compile=materialize('store_compile',own/'compile_worker_store_values_ci_r2.py')
 resources_compile=materialize('resources_compile',own/'compile_worker_init_resources_ci_r2.py')
 common.run('worker-store-composition-exact-dependency-restore',
  [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
 work=Path(context['base'])/'worker-recovery/work-r2'
 registry_out=output/'store-composition-registry-eight-compiles'
 compiled=panel('worker-store-composition-eight-peer-generation-B3',
  [sys.executable,'-B',registry_compile,work,context['repo'],registry_out],
  registry_out/'summary.json',timeout=300)
 project=work/'native-agent-worker-digest-next'
 store_project=work/'native-agent-worker-store-values-next'
 if compiled:
  assert details['components']['worker-store-composition-eight-peer-generation-B3']['actual_compiles']==8
  compiled=panel('worker-store-composition-digest-sha-generation-B3',
   [sys.executable,'-B',digest_compile,work,context['repo'],project,registry_out,context['reference']],
   project/'development/compile-r2/summary.json',timeout=300)
 if compiled:
  assert details['components']['worker-store-composition-digest-sha-generation-B3']['actual_compiles']==2
  compiled=panel('worker-store-composition-method-generation-B3',
   [sys.executable,'-B',store_compile,work,context['repo'],store_project,registry_out,context['reference']],
   store_project/'development/compile-r1/summary.json',timeout=300)
 if compiled:
  assert details['components']['worker-store-composition-method-generation-B3']['actual_compiles']==1
  resource_project=work/'native-agent-worker-initialization-resources-next'
  compiled=panel('worker-resources-metadata-generation-B3',
   [sys.executable,'-B',resources_compile,work,context['repo'],resource_project,context['workspace']],
   resource_project/'development/compile-r2/summary.json',timeout=300)
 if compiled:
  assert details['components']['worker-resources-metadata-generation-B3']['actual_compiles']==2
  materialize('resources_helper',resource_project/'development/resource_initializer_join_r2.py')
  materialize('evidence_cache',project/'development/evidence_bytes_cache_r1.py')
  materialize('harness',project/'development/digest_harness_r4.py')
  accounted=materialize('accounted',store_project/'development/accounted_full_initializer_r4.py')
  materialize('store_harness',store_project/'development/store_values_harness_r1.py')
  complete=materialize('complete',store_project/'development/test_worker_resources_initializer_r2.py')
  env=dict(os.environ,HIA_DIGEST_ROOT=str(project),HIA_STORE_VALUES_ROOT=str(store_project),HIA_RESOURCE_ROOT=str(resource_project),
   HIA_WORKER_REFERENCE=str(work/'Hepta-agent-edit-native'))
  for group in GROUPS:
   target=store_project/'development'/('ci-'+group+'-r2')
   group_env=dict(env,HIA_ACCOUNTING_OUTPUT=str(output/(group+'-process-accounting.json')))
   panel('worker-store-composition-'+group,
    [sys.executable,'-B',accounted,complete,work,registry_out,target,group],
    target/'summary.json',env=group_env)
 else:details['runtime_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
 restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
 assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
  and digest(Path(row['path']).read_bytes())==row['sha256']
  and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
 assert all(path.read_bytes()==raw for path,raw in submitted.items())
 assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
 details['all_submitted_and_restored_inputs_unchanged']=True
 if compiled and not failures:
  labels=['worker-store-composition-'+g for g in GROUPS]
  assert all(details['components'][label]['status']=='PASS' for label in labels)
  assert details['components']['worker-store-composition-resource-semantic']['cases']==2
  assert details['components']['worker-store-composition-resource-capacity']['cases']==1
  assert details['components']['worker-store-composition-resource-protocol']['cases']==52
  details['new_actual_cases']=sum(details['components'][label]['cases'] for label in labels)
  details['new_actual_native_entries']=sum(details['components'][label]['total_actual_entries'] for label in labels)
  status='PASS'
except BaseException as exc:
 failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
finally:
 details['failures']=failures;roots={}
 if project is not None and project.exists():roots['digest']=project
 if store_project is not None and store_project.exists():roots['store-values-composition']=store_project
 if resource_project is not None and resource_project.exists():roots['resource-peer']=resource_project
 if work is not None:
  base=work/'native-agent-initialization-registry-next'
  if base.exists():roots['initializer-registry']=base
 if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-resource-composition-ci-source'
 common.finish('worker-native-complete-resource-initializer-r2',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
