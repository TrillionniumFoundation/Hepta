"""New complete Store.json/profile methods with actual initializer continuations.

All original sources and nine compilation results are freshly obtained.
Namespace results are strictly declared fixtures until the real Store issuer
is connected. No prior digest, initializer or Store PASS is inherited.
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
  "store_compile": {
    "path": "compile_worker_store_values_ci_r2.py",
    "bytes": 9672,
    "sha256": "5b9f7220213a4b43fce38024d97d39257a80eb23f2015896f8c0af8b18b234c1",
    "gitsha": "2ab54f0edcce4ef145869543d7c0d1c89463b837"
  },
  "mechanics": {
    "path": "development/digest_harness_r4.py",
    "bytes": 12362,
    "sha256": "9e04554a902050a97c9e0c9449735671d77dd02d8d2090972294b4a205ac7528",
    "gitsha": "bb82b27d0ddad4c37e47431f8b2a775685122f40"
  },
  "harness": {
    "path": "development/store_values_harness_r1.py",
    "bytes": 15468,
    "sha256": "ee46468c8c5f41a3f35668a4b17e75686599536554c5924e0629223917c805e7",
    "gitsha": "49e7bc38ceacefad1d0cb055f3683de7c5b2ea6a"
  },
  "targets": {
    "path": "development/test_worker_store_values_targets_r1.py",
    "bytes": 10332,
    "sha256": "5041539f518c3f61d8e19d5e9d3f2b400894e9506ce040d6da616d665e8992b2",
    "gitsha": "2502fdeaa95ae167c5d1a44f29fdc02b2f0b2de7"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_store_values_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes();context=None;work=None;project=None;submitted={}
failures=[];status='FAIL'
GROUPS=('semantic','errors','protocol','growth','large-value-8m','large-value-over','large-ref-8m')
details=dict(scope='NEW_NATIVE_STORE_JSON_PROFILE_METHODS_AND_ACTUAL_INITIALIZER_CONTINUATIONS',
 groups=list(GROUPS),historical_pass_inheritance=False,previous_digest_cases=0,
 old_initializer_cases=0,actual_physical_namespace_entries=0,
 immutable_same_actual_peer_lease_required=True,controlled_private_graph_issuer=True,
 namespace_result_issuer_is_foreign=True,runtime_mechanical_python=True,
 ordinary_worker_closed=False,ordinary_namespace_closed=False,
 complete_constructor_composition_in_this_gate=False,
 production_activation=False,components={},
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
 result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
 details['components'][label]=result
 print('HIA_WORKER_STORE_VALUES_PANEL '+json.dumps(dict(
  label=label,actual_successful_process=success,original_summary=result),sort_keys=True),flush=True)
 if success and result.get('status')!='PASS':
  failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)));return False
 return success
try:
 context=common.prepare();output=Path(context['output'])
 save(output/'worker-store-values-submitted-source.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
  driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
 own=Path(context['base'])/'worker-store-values-ci-source'
 index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
 restore=materialize('restore',own/'worker_ci_restore_r2.py')
 registry_compile=materialize('registry_compile',own/'compile_worker_init_registry_ci_r2.py')
 store_compile=materialize('store_compile',own/'compile_worker_store_values_ci_r2.py')
 common.run('worker-store-values-exact-dependency-restore',
  [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
 work=Path(context['base'])/'worker-recovery/work-r2'
 registry_out=output/'store-values-registry-eight-compiles'
 compiled=panel('worker-store-values-eight-peer-generation-B3',
  [sys.executable,'-B',registry_compile,work,context['repo'],registry_out],
  registry_out/'summary.json',timeout=300)
 project=work/'native-agent-worker-store-values-next'
 if compiled:
  assert details['components']['worker-store-values-eight-peer-generation-B3']['actual_compiles']==8
  compiled=panel('worker-store-values-generation-B3',
   [sys.executable,'-B',store_compile,work,context['repo'],project,registry_out,context['reference']],
   project/'development/compile-r1/summary.json',timeout=300)
 if compiled:
  assert details['components']['worker-store-values-generation-B3']['actual_compiles']==1
  materialize('mechanics',project/'development/digest_harness_r4.py')
  materialize('harness',project/'development/store_values_harness_r1.py')
  targets=materialize('targets',project/'development/test_worker_store_values_targets_r1.py')
  env=dict(os.environ,HIA_DIGEST_ROOT=str(project),HIA_STORE_VALUES_ROOT=str(project),
   HIA_WORKER_REFERENCE=str(work/'Hepta-agent-edit-native'))
  for group in GROUPS:
   target=project/'development'/('ci-'+group+'-r1')
   panel('worker-store-values-'+group,[sys.executable,'-B',targets,group,target],
    target/'summary.json',env=env)
 else:details['runtime_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
 restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
 assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
  and digest(Path(row['path']).read_bytes())==row['sha256']
  and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
 assert all(path.read_bytes()==raw for path,raw in submitted.items())
 assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
 details['all_submitted_and_restored_inputs_unchanged']=True
 if compiled and not failures:
  labels=['worker-store-values-'+g for g in GROUPS]
  assert all(details['components'][label]['status']=='PASS' for label in labels)
  details['new_actual_cases']=sum(details['components'][label]['cases'] for label in labels)
  details['new_actual_native_entries']=sum(details['components'][label]['total_actual_entries'] for label in labels)
  status='PASS'
except BaseException as exc:
 failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
finally:
 details['failures']=failures;roots={}
 if project is not None and project.exists():roots['store-values']=project
 if work is not None:
  base=work/'native-agent-initialization-registry-next'
  if base.exists():roots['initializer-registry']=base
 if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-store-values-ci-source'
 common.finish('worker-native-store-json-profile-initializer-continuations-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
