"""Fresh actual Worker digest peer and complete initializer native join.

This is independent new CI evidence. The interrupted local smoke is historical
only, and neither its count nor previously passed registry cases are inherited.
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
    "path": "development/digest_harness_r3.py",
    "bytes": 12319,
    "sha256": "676c330fe8838ae255bddcbdcb2a7e199edcd93c337f960d7025710ee95cd821",
    "gitsha": "70d5c3252e56fb6cdfcdb4a50a64678655894bb6"
  },
  "targets": {
    "path": "development/test_worker_digest_targets_r2.py",
    "bytes": 12872,
    "sha256": "3f7c14581cceba5d52cc2cf6b6858a30febeed8c7478e373318457406efd8287",
    "gitsha": "7faa299cca20707169eb03f67719ab504f93fde5"
  },
  "complete": {
    "path": "development/test_worker_digest_complete_initializer_r1.py",
    "bytes": 51813,
    "sha256": "1369f37484a7af5a43380ba1ebb2c4e61d0640864e0e3e812913dd43c552041f",
    "gitsha": "8528177112edf9af8fe9dd511a730a4fd207269f"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_digest_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes();context=None;work=None;project=None;submitted={}
failures=[];status='FAIL'
GROUPS=('semantic','initializer','protocol','chunks','large-1m','large-8m','large-over')
details=dict(scope='NEW_NATIVE_DIGEST_AND_COMPLETE_INITIALIZER_COMPOSITION',groups=list(GROUPS),
 historical_pass_inheritance=False,old_local_smoke_count_in_new_results=0,
 old_registry_cases=0,old_purejoin_cases=0,namespace_entries=0,
 immutable_same_actual_peer_lease_required=True,controlled_private_graph_issuer=True,
 runtime_mechanical_python=True,ordinary_worker_closed=False,ordinary_namespace_closed=False,
 remaining_initializer_foreign_peer_count=14,production_activation=False,components={},
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
 print('HIA_WORKER_DIGEST_PANEL '+json.dumps(dict(label=label,actual_successful_process=success,original_summary=result),sort_keys=True),flush=True)
 if success and result.get('status')!='PASS':
  failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)));return False
 return success
try:
 context=common.prepare();output=Path(context['output'])
 save(output/'worker-digest-submitted-source.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
  driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
 own=Path(context['base'])/'worker-digest-ci-source'
 index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
 restore=materialize('restore',own/'worker_ci_restore_r2.py')
 registry_compile=materialize('registry_compile',own/'compile_worker_init_registry_ci_r2.py')
 digest_compile=materialize('digest_compile',own/'compile_worker_digest_ci_r1.py')
 common.run('worker-digest-exact-dependency-restore',
  [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
 work=Path(context['base'])/'worker-recovery/work-r2'
 registry_out=output/'digest-registry-eight-compiles'
 compiled=panel('worker-digest-eight-peer-generation-B3',
  [sys.executable,'-B',registry_compile,work,context['repo'],registry_out],
  registry_out/'summary.json',timeout=300)
 project=work/'native-agent-worker-digest-next'
 if compiled:
  assert details['components']['worker-digest-eight-peer-generation-B3']['actual_compiles']==8
  compiled=panel('worker-digest-sha-and-controller-generation-B3',
   [sys.executable,'-B',digest_compile,work,context['repo'],project,registry_out,context['reference']],
   project/'development/compile-r2/summary.json',timeout=300)
 if compiled:
  assert details['components']['worker-digest-sha-and-controller-generation-B3']['actual_compiles']==2
  harness=materialize('harness',project/'development/digest_harness_r3.py')
  targets=materialize('targets',project/'development/test_worker_digest_targets_r2.py')
  complete=materialize('complete',project/'development/test_worker_digest_complete_initializer_r1.py')
  env=dict(os.environ,HIA_DIGEST_ROOT=str(project),HIA_WORKER_REFERENCE=str(work/'Hepta-agent-edit-native'))
  for group in GROUPS:
   target=project/'development'/('ci-'+group+'-r1')
   panel('worker-digest-'+group,[sys.executable,'-B',targets,group,target],target/'summary.json',env=env)
  target=project/'development/ci-complete-initializer-r1'
  panel('worker-digest-complete-initializer',
   [sys.executable,'-B',complete,work,registry_out,target,'complete-digest'],target/'summary.json',env=env)
 else:details['runtime_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
 restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
 assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
  and digest(Path(row['path']).read_bytes())==row['sha256']
  and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
 assert all(path.read_bytes()==raw for path,raw in submitted.items())
 assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
 details['all_submitted_and_restored_inputs_unchanged']=True
 if compiled and not failures:
  labels=['worker-digest-'+g for g in GROUPS]+['worker-digest-complete-initializer']
  assert all(details['components'][label]['status']=='PASS' for label in labels)
  details['new_actual_cases']=sum(details['components'][label]['cases'] for label in labels)
  details['new_actual_native_entries']=sum(details['components'][label]['total_actual_entries'] for label in labels)
  status='PASS'
except BaseException as exc:
 failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
finally:
 details['failures']=failures;roots={}
 if project is not None and project.exists():roots['digest']=project
 if work is not None:
  base=work/'native-agent-initialization-registry-next'
  if base.exists():roots['initializer-registry']=base
 if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-digest-ci-source'
 common.finish('worker-native-store-wire-digest-complete-initializer-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
