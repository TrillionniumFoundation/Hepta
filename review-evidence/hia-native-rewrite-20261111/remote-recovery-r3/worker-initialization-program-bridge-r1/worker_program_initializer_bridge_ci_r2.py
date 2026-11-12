"""Fresh complete initializer -> actual native program/assembly bridge CI.

No prior group counts are inherited. Eight remaining initializer peer kinds and
namespace physical effects remain explicit fixtures. All original resource
limits and aggregate process-tree CPU observation apply to each complete group.
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
    "path": "development/test_worker_program_initializer_r2.py",
    "mode": "100644",
    "bytes": 72519,
    "sha256": "a0411a2bcfb67c7e12da90480b19c0a71adce0b642780e8a7969c7f6e35fe1d4",
    "gitsha": "13c11f871013b5a217b8e2dcd6771211520ef9b3"
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
    "path": "compile_worker_init_resources_ci_r3.py",
    "bytes": 6650,
    "sha256": "bd7d9547ac6cf01abe3bffb7353b29fe300deb47eac5b1643a06ea7204b6bd24",
    "gitsha": "6d8095612e26eeae9e456249d37ddb9db6e83205"
  },
  "resources_helper": {
    "path": "development/resource_initializer_join_r3.py",
    "bytes": 20355,
    "sha256": "1997d92ddd96c063407726dd7d514d5312d76c32392f03b03a1a8bdfc80aaed0",
    "gitsha": "68c8ca5e31ec7d6a3518b006ae5792e91c7dcc4a"
  },
  "bridge_compile": {
    "path": "compile_worker_program_bridge_ci_r1.py",
    "mode": "100644",
    "bytes": 10962,
    "sha256": "643664bd2ac358ca61d576ac20e9b0041341687b2f5662d73528f485ae56f2ca",
    "gitsha": "99a4297185ddab4a3ca3d224c2dd9e100ba41c99"
  },
  "bridge_helper": {
    "path": "development/program_initializer_join_r2.py",
    "mode": "100644",
    "bytes": 39838,
    "sha256": "6abf489a20bfc5cff74c96b0602a4595d5345830cdc30d9b38200ba0ed573a9e",
    "gitsha": "395b214aa6e51427afda73f32bd8109a9970c607"
  },
  "program_index": {
    "path": "sources.json",
    "mode": "100644",
    "bytes": 6938,
    "sha256": "0aee57620730b11f2f6ce47bed63aedbc3b166070222e2dbcfb3602f32052d9d",
    "gitsha": "ca7e78bcbdba6b2758a94e2ca1b564dd439da2c7"
  }
}
GROUPS=[
  {
    "name": "program-semantic",
    "cases": 3,
    "actual_program_processes": 9
  },
  {
    "name": "program-failure",
    "cases": 3,
    "actual_program_processes": 6
  },
  {
    "name": "program-capacity",
    "cases": 2,
    "actual_program_processes": 6
  },
  {
    "name": "program-protocol",
    "cases": 121,
    "actual_program_processes": 6
  }
]
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_program_bridge_ci_common',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;own=None;work=None;project=None;store_project=None;resource_project=None
bridge_project=None;program_project=None;submitted={};failures=[];status='FAIL'
details=dict(schema='hia-worker-initializer-program-bridge-ci-r2',
 scope='NEW_INITIALIZER_P16_P17_P18_ACTUAL_PROGRAM_GRAPH_RECORD_BRIDGE_DEVELOPMENT',
 runtime_python_mechanical_transport=True,original_complete_Service_Store_program_assembly_oracle=True,
 expected_fresh_compiles=23,worker_side_native_roles=17,program_context_live_roles=41,
 claimed_distinct_kernel_sum=False,namespace_put_sql_results_are_foreign=True,
 remaining_foreign_initializer_peers=[1,3,4,5,6,7,13,14],actual_namespace_entries=0,
 old_case_counts_inherited=0,old_resources91_and_program113_cases_reexecuted=0,
 groups_1_to_6_and_9_diagnostics_open=True,ordinary_worker_closed=False,
 fixed_whole_initializer_executor_closed=False,production_activation=False,
 cases=0,actual_program_processes=0,new_direct_native_entries=0,components={},
 limits=dict(compiler_cpu_seconds=10,compiler_wall_seconds=20,compiler_address_space_bytes=268435456,
  group_cpu_seconds=90,group_wall_seconds=180,group_address_space_bytes=1073741824,
  aggregate_group_process_tree_cpu_must_be_below90=True))
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def materialize_row(row,target):
 raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=context['repo'])
 assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha']),row['path']
 if target.suffix=='.py':ast.parse(raw,filename=str(target))
 target.parent.mkdir(parents=True,exist_ok=True)
 with target.open('xb') as stream:stream.write(raw)
 target.chmod(0o644);submitted[target]=(raw,0o644);return target
def materialize(key,target):return materialize_row(PINS[key],target)
def panel(label,args,path,timeout=180,env=None,runtime=False):
 success=False
 try:common.run(label,args,timeout=timeout,env=env);success=True
 except BaseException as exc:
  failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
 report=json.loads(path.read_bytes()) if path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
 process_path=Path(context['output'])/'steps'/label/'process.json'
 process=json.loads(process_path.read_bytes()) if process_path.is_file() else None
 accounting=None;cpu_observation=None
 if runtime:
  accounting_path=Path(env['HIA_ACCOUNTING_OUTPUT'])
  if accounting_path.is_file():accounting=json.loads(accounting_path.read_bytes())
 if success and runtime:
  try:
   cpu=process['child_cpu_seconds']
   assert isinstance(cpu,(int,float)) and 0<=cpu<90,('whole_process_tree_cpu',cpu)
   assert accounting is not None,('missing_original_accounting',str(accounting_path))
   fields=('self_user','self_system','children_user','children_system')
   before=accounting['before'];after=accounting['after']
   assert before['pid']==after['pid'] and before['monotonic_ns']<=after['monotonic_ns']
   for snapshot in (before,after):
    assert snapshot['cpu_limit']==[90,90]
    assert snapshot['address_limit']==[1073741824,1073741824]
    assert all(isinstance(snapshot[key],(int,float)) and 0<=snapshot[key]<90 for key in fields)
   assert all(after[key]>=before[key] for key in fields)
   cumulative=sum(after[key] for key in fields)
   interval=sum(after[key]-before[key] for key in fields)
   assert 0<=interval<=cumulative<90,('accounted_self_and_children_cpu',cumulative,interval)
   cpu_observation=dict(external_process_tree_cpu_seconds=cpu,
    accounted_cumulative_self_and_children_seconds=cumulative,
    accounted_interval_self_and_children_seconds=interval,all_original_limits_preserved=True)
  except BaseException as exc:
   failures.append(dict(label=label,error_class='AggregateCpuBudgetObservation',
    actual_external_cpu_seconds=None if process is None else process.get('child_cpu_seconds'),
    error=str(exc),traceback=traceback.format_exc()))
   success=False
 if success and report.get('status')!='PASS':
  failures.append(dict(label=label,error_class='TerminalSummaryMismatch',status=report.get('status')));success=False
 row=dict(actual_successful_process=success,original_summary=report,original_process=process,
  original_accounting=accounting,cpu_observation=cpu_observation)
 details['components'][label]=row
 print('HIA_WORKER_PROGRAM_INITIALIZER_PANEL '+json.dumps(dict(label=label,**row),sort_keys=True),flush=True)
 return success
try:
 context=common.prepare();output=Path(context['output'])
 own=Path(context['base'])/'worker-program-initializer-ci-source-r1';own.mkdir()
 save(output/'worker-program-initializer-submitted.json',dict(pins=PINS,groups=GROUPS,
  driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw)),common_gitsha=COMMON_SHA))
 index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
 restore=materialize('restore',own/'worker_ci_restore_r2.py')
 registry_compile=materialize('registry_compile',own/'compile_worker_init_registry_ci_r2.py')
 digest_compile=materialize('digest_compile',own/'compile_worker_digest_ci_r1.py')
 store_compile=materialize('store_compile',own/'compile_worker_store_values_ci_r2.py')
 resource_compile=materialize('resources_compile',own/'compile_worker_init_resources_ci_r3.py')
 bridge_compile=materialize('bridge_compile',own/'compile_worker_program_bridge_ci_r1.py')
 common.run('worker-program-initializer-exact-dependency-restore',
  [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
 work=Path(context['base'])/'worker-recovery/work-r2'
 registry_out=output/'initializer-registry-eight-compiles'
 project=work/'native-agent-worker-digest-next'
 store_project=work/'native-agent-worker-store-values-next'
 resource_project=work/'native-agent-worker-initialization-resources-next'
 bridge_project=work/'native-agent-worker-program-bridge-next'
 program_project=Path(context['base'])/'worker-program-fixed-for-initializer-r1'
 program_project.mkdir()
 program_index_path=materialize('program_index',program_project/'sources.json')
 program_index=json.loads(program_index_path.read_bytes())
 assert program_index['schema']=='hia-worker-program-source-index-v1'
 assert len(program_index['files'])==15 and program_index['fresh_compiles']==6
 assert program_index['retained_images']==36 and program_index['nonzero_images']==41
 for row in program_index['files']:
  relative=Path(row['path']);assert not relative.is_absolute() and '..' not in relative.parts
  materialize_row(row,program_project/relative)
 compiler=work/'dependencies/f50-B3.image.bin'
 assert (compiler.stat().st_size,digest(compiler.read_bytes()))==(668608,
  '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
 plans=[
  ('eight-peer-generation-B3',[sys.executable,'-B',registry_compile,work,context['repo'],registry_out],
     registry_out/'summary.json',8),
  ('digest-sha-generation-B3',[sys.executable,'-B',digest_compile,work,context['repo'],project,registry_out,context['reference']],
     project/'development/compile-r2/summary.json',2),
  ('store-method-generation-B3',[sys.executable,'-B',store_compile,work,context['repo'],store_project,registry_out,context['reference']],
     store_project/'development/compile-r1/summary.json',1),
  ('resources-metadata-generation-B3',[sys.executable,'-B',resource_compile,work,context['repo'],resource_project,context['workspace']],
     resource_project/'development/compile-r2/summary.json',2),
  ('new-program-bridge-four-B3',[sys.executable,'-B',bridge_compile,work,context['repo'],bridge_project],
     bridge_project/'development/compile-r1/summary.json',4),
  ('fixed-program-six-B3-HIA-packer',[sys.executable,'-B',program_project/program_index['build'],
     '--project',program_project,'--reference',context['reference'],'--workspace',context['workspace'],
     '--compiler',compiler,'--out',program_project/'development/build-r1'],
     program_project/'development/build-r1/summary.json',6)]
 compiled=True;compiles=0
 for suffix,args,summary,expected in plans:
  label='worker-program-initializer-'+suffix
  good=panel(label,args,summary,timeout=300)
  if not good:compiled=False;break
  observed=details['components'][label]['original_summary']['actual_compiles']
  assert observed==expected,(label,observed,expected);compiles+=observed
 details['actual_fresh_compiles']=compiles
 if compiled:
  assert compiles==23
  program_bundle=program_project/'development/build-r1/bundle.json'
  materialize('resources_helper',resource_project/'development/resource_initializer_join_r3.py')
  materialize('evidence_cache',project/'development/evidence_bytes_cache_r1.py')
  materialize('harness',project/'development/digest_harness_r4.py')
  materialize('store_harness',store_project/'development/store_values_harness_r1.py')
  materialize('bridge_helper',bridge_project/'development/program_initializer_join_r2.py')
  accounted=materialize('accounted',own/'accounted_full_initializer_r4.py')
  complete=materialize('complete',bridge_project/'development/test_worker_program_initializer_r2.py')
  env=dict(os.environ,HIA_DIGEST_ROOT=str(project),HIA_STORE_VALUES_ROOT=str(store_project),
   HIA_RESOURCE_ROOT=str(resource_project),HIA_PROGRAM_BRIDGE_ROOT=str(bridge_project),
   HIA_PROGRAM_BUNDLE=str(program_bundle),HIA_WORKER_REFERENCE=str(work/'Hepta-agent-edit-native'))
  for group in GROUPS:
   name=group['name'];target=bridge_project/'development'/('ci-'+name+'-r1')
   label='worker-program-initializer-'+name
   group_env=dict(env,HIA_ACCOUNTING_OUTPUT=str(output/(name+'-accounting.json')))
   good=panel(label,[sys.executable,'-B',accounted,complete,work,registry_out,target,name],
      target/'summary.json',env=group_env,runtime=True)
   if good:
    result=details['components'][label]['original_summary']
    assert result['cases']==result['planned_cases']==group['cases'],(name,result['cases'],group)
    assert result['actual_native_program_processes']==group['actual_program_processes']
    assert result['all_seventeen_roles_actual'] and result['source_unchanged']
    assert result['actual_namespace_entries']==0
    details['cases']+=result['cases']
    details['actual_program_processes']+=result['actual_native_program_processes']
    details['new_direct_native_entries']+=result['total_actual_entries']
 else:details['runtime_groups']='NOT_RUN_DEPENDENCY_OR_NEW_BUILD_DID_NOT_PASS'
 restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
 assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
  and digest(Path(row['path']).read_bytes())==row['sha256']
  and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
 assert all(path.is_file() and path.read_bytes()==raw
  and stat.S_IMODE(path.stat().st_mode)==mode for path,(raw,mode) in submitted.items())
 assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
 details['submitted_and_restored_source_unchanged']=True
 if compiled and not failures:
  assert len(details['components'])==10
  assert all(row['actual_successful_process'] and row['original_summary']['status']=='PASS'
   for row in details['components'].values())
  assert details['cases']==129 and details['actual_program_processes']==27
  status='PASS'
except BaseException as exc:
 failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc),
  traceback=traceback.format_exc()));traceback.print_exc()
finally:
 details['failures']=failures;roots={}
 for label,path in (('digest',project),('store-values',store_project),('resources',resource_project),
     ('program-bridge',bridge_project),('fixed-program',program_project),('submitted-ci-sources',own)):
  if path is not None and path.exists():roots[label]=path
 if work is not None:
  path=work/'native-agent-initialization-registry-next'
  if path.exists():roots['initializer-registry']=path
 common.finish('worker-initializer-program-native-bridge-r2',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
