"""Fresh initializer sequence with full original order / partial-state oracles.

All nineteen semantic services are explicit foreign fixtures in this gate.
Only the complete sequencing image is under actual HIA ownership. No native
projection, namespace, Path, assembly, or ordinary Worker proof is inherited.
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
  "compile": {
    "path": "compile_worker_init_sequence_ci_r1.py",
    "bytes": 6541,
    "sha256": "a1513e2bdef18fab6c483e73f263eb2a38008a97f3f658ddf9b4a61092a8fceb",
    "gitsha": "fa384acd553e601cc9b2c853a20191b3e8b8251e"
  },
  "tests": {
    "path": "development/test_worker_init_sequence_ci_r2.py",
    "bytes": 30475,
    "sha256": "8d3c0b7bc9c5e069dc4328bf8f41d6171109a759f38597055cca04137484bd32",
    "gitsha": "bcb26cf55309c3bbf78c8142a9d7528fd7db8d7f"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_initialization_sequence_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[];status='FAIL'
GROUPS=('semantic','constructor','profiles','resources','examples','protocol')
details=dict(scope='COMPLETE_INITIALIZATION_SEQUENCE_NATIVE_WITH_ALL_NINETEEN_PEERS_FOREIGN',
    historical_pass_inheritance=False,old_default_DataJSON_cases=0,
    old_read_cases=0,old_worker_records_cases=0,old_journal_cases=0,
    whole_worker_closed=False,ordinary_initialization_closed=False,ordinary_namespace_closed=False,
    all_19_semantic_peers_are_foreign=True,namespace_effects_are_foreign_fixtures=True,
    actual_projection_entries=0,actual_namespace_effects=0,actual_filesystem_effects=0,
    runtime_python_mechanical_transport=True,
    production_activation=False,groups=list(GROUPS),components={},
    limits=dict(test_cpu_seconds=90,test_wall_seconds=180,test_address_space_bytes=1<<30,
        compiler_cpu_seconds=10,compiler_wall_seconds=20,compiler_address_space_bytes=256<<20))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def materialize(name,target):
    row=PINS[name]
    raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=context['repo'])
    assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha']),name
    if target.suffix=='.py':ast.parse(raw,filename=str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb') as stream:stream.write(raw)
    submitted[target]=raw;return target
def panel(label,args,summary_path,timeout=180):
    success=False
    try:
        common.run(label,args,timeout=timeout);success=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
    details['components'][label]=result
    print('HIA_INITIALIZATION_SEQUENCE_PANEL '+json.dumps(dict(label=label,
        actual_successful_process=success,original_summary=result),sort_keys=True),flush=True)
    if success and result.get('status')!='PASS':
        failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)))
        return False
    return success
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'initialization-sequence-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-initialization-sequence-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    compiler=materialize('compile',own/'compile_worker_init_sequence_ci_r1.py')
    tests=materialize('tests',own/'test_worker_init_sequence_ci_r2.py')
    common.run('worker-initialization-sequence-exact-dependency-restore',
        [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    compile_out=output/'initialization-sequence-compile'
    compiled=panel('worker-initialization-sequence-generation-and-original-bounded-B3',
        [sys.executable,'-B',compiler,work,context['repo'],compile_out],
        compile_out/'summary.json',timeout=300)
    if compiled:
        assert details['components']['worker-initialization-sequence-generation-and-original-bounded-B3']['actual_compiles']==1
        for group in GROUPS:
            target=work/'native-agent-initialization-sequence-next/development'/('actual-'+group+'-r1')
            panel('worker-initialization-sequence-'+group,
                [sys.executable,'-B',tests,work,compile_out,target,group],target/'summary.json')
    else:
        details['native_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
    restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
    assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
        and digest(Path(row['path']).read_bytes())==row['sha256']
        and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
    assert all(path.read_bytes()==raw for path,raw in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
    details['all_submitted_and_restored_inputs_unchanged']=True
    if not failures:
        assert compiled and all(details['components']['worker-initialization-sequence-'+g]['status']=='PASS' for g in GROUPS)
        details['new_actual_cases']=sum(details['components']['worker-initialization-sequence-'+g]['cases'] for g in GROUPS)
        details['new_actual_native_entries']=sum(details['components']['worker-initialization-sequence-'+g]['total_actual_entries'] for g in GROUPS)
        status='PASS'
except BaseException as exc:
    failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)))
    traceback.print_exc()
finally:
    details['failures']=failures;roots={}
    if work is not None:
        path=work/'native-agent-initialization-sequence-next'
        if path.exists():roots['initialization-sequence']=path
    if context is not None:
        roots['submitted-ci-sources']=Path(context['base'])/'worker-initialization-sequence-ci-source'
    common.finish('worker-complete-initialization-sequence-native-foreign-peers-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
