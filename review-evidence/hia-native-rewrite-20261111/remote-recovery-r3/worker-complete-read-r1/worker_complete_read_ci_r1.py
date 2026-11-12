"""Fresh complete hia_read HIA business qualification with exact dependencies.

The complete original namespace ABI is restored and checked before operation
numbers are bound at authoring time. Actual read, wire, and SHA images execute;
high-level Store.get and cursor SQL remain explicitly controlled foreign peers.
No original Worker/records/request/journal result is reused as a new PASS.
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
  "namespace_reader": {
    "path": "read_namespace_original_source_r1.py",
    "bytes": 5734,
    "sha256": "adc1ffa9f8f1f15cb79e8d071b3be5780ec543c2266c85d2b9f790cd2b9fb932",
    "gitsha": "c5c74f927601ce4d2999524b2ea1884262edca12"
  },
  "compile": {
    "path": "compile_hia_read_ci_r2.py",
    "bytes": 9070,
    "sha256": "1161145a458e142eb599d639e9987d091c69bba0ff3a3186d7d5e471f3495c61",
    "gitsha": "6179fa170644eed650e01665b46921268d7e22ae"
  },
  "tests": {
    "path": "development/test_hia_read_ci_r2.py",
    "bytes": 28670,
    "sha256": "0989d6431729dc6a23f4faf84035096f217edb929f182a691836317d4c6ae27e",
    "gitsha": "cfa452ed967b6b9c8b3edbfb7ffa55e6a49788d5"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_read_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[];status='FAIL'
GROUPS=('semantic','unicode','storage','wire','large','protocol')
details=dict(scope='COMPLETE_HIA_READ_BUSINESS_WITH_PENDING_NAMESPACE',
    historical_pass_inheritance=False,old_records_cases=0,old_journal_cases=0,
    old_call_control_cases=0,new_namespace_effects=0,whole_worker_closed=False,
    ordinary_namespace_closed=False,runtime_python_fixture_dispatch=True,
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
    submitted[target]=raw
    return target
def panel(label,args,summary_path,timeout=180):
    success=False
    try:
        common.run(label,args,timeout=timeout);success=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
    details['components'][label]=result
    print('HIA_READ_PANEL '+json.dumps(dict(label=label,actual_successful_process=success,
        original_summary=result),sort_keys=True),flush=True)
    if success and result.get('status')!='PASS':
        failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)))
        return False
    return success
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'read-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-read-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    abi_reader=materialize('namespace_reader',own/'read_namespace_original_source_r1.py')
    compiler=materialize('compile',own/'compile_hia_read_ci_r2.py')
    tests=materialize('tests',own/'test_hia_read_ci_r2.py')
    common.run('worker-read-exact-dependency-restore',
        [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    abi_out=output/'namespace-original-source'
    common.run('worker-read-exact-namespace-ABI-readback',
        [sys.executable,'-B',abi_reader,'--repo',context['source'],'--out',abi_out],timeout=180)
    abi=abi_out/'HIA_AGENT_NAMESPACE_STORE_ABI.original.json'
    abi_raw=abi.read_bytes()
    assert (len(abi_raw),digest(abi_raw))==(51264,
        'c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04')
    original_abi=json.loads((abi_out/'summary.json').read_bytes())
    assert original_abi['status']=='PASS_READBACK_ONLY' and original_abi['all_original_inputs_unchanged']
    details['original_namespace_abi_readback']=original_abi
    compile_out=output/'read-compile'
    compiled=panel('worker-read-generation-and-original-bounded-B3',
        [sys.executable,'-B',compiler,work,context['repo'],compile_out,abi],
        compile_out/'summary.json',timeout=300)
    if compiled:
        assert details['components']['worker-read-generation-and-original-bounded-B3']['actual_compiles']==5
        for group in GROUPS:
            target=work/'native-agent-read-next/development'/('actual-'+group+'-r1')
            panel('worker-read-'+group,
                [sys.executable,'-B',tests,work,compile_out,target,group],target/'summary.json')
    else:
        details['native_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
    restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
    assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
        and digest(Path(row['path']).read_bytes())==row['sha256']
        and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
    assert abi.read_bytes()==abi_raw
    assert all(path.read_bytes()==raw for path,raw in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
    details['all_submitted_and_restored_inputs_unchanged']=True
    if not failures:
        assert compiled and all(details['components']['worker-read-'+g]['status']=='PASS' for g in GROUPS)
        details['new_actual_cases']=sum(details['components']['worker-read-'+g]['cases'] for g in GROUPS)
        details['new_actual_native_entries']=sum(details['components']['worker-read-'+g]['total_actual_entries'] for g in GROUPS)
        status='PASS'
except BaseException as exc:
    failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)))
    traceback.print_exc()
finally:
    details['failures']=failures
    roots={}
    if work is not None:
        path=work/'native-agent-read-next'
        if path.exists():roots['read']=path
    if context is not None:
        roots['submitted-ci-sources']=Path(context['base'])/'worker-read-ci-source'
    common.finish('worker-complete-hia-read-business-development-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
