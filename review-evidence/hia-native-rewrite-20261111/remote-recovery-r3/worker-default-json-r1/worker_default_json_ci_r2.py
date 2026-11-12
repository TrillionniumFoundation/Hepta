"""First complete ordinary default DataJSON prefix component qualification.

No previous DataGraph, pattern, schema, request, records or journal PASS is
inherited or rerun as its own qualification. Seven real HIA peers are freshly
compiled and all default-path groups below have new execution identities.
Failure of one group is retained while the remaining independent groups run.
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
    "path": "compile_default_json_ci_r3.py",
    "bytes": 9863,
    "sha256": "4ef11d798f6d4e5e804ffe07b8c0b3e0e8a3a5722ef75dc641183e9301f93158",
    "gitsha": "d8b4890e813d8dd92ac6df461a9f5b1d11350906"
  },
  "tests": {
    "path": "development/test_default_json_ci_r1.py",
    "bytes": 30925,
    "sha256": "8fc80813b37970f917940549345d880de1115603ce93e31019300e97187b7065",
    "gitsha": "2cfb300f79b63a1be5fdb24e04851b51b6510f1c"
  },
  "doc": {
    "path": "docs/HIA_AGENT_DEFAULT_JSON_CONTROLLER.md",
    "bytes": 9619,
    "sha256": "5f590790d58c7b9679e7ae8502c73aa2e70cb6a460e6eddbf9dfa18545b318c3",
    "gitsha": "bc27825e9a2e7fef6afa7ff481a0de79ed0a4641"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_default_json_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[];status='FAIL'
details=dict(scope='NEW_COMPLETE_ORDINARY_DEFAULT_DATAJSON_WITH_ACTUAL_PEERS',
    historical_pass_inheritance=False,records_cases=0,journal_groups=0,call_control_cases=0,
    public_decode_prefix_closed=False,fixed_worker_coordinator=False,namespace_effects=0,
    previous_data_graph_or_schema_pass_inheritance=False,selected_data_json_profile_equivalence=False,
    whole_worker_closed=False,production_activation=False,components={},
    test_cpu_seconds=90,test_address_space_bytes=1<<30,
    compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
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
    successful=False
    try:
        common.run(label,args,timeout=timeout)
        successful=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
    details['components'][label]=result
    print(json.dumps(dict(event='DEFAULT_JSON_PANEL',label=label,actual_successful_process=successful,
                          original_summary=result),sort_keys=True),flush=True)
    if successful and result.get('status')!='PASS':
        failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)))
        return False
    return successful
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'default-json-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-default-json-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    compiler=materialize('compile',own/'compile_default_json_ci_r3.py')
    tests=materialize('tests',own/'test_default_json_ci_r1.py')
    documentation=materialize('doc',own/'HIA_AGENT_DEFAULT_JSON_CONTROLLER.md')
    common.run('worker-default-json-exact-dependency-restore',
        [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    compile_out=output/'default-json-compile'
    compiled=panel('worker-default-json-generation-and-original-bounded-B3',
        [sys.executable,'-B',compiler,work,context['repo'],compile_out],compile_out/'summary.json',timeout=300)
    if compiled:
        for group in ('semantic','unicode','digits','depth','large-utf8','large-values','large-nodes','large-digits','protocol'):
            target=work/'native-agent-default-json-next/development'/('actual-'+group+'-r1')
            panel('worker-default-json-'+group,
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
    if not failures:status='PASS'
except BaseException as exc:
    failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)))
    traceback.print_exc()
finally:
    details['failures']=failures
    roots={}
    if work is not None:
        path=work/'native-agent-default-json-next'
        if path.exists():roots['default-json']=path
    if context is not None:
        roots['submitted-ci-sources']=Path(context['base'])/'worker-default-json-ci-source'
    common.finish('worker-default-datajson-complete-prefix-development-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
