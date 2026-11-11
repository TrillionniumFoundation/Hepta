"""Independent new HIA DataJSON value and fixed-schema-pattern component job.

No records/journal/control PASS is rerun or inherited. Pattern and DataGraph
panels are independent; every failed actual child remains a failed result.
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
  "patterns": {
    "path": "compile_and_test_schema_patterns_ci_r1.py",
    "bytes": 10627,
    "sha256": "b375653f1f5026bbdb7b002b72194098674b495fb55d6cad546de796abf6b925",
    "gitsha": "1d5a09b85581c9d485a5678e1b2d7636c5cfe637"
  },
  "data_compile": {
    "path": "compile_data_graph_ci_r1.py",
    "bytes": 7348,
    "sha256": "d3c55f9d10c08171fb6781f956b95999ae75fa31f763983f8a20a3444534ffa7",
    "gitsha": "0f9d91b4c608365339965b1b1b2f192965a9231b"
  },
  "data_tests": {
    "path": "development/test_data_graph_ci_r2.py",
    "bytes": 20501,
    "sha256": "b212d558bbc83e4ae6aa97144491b8956e1b3f0afd03a2670f08ffa0c0691fea",
    "gitsha": "f7c7e2d5d21ebabce9abe6e2568af27484988bff"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_component_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[]
details=dict(scope='NEW_NATIVE_AGENT_DATA_GRAPH_AND_FIXED_PATTERN_COMPONENTS',
             historical_pass_inheritance=False,records_cases=0,journal_groups=0,call_control_cases=0,
             namespace_effects=0,complete_tool_schema_closed=False,public_decode_prefix_closed=False,
             fixed_worker_coordinator=False,whole_worker_closed=False,components={})
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def materialize(name,target):
    row=PINS[name];raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=context['repo'])
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
    result=json.loads(summary_path.read_bytes()) if summary_path.exists() else dict(status='MISSING_TERMINAL_SUMMARY')
    details['components'][label]=result
    if successful:assert result.get('status')=='PASS',result
    return successful
status='FAIL'
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'components-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-components-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    pattern=materialize('patterns',own/'compile_and_test_schema_patterns_ci_r1.py')
    compiler=materialize('data_compile',own/'compile_data_graph_ci_r1.py')
    tests=materialize('data_tests',own/'test_data_graph_ci_r2.py')
    common.run('worker-components-exact-dependency-restore',[sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    pattern_out=output/'schema-patterns'
    panel('worker-fixed-patterns-complete-native',[sys.executable,'-B',pattern,work,context['repo'],pattern_out],
          pattern_out/'summary.json')
    compile_out=output/'data-graph-compile'
    compiled=panel('worker-data-graph-full-generation-and-bounded-B3',
        [sys.executable,'-B',compiler,work,context['repo'],compile_out],compile_out/'summary.json')
    if compiled:
        for group in ('semantic','protocol','large'):
            target=work/'native-agent-data-graph-next/development'/('actual-'+group+'-r1')
            panel('worker-data-graph-'+group,[sys.executable,'-B',tests,work,compile_out,target,group],target/'summary.json')
    else:
        details['data_graph_native_groups']='NOT_RUN_GENERATION_OR_COMPILATION_FAILED'
    restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
    assert all(Path(r['path']).is_file() and Path(r['path']).stat().st_size==r['bytes']
      and digest(Path(r['path']).read_bytes())==r['sha256']
      and stat.S_IMODE(Path(r['path']).stat().st_mode)==r['mode'] for r in restored)
    assert all(p.read_bytes()==raw for p,raw in submitted.items())
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
        for label,name in (('patterns','native-agent-schema-next'),('data-graph','native-agent-data-graph-next')):
            path=work/name
            if path.exists():roots[label]=path
    if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-components-ci-source'
    common.finish('worker-new-data-graph-and-schema-patterns-development-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
