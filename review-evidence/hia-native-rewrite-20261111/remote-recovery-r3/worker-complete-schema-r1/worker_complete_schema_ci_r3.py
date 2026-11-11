"""Remaining schema r3 gates, with exact old/new initial-state differential.

The 1702 cases and 11985 native entries already completed in r2 are historical.
They are not rerun or counted here. The first r2 large-group SIGKILL at the
unchanged 90 CPU seconds and the protocol fixture failure remain preserved.
This revision changes only ASCII span handling in full initial string validation,
normalizes test bytearray buffers to exact bytes, and adds pre-entry progress.
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
  "schema_compile": {
    "path": "compile_complete_schema_ci_r4.py",
    "bytes": 11816,
    "sha256": "0c3e49f52da29cc9e98ba80c9f9757cf04ed12770ab5da0c2cc2f1655371c670",
    "gitsha": "7e9cdb6c9f4030d6d669e29079603b52f10ed2ff"
  },
  "schema_tests": {
    "path": "development/test_complete_schema_ci_r2.py",
    "bytes": 32948,
    "sha256": "c41de7121c4dbde203489fa5bca74af907099e266478acfb3f52d3b317fdb3a6",
    "gitsha": "f3c159cde18c0c84f224431eef84949ade828874"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_schema_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[];status='FAIL'
details=dict(scope='NEW_COMPLETE_FIXED_CATALOG_HIA_SCHEMA_WITH_ACTUAL_WIRE_AND_PATTERN',
    historical_pass_inheritance=False,records_cases=0,journal_groups=0,call_control_cases=0,
    prior_r2_completed_cases_not_rerun=1702,prior_r2_completed_entries_not_rerun=11985,
    public_decode_prefix_closed=False,fixed_worker_coordinator=False,namespace_effects=0,
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
    print(json.dumps(dict(event='COMPLETE_SCHEMA_PANEL',label=label,actual_successful_process=successful,
                          original_summary=result),sort_keys=True),flush=True)
    if successful and result.get('status')!='PASS':
        failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)))
        return False
    return successful
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'complete-schema-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-complete-schema-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    compiler=materialize('schema_compile',own/'compile_complete_schema_ci_r4.py')
    tests=materialize('schema_tests',own/'test_complete_schema_ci_r2.py')
    common.run('worker-schema-exact-dependency-restore',
        [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    compile_out=output/'complete-schema-compile'
    compiled=panel('worker-complete-schema-generation-and-original-bounded-B3',
        [sys.executable,'-B',compiler,work,context['repo'],compile_out],compile_out/'summary.json',timeout=300)
    if compiled:
        for group in ('paired','large','protocol'):
            target=work/'native-agent-schema-complete-next/development'/('actual-'+group+'-r3')
            panel('worker-complete-schema-'+group,
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
        path=work/'native-agent-schema-complete-next'
        if path.exists():roots['complete-schema']=path
    if context is not None:
        roots['submitted-ci-sources']=Path(context['base'])/'worker-complete-schema-ci-source'
    common.finish('worker-complete-fixed-catalog-schema-remaining-development-r3',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
