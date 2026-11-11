"""Fresh complete call-control authoring and controlled native continuations.

Foreign semantic peers are explicit fixtures, never a production fallback.
This job does not rerun the passed records or journal semantic groups.
"""
from __future__ import annotations
import ast
from hashlib import sha1,sha256
import importlib.util,json,os,stat,subprocess,sys,traceback
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
    "path": "compile_call_control_ci_r3.py",
    "bytes": 6163,
    "sha256": "1f724b02392642ecd8f99c9a1403b7a36728bffe170f87cda762758a850020c9",
    "gitsha": "cea0f3461738254a07834da83d27f79d1e0876d0"
  },
  "tests": {
    "path": "development/test_call_control_ci_r3.py",
    "bytes": 27861,
    "sha256": "3b6075e50e7400cb2e988fe34e551fcfd4a6e95b3f9173b9743f75d39d478c59",
    "gitsha": "278fff556e6613d27239885bd6ac96a8c5469c71"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_call_common_ci',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;control=None;submitted={}
details=dict(scope='NEW_ACTUAL_CALL_CONTROL_WITH_FOREIGN_FIXTURES_NOT_WHOLE_WORKER',
             historical_pass_inheritance=False,records_cases=0,journal_semantic_groups=0,
             namespace_effects=0,schema_peer_qualified=False,business_peer_qualified=False,
             full_worker_closed=False,expected_control_cases=184,old_records_and_journal_passes_not_newly_counted=True)
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def materialize(name,target):
    row=PINS[name]
    raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=context['repo'])
    assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha']),name
    if target.suffix=='.py':ast.parse(raw,filename=str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    assert not target.exists(),str(target)
    with target.open('xb') as f:f.write(raw)
    submitted[target]=raw
    return target
status='FAIL'
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'call-control-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
         driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-call-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    compiler=materialize('compile',own/'compile_call_control_ci_r3.py')
    tests=materialize('tests',own/'test_call_control_ci_r3.py')
    common.run('worker-call-exact-dependency-restore',[sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    control=work/'native-agent-service-call-control-next'
    compiled=output/'call-control-compile'
    common.run('worker-call-complete-generation-and-bounded-B3',[sys.executable,'-B',compiler,work,context['repo'],compiled],timeout=180)
    generation=json.loads((compiled/'summary.json').read_bytes())
    assert generation['status']=='PASS'
    assert generation['native_control_entries']==0 and generation['source_unchanged']
    common.run('worker-call-original-control-and-native-continuations',[sys.executable,'-B',tests,work,compiled,
               control/'development/controlled-native-ci-r1'],timeout=180)
    summary=json.loads((control/'development/controlled-native-ci-r1/summary.json').read_bytes())
    assert summary['status']=='PASS' and summary['cases']==184 and summary['entries']>0,summary
    assert summary['fixture_peers_only'] is True and summary['whole_worker_closed'] is False
    assert summary['namespace_effects']==0 and summary['source_unchanged']
    details.update(generation=generation,actual_control=summary)
    input_pins=json.loads((output/'worker-restore/input-pins.json').read_bytes())
    assert all(Path(r['path']).is_file() and Path(r['path']).stat().st_size==r['bytes']
      and digest(Path(r['path']).read_bytes())==r['sha256']
      and stat.S_IMODE(Path(r['path']).stat().st_mode)==r['mode'] for r in input_pins)
    assert all(p.read_bytes()==raw for p,raw in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
    details['all_submitted_and_restored_inputs_unchanged']=True
    print(json.dumps(dict(scope=details['scope'],actual_control=summary),sort_keys=True),flush=True)
    status='PASS'
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    if control is not None:
        p=control/'development/controlled-native-ci-r1/summary.json'
        if p.exists():details['actual_partial_control']=json.loads(p.read_bytes())
    traceback.print_exc()
finally:
    roots={}
    if control is not None and control.exists():roots['call-control']=control
    if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-call-ci-source'
    common.finish('worker-complete-call-control-development-ci-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
