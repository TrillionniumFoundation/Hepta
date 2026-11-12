"""Independent complete fixed native default-DataJSON component CI.

No default/Worker selector changes. Each actual run first reconstructs exact
dependencies, freshly compiles all seven semantic peers, compiles the new HIA
forwarding/packing owners, then runs independent native ELF and private protocol
groups. Original failures and every independent later result remain separate.
"""
from __future__ import annotations
import ast,base64,importlib.util,json,os,stat,subprocess,sys,traceback
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
  "peer_compile": {
    "path": "compile_default_json_ci_r3.py",
    "bytes": 9863,
    "sha256": "4ef11d798f6d4e5e804ffe07b8c0b3e0e8a3a5722ef75dc641183e9301f93158",
    "gitsha": "d8b4890e813d8dd92ac6df461a9f5b1d11350906"
  },
  "reference_fixture": {
    "path": "development/test_default_json_ci_r1.py",
    "bytes": 30925,
    "sha256": "8fc80813b37970f917940549345d880de1115603ce93e31019300e97187b7065",
    "gitsha": "2cfb300f79b63a1be5fdb24e04851b51b6510f1c"
  },
  "build": {
    "path": "build_default_json_fixed_ci_r2.py",
    "bytes": 13078,
    "sha256": "0804ae727201d8d60843d8b39dda91932007a1146aa3e31306ecfdffe380ec2c",
    "gitsha": "c0a567c501881d1897982b9fe182f334880fb045"
  },
  "tests": {
    "path": "development/test_default_json_fixed_ci_r3.py",
    "bytes": 25274,
    "sha256": "2e4c832af17fe731f9a5444841258d941a7adb5f4c2dbbf3b007b57634297892",
    "gitsha": "2b43954c8d062ad1d152dccae04da7787b34369a"
  },
  "doc": {
    "path": "docs/HIA_DEFAULT_JSON_FIXED_COMPONENT_R1.md",
    "bytes": 9976,
    "sha256": "9209ec700e0b20220ce317b676825a1b5db2f56d8871814923ff135337de20e8",
    "gitsha": "7846eac071b948d8b69243ed63bb35770db1c615"
  }
}
COMMON_SHA='61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e'
COMMON=Path(os.environ['HIA_CI_COMMON']).resolve()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
common_raw=COMMON.read_bytes();assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location('worker_fixed_default_ci_common',COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None;submitted={};failures=[];status='FAIL'
details=dict(scope='NEW_FIXED_NATIVE_DEFAULT_DATAJSON_PRIVATE_COMPONENT',
    runtime_python_dispatch=False,ordinary_eleven_tool_worker=False,
    old_component_groups_inherited=False,records_cases=0,journal_groups=0,namespace_effects=0,
    whole_worker_closed=False,production_activation=False,components={},
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
    with target.open('xb') as out:out.write(raw)
    submitted[target]=raw
    return target

def export_request_report_originals(work,output):
    """Read only the independently restored R13/R14 originals; no test import."""
    root=work/'native-agent-worker-next'
    destination=output/'worker-request-report-originals'
    destination.mkdir(parents=True,exist_ok=False)
    selected=[];inventory=[]
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        relative=path.relative_to(root);name=path.name.lower()
        if relative.parts[0] not in ('tools','docs','development','examples'):continue
        if relative.parts[0]=='development' and (len(relative.parts)!=2 or 'harness' not in name):continue
        if relative.parts[0] in ('tools','docs','examples') and len(relative.parts)>4:continue
        if path.suffix not in ('.py','.md','.json','.hiaasm'):continue
        inventory.append(relative.as_posix())
        if 'request' not in name and 'report' not in name:continue
        before_mode=stat.S_IMODE(path.stat().st_mode);raw=path.read_bytes()
        row=dict(path=relative.as_posix(),original_path=str(path),bytes=len(raw),
                 sha256=digest(raw),gitsha=gitsha(raw),mode=before_mode)
        target=destination/relative;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as handle:handle.write(raw)
        target.chmod(before_mode)
        assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==before_mode
        assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==before_mode
        selected.append(row)
        # Small authoring/doc/mechanical fixture text is recoverable directly
        # from the log too. Generated HIA is archived without another log copy.
        if path.suffix!='.hiaasm':
            raw.decode('utf-8')
            print(json.dumps(dict(event='HIA_WORKER_SOURCE_EXPORT',**row,
                base64=base64.b64encode(raw).decode('ascii')),sort_keys=True),flush=True)
    manifest=dict(scope='READ_ONLY_EXACT_RESTORED_REQUEST_REPORT_ORIGINALS',
        selected=selected,available_source_paths=inventory,native_entries=0,
        old_tests_imported_or_executed=False,
        all_original_and_copy_bytes_sha_mode_before_after_equal=True)
    save(destination/'manifest.json',manifest)
    details['request_report_original_export']=manifest

def panel(label,args,summary_path,timeout=180):
    ok=False
    try:
        common.run(label,args,timeout=timeout);ok=True
    except BaseException as exc:
        failures.append(dict(label=label,error_class=type(exc).__name__,error=str(exc)))
        traceback.print_exc()
    result=json.loads(summary_path.read_bytes()) if summary_path.is_file() else dict(status='MISSING_TERMINAL_SUMMARY')
    details['components'][label]=result
    print(json.dumps(dict(event='FIXED_DEFAULT_JSON_PANEL',label=label,actual_process_success=ok,
        original_summary=result),sort_keys=True),flush=True)
    if ok and result.get('status')!='PASS':
        failures.append(dict(label=label,error_class='TerminalSummaryMismatch',error=str(result)));return False
    return ok
try:
    context=common.prepare();output=Path(context['output'])
    save(output/'fixed-default-submitted-inputs.json',dict(common_git_sha=COMMON_SHA,pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context['base'])/'worker-fixed-default-json-ci-source'
    index=materialize('dependency_index',own/'worker_ci_dependencies_r4.json')
    restore=materialize('restore',own/'worker_ci_restore_r2.py')
    peer_compile=materialize('peer_compile',own/'compile_default_json_ci_r3.py')
    component_reference=materialize('reference_fixture',own/'default_component_reference_fixture.py')
    build=materialize('build',own/'build_default_json_fixed_ci_r2.py')
    tests=materialize('tests',own/'test_default_json_fixed_ci_r3.py')
    materialize('doc',own/'HIA_DEFAULT_JSON_FIXED_COMPONENT_R1.md')
    common.run('fixed-default-exact-dependency-restore',
        [sys.executable,'-B',restore,output/'context.json',index],timeout=300)
    work=Path(context['base'])/'worker-recovery/work-r2'
    export_request_report_originals(work,output)
    compile_out=output/'default-json-peer-compile'
    peers_ok=panel('fixed-default-fresh-seven-peer-compiles',
        [sys.executable,'-B',peer_compile,work,context['repo'],compile_out],
        compile_out/'summary.json',timeout=300)
    build_out=output/'fixed-default-build'
    if peers_ok:
        build_ok=panel('fixed-default-generation-B3-actual-HIA-pack',
            [sys.executable,'-B',build,work,context['repo'],compile_out,build_out],
            build_out/'summary.json',timeout=300)
        if build_ok:
            for group in ('semantic','unicode','boundaries','byte-reference','framing','protocol',
                          'large-values','large-order','large-nodes'):
                target=work/'native-agent-default-json-fixed-next/development'/('actual-'+group+'-r1')
                panel('fixed-default-'+group,
                    [sys.executable,'-B',tests,work,build_out,target,group,component_reference],
                    target/'summary.json')
        else:details['actual_executable_groups']='NOT_RUN_BUILD_FAILED'
    else:details['actual_executable_groups']='NOT_RUN_PEER_COMPILE_FAILED'
    restored=json.loads((output/'worker-restore/input-pins.json').read_bytes())
    assert all(Path(row['path']).is_file() and Path(row['path']).stat().st_size==row['bytes']
        and digest(Path(row['path']).read_bytes())==row['sha256']
        and stat.S_IMODE(Path(row['path']).stat().st_mode)==row['mode'] for row in restored)
    assert all(path.read_bytes()==raw for path,raw in submitted.items())
    assert COMMON.read_bytes()==common_raw and Path(__file__).read_bytes()==self_raw
    details['all_submitted_and_restored_inputs_unchanged']=True
    if not failures:status='PASS'
except BaseException as exc:
    failures.append(dict(label='driver',error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
finally:
    details['failures']=failures
    roots={}
    if context is not None:roots['submitted-ci-sources']=Path(context['base'])/'worker-fixed-default-json-ci-source'
    if work is not None:
        for name,relative in (('fixed-default','native-agent-default-json-fixed-next'),
                              ('default-peers','native-agent-default-json-next')):
            root=work/relative
            if root.exists():roots[name]=root
    common.finish('worker-fixed-native-default-json-development-r1',status,details,roots=roots)
if status!='PASS':raise SystemExit(1)
