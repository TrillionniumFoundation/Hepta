"""Author only a fresh r2 immutable request; never import project/control code."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import os
import stat
import sys

ROOT=Path(__file__).resolve().parent
ORIGINAL=ROOT/'reference/original-preserved/experiments/hia_sqlite_varint_20261113/source-authoring-r1'
CANDIDATE=ROOT/'candidate'
RUNTIME=Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12')
OUTPUT=Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e')
IDENTITY_KEYS=('path','bytes','sha256','git_blob','identity')

def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def pin(path):
    before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    raw=path.read_bytes();after=path.lstat()
    assert identity(before)==identity(after) and len(raw)==before.st_size
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'identity':identity(before)}

def wire(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def create(path,body):
    raw=body if isinstance(body,bytes) else wire(body)
    with path.open('xb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    assert path.read_bytes()==raw
    return pin(path)

def main():
    assert sys.version_info[:3]==(3,12,14) and not OUTPUT.exists()
    assert not (ROOT/'REQUEST.json').exists() and not (ROOT/'LAUNCH.json').exists()
    # Only the three physical source-root fields differ from the preserved candidate.
    candidate_rows=[]
    differences=[]
    for old in sorted(ORIGINAL.rglob('*')):
        if not old.is_file():
            continue
        rel=str(old.relative_to(ORIGINAL));new=CANDIDATE/rel
        if rel=='FILES.json':
            continue
        old_raw=old.read_bytes();new_raw=new.read_bytes()
        if old_raw!=new_raw:
            assert rel in ('BASE.json','reference/V92-PHYSICAL-INPUTS.json','reference/RETAINED-CONTROLS.json')
            a=json.loads(old_raw);b=json.loads(new_raw)
            key={'BASE.json':'read_only_source','reference/V92-PHYSICAL-INPUTS.json':'root',
                 'reference/RETAINED-CONTROLS.json':'source_root'}[rel]
            copy=dict(b);copy[key]=a[key]
            assert copy==a and b[key]==str(ROOT/'source-base')
            differences.append({'path':rel,'only_field':key,'before':pin(old),'after':pin(new)})
        p=pin(new)
        candidate_rows.append({'path':rel,**{k:p[k] for k in ('bytes','sha256','git_blob')}})
    assert len(candidate_rows)==35 and len(differences)==3
    file_manifest={'schema':'hia.sqlite-varint.candidate-files.r2','status':'EXACT_CODE_ORIGINAL_ROOT_RELOCATION_ONLY',
        'preserved_source_commit':'7ab75efecb5f00e49fb6b455d7dc119fcddd34e6','candidate_root':str(CANDIDATE),
        'files':candidate_rows,'original_source8_request_state':'UNEXECUTED_PUBLICATION_BOUNDARY_UNKNOWN',
        'historical_authoring_reports_are_not_r2_execution_receipts':True}
    # This is a new local copy. The original 39 canonical bodies remain unchanged.
    (CANDIDATE/'FILES.json').write_bytes(wire(file_manifest))
    create(ROOT/'CANDIDATE-RELOCATION-READBACK.json',{'schema':'hia.sqlite-varint.candidate-relocation-check.v1',
        'code_bodies_unchanged':True,'original_test_body_unchanged':True,'three_physical_root_fields':differences,
        'new_files_manifest':pin(CANDIDATE/'FILES.json'),'source8_executed':False})
    parsed=[]
    for path in sorted((ROOT/'control').glob('*.py')):
        ast.parse(path.read_bytes(),filename=str(path));parsed.append(pin(path))
    assert len(parsed)==5
    assert pin(ROOT/'control/process_owner_impl.py')['sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    assert pin(ROOT/'control/common.py')['sha256']=='4bbf3343b3b48bf30b553a49db4fa9696e50ac48dc86762832bfecbbacb5ff8b'
    test_raw=(CANDIDATE/'inputs/tests/test_hia_sqlite_varint_source.py').read_bytes()
    assert hashlib.sha256(test_raw).hexdigest()=='4101654ceaa24f564fbbb7f78e466bd340cde5d21fded2e206ee521c8e451af4'
    module=ast.parse(test_raw)
    literal=next(n.value for n in module.body if isinstance(n,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=='EXPECTED_NAMES' for t in n.targets))
    names=list(ast.literal_eval(literal))
    cls=next(n for n in module.body if isinstance(n,ast.ClassDef) and n.name=='SQLiteVarintSourceTests')
    assert [n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]==names
    ids=['tests.test_hia_sqlite_varint_source.SQLiteVarintSourceTests.'+n for n in names]
    plan=json.loads((ORIGINAL/'plan/PREEXECUTION-PLAN.json').read_bytes())
    assert ids==plan['source_request']['ordered_expected_ids'] and len(ids)==8
    counts=dict(zip(ids,(0,573,816,36,180,12,1,0)))
    assert sum(counts.values())==plan['source_request']['expected_native_shaped_Core_VM_return_count']==1618
    create(ROOT/'REFERENCE-CONTROLS.json',{'schema':'hia.sqlite-varint.reauthored-controls-provenance.v1',
        'status':'REAUTHORED_CONTROLS_AFTER_ENVIRONMENT_CHANGE','unknown_old_request_replayed':False,
        'original_hold_commit':'7ab75efecb5f00e49fb6b455d7dc119fcddd34e6',
        'reused_common':pin(ROOT/'control/common.py'),'reused_original_owner':pin(ROOT/'control/process_owner_impl.py'),
        'reference_rust_source8_launcher':pin(ROOT/'reference/rust195-source8-r2-launch.original.py'),
        'newly_authored_controls':['control/launch.py','control/worker.py','control/support.py'],
        'no_claim_to_recover_missing_old_control_bodies':True})
    delta=''.join(difflib.unified_diff((ROOT/'reference/rust195-source8-r2-launch.original.py').read_text().splitlines(True),
        (ROOT/'control/launch.py').read_text().splitlines(True),fromfile='retained-rust-source8-r2-launch.original.py',
        tofile='new-sqlite-source8-r2-launch.py'))
    create(ROOT/'LAUNCHER-FROM-RETAINED.diff',delta.encode())
    inputs={}
    selected=list(sorted(CANDIDATE.rglob('*')))+list(sorted((ROOT/'control').glob('*.py')))+[
        ROOT/'reference/rust195-source8-r2-launch.original.py',ROOT/'REFERENCE-CONTROLS.json',
        ROOT/'SOURCE-RELOCATION.json',ROOT/'CANDIDATE-RELOCATION-READBACK.json',
        ROOT/'LAUNCHER-FROM-RETAINED.diff']
    for path in selected:
        if path.is_file():
            p=pin(path)
            inputs[str(path.relative_to(ROOT))]={k:p[k] for k in ('bytes','sha256','git_blob')}
    runtime=pin(RUNTIME)
    assert runtime['bytes']==30894944 and runtime['sha256']=='fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7'
    source=json.loads((CANDIDATE/'reference/V92-PHYSICAL-INPUTS.json').read_bytes())
    assert source['root']==str(ROOT/'source-base') and len(source['files'])==1686
    assert sum(r['bytes'] for r in source['files'])==40890650
    source_observed=[]
    for row in source['files']:
        actual=pin(ROOT/'source-base'/row['path'])
        assert all(actual[k]==row[k] for k in ('bytes','sha256','git_blob'))
        assert ('100755' if actual['identity'][2]&0o111 else '100644')==row['mode']
        source_observed.append(actual)
    env={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'','PYTHONDONTWRITEBYTECODE':'1',
         'PYTHONNOUSERSITE':'1','PYTHONUNBUFFERED':'1'}
    request={'schema':'hia.sqlite-varint.source-eight-request.v2',
        'status':'REAUTHORED_CONTROLS_AFTER_ENVIRONMENT_CHANGE_UNEXECUTED',
        'runtime':runtime,'runtime_version':[3,12,14],
        'source_commit':source['commit'],'source_tree':source['tree'],'source_root':source['root'],
        'source_map':'candidate/reference/V92-PHYSICAL-INPUTS.json','source_file_count':1686,
        'source_total_bytes':40890650,'candidate_root':str(CANDIDATE),'operation_root':str(OUTPUT),
        'qualification_seconds':180,'cleanup_seconds':3,'expected_methods':8,'expected_ids':ids,
        'expected_vm_returns':1618,'expected_vm_by_id':counts,
        'test_module':'tests.test_hia_sqlite_varint_source','environment':env,
        'command':[str(RUNTIME),'-I','-S','-B',str(ROOT/'control/worker.py'),str(ROOT/'REQUEST.json')],
        'inputs':inputs,'minimum_free_bytes':256<<20,'minimum_free_inodes':4096,
        'maximum_output_bytes':16<<20,'maximum_output_regular_files':64,
        'maximum_single_output_bytes':16<<20,'original_compiler_caps':plan['complete_existing_compiler_caps'],
        'product_limits_unchanged':plan['product_limits_unchanged'],
        'old_48_path_publication_replayed':False,'old_mutation_boundary':'UNKNOWN_NOT_REPLAYED',
        'old_source8_executions':0,'new_source8_executions':0,
        'native_execution_permitted':False,'native_compilation_permitted':False,
        'C_oracle_compilation_permitted':False,'network_permitted':False,'SQLite_database_open_permitted':False,
        'scope':'Eight original source/Core-VM methods only; no current native/cold/database/full32 qualification'}
    reqpin=create(ROOT/'REQUEST.json',request)
    launch={'schema':'hia.sqlite-varint.source-eight-launch.v2','status':'FROZEN_UNEXECUTED',
        'request':{k:reqpin[k] for k in ('path','bytes','sha256','git_blob')},
        'command':[str(RUNTIME),'-I','-S','-B',str(ROOT/'control/launch.py')],
        'cwd':str(ROOT),'environment':env,'operation_root':str(OUTPUT),
        'root_review_required_before_execution':True,'no_execution_in_freezer':True,
        'runtime':runtime}
    launchpin=create(ROOT/'LAUNCH.json',launch)
    ast_report={'schema':'hia.sqlite-varint.source8-r2-static-freeze.v1','status':'AST_AND_FULL_INPUT_BYTES_ONLY',
        'control_ast':parsed,'candidate_files':36,'all_code_byte_equal_original':True,
        'expected_ids':ids,'expected_vm_by_id':counts,'expected_vm_returns':1618,
        'source_file_count':len(source_observed),'source_total_bytes':sum(p['bytes'] for p in source_observed),
        'runtime':runtime,'request':reqpin,'launch':launchpin,'project_module_imported':False,
        'generator_executed':False,'source8_executed':False,'native_executed':False}
    create(ROOT/'STATIC-FREEZE.json',ast_report)
    print(json.dumps({'root':str(ROOT),'request':{k:reqpin[k] for k in ('path','bytes','sha256','git_blob')},
                      'launch':{k:launchpin[k] for k in ('path','bytes','sha256','git_blob')},
                      'input_count':len(inputs),'source_count':1686,'methods':8,'VM_planned':1618,
                      'source8_executed':False}))
if __name__=='__main__':
    main()
