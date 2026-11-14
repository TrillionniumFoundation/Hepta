"""Repair only the omitted pinned harness path after the immutable R16 attempt-1 failure."""
from pathlib import Path
import base64, hashlib, json, shutil, stat, tarfile

ROOT = Path(__file__).resolve().parent
OLD = ROOT / 'formal-preparation-r2'
NEW = ROOT / 'formal-preparation-r3'
FAIL = ROOT.parent / 'v103-source-parser-r16-original'

def oid(kind, raw):
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':oid('blob',raw)}

def dump(path, value):
    data=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        assert path.read_bytes()==data,str(path)
    else:
        path.write_bytes(data)

def tree(rows):
    root={}
    for name,row in rows.items():
        node=root
        parts=name.split('/')
        for part in parts[:-1]: node=node.setdefault(part,{})
        assert parts[-1] not in node
        node[parts[-1]]=row['git_blob']
    def rec(node):
        chunks=[]
        for name,value in sorted(node.items(),key=lambda item:(item[0]+('/' if isinstance(item[1],dict) else '')).encode()):
            mode='40000' if isinstance(value,dict) else '100644'
            sha=rec(value) if isinstance(value,dict) else value
            chunks.append(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha))
        return oid('tree',b''.join(chunks))
    return rec(root)

def main():
    assert not NEW.exists(), 'new revision must be exclusive'
    NEW.mkdir()
    shutil.copytree(OLD/'harness',NEW/'harness')
    old_manifest=json.loads((OLD/'HARNESS-MANIFEST.json').read_bytes())
    for name,p in old_manifest.items():
        assert pin((NEW/'harness'/name).read_bytes())=={k:p[k] for k in ('bytes','sha256','git_blob')},name
    alias='tools/materialize_candidate_r16.py'
    data=(NEW/'harness/tools/materialize_candidate.py').read_bytes()
    (NEW/'harness'/alias).write_bytes(data)
    plan=json.loads((NEW/'harness/inputs/MATERIALIZATION.json').read_bytes())
    closure=[]
    for p in plan['harness_files']:
        body=(NEW/'harness'/p['path']).read_bytes()
        assert len(body)==p['bytes'] and oid('blob',body)==p['blob'],p['path']
        if 'sha256' in p: assert hashlib.sha256(body).hexdigest()==p['sha256']
        closure.append({'path':p['path'],**pin(body),'actual_present':True,'mode':'100644'})
    files={str(p.relative_to(NEW/'harness')):{**pin(p.read_bytes()),'mode':'100644'} for p in sorted((NEW/'harness').rglob('*')) if p.is_file()}
    assert len(files)==17 and set(files)-set(old_manifest)=={alias}
    for name,p in old_manifest.items(): assert files[name]==p,name
    assert files[alias]==files['tools/materialize_candidate.py']
    intent={'schema':'hepta.r16-harness-path-repair.v1','status':'AUTHORED_NOT_PUBLISHED_NOT_EXECUTED',
      'repository':'TrillionniumFoundation/Hepta','sole_parent':'7145c1cca251b6615e3bace54d8e033cad493875',
      'branch':'codex/hia-combined-source-parser-v103-r16-20261113-dda7',
      'ref_operation':'one fast-forward compare-and-swap from the failed parent, only after root review',
      'expected_old_tree':'13631b5a2bca668e45fe912b66305b21346a0e1b','expected_harness_tree':tree(files),
      'file_count':17,'old_files_byte_and_mode_identical':16,'added_path':alias,'added_pin':files[alias],
      'all_harness_file_pins_closed':closure,'original_plan_unchanged':files['inputs/MATERIALIZATION.json'],
      'original_workflow_unchanged':files['.github/workflows/hia-combined-source.yml'],
      'original_runner_unchanged':files['tools/run_parser_bounded.py'],'source_expected':1357,'bounded_expected':62,
      'original_limits_unchanged':{'workflow_minutes':90,'source_seconds':1800,'bounded_seconds':180,'cleanup_seconds':3,'compile_seconds':20,'capacity':1048576,'vm_fuel':10000000},
      'prior_failure':{'run':43520413130,'job':132212950593,'artifact_id':14081878942,
        'artifact_bytes':357237,'artifact_sha256':'448726bc12d0e33683098da8c929876b2ebac9b22543475e1cacb931317152a2',
        'failure':'FileNotFoundError for the pinned driver alias before repository initialization',
        'product_tests_executed':0,'generators_executed':0,'bounded62':'SKIPPED'},
      'product_executions_during_preparation':0,'requires_root_review_before_ref_write':True}
    dump(NEW/'HARNESS-MANIFEST.json',files)
    dump(NEW/'HARNESS-PUBLICATION-INTENT.json',intent)
    dump(NEW/'STATIC-PATH-CLOSURE.json',{'original_missing':[alias],'current_missing':[],'pins':closure,'old16_unchanged':True,'product_executed':False})
    manifest=json.loads((FAIL/'raw/EVIDENCE-MANIFEST.json').read_bytes())
    archive=(FAIL/'raw/FROZEN-SOURCE-EVIDENCE.tar.gz').read_bytes()
    assert len(archive)==manifest['bytes'] and hashlib.sha256(archive).hexdigest()==manifest['sha256']
    actual=[]
    with tarfile.open(FAIL/'raw/FROZEN-SOURCE-EVIDENCE.tar.gz',mode='r:gz') as tf:
        for t in tf:
            assert t.isfile() and not t.name.startswith('/') and '..' not in Path(t.name).parts
            body=tf.extractfile(t).read()
            p=next(p for p in manifest['members'] if p['path']==t.name)
            assert len(body)==p['bytes'] and hashlib.sha256(body).hexdigest()==p['sha256'] and oid('blob',body)==p['blob'] and t.mode==p['mode']
            assert body==(FAIL/'raw/raw'/t.name).read_bytes()
            actual.append(t.name)
    assert sorted(actual)==sorted(p['path'] for p in manifest['members'])
    dump(FAIL/'NESTED-READBACK.json',{'status':'PASS','members':len(actual),'paths':actual,'archive':pin(archive),'result_equal':manifest['result']==json.loads((FAIL/'raw/raw/RESULT.json').read_bytes()),'product_tests_executed_by_verifier':0})
    outer=(FAIL/'ORIGINAL-ARTIFACT.zip').read_bytes()
    dump(FAIL/'COMPLETE-ORIGINAL-ARTIFACT.base64.json',{'schema':'hepta.raw-artifact-base64.v1','artifact_id':14081878942,**pin(outer),'base64':base64.b64encode(outer).decode()})
    print(json.dumps(intent,sort_keys=True))

if __name__=='__main__': main()
