"""Read the producer's actual ordinary-directory and file contract; no product execution."""
from pathlib import Path, PurePosixPath
import base64, hashlib, json, tarfile

ROOT=Path(__file__).resolve().parent
def pin(body):
    return {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def put(path,value):
    body=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    if path.exists(): assert path.read_bytes()==body
    else: path.write_bytes(body)

put(ROOT/'NESTED-READBACK-r1-ERROR.json',{
    'status':'FAIL','scope':'CUSTODY_VERIFIER_NOT_PRODUCT',
    'script':'../v103-union-r16/prepare_harness_r3_alias.py',
    'error':'AssertionError at line86: verifier incorrectly required every tar member to be a file',
    'observed_first_nonfile':'harness','actual_type':'ordinary directory',
    'published_harness_files_written_before_error':17,'product_executions':0,
    'repair':'R2 verifies every explicit directory mode against the original manifest and every complete file byte; no producer data changed'})
manifest=json.loads((ROOT/'raw/EVIDENCE-MANIFEST.json').read_bytes())
archive=(ROOT/'raw/FROZEN-SOURCE-EVIDENCE.tar.gz').read_bytes()
assert len(archive)==manifest['bytes'] and hashlib.sha256(archive).hexdigest()==manifest['sha256']
file_pins={p['path']:p for p in manifest['members']}
dir_pins={p['path']:p for p in manifest['directories']}
files=[];dirs=[];seen=set()
with tarfile.open(ROOT/'raw/FROZEN-SOURCE-EVIDENCE.tar.gz','r:gz') as tf:
    for t in tf:
        path=PurePosixPath(t.name)
        assert t.name not in seen and not path.is_absolute() and '..' not in path.parts and '\\' not in t.name
        seen.add(t.name)
        if t.isdir():
            assert t.name in dir_pins and t.mode==dir_pins[t.name]['mode'] and t.size==0
            dirs.append(t.name)
        else:
            assert t.isfile() and t.name in file_pins
            body=tf.extractfile(t).read();p=file_pins[t.name];actual=pin(body)
            assert actual['bytes']==p['bytes'] and actual['sha256']==p['sha256'] and actual['git_blob']==p['blob'] and t.mode==p['mode']
            assert body==(ROOT/'raw/raw'/t.name).read_bytes()
            files.append(t.name)
assert set(files)==set(file_pins) and set(dirs)==set(dir_pins)
put(ROOT/'NESTED-READBACK.json',{'status':'PASS','files':files,'directories':dirs,'archive':pin(archive),
    'result_equal':manifest['result']==json.loads((ROOT/'raw/raw/RESULT.json').read_bytes()),
    'actual_directory_modes_verified':True,'root_mode_from_producer_manifest':manifest['root_mode'],
    'prior_verifier_failure_retained':True,'product_tests_executed_by_verifier':0})
outer=(ROOT/'ORIGINAL-ARTIFACT.zip').read_bytes()
put(ROOT/'COMPLETE-ORIGINAL-ARTIFACT.base64.json',{'schema':'hepta.raw-artifact-base64.v1',
    'artifact_id':14081878942,**pin(outer),'base64':base64.b64encode(outer).decode()})
paths=[ROOT/'FULL-JOB.log',ROOT/'VERIFICATION.json',ROOT/'NESTED-READBACK.json',ROOT/'NESTED-READBACK-r1-ERROR.json',
       ROOT/'verify_originals.py',ROOT/'verify_nested_r2.py',ROOT/'raw/EVIDENCE-MANIFEST.json',ROOT/'raw/raw/RESULT.json',
       ROOT/'COMPLETE-ORIGINAL-ARTIFACT.base64.json',ROOT/'RUN-20261113T224004Z.GET.json',ROOT/'JOBS-TERMINAL.json',ROOT/'ARTIFACTS-TERMINAL.json']
prep=ROOT.parent/'v103-union-r16/formal-preparation-r3'
paths += [prep/'HARNESS-MANIFEST.json',prep/'HARNESS-PUBLICATION-INTENT.json',prep/'STATIC-PATH-CLOSURE.json',prep.parent/'prepare_harness_r3_alias.py']
index=[{'path':str(p),**pin(p.read_bytes())} for p in paths]
put(ROOT/'PUBLICATION-INDEX.json',index)
print(json.dumps({'status':'PASS','files':len(files),'directories':len(dirs),'publication_files':len(index),'publication_bytes':sum(p['bytes'] for p in index)}))
