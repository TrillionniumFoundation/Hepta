"""Seal the completed observation-repair originals without reexecuting them."""
import base64
import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

repo=Path('/workspace/scratch/c7c6ee414a6c/hepta-task-io-fix')
rawroot=Path('/tmp/hepta-task-io-observation-fix-20261027')
out=repo/'evidence/task_io_observation_fix_20261027'
out.mkdir(parents=True,exist_ok=False)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
save=lambda path,value:path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
commit='8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776'
published='4ac39e626acd7f78e2f66708be741e78308b4e6a'
base='a1ade3cc2bf4a3b3eabd87f82ba6c8c515215e49'
git=lambda *args:subprocess.check_output(['git','-C',str(repo),*args])
assert git('rev-parse','HEAD').decode().strip()==commit
tree=git('rev-parse',commit+'^{tree}').decode().strip()
assert git('rev-parse',published+'^{tree}').decode().strip()==tree
fixed=json.loads((rawroot/'fixed-source-identity.json').read_bytes())
payload={}
for path in sorted(rawroot.rglob('*')):
    if path.is_file():
        assert not path.is_symlink()
        payload['records/'+path.relative_to(rawroot).as_posix()]=(path.read_bytes(),path.stat().st_mode&0o777)
source_rows=[]
for row in fixed['source_files']:
    data=git('show',commit+':'+row['path'])
    assert sha(data)==row['sha256'] and len(data)==row['bytes']
    target='source/fixed/'+row['path']
    payload[target]=(data,0o644)
    source_rows.append({**row,'archived_path':target,'commit':commit})
old_fixture='tools/fixtures/task_io_controls.rs'
data=git('show',base+':'+old_fixture)
target='source/base/'+old_fixture
payload[target]=(data,0o644)
source_rows.append({'path':old_fixture,'bytes':len(data),'sha256':sha(data),
    'git_blob_sha1':git('rev-parse',base+':'+old_fixture).decode().strip(),'archived_path':target,'commit':base})
with zipfile.ZipFile('/tmp/hepta-ci-recovered-20261026/12706738924.zip') as z:
    for name in ('task_io_composition.json','task_io_composition.files/positive.rs',
                 'task_io_composition.files/positive-run-2.stderr.bin','task_io_composition.files/positive-run-2.stdout.bin'):
        payload['ci44/'+name]=(z.read('artifacts/candidate/'+name),0o644)
source_record={'source_commit':commit,'source_tree':tree,'published_commit':published,
    'published_tree':tree,'base_commit':base,'compiler_sha256':fixed['compiler_sha256'],
    'files':source_rows,'git_commit_objects':{oid:base64.b64encode(git('cat-file','commit',oid)).decode()
                                           for oid in (base,commit,published)},
    'capture_scope':'Each retained source file was compared with immutable Git blob bytes at capture; selected bytes and blob IDs are retained, not the whole compiler source tree.'}
save(out/'source-identities.json',source_record)
for name in ('fixed-three-rounds.json','fixed-three-rounds.log','targeted-unit.log','ci44-failure-summary.json'):
    (out/name).write_bytes((rawroot/name).read_bytes())
(out/'baseline-counterexample.json').write_bytes((rawroot/'baseline/report.json').read_bytes())
(out/'independent-review.json').write_bytes(Path('/tmp/hepta-task-io-8c-independent-review-20261027.json').read_bytes())
(out/'capture-counterexample.py').write_bytes(Path('/tmp/hepta-task-io-capture-counterexample.py').read_bytes())
(out/'capture-archive.py').write_bytes(Path(__file__).read_bytes())
(out/'.gitattributes').write_bytes(b'* -text\n*.log -diff\n*.b64* -diff\n')
buffer=io.BytesIO()
members=[]
with tarfile.open(fileobj=buffer,mode='w:',format=tarfile.USTAR_FORMAT) as archive:
    for name,(data,mode) in sorted(payload.items()):
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.uid=info.gid=info.mtime=0
        info.uname=info.gname='';archive.addfile(info,io.BytesIO(data))
        members.append({'path':name,'bytes':len(data),'sha256':sha(data),'mode':mode})
tar=buffer.getvalue()
packed=lzma.compress(tar,format=lzma.FORMAT_XZ,filters=[{'id':lzma.FILTER_LZMA2,'preset':6,'dict_size':64*1024*1024}])
encoded=base64.b64encode(packed)+b'\n';parts=[]
for index,offset in enumerate(range(0,len(encoded),3500000)):
    name='native-records.tar.xz.b64.part%02d'%(index+1);data=encoded[offset:offset+3500000]
    (out/name).write_bytes(data);parts.append({'path':name,'bytes':len(data),'sha256':sha(data)})
manifest={'schema':'hepta.task-io-observation-repair.archive.v1','source_commit':commit,
    'compression':'xz-preset-6-dict-64MiB-single-thread','parts':parts,'encoded_bytes':len(encoded),
    'encoded_sha256':sha(encoded),'packed_bytes':len(packed),'packed_sha256':sha(packed),
    'tar_bytes':len(tar),'tar_sha256':sha(tar),'member_count':len(members),
    'uncompressed_bytes':sum(row['bytes'] for row in members),'members':members}
save(out/'archive-manifest.json',manifest)
print(json.dumps({key:manifest[key] for key in ('member_count','uncompressed_bytes','packed_bytes','packed_sha256','encoded_bytes','parts')},indent=2))
