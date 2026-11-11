"""Remove only byte-identical duplicate raw captures from reachable r10."""
from pathlib import Path
from hashlib import sha256,sha1
import json,stat,tarfile,time

ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent
OLD=ROOT/'recovery-completed-r10';archive=OLD/'root-completed-edit-composition.tar.xz'
receipt=json.loads((OLD/'root-custody.json').read_text())
pub=json.loads((OLD/'publication.json').read_text())
plan=json.loads((OLD/'publication-plan.json').read_text())
raw=archive.read_bytes();assert len(raw)==receipt['bytes'] and sha256(raw).hexdigest()==receipt['sha256']
git=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
entry=next(r for r in plan if r['local_path']==str(archive))
assert git==receipt['git_sha']==entry['git_sha']
assert pub['commit']=='5c8189965d8b407859d990837a6bbf9de7ef237a'
start=time.monotonic_ns()
with tarfile.open(archive,'r:xz') as tf:
    manifest=json.load(tf.extractfile('MANIFEST.json'))
candidates={r['path']:r for r in manifest['files'] if
    r['path'].split('/')[1] in ('complete-edit-native-r1','complete-edit-native-r2','complete-edit-native-r3')
    and '/raw/' in r['path'] and r['bytes']>=1<<20
    and len(r['path'].rsplit('/',1)[1])==64}
assert candidates
verified=[]
def digest(p):
    h=sha256();n=0
    with p.open('rb') as f:
        while data:=f.read(1<<20):h.update(data);n+=len(data)
    return n,h.hexdigest()
with tarfile.open(archive,'r|xz') as tf:
    for m in tf:
        if m.name not in candidates:continue
        row=candidates[m.name];assert m.isfile() and m.size==row['bytes'] and m.mode==row['mode']
        h=sha256();size=0;f=tf.extractfile(m)
        while data:=f.read(1<<20):h.update(data);size+=len(data)
        assert (size,h.hexdigest())==(row['bytes'],row['sha256'])
        p=ROOT/'native-agent-edit-development'/m.name.removeprefix('development/')
        assert p.is_file() and not p.is_symlink() and digest(p)==(size,h.hexdigest())
        s=p.stat();assert stat.S_IMODE(s.st_mode)==m.mode
        verified.append(dict(path=str(p),archive_member=m.name,bytes=size,sha256=h.hexdigest(),
            mode=m.mode,inode=s.st_ino,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns))
assert len(verified)==len(candidates)
result=dict(scope='RECLAIM_ONLY_EXACT_ARCHIVED_DUPLICATE_RAW_CAPTURES',archive=str(archive),
    archive_sha256=receipt['sha256'],archive_git_sha=git,published_commit=pub['commit'],
    inherited_and_reverified_in_commit='2742e2aef9d4f3b4b94049bee4a73af3b9ed90cf',
    all_archive_members_and_local_payloads_equal=True,files=verified,status='VERIFIED_PENDING_UNLINK')
dest=OUT/'reclaimed-r10-duplicates.json';dest.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
removed=[]
try:
    for row in verified:
        p=Path(row['path']);s=p.stat()
        assert (s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(row['inode'],row['bytes'],row['mtime_ns'],row['ctime_ns'])
        p.unlink();removed.append(row['path'])
    result['status']='PASS'
finally:
    result.update(removed_files=len(removed),removed_bytes=sum(r['bytes'] for r in verified if r['path'] in removed),
        elapsed_ns=time.monotonic_ns()-start,active_sources_removed=False)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='files'},sort_keys=True))
