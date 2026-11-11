from pathlib import Path
from hashlib import sha256,sha1
import io,json,tarfile,time
root=Path('/workspace/scratch/9acdfa9f5639');src=root/'native-edit-controller-next';out=root/'recovery-completed-r10'
archive=out/'raw-bytes-graph-r1-development.tar.xz';assert not archive.exists()
start=time.monotonic_ns();paths=sorted(p for p in src.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
rows=[]
for p in paths:
    raw=p.read_bytes();rows.append(dict(path=str(p.relative_to(root)),bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=p.stat().st_mode&0o777))
manifest=json.dumps(rows,indent=2,sort_keys=True).encode()+b'\n'
with tarfile.open(archive,'w:xz',preset=1) as t:
    for p,row in zip(paths,rows):
        t.add(p,arcname=row['path'],recursive=False)
    ti=tarfile.TarInfo('MANIFEST.json');ti.mode=0o644;ti.size=len(manifest);t.addfile(ti,io.BytesIO(manifest))
with tarfile.open(archive,'r:xz') as t:
    assert t.extractfile('MANIFEST.json').read()==manifest
    members=t.getmembers();assert len(members)==len(rows)+1
    for row in rows:
        m=t.getmember(row['path']);raw=t.extractfile(m).read();p=root/row['path']
        assert m.isfile() and m.mode==row['mode'] and m.size==row['bytes']
        assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256'] and p.read_bytes()==raw and p.stat().st_mode&0o777==row['mode']
raw=archive.read_bytes();receipt=dict(archive=str(archive),bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
    members=len(rows)+1,original_bytes=sum(r['bytes'] for r in rows),all_original_bytes_modes_and_live_readback_equal=True,elapsed_ns=time.monotonic_ns()-start,
    scope='COMPLETED_PRIVATE_BYTES_ISSUER_AND_UNEXECUTED_CONTROLLER_DESIGN',whole_stack_closed=False)
(out/'raw-bytes-graph-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))
