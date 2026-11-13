"""Restore preexecution bytes to a NEW directory. Never executes a request."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile
root=Path(sys.argv[1]);out=Path(sys.argv[2])
if out.exists():raise RuntimeError('new restoration directory required')
manifest=json.loads((root/'ARCHIVE.json').read_bytes());chunks=[]
for i,item in enumerate(manifest['parts']):
    if item['path']!='archive/part-%04d.b64'%i:raise RuntimeError('part order')
    wire=(root/item['path']).read_bytes()
    if hashlib.sha256(wire).hexdigest()!=item['text_sha256']:raise RuntimeError('text part SHA')
    raw=base64.b64decode(wire,validate=False)
    if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('binary part SHA')
    chunks.append(raw)
z=b''.join(chunks)
if len(z)!=manifest['archive']['bytes'] or hashlib.sha256(z).hexdigest()!=manifest['archive']['sha256']:raise RuntimeError('whole gzip')
with tarfile.open(fileobj=io.BytesIO(z),mode='r:gz') as t:
    members=t.getmembers()
    if len(members)!=len(manifest['originals']) or {m.name for m in members}!={r['relative_path'] for r in manifest['originals']}:raise RuntimeError('exact regular member population')
    expected={r['relative_path']:r for r in manifest['originals']}
    out.mkdir(mode=0o700)
    for m in members:
        if not m.isfile() or m.name.startswith('/') or '..' in Path(m.name).parts:raise RuntimeError('unsafe member')
        row=expected[m.name];raw=t.extractfile(m).read()
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise RuntimeError('full member SHA')
        path=out/m.name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            view=memoryview(raw)
            while view:
                n=os.write(fd,view)
                if n<=0:raise OSError('short write')
                view=view[n:]
            os.fchmod(fd,row['identity'][2]&0o777);os.fsync(fd)
        finally:os.close(fd)
        if path.read_bytes()!=raw:raise RuntimeError('restored full body')
print(json.dumps({'status':'PREEXECUTION_BYTES_RESTORED_ONLY_NOT_EXECUTABLE_CURRENT_IDENTITIES','files':len(manifest['originals']),'source_base_not_duplicated':True,'must_refreeze_physical_identities_before_new_execution':True}))
