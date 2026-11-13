"""Recover content from the lossless original archive without running the experiment."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile,sys
root=Path(__file__).resolve().parent
manifest=json.loads((root/'ARCHIVE.json').read_bytes())
chunks=[]
for row in manifest['parts']:
    raw=base64.b64decode((root/row['path']).read_bytes(),validate=True)
    assert len(raw)==row['raw_bytes'] and hashlib.sha256(raw).hexdigest()==row['raw_sha256']
    chunks.append(raw)
compressed=b''.join(chunks)
assert len(compressed)==manifest['compressed_bytes'] and hashlib.sha256(compressed).hexdigest()==manifest['compressed_sha256']
data=gzip.decompress(compressed)
assert len(data)==manifest['tar_bytes'] and hashlib.sha256(data).hexdigest()==manifest['tar_sha256']
target=Path(sys.argv[1]);target.mkdir(mode=0o700,parents=False,exist_ok=False)
expected={r['archive_path']:r for r in manifest['files']}
seen=set()
with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
    for member in archive:
        assert member.isreg() and member.name in expected and member.name not in seen
        row=expected[member.name];seen.add(member.name)
        raw=archive.extractfile(member).read()
        assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
        assert member.mode==stat.S_IMODE(row['identity'][2]) and member.uid==row['identity'][3] and member.gid==row['identity'][4]
        assert member.pax_headers['mtime_ns']==str(row['identity'][7])
        path=target/member.name
        assert '..' not in Path(member.name).parts and not Path(member.name).is_absolute()
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.chmod(path,member.mode);os.utime(path,ns=(row['identity'][7],row['identity'][7]))
assert seen==set(expected)
print(json.dumps({'status':'RESTORED_CONTENT_MODE_MTIME','files':len(seen),'original_host_inodes_not_recreated':True}))
