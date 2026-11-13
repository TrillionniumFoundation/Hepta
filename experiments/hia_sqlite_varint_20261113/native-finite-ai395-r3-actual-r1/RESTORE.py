"""Restore the closed original bytes from fixed lossless pieces; never runs the experiment."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile
root=Path(__file__).resolve().parent;manifest=json.loads((root/'ARCHIVE.json').read_bytes())
compressed=bytearray()
for item in manifest['parts']:
    encoded=(root/item['path']).read_bytes()
    assert len(encoded)==item['encoded_bytes'] and hashlib.sha256(encoded).hexdigest()==item['encoded_sha256']
    raw=base64.b64decode(encoded,validate=True)
    assert len(raw)==item['raw_bytes'] and hashlib.sha256(raw).hexdigest()==item['raw_sha256']
    compressed.extend(raw)
assert len(compressed)==manifest['compressed_bytes'] and hashlib.sha256(compressed).hexdigest()==manifest['compressed_sha256']
target=Path(sys.argv[1]);target.mkdir(mode=0o700,parents=False,exist_ok=False)
wanted={x['archive_path']:x for x in manifest['files']};seen=set()
class Reader:
    def __init__(self,f):self.f=f;self.n=0;self.hash=hashlib.sha256()
    def read(self,n=-1):
        b=self.f.read(n);self.n+=len(b);self.hash.update(b);return b
with gzip.GzipFile(fileobj=io.BytesIO(compressed),mode='rb') as gz:
    reader=Reader(gz)
    with tarfile.open(fileobj=reader,mode='r|') as tar:
        for m in tar:
            assert m.isreg() and m.name in wanted and m.name not in seen;seen.add(m.name);r=wanted[m.name]
            assert not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
            raw=tar.extractfile(m).read()
            assert len(raw)==r['bytes'] and hashlib.sha256(raw).hexdigest()==r['sha256']
            assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==r['git_blob']
            assert m.mode==stat.S_IMODE(r['identity'][2]) and m.uid==r['identity'][3] and m.gid==r['identity'][4]
            assert json.loads(m.pax_headers['original_identity'])==r['identity']
            p=target/m.name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                pending=memoryview(raw)
                while pending:
                    n=os.write(fd,pending);assert n>0;pending=pending[n:]
                os.fchmod(fd,m.mode);os.utime(fd,ns=(r['identity'][7],r['identity'][7]));os.fsync(fd)
                observed=b'';offset=0
                while offset<len(raw):
                    b=os.pread(fd,min(1<<20,len(raw)-offset),offset);assert b;observed+=b;offset+=len(b)
                assert observed==raw
            finally:os.close(fd)
    while reader.read(1<<20):pass
assert reader.n==manifest['tar_bytes'] and reader.hash.hexdigest()==manifest['tar_sha256'] and seen==set(wanted)
print(json.dumps({'status':'RESTORED_EXACT_CONTENT_MODE_MTIME','files':len(seen),'original_host_inodes_not_recreated':True}))
