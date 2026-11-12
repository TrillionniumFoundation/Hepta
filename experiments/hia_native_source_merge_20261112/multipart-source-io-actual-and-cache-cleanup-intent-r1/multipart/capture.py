"""Read closed finite source/I/O originals; never follow aliases or open special nodes."""
from hashlib import sha256
import base64
import gzip
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root/multipart-source-io-r1')
OUT = Path(__file__).parent

def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def wire(x):
    return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()

def create(p, raw):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    assert p.read_bytes()==raw

def read(p, expected=None):
    before=p.lstat()
    assert stat.S_ISREG(before.st_mode)
    if expected is not None: assert identity(before)==expected
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        assert identity(os.fstat(f.fileno()))==identity(before)
        raw=f.read()
        assert len(raw)==before.st_size and identity(os.fstat(f.fileno()))==identity(before)
    assert identity(p.lstat())==identity(before)
    return raw,identity(before)

guard=json.loads((ROOT/'guardian-r1/guardian.json').read_bytes())
report=json.loads((ROOT/'actual-r1/REPORT.json').read_bytes())
assert guard['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED'
assert guard['lifecycle']['cleanup']['observed_echild'] and guard['input_identity_preserved']
assert report['tests_run']==21 and report['source_preserved']
rows=[]
def visit(path):
    before=path.lstat(); rel=path.relative_to(ROOT).as_posix()
    row={'path':rel,'identity':identity(before),'mode':stat.S_IMODE(before.st_mode)}
    if stat.S_ISDIR(before.st_mode):
        row['kind']='directory';rows.append(row)
        for child in sorted(path.iterdir(),key=lambda p:p.name):visit(child)
    elif stat.S_ISREG(before.st_mode):
        raw,_=read(path,identity(before));row.update(kind='regular',bytes=len(raw),sha256=sha256(raw).hexdigest());rows.append(row)
    elif stat.S_ISLNK(before.st_mode):
        row.update(kind='symlink',target=os.readlink(path),body_opened=False);rows.append(row)
    elif stat.S_ISFIFO(before.st_mode):
        row.update(kind='fifo',body_opened=False);rows.append(row)
    else:raise RuntimeError('unexpected actual node')
    assert identity(path.lstat())==identity(before)
visit(ROOT)
regular=[r for r in rows if r['kind']=='regular']
manifest={'schema':'hia.multipart-source-io.closed-originals.v1','root':str(ROOT),
 'typed':rows,'regular_files':len(regular),'regular_bytes':sum(r['bytes'] for r in regular),
 'aliases_and_fifo_opened':False,'hardlinked_names_each_retain_complete_bytes':True,
 'scope':'21 finite source/filesystem controls only; synthetic capacity and mocked HTTP are not real capacity/network qualification.'}
manifest_raw=wire(manifest);create(OUT/'TYPED-MANIFEST.json',manifest_raw)
archive=OUT/'ALL-ORIGINALS.tar.gz'
fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb') as storage:
    with gzip.GzipFile(filename='',mode='wb',fileobj=storage,mtime=0,compresslevel=6) as zipped:
        with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as tar:
            for row in regular:
                raw,_=read(ROOT/row['path'],row['identity'])
                assert sha256(raw).hexdigest()==row['sha256']
                info=tarfile.TarInfo('originals/'+row['path']);info.size=len(raw);info.mode=row['mode'];info.mtime=0
                tar.addfile(info,io.BytesIO(raw))
            info=tarfile.TarInfo('TYPED-MANIFEST.json');info.size=len(manifest_raw);info.mode=0o400;info.mtime=0
            tar.addfile(info,io.BytesIO(manifest_raw))
    storage.flush();os.fsync(storage.fileno())
expected={'originals/'+r['path']:r for r in regular}; seen=[];total=0
with tarfile.open(archive,'r:gz') as tar:
    for item in tar:
        assert item.isfile()
        body=tar.extractfile(item).read()
        if item.name=='TYPED-MANIFEST.json':assert body==manifest_raw
        else:
            row=expected[item.name];assert len(body)==row['bytes'] and sha256(body).hexdigest()==row['sha256']
            assert item.mode==row['mode'];seen.append(item.name);total+=len(body)
assert sorted(seen)==sorted(expected) and total==manifest['regular_bytes']
archive_raw=archive.read_bytes()
proof={'status':'COMPLETE_CLOSED_ORIGINALS_RESTORE_PASS','regular_files':len(regular),
 'regular_bytes':total,'typed_entries':len(rows),'symlinks':sum(r['kind']=='symlink' for r in rows),
 'fifos':sum(r['kind']=='fifo' for r in rows),'archive_bytes':len(archive_raw),
 'archive_sha256':sha256(archive_raw).hexdigest(),'all_regular_archive_members_read':True,
 'actual_original_nodes_preserved':True,'execution_repeated':False}
create(OUT/'FULL-RESTORE.json',wire(proof))
create(OUT/'ALL-ORIGINALS.tar.gz.base64',(base64.b64encode(archive_raw).decode()+'\n').encode())
files=[]
for name in ('capture.py','TYPED-MANIFEST.json','FULL-RESTORE.json','ALL-ORIGINALS.tar.gz.base64'):
    raw=(OUT/name).read_bytes();files.append({'path':name,'text':raw.decode(),'bytes':len(raw),'sha256':sha256(raw).hexdigest()})
create(OUT/'BUNDLE.json',wire({'files':files,'proof':proof}))
print(json.dumps(proof,sort_keys=True))
