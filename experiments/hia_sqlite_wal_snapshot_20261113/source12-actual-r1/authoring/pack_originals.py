"""Archive closed Source12 originals and independent readers; no product imports."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import time

P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
A=P/'sqlite-wal-snapshot-source12-actual-r1'
R1=P/'sqlite-wal-snapshot-source12-actual-audit-r1'
R2=P/'sqlite-wal-snapshot-source12-actual-audit-r2'
OUT=P/'sqlite-wal-snapshot-source12-actual-publication-r1'
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    s=path.lstat();assert path.resolve()==path and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=64<<20
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as f:
        assert ident(os.fstat(f.fileno()))==ident(s);raw=f.read();assert ident(os.fstat(f.fileno()))==ident(s)
    assert ident(path.lstat())==ident(s) and len(raw)==s.st_size
    return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'identity':ident(s)}
def create(path,raw):
    if not isinstance(raw,bytes):raw=(json.dumps(raw,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    actual,pin=read(path);assert actual==raw;return pin
started=time.monotonic()
raw,pin=read(R2/'READBACK.json')
assert pin['sha256']=='50a1d3dfa263da7dee20c60a0d29f778d89919639473a92a036c980f2f0795c1'
audit=json.loads(raw);assert audit['status']=='PASS_READBACK_SOURCE12_VM_ONLY' and audit['closed_before_child_read'] is True
rows=[];data={}
for tag,root in [('actual',A),('audit-r1-preserved-HOLD',R1),('audit-r2',R2)]:
    for parent,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:assert stat.S_ISDIR((Path(parent)/name).lstat().st_mode)
        for name in sorted(names):
            path=Path(parent)/name;body,meta=read(path);arc=tag+'/'+str(path.relative_to(root))
            assert arc not in data;data[arc]=body;rows.append({'archive_path':arc,'kind':'regular',**meta})
for name,sha in [
 ('root-wal-snapshot-generation-source12-r1-INTENT.json','fdd7c394378c827a40d1863cab35cecce48a2bde91f05f85a2b5214572bcafeb'),
 ('root-wal-snapshot-generation-source12-r1-OWNER-READBACK.json','c46c797450c2be08cdf659a62ffc62351d64ba13438cd8cc99c60c03083370b1'),
 ('root-wal-snapshot-generation-source12-r1-HJOB.json','ba6748c6e195ca83d5e27ae3ea18123ea00fd67ee975ba7ce7c5aa613bda905d')]:
    body,meta=read(P/name);assert meta['sha256']==sha;arc='root/'+name
    assert arc not in data;data[arc]=body;rows.append({'archive_path':arc,'kind':'regular',**meta})
body,meta=read(Path(__file__).resolve());arc='authoring/pack_originals.py';data[arc]=body;rows.append({'archive_path':arc,'kind':'regular',**meta})
rows.sort(key=lambda r:r['archive_path'])
actual_rows=[r for r in rows if r['archive_path'].startswith('actual/')]
assert len(actual_rows)==len(audit['actual_files'])==21
for r in audit['actual_files']:
    found=next(x for x in actual_rows if x['archive_path']=='actual/'+r['relative'])
    assert all(found[k]==r[k] for k in ('path','bytes','sha256','identity'))
assert sum(r['bytes'] for r in actual_rows)==3835488
manifest={'schema':'hia.sqlite-wal-snapshot.source12-actual-originals.v1','parent_request_commit':'d217e137db1b46b70199a56d7c9cde94811b68f4','request_sha256':'21b2313e1134cbc5c10a098dbbc343d805d63d5db44ae6c79e78718fc78be308','status':'SOURCE12_VM_ACTUAL_PASS_WITH_READER_R1_HOLD_PRESERVED','files':rows,'file_count':len(rows),'bytes':sum(r['bytes'] for r in rows),'actual_files':21,'actual_bytes':3835488,'product_reexecuted':False,'C_native_SQL_qualification':False}
mpin=create(OUT/'ORIGINALS-MANIFEST.json',manifest);mraw,_=read(OUT/'ORIGINALS-MANIFEST.json')
tar_raw=io.BytesIO()
with tarfile.open(fileobj=tar_raw,mode='w',format=tarfile.PAX_FORMAT) as tf:
    for row in rows:
        raw=data[row['archive_path']];s=row['identity'];info=tarfile.TarInfo(row['archive_path'])
        info.size=len(raw);info.mode=stat.S_IMODE(s[2]);info.uid=s[3];info.gid=s[4];info.mtime=s[7]//1000000000
        info.pax_headers={'mtime':str(s[7]//1000000000)+'.'+str(s[7]%1000000000).zfill(9)}
        tf.addfile(info,io.BytesIO(raw))
    info=tarfile.TarInfo('ORIGINALS-MANIFEST.json');info.size=len(mraw);info.mode=0o400;info.mtime=0
    tf.addfile(info,io.BytesIO(mraw))
plain=tar_raw.getvalue();zipped=gzip.compress(plain,compresslevel=6,mtime=0)
zpin=create(OUT/'ORIGINALS.tar.gz',zipped)
whole,_=read(OUT/'ORIGINALS.tar.gz');assert gzip.decompress(whole)==plain
expected={**data,'ORIGINALS-MANIFEST.json':mraw};seen=set()
with tarfile.open(fileobj=io.BytesIO(whole),mode='r:gz') as tf:
    for member in tf:
        assert member.isfile() and member.name in expected and member.name not in seen
        raw=tf.extractfile(member).read();assert raw==expected[member.name];seen.add(member.name)
        if member.name in data:
            row=next(r for r in rows if r['archive_path']==member.name);s=row['identity']
            assert member.mode==stat.S_IMODE(s[2]) and member.uid==s[3] and member.gid==s[4]
            assert member.pax_headers['mtime']==str(s[7]//1000000000)+'.'+str(s[7]%1000000000).zfill(9)
assert seen==set(expected)
parts=[];decoded=b''
for number,offset in enumerate(range(0,len(whole),180000)):
    body=whole[offset:offset+180000];raw=base64.b64encode(body)+b'\n';name='ORIGINALS.part-%03d.base64'%number
    partpin=create(OUT/name,raw);again,_=read(OUT/name);restored=base64.b64decode(again.rstrip(b'\n'),validate=True)
    assert restored==body;decoded+=restored;parts.append({'path':name,'offset':offset,'decoded_bytes':len(body),'decoded_sha256':hashlib.sha256(body).hexdigest(),'ascii_pin':partpin})
assert decoded==whole
report={'schema':'hia.sqlite-wal-snapshot.source12-archive-readback.v1','status':'PASS_FULL_RAW_ARCHIVE_READBACK','manifest':mpin,'archive':zpin,'uncompressed_tar_bytes':len(plain),'uncompressed_tar_sha256':hashlib.sha256(plain).hexdigest(),'members':len(seen),'original_files':len(rows),'original_bytes':manifest['bytes'],'actual_files':21,'actual_bytes':3835488,'parts':parts,'all_full_bodies_and_modes_uid_gid_nanosecond_mtime_equal':True,'combined_base64_restore_sha256':hashlib.sha256(decoded).hexdigest(),'source12_reexecuted':False,'seconds':time.monotonic()-started}
rp=create(OUT/'ARCHIVE-READBACK.json',report)
print(json.dumps({'status':report['status'],'originals':len(rows),'members':len(seen),'archive':zpin,'parts':len(parts),'readback':rp}),flush=True)
