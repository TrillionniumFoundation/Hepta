"""Deterministic complete metadata custody, excluding already-published payloads."""
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

ROOT=Path('/tmp/hia-r8-inputs-recovery-20261114-dda7')
AUTHOR=Path('/tmp/hia-r8-inputs-recovery-author-20261114-dda7')
DEST=Path('/tmp/hia-r8-inputs-recovery-custody-20261114-dda7')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def enc(obj):return (json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()

def put(path,raw):
    with path.open('xb') as f:f.write(raw)
    return pin(raw)

def collect():
    selected={}
    for p in ROOT.iterdir():
        if p.is_file():selected['actual/'+p.name]=p
    for folder in ('metadata','reports'):
        for p in (ROOT/folder).rglob('*'):
            if p.is_file():selected['actual/'+str(p.relative_to(ROOT))]=p
    for p in AUTHOR.iterdir():
        if p.is_file():selected['author/'+p.name]=p
    for name in ('CONTRACT.md','AUTHORING-NOTES.json','verify_restored.py','seal_metadata.py'):
        selected['custody/'+name]=DEST/name
    return selected

def main():
    started=time.monotonic();selected=collect();captured={};files={}
    for name,path in sorted(selected.items()):
        s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
        with path.open('rb') as f:
            assert seven(os.fstat(f.fileno()))==seven(s)
            raw=f.read();assert seven(os.fstat(f.fileno()))==seven(s)
        assert seven(path.lstat())==seven(s)
        captured[name]=raw;files[name]={'origin':str(path),'identity':pin(raw),
            'mode':stat.S_IMODE(s.st_mode),'new_seven_stats':seven(s)}
    manifest={'schema':'hepta.r8.reset-recovery.complete-metadata-custody.v1',
        'files':files,'file_count':len(files),'logical_bytes':sum(len(x) for x in captured.values()),
        'scope':'All recovery author scripts, exact plan/mapping/manifests, download ledger, failed R1 and successful R2 data-run raw streams, complete resulting map and reports.',
        'excluded':'944 recovered input payloads and old archive/transport payloads are already independently published and are referenced by full identities; this capsule does not duplicate them.',
        'old_originals_recreated':False,'products':0}
    mf=enc(manifest);mfp=put(DEST/'MANIFEST.json',mf)
    archive=DEST/'METADATA.tar.gz'
    with archive.open('xb') as out:
        with gzip.GzipFile(fileobj=out,mode='wb',filename='',mtime=0,compresslevel=9) as gz:
            with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as tar:
                for name,raw in [('MANIFEST.json',mf)]+list(sorted(captured.items())):
                    ti=tarfile.TarInfo(name);ti.size=len(raw);ti.mode=0o644 if name=='MANIFEST.json' else files[name]['mode']
                    ti.uid=ti.gid=ti.mtime=0;ti.uname=ti.gname=''
                    tar.addfile(ti,io.BytesIO(raw))
    raw=archive.read_bytes();ap=pin(raw);seen=set();total=0
    with gzip.GzipFile(fileobj=io.BytesIO(raw),mode='rb') as gz:
        with tarfile.open(fileobj=gz,mode='r|') as tar:
            for ti in tar:
                assert ti.isfile() and ti.name not in seen
                seen.add(ti.name);body=tar.extractfile(ti).read()
                if ti.name=='MANIFEST.json':assert body==mf and ti.mode==0o644
                else:
                    row=files[ti.name]
                    assert body==captured[ti.name] and pin(body)==row['identity'] and ti.mode==row['mode']
                    assert Path(row['origin']).read_bytes()==body
                    assert seven(Path(row['origin']).lstat())==row['new_seven_stats']
                    total+=len(body)
        while True:
            tail=gz.read(1<<20)
            if not tail:break
            assert not any(tail)
    assert seen=={'MANIFEST.json'}|set(files)
    assert total==manifest['logical_bytes']
    parts=[];(DEST/'parts').mkdir()
    for number,offset in enumerate(range(0,len(raw),320<<10)):
        piece=raw[offset:offset+(320<<10)]
        obj={'schema':'hepta.r8.recovery.metadata-part.v1','number':number,'offset':offset,
             'encoding':'base64','decoded':pin(piece),'payload':base64.b64encode(piece).decode()}
        path=DEST/'parts'/('%03d.json'%number);p=put(path,enc(obj))
        parts.append({'path':str(path.relative_to(DEST)),'identity':p,'decoded':pin(piece),'offset':offset})
    index={'schema':'hepta.r8.recovery.metadata-transport.v1','manifest':mfp,'archive':ap,
        'file_count':len(files),'logical_bytes':total,'parts':parts,'products':0}
    ip=put(DEST/'INDEX.json',enc(index))
    report={'schema':'hepta.r8.recovery.metadata-local-readback.v1','status':'PASS',
        'manifest':mfp,'archive':ap,'index':ip,'files':len(files),'logical_bytes':total,
        'all_full_bytes_modes_and_new_stats_verified':True,'complete_gzip_CRC':True,
        'elapsed_seconds':time.monotonic()-started,'products':0}
    rp=put(DEST/'LOCAL-READBACK.json',enc(report))
    print(json.dumps({'status':'PASS','files':len(files),'logical_bytes':total,
        'archive':ap,'index':ip,'parts':len(parts),'readback':rp},sort_keys=True))

if __name__=='__main__':main()
