"""Decode actual full GET bytes and compare every metadata member to its origin."""
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

ROOT=Path('/tmp/hia-r8-inputs-recovery-custody-20261114-dda7')
GET=ROOT/'actual-Git'

def pin(b):
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}

def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def fixed(path,identity):
    before=path.lstat();assert stat.S_ISREG(before.st_mode)
    data=path.read_bytes();assert seven(path.lstat())==seven(before)
    assert pin(data)==identity
    return data

def main():
    start=time.monotonic()
    intent=json.loads((ROOT/'PUBLICATION-INTENT.json').read_bytes())
    get={r['name']:fixed(GET/r['name'],r['identity']) for r in intent['entries']}
    index=json.loads(get['INDEX.json'])
    manifest_raw=get['MANIFEST.json'];assert pin(manifest_raw)==index['manifest']
    manifest=json.loads(manifest_raw)
    chunks=[]
    for number,row in enumerate(index['parts']):
        assert row['path']=='parts/%03d.json'%number
        raw=get[row['path']];assert pin(raw)==row['identity']
        wrapper=json.loads(raw)
        assert wrapper['schema']=='hepta.r8.recovery.metadata-part.v1'
        assert wrapper['number']==number and wrapper['offset']==row['offset']==sum(map(len,chunks))
        data=base64.b64decode(wrapper['payload'],validate=True)
        assert pin(data)==row['decoded']==wrapper['decoded']
        chunks.append(data)
    archive=b''.join(chunks);assert pin(archive)==index['archive']
    seen=set();total=0;current=[]
    with gzip.GzipFile(fileobj=io.BytesIO(archive),mode='rb') as gz:
        with tarfile.open(fileobj=gz,mode='r|') as tar:
            for ti in tar:
                assert ti.isfile() and ti.name not in seen
                seen.add(ti.name);data=tar.extractfile(ti).read()
                if ti.name=='MANIFEST.json':assert data==manifest_raw and ti.mode==0o644
                else:
                    row=manifest['files'][ti.name]
                    assert pin(data)==row['identity'] and ti.mode==row['mode']
                    path=Path(row['origin']);before=path.lstat()
                    assert stat.S_ISREG(before.st_mode) and seven(before)==row['new_seven_stats']
                    assert stat.S_IMODE(before.st_mode)==row['mode']
                    assert path.read_bytes()==data and seven(path.lstat())==seven(before)
                    current.append({'path':row['origin'],'new_seven_stats':seven(before)})
                    total+=len(data)
        while True:
            tail=gz.read(1<<20)
            if not tail:break
            assert not any(tail)
    assert seen=={'MANIFEST.json'}|set(manifest['files'])
    assert len(current)==manifest['file_count']==index['file_count']==42
    assert total==manifest['logical_bytes']==index['logical_bytes']==10211289
    for row in current:assert seven(Path(row['path']).lstat())==row['new_seven_stats']
    result={'schema':'hepta.r8.recovery.actual-git-readback.v1',
        'status':'PASS_ACTUAL_FULL_GET_DECODE_AND_ORIGIN_COMPARE',
        'repository':intent['repository'],'GET_leaves':len(get),'archive':index['archive'],
        'manifest':index['manifest'],'parts':len(chunks),'files':len(current),
        'logical_bytes':total,'all_members_complete_bytes_modes_and_new_stats_equal':True,
        'full_gzip_CRC_verified':True,'products':0,'refs_modified':False,
        'elapsed_seconds':time.monotonic()-start,
        'originals':current}
    raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb') as f:f.write(raw)
    print(json.dumps({'status':result['status'],'report':pin(raw),'files':42,
        'logical_bytes':total,'elapsed_seconds':result['elapsed_seconds']},sort_keys=True))

if __name__=='__main__':main()
