"""Full readback of the already published small author package; no products."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
ROOT=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def read(path):
    before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    raw=path.read_bytes();after=path.lstat()
    assert len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in FIELDS)
    return raw,stat.S_IMODE(before.st_mode),{k:getattr(before,k) for k in FIELDS}
def main():
    plan=json.loads(read(ROOT/'PUBLISH-PLAN.json')[0]);actual={};receipts=[]
    for index,row in enumerate(plan):
        stem=ROOT/'GIT-ACK'/(str(index).zfill(3)+'-'+row['mount'].replace('/','_'))
        posted=json.loads(read(Path(str(stem)+'.POST.json'))[0])
        fetched=json.loads(read(Path(str(stem)+'.GET.json'))[0])
        raw=fetched['structuredContent']['content'].encode()
        assert posted['structuredContent']['sha']==row['identity']['git_blob']
        assert pin(raw)==row['identity'] and raw==read(Path(row['path']))[0]
        actual[row['mount']]=raw
        receipts.append({'mount':row['mount'],'identity':pin(raw),'full_GET_equal':True})
    index=json.loads(actual['AUTHOR-INDEX.json'])
    offset=0;chunks=[]
    for row in index['parts']:
        assert row['start']==offset and pin(actual[row['mount']])==row['identity']
        chunks.append(actual[row['mount']]);offset+=row['identity']['bytes']
    capsule=b''.join(chunks)
    assert pin(capsule)==index['capsule'] and capsule==read(ROOT/'AUTHOR-CAPSULE.json')[0]
    wrapper=json.loads(capsule);packed=base64.b64decode(wrapper['data'],validate=True)
    assert pin(packed)==wrapper['compressed']
    decoder=zlib.decompressobj();decoded=decoder.decompress(packed,wrapper['decoded']['bytes']+1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(decoded)==wrapper['decoded']
    files=json.loads(decoded)['files'];assert set(files)==set(index['files']) and len(files)==26
    for name,row in files.items():
        raw=base64.b64decode(row['data_base64'],validate=True);authority=index['files'][name]
        current,mode,stamp=read(Path(authority['path']))
        assert raw==current and pin(raw)==row['identity']==authority['identity']
        assert mode==row['mode']==authority['mode'] and stamp==authority['seven_stats']
    for label,path in [('boundary',Path('/tmp/hia-r11-predicate-controls-author-r1-dda7')),
                       ('prefix-reader-author',Path('/tmp/hia-r11-prefix-terminal-reader-r1-dda7'))]:
        assert {label+'/'+p.relative_to(path).as_posix() for p in path.rglob('*') if p.is_file()}=={name for name in files if name.startswith(label+'/')}
    result={'schema':'hia.R11.complete-boundary-prefix-reader-author-Git-readback.v1','status':'PASS_ACTUAL_FULL_GET_AUTHOR_BYTES_ONLY',
        'files':len(files),'logical_bytes':sum(row['identity']['bytes'] for row in files.values()),
        'capsule':pin(capsule),'actual_full_GET_leaves':receipts,'whole_bytes_modes_sevenstats_pathsets_equal':True,
        'products':0,'binders':0,'reader_of_product_evidence_invocations':0,'qualification_transfer':False}
    raw=encode(result)
    with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb') as stream:stream.write(raw)
    (ROOT/'ACTUAL-GIT-READBACK.json').chmod(0o644)
    print(json.dumps({'status':result['status'],'files':len(files),'logical_bytes':result['logical_bytes'],'result':pin(raw)},sort_keys=True))
if __name__=='__main__':main()
