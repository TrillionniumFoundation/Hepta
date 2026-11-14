"""Read only actual POST/fullGET envelopes and prove the complete author bytes."""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import json
import stat
import time
import zlib

ROOT=Path('/tmp/hia-r11-ascii-predicate-author-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def pin(raw):
    return {'bytes':len(raw),'git_blob':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'sha256':sha256(raw).hexdigest()}

def read(path):
    a=path.lstat()
    if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1:raise ValueError('not regular single link: '+str(path))
    raw=path.read_bytes();b=path.lstat()
    if len(raw)!=a.st_size or any(getattr(a,k)!=getattr(b,k) for k in FIELDS):raise ValueError('read changed')
    return raw,a

start=time.monotonic_ns()
plan=json.loads(read(ROOT/'PUBLISH-PLAN-R2.json')[0])
actual={};rows=[]
for index,leaf in enumerate(plan['leaves']):
    base=ROOT/'GIT-ACK'/(str(index).zfill(3)+'-'+leaf['mount'].replace('/','_'))
    post=json.loads(read(Path(str(base)+'.POST.json'))[0])
    get=json.loads(read(Path(str(base)+'.GET.json'))[0])
    raw=get['structuredContent']['content'].encode()
    local,_=read(Path(leaf['path']))
    if post['structuredContent']['sha']!=leaf['identity']['git_blob'] or pin(raw)!=leaf['identity'] or raw!=local:
        raise ValueError('full actual Git bytes differ: '+leaf['mount'])
    actual[leaf['mount']]=raw
    rows.append({'mount':leaf['mount'],'identity':pin(raw),'POST_SHA_and_fullGET_equal':True})
transport=json.loads(actual['CAPSULE-TRANSPORT.json'])
raw=b''.join(actual[row['mount']] for row in transport['parts'])
if pin(raw)!=transport['complete'] or raw!=read(ROOT/'CAPSULE.json')[0]:raise ValueError('actual capsule concatenation differs')
wrapper=json.loads(raw)
encoded=base64.b64decode(wrapper['data'],validate=True)
decoder=zlib.decompressobj();payload=decoder.decompress(encoded)+decoder.flush()
if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or pin(payload)!=wrapper['payload']:
    raise ValueError('complete actual zlib payload differs')
files=json.loads(payload)['files'];manifest=json.loads(actual['MANIFEST.json'])
if set(files)!=set(manifest['files']) or len(files)!=wrapper['file_count']:raise ValueError('complete author pathset differs')
total=0
for name,item in files.items():
    current,st=read(ROOT/name);restored=item['text'].encode()
    if (current!=restored or pin(restored)!=item['identity'] or item['mode']!=stat.S_IMODE(st.st_mode)
            or item['stat']!={k:getattr(st,k) for k in FIELDS}
            or {k:v for k,v in item.items() if k!='text'}!=manifest['files'][name]):
        raise ValueError('complete source byte/mode/stat differs: '+name)
    total+=len(restored)
if total!=wrapper['logical_bytes']:raise ValueError('logical bytes differ')
report={'schema':'hia.R11.actual-Git-author-readback.v1','status':'PASS_COMPLETE_AUTHOR_BYTES_ONLY',
        'elapsed_ns':time.monotonic_ns()-start,'files':len(files),'logical_bytes':total,
        'all_original_bytes_modes_seven_stats_equal':True,'complete_pathset_equal':True,
        'strict_complete_zlib_decode':True,'actual_POST_fullGET_leaves':rows,
        'capsule':pin(raw),'product_or_VM_executions':0,'fuel_or_native_qualification':False}
out=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb') as f:f.write(out)
print(json.dumps({'status':report['status'],'report':pin(out),'files':len(files),'logical_bytes':total},sort_keys=True))
