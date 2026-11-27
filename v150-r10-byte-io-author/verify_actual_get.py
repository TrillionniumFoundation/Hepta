from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import base64,json,stat,time,zlib
R=Path('/tmp/hia-r10-byte-io-author-r1-dda7')
O=Path('/tmp/hia-r10-byte-io-custody-r1-dda7')
start=time.monotonic_ns()

def identity(raw):
 return {'bytes':len(raw),'git_blob':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':sha256(raw).hexdigest()}

plan=json.loads((O/'PUBLISH-PLAN.json').read_bytes())
leaves=[]; objects={}
for i,row in enumerate(plan['leaves']):
 prefix=O/'GIT-ACK'/(str(i).zfill(2)+'-'+row['mount'].replace('/','_'))
 post=json.loads(Path(str(prefix)+'.POST.json').read_bytes())
 get=json.loads(Path(str(prefix)+'.GET.json').read_bytes())
 assert post['structuredContent']['sha']==row['identity']['git_blob']
 raw=get['structuredContent']['content'].encode()
 assert identity(raw)==row['identity'] and raw==Path(row['path']).read_bytes()
 assert stat.S_IMODE(Path(row['path']).lstat().st_mode)==row['mode']
 objects[row['mount']]=raw
 leaves.append({'path':row['mount'],'identity':row['identity'],'mode':row['mode'],'actual_POST_ACK':True,'actual_full_GET_equal':True})
cap=json.loads(objects['SOURCE-CAPSULE.json'])
compressed=base64.b64decode(cap['data'],validate=True)
assert identity(compressed)==cap['compressed']
z=zlib.decompressobj(); raw=z.decompress(compressed,cap['raw_json']['bytes']+1)
assert z.eof and not z.unused_data and not z.unconsumed_tail and identity(raw)==cap['raw_json']
payload=json.loads(raw)
index=json.loads(objects['SOURCE-INDEX.json'])
assert len(payload['files'])==cap['file_count']==index['file_count']==22
seen=set(); total=0; checked=[]
for row in payload['files']:
 name=row['path']; path=PurePosixPath(name)
 assert not path.is_absolute() and all(v not in ('','..','.') for v in path.parts) and name not in seen
 seen.add(name); current=R/name
 before=current.lstat(); data=current.read_bytes(); after=current.lstat()
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
 assert identity(data)==row['identity'] and row['text'].encode()==data
 assert stat.S_IMODE(before.st_mode)==row['mode']
 assert all(getattr(before,k)==v==getattr(after,k) for k,v in row['stat'].items())
 checked.append({'path':name,'identity':row['identity'],'mode':row['mode'],'seven_stats_equal':True})
 total+=len(data)
assert total==cap['logical_file_bytes']==index['logical_file_bytes']
assert {r['path'] for r in index['rows']}==seen
report={'schema':'hia.R10.actual-GET-full-author-readback.v1','status':'PASS_READBACK_ONLY',
        'source_capsule':identity(objects['SOURCE-CAPSULE.json']),'leaves':leaves,'logical_files':checked,
        'complete_pathset_equal':True,'logical_file_count':len(seen),'logical_bytes':total,
        'whole_actual_GET_decode_equal':True,'all_bytes_modes_and_seven_stats_equal':True,
        'elapsed_ns':time.monotonic_ns()-start,'product_executions':0,'candidate_generated':False}
report_raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with (O/'ACTUAL-GIT-READBACK.json').open('xb') as f:f.write(report_raw)
(O/'ACTUAL-GIT-READBACK.json').chmod(0o644)
print(json.dumps({'status':report['status'],'report':identity(report_raw),'files':len(seen),'bytes':total,'elapsed_ns':report['elapsed_ns']},sort_keys=True))
