from pathlib import Path
import base64,hashlib,json,stat,time,zlib
R=Path(__file__).resolve().parent;started=time.monotonic_ns()
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
plan=json.loads((R/'PUBLISH-PLAN-R2.json').read_bytes());payloads={};receipts=[]
for i,row in enumerate(plan['leaves']):
 p=R/'GIT-ACK'/('%03d-'%i+row['mount'].replace('/','_'));post_raw=Path(str(p)+'.POST.json').read_bytes();get_raw=Path(str(p)+'.GET.json').read_bytes();post=json.loads(post_raw);get=json.loads(get_raw);raw=get['structuredContent']['content'].encode()
 assert post['structuredContent']['sha']==row['identity']['git_blob'] and pin(raw)==row['identity'] and Path(row['path']).read_bytes()==raw;payloads[row['mount']]=raw;receipts.append({'mount':row['mount'],'identity':row['identity'],'POST':pin(post_raw),'full_GET':pin(get_raw)})
transport=json.loads(payloads['CAPSULE-TRANSPORT.json']);chunks=[];offset=0
for i,row in enumerate(transport['parts']):
 raw=payloads[row['path']];assert pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')};part=json.loads(raw);chunk=base64.b64decode(part['base64'],validate=True);assert part['index']==i and part['offset']==offset and pin(chunk)==part['decoded'];offset+=len(chunk);chunks.append(chunk)
capsule_raw=b''.join(chunks);assert pin(capsule_raw)==transport['original'] and capsule_raw==(R/'AUTHOR-CAPSULE.json').read_bytes();capsule=json.loads(capsule_raw);compressed=base64.b64decode(capsule['data'],validate=True);assert pin(compressed)==capsule['compressed'];d=zlib.decompressobj();decoded=d.decompress(compressed)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(decoded)==capsule['decoded'];value=json.loads(decoded)
names=set();total=0
for row in value['files']:
 assert row['logical'] not in names;names.add(row['logical']);p=Path(row['path']);s=p.lstat();actual=p.read_bytes();assert actual==row['text'].encode() and pin(actual)==row['identity'] and stat.S_IMODE(s.st_mode)==row['mode'] and {k:getattr(s,k) for k in KEYS}==row['seven_stat'] and all(getattr(s,k)==getattr(p.lstat(),k) for k in KEYS);total+=len(actual)
source=Path('/tmp/hia-r10-cross-counted-author-r1-dda7');assert {str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()}=={n for n in names if not n.startswith('custody/')}
proof={'schema':'hia.R10.counted-author.actual-git-readback.v1','status':'PASS_ACTUAL_FULL_GET_COMPLETE39_AUTHOR_FILES','originals':len(names),'logical_bytes':total,'capsule_reconstructed_from_actual_part_GETs':True,'all_original_bytes_modes_seven_stats_pathset_equal':True,'capsule':pin(capsule_raw),'decoded':pin(decoded),'receipts':receipts,'elapsed_ns':time.monotonic_ns()-started,'products':0,'diagnostics':0,'refs':0}
with (R/'ACTUAL-GIT-READBACK.json').open('xb') as f:f.write(enc(proof))
print(json.dumps({k:v for k,v in proof.items() if k!='receipts'},sort_keys=True))
