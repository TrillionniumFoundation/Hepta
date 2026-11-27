from pathlib import Path
from hashlib import sha1,sha256
import base64,json,stat,time,zlib
O=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(b):return {'bytes':len(b),'git_blob':sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':sha256(b).hexdigest()}
def encode(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
start=time.monotonic_ns();plan=json.loads((O/'PUBLISH-PLAN.json').read_bytes());published={}
for index,row in enumerate(plan['leaves']):
 stem=str(index).zfill(2)+'-'+row['mount'].replace('/','_')
 post=json.loads((O/'GIT-ACK'/(stem+'.POST.json')).read_bytes())
 get=json.loads((O/'GIT-ACK'/(stem+'.GET.json')).read_bytes())
 assert post['structuredContent']['sha']==row['identity']['git_blob']
 b=get['structuredContent']['content'].encode();assert b==Path(row['path']).read_bytes() and pin(b)==row['identity']
 published[row['mount']]=b
capsule=json.loads(published['AUTHOR-CAPSULE.json']);compressed=base64.b64decode(capsule['data'],validate=True)
assert pin(compressed)==capsule['compressed']
decoder=zlib.decompressobj();raw=decoder.decompress(compressed,capsule['decoded']['bytes']+1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(raw)==capsule['decoded']
payload=json.loads(raw);index=json.loads(published['AUTHOR-INDEX.json'])
assert len(payload['files'])==capsule['files']==index['count']==19
assert sum(r['identity']['bytes'] for r in payload['files'])==capsule['logical_bytes']==345122
seen=set()
for row in payload['files']:
 assert row['path'] not in seen;seen.add(row['path'])
 p=Path(row['source_path']);b=p.read_bytes();s=p.lstat()
 assert b==row['text'].encode() and pin(b)==row['identity'] and stat.S_IMODE(s.st_mode)==row['mode']
 assert [getattr(s,k) for k in FIELDS]==row['seven_stats']
for label,path in index['roots'].items():
 root=Path(path)
 actual={label+'/'+p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
 assert actual=={n for n in seen if n.startswith(label+'/')}
for name,row in payload['directories'].items():
 label,relative=name.split('/',1);p=Path(index['roots'][label])/relative;s=p.lstat()
 assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==row['mode']
 assert [getattr(s,k) for k in FIELDS]==row['seven_stats']
result={'schema':'hia.R10.helper-author.actual-Git-full-readback.v1','status':'PASS',
 'actual_POST_ACK_and_full_GET_leaves':len(plan['leaves']),'all_leaf_bytes_equal':True,
 'decoded_files':19,'logical_bytes':345122,'all_original_file_bytes_modes_sevenstats_pathsets_equal':True,
 'capsule':pin(published['AUTHOR-CAPSULE.json']),'index':pin(published['AUTHOR-INDEX.json']),
 'elapsed_ns':time.monotonic_ns()-start,'products':0,'terminal_reader_runs':0,'eight_group_binding_runs':0}
p=O/'ACTUAL-GIT-READBACK.json'
with p.open('xb') as stream:stream.write(encode(result))
p.chmod(0o644)
print(json.dumps({'result':pin(p.read_bytes()),'status':'PASS','files':19,'products':0},sort_keys=True))
