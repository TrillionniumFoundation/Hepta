"""Preserve the complete reader author package; no reader/product invocation."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
BASE=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-reader-r1-dda7')
OUT=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-publication-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def write(name,raw):
    path=OUT/name
    with path.open('xb')as f:f.write(raw)
    assert path.read_bytes()==raw
    return {'path':str(path),**pin(raw)}
names=sorted(p.name for p in BASE.iterdir())
assert names==sorted(['TERMINAL-BODY.py.txt','read_terminal.py','STATIC-PROJECTION.json',
    'assemble_reader.py','freeze_inputs.py','CONTRACT.md','READBACK-PLAN.json',
    'READBACK-LAUNCH.json','HANDOFF.json'])
files=[]
for name in names:
    path=BASE/name;s=path.lstat();before=seven(s)
    assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    raw=path.read_bytes();assert seven(path.lstat())==before and len(raw)==s.st_size
    files.append({'name':name,'text':raw.decode('utf-8'),'pin':pin(raw),'mode':stat.S_IMODE(s.st_mode),'stat':before})
payload=encoded({'schema':'hepta.hia.reader-author.fullfiles.v1','files':files})
compressed=zlib.compress(payload,9)
capsule=encoded({'schema':'hepta.hia.reader-author.capsule.v1','codec':'zlib9+base64',
    'payload':pin(payload),'compressed':pin(compressed),'data':base64.b64encode(compressed).decode()})
write('AUTHORING-CAPSULE.json',capsule)
back=json.loads(zlib.decompress(base64.b64decode(json.loads(capsule)['data'])))
assert back==json.loads(payload)
for row in back['files']:
    raw=row['text'].encode();path=BASE/row['name']
    assert pin(raw)==row['pin']and path.read_bytes()==raw and seven(path.lstat())==row['stat']
    assert stat.S_IMODE(path.lstat().st_mode)==row['mode']
assert sorted(p.name for p in BASE.iterdir())==names
report={'status':'PASS_COMPLETE_AUTHORING_CAPSULE_READBACK_ONLY','files':len(files),
    'logical_bytes':sum(r['pin']['bytes']for r in files),'payload':pin(payload),
    'compressed':pin(compressed),'capsule':pin(capsule),'all_bytes_modes_seven_stats_equal':True,
    'reader_executed_by_this_sealer':False,'products_executed':0,'source_copy':False}
write('LOCAL-READBACK.json',encoded(report))
manifest={'schema':'hepta.hia.reader-author.manifest.v1','root':str(BASE),
    'files':[{k:v for k,v in r.items()if k!='text'}for r in files]}
write('MANIFEST.json',encoded(manifest))
leaves=[]
for name in ['read_terminal.py','READBACK-PLAN.json','READBACK-LAUNCH.json','STATIC-PROJECTION.json','HANDOFF.json','CONTRACT.md']:
    raw=(BASE/name).read_bytes();leaves.append({'name':'reader/'+name,'text':raw.decode(),**pin(raw)})
for name in ['AUTHORING-CAPSULE.json','LOCAL-READBACK.json','MANIFEST.json','seal_authoring.py']:
    raw=(OUT/name).read_bytes();leaves.append({'name':'custody/'+name,'text':raw.decode(),**pin(raw)})
write('PUBLICATION-INPUTS.json',encoded(leaves))
print(json.dumps({'status':report['status'],'files':len(files),'logical_bytes':report['logical_bytes'],
    'capsule':pin(capsule),'publication_leaves':len(leaves),'reader_executed_by_this_sealer':False},sort_keys=True))
