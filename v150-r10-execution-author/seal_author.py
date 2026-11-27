from pathlib import Path
from hashlib import sha1,sha256
import base64,json,stat,zlib
O=Path(__file__).resolve().parent
ROOTS={'prefix':Path('/tmp/hia-r10-execution-author-r1-dda7'),
 'reader':Path('/tmp/hia-r10-prefix-terminal-reader-r1-dda7'),
 'eight-group-binding':Path('/tmp/hia-r10-controls-author-r1-dda7')}
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(b):return {'bytes':len(b),'git_blob':sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':sha256(b).hexdigest()}
def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def save(n,x):
 b=encode(x);p=O/n
 with p.open('xb') as f:f.write(b)
 p.chmod(0o644);assert p.read_bytes()==b
 return pin(b)
files=[];dirs={}
for label,root in ROOTS.items():
 for p in [root,*sorted(root.rglob('*'))]:
  s=p.lstat();name=label+'/'+p.relative_to(root).as_posix()
  if stat.S_ISDIR(s.st_mode):dirs[name]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':[getattr(s,k) for k in FIELDS]};continue
  assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
  b=p.read_bytes();assert len(b)==s.st_size and all(getattr(s,k)==getattr(p.lstat(),k) for k in FIELDS)
  files.append({'path':name,'source_path':str(p),'text':b.decode(),'identity':pin(b),
   'mode':stat.S_IMODE(s.st_mode),'seven_stats':[getattr(s,k) for k in FIELDS]})
payload={'schema':'hia.R10.prefix-reader-eight-author-complete.v1','files':files,'directories':dirs,'product_runs':0}
raw=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode();packed=zlib.compress(raw,9)
cap={'schema':'hia.R10.execution-author.lossless-capsule.v1','encoding':'base64(zlib(UTF-8 JSON))',
 'decoded':pin(raw),'compressed':pin(packed),'files':len(files),'logical_bytes':sum(x['identity']['bytes'] for x in files),
 'data':base64.b64encode(packed).decode()}
cap_pin=save('AUTHOR-CAPSULE.json',cap)
decoded=zlib.decompress(base64.b64decode(cap['data'],validate=True));assert decoded==raw
value=json.loads(decoded)
for r in value['files']:
 p=Path(r['source_path']);b=p.read_bytes();s=p.lstat()
 assert b==r['text'].encode() and pin(b)==r['identity'] and stat.S_IMODE(s.st_mode)==r['mode']
 assert [getattr(s,k) for k in FIELDS]==r['seven_stats']
index={'schema':'hia.R10.execution-author.index.v1','capsule':cap_pin,'roots':{k:str(v) for k,v in ROOTS.items()},
 'files':[{k:v for k,v in r.items() if k!='text'} for r in files],'directories':dirs,
 'count':len(files),'logical_bytes':cap['logical_bytes'],'full_roundtrip_equal':True,'products':0,'reader_runs':0,'binding_runs':0}
save('AUTHOR-INDEX.json',index)
selected=[('AUTHOR-CAPSULE.json',O/'AUTHOR-CAPSULE.json'),('AUTHOR-INDEX.json',O/'AUTHOR-INDEX.json'),
 ('prefix/HANDOFF.json',ROOTS['prefix']/'HANDOFF.json'),('prefix/PREFIX-PLAN.json',ROOTS['prefix']/'PREFIX-PLAN.json'),
 ('prefix/PREFIX-LAUNCH.json',ROOTS['prefix']/'PREFIX-LAUNCH.json'),('reader/HANDOFF.json',ROOTS['reader']/'HANDOFF.json'),
 ('reader/verify_terminal.py',ROOTS['reader']/'verify_terminal.py'),('reader/EXACT-INVERSE.json',ROOTS['reader']/'EXACT-INVERSE.json'),
 ('reader/ACTUAL-BINDING.json',ROOTS['reader']/'ACTUAL-BINDING.json'),
 ('eight-group-binding/AUTHOR-HANDOFF.json',ROOTS['eight-group-binding']/'AUTHOR-HANDOFF.json'),
 ('eight-group-binding/BINDING-CONTRACT.md',ROOTS['eight-group-binding']/'BINDING-CONTRACT.md'),
 ('eight-group-binding/BINDING-INVERSE.json',ROOTS['eight-group-binding']/'BINDING-INVERSE.json'),
 ('seal_author.py',O/'seal_author.py')]
plan={'repository':'TrillionniumFoundation/Hepta','ref_changes':False,'products':0,
 'leaves':[{'mount':n,'path':str(p),'identity':pin(p.read_bytes()),'mode':stat.S_IMODE(p.lstat().st_mode)} for n,p in selected]}
save('PUBLISH-PLAN.json',plan)
print(json.dumps({'capsule':cap_pin,'files':len(files),'logical_bytes':cap['logical_bytes'],'leaves':len(selected),'products':0},sort_keys=True))
