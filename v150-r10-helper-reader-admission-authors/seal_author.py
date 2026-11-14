from pathlib import Path
from hashlib import sha1,sha256
import base64,json,stat,zlib
O=Path(__file__).resolve().parent
ROOTS={'helper-reader':Path('/tmp/hia-r10-helper-terminal-reader-r1-dda7'),'reader-freeze':Path('/tmp/hia-r10-helper-reader-freeze-r1-dda7'),'eight-admission':Path('/tmp/hia-r10-controls-admission-author-r1-dda7')}
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
payload={'schema':'hia.R10.helper-reader-eight-admission.author-complete.v1','files':files,'directories':dirs,'product_runs':0}
raw=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode();packed=zlib.compress(raw,9)
cap={'schema':'hia.R10.helper-reader-eight-admission.lossless-capsule.v1','encoding':'base64(zlib(UTF-8 JSON))',
 'decoded':pin(raw),'compressed':pin(packed),'files':len(files),'logical_bytes':sum(x['identity']['bytes'] for x in files),
 'data':base64.b64encode(packed).decode()}
cap_pin=save('AUTHOR-CAPSULE.json',cap)
decoded=zlib.decompress(base64.b64decode(cap['data'],validate=True));assert decoded==raw
value=json.loads(decoded)
for r in value['files']:
 p=Path(r['source_path']);b=p.read_bytes();s=p.lstat()
 assert b==r['text'].encode() and pin(b)==r['identity'] and stat.S_IMODE(s.st_mode)==r['mode']
 assert [getattr(s,k) for k in FIELDS]==r['seven_stats']
index={'schema':'hia.R10.helper-reader-eight-admission.index.v1','capsule':cap_pin,'roots':{k:str(v) for k,v in ROOTS.items()},
 'files':[{k:v for k,v in r.items() if k!='text'} for r in files],'directories':dirs,
 'count':len(files),'logical_bytes':cap['logical_bytes'],'full_roundtrip_equal':True,'products':0,'reader_runs':0,'binding_runs':0}
save('AUTHOR-INDEX.json',index)
selected=[('AUTHOR-CAPSULE.json',O/'AUTHOR-CAPSULE.json'),('AUTHOR-INDEX.json',O/'AUTHOR-INDEX.json'),
 ('helper-reader/HANDOFF.json',ROOTS['helper-reader']/'HANDOFF.json'),('helper-reader/verify_terminal.py',ROOTS['helper-reader']/'verify_terminal.py'),
 ('helper-reader/EXACT-INVERSE.json',ROOTS['helper-reader']/'EXACT-INVERSE.json'),('helper-reader/READER-LAUNCH.json',ROOTS['helper-reader']/'READER-LAUNCH.json'),
 ('eight-admission/HANDOFF.json',ROOTS['eight-admission']/'HANDOFF.json'),('eight-admission/verify_controls_admission.py',ROOTS['eight-admission']/'verify_controls_admission.py'),
 ('eight-admission/EXACT-INVERSE.json',ROOTS['eight-admission']/'EXACT-INVERSE.json'),('eight-admission/LAUNCH.json',ROOTS['eight-admission']/'LAUNCH.json'),
 ('seal_author.py',O/'seal_author.py')]
plan={'repository':'TrillionniumFoundation/Hepta','ref_changes':False,'products':0,
 'leaves':[{'mount':n,'path':str(p),'identity':pin(p.read_bytes()),'mode':stat.S_IMODE(p.lstat().st_mode)} for n,p in selected]}
save('PUBLISH-PLAN.json',plan)
print(json.dumps({'capsule':cap_pin,'files':len(files),'logical_bytes':cap['logical_bytes'],'leaves':len(selected),'products':0},sort_keys=True))
