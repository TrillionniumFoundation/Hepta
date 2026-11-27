"""Lossless original UTF-8 author custody, zero product execution."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path(__file__).resolve().parent;SOURCE=Path('/tmp/hia-r10-cross-counted-author-r1-dda7')
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;b=p.read_bytes();assert len(b)==s.st_size and all(getattr(s,k)==getattr(p.lstat(),k) for k in KEYS);return b,{k:getattr(s,k) for k in KEYS}
def write(n,b):
 with (R/n).open('xb') as f:f.write(b)
 (R/n).chmod(0o644);assert read(R/n)[0]==b
 return pin(b)
paths={str(p.relative_to(SOURCE)):p for p in sorted(SOURCE.rglob('*')) if p.is_file()}
assert len(paths)==37
paths.update({'custody/seal_author.py':Path(__file__),'custody/AUTHOR-FREEZE-TOOL-RETURN.json':R/'AUTHOR-FREEZE-TOOL-RETURN.json'})
rows=[]
for logical,p in paths.items():
 b,s=read(p);rows.append({'logical':logical,'path':str(p),'identity':pin(b),'mode':stat.S_IMODE(s['st_mode']),'seven_stat':s,'text':b.decode('utf-8')})
raw=enc({'schema':'hia.R10.cross-counted.complete-author.v1','files':rows,'products':0,'future_output_absent':not Path('/workspace/hia-r10-cross-counted-r1-dda7').exists(),'qualification':'NO_NEW_PRODUCT_OR_DIAGNOSTIC_EXECUTION'});packed=zlib.compress(raw,9)
d=zlib.decompressobj();back=d.decompress(packed)+d.flush();assert back==raw and d.eof and not d.unused_data and not d.unconsumed_tail
for row in json.loads(back)['files']:
 b,s=read(Path(row['path']));assert b==row['text'].encode() and pin(b)==row['identity'] and s==row['seven_stat'] and stat.S_IMODE(s['st_mode'])==row['mode']
capsule=enc({'schema':'hia.R10.cross-counted.author.zlib-wrapper.v1','decoded':pin(raw),'compressed':pin(packed),'encoding':'zlib-base64','data':base64.b64encode(packed).decode()});write('AUTHOR-CAPSULE.json',capsule)
index={'files':[{k:v for k,v in r.items() if k!='text'} for r in rows],'logical_files':len(rows),'logical_bytes':sum(r['identity']['bytes'] for r in rows),'complete_local_decode_all_original_bytes_modes_stats':True,'products':0,'capsule':pin(capsule),'decoded':pin(raw)};write('AUTHOR-INDEX.json',enc(index))
direct=['HANDOFF.json','EXECUTION-PLAN.json','LAUNCH.json','CONTRACT.md','EXACT-INVERSE.json','STATIC-PROOF.json','PLAN-PIN-ROLES.json','PLAN-DIFFERENCES.json','ACTUAL-INPUT-SUMMARY.json','counted_machine.py','counted_support.py','run_cross_counted.py','freeze_authoring.py','project_authoring.py','finalize_authoring.py']
leaves=[]
for n in ['AUTHOR-CAPSULE.json','AUTHOR-INDEX.json','seal_author.py','AUTHOR-FREEZE-TOOL-RETURN.json']:
 leaves.append({'mount':n,'path':str(R/n),'identity':pin(read(R/n)[0])})
for n in direct:leaves.append({'mount':'author/'+n,'path':str(SOURCE/n),'identity':pin(read(SOURCE/n)[0])})
write('PUBLISH-PLAN.json',enc({'repository_full_name':'TrillionniumFoundation/Hepta','leaves':leaves}))
print(json.dumps({'files':len(rows),'logical_bytes':index['logical_bytes'],'capsule':pin(capsule),'leaves':len(leaves),'products':0},sort_keys=True))
