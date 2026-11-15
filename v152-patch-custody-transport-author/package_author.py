"""Small author text capsule only, no archive/product data reads."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
AUTHOR=Path('/workspace/hia-patch-custody-transport-author-r1-20261115-dda7')
ROOT=Path('/workspace/hia-patch-custody-transport-author-publication-r1-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(p):
 s=p.lstat();return{k:getattr(s,k)for k in FIELDS}
def pin(b):return{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def capture(p):
 s=seven(p);assert stat.S_ISREG(s['st_mode'])and s['st_nlink']==1 and s['st_size']<=16<<20
 b=p.read_bytes();assert seven(p)==s
 return b,{'path':str(p),'pin':pin(b),'mode':stat.S_IMODE(s['st_mode']),'stat':s}
def put(name,v):
 b=enc(v)
 with(ROOT/name).open('xb')as f:f.write(b)
 return{'logical':name,**capture(ROOT/name)[1]}
files={};dirs={}
for p in sorted(AUTHOR.rglob('*')):
 if p.is_dir():dirs[p.relative_to(AUTHOR).as_posix()]=seven(p)
 else:
  b,d=capture(p);files[p.relative_to(AUTHOR).as_posix()]={'descriptor':d,'text':b.decode()}
dirs['.']=seven(AUTHOR);assert len(files)==16
payload=enc({'schema':'hepta.hia.patch-custody.transport.complete-author.v1','root':str(AUTHOR),'directories':dirs,'files':files})
packed=zlib.compress(payload,6);decoder=zlib.decompressobj();decoded=decoder.decompress(packed)+decoder.flush()
assert decoded==payload and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
capsule=put('AUTHORING-CAPSULE.json',{'schema':'hepta.hia.zlib.complete-author.v1','payload':pin(payload),'packed':pin(packed),'data_base64':base64.b64encode(packed).decode()})
manifest=put('MEMBERS.json',{'root':str(AUTHOR),'directories':dirs,'files':{n:r['descriptor']for n,r in files.items()},'files_count':len(files)})
for n,r in files.items():assert capture(Path(r['descriptor']['path']))==(r['text'].encode(),r['descriptor'])
for n,s in dirs.items():assert seven(AUTHOR/n)==s
local=put('LOCAL-READBACK.json',{'status':'PASS_SMALL_AUTHOR_CAPSULE_LOCAL_INVERSE','files':len(files),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values()),'payload':pin(payload),'compressed':pin(packed),'strict_zlib_eof':True,'archive_payload_read_bytes':0,'transport_or_product_executions':0})
leaves=[capsule,manifest,local,{'logical':'package_author.py',**capture(Path(__file__))[1]}]
put('PUBLICATION-INPUTS.json',{'repository':'TrillionniumFoundation/Hepta','leaves':leaves})
print(json.dumps({'files':len(files),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values()),'capsule':capsule['pin'],'packed':pin(packed)},sort_keys=True))
