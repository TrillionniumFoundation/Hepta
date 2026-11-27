"""Small source-authoring custody only; no project import or product."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-cli-owner-bundle-author-custody-r1-20261115-dda7')
AUTHOR=Path('/workspace/hia-cli-owner-bundle-author-r1-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(path):
 s=Path(path).lstat();return{k:getattr(s,k)for k in FIELDS}
def pin(raw,mode='100644'):
 return{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def read(path):
 p=Path(path);before=seven(p);assert stat.S_ISREG(before['st_mode'])and before['st_nlink']==1 and before['st_size']<=16<<20
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  assert before=={k:getattr(os.fstat(fd),k)for k in FIELDS}
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(before['st_size']+1)
  assert len(raw)==before['st_size']and before==seven(p)=={k:getattr(os.fstat(fd),k)for k in FIELDS}
 finally:os.close(fd)
 assert raw.decode().encode()==raw
 return raw,{'path':str(p),'pin':pin(raw,'100755'if before['st_mode']&0o111 else'100644'),'stat':before}
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(name,value):
 p=ROOT/name;p.parent.mkdir(parents=True,exist_ok=True);raw=enc(value)
 with p.open('xb')as f:assert f.write(raw)==len(raw)
 return{'logical':name,**read(p)[1]}
files={};directories={}
def walk(p):
 before=seven(p);assert stat.S_ISDIR(before['st_mode']);directories[str(p.relative_to(AUTHOR))]=before
 names=sorted(x.name for x in p.iterdir())
 for n in names:
  c=p/n
  if stat.S_ISDIR(c.lstat().st_mode):walk(c)
  else:
   raw,desc=read(c);files[str(c.relative_to(AUTHOR))]={'descriptor':desc,'text':raw.decode()}
 assert seven(p)==before and sorted(x.name for x in p.iterdir())==names
walk(AUTHOR)
assert len(files)==47
payload=enc({'schema':'hepta.hia.cli-owner-selection.complete-author.v1','root':str(AUTHOR),
 'directories':directories,'files':files,'products':0,'default_activated':False,'whole_native':False})
compressed=zlib.compress(payload,6)
dec=zlib.decompressobj();decoded=dec.decompress(compressed)+dec.flush()
assert decoded==payload and dec.eof and not dec.unused_data and not dec.unconsumed_tail
parts=[]
for start in range(0,len(compressed),196608):
 block=compressed[start:start+196608]
 parts.append(write('parts/%04d.json'%len(parts),{'schema':'hepta.hia.zlib-part.v1','index':len(parts),
  'offset':start,'compressed_whole':pin(compressed),'piece':pin(block),'data':base64.b64encode(block).decode()}))
index=write('INDEX.json',{'schema':'hepta.hia.cli-owner-selection.author-archive-index.v1',
 'payload':pin(payload),'compressed':pin(compressed),'parts':parts,'files':len(files),
 'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values())})
members=write('MEMBERS.json',{'root':str(AUTHOR),'directories':directories,
 'files':{n:r['descriptor']for n,r in files.items()},'files_count':len(files)})
for n,r in files.items():assert read(r['descriptor']['path'])==(r['text'].encode(),r['descriptor'])
for n,s in directories.items():assert seven(AUTHOR/n)==s
local=write('LOCAL-READBACK.json',{'status':'PASS_COMPLETE_AUTHOR_SOURCE_LOCAL_INVERSE',
 'payload':pin(payload),'compressed':pin(compressed),'files':len(files),'parts':len(parts),
 'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values()),
 'strict_zlib_eof':True,'all_full_bytes_modes_sevenstats':True,'project_executions':0})
leaves=parts+[index,members,local,{'logical':'prepare.py',**read(__file__)[1]}]
write('PUBLICATION-INPUTS.json',{'repository':'TrillionniumFoundation/Hepta','leaves':leaves})
print(json.dumps({'files':len(files),'parts':len(parts),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values()),'compressed':pin(compressed)},sort_keys=True))
