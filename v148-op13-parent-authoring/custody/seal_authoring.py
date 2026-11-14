"""Losslessly seal only the op13 static author directory; no products."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
R=Path('/tmp/hia-op13-execution-author-r1-dda7');D=Path('/tmp/hia-op13-execution-custody-r1-dda7')
F=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b,mode='100644'):return {'bytes':len(b),'mode':mode,'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def write(path,b):
 with path.open('xb')as f:f.write(b)
 assert path.read_bytes()==b
 return pin(b)
def state(root):
 out={'.':{k:getattr(root.lstat(),k)for k in F}}
 def walk(p,prefix):
  for e in sorted(os.scandir(p),key=lambda e:e.name):
   s=e.stat(follow_symlinks=False);name=prefix+e.name
   assert stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)
   out[name]={k:getattr(s,k)for k in F}
   if stat.S_ISDIR(s.st_mode):walk(Path(e.path),name+'/')
   else:assert s.st_nlink==1
 walk(root,'');return out
before=state(R);files=[];dirs=[];total=0
for name,s in sorted(before.items()):
 if stat.S_ISDIR(s['st_mode']):dirs.append({'path':name,'posix_mode':stat.S_IMODE(s['st_mode']),'new_stat':s});continue
 p=R/name;raw=p.read_bytes();assert {k:getattr(p.lstat(),k)for k in F}==s
 mode='100755'if s['st_mode']&0o111 else'100644'
 files.append({'path':name,'pin':pin(raw,mode),'posix_mode':stat.S_IMODE(s['st_mode']),'new_stat':s,'base64':base64.b64encode(raw).decode()});total+=len(raw)
assert state(R)==before
payload=enc({'schema':'hepta.hia.complete-static-author-files.v1','root':str(R),'files':files,'directories':dirs,'products':0,'source_view_materialized':False,'no_historical_stat_inherited':True})
archive=zlib.compress(payload,1);write(D/'COMPLETE-AUTHOR.zlib',archive)
(D/'parts').mkdir();parts=[]
size=110000;count=(len(archive)+size-1)//size
for i,offset in enumerate(range(0,len(archive),size)):
 chunk=archive[offset:offset+size]
 row={'schema':'hepta.hia.lossless-author-part.v1','index':i,'count':count,'offset':offset,'archive':pin(archive),'raw':pin(chunk),'payload':base64.b64encode(chunk).decode()}
 text=enc(row);name='parts/part-%03d.json'%i;parts.append({'path':name,'pin':write(D/name,text),'index':i,'offset':offset,'raw':pin(chunk)})
manifest={'schema':'hepta.hia.complete-static-author-index.v1','root':str(R),'files':[{k:v for k,v in row.items()if k!='base64'}for row in files],'directories':dirs,'logical_bytes':total,'file_count':len(files),'directory_count':len(dirs),'decoded':pin(payload),'archive':pin(archive),'parts':parts,'product_execution':0,'full_source_copy':0,'bounded_part_raw_bytes':size}
write(D/'INDEX.json',enc(manifest))
actual=b''.join(base64.b64decode(json.loads((D/p['path']).read_bytes())['payload'],validate=True)for p in parts)
assert actual==archive;decoder=zlib.decompressobj();decoded=decoder.decompress(actual);decoded+=decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and decoded==payload
v=json.loads(decoded);assert len(v['files'])==len(files)
for row in v['files']:
 b=base64.b64decode(row['base64'],validate=True);p=R/row['path'];assert pin(b,row['pin']['mode'])==row['pin']and p.read_bytes()==b
 assert stat.S_IMODE(p.lstat().st_mode)==row['posix_mode']and {k:getattr(p.lstat(),k)for k in F}==row['new_stat']
assert state(R)==before
report={'schema':'hepta.hia.complete-static-author-readback.v1','status':'PASS','file_count':len(files),'directory_count':len(dirs),'logical_bytes':total,'decoded_bytes':len(payload),'archive_bytes':len(archive),'parts':len(parts),'all_bytes_modes_and_new_seven_stats_equal':True,'pathset_before_after_equal':True,'archive_final_eof_checked':True,'old_stats_inherited':False,'project_imports':0,'products':0,'materialized_source':False,'index':pin((D/'INDEX.json').read_bytes()),'archive':pin(archive),'decoded':pin(decoded)}
write(D/'LOCAL-READBACK.json',enc(report));print(json.dumps(report))
