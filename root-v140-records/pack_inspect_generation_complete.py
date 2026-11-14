import base64,hashlib,json,os,stat,zlib
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35');S=R/'v132-inspect-machine-entry-r1/successor-r2';O=R/'v95-audit-mount-r1/v140-progress';D=O/'inspect-generation-complete-r1'
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n').encode()
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def stamp(s):return {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'nlink':s.st_nlink,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
def read(p):
 before=p.lstat();assert stat.S_ISREG(before.st_mode);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  assert stamp(os.fstat(f.fileno()))==stamp(before);b=f.read(before.st_size+1);assert len(b)==before.st_size and stamp(os.fstat(f.fileno()))==stamp(before)
 assert stamp(p.lstat())==stamp(before);return b,stamp(before)
def write(p,b):
 with p.open('xb') as f:f.write(b)
 os.chmod(p,0o644)
assert not D.exists();D.mkdir(mode=0o700);(D/'parts').mkdir(mode=0o700)
files={};dirs={};objects={};before={};paths={}
def add(p,name):
 s=p.lstat();paths[name]=p;before[name]=stamp(s)
 if stat.S_ISDIR(s.st_mode):dirs[name]={'type':'directory','mode':stat.S_IMODE(s.st_mode)};return
 assert stat.S_ISREG(s.st_mode),'unexpected nonregular evidence node'
 b,observed=read(p);assert observed==before[name];i=pin(b);files[name]={**i,'mode':stat.S_IMODE(s.st_mode),'type':'regular'};objects.setdefault(i['sha256'],b)
for label in ('generation-attempt-r1','generation-outer-r1'):
 root=S/label;add(root,label)
 for folder,ds,fs in os.walk(root,followlinks=False):
  for name in sorted(ds):p=Path(folder)/name;add(p,label+'/'+p.relative_to(root).as_posix())
  for name in sorted(fs):p=Path(folder)/name;add(p,label+'/'+p.relative_to(root).as_posix())
for p,name in [(O/'verify_inspect_private_generation_terminal.py','root/verify_terminal.py'),(O/'ROOT-INSPECT-PRIVATE-GENERATION-TERMINAL.json','root/READBACK.json'),(Path(__file__),'root/pack_complete.py')]:add(p,name)
payload={'schema':'hepta.inspect-generation-complete-originals.v1','files':files,'directories':dirs,'source_stat_before':before,'objects_base64_by_sha256':{k:base64.b64encode(v).decode() for k,v in objects.items()},'scope':'all actual nodes under generation-attempt-r1 and generation-outer-r1, plus three Root records; private source is separately reconstructible from its full map and pinned prior source/overlay/generated outputs'}
raw=enc(payload);compressed=zlib.compress(raw,9);capsule=enc({'schema':'hepta.hia.zlib-base64-lossless-capsule.v1','codec':'zlib+base64','payload':pin(raw),'data':base64.b64encode(compressed).decode()})
write(D/'CAPSULE.json',capsule)
parts=[]
for i,start in enumerate(range(0,len(capsule),196608)):
 b=capsule[start:start+196608];name='parts/%03d.json'%i;part=enc({'schema':'hepta.hia.raw-span.v1','index':i,'offset':start,'data_pin':pin(b),'data_base64':base64.b64encode(b).decode()});write(D/name,part);parts.append({'path':name,'offset':start,**pin(part),'decoded':pin(b)})
write(D/'PARTS.json',enc({'capsule':pin(capsule),'parts':parts}))
restored=[]
for i,row in enumerate(parts):
 b=(D/row['path']).read_bytes();assert pin(b)=={k:row[k] for k in ('bytes','git_blob','sha256')};d=json.loads(b);x=base64.b64decode(d['data_base64'],validate=True);assert base64.b64encode(x).decode()==d['data_base64'] and pin(x)==row['decoded'] and d['index']==i and d['offset']==row['offset'];restored.append(x)
assert b''.join(restored)==capsule
c=json.loads(capsule);z=zlib.decompressobj();decoded=z.decompress(base64.b64decode(c['data'],validate=True),c['payload']['bytes']+1)
assert z.eof and not z.unused_data and not z.unconsumed_tail and decoded==raw and pin(decoded)==c['payload']
d=json.loads(decoded);assert d['files']==files and d['directories']==dirs
for name,row in files.items():
 b=base64.b64decode(d['objects_base64_by_sha256'][row['sha256']],validate=True);actual,observed=read(paths[name])
 assert b==actual and pin(b)=={k:row[k] for k in ('bytes','git_blob','sha256')} and observed==before[name]
for name in dirs:assert stamp(paths[name].lstat())==before[name]
manifest={'schema':'hepta.inspect-generation-complete-manifest.v1','capsule':pin(capsule),'files':files,'directories':dirs,'file_count':len(files),'directory_count':len(dirs),'logical_bytes':sum(x['bytes'] for x in files.values()),'unique_objects':len(objects),'product_generation_status':'GENERATION_ONLY_PASS','new_products_by_packer':0,'new_source_tests_native_VM_cold':False,'whole_native':False}
write(D/'MANIFEST.json',enc(manifest))
report={'schema':'hepta.inspect-generation-complete-readback.v1','status':'PASS_COMPLETE_LOCAL_BYTES_MODES_SEVEN_STATS_AND_PARTS_ROUNDTRIP','capsule':pin(capsule),'files':len(files),'directories':len(dirs),'logical_bytes':manifest['logical_bytes'],'unique_objects':len(objects),'parts':len(parts),'source_records_unchanged':True,'product_executions_by_packer':0,'whole_native':False}
write(D/'READBACK.json',enc(report))
print(json.dumps(report,sort_keys=True))
