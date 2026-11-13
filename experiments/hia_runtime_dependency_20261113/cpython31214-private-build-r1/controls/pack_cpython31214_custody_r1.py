import base64,gzip,hashlib,io,json,os,stat,tarfile,time
from pathlib import Path
T=Path('/home/qq/hia-rewrite-20261113-e26e-r1');D=T/'cpython31214-custody-r1'
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  assert identity(os.fstat(fd))==identity(s)
  chunks=[]
  while True:
   z=os.read(fd,1048576)
   if not z:break
   chunks.append(z)
  b=b''.join(chunks);assert len(b)==s.st_size and identity(os.fstat(fd))==identity(s)
 finally:os.close(fd)
 assert identity(p.lstat())==identity(s)
 return b,{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'identity':identity(s)}
def create(p,b):
 with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 z,r=read(p);assert z==b
 return r
selected=[]
for n in ['cpython31214-r1','cpython31214-r2','cpython31214-r1/development-packages-r1']:
 for p in sorted((T/n).iterdir()):
  if p.is_file() and not p.name.startswith('.') and p.suffix not in {'.xz','.deb'}:selected.append(p)
selected.append(T/'build_cpython31214_with_deps_r3.py')
for root in ['cpython31214-r1','cpython31214-r2']:
 for n in ['Makefile','pyconfig.h','config.status']:selected.append(T/root/'build'/n)
for n in ['ceval.c','frame.c','generated_cases.c.h','specialize.c']:selected.append(T/'cpython31214-r1/Python-3.12.14/Python'/n)
files={};members={}
for p in selected:
 b,r=read(p);name=p.relative_to(T).as_posix();assert name not in members;files[name]=r;members[name]=b
exe=T/'cpython31214-r2/prefix/bin/python3.12';binary,exepin=read(exe)
assert len(binary)==29756920 and exepin['sha256']=='1dbbe782bad1bf4519a583edbefcb9544971f39b0ea93fb874d0515283e76401'
assert json.loads(members['cpython31214-r2/BUILD-RETURN.json'])['status']=='PRIVATE_CPYTHON_31214_BUILT_UNQUALIFIED_FOR_HIA'
bio=io.BytesIO()
with tarfile.open(fileobj=bio,mode='w',format=tarfile.USTAR_FORMAT) as tf:
 for name,b in sorted(members.items()):
  ti=tarfile.TarInfo(name);ti.size=len(b);ti.mode=0o600;ti.uid=1000;ti.gid=1000;ti.mtime=0;tf.addfile(ti,io.BytesIO(b))
tar=bio.getvalue();gz=gzip.compress(tar,compresslevel=9,mtime=0)
decoded={}
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(gz)),mode='r:') as tf:
 for m in tf:
  assert m.isfile() and m.name not in decoded;decoded[m.name]=tf.extractfile(m).read()
assert decoded==members
os.mkdir(D,0o700);archive=create(D/'ORIGINALS.tar.gz',gz)
parts=[]
for i,off in enumerate(range(0,len(gz),262144),1):
 b=base64.b64encode(gz[off:off+262144])+b'\n';p=D/f'ORIGINALS.tar.gz.base64.part-{i:03}.txt';parts.append(create(p,b))
manifest={'schema':'hia.private-cpython31214.build-custody.v1','status':'PRIVATE_RUNTIME_BUILT_NOT_HIA_QUALIFIED','executable':exepin,'binary_and_installed_prefix_archived':False,'included':'Complete original build controls, intents, returns, logs, inventories, ELF readelf output, and four upstream reference bodies; executable remains at bound private host path.','original_files':files,'file_count':len(files),'original_bytes':sum(len(v) for v in members.values()),'archive':archive,'archive_members_full_byte_roundtrip_verified':True,'parts':parts,'source_archive':{'url':'https://www.python.org/ftp/python/3.12.14/Python-3.12.14.tar.xz','bytes':20820300,'sha256':'5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a'},'old_failures_preserved':['Original owner rejected 900-second invocation before worker launch','First dependency build lacked _ctypes; original successful stages and failing isolated probe remain HOLD'],'successful_build_job':'1a1d3654e33-392-11b','no_HIA_source_or_native_qualification_executed_by_this_build':True}
mr=create(D/'MANIFEST.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'status':manifest['status'],'files':len(files),'original_bytes':manifest['original_bytes'],'archive':archive,'manifest':mr,'parts':parts},sort_keys=True))
