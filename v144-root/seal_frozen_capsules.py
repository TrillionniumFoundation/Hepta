"""Lossless Root-only custody of frozen authoring and actual op10 failure."""
import base64,gzip,hashlib,io,json,os,stat,tarfile,time
from pathlib import Path
OUT=Path('/tmp/hia-root-v144-capsules-dda7');OUT.mkdir(mode=0o700)
def pin(raw):
 return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def seven(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(name,raw):
 with (OUT/name).open('xb') as f:f.write(raw)
 return {'path':str(OUT/name),**pin(raw)}
packages={
 'patch-author-r1-r2-r3':{'trees':{'author':Path('/tmp/hia-patch-result-owner-r1-dda7')},'extra':[]},
 'op10-r3-actual-failure':{'trees':{'attempt':Path('/dev/shm/hia-inspect-cli-controls-r3-dda7/attempt-r1'),'launch':Path('/tmp/hia-root-op10-r3-execution-dda7')},'extra':[
 '/tmp/hia-root-v141-dda7/verify_op10_r3_product_failure.py',
 '/tmp/hia-root-v141-dda7/verify_op10_r3_product_failure_r2.py',
 '/tmp/hia-root-v141-dda7/op10-r3-failure-reader-r1-error.json',
 '/tmp/hia-root-v141-dda7/op10-r3-product-failure-root-terminal.json',
 '/tmp/hia-root-v141-dda7/op10-r3-product-failure-root-inventory.json',
 '/tmp/hia-root-v141-dda7/launch_op10_r3_once.py',
 '/tmp/hia-root-v141-dda7/op10-r3-root-product-authorization.json']}}
summaries={}
for label,config in packages.items():
 start=time.monotonic_ns();files={};directories={}
 def add(path,logical):
  s=path.lstat();assert stat.S_ISREG(s.st_mode)
  raw=path.read_bytes();assert seven(s)==seven(path.lstat())
  assert logical not in files
  files[logical]={'origin':str(path),'pin':pin(raw),'posix_mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s),'raw':raw}
 for prefix,root in config['trees'].items():
  directories[prefix]=stat.S_IMODE(root.lstat().st_mode)
  for path in sorted(root.rglob('*')):
   s=path.lstat();assert not stat.S_ISLNK(s.st_mode)
   logical=prefix+'/'+path.relative_to(root).as_posix()
   if stat.S_ISDIR(s.st_mode):directories[logical]=stat.S_IMODE(s.st_mode)
   else:add(path,logical)
 if config['extra']:directories['root']=0o755
 for name in config['extra']:add(Path(name),'root/'+Path(name).name)
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
  for name,mode in sorted(directories.items()):
   info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=mode;info.mtime=0;tar.addfile(info)
  for name,row in sorted(files.items()):
   info=tarfile.TarInfo(name);info.mode=row['posix_mode'];info.size=len(row['raw']);info.mtime=0
   tar.addfile(info,io.BytesIO(row['raw']))
 archive=gzip.compress(stream.getvalue(),compresslevel=6,mtime=0)
 with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive)),mode='r:') as tar:
  got_files={m.name:m for m in tar.getmembers() if m.isfile()};got_dirs={m.name:m for m in tar.getmembers() if m.isdir()}
  assert set(got_files)==set(files) and set(got_dirs)==set(directories)
  assert len(tar.getmembers())==len(files)+len(directories)
  for name,m in got_files.items():assert m.mode==files[name]['posix_mode'] and tar.extractfile(m).read()==files[name]['raw']
  for name,m in got_dirs.items():assert m.mode==directories[name]
 for name,row in files.items():assert seven(Path(row['origin']).lstat())==row['seven_stats']
 manifest={name:{k:v for k,v in row.items() if k!='raw'} for name,row in files.items()}
 total=sum(len(row['raw']) for row in files.values())
 capsule={'schema':'hepta.root.lossless-custody.v1','label':label,'encoding':'gzip-ustar+base64','archive':pin(archive),'files':len(files),'directories':len(directories),'logical_bytes':total,'data_base64':base64.b64encode(archive).decode(),'qualification':'No new product execution; immutable historical authoring or exact failed run only'}
 refs={}
 refs['capsule']=write(label+'-CAPSULE.json',encoded(capsule))
 refs['manifest']=write(label+'-MANIFEST.json',encoded({'schema':'hepta.root.lossless-custody-manifest.v1','label':label,'files':manifest,'directories':directories}))
 proof={'schema':'hepta.root.lossless-custody-readback.v1','status':'PASS_FULL_ROUNDTRIP','label':label,'capsule':refs['capsule'],'manifest':refs['manifest'],'archive':pin(archive),'files':len(files),'directories':len(directories),'logical_bytes':total,'full_all_bytes_modes_pathsets_current_seven_stats':True,'product_executions':0,'originals_deleted':False,'elapsed_ns':time.monotonic_ns()-start}
 refs['proof']=write(label+'-READBACK.json',encoded(proof));summaries[label]=refs
print(json.dumps(summaries,sort_keys=True,indent=2))
