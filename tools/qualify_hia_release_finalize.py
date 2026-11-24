"""External qualification of the HIA finalization boundary.

This Python fixture creates sealed descriptors and observes real native effects.
It is never called by the product release owner or by a native finalizer child.
Each output directory is new and private; failed cases are retained.
"""
from pathlib import Path
from hashlib import sha256
import os,fcntl,struct,subprocess,json,sys,time,shutil,traceback
import argparse

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description="Qualify the native HIA finalizer against supplied native release components.")
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--runner',type=Path,required=True)
parser.add_argument('--runner-sha256',required=True)
parser.add_argument('--release',type=Path,required=True)
parser.add_argument('--directory-image',type=Path)
parser.add_argument('--installer-image',type=Path)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--trace',action='store_true')
parser.add_argument('--case',default='minimal',choices=('minimal','full','parent-auto','nested','wrong-parent','expired','wrong-payload-pin','wrong-tool-pin','occupied','work-occupied','wrong-directory','unsealed','unsealed-request','fsync-after-publish','receipt-loss'))
args=parser.parse_args()
R=args.release.resolve(strict=True)
exe=args.image.resolve(strict=True);D=args.output.resolve();kind=args.case
D.mkdir(mode=0o700,exist_ok=False)
stage=D/'stage';work=D/'work';output=D/'output'
for d in (stage,work,output):d.mkdir(mode=0o700)
names=['hia-directory-package-build','hia-source-build','hia-release','hia-artifact']
if kind=='full':
 for p in R.iterdir():
  assert p.is_file() and not p.is_symlink()
  target=stage/p.name;target.write_bytes(p.read_bytes());target.chmod(p.stat().st_mode & 0o777)
else:
 for n in names:
  target=stage/n;target.write_bytes((R/n).read_bytes());target.chmod((R/n).stat().st_mode & 0o777)
 (stage/'payload.txt').write_bytes(b'HIA native finalization boundary\n');(stage/'payload.txt').chmod(0o400)
for name,override in [('hia-directory-package-build',args.directory_image),('hia-release',args.installer_image)]:
 if override:
  target=stage/name;target.chmod(0o600);target.write_bytes(Path(override).read_bytes());target.chmod(0o500)
members={p.name:sha256(p.read_bytes()).hexdigest() for p in sorted(stage.iterdir())}
if kind=='wrong-payload-pin':members['payload.txt']='0'*64
if kind=='wrong-tool-pin':members['hia-artifact']='0'*64
if kind=='occupied':(output/'keep.txt').write_text('unrelated file must remain\n')
if kind=='work-occupied':(work/'store.hiapack').write_text('unrelated work file must remain\n')
outname='output'
if kind=='wrong-directory':
 (D/'different').mkdir(mode=0o700);outname='different'
fds=[]
def opened(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd);return fd
def memory(data,sealed=True,mode=0o600):
 fd=os.memfd_create('hia-finalizer-test',os.MFD_ALLOW_SEALING);fds.append(fd);os.fchmod(fd,mode)
 view=memoryview(data)
 while view:
  n=os.write(fd,view);assert n>0;view=view[n:]
 if sealed:fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 return fd
st,wo,pa,ou=map(opened,(stage,work,D,output))
runner=args.runner.read_bytes();assert sha256(runner).hexdigest()==args.runner_sha256
code=[memory(runner,mode=0o500)]+[memory((stage/n).read_bytes(),mode=0o500,sealed=not(kind=='unsealed' and n=='hia-artifact')) for n in names]
inv=bytearray(struct.pack('<8sQQ',b'HIAINV01',len(members),0))
for n,pin in members.items():
 n=n.encode();d=pin.encode();inv+=struct.pack('<QQ',len(n),len(d))+n+d
rawname=outname.encode()
parent=0 if kind in ('parent-auto','nested') else os.getpid()+1000 if kind=='wrong-parent' else os.getpid()
deadline=1 if kind=='expired' else time.monotonic_ns()+180_000_000_000
wire=struct.pack('<8s15Q',b'HIAFIN01',parent,deadline,st,wo,pa,ou,*code,len(rawname),len(inv),64,0)+rawname+sha256(runner).hexdigest().encode()+inv
request=memory(wire,sealed=kind!='unsealed-request');image=memory(exe.read_bytes(),mode=0o500);started=time.monotonic()
record={'schema':'hepta.hia.release-finalize-qualification.v1','whole_native_delivery_qualified':False,'kind':kind,'source':str(exe),'exe_sha256':sha256(exe.read_bytes()).hexdigest(),'runner_sha256':sha256(runner).hexdigest(),'input_sha256':sha256(wire).hexdigest(),'member_count':len(members),'started_ns':time.time_ns()}
try:
 command=['/proc/self/fd/'+str(image)]
 if kind=='nested':
  outer_out=memory(b'',sealed=False);outer_err=memory(b'',sealed=False);outer_receipt=memory(b'',sealed=False)
  argv=b'hia-release-finalize';env=b'PATH='
  packet=struct.pack('<8s15Q',b'HIASUB01',os.getpid(),deadline,image,request,outer_out,outer_err,pa,outer_receipt,1,1,4096,16384,1_000_000_000,2_147_483_648,0)
  packet+=struct.pack('<Q',len(argv))+argv+b'\0'+struct.pack('<Q',len(env))+env+b'\0'
  inherited=[st,wo,pa,ou,*code];packet+=struct.pack('<8sQ',b'HIAPFD01',len(inherited))+struct.pack('<'+'Q'*len(inherited),*inherited)
  request=memory(packet);command=['/proc/self/fd/'+str(code[0])]

 if kind=='fsync-after-publish':command=['/usr/bin/strace','-D','-qq','-s','96','-o',str(D/'trace.log'),'-e','inject=fsync:error=EIO:when=2','-e','trace=process,fsync,write',*command]
 if args.trace:command=['/usr/bin/strace','-D','-f','-qq','-s','96','-o',str(D/'trace.log'),'-e','trace=process,read,write,pread64,pwrite64,fcntl,fstat,newfstatat,openat,mkdirat,linkat,unlinkat,lseek,getdents64,fsync,sendfile',*command]
 sink=subprocess.PIPE
 if kind=='receipt-loss':
  read_end,write_end=os.pipe();os.close(read_end);fds.append(write_end);sink=write_end
 r=subprocess.run(command,stdin=request,stdout=sink,stderr=subprocess.PIPE,env={'PATH':''},pass_fds=tuple(fds),cwd=D,timeout=200)
 if r.stdout is None:r=subprocess.CompletedProcess(command,r.returncode,b'',r.stderr)
 if kind=='nested':
  raw=os.pread(outer_receipt,128,0);values=struct.unpack('<8sq14Q',raw)
  record['outer_receipt']=list(values[1:])
  assert r.returncode==0 and values[0]==b'HIASBR01' and values[1]==0 and values[2]==0 and values[12]==values[13]==values[15]==1,values
  r=subprocess.CompletedProcess(command,values[1],os.pread(outer_out,4096,0),os.pread(outer_err,16384,0))
 (D/'stdout').write_bytes(r.stdout);(D/'stderr').write_bytes(r.stderr);(D/'run.rc').write_text(str(r.returncode)+'\n')
 record.update(rc=r.returncode,seconds=time.monotonic()-started,stdout=r.stdout.decode(errors='replace'),stderr=r.stderr.decode(errors='replace'),output_files=[p.name for p in output.iterdir()],work_files=[p.name for p in work.iterdir()])
 if kind in ('minimal','full','parent-auto','nested'):
  assert r.returncode==0 and not r.stderr,record
  receipt=json.loads(r.stdout)
  package=output/'store.hiapack';assert package.is_file() and package.stat().st_mode & 0o777==0o400
  actual=sha256(package.read_bytes()).hexdigest()
  assert receipt=={'schema':'hepta.hia.release-finalize.v1','sha256':actual,'bytes':package.stat().st_size,'files':len(members),'published':True,'source_attested':True}
  assert os.path.samestat(package.stat(),(work/'store.hiapack').stat()) and os.path.samestat(package.stat(),(work/'authority.hiapack').stat())
  reference=subprocess.run([str(stage/'hia-directory-package-build'),str(stage)],capture_output=True,env={'PATH':''},timeout=180)
  assert reference.returncode==0 and reference.stdout==package.read_bytes() and reference.stderr==actual.encode()+b'\n'
  record['package_sha256']=actual;record['bytes']=package.stat().st_size
 else:
  assert r.returncode!=0
  assert not (output/'store.hiapack').exists()
  if kind in ('fsync-after-publish','receipt-loss'):
   assert (work/'authority.hiapack').is_file() and (work/'store.hiapack').is_file()
  if kind=='occupied':assert (output/'keep.txt').read_text()=='unrelated file must remain\n'
  if kind=='work-occupied':assert (work/'store.hiapack').read_text()=='unrelated work file must remain\n'
 record['passed']=True
except BaseException:
 record['error']=traceback.format_exc();raise
finally:
 record['finished_ns']=time.time_ns();(D/'terminal.json').write_text(json.dumps(record,indent=2)+'\n')
 for fd in fds:os.close(fd)
print(json.dumps(record))
