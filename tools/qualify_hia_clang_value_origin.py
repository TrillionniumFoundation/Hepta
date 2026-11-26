"""Actual native Clang Value origin qualification; Python is a QA driver only."""
from pathlib import Path
import ctypes as C,mmap,os,json,struct,hashlib,traceback,shutil,fcntl,subprocess,queue,threading,stat
from _ctypes import dlclose
from tools.qualify_hia_result_value_invocations import Values,Bound,make_engine,sweep
from tools.qualify_hia_clang_compile import small,guarded
from tools.qualify_hia_native_callable_code_owner import deny_native
from hepta.hia_program import verify_program
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--package',type=Path,required=True)
parser.add_argument('--owner',type=Path,required=True)
parser.add_argument('--owner-sha256',default='da5f0d0a144a1bd82b590cc87f0d1d55f98166348bba3ad346179339deb32897')
parser.add_argument('--library-sha256',default='631c9d64dd9f60d0e27fdb704aefaf8b40f03cb934962b07a7780d664c23f2fe')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.output;root.mkdir(mode=0o700)
build=args.package;owner=args.owner;library=build/'build/clang-value.so'
assert hashlib.sha256(owner.read_bytes()).hexdigest()==args.owner_sha256
assert hashlib.sha256(library.read_bytes()).hexdigest()==args.library_sha256
before_all=set(os.listdir('/proc/self/fd'))
memfd=os.memfd_create('hia-actual-clang-origin-test',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
raw_image=library.read_bytes();at=0
while at<len(raw_image):at+=os.write(memfd,raw_image[at:])
fcntl.fcntl(memfd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
assert fcntl.fcntl(memfd,fcntl.F_GET_SEALS)==15
lib=C.CDLL('/proc/self/fd/'+str(memfd))
for name in ['hia_clang_value_bind_owner','hia_clang_value_compile','hia_clang_value_exception']:
 f=getattr(lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
source=root/'source-initial';shutil.copytree(build/'source',source)
before=set(os.listdir('/proc/self/fd'))
b=Bound(owner);a=b.call(0);assert a['status']==0 and a['state']==2 and a['pending']==0,a
v=Values(make_engine(b));program=verify_program(small(7));cases=[]
report=dict(passed=False,cases=cases,sealed_memfd=True,product=dict(bytes=len(raw_image),sha256=hashlib.sha256(raw_image).hexdigest()),whole_public_runtime_qualified=False)
def save():(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def passed(name,**kw):
 cases.append(dict(case=name,passed=True,**kw));save();print('ORIGIN_PASS',name,flush=True)
bridge=(build/'build/bridge.bin').read_bytes();symbols={}
for line in subprocess.check_output(['/usr/bin/nm','-n',str(build/'build/bridge.o')],text=True).splitlines():
 f=line.split()
 if len(f)==3:symbols[f[2]]=int(f[0],16)
at=bridge.index(b'\x0f\x05',symbols['.Av_syscall']);assert at<symbols['.Av_busy']
ip=C.cast(lib.hia_clang_value_compile,C.c_void_p).value+at+2
def isolated(filters,fn):
 q=queue.Queue()
 def go():
  try:
   for nr,err in filters:deny_native(ip,nr,err)
   q.put(fn())
  except BaseException as e:q.put(e)
 t=threading.Thread(target=go);t.start();t.join(120);assert not t.is_alive()
 result=q.get_nowait()
 if isinstance(result,BaseException):raise result
 return result
def new_work():
 w=mmap.mmap(-1,538968064);return w,C.addressof(C.c_char.from_buffer(w))
def bind(w,wp,fd,owner_=None):
 rq=C.create_string_buffer(b'HIACVOB2'+struct.pack('<3Q',fd,0,0))
 return lib.hia_clang_value_bind_owner(rq,32,wp,len(w),(owner_ or b).owner.context,2048)
def session():
 w,wp=new_work();fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  assert bind(w,wp,fd)==0
  owned=struct.unpack_from('<Q',w,104)[0]
  assert struct.unpack_from('<Q',w,112)[0]==1 and owned!=fd
  assert fcntl.fcntl(owned,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
  assert os.fstat(owned).st_ino==os.fstat(fd).st_ino and stat.S_ISDIR(os.fstat(owned).st_mode)
 finally:os.close(fd)
 return w,wp,owned
def frame(cap,name,target=0,kind=0,layout=0):
 raw=program.canonical_bytes;path=os.fsencode(root/(name+('.so' if kind==0 else '.o')))
 data=bytearray(256);data[:8]=b'HIACVPC1'
 for at,n in [(16,target),(24,kind),(32,layout),(40,len(raw)),(56,len(path))]:struct.pack_into('<Q',data,at,n)
 struct.pack_into('<3Q',data,64,*cap);return bytes(data)+raw+path
retire=b'HIAMVBC1'+struct.pack('<31Q',1,*([0]*30))
def invoke(w,wp,data):
 s=C.create_string_buffer(data);out=C.create_string_buffer(1049088 if len(data)>256 else 512)
 rc=lib.hia_clang_value_compile(s,len(data),out,len(out),wp,len(w))
 return rc,bytes(out)
def ended(w,wp):
 rc,out=invoke(w,wp,retire);vals=struct.unpack('<64Q',out[:512])
 assert rc==0 and vals[43:46]==(1,1,0),(rc,vals[42:48])
 assert struct.unpack_from('<Q',w,112)[0]==0
 w.close();sweep(v,b);assert set(os.listdir('/proc/self/fd'))==before
try:
 for target,kind,layout in [(0,0,0),(0,1,0),(1,1,0),(2,1,0),(0,0,1)]:
  program=verify_program(guarded(7) if layout else small(7))
  cap=v.scalar('clang');w,wp,owned=session()
  name='profile_'+str(target)+'_'+str(kind)+'_'+str(layout)
  if len(cases)==0:
   new_source=root/'source-after-native-dup';source.rename(new_source);source=new_source
  rc,out=invoke(w,wp,frame(cap,name,target,kind,layout));h=struct.unpack('<64Q',out[:512])
  print('ORIGIN_PROFILE_RESULT',name,rc,h[:17],struct.unpack_from('<Q',w,256)[0],flush=True)
  assert rc==0 and h[1]==0 and h[13]==target and h[41]==kind,(name,rc,h)
  receipt=json.loads(out[512:512+h[10]]);assert receipt['input_sha256']==program.sha256
  artifact=root/(name+('.so' if kind==0 else '.o'));raw=artifact.read_bytes()
  assert raw[:4]==b'\x7fELF' and struct.unpack_from('<H',raw,18)[0]==[62,183,243][target]
  assert struct.unpack_from('<H',raw,16)[0]==(3 if kind==0 else 1)
  if kind==0:
   native=C.CDLL(str(artifact));calc=native.calculate;calc.argtypes=[C.c_uint64];calc.restype=C.c_uint64
   vectors=[(0,7),(1,8),(31,38),(32,43),(35,46),((1<<64)-1,10)] if layout else [(35,42),((1<<64)-1,6)]
   for arg,expected in vectors:assert calc(arg)==expected
   del calc;dlclose(native._handle);del native
  ended(w,wp);passed(name,source_directory_captured_and_parent_fd_closed=True,real_clang=True,actual_artifact=True,receipt=receipt)
 for nr,err,label in [(72,24,'actual-fcntl-dup-emfile'),(5,5,'actual-fstat-eio')]:
  w,wp=new_work();fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try:rc=isolated([(nr,err)],lambda:bind(w,wp,fd))
  finally:os.close(fd)
  assert rc==0xfffffffb,hex(rc)
  assert struct.unpack_from('<Q',w,96)[0]==1
  assert struct.unpack_from('<Q',w,112)[0]==(0 if nr==72 else 1)
  ended(w,wp);passed(label,actual_failed_bind=True,actual_token_and_fd_retirement=True)
 w,wp=new_work();fd=os.open(library,os.O_RDONLY|os.O_CLOEXEC)
 try:rc=bind(w,wp,fd)
 finally:os.close(fd)
 assert rc==0xfffffffb and struct.unpack_from('<Q',w,112)[0]==1
 ended(w,wp);passed('actual-nondirectory-rejection-and-retirement')
 w,wp,owned=session()
 rc,out=isolated([(436,5)],lambda:invoke(w,wp,retire));h=struct.unpack('<64Q',out[:512])
 assert rc==0 and h[43:46]==(1,0,1) and h[46:48]==(12,5),h[42:48]
 assert struct.unpack_from('<Q',w,112)[0]==1 and stat.S_ISDIR(os.fstat(owned).st_mode)
 ended(w,wp);passed('actual-close-range-eio-keeps-owned-directory-until-real-ACK')
 w,wp,owned=session()
 rc,out=isolated([(436,38)],lambda:invoke(w,wp,retire));h=struct.unpack('<64Q',out[:512])
 assert rc==0 and h[43:46]==(1,1,0),h[42:48]
 ended(w,wp);passed('actual-close-range-enosys-native-close-fallback-ACK')
 cap=v.scalar('clang');w,wp,owned=session();valid=frame(cap,'guards');prefix=bytes(w[:4096]);badframes=[]
 for at,n in [(16,3),(24,2),(32,2),(88,1),(248,1)]:
  z=bytearray(valid);struct.pack_into('<Q',z,at,n);badframes.append(bytes(z))
 for data in badframes:
  inp=C.create_string_buffer(data);out=C.create_string_buffer(b'\xa5'*1049088)
  rc=lib.hia_clang_value_compile(inp,len(data),out,1049088,wp,len(w))
  assert rc==0xfffffffd and out.raw==b'\xa5'*1049088+b'\0' and bytes(w[:4096])==prefix
 ended(w,wp);passed('new-public-profile-static-guards-no-write',controls=len(badframes))
 w,wp=new_work()
 for at,n in [(8,(1<<64)-1),(16,1),(24,1)]:
  data=bytearray(b'HIACVOB2'+bytes(24));struct.pack_into('<Q',data,at,n);inp=C.create_string_buffer(bytes(data))
  rc=lib.hia_clang_value_bind_owner(inp,32,wp,len(w),b.owner.context,2048)
  assert rc==0xfffffffd and bytes(w[:4096])==bytes(4096)
 w.close();assert set(os.listdir('/proc/self/fd'))==before
 passed('new-native-origin-binder-static-guards-no-authority-write',controls=3)
 rd,wr=os.pipe();pid=os.fork()
 if pid==0:
  os.close(rd)
  try:
   child=Bound(owner);z=child.call(0);assert z['status']==0 and z['state']==2
   w,wp=new_work();fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
   assert bind(w,wp,fd,child)==0;os.close(fd);owned=struct.unpack_from('<Q',w,104)[0]
   deny_native(ip,436,38);deny_native(ip,3,5)
   rc,out=invoke(w,wp,retire);h=struct.unpack('<64Q',out[:512])
   assert rc==0 and h[42:46]==(2,0,0,1),h[42:48]
   assert struct.unpack_from('<Q',w,112)[0]==1 and stat.S_ISDIR(os.fstat(owned).st_mode)
   rc,out=invoke(w,wp,retire);h=struct.unpack('<64Q',out[:512])
   assert rc==0 and h[42:46]==(2,0,0,1) and stat.S_ISDIR(os.fstat(owned).st_mode)
   os.write(wr,b'known-unknown-custody-retained-until-process-exit')
   os._exit(0)
  except BaseException:
   os.write(wr,traceback.format_exc().encode());os._exit(1)
 os.close(wr);_,status=os.waitpid(pid,0);message=os.read(rd,4096);os.close(rd)
 assert status==0,(status,message)
 assert set(os.listdir('/proc/self/fd'))==before
 passed('actual-fallback-close-eio-quarantines-unknown-custody',child_exit_status=status,message=message.decode(),actual_process_bounded_retirement=True,no_false_per_context_retirement=True)
 b.close();assert set(os.listdir('/proc/self/fd'))==before
 del lib.hia_clang_value_bind_owner,lib.hia_clang_value_compile,lib.hia_clang_value_exception
 dlclose(lib._handle);del lib;os.close(memfd)
 assert set(os.listdir('/proc/self/fd'))==before_all
 report.update(passed=True,groups=len(cases),no_host_binding_writes=True,actual_final_memfd_closed=True)
except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();save();raise
finally:save()
print('CLANG_VALUE_ORIGIN_PASS',len(cases),flush=True)
