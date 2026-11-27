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
parser.add_argument('--owner-sha256',default='194a4a876ac00af12d4a2ca4e4ff34825eec7495d4b0e825a278cdb076a60e32')
parser.add_argument('--library-sha256',default='95a68b650aa094a5764eb78ab600e3e98e369b350b584c33f793473fb655ea95')
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
from tools import generate_hia_clang_value_error_packer as spec
from tools import generate_hia_clang_stable_file_packer as filespec
offsets={};at=len(spec.BRIDGE)
for role in spec.ROLES:
 at=(at+15)&~15;offsets[role]=at;at+=(build/'build'/(role+'.component')).stat().st_size
native_base=C.cast(lib.hia_clang_value_compile,C.c_void_p).value
file_raw=(build/'build/file.component').read_bytes()
file_syscall=filespec.BRIDGE.rindex(b'\x0f\x05')+2
identity_raw=(build/'build/error_identity.component').read_bytes()
identity_file_offset=identity_raw.index(file_raw)
file_ip=native_base+offsets['file']+file_syscall
identity_ip=native_base+offsets['error_identity']+identity_file_offset+file_syscall

def take_exception(w,wp):
 rq=C.create_string_buffer(b'HIAMVCE1'+bytes(120));answer=C.create_string_buffer(128)
 assert lib.hia_clang_value_exception(rq,128,answer,128,wp,len(w))==0
 values=struct.unpack('<16Q',bytes(answer))
 assert values[2]==2 and values[11]==1 and values[12]==1,('exception delivery',values,'phase',struct.unpack_from('<Q',w,256)[0],'plan',struct.unpack_from('<4Q',w,3072),'op',struct.unpack_from('<3Q',w,3160))
 return v.keep(bytes(answer))
def dictionary_get(cap,key):
 return v.keep(v.raw(9,a=cap,b=v.scalar(key)))
def exception_fields(cap):
 ns,arguments,name=v.parts(cap)
 return ns,v.python_value(arguments),v.python(name)
def chain_fields(cap):
 return [v.keep(v.raw(107,a=cap,arg0=i))for i in range(3)]

from tools.qualify_hia_clang_inventory_error_text import original,u,alter
def metadata_exports(w):
 at=2097152+291504128;n=u(w,at+32);assert 1<=n<=128
 pos=at+64;names=[]
 for _ in range(n):
  size=u(w,pos);assert 0<size<=512;names.append(bytes(w[pos+8:pos+8+size]).decode('ascii'));pos+=8+size
 return tuple(names)
def symbol_location(raw,kind,expected):
 table=u(raw,40);count=u(raw,60,2);wanted=11 if kind==0 else 2
 sections=[table+64*i for i in range(count)if u(raw,table+64*i+4,4)==wanted];assert len(sections)==1
 row=sections[0];symbols=u(raw,row+24);n=u(raw,row+32);names_row=table+64*u(raw,row+40,4)
 names=u(raw,names_row+24);names_n=u(raw,names_row+32)
 matches=[]
 for pos in range(symbols,symbols+n,24):
  offset=u(raw,pos,4)
  if offset and u(raw,pos+6,2):
   end=raw.index(b'\0',names+offset,names+names_n)
   if raw[names+offset:end].decode('ascii')in expected:matches.append((pos,names+offset,end))
 assert len(matches)==1,(kind,expected,matches)
 return matches[0]
def mutated(raw,kind,mode,expected):
 if mode=='shape':return alter(raw,(16,2,1 if kind==0 else 3))
 if mode=='flags':return alter(raw,(48,4,0))
 pos,name,end=symbol_location(raw,kind,expected)
 if mode=='unicode':return alter(raw,(name,1,255))
 if mode=='rename':return alter(raw,(name,1,81 if raw[name]!=81 else 90))
 if mode=='extent':return alter(raw,(pos+8,8,0))
 if mode=='zero':return alter(raw,(pos+16,8,0))
 if mode=='binding':return alter(raw,(pos+4,1,0xa2))
 if mode=='data':return alter(raw,(pos+4,1,0x11))
 if mode=='weak':return alter(raw,(pos+4,1,0x22))
 if mode=='no-export':return alter(raw,(pos+4,1,0x02))
 raise AssertionError(mode)
def changed_artifact(w,wp,data,kind,target,mode,label):
 import time,select,errno
 from tools.qualify_hia_native_callable_code_owner import listener,Notification,Response,LIBC
 ready=queue.Queue();result=queue.Queue();notices=[];changed={}
 def go():
  try:
   ready.put(listener(file_ip,[6]));result.put(invoke(w,wp,data))
  except BaseException as error:ready.put(error);result.put(error)
 thread=threading.Thread(target=go);thread.start();fd=ready.get(timeout=30)
 if isinstance(fd,BaseException):raise fd
 try:
  until=time.monotonic()+120
  while thread.is_alive():
   assert time.monotonic()<until,'original 120 second native gate exceeded'
   readable,_,_=select.select([fd],[],[],0.2)
   if not readable:continue
   notice=Notification()
   if LIBC.ioctl(fd,0xc0502100,C.byref(notice))<0:
    if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
    raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
   assert notice.data.ip==file_ip and notice.data.nr==6
   path=Path(os.fsdecode(C.string_at(notice.data.args[0])))
   if not changed and path.is_file()and path.suffix in('.so','.o'):
    assert path.resolve().is_relative_to(root.resolve()),path
    raw=path.read_bytes();expected=metadata_exports(w);machine=(62,183,243)[target]
    assert original(kind,raw,expected,machine)is None,('actual Clang must first create valid original artifact',path)
    altered=mutated(raw,kind,mode,expected);assert altered!=raw
    refused=original(kind,altered,expected,machine);assert refused is not None
    path.write_bytes(altered);assert path.read_bytes()==altered
    changed.update(path=str(path),original_sha256=hashlib.sha256(raw).hexdigest(),mutated_sha256=hashlib.sha256(altered).hexdigest(),expected=expected,exception=refused)
   notices.append({'nr':6,'path':str(path),'artifact_changed':bool(changed)})
   response=Response(notice.id,0,0,1);assert LIBC.ioctl(fd,0xc0182101,C.byref(response))==0,C.get_errno()
  thread.join(1)
 finally:os.close(fd);thread.join(10)
 assert not thread.is_alive();pair=result.get_nowait()
 if isinstance(pair,BaseException):raise pair
 assert changed,(label,notices)
 (root/(label+'.notices.json')).write_text(json.dumps(notices,indent=2)+'\n')
 return pair,changed
try:
 cases_to_run=[
  (0,0,'shape'),(0,0,'rename'),(0,0,'unicode'),(0,0,'zero'),(0,0,'extent'),
  (1,0,'shape'),(1,0,'binding'),(1,0,'unicode'),(1,0,'data'),(1,0,'weak'),
  (1,0,'rename'),(1,0,'no-export'),(1,2,'flags')]
 for kind,target,mode in cases_to_run:
  label=('shared'if kind==0 else'object')+'-'+mode
  cap=v.scalar('clang');w,wp,owned=session();data=frame(cap,label,target,kind)
  (rc,out),changed=changed_artifact(w,wp,data,kind,target,mode,label)
  h=struct.unpack('<64Q',out[:512]);assert rc==0 and h[1]==9,(label,rc,h[:12],u(w,256),u(w,288),u(w,2097152+696))
  expected=changed.pop('exception');actual=take_exception(w,wp)
  ns,arguments,name=exception_fields(actual)
  assert name==type(expected).__name__ and arguments==expected.args,(label,name,arguments,type(expected).__name__,expected.args)
  cause,context,suppress=chain_fields(actual)
  if expected.__cause__ is None:
   assert v.python(cause)is None and v.python(context)is None and v.python(suppress)is False,(label,'unexpected chain')
  else:
   ref=expected.__cause__;assert isinstance(ref,UnicodeDecodeError)and v.same(cause,context)and v.python(suppress)is True
   _,cargs,cname=exception_fields(cause);assert cname=='UnicodeDecodeError'and cargs==ref.args,(label,cname,cargs,ref.args)
   for i,key in enumerate(['encoding','object','start','end','reason']):
    value=v.keep(v.raw(109,a=cause,arg0=i));assert v.python_value(value)==getattr(ref,key),(label,key)
  assert not (root/(label+('.so'if kind==0 else'.o'))).exists(),('invalid artifact published',label)
  ended(w,wp);passed(label,actual_artifact_mutation=changed,actual_exception_graph=True,all_resources_retired=True)
 b.close();assert set(os.listdir('/proc/self/fd'))==before
 del lib.hia_clang_value_bind_owner,lib.hia_clang_value_compile,lib.hia_clang_value_exception
 dlclose(lib._handle);del lib;os.close(memfd)
 assert set(os.listdir('/proc/self/fd'))==before_all
 report.update(passed=True,groups=len(cases),actual_clang_and_native_inventory=True,typed_inventory_refusals_qualified=True,host_binding_writes=False,actual_final_memfd_closed=True)
except BaseException as e:report.update(failure=repr(e),traceback=traceback.format_exc());raise
finally:save()
print('CLANG_TYPED_INVENTORY_ACTUAL_PASS',len(cases),flush=True)
