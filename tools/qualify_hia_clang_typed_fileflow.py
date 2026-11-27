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
def compare_os(cap,expected):
 ns,stored,name=v.parts(cap)
 assert v.python(name)==type(expected).__name__ and v.python_value(stored)==expected.args,(v.python(name),v.python_value(stored),expected)
 for i,field in enumerate(['errno','strerror','filename','filename2']):
  value=v.keep(v.raw(105,a=cap,arg0=i));assert v.python_value(value)==getattr(expected,field),(field,v.python_value(value),getattr(expected,field))
def exception_fields(cap):
 ns,arguments,name=v.parts(cap)
 return ns,v.python_value(arguments),v.python(name)
def chain_fields(cap):
 return [v.keep(v.raw(107,a=cap,arg0=i))for i in range(3)]

from tools.qualify_hia_clang_inventory_error_text import u
origin_ip=native_base+bridge.rindex(b'\x0f\x05')+2
assert origin_ip>native_base+symbols['.Av_origin_producer']
def notified(w,wp,data,point,numbers,action,label):
 import time,select,errno
 from tools.qualify_hia_native_callable_code_owner import listener,Notification,Response,LIBC
 ready=queue.Queue();result=queue.Queue();notices=[]
 def go():
  try:ready.put(listener(point,numbers));result.put(invoke(w,wp,data))
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
   assert notice.data.ip==point and notice.data.nr in numbers
   phase=u(w,2097152);error=action(notice,phase)
   notices.append({'nr':notice.data.nr,'phase':phase,'error':error})
   response=Response(notice.id,0,-error if error else 0,0 if error else 1)
   assert LIBC.ioctl(fd,0xc0182101,C.byref(response))==0,C.get_errno()
  thread.join(1)
 finally:os.close(fd);thread.join(10)
 assert not thread.is_alive();pair=result.get_nowait()
 if isinstance(pair,BaseException):raise pair
 (root/(label+'.notices.json')).write_text(json.dumps(notices,indent=2)+'\n')
 return pair,notices
def none_chain(cap):
 cause,context,suppress=chain_fields(cap)
 assert v.python(cause)is None and v.python(context)is None and v.python(suppress)is False
def inner_path(w,off,size):
 ptr=u(w,2097152+616)+u(w,2097152+off);n=u(w,2097152+size);assert n and ptr
 return os.fsdecode(C.string_at(ptr,n))
try:
 for nr,phase,number,label in [(258,304,13,'mkdir-permission'),(257,307,24,'source-open-files'),(1,308,5,'source-write-io'),(86,515,13,'publish-link-permission'),(86,515,17,'publish-link-exists')]:
  cap=v.scalar('clang');w,wp,owned=session();expected={}
  def action(notice,now):
   if now!=phase:return 0
   if nr==258:
    path=os.path.join(os.readlink('/proc/self/fd/'+str(notice.data.args[0])),os.fsdecode(C.string_at(notice.data.args[1])))
    assert path==inner_path(w,912,904);expected['os']=OSError(number,os.strerror(number),path)
   elif nr==257:
    path=os.path.join(os.readlink('/proc/self/fd/'+str(notice.data.args[0])),os.fsdecode(C.string_at(notice.data.args[1])))
    assert path==inner_path(w,928,920);expected['os']=OSError(number,os.strerror(number),path)
   elif nr==86:
    stage=os.fsdecode(C.string_at(notice.data.args[0]));dest=os.fsdecode(C.string_at(notice.data.args[1]))
    assert stage==inner_path(w,944,936)and dest==inner_path(w,880,872)
    expected['os']=OSError(number,os.strerror(number),stage,None,dest)
   else:expected['os']=OSError(number,os.strerror(number))
   return number
  (rc,out),notices=notified(w,wp,frame(cap,label),origin_ip,[nr],action,label)
  h=struct.unpack('<64Q',out[:512]);assert rc==0 and h[1]!=0 and expected and any(row['error']==number for row in notices),(label,rc,h)
  actual=take_exception(w,wp)
  if nr==86:
   _,arguments,name=exception_fields(actual);assert name=='PublicationRejected'and arguments==('E_PUBLISH_LINK: no-replace link failed',)
   cause,context,suppress=chain_fields(actual);assert v.same(cause,context)and v.python(suppress)is True
   compare_os(cause,expected['os'])
  else:compare_os(actual,expected['os']);none_chain(actual)
  ended(w,wp);passed(label,actual_errno=number,actual_exception_graph=True,all_resources_retired=True)
 import tempfile
 assert tempfile.TMP_MAX==20
 cap=v.scalar('clang');w,wp,owned=session();collisions=[]
 def collide(notice,phase):
  assert phase==304
  parent=Path(os.readlink('/proc/self/fd/'+str(notice.data.args[0])));leaf=os.fsdecode(C.string_at(notice.data.args[1]));path=parent/leaf
  assert parent.resolve()==root.resolve()and not path.exists()and len(collisions)<20
  path.mkdir(mode=0o700);collisions.append(path)
  return 0
 (rc,out),notices=notified(w,wp,frame(cap,'original-twenty-temp-collisions'),origin_ip,[258],collide,'original-twenty-temp-collisions')
 assert rc==0 and len(collisions)==20 and u(w,2097152+1144)==20
 actual=take_exception(w,wp);compare_os(actual,FileExistsError(17,'No usable temporary directory name found'));none_chain(actual)
 ended(w,wp)
 for path in collisions:assert path.is_dir();path.rmdir()
 passed('original-twenty-real-temp-collisions',actual_kernel_eexist=20,original_TMP_MAX=20,exact_exception=True)
 cap=v.scalar('clang');w,wp,owned=session();competitor=root/'publication-competitor.so';written={}
 def competing(notice,phase):
  if phase==512 and not written:
   path=Path(os.fsdecode(C.string_at(notice.data.args[0])));assert path==competitor and not path.exists()
   path.write_bytes(b'other writer');written['path']=str(path)
  return 0
 (rc,out),notices=notified(w,wp,frame(cap,'publication-competitor'),origin_ip,[4],competing,'publication-competitor')
 assert rc==0 and written
 actual=take_exception(w,wp);_,arguments,name=exception_fields(actual)
 assert name=='PublicationRejected'and arguments==('E_PUBLISH_EXISTS: output must be a new file',);none_chain(actual)
 ended(w,wp);assert competitor.read_bytes()==b'other writer';competitor.unlink()
 passed('publication-existing-path-keeps-actual-other-writer',actual_exception_graph=True,other_inode_untouched=True)
 chosen=source/'examples/hia_bootstrap/clang_value_early_error.hepta'
 assert chosen.is_file()
 original_source=chosen.read_bytes()
 for post in [False,True]:
  label='implementation-stale-'+('publication'if post else'compilation')
  cap=v.scalar('clang');w,wp,owned=session();changed={}
  def mutate(notice,phase):
   trigger=phase==515 if post else u(w,2097152+1080)==0 and u(w,2097152+1072)==501
   if trigger and not changed:
    chosen.chmod(0o600);chosen.write_bytes(original_source+b'\n');chosen.chmod(0o400)
    changed['actual_source_file']=str(chosen)
   return 0
  try:
   (rc,out),notices=notified(w,wp,frame(cap,label),origin_ip if post else file_ip,[86]if post else[6],mutate,label)
   h=struct.unpack('<64Q',out[:512]);assert rc==0 and h[1]==10 and changed,(label,rc,h,changed)
   actual=take_exception(w,wp);_,arguments,name=exception_fields(actual)
   want='E_HIA_PROGRAM_STALE: native compiler or HIA implementation changed during '+('publication'if post else'compilation')
   assert name=='HIAProgramLLVMRejected'and arguments==(want,),(label,name,arguments)
   none_chain(actual)
   assert not (root/(label+'.so')).exists()
   if post:assert h[40]==1 and h[41]==0 and u(w,2097152+1312)==1 and u(w,2097152+1728)==0,('real own hardlink must be withdrawn',h)
   ended(w,wp);passed(label,actual_source_mutation=changed,exact_exception=True,actual_withdrawal=post)
  finally:chosen.chmod(0o600);chosen.write_bytes(original_source);chosen.chmod(0o400)
 b.close();assert set(os.listdir('/proc/self/fd'))==before
 del lib.hia_clang_value_bind_owner,lib.hia_clang_value_compile,lib.hia_clang_value_exception
 dlclose(lib._handle);del lib;os.close(memfd)
 assert set(os.listdir('/proc/self/fd'))==before_all
 report.update(passed=True,groups=len(cases),actual_clang_and_filesystem=True,typed_fileflow_qualified=True,host_binding_writes=False,actual_final_memfd_closed=True)
except BaseException as e:report.update(failure=repr(e),traceback=traceback.format_exc());raise
finally:save()
print('CLANG_TYPED_FILEFLOW_ACTUAL_PASS',len(cases),flush=True)
