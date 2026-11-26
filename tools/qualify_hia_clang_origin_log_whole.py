"""Actual PL1 logger initialization, Clang captures, row identity and cleanup."""
from pathlib import Path
import argparse,copy,ctypes as C,errno,fcntl,hashlib,json,mmap,os,platform,queue,select,stat,struct,subprocess,threading,time,traceback
from _ctypes import dlclose
from tools.qualify_hia_result_value_platform import Values
from tools.qualify_hia_result_value_invocations import Bound,Engine,sweep
from tools.qualify_hia_result_value_exceptions import frame as value_frame
from tools.qualify_hia_clang_compile import small
from tools.qualify_hia_native_callable_code_owner import deny_native,listener,Notification,Response,LIBC
from hepta.hia_program import verify_program
from hepta import hia_program_llvm as original
from hepta.clang_capture import CaptureResult,CaptureFailure,CaptureRejected
INNER=2097152;LOG=INNER+(290<<20);MASK=(1<<64)-1
def u(raw,at=0):return struct.unpack_from('<Q',raw,at)[0]
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
class DeferredEngine(Engine):
 def call(self,request,on=16384):
  raw=bytearray(request);op=u(raw,8)
  if raw[:6]==b'HIABVQ':
   proto=None;new=op
   if op==1:proto=b'HIABVQ10'
   elif op in(2,4,7,8,9,10,17,19,21,26,36,37,38,39):proto=b'HIABVQ06'
   elif op in(3,12,16,18,24):proto=b'HIABVQ07'
   elif op==23:proto=b'HIABVQ09'
   elif op in(32,40,43,57,75,87,98,99,100)or 101<=op<=112:proto=b'HIABVQ11'
   elif op==5:proto=b'HIABVQ05';new=91
   elif op in(6,29):proto=b'HIABVQ05';new=78
   elif op==30:proto=b'HIABVQ05';new=92
   elif op==31:proto=b'HIABVQ05';new=93
   if proto is not None:raw[:8]=proto;struct.pack_into('<Q',raw,8,new)
  return super().call(bytes(raw),on=on)

class Fixture:
 def __init__(self,package,owner,owner_sha,library_sha,out):
  assert platform.python_version()=='3.14.4'
  self.out=out;out.mkdir(parents=True,exist_ok=False)
  self.package=package;self.source=package/'source';self.before_all=set(os.listdir('/proc/self/fd'))
  library=package/'build/clang-value.so';raw=library.read_bytes()
  assert pin(raw)['sha256']==library_sha and pin(owner.read_bytes())['sha256']==owner_sha
  self.fd=os.memfd_create('hia-actual-logged-clang',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  at=0
  while at<len(raw):at+=os.write(self.fd,raw[at:])
  fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
  self.lib=C.CDLL('/proc/self/fd/'+str(self.fd))
  for name in('hia_clang_value_bind_owner','hia_clang_value_compile','hia_clang_value_exception'):
   fun=getattr(self.lib,name);fun.argtypes=[C.c_void_p,C.c_uint64]*3;fun.restype=C.c_uint32
  self.before=set(os.listdir('/proc/self/fd'));self.b=Bound(owner)
  bound=self.b.call(0);assert bound['status']==0 and bound['pending']==0,bound
  self.v=Values(DeferredEngine(self.b));self.program=verify_program(small(7))
  self.bridge=(package/'build/bridge.bin').read_bytes()
  self.base=C.cast(self.lib.hia_clang_value_compile,C.c_void_p).value
  assert C.string_at(self.base,32)==self.bridge[:32]
  shoff=struct.unpack_from('<Q',raw,40)[0];shsize,shnum,shstr=struct.unpack_from('<3H',raw,58)
  assert shsize==64
  sections=[struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*64)for i in range(shnum)]
  names=raw[sections[shstr][4]:sections[shstr][4]+sections[shstr][5]]
  textrow=next(row for row in sections if names[row[0]:].split(b'\x00',1)[0]==b'.text')
  self.expected_text=raw[textrow[4]:textrow[4]+textrow[5]]
  assert C.string_at(self.base,len(self.expected_text))==self.expected_text
  self.symbols={}
  for line in subprocess.check_output(['/usr/bin/nm','-n',str(package/'build/bridge.o')],text=True).splitlines():
   fields=line.split()
   if len(fields)==3:self.symbols[fields[2]]=int(fields[0],16)
  self.origin_ip=self.base+self.bridge.rindex(b'\x0f\x05')+2
  assert self.origin_ip>self.base+self.symbols['.Av_origin_producer']
  metadata=json.loads((package/'build.json').read_text());self.offsets={};self.role_data={}
  at=len(self.bridge)
  for row in metadata['roles']:
   at=(at+15)&~15;name=row['role'];data=(package/'build'/(name+'.component')).read_bytes()
   assert pin(data)=={k:row[k]for k in('bytes','sha256')},name
   assert at+len(data)<=len(self.expected_text),name
   self.offsets[name]=at;self.role_data[name]=data;at+=len(data)
  assert at==len(self.expected_text)
  self.report=dict(passed=False,cases=[],product=pin(raw),owner=pin(owner.read_bytes()),
    sealed_memfd=True,host_binding_writes=False,whole_public_llvm_qualified=False,whole_public_runtime_qualified=False)
 def save(self):(self.out/'report.json').write_text(json.dumps(self.report,indent=2,sort_keys=True)+'\n')
 def passed(self,name,**details):
  self.report['cases'].append(dict(case=name,passed=True,**details));self.save();print('ACTUAL_LOG_PASS',name,flush=True)
 def session(self):
  w=mmap.mmap(-1,538968064);wp=C.addressof(C.c_char.from_buffer(w));fd=os.open(self.source,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try:
   request=C.create_string_buffer(b'HIACVOB2'+struct.pack('<3Q',fd,0,0))
   assert self.lib.hia_clang_value_bind_owner(request,32,wp,len(w),self.b.owner.context,2048)==0
   owned=u(w,104);assert u(w,112)==1 and owned!=fd and os.fstat(owned).st_ino==os.fstat(fd).st_ino
   assert fcntl.fcntl(owned,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
  finally:os.close(fd)
  return w,wp
 def frame(self,compiler,log,name,target=0,kind=0,layout=0):
  core=self.program.canonical_bytes;path=os.fsencode(self.out/(name+('.so'if kind==0 else'.o')))
  raw=bytearray(256);raw[:8]=b'HIACVPL1'
  for at,n in((16,target),(24,kind),(32,layout),(40,len(core)),(56,len(path))):struct.pack_into('<Q',raw,at,n)
  struct.pack_into('<3Q',raw,64,*compiler);struct.pack_into('<3Q',raw,96,*log)
  return bytes(raw)+core+path
 def invoke(self,w,wp,data):
  request=C.create_string_buffer(data);out=C.create_string_buffer(1049088 if len(data)>256 else 512)
  rc=self.lib.hia_clang_value_compile(request,len(data),out,len(out),wp,len(w))
  assert request.raw==data+b'\0'
  return rc,bytes(out)
 def take(self,w,wp):
  request=C.create_string_buffer(b'HIAMVCE1'+bytes(120));out=C.create_string_buffer(128)
  assert self.lib.hia_clang_value_exception(request,128,out,128,wp,len(w))==0
  assert (u(out.raw,16),u(out.raw,88),u(out.raw,96))==(2,1,1),('actual exception',out.raw[:128].hex(),u(w,256))
  return self.v.keep(out.raw)
 def ended(self,w,wp):
  rc,out=self.invoke(w,wp,b'HIAMVBC1'+struct.pack('<31Q',1,*([0]*30)))
  assert rc==0 and struct.unpack_from('<3Q',out,344)==(1,1,0),('retire',rc,out[:512].hex(),u(w,256))
  assert u(w,112)==0
  if u(w,LOG)!=0:
   assert u(w,LOG+104)==6 and u(w,LOG+96)==0
   assert all(u(w,LOG+512+i*32+24)==0 for i in range(5))
  w.close();sweep(self.v,self.b);assert set(os.listdir('/proc/self/fd'))==self.before
 def close(self):
  self.b.close();assert set(os.listdir('/proc/self/fd'))==self.before
  for name in('hia_clang_value_bind_owner','hia_clang_value_compile','hia_clang_value_exception'):delattr(self.lib,name)
  dlclose(self.lib._handle);del self.lib;os.close(self.fd)
  assert set(os.listdir('/proc/self/fd'))==self.before_all
 def notified(self,w,wp,data,point,numbers,action,label,filters=()):
  ready=queue.Queue();result=queue.Queue();notices=[]
  def worker():
   try:
    for ip,nr,err in filters:deny_native(ip,nr,err)
    ready.put(listener(point,numbers));result.put(self.invoke(w,wp,data))
   except BaseException as error:ready.put(error);result.put(error)
  thread=threading.Thread(target=worker);thread.start();fd=ready.get(timeout=30)
  if isinstance(fd,BaseException):raise fd
  try:
   until=time.monotonic()+120
   while thread.is_alive():
    assert time.monotonic()<until,'original 120 second native gate exceeded'
    if not select.select([fd],[],[],0.2)[0]:continue
    notice=Notification()
    if LIBC.ioctl(fd,0xc0502100,C.byref(notice))<0:
     if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
     raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
    assert notice.data.ip==point and notice.data.nr in numbers
    phase=u(w,INNER);error=action(notice,phase)
    notices.append(dict(nr=notice.data.nr,phase=phase,error=error))
    response=Response(notice.id,0,-error if error else 0,0 if error else 1)
    assert LIBC.ioctl(fd,0xc0182101,C.byref(response))==0,C.get_errno()
   thread.join(1)
  finally:os.close(fd);thread.join(10)
  assert not thread.is_alive();pair=result.get_nowait()
  if isinstance(pair,BaseException):raise pair
  (self.out/(label+'.notices.json')).write_text(json.dumps(notices,indent=2)+'\n')
  return pair,notices
 def items(self,container):
  n=u(self.v.raw(7,a=container),48);result=[]
  for i in range(n):
   index=self.v.scalar(i);result.append(self.v.keep(self.v.raw(12,a=container,b=index)));self.v.drop(index)
  return result
 def capture(self,w,index):
  at=INNER+2300000+index*256
  assert bytes(w[at:at+8])==b'HIACAR01'and u(w,at+24)==1
  read=lambda p,n:C.string_at(p,n)if n else b''
  rawout=read(u(w,at+72),u(w,at+80));rawerr=read(u(w,at+88),u(w,at+96))
  stdout=read(u(w,at+104),u(w,at+112)).decode('utf-8');stderr=read(u(w,at+120),u(w,at+128)).decode('utf-8')
  return CaptureResult(struct.unpack_from('<q',w,at+32)[0],stdout,stderr,rawout,rawerr)
 def capture_request(self,w):
  pointer=u(w,INNER+600);n=u(w,INNER+2752);raw=C.string_at(pointer,n)
  assert raw[:8]==b'HIACAP01'
  count=u(raw,16);at=128;argv=[]
  for i in range(count):
   size=u(raw,at);at+=8;argv.append(os.fsdecode(raw[at:at+size]));assert raw[at+size]==0;at+=size+1
  assert at==len(raw)
  return argv,dict(timeout=u(raw,40)//1000000000,stdout_limit=u(raw,48),stderr_limit=u(raw,56),stdin_limit=u(raw,64))
 def oracle(self,argv,kwargs,result=None,error=None):
  sink=[];attempt=[];old=original.run_bounded
  def actual_replay(*args,**kw):
   assert list(args[0])==argv and kw==kwargs
   attempt.append(copy.deepcopy(sink[0]))
   if error is not None:raise error
   return result
  original.run_bounded=actual_replay
  try:
   try:original._run_logged(argv,command_log=sink,**kwargs)
   except BaseException as caught:assert caught is error
   else:assert error is None
  finally:original.run_bounded=old
  return attempt[0],sink[0]
 def exception_fields(self,cap):
  ns,arguments,name=self.v.parts(cap)
  return ns,self.v.python_value(arguments),self.v.python(name)

def run(package,owner,owner_sha,library_sha,out):
 f=Fixture(package,owner,owner_sha,library_sha,out);v=f.v
 try:
  cap=v.scalar('clang');log=v.lst([]);w,wp=f.session();seen={};saved={}
  def observe(notice,phase):
   if phase!=2531:return 0
   mode=u(w,INNER+2560);index=u(w,INNER+840)
   if mode not in(0,1)or(mode,index)in seen:return 0
   assert u(w,120)==1
   row=f.items(log)[index];value=v.python_value(row)
   argv,kwargs=f.capture_request(w)
   expected_attempt,expected_final=f.oracle(argv,kwargs,f.capture(w,index)if mode==1 else CaptureResult(0,'','',b'',b''))
   expected=expected_attempt if mode==0 else expected_final
   assert value==expected and list(value)==list(expected),(mode,index,value,expected)
   if mode==0:saved[index]=row
   else:assert v.same(saved[index],row)
   seen[mode,index]=value
   return 0
  (rc,reply),notices=f.notified(w,wp,f.frame(cap,log,'normal'),f.origin_ip,[11],observe,'normal')
  assert rc==0 and u(reply,8)==0,(rc,reply[:512].hex(),u(w,256),u(w,INNER))
  assert set(seen)=={(mode,index)for mode in(0,1)for index in range(3)},seen
  assert [r['status']for r in v.python_value(log)]==['completed']*3
  assert (out/'normal.so').read_bytes().startswith(b'\x7fELF')
  f.ended(w,wp);f.passed('native-initializer-and-real-three-capture-row-timing',kernel_notices=len(notices),exact_original_oracle=True,same_row_identity=True)

  for name,value in [('none',None),('integer',7),('dictionary',{})]:
   cap=v.scalar('clang');bad=v.keep(v.raw(4))if isinstance(value,dict)else v.scalar(value)
   w,wp=f.session();rc,reply=f.invoke(w,wp,f.frame(cap,bad,'invalid-'+name))
   assert rc==0 and u(reply,8)!=0 and u(w,544)==0,(name,rc,reply[:512].hex())
   error=f.take(w,wp);ns,args,cls=f.exception_fields(error)
   assert cls=='HIAProgramLLVMRejected'and args==('E_HIA_COMMAND_LOG: command log must be a plain list',),(name,cls,args)
   f.ended(w,wp)
  f.passed('invalid-log-type-real-canonical-rejection-before-any-native-capture',cases=3)

  cap=v.scalar('clang');log=v.lst([]);w,wp=f.session();removed=[];done=set()
  def detach(notice,phase):
   if phase==2531 and u(w,INNER+2560)==0 and u(w,INNER+840)==0 and not removed:
    row=f.items(log)[0];removed.append(row)
    v.raw(15,a=log,b=v.scalar(0))
    assert v.python_value(log)==[]
   if phase==2531 and u(w,INNER+2560)==1:
    index=u(w,INNER+840)
    if index not in done:
     if index==0:
      argv,kwargs=f.capture_request(w);_,expected=f.oracle(argv,kwargs,f.capture(w,index))
      assert v.python_value(removed[0])==expected
     done.add(index)
   return 0
  (rc,reply),notices=f.notified(w,wp,f.frame(cap,log,'detached-row'),f.origin_ip,[11],detach,'detached-row')
  assert rc==0 and u(reply,8)==0 and len(removed)==1 and done=={0,1,2}
  assert len(v.python_value(log))==2 and all(row['status']=='completed'for row in v.python_value(log))
  f.ended(w,wp);f.passed('same-row-native-strong-custody-after-caller-removes-row',kernel_notices=len(notices))

  cap=v.scalar('clang');log=v.lst([]);w,wp=f.session();dropped=[];complete=set()
  def drop_originals(notice,phase):
   if phase!=2531:return 0
   mode=u(w,INNER+2560);index=u(w,INNER+840)
   if mode==0 and index==0 and not dropped:
    assert u(w,LOG+536)==1 and u(w,1024+24)==1
    v.drop(log);v.drop(cap);dropped.append(True)
   if mode==1:
    borrowed=struct.unpack_from('<3Q',w,LOG+512)
    assert all(borrowed)
    assert v.python_value(borrowed)[index]['status']=='completed'
    complete.add(index)
   return 0
  (rc,reply),notices=f.notified(w,wp,f.frame(cap,log,'caller-cap-drop'),f.origin_ip,[11],drop_originals,'caller-cap-drop')
  assert rc==0 and u(reply,8)==0 and dropped==[True]and complete=={0,1,2},(rc,reply[:512].hex(),complete)
  f.ended(w,wp);f.passed('actual-caller-log-and-compiler-cap-drop-while-private-native-pins-live',kernel_notices=len(notices))

  # Fault the actual hook's mapping retirement and preserve its ledger.
  cap=v.scalar('clang');log=v.lst([]);w,wp=f.session();failed=[]
  def fail_unmap(notice,phase):
   if phase==2531 and u(w,INNER+2560)==0 and not failed:
    failed.append((notice.data.args[0],notice.data.args[1]));return 5
   return 0
  (rc,reply),notices=f.notified(w,wp,f.frame(cap,log,'unmap-pending'),f.origin_ip,[11],fail_unmap,'unmap-pending')
  assert rc==0 and u(reply,8)!=0 and failed and u(w,INNER+2880)!=0,(rc,reply[:512].hex(),failed)
  assert u(w,INNER+2880)==failed[0][0]and v.python_value(log)[0]['status']=='attempted'
  f.ended(w,wp);f.passed('real-log-buffer-munmap-EIO-preserved-until-native-retirement-retry',mapping=list(failed[0]),kernel_notices=len(notices))

  initial=os.getcwd()
  for name,component in [('surrogate-cwd',os.fsdecode(b'cwd-\xff')),('long-cwd','a'*230)]:
   cap=v.scalar('clang');log=v.lst([]);w,wp=f.session();base=out/name;base.mkdir()
   fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
   try:
    for i in range(20 if name=='long-cwd'else 1):
     part=component+str(i);os.mkdir(part,dir_fd=fd)
     newer=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=newer
    os.fchdir(fd)
   finally:os.close(fd)
   try:
    actual=os.getcwd();rc,reply=f.invoke(w,wp,f.frame(cap,log,name))
    assert rc==0 and u(reply,8)==0,(name,rc,reply[:512].hex())
    rows=v.python_value(log);assert len(rows)==3 and all(row['cwd']==actual for row in rows)
    if name=='long-cwd':assert len(os.fsencode(actual))>4096
   finally:os.chdir(initial)
   f.ended(w,wp);f.passed(name,actual_filesystem_path=True,bytes=len(os.fsencode(actual)))

  f.close();f.report.update(passed=True,groups=len(f.report['cases']),actual_clang_and_filesystem=True,
    production_log_initializer_qualified=True,command_log_ordering_component_qualified=True)
  print('ACTUAL_LOG_ALL_PASS',len(f.report['cases']),flush=True)
 except BaseException as error:
  f.report.update(failure=repr(error),traceback=traceback.format_exc());raise
 finally:f.save()
 return f.report

def run_failures(package,owner,owner_sha,library_sha,out):
 f=Fixture(package,owner,owner_sha,library_sha,out);v=f.v
 try:
  from tools import generate_hia_clang_capture_packer as caps
  capture_ip=f.base+f.offsets['error_capture']+64+caps.BRIDGE.rindex(b'\x0f\x05')+2
  signature=b'\x49\x8b\x06\x0f\x05'
  component=f.role_data['log_owner'];assert component[:1893].count(signature)==1
  log_ip=f.base+f.offsets['log_owner']+component.index(signature)+len(signature)
  def captured_error(w,kind):
   if kind=='waitid':
    return CaptureRejected('E_CAPTURE_OWNERSHIP','Non-reaping child observation unavailable')
   if kind=='os':return OSError(1,os.strerror(1))
   assert kind=='encoding'
   index=u(w,INNER+840);at=INNER+2300000+index*256
   argv,kwargs=f.capture_request(w)
   error=CaptureRejected('E_CAPTURE_ENCODING','Compiler stderr was not UTF-8')
   error.capture=CaptureFailure(tuple(argv),
    struct.unpack_from('<q',w,at+32)[0]if u(w,at+24)else None,
    C.string_at(u(w,at+72),u(w,at+80)),C.string_at(u(w,at+88),u(w,at+96)),
    u(w,at+56),u(w,at+64))
   assert b'\xff'in error.capture.stderr
   return error
  def compare_exception(cap,expected):
   ns,args,typ=f.exception_fields(cap)
   assert typ==type(expected).__name__ and args==expected.args,(typ,args,type(expected).__name__,expected.args)
   if isinstance(expected,OSError):
    for i,key in enumerate(('errno','strerror','filename','filename2')):
     child=v.keep(v.raw(105,a=cap,arg0=i));assert v.python_value(child)==getattr(expected,key)
   else:
    assert isinstance(expected,CaptureRejected)
    for key,want in [('code',expected.code),('capture_error',expected.capture_error)]:
     k=v.scalar(key);child=v.keep(v.raw(9,a=ns,b=k));assert v.python_value(child)==want;(v.drop(k),v.drop(child))
    k=v.scalar('capture');record=v.keep(v.raw(9,a=ns,b=k));v.drop(k)
    if expected.capture is None:assert v.python_value(record)is None
    else:
     expected_fields=(expected.capture.command,expected.capture.returncode,expected.capture.stdout,
      expected.capture.stderr,expected.capture.stdout_total_bytes,expected.capture.stderr_total_bytes)
     for i,want in enumerate(expected_fields):
      child=v.field(record,i);assert v.python_value(child)==want,(i,v.python_value(child),want)
  for kind,filters in [('waitid',[(capture_ip,247,5)]),('os',[(capture_ip,13,1)]),('encoding',[])]:
   compiler=v.scalar('clang');log=v.lst([]);w,wp=f.session();seen={};same=[];expected_box=[]
   prior=os.environb.get(b'CCC_OVERRIDE_OPTIONS')
   try:
    if kind=='encoding':os.environb[b'CCC_OVERRIDE_OPTIONS']=b'X\xff'
    def observe(notice,phase):
     if phase!=2531:return 0
     mode=u(w,INNER+2560);index=u(w,INNER+840)
     if index!=0 or mode not in(0,2)or mode in seen:return 0
     assert u(w,120)==1
     row=f.items(log)[0];value=v.python_value(row);argv,kwargs=f.capture_request(w)
     if mode==0:
      expect,_=f.oracle(argv,kwargs,CaptureResult(0,'','',b'',b''));same.append(row)
     else:
      expected=captured_error(w,kind);expected_box.append(expected)
      _,expect=f.oracle(argv,kwargs,error=expected)
      assert v.same(same[0],row)
      cap=struct.unpack_from('<3Q',w,1024+15*32);assert all(cap)and u(w,1024+15*32+24)==1
      same.append(v.keep(v.raw(91,a=cap)));compare_exception(same[-1],expected)
     assert value==expect and list(value)==list(expect),(kind,mode,value,expect)
     seen[mode]=value
     return 0
    (rc,reply),notices=f.notified(w,wp,f.frame(compiler,log,'capture-'+kind),f.origin_ip,[11],observe,'capture-'+kind,filters)
    assert rc==0 and u(reply,8)!=0 and set(seen)=={0,2},(kind,rc,reply[:512].hex(),seen)
    delivered=f.take(w,wp);assert v.same(delivered,same[-1]);compare_exception(delivered,expected_box[0])
    assert v.python_value(log)==[seen[2]]
    f.ended(w,wp);f.passed('real-'+kind+'-failure-log-before-cleanup',kernel_notices=len(notices),actual_early_exception_identity=True,exact_original_row=True)
   finally:
    if prior is None:os.environb.pop(b'CCC_OVERRIDE_OPTIONS',None)
    else:os.environb[b'CCC_OVERRIDE_OPTIONS']=prior

  for label,mode,kind in [('attempt',0,None),('completed',1,None),('failure',2,'waitid'),('failure-capture-record',2,'encoding')]:
   compiler=v.scalar('clang');log=v.lst([]);w,wp=f.session();denied=[];primary=[]
   prior=os.environb.get(b'CCC_OVERRIDE_OPTIONS')
   filters=[(capture_ip,247,5)]if kind=='waitid'else []
   try:
    if kind=='encoding':os.environb[b'CCC_OVERRIDE_OPTIONS']=b'X\xff'
    def deny_log_mapping(notice,phase):
     if phase==2334 and u(w,INNER+2560)==mode and not denied:
      assert u(w,120)==1 and u(w,LOG+120)==1
      assert notice.data.nr==9
      if mode==2:
       borrowed=struct.unpack_from('<3Q',w,1024+15*32);assert u(w,1024+15*32+24)==1
       primary.append(v.keep(v.raw(91,a=borrowed)))
       compare_exception(primary[0],captured_error(w,kind))
       if kind=='encoding':assert u(w,1024+61*32+24)==1,'real CaptureFailure occupies former hardcoded helper slot'
      denied.append((notice.data.args[1],u(w,LOG+256)));return 12
     return 0
    (rc,reply),notices=f.notified(w,wp,f.frame(compiler,log,'log-memory-'+label),log_ip,[9],deny_log_mapping,'log-memory-'+label,filters)
    assert rc==0 and u(reply,8)!=0 and len(denied)==1,(label,rc,reply[:512].hex(),denied)
    actual=f.take(w,wp);ns,arguments,typ=f.exception_fields(actual)
    assert typ=='MemoryError'and arguments==(),(label,typ,arguments)
    cause=v.keep(v.raw(107,a=actual,arg0=0));context=v.keep(v.raw(107,a=actual,arg0=1));suppress=v.keep(v.raw(107,a=actual,arg0=2))
    assert v.python_value(cause)is None and v.python_value(suppress)is False
    if mode==2:assert v.same(context,primary[0]),(label,context,primary[0])
    else:assert v.python_value(context)is None
    rows=v.python_value(log)
    if mode==0:assert rows==[]
    else:assert len(rows)==1 and rows[0]['status']=='attempted'
    f.ended(w,wp);f.passed('actual-log-'+label+'-ENOMEM-replaces-main-exception',kernel_notices=len(notices),true_memory_error=True,
     actual_prior_exception_context=mode==2,retained_original_capture_record=kind=='encoding',native_mapping_attempt=list(denied[0]))
   finally:
    if prior is None:os.environb.pop(b'CCC_OVERRIDE_OPTIONS',None)
    else:os.environb[b'CCC_OVERRIDE_OPTIONS']=prior

  f.close();f.report.update(passed=True,groups=len(f.report['cases']),actual_clang_and_filesystem=True,
   production_log_failure_custody_qualified=True)
  print('ACTUAL_LOG_FAILURE_ALL_PASS',len(f.report['cases']),flush=True)
 except BaseException as error:
  f.report.update(failure=repr(error),traceback=traceback.format_exc());raise
 finally:f.save()
 return f.report

def main():
 p=argparse.ArgumentParser()
 for name in('package','owner','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in('owner-sha256','library-sha256'):p.add_argument('--'+name,required=True)
 p.add_argument('--suite',choices=('baseline','faults'),default='baseline')
 a=p.parse_args();fn=run if a.suite=='baseline'else run_failures
 fn(a.package,a.owner,a.owner_sha256,a.library_sha256,a.output)
if __name__=='__main__':main()
