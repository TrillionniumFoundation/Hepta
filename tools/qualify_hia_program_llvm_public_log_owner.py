"""Actual native command-log list/row custody, native binding and OS failures."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,traceback,queue,select,threading,time
from tools.qualify_hia_result_value_platform import Bound,Engine,Values,sweep,word
from tools.qualify_hia_program_llvm_public_log_codec import Codec,capture_frame,packet,result_packet,error_packet
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools.qualify_hia_native_callable_code_owner import listener
from tools.qualify_hia_result_value_cleanup import Notification,Response,LIBC
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from hepta.clang_capture import CaptureResult,CaptureFailure,CaptureRejected
BAD=0xfffffffd
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def wire(op,tail=b'',cap=(0,0,0)):
 raw=bytearray(128);raw[:8]=b'HIALLVQ1';struct.pack_into('<Q',raw,8,op);struct.pack_into('<3Q',raw,24,*cap);struct.pack_into('<Q',raw,96,len(tail))
 return bytes(raw)+tail
class Logger:
 def __init__(self,path,bound):
  self.lib=C.CDLL(str(path));self.bound=bound;self.context=C.create_string_buffer(bytes(65536)+b'\xa5'*64,65600)
  self.entry=self.lib.hia_program_llvm_public_log;self.bind_entry=self.lib.hia_program_llvm_public_log_bind_owner
  for fn in(self.entry,self.bind_entry):fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
  self.address=C.cast(self.entry,C.c_void_p).value;self.calls=0
 def bind(self,cap):
  raw=bytearray(64);raw[:8]=b'HIALLBO1';struct.pack_into('<3Q',raw,16,*cap);s=C.create_string_buffer(bytes(raw))
  rc=int(self.bind_entry(s,64,self.context,65536,self.bound.owner.context,2048))
  assert s.raw==bytes(raw)+b'\0'and self.context.raw[65536:]==b'\xa5'*64
  assert rc==0,(rc,self.context.raw[1024:1152].hex())
  result=self.parse(self.context.raw[1024:1152]);self.calls+=1;return result
 @staticmethod
 def parse(raw):
  assert raw[:8]==b'HIALLVR1',raw.hex()
  names=('status','detail','op','state','primary','log','row','temps','unknown','pending','known','retired','map_pending','queue_pending','deferred')
  return dict(zip(names,struct.unpack_from('<15Q',raw,8)))
 def raw(self,raw):
  s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa5'*192,192)
  rc=int(self.entry(s,len(raw),o,128,self.context,65536));self.calls+=1
  assert s.raw==raw+b'\0'and o.raw[128:]==b'\xa5'*64 and self.context.raw[65536:]==b'\xa5'*64
  return rc,o.raw[:128]
 def call(self,op,tail=b'',cap=(0,0,0)):
  rc,raw=self.raw(wire(op,tail,cap));assert rc==0,(op,rc,raw.hex())
  return self.parse(raw)
 def close(self):
  r=self.call(3);assert r['status']==0 and r['known']==r['retired']==1 and r['map_pending']==0 and r['log']==r['row']==r['temps']==0,r
  return r
def notified_log(route,request,ip,target,handle):
 ready=queue.Queue();result=queue.Queue();notices=[]
 def execute():
  try:
   ready.put(listener(ip,[318]));result.put(route.call(request))
  except BaseException as error:ready.put(error);result.put(error)
 worker=threading.Thread(target=execute);worker.start();fd=ready.get(timeout=30)
 if isinstance(fd,BaseException):raise fd
 try:
  deadline=time.monotonic()+120
  while worker.is_alive():
   assert time.monotonic()<deadline,'native log binding notification timed out'
   if not select.select([fd],[],[],0.2)[0]:continue
   notice=Notification()
   if LIBC.ioctl(fd,0xc0502100,C.byref(notice))<0:
    if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
    raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
   assert notice.data.ip==ip and notice.data.nr==318
   error=handle(notice,len(notices));notices.append(dict(number=notice.data.nr,ip=notice.data.ip,tid=notice.pid,args=list(notice.data.args),errno=error))
   target.write_text(json.dumps(notices,indent=2)+'\n')
   response=Response(notice.id,0,-error if error else 0,0 if error else 1)
   assert LIBC.ioctl(fd,0xc0182101,C.byref(response))==0,C.get_errno()
  worker.join(1)
 finally:os.close(fd);worker.join(10)
 assert not worker.is_alive()
 pair=result.get_nowait()
 if isinstance(pair,BaseException):raise pair
 rc,raw=pair;target.with_suffix('.reply.bin').write_bytes(raw)
 assert rc==0 and raw[:8]==b'HIALLVR1',(rc,raw.hex())
 return raw,notices

def getrow(v,log,index=0):
 i=v.scalar(index);row=v.keep(v.raw(12,a=log,b=i));v.drop(i);return row
def native_patch(v,items):
 p=v.keep(v.raw(4))
 for k,c in items:
  key=v.scalar(k);v.raw(10,a=p,b=key,c=c);v.drop(key)
 return p
def run(image,owner,codec_path,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 report=dict(passed=False,native_log_owner_qualified=False,actual_clang_hook_enclosing_qualified=False,
             whole_public_api_qualified=False,product=pin(image.read_bytes()),owner=pin(owner.read_bytes()),codec=pin(codec_path.read_bytes()))
 rows=[];before=set(os.listdir('/proc/self/fd'));codec=Codec(codec_path)
 try:
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b));sink=v.lst([]);logger=Logger(image,b)
  r=logger.bind(sink);assert r['status']==0 and r['state']==1 and r['primary']==1 and r['log']==1 and r['row']==0,r
  assert word(logger.context,40)==b.value and word(logger.context,48)==C.addressof(b.owner.context)+512
  assert word(logger.context,64)==word(b.owner.context,664)
  assert all(word(logger.context,i)for i in(72,80,88))and word(logger.context,96)==1
  raw=packet(0,frame=capture_frame(['/actual/clang','--version']),cwd=os.fsencode(os.getcwd()))
  attempted,attempt_json=codec.value(raw);r=logger.call(0,attempt_json)
  assert r['status']==0 and r['primary']==1 and r['row']==1 and r['pending']==0,r
  row=getrow(v,sink);assert v.python_value(row)==attempted
  patch,pdata=codec.value(result_packet(CaptureResult(0,'ignored','ignored',b'hello\r\n',b'\xff')))
  r=logger.call(1,pdata);assert r['status']==0 and r['primary']==1 and r['row']==0 and r['temps']==0,r
  again=getrow(v,sink);assert v.same(row,again)
  attempted.update(patch);assert v.python_value(row)==attempted and list(v.python_value(row))==list(attempted)
  for cap in(row,again):v.drop(cap)
  rows.append(dict(case='native-owner-captures-one-arena-and-updates-identical-log-row'))
  print('LLVM_LOG_OWNER_PASS actual-row',flush=True)
  r=logger.call(0,attempt_json);assert r['status']==0
  held=getrow(v,sink,1);index=v.scalar(1);v.raw(15,a=sink,b=index);v.drop(index)
  error=CaptureRejected('E_CAPTURE_NATIVE','actual failure');error.capture=CaptureFailure(('clang',),None,b'x',b'y',30,40);error.capture_error='independent evidence failure'
  patch,pdata=codec.value(error_packet(error));r=logger.call(1,pdata);assert r['status']==0 and r['primary']==1
  expected=json.loads(attempt_json);expected.update(patch)
  assert v.python_value(held)==expected
  v.drop(held);rows.append(dict(case='native-strong-row-survives-caller-list-removal-and-failure-update'))
  print('LLVM_LOG_OWNER_PASS removed-row',flush=True)
  assert logger.call(0,attempt_json)['status']==0
  code=v.lst([]);namespace=native_patch(v,[('code',code)]);r=logger.call(2,cap=namespace);assert r['status']==0
  actual=getrow(v,sink,1);key=v.scalar('code');alias=v.keep(v.raw(9,a=actual,b=key));assert v.same(alias,code)
  number=v.scalar(71);v.raw(16,a=code,b=number);assert v.python_value(alias)==[71]
  for cap in(namespace,actual,key,alias,code,number):v.drop(cap)
  rows.append(dict(case='arbitrary-error-code-is-real-strong-Value-alias-without-text-coercion'))
  logger.close();v.drop(sink);sweep(v,b);b.close()
  assert logger.call(3)['retired']==1
  assert set(os.listdir('/proc/self/fd'))==before
  print('LLVM_LOG_OWNER_PASS alias-retired',flush=True)
  for name,nr,error_code,stage in [('native-map',9,errno.ENOMEM,'append'),('native-unmap',11,errno.EIO,'append'),('actual-value-token',318,errno.EIO,'bind')]:
   b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b));sink=v.lst([]);logger=Logger(image,b)
   if stage!='bind':assert logger.bind(sink)['status']==0
   start=b.value if stage=='bind' else logger.address
   extent=(owner.parent/'hia-generation-lease-values.core.bin').stat().st_size if stage=='bind' else 1166
   def denied():
    faults.deny_fixed_syscall(start,start+extent,nr,error_code)
    return logger.bind(sink)if stage=='bind'else logger.call(0,attempt_json)
   failed=faults.thread_result(denied);assert failed['status']!=0 and failed['unknown']==0,failed
   if name=='native-unmap':
    assert failed['primary']==1 and failed['row']==1 and failed['map_pending']==1 and failed['retired']==0,failed
    row=getrow(v,sink);assert v.python_value(row)==json.loads(attempt_json);v.drop(row)
   else:assert failed['primary']==0 and failed['row']==0,failed
   final=logger.close();assert final['map_pending']==final['pending']==0,final
   v.drop(sink);sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
   rows.append(dict(case=name,actual_syscall=nr,errno=error_code,failure=failed,retry=final))
   print('LLVM_LOG_OWNER_PASS',name,flush=True)
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b));sink=v.lst([]);logger=Logger(image,b)
  assert logger.bind(sink)['status']==0
  huge=json.dumps({'payload':['x'*200 for _ in range(40000)]},separators=(',',':')).encode()
  def no_growth():
   faults.deny_fixed_syscall(b.value,b.value+(owner.parent/'hia-generation-lease-values.core.bin').stat().st_size,25,errno.ENOMEM)
   return logger.call(0,huge)
  failed=faults.thread_result(no_growth);assert failed['status']!=0 and failed['primary']==0 and failed['row']==0 and failed['map_pending']==0,failed
  assert v.python_value(sink)==[]
  final=logger.close();v.drop(sink);sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
  rows.append(dict(case='actual-Value-arena-mremap-ENOMEM-no-partial-row',failure=failed,retry=final))
  print('LLVM_LOG_OWNER_PASS arena-growth',flush=True)
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b));sink=v.lst([]);logger=Logger(image,b)
  pending_function(v,b);assert word(v.engine.context,176)==1
  bound=logger.bind(sink);assert bound['status']==0 and bound['queue_pending']==1 and word(v.engine.context,176)==1,bound
  append=logger.call(0,attempt_json);assert append['status']==0 and append['primary']==1 and append['queue_pending']==1 and word(v.engine.context,176)==1,append
  closed=logger.close();assert closed['queue_pending']==1 and word(v.engine.context,176)==1,closed
  v.raw(47);assert word(v.engine.context,176)==0
  v.drop(sink);sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
  rows.append(dict(case='native-code-munmap-pending-is-never-drained-under-log-entry',bound=bound,append=append,closed=closed))
  print('LLVM_LOG_OWNER_PASS no-finalizer-under-entry',flush=True)
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b))
  for obj in (v.scalar(None),v.scalar('[]'),v.keep(v.raw(4))):
   logger=Logger(image,b);r=logger.bind(obj);assert r['status']==2 and r['retired']==1 and r['log']==0,r
   logger.close();v.drop(obj)
  sink=v.lst([]);logger=Logger(image,b);logger.bind(sink)
  for raw in [b'',bytes(127),wire(4),wire(1,b'{}'),wire(0),wire(3,b'x')]:
   rc,outbytes=logger.raw(raw);assert rc==BAD and outbytes==b'\xa5'*128,(rc,outbytes.hex())
  logger.close();v.drop(sink);sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
  rows.append(dict(case='plain-list-type-and-malformed-state-requests-refused',wire_cases=6))
  # No sidecar is present here: the logger takes its own actual arena token.
  b=Bound(owner);v=Values(Engine(b));sink=v.lst([]);logger=Logger(image,b)
  request=bytearray(64);request[:8]=b'HIALLBO1';struct.pack_into('<3Q',request,16,*sink)
  class BindRoute:
   def call(self,request):
    source=C.create_string_buffer(request)
    rc=int(logger.bind_entry(source,len(request),logger.context,65536,b.owner.context,2048))
    assert source.raw==request+b'\0'
    return rc,logger.context.raw[1024:1152]
  checks=[]
  def at_binding(notice,index):
   assert word(b.owner.context,64)==1
   denied=b.owner.call(3)
   assert denied['status']==2 and word(b.owner.context,80)==1,denied
   checks.append(dict(outer_mutex=word(b.owner.context,64),destroy_status=denied['status']))
   return 0
  raw,notices=notified_log(BindRoute(),bytes(request),ip_at(b.value,value_pack),out/'bind-native-mutex.json',at_binding)
  assert Logger.parse(raw)['status']==0 and checks
  assert word(b.owner.context,72)==0 and word(b.owner.context,64)==0 and word(logger.context,96)==1
  v.drop(sink)
  blocked=b.owner.call(3);assert blocked['status']==2 and blocked['state']==1,blocked
  logger.close();assert word(v.raw(47),48)==0
  done=b.owner.call(3);assert done['status']==0 and done['state']==3,done
  rows.append(dict(case='actual-sole-owner-mutex-spans-native-token-binding-and-destroy-refusal',notifications=len(notices),checks=checks,after_close=done['status']))
  assert set(os.listdir('/proc/self/fd'))==before
  print('LLVM_LOG_OWNER_PASS bind-destroy-lock',flush=True)
  report.update(passed=True,native_log_owner_qualified=True,groups=rows,source=pin(Path(__file__).read_bytes()))
  print('LLVM_LOG_OWNER_ALL_PASS',len(rows),flush=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('image','owner','codec','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.image,a.owner,a.codec,a.output)
if __name__=='__main__':main()
