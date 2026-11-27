"""Actual immutable VFY error payload to native HIAProgramRejected."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,queue,struct,threading,traceback
from tools.qualify_hia_native_callable_code_owner import deny_native
from tools.generate_hia_generation_runtime_verify_exception_packer import BRIDGE
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_runtime_global import Global,sidecar
from tools.qualify_hia_native_runtime_resources import ready,retired
from tools.qualify_hia_result_value_exceptions import Values,frame,ZERO
from tools.qualify_hia_publication_cancellation import Image
from tools.qualify_hia_clang_compile import small
from hepta.hia_program import verify_program,VerifiedProgram,HIAProgramRejected

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--frontend',type=Path,required=True);ap.add_argument('--exception',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 B=a.frontend.resolve();O=a.output.resolve();O.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(O.with_suffix('.claim'),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd);O.mkdir()
 pin=lambda data:dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
 path=B/'install/hia-generation-component-root.so';build=json.loads((B/'build.json').read_bytes());assert pin(path.read_bytes())==build['products']['hia-generation-component-root.so']
 report=dict(passed=False,frontend=pin(path.read_bytes()),exception=pin(a.exception.read_bytes()),stages=[],calls=[],causal_data_qualified=False,public_constructor_qualified=False,whole_public_runtime_qualified=False)
 def save():(O/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 def stage(name,**details):
  report['stages'].append(dict(name=name,passed=True,**details));save();print('VERIFY_EXCEPTION_PASS',name,flush=True)
 def wire(magic,op=0,cap=ZERO,format=0):
  b=bytearray(128);b[:8]=magic;struct.pack_into('<2Q',b,8,op,format);struct.pack_into('<3Q',b,24,*cap);return bytes(b)
 def call(f,raw,out,ctx,wn):
  s=C.create_string_buffer(raw);rc=int(f(s,len(raw),out,len(out),ctx,wn));assert s.raw==raw+b'\0';return rc
 owner=q.Owner(path);owner.initialize();g=Global(owner);initial_fds=set(os.listdir('/proc/self/fd'));ready(g.call(0));assert sidecar(owner,0)['status']==0
 v=Values(q.ValueTransport(owner));front=C.create_string_buffer(1<<20);yc=(C.c_char*8192).from_buffer(front,16384)
 yo=C.create_string_buffer(524288);xo=C.create_string_buffer(65536);image=None
 def entry(name):
  f=getattr(owner.lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;return f
 bind=entry('hia_generation_runtime_frontend_bind');verify=entry('hia_generation_runtime_verify')
 if a.exception.read_bytes()[:4]==b'\x7fELF':
  from tools import generate_hia_generation_runtime_verified_frontend_capsule_packer as typed
  assert a.exception.resolve()==path.resolve(),'whole product must be the same actual root'
  image=type('NativeFixedEntry',(),{})();image.entry=verify
  image.syscall_base=C.cast(verify,C.c_void_p).value+typed.ERROR_AT-typed.VERIFY_AT
  actual=bytearray(C.string_at(image.syscall_base,len(BRIDGE)));actual[207:211]=bytes(4)
  assert bytes(actual)==BRIDGE,'actual fixed typed exception bridge differs'
 else:
  image=Image(a.exception.read_bytes());image.syscall_base=q.address(image.mapping)
 def bindcall(op):
  rc=call(bind,wire(b'HIARTBQ1',op),front,owner.context,2048)
  row={k:q.get(front,1024+at)for k,at in dict(status=8,state=16,pending=80,known=88,consumed=96,retired=104,detail=112).items()}
  assert rc==0 and front.raw[1024:1032]==b'HIARTBR1',(rc,row);return row
 def verifycall(cap):
  rc=call(verify,wire(b'HIARTVQ1',cap=cap),yo,yc,8192);raw=yo.raw
  row={k:q.get(raw,at)for k,at in dict(status=8,format=16,size=48,profile=56,core_n=64,input_n=72,quarantine=80,known=88,pending=96,detail=120).items()}
  row['cap']=struct.unpack_from('<3Q',raw,24)
  report['calls'].append(dict(operation='fresh-verify',rc=rc,**row));save()
  assert rc==0 and raw[:8]==b'HIARTVR1',(rc,raw[:128].hex());return row
 def convert(row,op=0):
  raw=wire(b'HIARTXQ1',op,cap=row['cap']if op==0 else ZERO,format=row['format']if op==0 else 0)
  rc=call(image.entry,raw,xo,yc,8192);data=xo.raw
  r={k:q.get(data,at)for k,at in dict(status=8,disposition=16,pending=80,known=88,delivered=96,quarantine=104,detail=112).items()}
  r['cap']=struct.unpack_from('<3Q',data,24)
  report['calls'].append(dict(operation='actual-exception',op=op,rc=rc,**r,child=data[8192:8320].hex(),phase=q.get(xo,128)));save()
  assert rc==0 and data[:8]==b'HIARTXR1',(rc,data[:128].hex(),r)
  return r,data
 def payload_call(op,cap):
  s=wire(b'HIABPY01',op,cap);out=C.create_string_buffer(512)
  rc=call(payload,s,out,C.c_void_p(q.get(yc,48)),256);raw=out.raw
  assert rc==0 and raw[:8]==b'HIABPYR1'and q.get(raw,8)==0,(rc,raw[:128].hex())
  return raw
 def exception_data(cap):
  parts=v.parts(cap);namespace,args,name=parts;cls=v.keep(v.raw(36,a=cap));canonical=v.builtin(42)
  assert v.same(cls,canonical),'actual class identity differs from HIAProgramRejected'
  data=dict(classname=v.python(name),args=v.python_value(args),namespace=v.python_value(namespace))
  for c in [*parts,cls,canonical]:v.drop(c)
  return data
 def expected_error(value):
  try:verify_program(value)
  except HIAProgramRejected as exc:return dict(classname=type(exc).__name__,args=exc.args,namespace={'code':exc.code})
  raise AssertionError('original verification accepted rejected fixture')
 try:
  before=q.get(owner.context,72);assert bindcall(0)['status']==0;assert q.get(owner.context,72)==before+1
  Payload=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64);payload=Payload(q.get(yc,40))
  stage('actual-parent-binding-sole-value-and-immutable-payload-context')
  valid=verify_program(small(7));rawcases=[('missing-schema',b'{}'),('malformed-json',b'not a HIA program'),('invalid-utf8',b'\xff'),('missing-schema-text','{}')]
  for name,value in rawcases:
   cap=v.scalar(value);row=verifycall(cap);assert row['status']!=0 and row['format']in(1,2)and all(row['cap']),row
   retained=payload_call(6,row['cap']);payload_raw=C.string_at(q.get(retained,64),q.get(retained,40))
   (O/(name+'.json')).write_bytes(payload_raw)
   result,data=convert(row)
   assert result['status']==0 and result['known']==result['delivered']==1 and result['disposition']==2 and result['quarantine']==0,(name,result)
   actual=v.keep(data);got=exception_data(actual);expected=expected_error(value)
   report['calls'].append(dict(case=name,got=got,expected=expected));save()
   assert got==expected,(name,got,expected)
   assert payload_call(6,row['cap'])[16:40]==retained[16:40]
   payload_call(3,row['cap']);v.drop(actual);v.drop(cap)
   stage(name,format=row['format'],code=got['namespace']['code'])
  baseline=v.scalar(valid.canonical_bytes);wrong=v.scalar(b'not a HIA program');vp=v.keep(v.raw(67,a=baseline,b=wrong))
  row=verifycall(vp);result,data=convert(row);assert result['status']==0 and result['known']==result['delivered']==1,result
  actual=v.keep(data);got=exception_data(actual);expected=expected_error(VerifiedProgram(valid.canonical_bytes,b'not a HIA program'));assert got==expected,(got,expected)
  payload_call(3,row['cap']);v.drop(actual);stage('verified-program-structured-field-real-error')
  def mapped(address):
   return any(int(line.split('-')[0],16)<=address<int(line.split('-')[1].split()[0],16)for line in Path('/proc/self/maps').read_text().splitlines())
  sites=[i+2 for i in range(len(BRIDGE)-1)if BRIDGE[i:i+2]==b'\x0f\x05'];assert len(sites)==1,sites
  syscall_ip=image.syscall_base+sites[0]
  def fault_convert(row,number,error):
   results=queue.Queue()
   def run():
    try:
     deny_native(syscall_ip,number,error);results.put(convert(row))
    except BaseException as exc:results.put(exc)
   thread=threading.Thread(target=run);thread.start();thread.join(60);assert not thread.is_alive(),'native exception conversion remained blocked'
   result=results.get_nowait()
   if isinstance(result,BaseException):raise result
   return result
  raw=v.scalar(b'{}');row=verifycall(raw);count=q.get(v.raw(47),48)
  result,data=fault_convert(row,9,12)
  assert result['status']==5 and result['known']==1 and result['delivered']==0 and result['quarantine']==0,result
  assert q.get(yc,152)==0 and q.get(v.raw(47),48)==count
  assert payload_call(6,row['cap'])[:8]==b'HIABPYR1'
  payload_call(3,row['cap']);v.drop(raw)
  stage('actual-mmap-enomem-before-publication-keeps-caller-payload-and-no-value-leak')
  raw=v.scalar(b'{}');row=verifycall(raw);result,data=fault_convert(row,11,5)
  assert result['status']==9 and result['known']==result['delivered']==result['pending']==1 and result['disposition']==2 and result['quarantine']==1,result
  actual=v.keep(data);got=exception_data(actual);assert got==expected_error(b'{}'),got
  retained_frame=q.get(yc,328);assert retained_frame and mapped(retained_frame)
  assert q.get(yc,152)==1 and yc.raw[184:192]==b'HIARTXC1'
  saved=yc.raw;wrong=call(verify,wire(b'HIARTVQ1',op=1),yo,yc,8192);assert wrong==0xfffffffd and yc.raw==saved
  blocked=bindcall(1);assert blocked['retired']==0 and blocked['status']==6 and q.get(owner.context,72)==before+1,blocked
  result,retry=convert(row,op=1)
  assert result['status']==0 and result['known']==1 and result['delivered']==result['pending']==result['quarantine']==0,result
  assert not mapped(retained_frame) and q.get(yc,152)==0 and q.get(yc,184)==0
  assert exception_data(actual)==got
  payload_call(3,row['cap']);v.drop(actual);v.drop(raw)
  stage('published-real-exception-survives-actual-munmap-eio-and-native-retry-with-no-double-handoff')
  for cap in list(v.held):v.drop(cap)
  assert q.get(yc,152)==0 and q.get(yc,184)==0
  row=bindcall(1);assert row['retired']==1 and row['state']==3,row;assert q.get(owner.context,72)==before
  assert sidecar(owner,1)['retired']==1;retired(g.call(1));last=owner.call(3);assert last['status']==0 and last['state']==3,last
  assert set(os.listdir('/proc/self/fd'))==initial_fds
  stage('all-real-value-payload-fds-and-parent-custody-retired')
  report.update(passed=True,groups=len(report['stages']),actual_class_and_args=True,actual_payload_not_consumed=True)
 except BaseException as exc:
  report.update(error=repr(exc),traceback=traceback.format_exc());raise
 finally:save()
 print('VERIFY_EXCEPTION_ACTUAL_PASS',len(report['stages']),flush=True)

if __name__=='__main__':main()
