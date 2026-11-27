"""Actual canonical heap-bound exception and an explicitly deferred private class query."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,traceback
from hepta.hia_heap_bound import HIAHeapBoundRejected
from tools.qualify_hia_result_value_subprocess import Values,Bound,Engine,sweep,word,ZERO
from tools.qualify_hia_result_value_platform import args_and_dict
from tools.qualify_hia_result_value_deferred_boundmethod import snapshot
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame
def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def request(private=True,**kw):
 raw=bytearray(frame(116,arg0=75,**kw))
 if private:raw[:8]=b'HIABVQ12'
 return bytes(raw)
def call(v,private=True,want=0,queue=0,known=1):
 rc,out=v.engine.call(request(private))
 assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==want,(rc,out[:192].hex())
 if private:snapshot(out,queue,known)
 if want==0:
  assert word(out,88)==1 and word(out,96)==1
  return v.keep(out),out
 assert out[24:48]==bytes(24)and word(out,96)==0,out[:192].hex()
 return ZERO,out
def setup(path):
 b=Bound(path);assert b.call(0)['status']==0
 return b,Values(Engine(b))
def clean(v,b):
 sweep(v,b);b.close()
def run(path,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 rows=[];fds=set(os.listdir('/proc/self/fd'))
 report=dict(schema='hia.native-heap-bound-error.component.v1',passed=False,product=pin(path.read_bytes()),
  original_115_domain_unchanged=True,whole_public_llvm_qualified=False,
  public_Q12_refusal_qualified=False,bounded_resource_analysis_qualified=False)
 try:
  b,v=setup(path);cls,reply=call(v,False);again,deferred=call(v)
  assert v.same(cls,again)
  # Each query publishes its own strong token; compare the real node identity and all non-token facts.
  fields=(8,16,48,56,64,72,80,88,96,104,112,120)
  assert tuple(word(reply,i)for i in fields)==tuple(word(deferred,i)for i in fields),(reply[:128].hex(),deferred[:128].hex())
  name=v.keep(v.raw(38,a=cls));assert v.python_value(name)=='HIAHeapBoundRejected'
  mro=v.keep(v.raw(38,a=cls,arg0=2))
  for index,expected in enumerate((75,24,22,21,1)):
   ix=v.scalar(index);actual=v.keep(v.raw(12,a=mro,b=ix))
   want=cls if expected==75 else v.builtin(expected)
   assert v.same(actual,want)
  static=v.builtin(47);assert not v.same(cls,static)
  fake=v.cls('HIAHeapBoundRejected',[v.builtin(24)]);assert not v.same(fake,cls)
  clean(v,b);rows.append(dict(case='actual-canonical-class-75-and-exact-MRO-with-existing-static-budget47-distinct'))
  print('HEAP_ERROR_PASS canonical',flush=True)

  b,v=setup(path);cls,_=call(v)
  for code,detail in [('E_HIA_BUDGET_UNBOUNDED','native allocation cycle'),('E_TEST',''),('E_TEST','\ud800 literal')]:
   oracle=HIAHeapBoundRejected(code,detail);text=v.scalar(str(oracle));args=v.tuple([text])
   namespace=v.dictionary([('code',oracle.code)])
   error=v.keep(v.raw(75,a=cls,b=args,c=namespace))
   ns,actualargs,name=args_and_dict(v,error)
   assert v.python_value(actualargs)==oracle.args
   assert v.python_value(ns)=={'code':oracle.code}
   assert v.python_value(name)==type(oracle).__name__
   assert v.isinst(error,cls)and v.isinst(error,v.builtin(24))
   v.drop(namespace);v.drop(args);v.drop(text)
   assert v.python_value(actualargs)==oracle.args
  clean(v,b);rows.append(dict(case='actual75-exception-args-code-and-strong-namespace-match-original-heap-error',cases=3))
  print('HEAP_ERROR_PASS exception',flush=True)

  b,v=setup(path);cls,_=call(v);pending_function(v,b)
  assert word(v.engine.context,176)==1
  retained,reply=call(v,queue=1)
  assert word(v.engine.context,176)==1 and word(v.engine.context,184)==0
  # Ordinary identity queries drain; inspect the retained class only after the explicit retry.
  rc,dropped=v.engine.call(frame(78,a=retained))
  assert rc==0 and word(dropped,88)==word(dropped,96)==1 and word(dropped,112)==1
  v.held.remove(retained);assert word(v.engine.context,176)==1
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  again,unused=call(v);assert v.same(cls,again)
  clean(v,b);rows.append(dict(case='real-code-munmap-EIO-pending-preserved-by-privateQ12-and-consumed-by-one-native-drain',receipt=reply[:192].hex()))
  print('HEAP_ERROR_PASS real-pending',flush=True)

  b,v=setup(path);cls,_=call(v);pending_function(v,b)
  def prelock():
   deny_native(ip_at(b.value,value_pack),39,errno.EIO)
   return v.engine.call(request())
  rc,failed=faults.thread_result(prelock)
  assert rc==0 and word(failed,8)==11 and failed[24:48]==bytes(24)and word(failed,96)==0
  snapshot(failed,known=0);assert word(v.engine.context,176)==1
  v.raw(56);clean(v,b);rows.append(dict(case='actual-getpid-EIO-preserves-unknown-pre-lock-custody-with-existing-queue',receipt=failed[:192].hex()))
  print('HEAP_ERROR_PASS prelock',flush=True)

  b,v=setup(path);cls,_=call(v)
  def random_failure():
   deny_native(ip_at(b.value,value_pack),318,errno.EIO)
   return v.engine.call(request())
  rc,failed=faults.thread_result(random_failure)
  assert rc==0 and word(failed,8)==11 and failed[24:48]==bytes(24)and word(failed,96)==0,failed[:192].hex()
  snapshot(failed);again,_=call(v);assert v.same(cls,again)
  clean(v,b);rows.append(dict(case='actual-token-getrandom-EIO-before-class-cap-delivery-and-retry',receipt=failed[:192].hex()))
  print('HEAP_ERROR_PASS native-allocation',flush=True)

  b,v=setup(path);controls=[];good=request()
  for magic in tuple(('HIABVQ%02d'%i).encode()for i in range(1,12)if i!=5):
   raw=bytearray(good);raw[:8]=magic;controls.append(bytes(raw))
  for op in tuple(range(116))+(117,255):
   raw=bytearray(good);struct.pack_into('<Q',raw,8,op);controls.append(bytes(raw))
  for at in(16,24,32,40,48,56,64,72,80,88,96,112,120):
   raw=bytearray(good);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
  for index in(0,47,71,72,73,74,76):
   raw=bytearray(good);struct.pack_into('<Q',raw,104,index);controls.append(bytes(raw))
  controls.extend([good[:-1],good+b'\0'])
  for op in(87,98,99,101,110,112,114):
   controls.append(frame(op,arg0=75))
  for raw in controls:
   state=bytes(v.engine.context);rc,reply=v.engine.call(raw)
   assert rc==0xfffffffd and bytes(v.engine.context)==state,(raw.hex(),rc,reply[:192].hex())
  for magic in(b'HIABVQ05',b'HIABVQ12'):
   body=policy('private_heap_catalog_refusal','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,128,128)
    put(o,0,NC_BODY_VALUE)
    put(o,8,128)
    put(o,128,MAGIC)
    put(o,136,116)
    put(o,232,75)
    return 1
'''.replace('MAGIC',str(int.from_bytes(magic,'little'))))
   f=v.function(body);reply=v.raw(70,a=f,b=v.tuple([]),want=11)
   assert word(reply,96)==0 and reply[24:48]==bytes(24)
  clean(v,b);rows.append(dict(case='all-prior-domain-boundaries-and-native-body-refusals',controls=len(controls),native_bodies=2))
  print('HEAP_ERROR_PASS exact-domain',flush=True)
  assert set(os.listdir('/proc/self/fd'))==fds
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),
   canonical_heap_exception_qualified=True,deferred_heap_catalog_qualified=True,native_body_refusal_qualified=True)
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
