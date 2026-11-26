"""Actual resource subclasses retain native carrier custody and real class edges."""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,errno,hashlib,json,os,platform,queue,struct,traceback
from tools.qualify_hia_result_value_subprocess import Values as Previous,Bound,Engine,sweep,word,ZERO
from tools.qualify_hia_result_value_platform import objects,periodic_gc
from tools.qualify_hia_result_value_deferred_capture import pending_function,q
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def triple(b,at=24):return struct.unpack_from('<3Q',b,at)
class Values(Previous):
 def builtin(self,index):
  return self.keep(self.raw(114,arg0=index))if index==74 else super().builtin(index)
 def snapshot(self,reply,pending=0,known=1):
  assert reply[128:136]==b'HIABVD01'
  assert tuple(word(reply,i)for i in(136,144,152,160))==(known,0,pending,1),reply[:192].hex()
 def capture(self,kind,carrier,cls,env=ZERO,base=ZERO,want=0,pending=0):
  result=self.raw(113,a=env,b=base,c=cls,arg0=kind,tail=struct.pack('<3Q',*carrier),want=want)
  if pending is None:
   pending=word(result,80);assert pending in(0,1)
  assert tuple(word(result,i)for i in(80,88,96,104,112,120))==(pending,1,int(want==0),0,pending,1),result[:192].hex()
  self.snapshot(result,pending)
  if want:assert result[24:48]==bytes(24);return result
  return self.keep(result),result
 def deferred(self,op,**kw):
  packet=bytearray(frame(op,**kw));packet[:8]=b'HIABVQ06'
  rc,out=self.engine.call(bytes(packet));assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==0,(op,rc,out[:128].hex())
  return out
def cleanup(v,b,parent):
 for cap in list(v.held):v.drop(cap)
 sweep(v,b);b.close();assert not list(parent.iterdir()),list(parent.iterdir())
def run(path,custody,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 report=dict(schema='hia.native-resource-subclass.component.v1',passed=False,product=pin(path.read_bytes()),
  whole_public_runtime_qualified=False,public_subclass_constructor_qualified=False,
  nonempty_builtin_multiple_inheritance_layout_qualified=False,
  background_and_future_subclass_native_carrier_integration_qualified=False)
 rows=[];files=[];before=set(os.listdir('/proc/self/fd'))
 try:
  for name in('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
   raw=(custody/name).read_bytes();files.append((q.old.sealed(raw),raw))
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
  pending_function(v,b)
  got=v.raw(114,arg0=74);v.snapshot(got,1)
  assert tuple(word(got,i)for i in(80,88,96,104))==(1,1,1,0),got[:128].hex()
  cls=v.keep(got);assert word(v.engine.context,176)==1
  v.raw(56);assert word(v.engine.context,176)==0
  from hepta.hia_background_optimizer import _OptimizationFuture
  name=v.keep(v.raw(38,a=cls));assert v.python_value(name)==_OptimizationFuture.__name__
  mro=v.keep(v.raw(38,a=cls,arg0=2));expected=('_OptimizationFuture','Future','object');actual=[]
  for i in range(3):
   index=v.scalar(i);item=v.keep(v.raw(12,a=mro,b=index));label=v.keep(v.raw(38,a=item));actual.append(v.python_value(label))
   for cap in(index,item,label):v.drop(cap)
  assert tuple(actual)==expected and tuple(t.__name__ for t in _OptimizationFuture.__mro__)==expected
  again=v.builtin(74);assert v.same(cls,again)
  for op,index in((57,74),(101,74),(110,74),(112,74),(114,73),(114,75)):
   raw=bytearray(frame(op,arg0=index));raw[:8]=b'HIABVQ05'
   rc,reply=v.engine.call(bytes(raw));assert rc==0xfffffffd
  for cap in list(v.held):v.drop(cap)
  sweep(v,b);b.close();rows.append(dict(case='actual-optimization-future-canonical-MRO-and-deferred-first-catalog',mro=actual))
  print('RESOURCE_SUBCLASS_PASS catalog',flush=True)

  for runtime_first in(False,True):
   b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));carrier=q.Carrier(b.owner)
   parent=out/('runtime-first'if runtime_first else'lease-first');parent.mkdir()
   raw=q.old.create(carrier,files,parent);lease_raw=q.old.lease(carrier,raw)
   rtbase=v.builtin(20);ltbase=v.builtin(31)
   rtclass=v.cls('ActualNativeRuntimeChild',[rtbase]);ltclass=v.cls('ActualNativeLeaseChild',[ltbase])
   rtidentity=v.raw(7,a=rtclass)[104:120];ltidentity=v.raw(7,a=ltclass)[104:120]
   clang=v.lst([v.scalar('actual environment')])
   runtime,rreply=v.capture(1,raw,rtclass,env=clang)
   lease,lreply=v.capture(2,lease_raw,ltclass,env=runtime)
   assert word(rreply,16)==word(lreply,16)==8
   v.drop(rtclass);v.drop(ltclass);v.drop(clang)
   rt=v.keep(v.raw(36,a=runtime));lt=v.keep(v.raw(36,a=lease))
   assert v.raw(7,a=rt)[104:120]==rtidentity and v.raw(7,a=lt)[104:120]==ltidentity
   assert v.isinst(runtime,rtbase)and v.isinst(lease,ltbase)and not v.isinst(runtime,ltbase)
   descriptor=v.raw(26,a=runtime);parts=[v.keep(descriptor,at)for at in(8224,8248,8272)]
   assert v.python_value(parts[0])==['actual environment']
   for cap in parts+[rt,lt]:v.drop(cap)
   carrier.call(lease_raw,71)
   if runtime_first:
    v.drop(runtime);descriptor=v.raw(26,a=lease);parts=[v.keep(descriptor,at)for at in(8224,8248,8272)]
    assert v.isinst(parts[0],rtbase)
    for cap in parts:v.drop(cap)
    v.drop(lease)
   else:v.drop(lease);v.drop(runtime)
   cleanup(v,b,parent);rows.append(dict(case='true-subclass-and-class-environment-strong-edges',runtime_first=runtime_first))
   print('RESOURCE_SUBCLASS_PASS lifecycle',runtime_first,flush=True)

  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));carrier=q.Carrier(b.owner);parent=out/'refusals';parent.mkdir()
  raw=q.old.create(carrier,files,parent);rt=v.builtin(20);lt=v.builtin(31);it=v.builtin(3)
  fake=v.cls('ScalarMultiversionRuntime',[]);fake_instance=v.instance(fake)
  mixed=v.cls('ActualIntegerRuntime',[rt,it]);actual=v.cls('ActualRuntime',[rt]);bg=v.builtin(35)
  refusals=[]
  for cls,want in((fake,2),(fake_instance,2),(lt,2),(ZERO,2),((1,2,3),1),(mixed,18)):
   reply=v.capture(1,raw,cls,want=want);refusals.append(dict(status=want,known=word(reply,88),consumed=word(reply,96)))
  v.capture(6,raw,bg,want=6)
  snapshot=carrier.q(4,raw,q.old.public_request(10),child=0);q.old.release_detached(snapshot)
  runtime,reply=v.capture(1,raw,actual);v.drop(runtime)
  cleanup(v,b,parent);rows.append(dict(case='same-name-wrong-MRO-stale-class-and-nonempty-layout-refuse-before-transfer',refusals=refusals,unsupported_binding_mask_refused=True))
  print('RESOURCE_SUBCLASS_PASS refusals',flush=True)

  for fail in(False,True):
   b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));carrier=q.Carrier(b.owner);parent=out/('failed-capture'if fail else'deferred-capture');parent.mkdir()
   raw=q.old.create(carrier,files,parent);base=v.builtin(20);cls=v.cls('QueuedActualRuntime',[base])
   pending_function(v,b)
   if fail:
    def denied():
     deny_native(ip_at(b.value,value_pack),318,errno.EIO)
     return v.capture(1,raw,cls,want=11,pending=1)
    reply=faults.thread_result(denied)
    assert word(v.engine.context,176)==1
    carrier.q(3,raw)
   else:
    runtime,reply=v.capture(1,raw,cls,pending=1)
    assert word(v.engine.context,176)==1
    typ=v.keep(v.deferred(36,a=runtime));identity=v.deferred(8,a=typ,b=cls)
    assert word(identity,48)==1 and word(v.engine.context,176)==1
   v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
   cleanup(v,b,parent);rows.append(dict(case='actual-pending-and-failure-preserve-capture-disposition',failed_before_transfer=fail,reply=reply[:192].hex()))
   print('RESOURCE_SUBCLASS_PASS queued',fail,flush=True)

  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));carrier=q.Carrier(b.owner);parent=out/'class-cycle';parent.mkdir()
  raw=q.old.create(carrier,files,parent);base=v.builtin(20);probe=v.scalar(None);periodic_gc(v,probe);baseline=objects(v)
  namespace=v.keep(v.raw(4));key=v.scalar('retained_instance');cls=v.cls('ActualCyclicRuntime',[base],namespace=namespace)
  runtime,reply=v.capture(1,raw,cls);v.raw(10,a=namespace,b=key,c=runtime)
  for cap in(runtime,cls,namespace,key):v.drop(cap)
  periodic_gc(v,probe);assert not list(parent.iterdir())
  assert objects(v)==baseline,(objects(v),baseline)
  cleanup(v,b,parent);rows.append(dict(case='actual-class-namespace-runtime-cycle-finalizes-native-carrier-and-collects',object_baseline_restored=True))
  print('RESOURCE_SUBCLASS_PASS class-cycle',flush=True)

  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));carrier=q.Carrier(b.owner);parent=out/'concurrent';parent.mkdir()
  raw=q.old.create(carrier,files,parent);base=v.builtin(20);cls=v.cls('ConcurrentActualRuntime',[base])
  def worker(index):
   for _ in range(8):
    alias=carrier.q(2,raw)['cap'];value,receipt=v.capture(1,alias,cls,pending=None)
    assert word(receipt,96)==1
    rc,retired=v.engine.call(frame(78,a=value))
    assert rc==0 and retired[:8]==b'HIABVR02'and word(retired,8)==0
    assert tuple(word(retired,i)for i in(88,96,104,120))==(1,1,0,1)
    assert word(retired,80)==word(retired,112)==1
    v.held.remove(value)
   return 8
  with concurrent.futures.ThreadPoolExecutor(max_workers=8)as executor:count=sum(executor.map(worker,range(8)))
  assert count==64 and word(v.engine.context,176)==64
  v.raw(56);assert word(v.engine.context,176)==0
  carrier.q(3,raw);cleanup(v,b,parent);rows.append(dict(case='eight-thread-real-carrier-clone-capture-retirement',threads=8,actual_captures=count,actual_pending_native_objects=64,one_outside_lock_native_drain=True))
  print('RESOURCE_SUBCLASS_PASS concurrency',flush=True)

  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));controls=[]
  for op in(113,114):
   for domain in(b'HIABVQ06',b'HIABVQ07',b'HIABVQ08',b'HIABVQ09',b'HIABVQ10',b'HIABVQ11'):
    raw=bytearray(frame(op,arg0=74 if op==114 else 1,tail=b''if op==114 else struct.pack('<3Q',1,2,3)));raw[:8]=domain;controls.append(bytes(raw))
  for kind in(0,3,4,5,8):
   raw=bytearray(frame(113,arg0=kind,tail=struct.pack('<3Q',1,2,3)));raw[:8]=b'HIABVQ05';controls.append(bytes(raw))
  for raw in controls:
   state=bytes(v.engine.context);rc,reply=v.engine.call(raw);assert rc==0xfffffffd and bytes(v.engine.context)==state
  for op in(113,114):
   body=policy('native_resource_class_private_request_'+str(op),'''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,0)==0:
        put(w,0,1)
        zero(o,128,152)
        put(o,0,NC_BODY_VALUE)
        put(o,8,152)
        put(o,128,0x3530515642414948)
        put(o,136,OP)
        put(o,224,24)
        put(o,232,1)
        put(o,256,1)
        put(o,264,2)
        put(o,272,3)
        return 1
    return 2
'''.replace('OP',str(op)))
   fn=v.function(body);args=v.tuple([]);reply=v.raw(70,a=fn,b=args,want=11)
   assert reply[24:48]==bytes(24)and word(reply,96)==0
  for cap in list(v.held):v.drop(cap)
  sweep(v,b);b.close();rows.append(dict(case='new-private-operation-boundaries-and-actual-native-body-refusals',controls=len(controls)))
  print('RESOURCE_SUBCLASS_PASS native-private',flush=True)
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),
   runtime_lease_plain_subclass_capture_qualified=True,optimization_future_canonical_class_qualified=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:
  for fd,_ in files:os.close(fd)
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 assert set(os.listdir('/proc/self/fd'))==before
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','custody','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.custody,a.output)
if __name__=='__main__':main()
