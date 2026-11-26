"""Actual deferred method binding keeps code, self and queued native custody."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,traceback,types
from tools.qualify_hia_result_value_subprocess import Values,Bound,Engine,sweep,word,ZERO
from tools.qualify_hia_result_value_invocations import echo_field,code_call
from tools.qualify_hia_result_value_invocation_custody import notified,ip_at,code_pack
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def setup(path):
 b=Bound(path);assert b.call(0)['status']==0
 return b,Values(Engine(b))
def snapshot(reply,queue=0,known=1):
 assert reply[128:136]==b'HIABVD01'
 assert tuple(word(reply,i)for i in(136,144,152,160))==(known,0,queue,1),reply[:192].hex()
def deferred_drop(v,cap):
 rc,out=v.engine.call(frame(78,a=cap))
 assert rc==0 and out[:8]==b'HIABVR02'and word(out,88)==word(out,96)==1,out[:128].hex()
 assert word(out,104)==0 and word(out,112)<=1 and word(out,120)==1
 if cap in v.held:v.held.remove(cap)
def bind(v,function,receiver,queued=0,want=0):
 reply=v.raw(115,a=function,b=receiver,want=want)
 snapshot(reply,queued)
 assert tuple(word(reply,i)for i in(80,88,96))==(queued,1,int(want==0)),reply[:192].hex()
 if want:
  assert reply[24:48]==bytes(24);return reply
 assert (word(reply,64),word(reply,104),word(reply,120))==(1,0,0),reply[:128].hex()
 return v.keep(reply),reply
def clean(v,b):
 sweep(v,b);b.close()
def run(path,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 before=set(os.listdir('/proc/self/fd'));rows=[]
 report=dict(schema='hia.native-deferred-boundmethod.component.v1',passed=False,product=pin(path.read_bytes()),
  whole_public_runtime_qualified=False,public_private_operation_refusal_qualified=False,
  enclosing_Clang_reentrant_user_call_lock_order_qualified=False)
 try:
  b,v=setup(path);receiver=v.dictionary([('self',7)]);f=v.function(echo_field(3))
  old=v.method(f,receiver);current,reply=bind(v,f,receiver)
  cls=v.builtin(33);assert v.isinst(old,cls)and v.isinst(current,cls)and not v.same(old,current)
  v.drop(f);v.drop(receiver)
  args=v.tuple([v.scalar('argument')]);left=v.invoke(old,args);right=v.invoke(current,args)
  oracle=types.MethodType(lambda *a:a,{'self':7})('argument')
  assert v.python_value(left)==v.python_value(right)==oracle
  second=v.scalar('second');nested,nreply=bind(v,current,second);v.drop(current);v.drop(second)
  result=v.invoke(nested,args)
  assert v.python_value(result)==types.MethodType(types.MethodType(lambda *a:a,{'self':7}),'second')('argument')
  clean(v,b);rows.append(dict(case='original-boundmethod-semantics-strong-self-function-and-nested-order',original_69_unchanged=True))
  print('DEFERRED_BIND_PASS semantics',flush=True)

  b,v=setup(path);receiver=v.lst([v.scalar('kept')]);f=v.function(echo_field(3));pending_function(v,b)
  assert word(v.engine.context,176)==1
  current,reply=bind(v,f,receiver,queued=1)
  assert word(v.engine.context,176)==1 and word(v.engine.context,184)==0
  for cap in list(v.held):
   if cap!=current:deferred_drop(v,cap)
  assert word(v.engine.context,176)==1
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  result=v.invoke(current,v.tuple([]));assert v.python_value(result)==(['kept'],)
  clean(v,b);rows.append(dict(case='real-code-munmap-EIO-queue-preserved-through-nested-Q08-capture-and-78-cleanup',
   primary_delivered=True,actual_single_native_drain=True,reply=reply[:192].hex()))
  print('DEFERRED_BIND_PASS actual-queue',flush=True)

  b,v=setup(path);receiver=v.dictionary([('kept',123)]);f=v.function(echo_field(3))
  observed={}
  def drop_at_code(notice,index):
   if index==0:
    assert word(v.engine.context,32)==0
    arena=word(v.engine.context,16);head=word(C.string_at(arena+1096,8),0);assert head
    token=C.string_at(arena+head,96);record=C.string_at(word(token,80),512)
    assert word(token,40)==1 and word(record,16)==115 and word(record,440)and word(record,464)
    assert b.call(1)['status']==6
    n=len(v.held)
    for cap in list(v.held):deferred_drop(v,cap)
    assert not v.held
    observed.update(original_caps_consumed=n,real_value_mutex_released=True,actual_private_strong_self=True)
   return 0
  reply,notes=notified(v,frame(115,a=f,b=receiver),ip_at(b.code,code_pack),[39],out/'concurrent-caller-drop.json',drop_at_code)
  assert word(reply,8)==0 and word(reply,96)==1 and word(reply,104)==0; snapshot(reply)
  current=v.keep(reply);result=v.invoke(current,v.tuple([]));assert v.python_value(result)==({'kept':123},)
  clean(v,b);rows.append(dict(case='actual-code-stop-original-function-and-self-caps-consumed-concurrently',
   notifications=len(notes),**observed))
  print('DEFERRED_BIND_PASS strong-self',flush=True)

  b,v=setup(path);receiver=v.scalar('self');f=v.function(echo_field(3));text=v.scalar('not callable')
  errors=[]
  for a,c in((text,receiver),(f,ZERO),((1,2,3),receiver),(f,(1,2,3))):
   rc,old=v.engine.call(frame(69,a=a,b=c));assert rc==0 and word(old,8)!=0 and old[24:48]==bytes(24)
   new=bind(v,a,c,want=word(old,8))
   assert new[:128]==old[:128],(old[:128].hex(),new[:128].hex())
   errors.append(word(new,8))
  pending_function(v,b)
  def failed_before_lock():
   deny_native(ip_at(b.value,value_pack),39,errno.EIO)
   return v.engine.call(frame(115,a=f,b=receiver))
  rc,failed=faults.thread_result(failed_before_lock)
  assert rc==0 and word(failed,8)==11 and word(failed,96)==0 and failed[24:48]==bytes(24)
  snapshot(failed,known=0)
  assert word(v.engine.context,176)==1
  v.raw(56);clean(v,b);rows.append(dict(case='original-validation-order-and-unknown-pre-lock-snapshot',
   statuses=errors,unknown_snapshot=failed[:192].hex()))
  print('DEFERRED_BIND_PASS original-errors',flush=True)

  b,v=setup(path);receiver=v.scalar('self');f=v.function(echo_field(3));pending_function(v,b)
  observed={}
  def reject_capture(notice,index):
   if index==1:
    arena=word(v.engine.context,16);head=word(C.string_at(arena+1096,8),0);assert head
    token=C.string_at(arena+head,96);record=C.string_at(word(token,80),2200)
    assert record[2048:2056]==b'HIABVQ08'and word(record,2056)==48
    assert word(v.engine.context,32)==1
    observed.update(actual_nested_deferred_capture=True,actual_value_mutex_held=True)
    return errno.EIO
   return 0
  reply,notes=notified(v,frame(115,a=f,b=receiver),ip_at(b.value,value_pack),[318],out/'capture-getrandom-eio.json',reject_capture)
  assert sum(n['errno']==errno.EIO for n in notes)==1 and observed
  assert word(reply,8)==11 and word(reply,96)==0 and reply[24:48]==bytes(24),reply[:192].hex()
  snapshot(reply,1);assert word(v.engine.context,176)==1 and word(v.engine.context,184)==0
  v.raw(56)
  current,reply=bind(v,f,receiver);result=v.invoke(current,v.tuple([]));assert v.python_value(result)==('self',)
  clean(v,b);rows.append(dict(case='actual-nested-capture-getrandom-EIO-preserves-code-custody-and-queued-finalizer',
   notifications=len(notes),**observed))
  print('DEFERRED_BIND_PASS capture-failure',flush=True)

  b,v=setup(path);receiver=v.scalar('self');f=v.function(echo_field(3))
  def code_random():
   deny_native(ip_at(b.code,code_pack),318,errno.EIO)
   return v.raw(115,a=f,b=receiver,want=11)
  reply=faults.thread_result(code_random)
  assert word(reply,96)==0 and reply[24:48]==bytes(24);snapshot(reply)
  current,reply=bind(v,f,receiver);result=v.invoke(current,v.tuple([]));assert v.python_value(result)==('self',)
  clean(v,b);rows.append(dict(case='actual-code-clone-getrandom-EIO-before-delivery',actual_retry_success=True))
  print('DEFERRED_BIND_PASS code-failure',flush=True)

  b,v=setup(path);receiver=v.scalar('retained');f=v.function(echo_field(3))
  reply,notes=notified(v,frame(115,a=f,b=receiver),ip_at(b.value,value_pack),[11],out/'call-record-munmap-eio.json',lambda n,i:errno.EIO)
  assert notes and tuple(word(reply,i)for i in(8,64,80,88,96,104))==(0,1,1,1,1,11),reply[:192].hex()
  snapshot(reply,1);current=v.keep(reply)
  assert word(v.engine.context,184)==1
  arena=word(v.engine.context,16);head=word(C.string_at(arena+1096,8),0);token=C.string_at(arena+head,96)
  held_record=word(token,80);assert word(token,40)==2 and held_record
  record=C.string_at(held_record,512);assert word(record,16)==115 and tuple(struct.unpack_from('<3Q',record,80))==current
  v.raw(56);assert word(v.engine.context,184)==0
  assert not any(int(line.split('-')[0],16)<=held_record<int(line.split()[0].split('-')[1],16)for line in Path('/proc/self/maps').read_text().splitlines())
  result=v.invoke(current,v.tuple([]));assert v.python_value(result)==('retained',)
  clean(v,b);rows.append(dict(case='delivered-method-survives-real-call-record-munmap-EIO-and-one-native-retry',
   notifications=len(notes),independent_primary_and_cleanup=True))
  print('DEFERRED_BIND_PASS post-delivery',flush=True)

  b,v=setup(path);controls=[]
  good=frame(115)
  for domain in(b'HIABVQ01',b'HIABVQ02',b'HIABVQ03',b'HIABVQ04',b'HIABVQ06',b'HIABVQ07',b'HIABVQ08',b'HIABVQ09',b'HIABVQ10',b'HIABVQ11'):
   raw=bytearray(good);raw[:8]=domain;controls.append(bytes(raw))
  for offset in(16,72,80,88,96,104,112,120):
   raw=bytearray(good);struct.pack_into('<Q',raw,offset,1);controls.append(bytes(raw))
  for raw in controls:
   state=bytes(v.engine.context);rc,reply=v.engine.call(raw)
   assert rc==0xfffffffd and bytes(v.engine.context)==state,(raw.hex(),rc,reply[:192].hex())
  body=policy('private_deferred_boundmethod_refused','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,128,128)
    put(o,0,NC_BODY_VALUE)
    put(o,8,128)
    put(o,128,0x3530515642414948)
    put(o,136,115)
    return 1
''')
  f=v.function(body);reply=v.raw(70,a=f,b=v.tuple([]),want=11)
  assert word(reply,96)==0 and reply[24:48]==bytes(24)
  clean(v,b);rows.append(dict(case='private115-exact-domain-and-actual-native-body-refusal',controls=len(controls)))
  print('DEFERRED_BIND_PASS private-domain',flush=True)
  assert set(os.listdir('/proc/self/fd'))==before
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),
   trusted_deferred_boundmethod_qualified=True,strong_self_and_function_qualified=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
