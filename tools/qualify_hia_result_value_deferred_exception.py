"""Fixed deferred exception/record requests preserve actual native ownership."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,traceback
from tools.qualify_hia_result_value_subprocess import Values,Bound,Engine,sweep,word,ZERO,make_value
from tools.qualify_hia_result_value_platform import args_and_dict,objects
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools import generate_hia_result_value_platform_packer as values_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame
ALLOWED=(32,40,43,57,75,87,98,99,100,*range(101,113))
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def request(op,kw,magic=None):
 raw=bytearray(frame(op,**kw))
 if magic is not None:raw[:8]=magic
 elif op>=99:raw[:8]=b'HIABVQ05'
 return bytes(raw)
def call(v,op,kw,private=True,want=0,known=1,queued=0):
 rc,out=v.engine.call(request(op,kw,b'HIABVQ11'if private else None))
 assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==want,(op,rc,out[:192].hex())
 if private:
  assert out[128:136]==b'HIABVD01'
  assert tuple(word(out,i)for i in(136,144,152,160))==(known,0,queued,1),out[:192].hex()
 return out
def same(v,a,b):assert v.same(a,b),(a,b)
def prepare(v):
 cls={i:v.builtin(i)for i in(21,22,23,24,25,27,31,38,44,46,48,53,54,70,71,72,73)}
 text=v.scalar('native error');none=v.scalar(None)
 numbers=[v.scalar(i)for i in range(13)]
 args=v.tuple([text]);namespace=v.keep(v.raw(4))
 error=v.keep(v.raw(75,a=cls[23],b=args,c=namespace))
 cause=v.keep(v.raw(75,a=cls[22],b=args))
 result=v.keep(v.raw(106,a=error,b=cause,arg0=0));v.drop(result)
 command=v.tuple([v.scalar('clang')]);rawout=v.scalar(b'out');rawerr=v.scalar(b'err')
 failurefields=[command,none,rawout,rawerr,numbers[3],numbers[3]];failureseq=v.lst(failurefields)
 failure=v.keep(v.raw(102,a=failureseq))
 resultseq=v.lst([numbers[0],text,text,rawout,rawerr])
 osargs=v.tuple([numbers[13-1],text,v.scalar('/tmp/observed')])
 oserror=v.keep(v.raw(104,a=cls[25],b=osargs))
 encoding=v.scalar('utf-8');invalid=v.scalar(b'\xff');reason=v.scalar('invalid start byte')
 unicodeargs=v.tuple([encoding,invalid,numbers[0],numbers[1],reason])
 unicode=v.keep(v.raw(108,a=unicodeargs,b=cls[70]))
 timeout=v.timeout(cls[72],[command,numbers[3],rawout,rawerr])
 replacement=v.scalar(b'new output')
 records=v.lst(numbers[:9]);tuple_input=v.lst(numbers[:3])
 cases=[]
 def add(name,op,check,**kw):cases.append(dict(name=name,op=op,kw=kw,check=check))
 for op,index in((32,23),(57,31),(87,38),(98,44),(99,46),(101,48),(110,72),(112,73)):
  add('canonical-'+str(index),op,lambda cap,index=index:same(v,cap,cls[index]),arg0=index)
 add('real-tuple',40,lambda cap: v.python_value(cap)==(0,1,2),a=tuple_input)
 add('real-record-field',43,lambda cap:same(v,cap,command),a=failure,arg0=0)
 add('exception',75,lambda cap:v.isinst(cap,cls[23]),a=cls[23],b=args,c=namespace)
 add('llvm-record',100,lambda cap:v.isinst(cap,cls[46]),a=records)
 add('capture-failure',102,lambda cap:v.isinst(cap,cls[53]),a=failureseq)
 add('capture-result',103,lambda cap:v.isinst(cap,cls[54]),a=resultseq)
 add('os-specialization',104,lambda cap:v.isinst(cap,cls[25]),a=cls[25],b=osargs)
 add('os-slot',105,lambda cap:same(v,cap,numbers[12]),a=oserror,arg0=0)
 add('cause-set',106,lambda cap:v.python_value(cap)is None,a=error,b=cause,arg0=0)
 add('cause-get',107,lambda cap:same(v,cap,cause),a=error,arg0=0)
 add('unicode-capture',108,lambda cap:v.isinst(cap,cls[70]),a=unicodeargs,b=cls[70])
 add('unicode-slot',109,lambda cap:same(v,cap,invalid),a=unicode,arg0=1)
 add('timeout-get',111,lambda cap:same(v,cap,rawout),a=timeout,arg0=4)
 add('timeout-set',111,lambda cap:v.python_value(cap)is None,a=timeout,b=replacement,arg0=4,arg1=1)
 return cases,dict(cls=cls,error=error,cause=cause,namespace=namespace,text=text,numbers=numbers,tuple_input=tuple_input)
def run(path,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 report=dict(schema='hia.native-value-deferred-exception.component.v1',passed=False,
  product=pin(path.read_bytes()),public_profile_refusal_qualified=False,whole_public_runtime_qualified=False)
 rows=[];before=set(os.listdir('/proc/self/fd'))
 try:
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));cases,inputs=prepare(v)
  assert set(c['op']for c in cases)==set(ALLOWED)
  paired=[]
  for c in cases:
   original=call(v,c['op'],c['kw'],False)
   current=call(v,c['op'],c['kw'])
   fields=(8,16,48,56,64,72,80,88,96,120)
   # Prior operations return the actual object identity at 104/112.
   # Fresh tuples/records have different identities; verify each against
   # that result's genuine native kind query instead of equating allocations.
   if c['op']>=101:fields+=(104,112)
   assert tuple(word(original,i)for i in fields)==tuple(word(current,i)for i in fields),(c['name'],original[:128].hex(),current[:128].hex())
   a=v.keep(original);d=v.keep(current)
   if c['op']<101:
    for reply,cap in((original,a),(current,d)):
     actual=v.raw(7,a=cap)
     assert reply[104:120]==actual[104:120],(c['name'],reply[:128].hex(),actual[:128].hex())
   assert c['check'](a)is not False and c['check'](d)is not False,c['name']
   v.drop(a);v.drop(d);paired.append(c['name'])
  sweep(v,b);b.close();rows.append(dict(case='every-fixed-operation-preserves-original-semantics-and-header',operations=paired))
  print('DEFERRED_EXCEPTION_PASS paired',flush=True)
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));cases,inputs=prepare(v)
  pending_function(v,b);held=[]
  for c in cases:
   current=call(v,c['op'],c['kw'],queued=1)
   assert word(v.engine.context,176)!=0
   held.append((c,v.keep(current)))
  retry=v.raw(56);assert word(retry,8)==0
  assert word(v.engine.context,176)==word(v.engine.context,184)==0
  for c,cap in held:
   assert c['check'](cap)is not False,c['name'];v.drop(cap)
  sweep(v,b);b.close();rows.append(dict(case='actual-code-munmap-EIO-queue-deferred-through-every-fixed-operation',operations=len(held),actual_native_retry=True))
  print('DEFERRED_EXCEPTION_PASS actual-pending',flush=True)
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));cases,inputs=prepare(v)
  bad=[(40,dict(a=inputs['text'])),(43,dict(a=inputs['text'],arg0=0)),
       (75,dict(a=inputs['text'],b=inputs['tuple_input'])),(100,dict(a=inputs['tuple_input'])),
       (102,dict(a=inputs['tuple_input'])),(103,dict(a=inputs['tuple_input'])),
       (104,dict(a=inputs['text'],b=inputs['tuple_input'])),(105,dict(a=inputs['text'],arg0=0)),
       (106,dict(a=inputs['text'],b=inputs['error'],arg0=0)),(107,dict(a=inputs['text'],arg0=0)),
       (108,dict(a=inputs['tuple_input'])),(109,dict(a=inputs['text'],arg0=0)),
       (111,dict(a=inputs['text'],arg0=4))]
  statuses=[]
  for op,kw in bad:
   rc,original=v.engine.call(request(op,kw));assert rc==0 and word(original,8)!=0
   current=call(v,op,kw,want=word(original,8))
   assert current[:128]==original[:128],(op,current[:128].hex(),original[:128].hex())
   statuses.append((op,word(current,8)))
  pending_function(v,b)
  failure_case=next(c for c in cases if c['op']==110)
  def denied():
   deny_native(ip_at(b.value,values_pack),318,errno.EIO)
   return call(v,failure_case['op'],failure_case['kw'],want=11,queued=1)
  failed=faults.thread_result(denied);assert failed[24:48]==bytes(24)and word(failed,88)==1 and word(failed,96)==0
  assert word(v.engine.context,176)!=0
  def before_lock():
   deny_native(ip_at(b.value,values_pack),39,errno.EIO)
   return call(v,110,dict(arg0=72),want=11,known=0,queued=0)
  unknown=faults.thread_result(before_lock)
  assert unknown[24:48]==bytes(24)and word(v.engine.context,176)!=0
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  sweep(v,b);b.close();rows.append(dict(case='original-errors-and-real-getrandom-and-admission-failures',statuses=statuses,
    unpublished=failed[:192].hex(),snapshot_unknown=unknown[:192].hex()))
  print('DEFERRED_EXCEPTION_PASS errors',flush=True)
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));cases,inputs=prepare(v)
  namespace=v.keep(v.raw(4));key=v.scalar('self');args=v.tuple([inputs['text']])
  cycle=v.keep(v.raw(75,a=inputs['cls'][23],b=args,c=namespace))
  v.raw(10,a=namespace,b=key,c=cycle)
  none=v.scalar(None);anchor=v.timeout(inputs['cls'][72],[inputs['text'],inputs['numbers'][3],cycle,none])
  v.drop(cycle);v.drop(namespace)
  pending_function(v,b);count=objects(v)
  delivered=call(v,111,dict(a=anchor,b=none,arg0=4,arg1=1),queued=1);v.keep(delivered)
  assert objects(v)==count
  for _ in range(4097):v.keep(call(v,110,dict(arg0=72),queued=1))
  assert objects(v)==count-2,(objects(v),count)
  assert word(v.engine.context,176)!=0
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  sweep(v,b);b.close()
  rows.append(dict(case='actual-cycle-collection-still-runs-in-deferred-profile',unreachable_nodes_collected=2,operations=4097,native_finalizer_still_deferred=True))
  print('DEFERRED_EXCEPTION_PASS real-GC',flush=True)
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));cases,inputs=prepare(v);controls=[]
  for op in range(114):
   if op not in ALLOWED:controls.append(request(op,{},b'HIABVQ11'))
  good=request(110,dict(arg0=72),b'HIABVQ11')
  for at in(16,24,48,72,96,112,120):
   raw=bytearray(good);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
  for op,arg in((101,71),(110,73),(112,72),(112,74),(32,28),(57,38),(98,46),(99,48)):
   controls.append(request(op,dict(arg0=arg),b'HIABVQ11'))
  for raw in controls:
   state=bytes(v.engine.context);rc,reply=v.engine.call(raw)
   assert rc==0xfffffffd and bytes(v.engine.context)==state
   expected=bytearray(b'\xa5'*len(reply));expected[128:136]=bytes(8);assert reply==expected
  sweep(v,b);b.close();rows.append(dict(case='exact-new-private-domain-and-unchanged-rejection',controls=len(controls)))
  print('DEFERRED_EXCEPTION_PASS domain',flush=True)
  b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
  body=policy('actual_private_exception_profile_is_refused','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,0)==0:
        put(w,0,1)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,0x3131515642414948)
        put(o,136,32)
        put(o,232,23)
        return 1
    if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
''')
  fn=v.function(body);args=v.tuple([]);rejected=v.raw(70,a=fn,b=args,want=11)
  assert rejected[24:48]==bytes(24)and word(rejected,96)==0 and word(rejected,80)==0
  sweep(v,b);b.close()
  rows.append(dict(case='actual-native-code-cannot-enter-new-private-profile',delivered=False))
  print('DEFERRED_EXCEPTION_PASS native-body-refusal',flush=True)
  assert set(os.listdir('/proc/self/fd'))==before
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),native_snapshot_inside_value_mutex=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
