"""Private Info operations retain native identity while postponing finalizer dispatch."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,mmap,os,platform,signal,struct,traceback
from tools.qualify_hia_result_value_subprocess import Values,Bound,Engine,sweep,word,ZERO
from tools.qualify_hia_result_value_deferred_boundmethod import snapshot,deferred_drop
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_lease_owner_resources import capture
from tools.qualify_hia_result_value_records import Values as RecordValues
from tools.qualify_hia_generation_info_owner import captured_metadata,compare_record

ENTRY=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def request(op,a=ZERO,b=ZERO,nonce=(0,0),tail=b'',magic=b'HIABVQ14'):
 out=bytearray(128)
 struct.pack_into('<8sQ',out,0,magic,op);struct.pack_into('<3Q',out,24,*a);struct.pack_into('<3Q',out,48,*b)
 struct.pack_into('<3Q',out,96,len(tail),*nonce)
 return bytes(out)+tail
def call(v,raw,want=0,queue=0):
 rc,out=v.engine.call(raw)
 assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==want,(rc,want,out[:192].hex())
 if raw[:8]==b'HIABVQ14':snapshot(out,queue)
 return out
def same(v,a,b):
 replies=[call(v,request(7,a=x,magic=b'HIABVQ06'))for x in(a,b)]
 return tuple(word(replies[0],i)for i in(104,112))==tuple(word(replies[1],i)for i in(104,112))
def nonce_from_actual_carrier(bound,raw):
 data=bytearray(128);struct.pack_into('<8s2Q',data,0,b'HIAMVHA1',6,2);struct.pack_into('<3Q',data,24,*raw)
 source=C.create_string_buffer(bytes(data));ctx=(C.c_char*256).from_buffer(bound.owner.context,256)
 with mmap.mmap(-1,q.OUT)as output:
  rc=ENTRY(word(bound.owner.context,32))(source,128,q.address(output),q.OUT,ctx,256)
  reply=bytes(output[:128])
 assert rc==0 and reply[:8]==b'HIAMVHA2'and word(reply,8)==0, (rc,reply.hex())
 assert tuple(word(reply,i)for i in(96,104,112))==(1,0,0),reply.hex()
 n=tuple(word(reply,i)for i in(24,32));assert any(n)
 return n,reply
def detached(carrier,raw,op):
 result=carrier.q(4,raw,q.old.public_request(op),child=0)
 ptr,n,data=q.old.detached(result)
 try:return data
 finally:q.old.free(ptr)

def run(path,out,tools):
 assert platform.python_version()=='3.14.4';signal.alarm(300)
 out.mkdir(parents=True,exist_ok=False);rows=[];initial=set(os.listdir('/proc/self/fd'))
 report=dict(schema='hia.native-deferred-info.component.v1',passed=False,owner=pin(path.read_bytes()),
  private_protocol='HIABVQ14',operations=[60,64,65,66],old_Q05_unchanged=True,
  public_private_refusal_qualified=False,enclosing_Info_root_lock_order_qualified=False,
  whole_public_runtime_qualified=False)
 files=[]
 try:
  for path0 in tools:
   data=path0.read_bytes();files.append((q.old.sealed(data),data))
  bound=Bound(path)
  v=Values(Engine(bound));rv=RecordValues(v.engine);rv.held=v.held
  c=q.Carrier(bound.owner);parent=out/'artifacts';parent.mkdir()
  runtime_raw=q.old.create(c,files,parent)
  lease_raw=q.old.lease(c,runtime_raw);second_raw=q.old.lease(c,runtime_raw)
  runtime=capture(bound.owner,v,1,runtime_raw)
  lease=capture(bound.owner,v,2,lease_raw,runtime)
  second=capture(bound.owner,v,2,second_raw,runtime)
  assert bound.call(0)['status']==0
  nonce,nonce_reply=nonce_from_actual_carrier(bound,lease_raw)
  blob=detached(c,lease_raw,6);assert blob[:8]==b'HIAMVIR2'
  snap=detached(c,runtime_raw,10);snapshot_json=snap;assert 'generations'in json.loads(snapshot_json)
  expected,original,_=captured_metadata(c,lease_raw)
  old=v.keep(call(v,request(60,nonce=nonce,tail=blob,magic=b'HIABVQ05')))
  current=v.keep(call(v,request(60,nonce=nonce,tail=blob)))
  assert same(v,old,current)
  call(v,request(65,a=lease),want=6)
  call(v,request(66,a=runtime,b=current,nonce=nonce,tail=snapshot_json))
  call(v,request(64,a=lease,b=current,nonce=nonce))
  cached=v.keep(call(v,request(65,a=lease)));assert same(v,current,cached)
  old_cached=v.keep(call(v,request(65,a=lease,magic=b'HIABVQ05')));assert same(v,current,old_cached)
  comparison=compare_record(rv,current,expected,original)
  rows.append(dict(case='actual-carrier-info-and-nonce-all-four-operations-original-record-identity',
   nonce_receipt=nonce_reply.hex(),info_blob=pin(blob),snapshot=pin(snap),**comparison))
  print('DEFERRED_INFO_PASS actual-info',flush=True)

  pending_function(v,bound);assert word(v.engine.context,176)==1
  replies=[]
  retained=v.keep(call(v,request(60,nonce=nonce,tail=blob),queue=1))
  replies.append(call(v,request(66,a=runtime,b=retained,nonce=nonce,tail=snapshot_json),queue=1))
  replies.append(call(v,request(64,a=second,b=retained,nonce=nonce),queue=1))
  retained2=v.keep(call(v,request(65,a=second),queue=1));assert same(v,current,retained2)
  replies.append(call(v,request(66,a=runtime,nonce=nonce,tail=snapshot_json),queue=1))
  assert word(v.engine.context,176)==1 and word(v.engine.context,184)==0
  for item in(retained,retained2):deferred_drop(v,item)
  assert word(v.engine.context,176)==1
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  rows.append(dict(case='real-code-munmap-EIO-no-finalizer-dispatch-for-all-four-operations',
   immutable_cache_and_prune_committed=True,replies=[x[:192].hex()for x in replies]))
  print('DEFERRED_INFO_PASS pending',flush=True)

  bad=(nonce[0]^1,nonce[1]);pending_function(v,bound)
  errors=[]
  errors.append(call(v,request(64,a=second,b=current,nonce=bad),want=6,queue=1))
  errors.append(call(v,request(66,a=runtime,b=current,nonce=bad,tail=snapshot_json),want=6,queue=1))
  errors.append(call(v,request(66,a=runtime,nonce=nonce,tail=b'{"generations":[{}]}'),want=2,queue=1))
  assert word(v.engine.context,176)==1
  v.raw(56);assert same(v,current,v.keep(call(v,request(65,a=second))))
  rows.append(dict(case='real-native-nonce-and-snapshot-refusals-preserve-live-cache-and-pending',replies=[x[:192].hex()for x in errors]))
  print('DEFERRED_INFO_PASS errors',flush=True)

  pending_function(v,bound);receipts=[]
  raw_requests=[request(60,nonce=nonce,tail=blob),request(64,a=lease,b=current,nonce=nonce),
                request(65,a=lease),request(66,a=runtime,nonce=nonce,tail=snapshot_json)]
  for raw in raw_requests:
   def worker():
    deny_native(ip_at(bound.value,value_pack),39,errno.EIO)
    return v.engine.call(raw)
   rc,reply=faults.thread_result(worker)
   assert rc==0 and word(reply,8)==11 and reply[24:48]==bytes(24)
   snapshot(reply,known=0);assert word(v.engine.context,176)==1
   receipts.append(reply[:192].hex())
  v.raw(56)
  rows.append(dict(case='actual-getpid-EIO-before-lock-never-invents-snapshot-or-primary',receipts=receipts))
  print('DEFERRED_INFO_PASS prelock',flush=True)

  controls=[request(op)for op in range(120)if op not in(60,64,65,66)]+[request((1<<64)-1)]
  for good in raw_requests:
   for at in(16,72,80,88,120):
    raw=bytearray(good);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
   controls.extend((good[:-1],good+b'\0'))
  for raw in controls:
   before=bytes(v.engine.context);rc,reply=v.engine.call(raw)
   assert rc==0xfffffffd and bytes(v.engine.context)==before,(raw[:128].hex(),rc,reply[:192].hex())
  for op in(60,64,65,66):
   body='''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,128,128)
    put(o,0,NC_BODY_VALUE)
    put(o,8,128)
    put(o,128,MAGIC)
    put(o,136,OP)
    return 1
'''
   body=body.replace('MAGIC',str(int.from_bytes(b'HIABVQ14','little'))).replace('OP',str(op))
   function=v.function(policy('private_info_body_refusal_'+str(op),body))
   failed=v.raw(70,a=function,b=v.tuple([]),want=11)
   assert word(failed,96)==0 and failed[24:48]==bytes(24)
  rows.append(dict(case='strict-new-domain-malformed-frame-and-native-body-refusal',controls=len(controls),native_bodies=4))
  print('DEFERRED_INFO_PASS domain',flush=True)
  for raw in(lease_raw,second_raw,runtime_raw):c.q(3,raw)
  sweep(v,bound);bound.close();assert not list(parent.iterdir())
  for fd,_ in files:os.close(fd)
  files=[]
  assert set(os.listdir('/proc/self/fd'))==initial
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),
   deferred_info_component_qualified=True,native_body_refusal_qualified=True)
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:
  for fd,_ in files:os.close(fd)
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
  signal.alarm(0)
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','output','normalizer','proof','builder'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.output,[a.normalizer,a.proof,a.builder])
if __name__=='__main__':main()
