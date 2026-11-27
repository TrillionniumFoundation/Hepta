"""Preserve original native equality/hash while deferring this fixed private call."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,sys,traceback
from tools import qualify_hia_result_value_protocols as original
from tools.qualify_hia_result_value_subprocess import Values,Bound,Engine,sweep,word,ZERO
from tools.qualify_hia_result_value_deferred_boundmethod import snapshot
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_native_callable_code_owner import deny_native,policy
from tools.qualify_hia_result_value_invocation_custody import ip_at
from tools import generate_hia_result_value_platform_packer as value_pack
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame

def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def request(op,**kw):
 raw=bytearray(frame(op,**kw));raw[:8]=b'HIABVQ13';return bytes(raw)
class DeferredValues(original.Values):
 def raw(self,op,*,want=0,on=16384,**kw):
  if op not in (62,63):return super().raw(op,want=want,on=on,**kw)
  rc,out=self.engine.call(request(op,**kw),on=on)
  assert rc==0 and out[:8]==b'HIABVR01',(op,rc,out[:192].hex())
  assert word(out,8)==want,(op,word(out,8),want,out[:192].hex())
  snapshot(out)
  return out
def setup(path):
 b=Bound(path);assert b.call(0)['status']==0
 return b,Values(Engine(b))
def clean(v,b):sweep(v,b);b.close()
def actual(v,op,*,want=0,queue=0,**kw):
 rc,out=v.engine.call(request(op,**kw))
 assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==want,(op,rc,out[:192].hex())
 snapshot(out,queue);return out

def run(image,path,out):
 assert platform.python_version()=='3.14.4'
 out.mkdir(parents=True,exist_ok=False)
 rows=[];fds=set(os.listdir('/proc/self/fd'))
 report=dict(schema='hia.native-deferred-protocols.component.v1',passed=False,
  image=pin(image.read_bytes()),owner=pin(path.read_bytes()),
  previous_Q05_Q11_Q12_unchanged=True,private_protocol='HIABVQ13',
  native_custom_method_dispatch_qualified=False,public_Q13_refusal_qualified=False,
  whole_public_llvm_qualified=False)
 try:
  prior=original.Values;argv=sys.argv
  try:
   original.Values=DeferredValues
   sys.argv=[str(Path(original.__file__)),'--image',str(image),'--output',str(out/'original-protocols')]
   original.main()
  finally:
   original.Values=prior;sys.argv=argv
  original_report=json.loads((out/'original-protocols/report.json').read_text())
  assert original_report['passed']
  rows.append(dict(case='all-original-equality-hash-key-oracle-assertions-through-Q13',
   groups=len(original_report['groups']),report=pin((out/'original-protocols/report.json').read_bytes()),
   unchanged_oracle_source=pin(Path(original.__file__).read_bytes())))
  print('DEFERRED_PROTOCOL_PASS original',flush=True)

  b,v=setup(path)
  a=v.scalar(1);c=v.scalar(1.0);ta=v.tuple([a]);tc=v.tuple([c])
  same=[]
  for op,kw in ((62,dict(a=a,b=c)),(62,dict(a=ta,b=tc)),(63,dict(a=ta))):
   baseline=v.raw(op,**kw);private=actual(v,op,**kw)
   assert baseline[:128]==private[:128],(op,baseline[:128].hex(),private[:128].hex())
   same.append(dict(op=op,reply=private[:192].hex()))
  clean(v,b);rows.append(dict(case='unchanged-primary-bytes-and-only-explicit-private-trailer',responses=same))
  print('DEFERRED_PROTOCOL_PASS primary',flush=True)

  b,v=setup(path);a=v.scalar(1);c=v.scalar(1.0);t=v.tuple([a])
  expected_hash=word(v.raw(63,a=t),48)
  pending_function(v,b);assert word(v.engine.context,176)==1
  eq=actual(v,62,a=a,b=c,queue=1);hs=actual(v,63,a=t,queue=1)
  assert word(eq,48)==1 and word(hs,48)==expected_hash
  assert word(v.engine.context,176)==1 and word(v.engine.context,184)==0
  v.raw(56);assert word(v.engine.context,176)==word(v.engine.context,184)==0
  clean(v,b);rows.append(dict(case='actual-code-munmap-EIO-queue-remains-through-equality-and-hash-until-native-drain',
   equality=eq[:192].hex(),hash=hs[:192].hex()))
  print('DEFERRED_PROTOCOL_PASS pending',flush=True)

  b,v=setup(path);a=v.scalar(1);pending_function(v,b)
  receipts=[]
  for op,kw in ((62,dict(a=a,b=a)),(63,dict(a=a))):
   def worker():
    deny_native(ip_at(b.value,value_pack),39,errno.EIO)
    return v.engine.call(request(op,**kw))
   rc,failed=faults.thread_result(worker)
   assert rc==0 and word(failed,8)==11 and failed[24:48]==bytes(24)
   snapshot(failed,known=0);assert word(v.engine.context,176)==1
   receipts.append(failed[:192].hex())
  v.raw(56);clean(v,b);rows.append(dict(case='actual-getpid-EIO-before-arena-lock-keeps-unknown-snapshot',receipts=receipts))
  print('DEFERRED_PROTOCOL_PASS prelock',flush=True)

  b,v=setup(path);a=v.scalar(4);controls=[]
  for op in tuple(range(62))+tuple(range(64,118))+(255,):
   controls.append(request(op))
  for op in(62,63):
   good=request(op,a=a,**({'b':a}if op==62 else{}))
   for at in(16,72,80,88,96,104,112,120):
    raw=bytearray(good);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
   if op==63:
    for at in(48,56,64):
     raw=bytearray(good);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
   controls.extend([good[:-1],good+b'\0'])
   for magic in tuple(('HIABVQ%02d'%i).encode()for i in range(1,13)if i!=5):
    raw=bytearray(good);raw[:8]=magic;controls.append(bytes(raw))
  for raw in controls:
   before=bytes(v.engine.context);rc,reply=v.engine.call(raw)
   assert rc==0xfffffffd and bytes(v.engine.context)==before,(raw[:128].hex(),rc,reply[:192].hex())
  for op in(62,63):
   body='''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,128,128)
    put(o,0,NC_BODY_VALUE)
    put(o,8,128)
    put(o,128,MAGIC)
    put(o,136,OP)
    put(o,152,CAP0)
    put(o,160,CAP1)
    put(o,168,CAP2)
EXTRA
    return 1
'''
   body=body.replace('MAGIC',str(int.from_bytes(b'HIABVQ13','little'))).replace('OP',str(op))
   for i in range(3):body=body.replace('CAP'+str(i),str(a[i]))
   body=body.replace('EXTRA','\n'.join('    put(o,'+str(176+8*i)+','+str(a[i])+')'for i in range(3))if op==62 else'')
   f=v.function(policy('deferred_protocol_refusal_'+str(op),body))
   reply=v.raw(70,a=f,b=v.tuple([]),want=11)
   assert word(reply,96)==0 and reply[24:48]==bytes(24)
  clean(v,b);rows.append(dict(case='only62and63-shapes-prior-domains-and-native-body-refusal',controls=len(controls),native_bodies=2))
  print('DEFERRED_PROTOCOL_PASS exact-domain',flush=True)
  assert set(os.listdir('/proc/self/fd'))==fds
  report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),
   deferred_builtin_comparison_hash_qualified=True,native_body_refusal_qualified=True)
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('image','owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.image,a.owner,a.output)
if __name__=='__main__':main()
