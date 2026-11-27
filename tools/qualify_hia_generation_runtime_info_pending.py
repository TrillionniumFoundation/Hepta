"""Real queued Runtime retirement through public Lease.info with an unlocked drain.

Runtime values come from the actual public constructor. The Lease fixture uses
an actual acquired carrier and fixed native capture; it is not public acquire
qualification. No native prefix, locks, capabilities or replies are fabricated.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools import qualify_hia_generation_info_owner as info
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_clang_capture_faults import isolated
ZERO=(0,0,0)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def private(owner,op,a=ZERO,b=ZERO,arg=0,tail=b''):
 raw=bytearray(128+len(tail));raw[:8]=b'HIABVQ05'
 for at,value in((8,op),(96,len(tail)),(104,arg)):struct.pack_into('<Q',raw,at,value)
 struct.pack_into('<3Q',raw,24,*a);struct.pack_into('<3Q',raw,48,*b);raw[128:]=tail
 src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(32768)
 F=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
 call=F(q.get(owner.context,40));rc=int(call(src,len(raw),out,len(out),C.addressof(owner.context)+512,256))
 assert rc==0 and out.raw[:8]in(b'HIABVR01',b'HIABVR02'),(rc,out.raw[:128].hex())
 assert src.raw==bytes(raw)+b'\0'
 return out.raw
def one(build,out,name):
 f=factory.installed.InstalledFixture(build/'install/hia-generation-component-root.so',out)
 v=factory.Values(factory.q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48);report=dict(passed=False,name=name)
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  inputs=[v.scalar(directory.current_core()),v.scalar(str(f.parent))]
  created=[]
  for i in range(2):
   rc,row,raw=factory.construct(f,inputs)
   assert rc==0 and row['status']==0 and row['disposition']==1 and row['known']==row['delivered']==row['retired']==1 and row['pending']==0,row
   created.append(v.keep(raw))
   if i==0:remaining={p.name for p in f.parent.iterdir()}
  first,queued=created
  raw_runtime=struct.unpack_from('<3Q',private(f.owner,49,first,arg=1),24)
  carrier=q.Carrier(f.owner);raw_lease=q.old.lease(carrier,raw_runtime)
  captured=private(f.owner,48,first,arg=2,tail=struct.pack('<3Q',*raw_lease))
  assert q.get(captured,88)==q.get(captured,96)==1 and q.get(captured,8)==0,captured[:128].hex()
  lease=v.keep(captured)
  prior=None
  if name=='cached-info':prior=info.info_call(f.owner,v,lease)
  target=v.scalar(123)if name=='wrong-kind'else lease
  f.guard(2);assert q.get(f.owner.context,688)==0
  before=set(p.name for p in f.parent.iterdir());assert len(before-remaining)==1,(before,remaining)
  release=private(f.owner,78,queued)
  assert release[:8]==b'HIABVR02'and q.get(release,88)==q.get(release,96)==1,release[:128].hex()
  assert q.get(release,120)==1 and q.get(release,104)==0
  v.held.remove(queued)
  queued_count=q.get(f.owner.context,688);assert queued_count>0,queued_count
  f.guard(2)
  row=f.owner.call(8,info.request(target))
  report.update(queued_runtime_native=True,queue_before=queued_count,info={k:x for k,x in row.items()if k!='result'},reply_head=row['result'][:128].hex());save()
  if name=='wrong-kind':
   assert row['status']==1 and row['kind']==4 and row['cleanup_status']==0 and not row['cleanup_caps'],row
   assert row['result'][:8]==b'HIABVR01'and q.get(row['result'],8)!=0 and q.get(row['result'],24)==0
  else:
   assert row['status']==0 and row['kind']==4 and row['child_rc']==0 and row['cleanup_status']==0 and not row['cleanup_caps'],row
   result=v.keep(row['result']);assert q.get(row['result'],16)==12
   if prior is not None:assert v.same(prior,result)
   detached=v.keep(v.raw(44,a=result));data=v.python_value(detached);assert data['generation']==0
   report['actual_info']=data
  assert q.get(f.owner.context,688)==0
  f.guard(1);assert set(p.name for p in f.parent.iterdir())==remaining
  report.update(queue_after=0,queued_runtime_directory_removed=True,terminal_runtime_guard_released=True);save()
  while v.held:v.drop(next(iter(v.held)))
  f.guard(0);assert q.get(v.raw(47),48)==baseline
  report.update(passed=True,**f.finish());save();return report
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());save();raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());so=a.build/'install/hia-generation-component-root.so'
 assert pin(so.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in('uncached-info','cached-info','wrong-kind'):
  here=a.output/name;here.mkdir();rows.append(isolated(name,lambda name=name,here=here:one(a.build,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n');print('INFO_UNLOCKED_PENDING_PASS',name,flush=True)
 r=dict(passed=True,groups=len(rows),cases=rows,owner=pin(so.read_bytes()),construction=pin((a.build/'build.json').read_bytes()),qualifier=pin(Path(__file__).read_bytes()),public_runtime_constructor=True,public_lease_value_acquire_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True,default=repr)+'\n');print('INFO_UNLOCKED_PENDING_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
