"""Actual immutable-object identity, event custody and unbounded-number gates."""
from pathlib import Path
from tools import generate_hia_multiversion_runtime_identity_packer as P
import argparse,ctypes as C,struct,hashlib,json,threading,concurrent.futures,time,os
NONE=(1<<64)-1
get=lambda b,a:struct.unpack_from('<Q',b,a)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
def frame(op,selector=0,a=0,b=0,c=0):return struct.pack('<8s7Q',b'HIAMVID1',op,selector,a,b,c,0,0)
def main():
 p=argparse.ArgumentParser();p.add_argument('--component',required=True,type=Path);p.add_argument('--values',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();d=a.output;d.mkdir(parents=True,exist_ok=False)
 lib=C.CDLL(str(a.component));f=lib.hia_mv_runtime_identity;f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
 address=C.cast(f,C.c_void_p).value;hole=P.OUTER_HOLES['values'];relative=struct.unpack('<i',C.string_at(address+hole,4))[0]
 vf=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(address+hole+4+relative)
 rows=[];call_count=0;values_count=0;began=time.monotonic_ns()
 class Ledger:
  def __init__(self):
   self.w=C.create_string_buffer(32768);self.call(0)
  def call(self,op,selector=0,a=0,b=0,c=0,want=0,output=4096):
   nonlocal call_count
   raw=frame(op,selector,a,b,c);s=C.create_string_buffer(raw);o=C.create_string_buffer(output);C.memset(o,0xa5,output)
   rc=f(s,len(raw),o,len(o),self.w,len(self.w));call_count+=1
   assert rc==0 and o.raw[:8]==b'HIAMVIDR' and get(o,8)==want,(op,selector,rc,get(o,8),o.raw[:128].hex())
   assert s.raw==raw+b'\0';return o.raw
  def cap(self,r):return tuple(get(r,i) for i in (24,32,40))
  def value(self,cap,n):
   r=self.call(13,a=cap[0],b=cap[1],c=cap[2],output=4096+n);assert get(r,48)==n and get(r,80)==n
   return r[1536:1536+n]
  def drop(self,cap):return self.call(8,a=cap[0],b=cap[1],c=cap[2])
  def raw_value(self,op,cap=(0,0,0),digits=b''):
   nonlocal values_count
   raw=bytearray(128);struct.pack_into('<8sQ',raw,0,b'HIAMVU01',op);struct.pack_into('<3Q',raw,24,*cap);struct.pack_into('<Q',raw,72,len(digits));raw=bytes(raw)+digits
   s=C.create_string_buffer(raw);o=C.create_string_buffer(512);rc=vf(s,len(raw),o,len(o),C.addressof(self.w)+64,256);values_count+=1
   assert rc==0 and o.raw[:8]==b'HIAMVUR1' and get(o,8)==0,(op,rc,o.raw[:64].hex())
   return tuple(get(o,i) for i in (16,24,32,40))
  def replace_private_seed(self,where,digits,ledger_at=None):
   # Privileged QA initialization of an unreachable-in-short-tests counter.
   # Values themselves are created/retained/dropped by the actual qualified owner.
   prior=tuple(get(self.w,i) for i in (where,where+8,where+16));fresh=self.raw_value(1,digits=digits)
   struct.pack_into('<4Q',self.w,where,*fresh);self.raw_value(3,prior)
   if ledger_at is not None:
    prior=tuple(get(self.w,i) for i in (ledger_at,ledger_at+8,ledger_at+16));clone=self.raw_value(2,fresh[:3]);struct.pack_into('<4Q',self.w,ledger_at,*clone);self.raw_value(3,prior)
  def finish(self):self.call(11)
 def done(name,**v):rows.append(dict(case=name,**v));print('IDENTITY_PASS',name,flush=True)
 x=Ledger();base=x.call(7,0);epoch=x.call(7,64)
 assert x.value(x.cap(base),1)==b'0' and x.value(x.cap(epoch),1)==b'0'
 x.call(8,a=x.cap(base)[0],b=x.cap(base)[1],c=x.cap(base)[2],want=5)
 g=x.call(1,1);assert x.value(x.cap(g),1)==b'1';kept=x.call(5,1);oldid=get(g,16);assert get(kept,16)==oldid
 ep=x.call(2);assert x.value(x.cap(ep),1)==b'1';eid=get(ep,16);x.call(3);assert get(x.call(7,64),16)==eid
 x.call(9,1,a=1);x.call(6,1);g2=x.call(1,1)
 assert get(g2,16)!=oldid and x.value(x.cap(kept),1)==b'1' and x.value(x.cap(g2),1)==b'2'
 record=x.call(10,0);gen_cap=tuple(get(record,i) for i in (16,24,32));epoch_cap=tuple(get(record,i) for i in (48,56,64))
 assert x.value(gen_cap,1)==b'1' and x.value(epoch_cap,1)==b'1' and get(record,80)==1
 snap=x.w.raw;x.call(11,want=5);assert x.w.raw==snap
 x.drop(x.cap(kept));x.call(6,1);x.finish();done('same-object-retains-event-and-reused-slot',original_identity=oldid,new_identity=get(g2,16),epoch_identity=eid)
 x=Ledger();g=x.call(1,1);e0=x.call(7,64);ep=x.call(2);keep=x.call(5,65);x.call(4)
 assert get(x.call(7,64),16)==get(e0,16) and x.value(x.cap(keep),1)==b'1'
 x.drop(x.cap(keep));x.call(4);x.call(6,1);x.finish();done('aborted-pending-epoch-keeps-previous')
 x=Ledger();g=x.call(1,1)
 for i in range(145):
  x.call(2);x.call(3);x.call(9,1,a=2,b=i,c=1000)
 assert get(x.w,28680)==128 and get(x.w,28672)==17
 for i in range(128):
  r=x.call(10,i);n=get(r,72);cap=tuple(get(r,j) for j in (48,56,64));value=x.value(cap,n)
  expected=i+1 if i>=17 else i+129
  assert value==str(expected).encode() and get(r,80)==2 and get(r,88)==expected-1 and get(r,96)==1000
 x.call(6,1);x.finish();done('full-128-ring-wrap-retains-both-values',events=145,final_head=17)
 for label,nextv,epochv in [('u64',str((1<<64)-1).encode(),str((1<<64)-1).encode()),('u128',str((1<<128)-1).encode(),str((1<<128)-1).encode()),('million',b'9'*1048577,b'9'*1048577)]:
  x=Ledger();x.replace_private_seed(320,nextv);x.replace_private_seed(352,epochv,10240)
  g=x.call(1,1);keep=x.call(5,1);assert x.value(x.cap(g),len(nextv))==nextv
  e=x.call(2);after=(b'1'+b'0'*len(epochv)) if label=='million' else str(int(epochv)+1).encode();assert x.value(x.cap(e),len(after))==after
  x.call(3);x.call(9,1,a=1);x.call(6,1);g2=x.call(1,1);next_after=(b'1'+b'0'*len(nextv)) if label=='million' else str(int(nextv)+1).encode()
  assert x.value(x.cap(g2),len(next_after))==next_after and get(g2,16)!=get(keep,16)
  assert x.value(x.cap(keep),len(nextv))==nextv;x.drop(x.cap(keep));x.call(6,1);x.finish()
  done('unbounded-'+label,input_digits=len(nextv),generation_sha256=sha(nextv),next_sha256=sha(next_after),epoch_sha256=sha(after))
 x=Ledger();errs=[];seen=[];guard=threading.Lock();start=threading.Barrier(8)
 def worker(slot):
  try:
   start.wait()
   for i in range(35):
    r=x.call(1,slot);data=x.value(x.cap(r),get(r,48));held=x.call(5,slot);assert get(held,16)==get(r,16)
    x.call(12);x.call(6,slot);assert x.value(x.cap(held),get(held,48))==data
    x.drop(x.cap(held))
    with guard:seen.append(int(data))
  except BaseException as e:
   with guard:errs.append(repr(e))
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(worker,range(1,9)))
 assert not errs,errs
 assert sorted(seen)==list(range(1,281)),seen
 attempts=x.call(7,66);assert x.value(x.cap(attempts),3)==b'280'
 x.finish();done('eight-thread-reserve-retain-release-accounting',publications=280,attempts=280)
 x=Ledger();snap=x.w.raw
 for cap in [(0,0,0),(NONE,0,0),(1,2,3)]:
  x.call(8,a=cap[0],b=cap[1],c=cap[2],want=1);assert x.w.raw==snap
 for at,val in [(0,0),(8,14),(16,99),(24,1),(48,1),(56,1)]:
  raw=bytearray(frame(7));struct.pack_into('<Q',raw,at,val);s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(4096);C.memset(o,0xa5,4096)
  before=x.w.raw;rc=f(s,len(raw),o,len(o),x.w,len(x.w));assert rc==0xfffffffd and x.w.raw==before and o.raw[:128]==b'\xa5'*128,(at,val,rc)
 x.finish();done('private-foreign-cap-and-frame-refusals')
 report=dict(schema='hepta.hia.multiversion-runtime-identity-qualification.v1',whole_native_runtime=False,passed=len(rows),failed=0,actual_identity_calls=call_count,actual_values_calls=values_count,image_sha256=sha(a.component.read_bytes()),elapsed_ns=time.monotonic_ns()-began,cases=rows)
 (d/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('IDENTITY_QUALIFIED',len(rows),call_count,values_count,flush=True)
if __name__=='__main__':main()
