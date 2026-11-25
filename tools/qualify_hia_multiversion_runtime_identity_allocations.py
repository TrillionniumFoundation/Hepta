"""Actual libc allocation faults in the fixed HIA identity ledger image."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys,struct
from tools.qualify_hia_multiversion_values_allocations import INJECTOR
get=lambda b,a:struct.unpack_from('<Q',b,a)[0]
def child(D,image):
 lib=C.CDLL(str(image));fn=lib.hia_mv_runtime_identity;fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
 h=C.CDLL(None);arm=h.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=h.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 maps=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(image) in x];lo=min(int(a,16) for a,b in maps);hi=max(int(b,16) for a,b in maps)
 rows=[]
 class Ledger:
  def __init__(self):self.w=C.create_string_buffer(32768)
  def call(self,op,selector=0,a=0,b=0,c=0,want=0):
   raw=struct.pack('<8s7Q',b'HIAMVID1',op,selector,a,b,c,0,0);s=C.create_string_buffer(raw);o=C.create_string_buffer(4096);rc=fn(s,len(raw),o,len(o),self.w,len(self.w))
   assert rc==0 and o.raw[:8]==b'HIAMVIDR' and get(o,8)==want,(op,selector,rc,get(o,8),want)
   return o.raw
  def digits(self,selector):
   r=self.call(7,selector);c=[get(r,i) for i in (24,32,40)];o=self.call(13,a=c[0],b=c[1],c=c[2]);return o[1536:1536+get(o,48)]
 for nth in range(1,13):
  q=Ledger();arm(lo,hi,nth);q.call(0,want=4);actual=[count(i) for i in range(3)]
  assert actual==[nth,nth-1,nth-1],(nth,actual)
  assert get(q.w,80)==0 and get(q.w,30016)==1,(nth,get(q.w,80),get(q.w,30016))
  q.call(11);q.call(7,want=5)
  rows.append(dict(operation='initialize',failed_ordinal=nth,actual_counts=actual,all_allocations_freed=True))
 for op,attempts in [(1,4),(2,4),(5,1),(9,2),(12,3)]:
  for nth in range(1,attempts+1):
   q=Ledger();arm(lo,hi,0);q.call(0)
   if op==9:q.call(1,1);q.call(9,1,a=3,b=5,c=7)
   before=q.w.raw;arm(lo,hi,nth);q.call(op,1 if op in (1,9) else 64 if op==5 else 0,want=4);actual=[count(i) for i in range(3)]
   assert actual==[nth,nth-1,nth-1],(op,nth,actual)
   if not (op==1 and nth==4):assert q.w.raw==before,(op,nth)
   else:assert get(q.w,544)==0 and get(q.w,8224)==0
   arm(lo,hi,0)
   if op==1:
    q.call(1,1);assert q.digits(1)==(b'2' if nth==4 else b'1');q.call(6,1)
   elif op==2:q.call(2);q.call(3);assert q.digits(64)==b'1'
   elif op==5:
    r=q.call(5,64);q.call(8,a=get(r,24),b=get(r,32),c=get(r,40))
   elif op==9:
    old=q.call(10,0);assert get(old,80)==3 and get(old,88)==5 and get(old,96)==7
    q.call(9,1,a=8);q.call(6,1)
   else:q.call(12);assert q.digits(66)==b'1'
   q.call(11)
   rows.append(dict(operation=op,failed_ordinal=nth,actual_counts=actual,transaction_unchanged=not(op==1 and nth==4),consumed_generation_preserved=(op==1 and nth==4),same_context_retry=True))
 arm(lo,hi,0);q=Ledger();q.call(0)
 for i in range(160):
  q.call(1,1);q.call(2);q.call(3);q.call(9,1,a=1);q.call(12);q.call(6,1)
 q.call(11);actual=[count(i) for i in range(3)];assert actual[0]==actual[1]==actual[2],actual
 rows.append(dict(operation='160-publication-event-wrap-transactions-complete-free',actual_counts=actual))
 print(json.dumps(dict(passed=len(rows),failed=0,cases=rows,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest())),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--component',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
 if a.child:return child(D,a.component)
 D.mkdir(parents=True,exist_ok=False);src=D/'allocation-injector.c';src.write_text(INJECTOR);so=D/'allocation-injector.so'
 subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(so),str(src)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_multiversion_runtime_identity_allocations','--directory',str(D),'--component',str(a.component),'--child'],env={**os.environ,'LD_PRELOAD':str(so)},capture_output=True,timeout=40)
 (D/'allocation.stdout').write_bytes(r.stdout);(D/'allocation.stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
 value=json.loads(r.stdout);report=dict(schema='hepta.hia.multiversion-runtime-identity-allocation.v1',whole_native_runtime=False,external_qa_injector=True,injector_source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),**value)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('IDENTITY_ALLOCATION_PASS',value['passed'],flush=True)
if __name__=='__main__':main()
