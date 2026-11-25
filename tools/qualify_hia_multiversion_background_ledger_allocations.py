"""Fail actual fixed decimal/payload allocation sites in native ledger operations."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
from tools.qualify_hia_multiversion_background_payload_allocations import INJECTOR
from tools.qualify_hia_multiversion_background_jobs import Jobs,get
from tools.qualify_hia_multiversion_values import Owner as Values
from tools.qualify_hia_multiversion_background_ledger import Ledger
def child(a):
 D=a.directory;q=Jobs(a.jobs,a.future,a.payload);v=Values(a.values);rows=[]
 hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 def region(path):
  m=[line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines() if str(path) in line]
  return min(int(x,16) for x,y in m),max(int(y,16) for x,y in m)
 lo,hi=region(a.values);plo,phi=region(a.payload);counts=lambda:[count(i) for i in range(3)]
 arm(lo,hi,0);l=Ledger(D/'ledger-component.so',q,v);init_allocs=count(0);l.destroy()
 assert get(v.w.raw,16)==0
 for nth in range(1,init_allocs+1):
  l=Ledger(D/'ledger-component.so',q,v,poison=True,auto_init=False);before=v.w.raw
  arm(lo,hi,nth);l.initialize(want=4);seen=counts()
  assert seen==[nth,nth-1,nth-1] and l.w.raw==bytes(4096) and v.w.raw==before,(nth,seen)
  arm(lo,hi,0);l.initialize();l.destroy();assert get(v.w.raw,16)==0
  rows.append({'case':'initialize','failed_allocation':nth,'counts':seen,'retry_same_context':True})
 l=Ledger(D/'ledger-component.so',q,v);job=q.create(b'baseline');receipt=q.payload.create(b'baseline');cost=v.create(b'7')
 arm(lo,hi,0);r=l.run(1,job,receipt,cost,0);assert get(r,40)==1
 settle_allocs=count(0);q.drop(job);v.drop(cost)
 for nth in range(1,settle_allocs+1):
  job=q.create(b'failure');receipt=q.payload.create(b'failure');cost=v.create(b'9999999999999999999999999');before=l.snapshot();saved=l.w.raw
  arm(lo,hi,nth);r=l.run(1,job,receipt,cost,1,want=4);seen=counts()
  assert seen==[nth,nth-1,nth-1] and get(r,40)==0 and l.w.raw==saved,(nth,seen)
  arm(lo,hi,0);assert get(l.run(4,job),48)==0 and l.snapshot()==before
  assert q.payload.copy(receipt,0,7)==b'failure'
  r=l.run(1,job,receipt,cost,1);assert get(r,40)==1 and get(l.run(4,job),48)==1
  q.drop(job);v.drop(cost)
  rows.append({'case':'settle','failed_allocation':nth,'counts':seen,'counter_and_marker_unchanged_on_failure':True,'same_job_retry':True})
 # Snapshot value refs and payload refs are all unpublished on failure.
 saved=l.w.raw;before=l.snapshot()
 for nth in range(1,9):
  oldv=v.w.raw;oldp=q.payload.w.raw
  arm(lo,hi,nth);r=l.run(2,want=4);seen=counts()
  assert seen==[nth,nth-1,nth-1] and get(r,32)==0,(nth,seen)
  assert l.w.raw==saved and v.w.raw==oldv and q.payload.w.raw==oldp
  arm(lo,hi,0);assert l.snapshot()==before
  rows.append({'case':'snapshot-decimal','failed_allocation':nth,'counts':seen,'all_unpublished_refs_released':True})
 count_receipts=len(before['recent'])
 for nth in range(1,count_receipts+1):
  oldv=v.w.raw;oldp=q.payload.w.raw
  arm(plo,phi,nth);r=l.run(2,want=4);seen=counts()
  assert seen==[nth,nth-1,nth-1] and get(r,32)==0,(nth,seen)
  assert l.w.raw==saved and v.w.raw==oldv and q.payload.w.raw==oldp
  arm(plo,phi,0);assert l.snapshot()==before
  rows.append({'case':'snapshot-receipt','failed_allocation':nth,'counts':seen,'all_decimal_and_payload_clones_released':True})
 arm(lo,hi,0);l.destroy();assert get(v.w.raw,16)==0 and get(q.payload.w.raw,16)==0
 q.destroy();v.run(9)
 print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'actual_initialize_allocation_sites':init_allocs,'actual_settle_allocation_sites':settle_allocs,'image_sha256':hashlib.sha256((D/'ledger-component.so').read_bytes()).hexdigest()}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--jobs',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--payload',type=Path,required=True);p.add_argument('--values',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
 if a.child:return child(a)
 src=D/'ledger-allocation-injector.c';src.write_text(INJECTOR);image=D/'ledger-allocation-injector.so'
 subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(src)],check=True,capture_output=True)
 args=[sys.executable,'-u','-m','tools.qualify_hia_multiversion_background_ledger_allocations','--directory',str(D),'--jobs',str(a.jobs),'--future',str(a.future),'--payload',str(a.payload),'--values',str(a.values),'--child']
 r=subprocess.run(args,env={**os.environ,'LD_PRELOAD':str(image)},capture_output=True,timeout=60)
 (D/'allocation-child.stdout').write_bytes(r.stdout);(D/'allocation-child.stderr').write_bytes(r.stderr)
 assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
 result=json.loads(r.stdout);result.update(schema='hepta.hia.background-native-ledger.allocations.v1',whole_background_qualified=False,external_injector_only=True,injector_source_sha256=hashlib.sha256(src.read_bytes()).hexdigest())
 (D/'allocation-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('BG_LEDGER_ALLOCATION_PASS',result['passed'],flush=True)
if __name__=='__main__':main()
