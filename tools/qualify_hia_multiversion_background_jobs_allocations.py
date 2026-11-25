"""Actual Job malloc/free failure sites; external injector does not implement ownership."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
from tools.qualify_hia_multiversion_background_payload_allocations import INJECTOR
from tools.qualify_hia_multiversion_background_jobs import Jobs,get
def child(a):
 D=a.directory;product=D/'jobs-component.so';q=Jobs(product,a.future,a.payload)
 hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 def region(path):
  rows=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(path) in x]
  return min(int(x,16) for x,y in rows),max(int(y,16) for x,y in rows)
 lo,hi=region(product);counts=lambda:[count(i) for i in range(3)];rows=[]
 for op,raw,nth in [(1,b'',1),(1,b'',2),(1,b'opaque\0\xff',1),(1,b'opaque\0\xff',2),(2,b'',1)]:
  arm(lo,hi,0);original=q.create(b'prior-job');old=q.w.raw
  arm(lo,hi,nth);q.run(op,original if op==2 else (0,0,0),raw=raw,want=4)
  actual=counts();assert actual==[nth,nth-1,nth-1],(op,nth,actual)
  assert q.w.raw==old and q.copy(original,0,9)==b'prior-job'
  arm(lo,hi,0);retry=q.create(raw) if op==1 else q.retain(original);q.drop(retry);q.drop(original)
  assert get(q.w.raw,16)==0 and get(q.w.raw,40)==0
  rows.append({'operation':op,'empty_input':not raw,'failed_allocation':nth,'actual_counts':actual,'original_owner_unchanged':True,'same_owner_retry':True})
 arm(lo,hi,0);cap=q.create(b'owned');caps=[cap]+[q.retain(cap) for _ in range(1000)]
 assert counts()==[1002,1002,0],counts()
 for cap in caps:q.drop(cap)
 assert counts()==[1002,1002,1002] and get(q.w.raw,16)==0 and get(q.w.raw,40)==0,counts()
 rows.append({'name':'1001-distinct-job-reference-nodes-and-one-job-future-object','counts':counts()})
 # Payload clone failure during a job-field read must not transfer or mutate the slot.
 plo,phi=region(a.payload);cap=q.create(b'holder');value=q.payload.create(b'value');q.set(cap,0,value);old=q.w.raw
 arm(plo,phi,1);r=q.run(8,cap,slot=0,want=4)
 assert counts()==[1,0,0] and get(r,16)==0 and q.w.raw==old,counts()
 arm(plo,phi,0);read=q.field(cap,0);assert q.payload.copy(read,0,5)==b'value';q.payload.drop(read);q.drop(cap)
 assert counts()==[1,1,3],counts()
 rows.append({'name':'payload-field-clone-allocation-failure-and-same-job-retry','actual_counts':[1,0,0],'post_retry_counts':counts()})
 q.destroy();print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'image_sha256':hashlib.sha256(product.read_bytes()).hexdigest()}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--payload',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
 if a.child:return child(a)
 source=D/'jobs-allocation-injector.c';source.write_text(INJECTOR);image=D/'jobs-allocation-injector.so'
 subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(source)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_multiversion_background_jobs_allocations','--directory',str(D),'--future',str(a.future),'--payload',str(a.payload),'--child'],env={**os.environ,'LD_PRELOAD':str(image)},capture_output=True,timeout=45)
 (D/'allocation-child.stdout').write_bytes(r.stdout);(D/'allocation-child.stderr').write_bytes(r.stderr)
 assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
 result=json.loads(r.stdout);result.update(schema='hepta.hia.background-native-jobs.allocations.v1',whole_background_qualified=False,external_injector_only=True,injector_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
 (D/'allocation-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('BG_JOBS_ALLOCATION_PASS',result['passed'],flush=True)
if __name__=='__main__':main()
