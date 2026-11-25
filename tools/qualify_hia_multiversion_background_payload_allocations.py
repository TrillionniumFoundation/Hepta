"""External malloc failure controls on the actual native payload call sites."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
INJECTOR = '\n#include <stdint.h>\n#include <stddef.h>\nextern void *__libc_malloc(size_t);\nextern void __libc_free(void *);\nstatic uintptr_t lo,hi;\nstatic unsigned long fail_after,attempts,allocs,frees;\nvoid values_fault_arm(uintptr_t low,uintptr_t high,unsigned long fail) {\n lo=low;hi=high;fail_after=fail;attempts=allocs=frees=0;\n}\nunsigned long values_fault_count(unsigned long selector) {\n return selector==0?attempts:selector==1?allocs:frees;\n}\nvoid *malloc(size_t n) {\n uintptr_t pc=(uintptr_t)__builtin_return_address(0);\n if(pc>=lo && pc<hi) {\n  attempts++;if(attempts==fail_after)return 0;\n  void *p=__libc_malloc(n);if(p)allocs++;return p;\n }\n return __libc_malloc(n);\n}\nvoid free(void *p) {\n uintptr_t pc=(uintptr_t)__builtin_return_address(0);\n if(p && pc>=lo && pc<hi)frees++;\n __libc_free(p);\n}\n'
from tools.qualify_hia_multiversion_background_payload import Owner,get
def child(D):
 product=D/'payload-component.so';q=Owner(product);hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 mappings=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(product) in x];lo=min(int(x,16) for x,y in mappings);hi=max(int(y,16) for x,y in mappings);counts=lambda:[count(i) for i in range(3)];rows=[]
 for op,raw,nth in [(1,b'',1),(1,b'',2),(1,b'opaque\0\xff',1),(1,b'opaque\0\xff',2),(2,b'',1)]:
  arm(lo,hi,0);original=q.create(b'prior-result');old=q.w.raw
  arm(lo,hi,nth)
  q.run(op,original if op==2 else (0,0,0),raw=raw,want=4)
  actual=counts();assert actual==[nth,nth-1,nth-1],(op,nth,actual)
  assert q.w.raw==old and q.copy(original,0,12)==b'prior-result'
  arm(lo,hi,0);retry=q.create(raw) if op==1 else q.retain(original);q.drop(retry);q.drop(original)
  assert get(q.w.raw,16)==0
  rows.append({'operation':op,'empty_payload':not raw,'failed_allocation':nth,'actual_counts':actual,'original_owner_unchanged':True,'same_owner_retry':True})
 arm(lo,hi,0);cap=q.create(b'owned');caps=[cap]+[q.retain(cap) for _ in range(1000)]
 assert counts()==[1002,1002,0],counts()
 for cap in caps:q.drop(cap)
 assert counts()==[1002,1002,1002] and get(q.w.raw,16)==0,counts()
 rows.append({'name':'1001-distinct-reference-nodes-and-one-object','counts':counts()})
 q.run(5);print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'image_sha256':hashlib.sha256(product.read_bytes()).hexdigest()}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
 if a.child:return child(D)
 source=D/'payload-allocation-injector.c';source.write_text(INJECTOR);image=D/'payload-allocation-injector.so'
 subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(source)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_multiversion_background_payload_allocations','--directory',str(D),'--child'],env={**os.environ,'LD_PRELOAD':str(image)},capture_output=True,timeout=45)
 (D/'allocation-child.stdout').write_bytes(r.stdout);(D/'allocation-child.stderr').write_bytes(r.stderr)
 assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
 result=json.loads(r.stdout);result.update(schema='hepta.hia.background-owned-payload.allocations.v1',whole_background_qualified=False,external_injector_only=True,injector_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
 (D/'allocation-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('BG_PAYLOAD_ALLOCATION_PASS',result['passed'],flush=True)
if __name__=='__main__':main()
