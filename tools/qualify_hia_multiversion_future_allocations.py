"""External fault injector for actual private Future malloc/free operations."""
from pathlib import Path
import argparse,ctypes,json,os,subprocess,sys
from tools.qualify_hia_multiversion_future import Native,CB,address
from tools.qualify_hia_multiversion_components import get,sha
INJECTOR=r'''
#include <stdint.h>
#include <stddef.h>
extern void *__libc_malloc(size_t);
extern void __libc_free(void *);
static uintptr_t lo,hi;
static unsigned long fail_after,attempts,allocs,frees;
void future_fault_arm(uintptr_t low, uintptr_t high, unsigned long fail) {
 lo=low; hi=high; fail_after=fail; attempts=allocs=frees=0;
}
unsigned long future_fault_count(unsigned long selector) { return selector==0?attempts:selector==1?allocs:frees; }
void *malloc(size_t n) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc>=lo && pc<hi && n==64) {
  attempts++;
  if(attempts==fail_after)return 0;
  void *p=__libc_malloc(n); if(p)allocs++; return p;
 }
 return __libc_malloc(n);
}
void free(void *p) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(p && pc>=lo && pc<hi)frees++;
 __libc_free(p);
}
'''
def child(D):
    product=D/'future-component.so';lib=ctypes.CDLL(str(product));hooks=ctypes.CDLL(None)
    arm=hooks.future_fault_arm;arm.argtypes=[ctypes.c_uint64]*3
    count=hooks.future_fault_count;count.argtypes=[ctypes.c_uint64];count.restype=ctypes.c_uint64
    maps=[line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines() if str(product) in line]
    lo=min(int(a,16) for a,b in maps);hi=max(int(b,16) for a,b in maps)
    rows=[]
    for nth in (1,2,8):
        q=Native(lib);arm(lo,hi,nth);events=[]
        for i in range(1,nth):q.add(lambda f,i=i:events.append(i))
        q.next+=1;number=q.next
        @CB
        def callback(owner,arg):events.append('must-not-run');return 0
        q.live[number]=callback
        rc,v=q.invoke(4,address(callback),number,address(q.drop),number)
        assert rc==5 and v[5]==nth-1 and q.drop_counts[number]==1 and number not in q.live
        assert get(q.work,72)==0 and get(q.work,128)==0 and get(q.work,16)==0
        assert [count(i) for i in range(3)]==[nth,nth-1,0]
        # The same owner admits a subsequent real allocation and completion.
        q.add(lambda f:events.append('retry'));q.complete(42)
        assert events==list(range(1,nth))+['retry']
        q.destroy();assert [count(i) for i in range(3)]==[nth+1,nth,nth]
        assert q.invoke(10)[0]==65 and count(2)==nth
        rows.append({'failed_allocation_ordinal':nth,'attempts':nth+1,'actual_allocations':nth,'actual_frees':nth,'failed_transferred_closure_dropped_once':True,'same_owner_retry':True})
    print(json.dumps({'cases':rows,'image_sha256':sha(product.read_bytes())}),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
    if a.child:return child(D)
    source=D/'future-allocation-injector.c';source.write_text(INJECTOR);image=D/'future-allocation-injector.so'
    subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(source)],check=True,capture_output=True)
    r=subprocess.run([sys.executable,'-u','-m',__name__ if __name__!='__main__' else 'tools.qualify_hia_multiversion_future_allocations','--directory',str(D),'--child'],env=dict(os.environ,LD_PRELOAD=str(image)),capture_output=True,timeout=20)
    (D/'allocation-child.stdout').write_bytes(r.stdout);(D/'allocation-child.stderr').write_bytes(r.stderr)
    assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'))
    result=json.loads(r.stdout);report={'schema':'hepta.hia.native-future-allocation-faults.v1','passed':len(result['cases']),'failed':0,'whole_native_runtime':False,'external_fault_injector_only':True,'fault_scope':'real malloc(64) call sites inside actual HIA Future image, never returned public business facts','injector_source_sha256':sha(source.read_bytes()),'injector_image_sha256':sha(image.read_bytes()),**result}
    (D/'allocation-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('FUTURE_ALLOCATION_PASS',report['passed'],flush=True)
if __name__=='__main__':main()
