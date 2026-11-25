"""Actual malloc/free failures restricted to the native value owner call sites."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
from tools.qualify_hia_multiversion_values import Owner,get
INJECTOR=r'''
#include <stdint.h>
#include <stddef.h>
extern void *__libc_malloc(size_t);
extern void __libc_free(void *);
static uintptr_t lo,hi;
static unsigned long fail_after,attempts,allocs,frees;
void values_fault_arm(uintptr_t low,uintptr_t high,unsigned long fail) {
 lo=low;hi=high;fail_after=fail;attempts=allocs=frees=0;
}
unsigned long values_fault_count(unsigned long selector) {
 return selector==0?attempts:selector==1?allocs:frees;
}
void *malloc(size_t n) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc>=lo && pc<hi) {
  attempts++;if(attempts==fail_after)return 0;
  void *p=__libc_malloc(n);if(p)allocs++;return p;
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
    product=D/'values-component.so';q=Owner(product);hooks=C.CDLL(None)
    arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3
    count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
    maps=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(product) in x]
    lo=min(int(a,16) for a,b in maps);hi=max(int(b,16) for a,b in maps)
    counts=lambda:[count(i) for i in range(3)]
    rows=[]
    for op,max_attempts in [(1,3),(2,1),(4,3),(5,3),(6,3),(7,2)]:
        for nth in range(1,max_attempts+1):
            arm(lo,hi,0)
            a=q.create(b'340282366920938463463374607431768211456');b=q.create(b'7')
            old_head=get(q.w.raw,16)
            arm(lo,hi,nth)
            if op==1:q.run(1,raw=b'18446744073709551616',want=4)
            elif op==2:q.run(2,a,want=4)
            elif op==4:q.run(4,a,want=4)
            else:q.run(op,a,b,want=4)
            observed=counts();assert observed==[nth,nth-1,nth-1],(op,nth,observed)
            assert get(q.w.raw,16)==old_head and get(q.w.raw,32)==0
            assert q.copy(a,39)==b'340282366920938463463374607431768211456' and q.copy(b,1)==b'7'
            arm(lo,hi,0)
            if op==1:r=q.create(b'18446744073709551616')
            elif op==2:r=q.clone(a)
            else:
                r,n,_=q.value(op,a,b if op in (5,6,7) else (0,0,0))
            if op!=7:q.drop(r)
            q.drop(a);q.drop(b)
            assert get(q.w.raw,16)==0 and get(q.w.raw,32)==0
            rows.append({'op':op,'failed_ordinal':nth,'actual_attempts':observed[0],'actual_allocations':observed[1],'actual_frees':observed[2],'same_owner_retry':True,'original_values_preserved':True})
    arm(lo,hi,0)
    a=q.create(b'9'*1024);caps=[a]
    for _ in range(1000):caps.append(q.clone(a))
    assert counts()==[1003,1003,1],counts()
    for c in caps:q.drop(c)
    assert counts()==[1003,1003,1003] and get(q.w.raw,16)==0,counts()
    q.run(9)
    rows.append({'case':'1001-strong-reference-nodes-exactly-once-free','actual_allocations':1003,'actual_frees':1003})
    print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'image_sha256':hashlib.sha256(product.read_bytes()).hexdigest()}),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
    if a.child:return child(D)
    source=D/'value-allocation-injector.c';source.write_text(INJECTOR);image=D/'value-allocation-injector.so'
    subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(source)],check=True,capture_output=True)
    r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_multiversion_values_allocations','--directory',str(D),'--child'],env={**os.environ,'LD_PRELOAD':str(image)},capture_output=True,timeout=30)
    (D/'allocation-child.stdout').write_bytes(r.stdout);(D/'allocation-child.stderr').write_bytes(r.stderr)
    assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
    data=json.loads(r.stdout);report={'schema':'hepta.hia.multiversion-values-allocation-qualification.v1','whole_native_runtime':False,'external_injector_only':True,'scope':'Actual malloc/free call sites in the current native owner; existing Python allocations are excluded by instruction address.','injector_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'injector_image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),**data}
    (D/'allocation-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('VALUE_ALLOCATION_PASS',data['passed'],flush=True)
if __name__=='__main__':main()
