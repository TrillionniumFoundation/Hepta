"""Test instrumentation targets libc thread calls made by this native image only."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys,time
from tools.qualify_hia_multiversion_background_worker import Worker
from tools.qualify_hia_multiversion_background_queue import Queue,Owner,get
INJECTOR=r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdatomic.h>
static uintptr_t lo,hi;
static _Atomic unsigned long creates,joins;
static _Atomic int create_error,join_error;
void bg_thread_fault_arm(uintptr_t a,uintptr_t b,int c,int j) {
 lo=a;hi=b;atomic_store(&creates,0);atomic_store(&joins,0);
 atomic_store(&create_error,c);atomic_store(&join_error,j);
}
unsigned long bg_thread_fault_count(unsigned long op) {
 return op?atomic_load(&joins):atomic_load(&creates);
}
int pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *p) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc>=lo && pc<hi) {
  atomic_fetch_add(&creates,1);int e=atomic_exchange(&create_error,0);if(e)return e;
 }
 int (*real)(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *)=dlsym(RTLD_NEXT,"pthread_create");
 return real(t,a,f,p);
}
int pthread_join(pthread_t t,void **v) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc>=lo && pc<hi) {
  atomic_fetch_add(&joins,1);int e=atomic_exchange(&join_error,0);if(e)return e;
 }
 int (*real)(pthread_t,void **)=dlsym(RTLD_NEXT,"pthread_join");
 return real(t,v);
}
"""
def child(a):
 values=Owner(a.values);future=C.CDLL(str(a.future));hooks=C.CDLL(None);arm=hooks.bg_thread_fault_arm;arm.argtypes=[C.c_uint64,C.c_uint64,C.c_int,C.c_int];count=hooks.bg_thread_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64;rows=[]
 def make():
  q=Queue(a.queue,values,future);w=Worker(a.image,q,lambda w,r:0)
  maps=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(a.image) in x]
  return q,w,min(int(x,16) for x,y in maps),max(int(y,16) for x,y in maps)
 for errno in (11,12,22):
  q,w,lo,hi=make();arm(lo,hi,errno,0);r=w.run(1,want=6)
  assert get(r,16)==errno and get(r,24)==5 and get(r,32)==0 and count(0)==1 and count(1)==0
  w.run(1,want=4);w.run(2,want=4);w.run(5);q.destroy();rows.append({'case':'pthread-create-failure','errno':errno,'calls':1,'worker_never_bound':True})
 for errno in (3,22,35):
  q,w,lo,hi=make();arm(lo,hi,0,0);q.run(4);w.run(1)
  limit=time.monotonic()+5
  while get(w.run(3),24)!=3:assert time.monotonic()<limit;time.sleep(.001)
  arm(lo,hi,0,errno);r=w.run(2,want=6)
  assert get(r,16)==errno and get(r,24)==3 and get(r,48)==0 and count(1)==1
  r=w.run(2);assert get(r,24)==4 and count(1)==2
  w.run(2);assert count(1)==2;w.run(5);q.destroy();rows.append({'case':'pthread-join-failure-then-same-owner-retry','errno':errno,'calls':2})
 values.run(9);print(json.dumps({'passed':len(rows),'failed':0,'cases':rows}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--queue',type=Path,required=True);p.add_argument('--values',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args()
 if a.child:return child(a)
 D=a.directory;source=D/'pthread-fault-injector.c';source.write_text(INJECTOR);image=D/'pthread-fault-injector.so'
 subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(image),str(source),'-ldl'],check=True,capture_output=True)
 args=[sys.executable,'-u','-m','tools.qualify_hia_multiversion_background_worker_faults',*sys.argv[1:],'--child'];r=subprocess.run(args,env={**os.environ,'LD_PRELOAD':str(image)},capture_output=True,timeout=30)
 (D/'pthread-fault-child.stdout').write_bytes(r.stdout);(D/'pthread-fault-child.stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
 result=json.loads(r.stdout);result.update(schema='hepta.hia.background-native-worker.pthread-faults.v1',whole_background_qualified=False,external_instrumentation_only=True,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),injector_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
 (D/'pthread-fault-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('BG_PTHREAD_FAULT_PASS',result['passed'],flush=True)
if __name__=='__main__':main()
