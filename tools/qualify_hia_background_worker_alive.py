"""Widen the actual native pthread return window; no business-policy replacement."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,subprocess,sys,threading,time
from tools.qualify_hia_multiversion_background_worker import Worker
from tools.qualify_hia_multiversion_background_queue import Queue,Owner,get
INJECTOR=r'''
#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
static uintptr_t lo,hi;
static _Atomic int gate,waiting,join_error;
static _Atomic unsigned long joins;
struct launch {void *(*fn)(void *);void *arg;};
void bg_alive_arm(uintptr_t a,uintptr_t b,int hold) {lo=a;hi=b;atomic_store(&gate,hold);atomic_store(&waiting,0);atomic_store(&joins,0);atomic_store(&join_error,0);}
void bg_alive_release(void) {atomic_store(&gate,0);}
void bg_alive_join_error(int e) {atomic_store(&join_error,e);}
unsigned long bg_alive_read(unsigned long op) {return op?atomic_load(&joins):(unsigned long)atomic_load(&waiting);}
static void *launch(void *p) {
 struct launch v=*(struct launch *)p;free(p);void *r=v.fn(v.arg);
 atomic_store(&waiting,1);while(atomic_load(&gate))usleep(100);return r;
}
int pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *p) {
 int (*real)(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *)=dlsym(RTLD_NEXT,"pthread_create");
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc<lo || pc>=hi)return real(t,a,f,p);
 struct launch *v=malloc(sizeof *v);if(!v)return 12;v->fn=f;v->arg=p;
 int rc=real(t,a,launch,v);if(rc)free(v);return rc;
}
int pthread_join(pthread_t t,void **v) {
 uintptr_t pc=(uintptr_t)__builtin_return_address(0);
 if(pc>=lo && pc<hi){atomic_fetch_add(&joins,1);int e=atomic_exchange(&join_error,0);if(e)return e;}
 int (*real)(pthread_t,void **)=dlsym(RTLD_NEXT,"pthread_join");return real(t,v);
}
'''
def child(a):
 values=Owner(a.values);future=C.CDLL(str(a.future));hooks=C.CDLL(None)
 arm=hooks.bg_alive_arm;arm.argtypes=[C.c_uint64,C.c_uint64,C.c_int]
 read=hooks.bg_alive_read;read.argtypes=[C.c_uint64];read.restype=C.c_uint64
 release=hooks.bg_alive_release;seterr=hooks.bg_alive_join_error;seterr.argtypes=[C.c_int]
 rows=[];workers=[]
 def query(w,want=0):return w.run(3,wire=b'HIABGW03'+w.packet(3)[8:],want=want)
 def make(handler=None,hold=1):
  q=Queue(a.queue,values,future);w=Worker(a.image,q,handler or (lambda w,r:0));workers.append(w)
  maps=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(a.image) in x]
  arm(min(int(x,16) for x,y in maps),max(int(y,16) for x,y in maps),hold);return q,w
 def wait(fn):
  until=time.monotonic()+8
  while not fn():assert time.monotonic()<until,'actual thread gate timeout';time.sleep(.0005)
 def done(q,w):w.run(5);q.destroy();assert get(values.w.raw,16)==0
 def row(name,detail):rows.append({'name':name,'passed':True,'detail':detail})
 q,w=make();assert get(query(w),24)==0;q.run(4);w.run(1);wait(lambda:read(0)==1)
 assert get(w.run(3),24)==3 and read(1)==0
 replies=[];errors=[]
 def call(op):
  try:replies.append(query(w) if op==3 else w.run(2))
  except BaseException as e:errors.append(repr(e))
 ts=[threading.Thread(target=call,args=(3 if i<12 else 2,)) for i in range(18)]
 for t in ts:t.start()
 wait(lambda:read(1)==1);time.sleep(.03);assert not replies and not errors
 release()
 for t in ts:t.join(8);assert not t.is_alive()
 assert len(replies)==18 and all(get(r,24)==4 for r in replies) and read(1)==1 and not errors
 for _ in range(10):assert get(query(w),24)==4
 assert read(1)==1;done(q,w);row('announced-exit-waits-for-real-thread-return-once',{'observers':12,'joiners':6,'actual_join_calls':1,'legacy_query_observed_announced_state':3})
 entered=threading.Event();proceed=threading.Event();own=[]
 def handler(w,r):
  own.append(get(query(w),24));entered.set();assert proceed.wait(8);owned=w.settle(r);j['future'].complete(7);q.release_refs(owned);return 0
 q,w=make(handler,hold=0);j=q.job(7);q.admit(j);w.run(1);assert entered.wait(5);q.run(4);result=[]
 joiner=threading.Thread(target=lambda:result.append(w.run(2)));joiner.start();wait(lambda:read(1)==1)
 start=time.monotonic();r=query(w);elapsed=time.monotonic()-start;assert get(r,24)==2 and elapsed<1 and not result and own==[2]
 proceed.set();joiner.join(8);assert not joiner.is_alive() and get(result[0],24)==4 and read(1)==1
 assert j['future'].result()==7;j['future'].destroy();done(q,w);row('live-thread-query-does-not-wait-for-another-joiner',{'native_self_query':2,'external_query':2,'join_calls':1})
 for errno in (3,22,35):
  q,w=make(hold=0);q.run(4);w.run(1);wait(lambda:read(0)==1);seterr(errno);r=query(w,want=6)
  assert get(r,16)==errno and get(r,24)==3 and get(r,48)==0 and read(1)==1
  assert get(query(w),24)==4 and read(1)==2;assert get(query(w),24)==4 and read(1)==2;done(q,w)
 row('announced-exit-join-errors-retain-same-owner-for-retry',{'errnos':[3,22,35],'joins_each':2})
 q,w=make(hold=0);controls=0
 for op in (0,1,2,4,5,6):
  raw=b'HIABGW03'+w.packet(op)[8:];before=w.w.raw;w.run(op,wire=raw,want=0xfffffffd);assert w.w.raw==before;controls+=1
 for at in range(16,128,8):
  raw=b'HIABGW03'+w.packet(3,{at:1})[8:];before=w.w.raw;w.run(3,wire=raw,want=0xfffffffd);assert w.w.raw==before;controls+=1
 for raw in (b'HIABGW03',b'HIABGW03'+w.packet(3)[8:127],b'HIABGW03'+w.packet(3)[8:]+b'x'):
  before=w.w.raw;w.run(3,wire=raw,want=0xfffffffd);assert w.w.raw==before;controls+=1
 q.run(4);w.run(1);wait(lambda:read(0)==1);pid=os.fork()
 if pid==0:
  try:query(w,want=65);os._exit(0)
  except BaseException:os._exit(71)
 _,status=os.waitpid(pid,0);assert status==0 and read(1)==0
 assert get(query(w),24)==4;done(q,w);row('new-private-profile-keeps-old-domain-and-owner-isolation',{'private_guards':controls,'fork_without_join':True})
 values.run(9)
 print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'actual_worker_calls':sum(w.calls for w in workers),'all_threads_reaped':True}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--queue',type=Path,required=True);p.add_argument('--values',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args()
 if a.child:return child(a)
 a.directory.mkdir(parents=True,exist_ok=True);src=a.directory/'thread-exit-window.c';src.write_text(INJECTOR);so=a.directory/'thread-exit-window.so'
 subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-o',str(so),str(src),'-ldl'],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_background_worker_alive',*sys.argv[1:],'--child'],env={**os.environ,'LD_PRELOAD':str(so)},capture_output=True,timeout=60)
 (a.directory/'child.stdout').write_bytes(r.stdout);(a.directory/'child.stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
 report=json.loads(r.stdout);report.update(schema='hia.background-native-worker-exit-observation.v1',whole_background_qualified=False,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),external_thread_window_only=True,injector_source_sha256=hashlib.sha256(src.read_bytes()).hexdigest())
 (a.directory/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('WORKER_ALIVE_PASS',report['passed'],report['actual_worker_calls'],flush=True)
if __name__=='__main__':main()
