"""Native FIFO/ownership/thread kernel gates; not a complete BackgroundOptimizer."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,sys,threading,time
from tools.qualify_hia_multiversion_values import Owner
from tools.qualify_hia_multiversion_future import Native
U64=(1<<64)-1
get=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
REF=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)

class Queue:
    def __init__(self,image,values,future,max_pending=8,poison=False):
        self.values=values;self.future_lib=future;self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_background_queue
        self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.w=C.create_string_buffer(4096);self.calls=0;self.mutex=threading.Lock();self.errors=[];self.clones=0;self.drops=0;self.fail_clone=0
        if poison:C.memset(self.w,0xa5,4096);C.memset(self.w,0,8)
        @REF
        def ref(src,n,out,on,ctx,cn):
            try:
                assert n==64 and on==128 and ctx==C.addressof(values.w) and cn==len(values.w)
                raw=C.string_at(src,n);assert raw[:8]==b'HIABJRF1' and raw[40:]==b'\0'*24
                op=get(raw,8);cap=struct.unpack_from('<3Q',raw,16);result=bytearray(128);result[:8]=b'HIABJRO1'
                if op==1:
                    self.clones+=1
                    if self.fail_clone and self.clones==self.fail_clone:struct.pack_into('<Q',result,8,4)
                    else:struct.pack_into('<3Q',result,16,*values.clone(cap))
                elif op==2:values.drop(cap);self.drops+=1
                else:raise AssertionError(op)
                C.memmove(out,bytes(result),128);return 0
            except BaseException as e:self.errors.append(repr(e));return 65
        self.ref=ref
        self.run(0,fields={16:max_pending,64:C.cast(ref,C.c_void_p).value,80:C.addressof(values.w),88:len(values.w)})
    @staticmethod
    def packet(op,fields=None):
        x=bytearray(128);x[:8]=b'HIABGQ01';struct.pack_into('<Q',x,8,op)
        for at,value in (fields or {}).items():struct.pack_into('<Q',x,at,value)
        return bytes(x)
    def run(self,op,fields=None,want=0,raw=None,on=4096,wn=4096):
        raw=self.packet(op,fields) if raw is None else raw
        s=C.create_string_buffer(raw);o=C.create_string_buffer(max(on,4096));C.memset(o,0xa5,len(o))
        rc=self.f(s,len(raw),o,on,self.w,wn)
        with self.mutex:self.calls+=1
        assert s.raw==raw+b'\0'
        if want>=0xfffffff0:
            assert rc==want,(op,rc,want);return o.raw
        assert rc==0 and o.raw[:8]==b'HIABGQR1',(op,rc,o.raw[:128].hex())
        assert get(o.raw,8)==want,(op,get(o.raw,8),want,o.raw[:128].hex())
        assert not self.errors,self.errors
        return o.raw
    def job(self,value):
        raw=str(value).encode();cap=self.values.create(raw);future=Native(self.future_lib,assert_global_unlocked=False)
        return {'value':value,'raw':raw,'cap':cap,'future':future}
    def admit(self,job,want=0):
        a,b,c=job['cap'];return self.run(1,{24:a,32:b,40:c,48:C.addressof(job['future'].work),56:512},want)
    def settle(self,raw):
        ref=self.refs(raw)[0];a,b,c=ref['cap'];return self.run(3,{16:ref['slot'],24:a,32:b,40:c})
    @staticmethod
    def refs(raw):
        out=[]
        for i in range(get(raw,56)):
            at=512+i*64
            out.append({'cap':struct.unpack_from('<3Q',raw,at),'future':get(raw,at+24),'extent':get(raw,at+32),'slot':get(raw,at+40)})
        return out
    def release_refs(self,raw):
        assert get(raw,64)==1 or get(raw,56)==0
        for r in self.refs(raw):self.values.drop(r['cap'])
    def destroy(self):self.run(9)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image',type=Path,required=True);ap.add_argument('--values',type=Path,required=True);ap.add_argument('--future',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    values=Owner(a.values);future=C.CDLL(str(a.future));cases=[];queues=[]
    def new(cap=8,poison=False):
        q=Queue(a.image,values,future,cap,poison);queues.append(q);return q
    def record(name,fn):
        start=time.monotonic_ns()
        try:detail=fn();assert get(values.w.raw,16)==0,('leaked native ownership nodes',get(values.w.raw,16))
        except BaseException as e:
            (a.output/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'completed':cases},indent=2)+'\n');raise
        cases.append({'name':name,'passed':True,'elapsed_ns':time.monotonic_ns()-start,'detail':detail});print('BG_QUEUE_PASS',name,flush=True)
    def capacity():
        for cap in range(1,9):
            q=new(cap,True);q.run(7);jobs=[q.job((1<<64)+i) for i in range(cap+1)]
            for j in jobs[:cap]:q.admit(j)
            q.admit(jobs[-1],2)
            active=q.run(2);assert get(active,32)==cap and get(active,40)==cap-1
            jobs[0]['future'].cancel();q.admit(jobs[-1],2)
            snap=q.run(5);assert len(q.refs(snap))==1 and q.refs(snap)[0]['cap']!=jobs[0]['cap']
            closed=q.run(4,{16:1});refs=q.refs(closed);assert [values.copy(r['cap'],20) for r in refs]==[j['raw'] for j in jobs[:cap]]
            for j in jobs[:cap]:j['future'].cancel()
            q.release_refs(q.settle(active))
            assert values.copy(q.refs(snap)[0]['cap'],20)==jobs[0]['raw'];q.release_refs(snap)
            for j in jobs[1:cap]:
                take=q.run(2);assert q.refs(take)[0]['cap']==j['cap'];q.release_refs(q.settle(take))
            assert get(q.run(2),16)==U64
            assert [values.copy(r['cap'],20) for r in refs]==[j['raw'] for j in jobs[:cap]]
            q.release_refs(closed);q.admit(jobs[-1],1);values.drop(jobs[-1]['cap'])
            q.run(8);q.destroy()
            for j in jobs:j['future'].destroy()
        return {'capacities':list(range(1,9)),'active_and_cancelled_slots_remain_charged':True}
    record('all-capacities-active-cancel-retain-close',capacity)
    def fifo():
        q=new(8);q.run(7)
        for batch in range(70):
            js=[q.job(batch*8+i) for i in range(8)]
            for j in js:q.admit(j)
            for j in js:
                r=q.run(2);assert q.refs(r)[0]['cap']==j['cap'];q.release_refs(q.settle(r));j['future'].complete(j['value']);assert j['future'].result()==j['value'];j['future'].destroy()
        q.run(4);assert get(q.run(2),16)==U64;q.run(8);q.destroy()
        return {'jobs':560,'complete_fifo_wraps':70}
    record('actual-fifo-ring-wrap-and-native-future-completion',fifo)
    def waiting():
        q=new(1);ready=threading.Event();taken=threading.Event();release=threading.Event();errors=[];seen=[]
        def worker():
            try:
                q.run(7);ready.set()
                while True:
                    raw=q.run(2)
                    if get(raw,16)==U64:break
                    seen.append(q.refs(raw)[0]['cap']);taken.set();assert release.wait(5);release.clear();q.release_refs(q.settle(raw))
                q.run(8)
            except BaseException as e:errors.append(repr(e));ready.set();taken.set()
        t=threading.Thread(target=worker,daemon=True);t.start();assert ready.wait(5)
        jobs=[]
        for i in range(120):
            taken.clear();j=q.job(i);jobs.append(j)
            while get(q.w.raw,40)!=0:time.sleep(.0001)
            q.admit(j);assert taken.wait(5);assert seen[-1]==j['cap'];j['future'].cancel()
            denied=q.job(9000+i);q.admit(denied,2);values.drop(denied['cap']);denied['future'].destroy()
            release.set()
        while get(q.w.raw,40)!=0:time.sleep(.0001)
        q.run(4);t.join(5);assert not t.is_alive() and not errors,errors;q.destroy()
        for j in jobs:j['future'].destroy()
        return {'native_idle_wake_cycles':120,'actual_worker_tid':get(q.w.raw,56)}
    record('actual-blocked-worker-120-wakes-cancel-does-not-free',waiting)
    def producers():
        q=new(8);errors=[];observed=[];all_jobs=[];jobs_by_cap={};ready=threading.Event();done=threading.Event();lock=threading.Lock()
        def worker():
            try:
                q.run(7);ready.set()
                while True:
                    r=q.run(2)
                    if get(r,16)==U64:break
                    cap=q.refs(r)[0]['cap']
                    with lock:j=jobs_by_cap[cap]
                    v=values.copy(cap,len(j['raw']))
                    observed.append(int(v));q.release_refs(q.settle(r))
                q.run(8)
            except BaseException as e:errors.append(repr(e));ready.set()
        def producer(k):
            try:
                for i in range(50):
                    j=q.job(k*1000+i)
                    with lock:all_jobs.append(j);jobs_by_cap[j['cap']]=j
                    while True:
                        raw=q.packet(1,{24:j['cap'][0],32:j['cap'][1],40:j['cap'][2],48:C.addressof(j['future'].work),56:512})
                        s=C.create_string_buffer(raw);out=C.create_string_buffer(4096);rc=q.f(s,128,out,4096,q.w,4096)
                        assert rc==0 and out.raw[:8]==b'HIABGQR1'
                        with q.mutex:q.calls+=1
                        status=get(out.raw,8);assert status in (0,2)
                        assert get(out.raw,32)<=8
                        if status==0:break
                        time.sleep(.0001)
            except BaseException as e:errors.append(repr(e))
        worker_t=threading.Thread(target=worker,daemon=True);worker_t.start();assert ready.wait(5)
        ts=[threading.Thread(target=producer,args=(i,),daemon=True) for i in range(8)]
        for t in ts:t.start()
        for t in ts:t.join(20);assert not t.is_alive()
        q.run(4);worker_t.join(10);assert not worker_t.is_alive() and not errors,errors
        assert sorted(observed)==[k*1000+i for k in range(8) for i in range(50)] and len(set(observed))==400
        q.destroy()
        for j in all_jobs:j['future'].destroy()
        return {'producer_threads':8,'exactly_once_jobs':400}
    record('eight-native-concurrent-submitters-single-worker',producers)
    def clone_failure():
        q=new(8);q.run(7);js=[q.job(i) for i in range(8)]
        for j in js:q.admit(j)
        active=q.run(2);q.fail_clone=3;r=q.run(4,{16:1},5);assert get(r,56)==0 and get(r,32)==8 and get(r,24)==1 and q.drops==2
        for j in js:assert values.copy(j['cap'],len(j['raw']))==j['raw']
        q.fail_clone=0;r=q.run(4,{16:1});assert len(q.refs(r))==8
        q.release_refs(q.settle(active))
        for j in js[1:]:q.release_refs(q.settle(q.run(2)))
        for ref,j in zip(q.refs(r),js):assert values.copy(ref['cap'],len(j['raw']))==j['raw']
        q.release_refs(r);q.run(8);q.destroy()
        for j in js:j['future'].destroy()
        return {'failed_clone_number':3,'partial_clones_dropped_once':2,'retry_still_owns_all_jobs':True}
    record('snapshot-allocation-failure-unwinds-new-owned-refs',clone_failure)
    def failure_drain():
        q=new(8);q.run(7);js=[q.job(i) for i in range(8)]
        for j in js:q.admit(j)
        q.run(2)
        saved=q.w.raw;bad=bytearray(saved);struct.pack_into('<Q',bad,512+8,0);C.memmove(q.w,bytes(bad),4096)
        q.run(6,want=65);assert q.w.raw==bytes(bad)
        C.memmove(q.w,saved,4096)
        r=q.run(6);assert [x['cap'] for x in q.refs(r)]==[j['cap'] for j in js] and get(r,32)==0 and get(r,48)==U64
        q.release_refs(r);assert get(q.run(2),16)==U64;q.run(8);q.destroy()
        for j in js:j['future'].destroy()
        return {'ordered_transferred_jobs':8,'corrupt_chain_no_partial_drain':True}
    record('worker-failure-drain-retains-submission-order',failure_drain)
    def reentrant_completion():
        q=new(1);q.run(7);first=q.job(1);second=q.job(2);seen=[]
        def callback(unused):
            r=q.run(5);assert get(r,32)==0;q.admit(second);seen.append('resubmitted')
        first['future'].add(callback);q.admit(first);q.release_refs(q.settle(q.run(2)));first['future'].complete(1)
        assert seen==['resubmitted'];q.release_refs(q.settle(q.run(2)));second['future'].complete(2)
        q.run(4);q.run(8);q.destroy();first['future'].destroy();second['future'].destroy()
        return {'callback_resubmit_after_pending_removal':True}
    record('native-future-callback-reenters-after-queue-release',reentrant_completion)
    def identity():
        q=new(2);q.run(7);q.run(7,want=4);errors=[]
        def other():
            try:
                for op in (2,3,6,8):q.run(op,want=3)
            except BaseException as e:errors.append(repr(e))
        t=threading.Thread(target=other,daemon=True);t.start();t.join(5);assert not t.is_alive() and not errors,errors
        j=q.job(7);q.admit(j);q.admit(j,4);r=q.run(2);wrong=dict(zip((16,24,32,40),(q.refs(r)[0]['slot'],j['cap'][0],j['cap'][1]^1,j['cap'][2])));q.run(3,wrong,4)
        q.run(8,want=4);q.run(9,want=4);q.release_refs(q.settle(r));q.run(8,want=4)
        pid=os.fork()
        if pid==0:
            try:q.run(5,want=65);os._exit(0)
            except BaseException:os._exit(71)
        _,status=os.waitpid(pid,0);assert status==0,status
        q.run(4);q.run(8);q.destroy();q.run(5,want=65);j['future'].destroy()
        return {'thread_refusals':4,'process_fork_refused':True,'duplicate_ownership_node_refused':True}
    record('worker-pid-tid-lifecycle-and-duplicate-ownership',identity)
    def guards():
        q=new(1);base=q.w.raw;count=0
        for raw in (b'',q.packet(5)[:-1],q.packet(5)+b'x',b'x'+q.packet(5)[1:],q.packet(10)):
            q.run(5,raw=raw,want=0xfffffffd);assert q.w.raw==base;count+=1
        for op in range(10):
            used={0:{16,64,80,88},1:{24,32,40,48,56},3:{16,24,32,40},4:{16}}.get(op,set())
            for at in range(16,128,8):
                if at not in used:q.run(op,{at:1},want=0xfffffffd);assert q.w.raw==base;count+=1
        q.run(5,on=4095,want=0xfffffffd);q.run(5,wn=4095,want=0xfffffffd);assert q.w.raw==base
        q.run(0,want=4);q.run(4,{16:2},4);q.destroy()
        return {'private_rejections':count+4,'owner_unchanged':True}
    record('complete-frame-unused-words-and-short-view-refusals',guards)
    values.run(9)
    report={'schema':'hepta.hia.background-native-queue.qualification.v1','whole_background_qualified':False,'scope':'Actual HIA queue/FIFO/futex/worker identity and strong references; Python threads and a wire-only provider translator are the external component fixture, not the BG product worker or rank implementation.','images':{n:{'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n,p in [('queue',a.image),('values',a.values),('future',a.future)]},'passed':len(cases),'failed':0,'native_queue_calls':sum(q.calls for q in queues),'native_value_calls':values.calls,'cases':cases}
    (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_QUEUE_QUALIFIED',len(cases),report['native_queue_calls'],values.calls,flush=True)
if __name__=='__main__':main()
