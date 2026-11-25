"""Actual native futex/token/Future callback and lifetime qualification."""
from pathlib import Path
import argparse,ctypes,json,logging,os,struct,threading,time
from concurrent.futures import CancelledError,TimeoutError,InvalidStateError
from tools.qualify_hia_multiversion_components import get,sha
from hepta.hia_background_optimizer import _OptimizationFuture
from hepta.hia_multiversion import PublicationCancellation
CB=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
DROP=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64)
def address(function):
    # cast(CFUNCTYPE, c_void_p) inserts a carrier self-reference into _objects.
    # A borrowed pointer read does not create that unrelated Python GC cycle.
    return ctypes.c_void_p.from_buffer(function).value
class Native:
    def __init__(self,library,assert_global_unlocked=True):
        self.library=library;self.fn=library.hia_mv_future;self.fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64];self.fn.restype=ctypes.c_uint32
        self.assert_global_unlocked=assert_global_unlocked
        self.work=ctypes.create_string_buffer(512);self.live={};self.drop_counts={};self.next=0;self.errors=[];self.lock_checks=0
        @DROP
        def drop(number):
            if self.assert_global_unlocked:
                assert get(self.work,128)&0xffffffff==0 and get(self.work,132)&0xffffffff==0
            self.drop_counts[number]=self.drop_counts.get(number,0)+1
            self.live.pop(number,None);return 0
        self.drop=drop;self.invoke(0)
    def invoke(self,op,*args):
        packet=struct.pack('<8s7Q',b'HIAMVFQ1',op,*(list(args)+[0]*(6-len(args))))
        source=ctypes.create_string_buffer(packet);out=ctypes.create_string_buffer(512)
        rc=self.fn(source,len(packet),out,512,self.work,512);assert source.raw==packet+b'\0'
        assert out.raw[:8]==b'HIAMVFR1',(op,rc,out.raw[:128].hex());values=struct.unpack('<16Q',out.raw[:128])
        if rc==4:
            assert self.errors;raise self.errors.pop(0)
        return rc,values
    def add(self,handler):
        self.next+=1;number=self.next
        @CB
        def callback(owner,argument):
            assert owner==ctypes.addressof(self.work) and argument==number
            # With competing native threads another thread may legally own a
            # lock at this instant. Those cases instead prove lock release by
            # actual reentrant result/state calls from this callback.
            if self.assert_global_unlocked:
                assert get(self.work,128)&0xffffffff==0 and get(self.work,132)&0xffffffff==0
            self.lock_checks+=1
            try:handler(self);return 0
            except Exception:return 1
            except BaseException as e:self.errors.append(e);return 2
        self.live[number]=callback
        rc,_=self.invoke(4,address(callback),number,address(self.drop),number);assert rc==0
    def cancel(self):
        rc,v=self.invoke(1);assert rc==0;return bool(v[2])
    def complete(self,value):
        rc,_=self.invoke(2,value)
        if rc==6:raise InvalidStateError("concurrent completion")
        assert rc==0
    def settle(self):
        rc,v=self.invoke(3)
        if rc==3:raise RuntimeError('token not cancelled')
        assert rc==0;return bool(v[2])
    def state(self):
        rc,v=self.invoke(5);assert rc==0;return ('pending','cancelled','finished')[v[3]]
    def token_cancel(self):
        rc,v=self.invoke(8);assert rc==0;return bool(v[2])
    def token_commit(self):
        rc,v=self.invoke(7);assert rc==0;return bool(v[2])
    def token_state(self):
        rc,v=self.invoke(9);assert rc==0;return v[2]
    def result(self,timeout=None):
        rc,v=self.invoke(6,0 if timeout is None else max(0,int(timeout*1e9)),int(timeout is None))
        if rc==1:raise CancelledError()
        if rc==2:raise TimeoutError()
        assert rc==0,(rc,v);return v[2]
    def destroy(self):
        rc,_=self.invoke(10);assert rc==0
        assert not self.live and all(n==1 for n in self.drop_counts.values())
class Reference:
    def __init__(self):
        self.token=PublicationCancellation();self.future=_OptimizationFuture(self.token)
    def add(self,handler):self.future.add_done_callback(lambda unused:handler(self))
    def cancel(self):return self.future.cancel()
    def complete(self,value):self.future._complete(value)
    def settle(self):
        try:return self.future._settle_token_cancellation()
        except Exception:raise RuntimeError('token not cancelled')
    def state(self):return self.future._accounting_state()
    def token_cancel(self):return self.token.cancel()
    def token_commit(self):
        with self.token._lock:
            if self.token.cancelled():return False
            self.token._committed=True;return True
    def token_state(self):return 2 if self.token.committed() else 1 if self.token.cancelled() else 0
    def result(self,timeout=None):return self.future.result(timeout)
    def destroy(self):pass
def capture(call):
    try:return ('result',call())
    except CancelledError:return ('cancelled',)
    except TimeoutError:return ('timeout',)
    except KeyboardInterrupt:return ('interrupted',)
    except RuntimeError as e:return ('error',str(e))
def scenario(q,name):
    events=[]
    def observed(label):
        def callback(f):events.append((label,f.state(),capture(lambda:f.result(0))))
        return callback
    if name=='normal':
        q.add(observed('a'));q.add(observed('b'));events.append(('pending',capture(lambda:q.result(0))))
        q.complete(73);events.append(('result',q.result(0)));events.append(('cancel',q.cancel()));q.complete(99);q.add(observed('late'))
    elif name=='cancel':
        q.add(observed('a'));q.add(observed('b'));events.append(('cancel',q.cancel()));events.append(('repeat',q.cancel()));q.complete(73);q.add(observed('late'))
    elif name=='committed':
        q.add(observed('a'));events.append(('commit',q.token_commit()));events.append(('cancel',q.cancel()));events.append(('pending',capture(lambda:q.result(0))));q.complete(73)
    elif name=='token-gap':
        q.add(observed('a'));events.append(('token',q.token_cancel()));events.append(('before',q.state(),capture(lambda:q.result(0))));events.append(('settle',q.settle()));events.append(('repeat',q.settle()))
    elif name=='invalid-settle':
        events.append(('settle',capture(q.settle)));q.complete(73)
    elif name=='exception':
        def bad(f):events.append(('raise',f.state()));raise ValueError('callback fault')
        q.add(bad);q.add(observed('after'));q.complete(73);q.add(bad);events.append(('result',q.result(0)))
    elif name=='interrupt':
        def bad(f):events.append(('raise',f.state()));raise KeyboardInterrupt()
        q.add(bad);q.add(observed('never'));events.append(('complete',capture(lambda:q.complete(73))));q.add(observed('late'));events.append(('cancel',q.cancel()))
    elif name=='recursive-add':
        def nested(f):events.append(('outer-start',f.state()));f.add(observed('inner'));events.append(('outer-end',f.state()))
        q.add(nested);q.add(observed('tail'));q.complete(73)
    elif name=='cancel-join':
        gate=threading.Event();stopped=threading.Event()
        def worker():assert gate.wait(2);q.complete(73);stopped.set()
        t=threading.Thread(target=worker);t.start()
        def joined(f):events.append(('callback',f.state()));gate.set();t.join(2);assert not t.is_alive() and stopped.is_set();events.append(('joined',))
        q.add(joined);events.append(('cancel',q.cancel()));t.join(2)
    elif name in ('wait-complete','wait-cancel'):
        barrier=threading.Barrier(9);answers=[];lock=threading.Lock()
        def wait():
            barrier.wait();value=capture(lambda:q.result(2))
            with lock:answers.append(value)
        ts=[threading.Thread(target=wait) for _ in range(8)]
        for t in ts:t.start()
        barrier.wait();time.sleep(0.01)
        q.complete(73) if name=='wait-complete' else q.cancel()
        for t in ts:t.join(3);assert not t.is_alive()
        events.append(('waiters',sorted(answers)))
    elif name=='timeout':
        started=time.monotonic();events.append(('timeout',capture(lambda:q.result(.02))));assert time.monotonic()-started>=.015;q.complete(73)
    elif name=='many-callbacks':
        for i in range(1000):q.add(lambda f,i=i:events.append((i,f.state())))
        q.complete(73)
    else:raise ValueError(name)
    events.append(('final',q.state(),q.token_state(),capture(lambda:q.result(0))))
    return events
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
    logging.getLogger('concurrent.futures').disabled=True
    library=ctypes.CDLL(str(D/'future-component.so'));rows=[]
    cases=['normal','cancel','committed','token-gap','invalid-settle','exception','interrupt','recursive-add','cancel-join','wait-complete','wait-cancel','timeout','many-callbacks']
    for name in cases:
        old=Reference();expected=scenario(old,name)
        new=Native(library);actual=scenario(new,name);assert actual==expected,(name,actual[:30],expected[:30])
        retained=len(new.live)
        if name not in ('invalid-settle','wait-complete','wait-cancel','timeout'):assert retained>0
        new.destroy();rows.append({'case':name,'events_sha256':sha(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()),'events':len(actual),'actual_callback_entries':new.lock_checks,'retained_closures_until_destroy':retained,'exactly_once_drops':sum(new.drop_counts.values())})
        print('FUTURE_PAIR_PASS',name,len(actual),new.lock_checks,retained,flush=True)
    races={}
    for i in range(80):
        q=Native(library);barrier=threading.Barrier(3);answer=[]
        def cancelling():barrier.wait();answer.append(q.cancel())
        def completing():barrier.wait();q.complete(73)
        ts=[threading.Thread(target=cancelling),threading.Thread(target=completing)]
        for t in ts:t.start()
        barrier.wait()
        for t in ts:t.join(3);assert not t.is_alive()
        state=q.state();token=q.token_state();combo=(answer[0],state,token)
        assert combo in {(True,'cancelled',1),(False,'finished',0),(False,'finished',1)},combo
        races[str(combo)]=races.get(str(combo),0)+1;q.destroy()
    report={'schema':'hepta.hia.native-future-component.v1','whole_native_runtime':False,'scope':'actual in-process HIA Future/token/futex/C callback state and transferred closure lifetime; optimizer/public value carrier not integrated','passed_pairs':len(rows),'native_races':80,'failed':0,'image_sha256':sha((D/'future-component.so').read_bytes()),'cases':rows,'race_outcomes':races}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('NATIVE_FUTURE_PASS',len(rows),80,flush=True)
if __name__=='__main__':main()
