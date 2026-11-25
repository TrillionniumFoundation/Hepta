"""Actual Future owner lifetime, futex, private admission and allocator gates."""
from pathlib import Path
import argparse,ctypes,json,os,signal,struct,threading,time,weakref
from tools.qualify_hia_multiversion_future import Native,Reference,CB,DROP,capture,address
from tools.qualify_hia_multiversion_components import get,sha

def until(test):
    stop=time.monotonic()+3
    while not test():
        assert time.monotonic()<stop,'real synchronization point was not reached'
        time.sleep(.001)

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
    lib=ctypes.CDLL(str(D/'future-component.so'));rows=[]
    def passed(name,**fields):rows.append({'case':name,**fields});print('FUTURE_GUARD_PASS',name,flush=True)
    # Private frames do not acquire, mutate, or release an existing owner.
    q=Native(lib);raw=struct.pack('<8s7Q',b'HIAMVFQ1',5,0,0,0,0,0,0)
    variants=[('magic',b'INVALID!'+raw[8:]),('truncated',raw[:-1]),('trailing',raw+b'\0'),('op11',raw[:8]+struct.pack('<Q',11)+raw[16:])]
    for at in (48,56):
        x=bytearray(raw);struct.pack_into('<Q',x,at,1);variants.append(('reserved'+str(at),bytes(x)))
    for name,data in variants:
        before=q.work.raw;out=ctypes.create_string_buffer(512);s=ctypes.create_string_buffer(data)
        rc=q.fn(s,len(data),out,512,q.work,512);assert rc==0xfffffffd and q.work.raw==before
        passed(name,refused_without_owner_mutation=True)
    for name,oc,wc in [('output-small',511,512),('work-small',512,511)]:
        before=q.work.raw;out=ctypes.create_string_buffer(512);s=ctypes.create_string_buffer(raw)
        rc=q.fn(s,64,out,oc,q.work,wc);assert rc==0xfffffffd and q.work.raw==before;passed(name)
    before=q.work.raw;assert q.invoke(0)[0]==3 and q.work.raw==before;passed('reinitialization-refused')
    assert q.invoke(4,0)[0]==3 and q.invoke(6,0,2)[0]==3
    assert q.state()=='pending';q.destroy();passed('invalid-capabilities-and-timeout-flag')
    # A forked copy cannot drop process-owned callback nodes or claim the token.
    q=Native(lib);q.add(lambda f:None);r,w=os.pipe();pid=os.fork()
    if pid==0:
        os.close(r);before=q.work.raw
        values=[q.invoke(op)[0] for op in (1,5,8,10)]
        os.write(w,json.dumps({'values':values,'unchanged':q.work.raw==before}).encode());os._exit(0)
    os.close(w);data=b''
    while x:=os.read(r,4096):data+=x
    os.close(r);assert os.waitpid(pid,0)[1]==0
    assert json.loads(data)=={'values':[65]*4,'unchanged':True};q.complete(7);q.destroy();passed('foreign-pid-retains-original-owner')
    # Thread blocked in actual HIA futex keeps the owner alive; SIGUSR1 causes an
    # actual signal/EINTR opportunity, without substituting a fabricated result.
    q=Native(lib);answers=[]
    oldhandler=signal.signal(signal.SIGUSR1,lambda signum,frame:None)
    t=threading.Thread(target=lambda:answers.append(capture(lambda:q.result(None))));t.start()
    until(lambda:get(q.work,72)==1)
    assert q.invoke(10)[0]==3 and get(q.work,80)==0
    signal.pthread_kill(t.ident,signal.SIGUSR1);time.sleep(.01)
    assert t.is_alive() and get(q.work,80)==0
    q.complete(19);t.join(3);assert not t.is_alive() and answers==[('result',19)]
    signal.signal(signal.SIGUSR1,oldhandler);q.destroy();passed('actual-futex-signal-and-active-wait-destroy')
    # The completing thread holds an active call through user callback execution.
    q=Native(lib);entered=threading.Event();resume=threading.Event();events=[]
    def blocked(f):entered.set();assert resume.wait(3);events.append(('done',f.result(0)))
    q.add(blocked);t=threading.Thread(target=lambda:q.complete(23));t.start();assert entered.wait(3)
    assert q.invoke(10)[0]==3 and get(q.work,80)==0
    q.add(lambda f:events.append(('late',f.result(0))))
    resume.set();t.join(3);assert not t.is_alive() and events==[('late',23),('done',23)]
    q.destroy();passed('callback-active-destroy-and-concurrent-late-add')
    # Capture a real weak reference to the caller closure. No gc.collect or
    # observer padding is involved; both implementations retain after invocation.
    class Handler:
        def __init__(self):self.calls=0
        def __call__(self,f):self.calls+=1
    references=[]
    # Use the actual original Future directly. The generic Reference wrapper's
    # adapter lambda intentionally captures itself, so it is not a lifetime
    # observer for the underlying original Future.
    from hepta.hia_background_optimizer import _OptimizationFuture
    from hepta.hia_multiversion import PublicationCancellation
    original=_OptimizationFuture(PublicationCancellation());h=Handler();ref=weakref.ref(h)
    original.add_done_callback(h);del h
    assert ref() is not None;original._complete(31);assert ref().calls==1
    del original
    assert ref() is None;references.append(True)
    q=Native(lib);h=Handler();ref=weakref.ref(h);q.add(h);del h
    assert ref() is not None;q.complete(31);assert ref().calls==1
    q.destroy();assert ref() is None;references.append(True)
    passed('actual-closure-retained-after-call-until-owner-release',original_and_native=references)
    # Private value capabilities are transferred once: losing completion drops
    # its incoming value; the selected value survives until the owner is released.
    q=Native(lib);drops=[];faults=[]
    @DROP
    def resultdrop(handle):
        if get(q.work,128)&0xffffffff or get(q.work,132)&0xffffffff:faults.append('locked')
        drops.append(handle);return 0
    dp=address(resultdrop)
    assert q.invoke(2,101,dp)[0]==0 and q.invoke(2,102,dp)[0]==0 and drops==[102]
    assert q.result(0)==101;q.destroy();assert drops==[102,101] and not faults
    passed('selected-and-losing-result-transferred-lifetimes')
    q=Native(lib);q.cancel();drops=[]
    @DROP
    def cancelleddrop(handle):drops.append(handle);return 0
    assert q.invoke(2,103,address(cancelleddrop))[0]==0 and drops==[103]
    q.destroy();assert drops==[103];passed('cancelled-future-drops-unselected-result-once')
    q=Native(lib);seen=[];q.add(lambda f:seen.append('never'));assert len(q.live)==1;q.destroy()
    assert seen==[] and q.drop_counts=={1:1};passed('pending-destruction-releases-without-invoking')
    q=Native(lib);q.complete(5)
    def abrupt(f):raise KeyboardInterrupt('immediate')
    assert capture(lambda:q.add(abrupt))==('interrupted',) and not q.live and q.drop_counts=={1:1}
    q.destroy();passed('immediate-abrupt-callback-releases-incoming-closure')
    # Callback destruction is refused while it is on the stack, and can safely
    # reenter ordinary observation because neither native lock surrounds it.
    q=Native(lib);seen=[]
    q.add(lambda f:seen.append((f.invoke(10)[0],f.result(0),f.cancel())));q.complete(17)
    assert seen==[(3,17,False)];q.destroy();passed('callback-reentrant-destroy-refusal')
    # Real boundary between future.done() and token cancellation in old contract.
    for cls in (Reference,lambda:Native(lib)):
        q=cls();assert q.token_cancel();q.complete(11)
        assert q.settle() is False and q.state()=='finished' and q.token_state()==1 and q.result(0)==11
        q.destroy()
    passed('settle-token-gap-after-normal-completion-original-pair')
    report={'schema':'hepta.hia.native-future-guards.v1','passed':len(rows),'failed':0,'whole_native_runtime':False,'image_sha256':sha((D/'future-component.so').read_bytes()),'cases':rows}
    (D/'guards-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('FUTURE_GUARDS_PASS',len(rows),flush=True)
if __name__=='__main__':main()
