"""Actual canonical _OptimizationFuture production, lifecycle, and callback identity.

This qualifies the private HIAFRD02 producer and the retained D01 protocol.
The complete BG cancellation-token protocol and queued-worker contract remain
separate gates; merely obtaining class 74 does not qualify those behaviors.
"""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,importlib.util,json,os,struct,traceback
from tools import qualify_hia_future_deferred_producer as prior
from tools import qualify_hia_future_native_callbacks as callbacks
from tools import qualify_hia_result_value_invocations as inv
from hepta.hia_background_optimizer import _OptimizationFuture
ZERO=(0,0,0)
word=prior.word;triple=prior.triple;put=prior.put;pin=prior.pin;save=prior.save
def frame(op=0,cap=ZERO,lease=ZERO):
    r=bytearray(prior.frame(op,cap,lease));r[:8]=b'HIAFRD02';return bytes(r)
class Fixture(prior.Fixture):
    def optimization(self,fac,keep=True):
        rc,r=self.raw(frame(0,fac[0],fac[1]))
        assert rc==0 and r[:8]==b'HIAFRDR2',(rc,r.hex())
        assert word(r,144)==1 and all(word(r,p)<=1 for p in(96,104,112,120,128,136,152))
        assert (word(r,16),word(r,96),word(r,104))==(7,1,1)and all(triple(r)),r.hex()
        assert word(r,8)in(0,11)and word(r,120)==word(r,136)==word(r,152)==0,r.hex()
        assert word(r,112)==word(r,128),r.hex()
        if keep:self.v.keep(r)
        return r
    def actual_type(self,resource):
        cls=self.v.keep(self.v.raw(36,a=resource))
        expected=self.v.keep(self.v.raw(114,arg0=74))
        base=self.v.keep(self.v.raw(57,arg0=37))
        name=self.v.keep(self.v.raw(38,a=cls))
        assert self.v.same(cls,expected)and not self.v.same(cls,base)
        assert word(self.v.raw(37,a=resource,b=base),48)==1
        assert self.v.python_value(name)==_OptimizationFuture.__name__
        assert word(self.v.raw(49,a=resource),16)==7
        for cap in(name,base,expected,cls):self.v.drop(cap)
    def new(self,fac):
        r=self.optimization(fac);resource=triple(r);self.actual_type(resource)
        return resource,triple(self.v.raw(80,a=resource))
def identity(owner,out):
    f=Fixture(owner);fac=f.public.factory();r=f.optimization(fac);resource=triple(r)
    assert word(r,8)==word(r,112)==0
    f.actual_type(resource);weak=triple(f.v.raw(80,a=resource))
    a=f.deferred(1,resource);strong=triple(a);pair=(triple(a,48),triple(a,72))
    value=f.v.scalar('same arena real _OptimizationFuture')
    f.public.call(22,*pair,value=value,kind=1);f.v.drop(value)
    returned=f.v.keep(f.public.call(10,*pair),72)
    assert f.v.python_value(returned)=='same arena real _OptimizationFuture'
    f.v.drop(returned);f.v.drop(strong);f.v.drop(resource)
    f.v.raw(80,a=weak,arg0=1,want=3)
    old=f.deferred(0,fac[0],fac[1]);oldvalue=triple(old)
    cls=f.v.keep(f.v.raw(36,a=oldvalue));base=f.v.keep(f.v.raw(57,arg0=37))
    assert f.v.same(cls,base)
    f.v.drop(cls);f.v.drop(base);f.v.drop(oldvalue);f.finish()
    return dict(case='actual-class74-MRO-result-retention-and-D01-class37',passed=True,
                canonical_class=74,actual_original_name=_OptimizationFuture.__name__,
                original_bases=[c.__name__ for c in _OptimizationFuture.__mro__],
                create=r.hex(),borrow=a.hex(),old_create=old.hex())
def cycle(owner,out,container=False):
    f=Fixture(owner);fac=f.public.factory();resource,weak=f.new(fac)
    a=f.deferred(1,resource);strong=triple(a);pair=(triple(a,48),triple(a,72))
    value=f.v.lst([resource])if container else resource
    f.public.call(22,*pair,value=value,kind=1)
    if container:f.v.drop(value)
    f.v.drop(strong);f.v.drop(resource)
    f.v.raw(80,a=weak,arg0=1,want=3)
    assert word(f.v.raw(47),48)==f.baseline+len(f.public.factories)
    f.finish()
    return dict(case='actual-class74-'+('list'if container else'self')+'-cycle-native-lastdrop',passed=True)
def self_cycle(owner,out):return cycle(owner,out)
def list_cycle(owner,out):return cycle(owner,out,True)
def callback(owner,out,immediate=False,cancel=False):
    f=Fixture(owner);fac=f.public.factory();resource,weak=f.new(fac)
    a=f.deferred(1,resource);strong=triple(a);pair=(triple(a,48),triple(a,72))
    events=f.v.lst([]);fn=f.v.function(callbacks.SOURCE,env=events)
    value=f.v.scalar(None)
    if immediate:f.public.call(22,*pair,value=value,kind=1)
    f.register(resource,fn);f.v.drop(fn)
    if not immediate:
        assert f.length(events)==0
        if cancel:
            r=f.public.call(7,*pair);assert word(r,16)==1
        else:f.public.call(22,*pair,value=value,kind=1)
    f.assert_events(events,resource,1)
    f.v.drop(value);f.v.drop(strong);f.v.drop(resource)
    still=f.v.keep(f.v.raw(80,a=weak,arg0=1));f.actual_type(still);f.v.drop(still)
    f.v.drop(events);f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(case='actual-class74-Value70-callback-'+('cancel-core'if cancel else'immediate'if immediate else'pending'),
                passed=True,actual_native_callable=True,same_actual_argument=True,
                registrations=f.registrations,full_BG_cancellation_token_semantics=False)
def pending_callback(owner,out):return callback(owner,out)
def immediate_callback(owner,out):return callback(owner,out,True)
def cancel_callback(owner,out):return callback(owner,out,False,True)
def queue_pending(owner,out):
    f=Fixture(owner);fac=f.public.factory()
    helper=Path('/home/qian-qi/hia-native-llvm-public-followthrough-20261126-620a/tools/qualify_hia_result_value_deferred_capture.py')
    spec=importlib.util.spec_from_file_location('actual_deferred_capture_qa',helper)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    mod.pending_function(f.v,f.bound);assert word(f.engine.context,176)==1
    r=f.optimization(fac);value=triple(r)
    assert word(f.engine.context,176)==1 and word(r,128)==1,r.hex()
    a=f.deferred(1,value);strong=triple(a)
    assert word(f.engine.context,176)==1 and word(a,128)==1,a.hex()
    f.v.raw(47);assert word(f.engine.context,176)==word(f.engine.context,184)==0
    f.actual_type(value);weak=triple(f.v.raw(80,a=value))
    f.v.drop(strong);f.v.drop(value);f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(case='class74-create-classcap-retirement-real-pending-no-inner-drain',passed=True,
                create=r.hex(),acquire=a.hex(),actual_code_failure=True,ordinary_outer_entry_drained=True,
                helper=pin(helper.read_bytes()))
def guards(owner,out):
    f=Fixture(owner);fac=f.public.factory();variants=[]
    for op in(1,2,3,4,5,31,2**64-1):variants.append(('op-'+str(op),frame(op,fac[0],fac[1])))
    for off in(40,48,56,88,96,104,112,120):
        raw=bytearray(frame(0,fac[0],fac[1]));put(raw,off,1);variants.append(('reserved-'+str(off),bytes(raw)))
    variants.extend([('short',frame(0,fac[0],fac[1])[:-1]),('extra',frame(0,fac[0],fac[1])+b'x')])
    for name,raw in variants:
        before=bytes(f.provider_ctx);vc=bytes(f.engine.context);rc,r=f.raw(raw)
        assert rc==0xfffffffd and bytes(f.provider_ctx)==before and bytes(f.engine.context)==vc,(name,rc,r.hex())
    before=bytes(f.provider_ctx);vc=bytes(f.engine.context);rc,r=f.raw(frame(0,fac[0],fac[1]),159)
    assert rc==0xfffffffe and bytes(f.provider_ctx)==before and bytes(f.engine.context)==vc,(rc,r.hex())
    f.finish()
    return dict(case='new-D02-exact-private-domain-and-output-span',passed=True,controls=len(variants)+1)
def parallel(owner,out):
    f=Fixture(owner);fac=f.public.factory();rows=[]
    def one(i):
        r=f.optimization(fac,keep=False);value=triple(r)
        a=f.deferred(1,value,keep=False);strong=triple(a)
        for owned in(strong,value):
            rc,reply=f.engine.call(inv.frame(78,a=owned))
            assert rc==0 and reply[:8]==b'HIABVR02' and (word(reply,88),word(reply,96))==(1,1),reply[:128].hex()
            assert word(reply,104)==0 and word(reply,120)==1
        rows.append(dict(index=i,create=r.hex(),acquire=a.hex()));return i
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        assert list(pool.map(one,range(32)))==list(range(32))
    f.v.raw(47)
    assert word(f.engine.context,176)==word(f.engine.context,184)==0
    assert word(f.provider_ctx,272)==word(f.provider_ctx,112)==0
    f.finish()
    return dict(case='eight-callers-class74-production-classcap-cleanup',passed=True,threads=8,created=32,calls=rows)
CASES=(identity,self_cycle,list_cycle,pending_callback,immediate_callback,cancel_callback,queue_pending,guards,parallel)
def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cases',nargs='*');a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    report=dict(schema='hia.OptimizationFuture-native-producer.component.v1',passed=False,component_qualified=False,
                whole_background_closed=False,queued_worker_qualified=False,full_cancellation_token_methods=False,
                native_initializer=True,same_physical_Value=True,python_callback_handlers=False,
                product=dict(path=str(a.owner),**pin(a.owner.read_bytes())),cases=[])
    selected=set(a.cases or [f.__name__ for f in CASES])
    try:
        for fn in CASES:
            if fn.__name__ not in selected:continue
            row=fn(a.owner,a.output);report['cases'].append(row);save(a.output/'report.json',report)
            print('ACTUAL_OPTIMIZATION_PRODUCER_CASE',row['case'],flush=True)
        report['passed']=True;report['component_qualified']=len(report['cases'])==len(CASES)
    except BaseException as e:report['error']=repr(e);report['traceback']=traceback.format_exc();raise
    finally:save(a.output/'report.json',report)
    print('ACTUAL_OPTIMIZATION_PRODUCER_PASS',len(report['cases']),flush=True)
if __name__=='__main__':main()
