"""Deferred canonical Future production for a held BG condition lock."""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,importlib.util,json,os,struct,traceback
from tools import qualify_hia_future_native_callbacks as callbacks
from tools import qualify_hia_result_value_invocations as inv
ZERO=(0,0,0)
def word(b,p):return struct.unpack_from('<Q',b,p)[0]
def triple(b,p=24):return struct.unpack_from('<3Q',b,p)
def put(b,p,*v):struct.pack_into('<'+'Q'*len(v),b,p,*v)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def frame(op,cap=ZERO,lease=ZERO):
    r=bytearray(128);r[:8]=b'HIAFRD01';put(r,8,op);put(r,16,*cap);put(r,64,*lease);return bytes(r)
class Fixture(callbacks.Fixture):
    def raw(self,raw,on=160):
        src=C.create_string_buffer(raw,len(raw));out=C.create_string_buffer(352)
        C.memset(C.addressof(out)+on,0xa5,352-on)
        rc=self.provider.entry(src,len(raw),out,on,self.provider_ctx,512)
        assert src.raw==raw and out.raw[on:]==b'\xa5'*(352-on)
        return rc,out.raw[:on]
    def deferred(self,op,cap=ZERO,lease=ZERO,keep=True):
        rc,r=self.raw(frame(op,cap,lease))
        assert rc==0 and r[:8]==b'HIAFRDR1',(op,rc,r.hex())
        assert word(r,144)==1 and all(word(r,p)<=1 for p in(96,104,112,120,128,136,152))
        assert word(r,96)==1 and word(r,104)==1 and all(triple(r)),r.hex()
        assert word(r,16)==7 and word(r,8) in(0,11),r.hex()
        assert word(r,120)==word(r,136)==word(r,152)==0,r.hex()
        assert word(r,112)==word(r,128),r.hex()
        if keep:self.v.keep(r)
        return r
def normal(owner,out):
    f=Fixture(owner);fac=f.public.factory()
    r=f.deferred(0,fac[0],fac[1]);value=triple(r);assert word(r,8)==word(r,112)==0
    a=f.deferred(1,value);strong=triple(a);pair=(triple(a,48),triple(a,72))
    scalar=f.v.scalar('actual deferred canonical submit');f.public.call(22,*pair,value=scalar,kind=1);f.v.drop(scalar)
    got=f.v.keep(f.public.call(10,*pair),72);assert f.v.python_value(got)=='actual deferred canonical submit';f.v.drop(got)
    weak=triple(f.v.raw(80,a=value));f.v.drop(strong);f.v.drop(value);f.v.raw(80,a=weak,arg0=1,want=3)
    old,oldweak=f.resource(fac);pin_,oldpair=f.acquire(old);f.v.drop(pin_);f.v.drop(old)
    f.v.raw(80,a=oldweak,arg0=1,want=3);f.finish()
    return dict(case='deferred-create-acquire-real-result-and-old-Q02-Q03',passed=True,
                create=r.hex(),acquire=a.hex(),old_domains_preserved=True)
def queue_pending(owner,out):
    f=Fixture(owner);fac=f.public.factory()
    helper=Path('/home/qian-qi/hia-native-llvm-public-followthrough-20261126-620a/tools/qualify_hia_result_value_deferred_capture.py')
    spec=importlib.util.spec_from_file_location('actual_deferred_capture_qa',helper)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    mod.pending_function(f.v,f.bound)
    assert word(f.engine.context,176)==1
    r=f.deferred(0,fac[0],fac[1]);value=triple(r)
    assert word(f.engine.context,176)==1 and word(r,128)==1,r.hex()
    a=f.deferred(1,value);strong=triple(a)
    assert word(f.engine.context,176)==1 and word(a,128)==1,a.hex()
    # Only this normal outer entry is allowed to execute the actual finalizer.
    f.v.raw(47);assert word(f.engine.context,176)==word(f.engine.context,184)==0
    weak=triple(f.v.raw(80,a=value));f.v.drop(strong);f.v.drop(value);f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(case='real-code-munmap-EIO-pending-no-inner-drain',passed=True,create=r.hex(),acquire=a.hex(),
                actual_code_failure=True,ordinary_outer_entry_drained=True,helper=pin(helper.read_bytes()))
def cycle(owner,out):
    f=Fixture(owner);fac=f.public.factory();r=f.deferred(0,fac[0],fac[1]);value=triple(r)
    a=f.deferred(1,value);strong=triple(a);pair=(triple(a,48),triple(a,72))
    weak=triple(f.v.raw(80,a=value));f.public.call(22,*pair,value=value,kind=1)
    f.v.drop(strong);f.v.drop(value);f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(case='deferred-producer-canonical-self-cycle-finalizer',passed=True)
def guards(owner,out):
    f=Fixture(owner);fac=f.public.factory();variants=[]
    for op in(2,3,4,5,31,2**64-1):variants.append(('op-'+str(op),frame(op)))
    for op in(0,1):
        for off in([40,48,56,88,96,104,112,120] if op==0 else list(range(40,128,8))):
            raw=bytearray(frame(op,fac[0],fac[1] if op==0 else ZERO));put(raw,off,1)
            variants.append((str(op)+'-reserved-'+str(off),bytes(raw)))
    variants.extend([('short',frame(0,fac[0],fac[1])[:-1]),('extra',frame(0,fac[0],fac[1])+b'x')])
    for name,raw in variants:
        before=bytes(f.provider_ctx);vc=bytes(f.engine.context);rc,r=f.raw(raw)
        assert rc==0xfffffffd and bytes(f.provider_ctx)==before and bytes(f.engine.context)==vc,(name,rc,r.hex())
    before=bytes(f.provider_ctx);rc,r=f.raw(frame(0,fac[0],fac[1]),159)
    assert rc==0xfffffffe and bytes(f.provider_ctx)==before,(rc,r.hex())
    f.finish()
    return dict(case='new-deferred-domain-exact-frames-and-output-span',passed=True,controls=len(variants)+1)
def parallel(owner,out):
    f=Fixture(owner);fac=f.public.factory();rows=[]
    def one(i):
        r=f.deferred(0,fac[0],fac[1],keep=False);value=triple(r)
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
    return dict(case='eight-callers-deferred-production-real-outer-drain',passed=True,threads=8,created=32,calls=rows)
CASES=(normal,queue_pending,cycle,guards,parallel)
def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    report=dict(schema='hia.Future-deferred-producer.component.v1',passed=False,component_qualified=False,
        whole_background_closed=False,production_BG_initializer=False,
        product=dict(path=str(a.owner),**pin(a.owner.read_bytes())),cases=[])
    try:
        for fn in CASES:
            row=fn(a.owner,a.output);report['cases'].append(row);save(a.output/'report.json',report)
            print('ACTUAL_DEFERRED_PRODUCER_CASE',row['case'],flush=True)
        report['passed']=report['component_qualified']=True
    except BaseException as e:report['error']=repr(e);report['traceback']=traceback.format_exc();raise
    finally:save(a.output/'report.json',report)
    print('ACTUAL_DEFERRED_PRODUCER_PASS',len(report['cases']),flush=True)
if __name__=='__main__':main()
