"""Actual native trusted Future binding and one finalizer in the enclosing owner."""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_generation_lease_owner_sidecar as sideqa
from tools import generate_hia_generation_lease_owner_sidecar_future_capsule_packer as capsule
from tools import qualify_hia_result_value_invocations as inv
from tools import qualify_hia_future_managed_edges as managed
from tools.qualify_hia_future_retirement import facts
ZERO=(0,0,0);BAD=0xfffffffd
def word(b,p):return struct.unpack_from('<Q',b,p)[0]
def triple(b,p=24):return struct.unpack_from('<3Q',b,p)
def put(b,p,*values):struct.pack_into('<'+'Q'*len(values),b,p,*values)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
class Bound(sideqa.Bound):
    def __init__(self,path):
        previous=sideqa.capsule;sideqa.capsule=capsule
        try:super().__init__(path)
        finally:sideqa.capsule=previous
    def bind(self):
        row=self.call(0)
        assert row['status']==0 and row['state']==2 and row['pending']==0,row
        w=self.owner.context;ptr=word(w,1152);base=C.addressof(w)
        assert ptr and word(w,1160)==212992 and word(w,1176)==self.address
        assert word(w,72)==1 and word(w,1208)==0 and word(w,680)==190
        assert word(w,704)==self.address+capsule.CODE_EXPORT and word(w,712)==ptr+1024
        assert word(w,736)==self.address+capsule.FUTURE_PROVIDER_EXPORT
        assert word(w,744)==ptr+1536 and word(w,752)==512 and word(w,760)
        future=C.string_at(ptr+1280,256);provider=C.string_at(ptr+1536,512)
        assert future[:8]==b'HIABFPS1' and word(future,8)==os.getpid()
        assert word(future,72)==self.value and word(future,112)==base+512 and word(future,120)==256
        assert provider[:8]==b'HIAFRCX2'
        assert word(provider,8)==os.getpid()and word(provider,16)==ptr+1536
        assert word(provider,24)==word(w,736)and word(provider,64)==base+512 and word(provider,56)==self.value
        assert word(provider,80)==word(w,760)and word(provider,160)==word(w,664)
        assert word(provider,96)==1 and word(provider,168)==1 and word(provider,176)==0
        assert C.string_at(ptr+2048,2048)==bytes(2048),'BG remains unbound'
        return row
class Fixture:
    def __init__(self,path):
        self.path=path;self.before=set(os.listdir('/proc/self/fd'))
        self.bound=Bound(path);self.bound.bind();self.engine=inv.Engine(self.bound);self.v=inv.Values(self.engine)
        ptr=word(self.bound.owner.context,1152)
        self.provider_ctx=(C.c_char*512).from_address(ptr+1536)
        self.provider=type('ActualFixedProvider',(),{})()
        self.provider.entry=inv.ENTRY(word(self.bound.owner.context,736))
        public=managed.PrivatePublic.__new__(managed.PrivatePublic)
        public.value=self.v;public.calls=0;public.factories=[];public.futures=[]
        public.ctx=(C.c_char*256).from_address(ptr+1280)
        public.image=type('ActualFixedFuture',(),{})()
        public.image.entry=self.bound.owner.lib.hia_background_optimizer_future_public
        public.image.entry.argtypes=[C.c_void_p,C.c_uint64]*3;public.image.entry.restype=C.c_uint32
        assert C.cast(public.image.entry,C.c_void_p).value==word(self.provider_ctx,32)
        self.public=public
        self.baseline=word(self.v.raw(47),48);assert self.baseline==2,self.baseline
    create_native=managed.Fixture.create_native
    acquire_native=managed.Fixture.acquire_native
    def resource(self,fac):
        r=self.create_native(fac);assert word(r,96)==1 and word(r,104)==1 and word(r,112)==0,r.hex()
        resource=self.v.keep(r);weak=triple(self.v.raw(80,a=resource))
        return resource,weak
    def acquire(self,resource):
        r=self.acquire_native(resource)
        assert (word(r,96),word(r,104),word(r,112))==(1,1,0),r.hex()
        strong=self.v.keep(r);return strong,(triple(r,48),triple(r,72))
    def release_factory(self,fac):
        r=self.public.typed(27,*fac);assert word(r,96)==1 and word(r,104)==1,r[:160].hex()
        self.public.factories.remove(fac)
        if word(r,112):facts(self.public.typed(28,fac[0]),0)
    def finish(self):
        for c in list(self.v.held):self.v.drop(c)
        assert word(self.engine.context,176)==word(self.engine.context,184)==0
        assert word(self.provider_ctx,272)==word(self.provider_ctx,112)==0
        for fac in list(self.public.factories):self.release_factory(fac)
        assert word(self.v.raw(47),48)==self.baseline,(word(self.v.raw(47),48),self.baseline)
        self.bound.close()
        assert set(os.listdir('/proc/self/fd'))==self.before

def normal(path,out):
    f=Fixture(path);w=f.bound.owner.context;before=bytes(w)
    r=f.bound.call(0);assert r['status']==6 and bytes(w)==before,r
    assert f.bound.owner.call(3)['status']==2
    fac=f.public.factory();resource,weak=f.resource(fac)
    cls=f.v.keep(f.v.raw(36,a=resource));actual=f.v.keep(f.v.raw(57,arg0=37))
    assert f.v.same(cls,actual);f.v.drop(cls);f.v.drop(actual)
    strong,borrowed=f.acquire(resource)
    value=f.v.scalar('actual one-arena canonical Future')
    f.public.call(22,*borrowed,value=value,kind=1);f.v.drop(value)
    returned=f.v.keep(f.public.call(10,*borrowed),72)
    assert f.v.python_value(returned)=='actual one-arena canonical Future';f.v.drop(returned)
    f.v.drop(strong);f.v.drop(resource)
    f.v.raw(80,a=weak,arg0=1,want=3)
    assert word(f.provider_ctx,272)==0 and word(f.provider_ctx,112)==0
    f.finish()
    return dict(case='trusted-init-canonical-Future-real-result-lastdrop',passed=True,
                same_value_code_and_arena=True,native_nonce_and_context_tokens=True,
                only_supported_mask190=True,real_lastdrop_finalizer=True)

def self_cycle(path,out):
    f=Fixture(path);fac=f.public.factory();resource,weak=f.resource(fac)
    strong,borrowed=f.acquire(resource)
    f.public.call(22,*borrowed,value=resource,kind=1)
    returned=f.v.keep(f.public.call(10,*borrowed),72);assert f.v.same(returned,resource);f.v.drop(returned)
    f.v.drop(strong);f.v.drop(resource)
    assert word(f.v.raw(47),48)==f.baseline+len(f.public.factories)
    f.v.raw(80,a=weak,arg0=1,want=3)
    f.finish()
    return dict(case='canonical-Future-self-result-cycle-actual-GC-finalizer',passed=True)

def container_cycle(path,out):
    f=Fixture(path);fac=f.public.factory();resource,weak=f.resource(fac)
    strong,borrowed=f.acquire(resource);container=f.v.lst([resource])
    f.public.call(22,*borrowed,value=container,kind=1);f.v.drop(container);f.v.drop(strong);f.v.drop(resource)
    f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(case='canonical-Future-list-Future-cycle-actual-GC',passed=True)

def live_future_close(path,out):
    f=Fixture(path);fac=f.public.factory();resource,weak=f.resource(fac)
    before=word(f.bound.owner.context,1184)
    row=f.bound.call(1)
    assert row['status']==6 and row['state']==2 and row['pending']==0,row
    assert word(f.bound.owner.context,1184)==before and word(f.bound.owner.context,680)==190
    strong,borrowed=f.acquire(resource);f.v.drop(strong);f.v.drop(resource)
    f.finish()
    return dict(case='provider-prepare-busy-keeps-owned-Future-and-ready-state',passed=True)

def post_commit_value_busy(path,out):
    f=Fixture(path);value=f.v.scalar('live Value after irreversible Future close')
    pointer=word(f.bound.owner.context,1152)
    row=f.bound.call(1)
    assert row['status']==6 and row['state']==4 and row['pending']==1 and row['stage']==130,row
    assert word(f.bound.owner.context,680)==62 and bytes(f.bound.owner.context)[736:768]==bytes(32)
    assert word(f.public.ctx,24)==1 and word(f.provider_ctx,96)==3
    assert word(f.bound.owner.context,1184)==0 and word(f.bound.owner.context,1152)==pointer
    assert f.v.python_value(value)=='live Value after irreversible Future close'
    again=f.bound.call(2);assert again['status']==6 and again['state']==4 and again['stage']==130,again
    f.v.drop(value);f.bound.close(2)
    assert set(os.listdir('/proc/self/fd'))==f.before
    return dict(case='irreversible-provider-and-global-close-Value-busy-retry',passed=True)

def raw_factory_close(path,out):
    f=Fixture(path);fac=f.public.factory()
    row=f.bound.call(1)
    assert row['status']==6 and row['state']==4 and row['pending']==1 and row['stage']==117,row
    assert word(f.provider_ctx,96)==3 and word(f.public.ctx,24)==0
    assert word(f.bound.owner.context,1184)!=0 and word(f.bound.owner.context,680)==190
    f.release_factory(fac);f.bound.close(2)
    assert set(os.listdir('/proc/self/fd'))==f.before
    return dict(case='raw-factory-keeps-global-context-after-provider-commit',passed=True)

def parallel(path,out):
    f=Fixture(path);fac=f.public.factory();observations=[]
    def delivered(raw,stage):
        status,pending=word(raw,8),word(raw,112)
        assert (word(raw,96),word(raw,104))==(1,1) and all(triple(raw)),(stage,raw.hex())
        assert (status==0 and pending==0)or(status==11 and pending==1),(stage,raw.hex())
        observations.append(dict(stage=stage,status=status,pending=pending))
        return triple(raw)
    def one(i):
        resource=delivered(f.create_native(fac,want=None),'create')
        strong=delivered(f.acquire_native(resource,want=None),'acquire')
        # No borrowed raw pair is used while any independent cleanup is pending.
        for owned in(strong,resource):
            rc,r=f.engine.call(inv.frame(29,a=owned))
            assert rc==0 and r[:8]==b'HIABVR02' and (word(r,88),word(r,96))==(1,1),(rc,r[:128].hex())
            assert word(r,80)<=1 and word(r,8)in(0,11),r[:128].hex()
            if word(r,8)==11:assert word(r,80)==1
            observations.append(dict(stage='drop',status=word(r,8),pending=word(r,80)))
        return i
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        assert list(pool.map(one,range(32)))==list(range(32))
    # The ordinary native query performs one outside-lock drain after all workers.
    assert word(f.v.raw(47),48)==f.baseline+1
    assert word(f.engine.context,176)==word(f.engine.context,184)==0
    assert word(f.provider_ctx,272)==word(f.provider_ctx,112)==0
    f.finish()
    return dict(case='eight-threads-canonical-producer-and-lastdrop',passed=True,calls=32,
                independent_delivery_and_cleanup_facts=observations,actual_pending_drained=True)


def prior_guards(path,out):
    old,oldcap=sideqa.Bound,sideqa.capsule
    sideqa.Bound,sideqa.capsule=Bound,capsule
    try:row=sideqa.guards(path,out)
    finally:sideqa.Bound,sideqa.capsule=old,oldcap
    return dict(case='original-wire-copy-fork-private-profile-guards',**row)

def prior_retirement_faults(path,out):
    old,oldcap=sideqa.Bound,sideqa.capsule
    sideqa.Bound,sideqa.capsule=Bound,capsule
    try:row=sideqa.actual_retirement_failures(path,out)
    finally:sideqa.Bound,sideqa.capsule=old,oldcap
    return dict(case='original-actual-tempdir-code-sidecar-retirement-faults',**row)

def init_faults(path,out):
    import errno
    rows=[]
    for kind,nr,error in (('sidecar-getrandom',318,errno.EIO),('sidecar-mmap',9,errno.ENOMEM),
                          ('Value-token',318,errno.EIO),('code-init',318,errno.EIO),
                          ('Future-getpid',39,errno.EIO),('provider-getrandom',318,errno.EIO)):
        before=set(os.listdir('/proc/self/fd'));b=Bound(path)
        if kind=='Value-token':
            start=b.value;extent=(path.parent/'hia-generation-lease-values.core.bin').stat().st_size
        elif kind=='code-init':
            start=b.code;extent=(path.parent/'code-owner.flat').stat().st_size
        elif kind=='Future-getpid':
            start=C.cast(b.owner.lib.hia_background_optimizer_future_public,C.c_void_p).value;extent=2780
        elif kind=='provider-getrandom':
            start=b.address+capsule.FUTURE_PROVIDER_EXPORT;extent=len(capsule.BRIDGE)-capsule.FUTURE_PROVIDER_EXPORT
        else:start=b.address;extent=len(capsule.OUTER)
        def denied():
            sideqa.fault.deny_fixed_syscall(start,start+extent,nr,error)
            return b.call(0)
        row=sideqa.fault.thread_result(denied)
        assert row['status']!=0 and row['pending']==1 and row['known']==1 and row['state']==4,(kind,row)
        assert word(b.owner.context,72)==1 and word(b.owner.context,1208)==0
        ptr=word(b.owner.context,1152);tokens=int(word(b.owner.context,1184)!=0)
        if ptr:tokens+=int(word(C.string_at(ptr+1280,256),128)!=0)
        assert b.value_probe()==tokens,(kind,b.value_probe(),tokens)
        assert b.owner.call(3)['status']==2
        retry=b.call(2)
        assert retry['status']==0 and retry['state']==2 and retry['pending']==0,(kind,retry)
        assert word(b.owner.context,680)==190 and b.value_probe()==2
        b.close();assert set(os.listdir('/proc/self/fd'))==before
        rows.append(dict(kind=kind,syscall=nr,errno=error,failed=row,actual_native_retry=retry))
    return dict(case='actual-binding-kernel-failures-owned-retry',passed=True,cases=rows)

def concurrent_bind(path,out):
    before=set(os.listdir('/proc/self/fd'));b=Bound(path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        rows=list(pool.map(lambda _:b.call(0),range(8)))
    assert sum(r['status']==0 for r in rows)==1 and sum(r['status']==6 for r in rows)==7,rows
    assert b.value_probe()==2 and word(b.owner.context,72)==1 and word(b.owner.context,680)==190
    b.close();assert set(os.listdir('/proc/self/fd'))==before
    return dict(case='eight-native-binds-exactly-one-owner',passed=True,threads=8)

CASES=(normal,self_cycle,container_cycle,live_future_close,post_commit_value_busy,raw_factory_close,parallel,
       prior_guards,prior_retirement_faults,init_faults,concurrent_bind)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',required=True,type=Path);ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--cases',nargs='*');args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    wanted=set(args.cases or [fn.__name__ for fn in CASES]);rows=[]
    report=dict(schema='hia.generation-future-managed-binding.qualification.v1',passed=False,
                whole_public_runtime_qualified=False,whole_background_qualified=False,
                product=pin(args.owner.read_bytes()),cases=rows)
    try:
        for fn in CASES:
            if fn.__name__ not in wanted:continue
            row=fn(args.owner,args.output);rows.append(row);save(args.output/'partial.json',report)
            print('NATIVE_MANAGED_BINDING_CASE',fn.__name__,flush=True)
        report['passed']=True;report['complete']=len(rows)==len(CASES)
    except BaseException as error:
        report['error']=repr(error);report['traceback']=traceback.format_exc();raise
    finally:save(args.output/'report.json',report)
    print('NATIVE_MANAGED_BINDING_PASS',len(rows),flush=True)
if __name__=='__main__':main()
