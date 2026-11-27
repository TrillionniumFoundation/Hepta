"""Exercise the complete fixed BG DSO without a host-provided entry table."""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,traceback,types
from tools import qualify_hia_background_native_context as old
from tools import qualify_hia_background_native_objects as objects
from tools import qualify_hia_background_native_methods as methods
from tools import qualify_hia_future_native_callbacks as callbacks
from tools import qualify_hia_generation_lease_owner as q
from tools.generate_hia_background_optimizer_native_context import ENTRY_NAMES
get=old.get;cap=old.cap;put=old.put;pin=old.pin;E=old.E;B=old.B
CALL=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def entry(lib,name):
    fn=getattr(lib,name);fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
    return fn
def target(fn):
    p=C.cast(fn,C.c_void_p).value;raw=C.string_at(p,5);assert raw[0]==0xe9
    return p+5+struct.unpack_from('<i',raw,1)[0]
class Fixture(old.Fixture):
    def __init__(self,a):
        self.f=callbacks.Fixture(a.owner)
        self.lib=C.CDLL(str(a.bundle));self.fn=entry(self.lib,'hia_background_native_context')
        self.registry=entry(self.lib,'hia_background_native_registry')
        self.entry=C.cast(self.fn,C.c_void_p).value
        self.ctx=C.create_string_buffer(512);self.calls=[];self.images={}
        self.threshold=C.create_string_buffer((B/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes())
        self.fds=[q.old.sealed((E/'shared-custody'/n).read_bytes())for n in
          ('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin')]
        self.fds.append(os.open(B,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC))
        self.pins=dict(bundle=dict(path=str(a.bundle),**pin(a.bundle.read_bytes())),
                       owner=dict(path=str(a.owner),**pin(a.owner.read_bytes())),
                       threshold=pin(self.threshold.raw[:-1]))
        self.bundle_path=a.bundle
    def init(self):
        raw=bytearray(256);raw[:8]=b'HIABGNI2'
        put(raw,16,C.addressof(self.f.bound.owner.context),2048,*self.fds[:3],
            C.addressof(self.threshold),len(self.threshold)-1,4300,self.fds[3])
        assert raw[88:]==bytes(168)
        reply=self.call(bytes(raw))
        assert get(reply,24)==1 and get(self.ctx,48)==256
        assert get(self.ctx,32)==get(self.f.bound.owner.context,40)
        assert get(self.ctx,40)==C.addressof(self.f.engine.context)
        cfg=C.string_at(get(self.ctx,240),1024);assert cfg[:8]==b'HIABGCF1'and get(cfg,128)==40
        self.captured_table=[get(cfg,136+i*8)for i in range(40)]
        public=entry(self.lib,'hia_background_native_public')
        code_base=C.cast(public,C.c_void_p).value
        raw_obj=self.bundle_path.read_bytes();sh=get(raw_obj,40);count=struct.unpack_from('<H',raw_obj,60)[0]
        ni=struct.unpack_from('<H',raw_obj,62)[0];ns=struct.unpack_from('<IIQQQQIIQQ',raw_obj,sh+64*ni)
        names=raw_obj[ns[4]:ns[4]+ns[5]]
        text=next(struct.unpack_from('<IIQQQQIIQQ',raw_obj,sh+64*i)for i in range(count)
          if names[struct.unpack_from('<I',raw_obj,sh+64*i)[0]:].split(b'\0',1)[0]==b'.text')
        for name,p in zip(ENTRY_NAMES,self.captured_table):
            if name=='future_provider_deferred':
                assert p==get(self.f.engine.context,224)==C.cast(self.f.provider.entry,C.c_void_p).value
            else:
                assert code_base<=p<code_base+text[5],(name,p,code_base,text[5])
        return reply
class Objects(objects.Objects):
    def __init__(self,path,f):
        assert path==f.bundle_path
        self.lib=f.lib
        public=entry(self.lib,'hia_background_native_public');base=target(public)
        finalizer=entry(self.lib,'hia_background_native_finalizer')
        assert target(finalizer)==base+528
        self.entry=CALL(base+512)
        self.f=f;self.calls=[];self.last=None
def context_case(a):
    f=Fixture(a);before=old.open_fds();r=f.init();cfg=C.string_at(get(f.ctx,240),1024)
    duplicated=[get(cfg,64+i*8)for i in range(4)]
    for src,dst in zip(f.fds,duplicated):
        x=os.fstat(src);y=os.fstat(dst);assert(x.st_dev,x.st_ino)==(y.st_dev,y.st_ino)
    held=cap(f.reg(1,data=b'complete native BG DSO context'))
    assert get(f.control(1,6),24)==1
    alias=cap(f.reg(2,held));assert get(f.reg(3,alias),88)==1
    assert get(f.reg(3,held),88)==1
    assert get(f.control(1),24)==2 and get(f.control(2),24)==1
    copied=C.create_string_buffer(f.ctx.raw,512);wire=b'HIABGCQ1'+bytes(120);prior=copied.raw
    f.call(wire,11,ctx=copied);assert copied.raw==prior
    assert get(f.control(1),24)==2 and get(f.control(3),24)==3
    assert get(f.ctx,240)==0 and f.ctx.raw[208:232]==bytes(24)
    assert old.open_fds()==before
    calls=list(f.calls);table=list(f.captured_table);f.finish()
    return dict(case='NI2-static-table-same-Value-real-busy-rollback-close',passed=True,
                host_table_pointer=False,internal_entries=39,one_captured_Future_provider=True,
                actual_context_token_consumed=True,actual_fd_retirement=True,calls=calls)
def original_case(a,name,fn):
    output=a.output/name;output.mkdir()
    args=types.SimpleNamespace(**vars(a));args.output=output;args.objects=a.bundle
    original_fixture=old.Fixture;original_objects=objects.Objects
    old.Fixture=Fixture;objects.Objects=Objects
    try:return fn(args)
    finally:old.Fixture=original_fixture;objects.Objects=original_objects
def main():
    p=argparse.ArgumentParser()
    for n in('owner','bundle','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--cases',nargs='*',default=['context','objects','methods'])
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    report=dict(schema='hia.BG.complete-native-child.component.v1',passed=False,
       whole_background_closed=False,kind6_finalizer_bound=False,queued_tasks_qualified=False,
       native_static_table=True,host_product_callbacks=False,
       bundle=dict(path=str(a.bundle),**pin(a.bundle.read_bytes())),cases=[])
    try:
        if 'context'in a.cases:report['cases'].append(context_case(a));print('ACTUAL_BG_FIXED_CONTEXT_PASS',flush=True)
        for name,fn in(('objects',objects.qualify),('methods',methods.qualify)):
            if name not in a.cases:continue
            result=original_case(a,name,fn);report['cases'].append(dict(case=name,passed=True,original_assertions_unchanged=True,report=result))
            print('ACTUAL_BG_FIXED_ORIGINAL_PASS',name,len(result['cases']),flush=True)
        report['passed']=True
    except BaseException as e:
        report.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
