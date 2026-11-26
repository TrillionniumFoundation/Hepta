"""Actual native BG global-context initialization and retirement."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_future_native_callbacks as callbacks
import tools
if str(Path(__file__).resolve().parent)not in tools.__path__:tools.__path__.insert(0,str(Path(__file__).resolve().parent))
from tools.qualify_hia_generation_lease_owner_provider import ObjectImage,libc
from tools.qualify_hia_multiversion_components import Image
from tools.generate_hia_background_optimizer_native_context import ENTRY_NAMES
E=Path('/home/qian-qi/hia-followthrough-evidence-20261126-620a')
B=Path(__file__).resolve().parents[1]
get=lambda b,p:struct.unpack_from('<Q',b,p)[0]
cap=lambda b,p=16:struct.unpack_from('<3Q',b,p)
def put(b,p,*v):struct.pack_into('<'+'Q'*len(v),b,p,*v)
def ptr(x):return C.cast(x,C.c_void_p).value
def pin(x):return dict(bytes=len(x),sha256=hashlib.sha256(x).hexdigest())
class Fixture:
    def __init__(self,a):
        self.f=callbacks.Fixture(a.owner);self.images={};self.pins={}
        self.imports={n:ptr(getattr(libc,n))for n in ('malloc','free')}
        def so(name,path,symbol):
            lib=C.CDLL(str(path));entry=getattr(lib,symbol);entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32
            self.images[name]=(lib,entry);self.pins[name]=dict(path=str(path),**pin(path.read_bytes()));return ptr(entry)
        def obj(name,path):
            im=ObjectImage(path.read_bytes(),self.imports);self.images[name]=im;self.pins[name]=dict(path=str(path),**pin(path.read_bytes()));return ptr(im.entry)
        def bare(name,path):
            im=Image(path);self.images[name]=im;self.pins[name]=dict(path=str(path),**pin(path.read_bytes()));return ptr(im.entry)
        self.entry=so('context',a.context/'context.so','hia_background_native_context')
        self.fn=self.images['context'][1]
        entries={}
        entries['registry']=so('registry',a.context/'registry.so','hia_background_native_registry');self.registry=self.images['registry'][1]
        for name,base,sym in [
          ('queue',a.dependencies,'hia_mv_background_queue'),('decimal',a.dependencies,'hia_mv_values')]:
            entries[name]=so(name,base/('multiversion_background_queue.so'if name=='queue'else'multiversion_values.so'),sym)
        entries['ledger']=so('ledger',a.ledger/'ledger.so','hia_background_ledger_managed')
        entries['jobs']=so('jobs',a.jobs,'hia_background_optimizer_jobs_owner')
        for name in ('job_refs','worker','submission','business','execution','shutdown','report'):
            path=getattr(a,'worker',None)if name=='worker'else None
            entries[name]=so(name,path or a.core/(name+'.so'),'hia_background_'+name+('_deferred'if name=='report'else'_managed'))
        entries['account']=so('account',a.consumers/'account.so','hia_background_account_managed')
        entries['snapshot']=so('snapshot',a.snapshot/'snapshot.so','hia_background_snapshot_managed')
        for name in ('structure','transport','freeze'):
            entries[name+'_deferred']=so(name+'_deferred',a.nested/(name+'.so'),'hia_background_value_'+name+'_deferred')
        mapping=dict(constructor='background_optimizer_public_constructor',options='background_optimizer_constructor_options',
          bridge_paths='background_optimizer_bridge_paths',constructor_binding='background_optimizer_constructor_binding',
          path_value='native_path_value',path_resolve='native_path_resolve',posix_factory='native_posix_path_factory',
          verifier='background_optimizer_verify_program',prepare_process='multiversion_prepare_process',
          transport_compat='background_optimizer_value_transport',freeze_compat='background_optimizer_value_freeze')
        for name,module in mapping.items():entries[name]=obj(name,a.constructor/(module+'.o'))
        mapping=dict(path_error='ndu_rank_native_owner_error',path_string_codec='native_path_string_codec',
          json_capture='background_optimizer_json_capture',sha256='sha256_stream',checked_freezer='background_optimizer_freeze',
          verify_raw='background_optimizer_verify_raw',structure_compat='background_optimizer_value_structure')
        for name,module in mapping.items():entries[name]=bare(name,a.constructor/(module+'.flat'))
        entries['decision']=obj('decision',E/'background-bound-chain-native-v1/decision_bound.o')
        entries['rank']=bare('rank',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/ndu-rank-engine-native-v2/rank-engine.flat'))
        for name,module in [('admission','background_optimizer_admission'),('decision_policy','background_optimizer_decision')]:
            entries[name]=bare(name,a.pure/(module+'.flat'))
        entries['future_provider_deferred']=ptr(self.f.provider.entry)
        assert set(entries)==set(ENTRY_NAMES),(set(entries)^set(ENTRY_NAMES))
        self.table=(C.c_uint64*len(ENTRY_NAMES))(*(entries[n]for n in ENTRY_NAMES))
        self.threshold=C.create_string_buffer((B/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes())
        self.ctx=C.create_string_buffer(512);self.calls=[]
        from tools import qualify_hia_generation_lease_owner as toolsqa
        self.fds=[toolsqa.old.sealed((E/'shared-custody'/n).read_bytes())for n in
          ('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin')]
        self.fds.append(os.open(B,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC))
    def init(self):
        r=bytearray(256);r[:8]=b'HIABGNI1'
        put(r,16,C.addressof(self.f.bound.owner.context),2048,*self.fds[:3],C.addressof(self.threshold),len(self.threshold)-1,4300,self.fds[3],C.addressof(self.table),len(ENTRY_NAMES)*8)
        return self.call(bytes(r))
    def call(self,wire,want=0,ctx=None,raw_rc=0):
        ctx=self.ctx if ctx is None else ctx
        s=C.create_string_buffer(wire,len(wire));o=C.create_string_buffer(16416);C.memset(o,0xa5,len(o))
        rc=self.fn(s,len(wire),o,16384,ctx,512);r=o.raw[:16384]
        assert rc==raw_rc and s.raw==wire and o.raw[16384:]==b'\xa5'*32,(rc,r[:128].hex())
        if raw_rc==0:
            assert r[:8]==b'HIABGCR1'and get(r,8)==want,(want,r[:128].hex())
            self.calls.append(dict(op=get(wire,8),status=get(r,8),known=get(r,16),state=get(r,24),flags=get(r,56),mapping=get(r,64),queue=get(r,72),unknown=get(r,80),incomplete=get(r,88)))
        return r
    def control(self,op,want=0):
        r=bytearray(128);r[:8]=b'HIABGCQ1';put(r,8,op);return self.call(bytes(r),want)
    def reg(self,op,a=(0,0,0),data=b''):
        r=bytearray(128+len(data));r[:8]=b'HIABGRG1';put(r,8,op);put(r,24,*a)
        if op==1:put(r,72,len(data));r[128:]=data
        s=C.create_string_buffer(bytes(r),len(r));o=C.create_string_buffer(2048)
        rc=self.registry(s,len(r),o,2048,C.addressof(self.ctx)+256,256)
        assert rc==0 and o.raw[:8]==b'HIABGRR1'and get(o,8)==0,(op,rc,o.raw[:128].hex())
        return o.raw
    def finish(self):
        for fd in self.fds:
            try:os.close(fd)
            except OSError:pass
        self.f.finish()
def open_fds():
    out={}
    for name in os.listdir('/proc/self/fd'):
        try:
            s=os.fstat(int(name))
        except OSError:
            continue
        out[name]=(s.st_dev,s.st_ino,s.st_mode)
    return out
def qualify(a):
    f=Fixture(a);before=open_fds();r=f.init()
    assert get(r,16)==1 and get(r,24)==1 and get(f.ctx,128)!=0 and get(f.ctx,48)==256
    assert get(f.ctx,32)==get(f.f.bound.owner.context,40)and get(f.ctx,40)==C.addressof(f.f.engine.context)
    cfg=C.string_at(get(f.ctx,240),1024)
    assert cfg[:8]==b'HIABGCF1'and get(cfg,128)==40
    assert [get(cfg,136+i*8)for i in range(40)]==list(f.table)
    dup=[get(cfg,64+i*8)for i in range(4)];assert len(set(dup))==4
    for original,copyfd in zip(f.fds,dup):
        a1=os.fstat(original);b1=os.fstat(copyfd);assert (a1.st_dev,a1.st_ino)==(b1.st_dev,b1.st_ino)
    after_init=open_fds()
    assert set(after_init)-set(before)==set(map(str,dup)),(before,after_init,dup)
    assert all(after_init[k]==v for k,v in before.items())
    q=f.control(0);assert get(q,24)==1 and get(q,40)==get(q,48)==0
    # This real registry object keeps prepare-close busy; no flags are forged.
    obj=cap(f.reg(1,data=b'actual BG registry custody'))
    busy=f.control(1,6);assert get(busy,24)==1
    alias=cap(f.reg(2,obj));assert get(f.reg(7,obj),72)==0
    ack=f.reg(3,alias);assert (get(ack,80),get(ack,88))==(1,1)
    assert get(f.reg(7,obj),72)==1
    ack=f.reg(3,obj);assert (get(ack,80),get(ack,88))==(1,1)
    assert get(f.control(1),24)==2
    assert get(f.control(2),24)==1
    copy=C.create_string_buffer(f.ctx.raw,512);wire=bytearray(128);wire[:8]=b'HIABGCQ1'
    before_copy=copy.raw;reply=f.call(bytes(wire),11,ctx=copy);assert copy.raw==before_copy and get(reply,16)==0
    assert get(f.control(1),24)==2
    end=f.control(3);assert get(end,24)==3 and get(end,56)==get(end,64)==get(end,72)==get(end,80)==get(end,88)==0
    assert f.ctx.raw[208:232]==bytes(24)and get(f.ctx,240)==0
    assert open_fds()==before
    assert get(f.control(4),24)==3
    calls=f.calls;products=f.pins;f.finish()
    return dict(schema='hia.BG.native-context.component.v1',passed=True,component_qualified=True,
      whole_background_closed=False,kind6_publication_enabled=False,
      same_physical_value_entry=True,actual_context_token_consumed=True,actual_registry_refs_consumed=True,
      original_tool_fds_dup_and_closed=True,prepare_busy_and_rollback=True,copied_context_rejected=True,
      product_entries=products,entry_names=ENTRY_NAMES,calls=calls)
def main():
    p=argparse.ArgumentParser()
    for n in ('owner','context','dependencies','ledger','jobs','core','consumers','snapshot','nested','constructor','pure','output'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True);r=dict(passed=False,whole_background_closed=False)
    try:r=qualify(a)
    except BaseException as e:r.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print('ACTUAL_BG_CONTEXT_LIFETIME_PASS',len(r['calls']),flush=True)
if __name__=='__main__':main()
