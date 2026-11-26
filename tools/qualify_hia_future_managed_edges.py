"""Actual managed Future edges in one physical native Value image.

The fixture captures trusted native component bindings. It does not substitute a
Python finalizer or claim that the final enclosing bootstrap is complete.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,signal,struct,subprocess
from tools.qualify_hia_multiversion_components import Image,ENTRY
from tools.qualify_hia_result_value_records import Values,frame as value_frame
from tools.qualify_hia_future_retirement import Public,facts
from tools.qualify_hia_generation_lease_owner_provider import ObjectImage,libc,get
from tools import generate_hia_future_resource_owner_packer as provider_spec
from tools import generate_hia_future_resource_finalizer_adapter_packer as adapter_spec
from tools import generate_hia_background_optimizer_future_public_cleanup_packer as public_spec
from tools.qualify_hia_future_value_kinds import PUBLIC
ROOT=Path(__file__).resolve().parents[1]
ZERO=(0,0,0)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def cap(b,p):return struct.unpack_from('<3Q',b,p)
def put(b,p,*v):struct.pack_into('<'+'Q'*len(v),b,p,*v)
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def address(fn):return C.cast(fn,C.c_void_p).value
def packed(image,wire):
    out=C.create_string_buffer(16<<20);work=C.create_string_buffer(16<<20)
    n=image(wire,out,work);assert 0<n<(16<<20),n
    return out.raw[:n]
def build(original,compiler,value_path,out,value_qualification=None):
    from tools import generate_hia_future_resource_registry_packer as registry_spec
    previous=json.loads((original/'build.json').read_text())
    assert pin(compiler.read_bytes())==previous['compiler']
    value=value_path.read_bytes()
    if value_qualification is None:
        assert pin(value)==dict(bytes=3066003,sha256='267d6ebf87a84077d37f9bd6e4de819d537157f5b566974c738eea4b0dfbd7aa')
        qualified_value=dict(frozen_commit='154faaae294a01bb822f3b1d9d6439da5d0f4fe0',product=pin(value))
    else:
        qraw=value_qualification.read_bytes();q=json.loads(qraw)
        assert q['component_qualified'] is True and q['original_six_campaigns_qualified'] is True
        qp=q['construction']['products']['value-component.flat']
        assert pin(value)=={k:qp[k]for k in('bytes','sha256')}
        qualified_value=dict(path=str(value_qualification.resolve()),receipt=pin(qraw),product=pin(value))
    names=PUBLIC+('background_optimizer_future_public_cleanup','background_optimizer_future_public_cleanup_packer',
                  'future_resource_owner','future_resource_owner_packer','future_resource_registry',
                  'future_resource_registry_packer','future_resource_finalizer_adapter','future_resource_finalizer_adapter_packer')
    out.mkdir(parents=True,exist_ok=False);flats={};modules=[];source_files={}
    for name in names:
        path='examples/hia_bootstrap/'+name+'.hepta';raw=(ROOT/path).read_bytes();pair=[]
        source_files[path]=pin(raw)
        for related in('tools/generate_hia_'+name+'.py','tools/hia_'+name+'_bridge.S'):
            if (ROOT/related).exists():source_files[related]=pin((ROOT/related).read_bytes())
        for _ in range(2):
            process=subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)
            assert process.returncode==0 and process.stdout and not process.stderr,(name,process.returncode,process.stderr)
            pair.append(process.stdout)
        assert pair[0]==pair[1];flats[name]=pair[0];(out/(name+'.flat')).write_bytes(pair[0])
        modules.append(dict(source_path=path,source=pin(raw),flat=pin(pair[0]),double_compile_identical=True))
        print('MANAGED_NATIVE_COMPILE',name,len(pair[0]),flush=True)
    notify=(original/'hia-future-notify.core.bin').read_bytes()
    assert pin(notify)==dict(bytes=80226,sha256='4a06fc521a47285685a6632e0f17b876364ee5e934bb81f5eb3f4195dc263580')
    assert previous['products']['hia-future-notify.core.bin']==pin(notify)
    parts=[flats[n]for n in PUBLIC]+[value,notify,flats['background_optimizer_future_public_cleanup']]
    products={'hia-result-value.core.bin':value,'hia-future-notify.core.bin':notify}
    image=Image(out/'background_optimizer_future_public_cleanup_packer.flat')
    for mode,ext in((0,'o'),(1,'core.bin')):
        wire=b'HIABFPP3'+struct.pack('<11Q',9,*map(len,parts),mode)+b''.join(parts)
        actual=packed(image,wire)
        assert actual==(public_spec.reference_flat(parts)if mode else public_spec.reference_object(parts))
        products['hia-future-public.'+ext]=actual
    for label,role_names,spec in(
        ('owner',('future_resource_owner','future_resource_registry'),provider_spec),
        ('registry',('future_resource_registry',),registry_spec),
        ('adapter',('future_resource_finalizer_adapter',),adapter_spec)):
        payloads=[flats[n]for n in role_names]
        wire=struct.pack('<'+'Q'*(len(payloads)+2),spec.MAGIC,len(payloads),*map(len,payloads))+b''.join(payloads)
        actual=packed(Image(out/(role_names[0]+'_packer.flat')),wire)
        assert actual==spec.reference_object(payloads)
        products['future-resource-'+label+'.o']=actual
    actual_bridge=out/'actual-adapter-bridge.o'
    subprocess.run(['as','--64',str(ROOT/'tools/hia_future_resource_finalizer_adapter_bridge.S'),'-o',str(actual_bridge)],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(actual_bridge),str(actual_bridge)+'.bin'],check=True,capture_output=True)
    assert Path(str(actual_bridge)+'.bin').read_bytes()==adapter_spec.BRIDGE
    offsets={};at=len(public_spec.BRIDGE)
    for name,part in zip(public_spec.ROLES,parts):
        at=(at+15)&~15;offsets[name]=at
        assert products['hia-future-public.core.bin'][at:at+len(part)]==part;at+=len(part)
    for name,raw in products.items():(out/name).write_bytes(raw)
    for name,expected in source_files.items():assert pin((ROOT/name).read_bytes())==expected,name
    report=dict(schema='hepta.hia.future-managed-native-build.v2',component_qualified=False,
                whole_public_future_closed=False,compiler=pin(compiler.read_bytes()),modules=modules,source_files=source_files,
                products={n:pin(b)for n,b in products.items()},role_offsets=offsets,
                value_qualification=qualified_value,notify_dependency=dict(build=str(original/'build.json'),build_pin=pin((original/'build.json').read_bytes()),product=pin(notify)),
                native_pack=True,independent_byte_comparison=True,actual_adapter_bridge_identical=True)
    save(out/'build.json',report);return report

class Engine:
    def __init__(self,image,offset):
        self.image=image;self.entry=ENTRY(image.address+offset);self.context=C.create_string_buffer(256);self.calls=0
        r=self.q(0,arg0=4300);assert get(r,8)==0
    def call(self,raw,on=32768):
        src=C.create_string_buffer(raw,len(raw));out=C.create_string_buffer(on)
        rc=self.entry(src,len(raw),out,on,self.context,256);self.calls+=1
        assert src.raw==raw
        return rc,out.raw
    def q(self,op,*,magic=None,want=0,**kw):
        raw=bytearray(value_frame(op,**kw))
        if op>=48:raw[:8]=b'HIABVQ05'
        if magic is not None:raw[:8]=magic
        rc,r=self.call(bytes(raw))
        expected=b'HIABVR02'if op in(29,30,31,77,78,79,92,93)else b'HIABVR01'
        assert rc==0 and r[:8]==expected,(op,rc,r[:128].hex())
        if want is not None:assert get(r,8)==want,(op,want,r[:128].hex())
        return r

class PrivatePublic(Public):
    def call(self,op,fid=ZERO,cap=ZERO,value=ZERO,kind=0,status=0,fn=0):
        raw=bytearray(192);raw[:8]=b'HIABFP04';put(raw,8,op)
        for at,part in ((16,fid),(40,cap),(64,value)):put(raw,at,*part)
        put(raw,96,kind);put(raw,88,fn)
        src=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(b'\xa5'*65568,65568)
        rc=self.image.entry(src,192,out,65536,self.ctx,256);self.calls+=1;r=out.raw[:65536]
        assert src.raw==bytes(raw)and out.raw[65536:]==b'\xa5'*32
        assert rc==0 and r[:8]==b'HIABFRP3',(op,rc,r[:192].hex())
        assert all(get(r,p)<=1 for p in(128,136,144)),r[:192].hex()
        if status is not None:assert get(r,8)==status,(op,status,r[:192].hex())
        return r
    def typed(self,op,fid=ZERO,owned=ZERO,status=0):
        return self.call(op,fid,owned,status=status)

class Fixture:
    def __init__(self,out):
        self.out=out;self.build=json.loads((out/'build.json').read_text())
        self.image=Image(out/'hia-future-public.core.bin')
        self.engine=Engine(self.image,self.build['role_offsets']['value']);self.v=Values(self.engine)
        self.public=PrivatePublic(self.v,self.image)
        self.baseline_caps=get(self.engine.q(47),48)
        assert self.baseline_caps==1, self.baseline_caps
        vc=self.engine.context;self.provider_ctx=C.create_string_buffer(512);self.adapter_ctx=C.create_string_buffer(256)
        imports={n:address(getattr(libc,n))for n in('malloc','free')}
        imports.update(hia_resource_future=self.image.address,hia_resource_values=address(self.engine.entry),hia_owner_carrier=self.image.address)
        self.provider=ObjectImage((out/'future-resource-owner.o').read_bytes(),imports)
        ai=dict(imports,hia_resource_owner=self.provider.base)
        self.adapter=ObjectImage((out/'future-resource-adapter.o').read_bytes(),ai)
        assert get(self.public.ctx,72)==address(self.engine.entry)and get(self.public.ctx,112)==C.addressof(vc)
        nonce=int.from_bytes(os.getrandom(8),'little')or 1
        put(vc,128,self.adapter.base,C.addressof(self.adapter_ctx),256,nonce)
        # Mask is enabled only after the real adapter and provider are bound.
        owner=C.addressof(self.provider_ctx)
        prefix=[int.from_bytes(b'HIAFRCX2','little'),os.getpid(),owner,self.provider.base,self.image.address,C.addressof(self.public.ctx),256,
                address(self.engine.entry),C.addressof(vc),256,0,0,0,0,0,0,0,self.provider.base+provider_spec.REGISTRY_OFFSET,owner+256,256,nonce]
        for i,x in enumerate(prefix):put(self.provider_ctx,i*8,x)
        self.control(0)
        pnonce=get(self.provider_ctx,80)
        ap=[int.from_bytes(b'HIAFRAX1','little'),os.getpid(),C.addressof(self.adapter_ctx),self.adapter.base,self.provider.base,
            owner,512,address(self.engine.entry),C.addressof(vc),256,nonce,pnonce]
        for i,x in enumerate(ap):put(self.adapter_ctx,i*8,x)
        put(vc,224,self.provider.base,owner,512,pnonce);put(vc,168,128)
        self.events=[]
    def producer(self,raw,want=0):
        src=C.create_string_buffer(raw,len(raw));out=C.create_string_buffer(160)
        rc=self.provider.entry(src,len(raw),out,128,self.provider_ctx,512);r=out.raw[:128]
        assert rc==0 and r[:8]==b'HIAFRR01',(rc,r.hex())
        if want is not None:assert get(r,8)==want,(raw[:16].hex(),r.hex())
        return r
    def control(self,op,want=0):
        return self.producer(b'HIAFRCQ1'+struct.pack('<Q',op)+bytes(112),want)
    def capture(self,fac,fut):
        raw=bytearray(128);raw[:8]=b'HIAFRQ01';put(raw,16,*fut[0]);put(raw,40,*fut[1]);put(raw,64,*fac[1])
        r=self.producer(bytes(raw));assert get(r,16)==1;return cap(r,24)
    def bind_cell(self,fac,fut,resource,owned):
        r=self.public.call(17,*fac);entry,ctx,n=cap(r,72);assert n==256
        identity=get(self.public.call(21,*fut),96)
        raw=bytearray(128);raw[:8]=b'HIABFQ05';put(raw,8,22);put(raw,24,*fut[1]);put(raw,48,*resource)
        put(raw,72,get(self.provider_ctx,80));put(raw,80,*owned);put(raw,104,identity)
        src=C.create_string_buffer(bytes(raw),128);out=C.create_string_buffer(16384)
        rc=ENTRY(entry)(src,128,out,16384,ctx,256);r=out.raw
        assert rc==0 and r[:8]==b'HIABFR03'and get(r,8)==0,(rc,r[:192].hex())
        assert get(r,16)==7 and get(r,64)==identity and get(r,48)==get(self.provider_ctx,80)
        return cap(r,24)
    def make(self):
        fac=self.public.factory();fut=self.public.make(fac);owned=self.capture(fac,fut)
        r=self.engine.q(48,arg0=7,tail=struct.pack('<3Q',*owned))
        assert (get(r,88),get(r,96))==(1,1)and get(r,16)==8,r[:128].hex()
        resource=self.v.keep(r);weak=self.bind_cell(fac,fut,resource,owned)
        return fac,fut,owned,resource,weak
    def create_native(self,fac,want=0):
        raw=bytearray(128);raw[:8]=b'HIAFRQ02'
        put(raw,16,*fac[0]);put(raw,64,*fac[1])
        src=C.create_string_buffer(bytes(raw),128);out=C.create_string_buffer(160)
        rc=self.provider.entry(src,128,out,128,self.provider_ctx,512);r=out.raw[:128]
        assert rc==0 and r[:8]==b'HIAFRR02',(rc,r.hex())
        assert src.raw==bytes(raw) and all(get(r,p)<=1 for p in(96,104,112))
        if want is not None:assert get(r,8)==want,(want,r.hex())
        return r
    def acquire_native(self,value,want=0):
        raw=b'HIAFRQ03'+struct.pack('<4Q',0,*value)+bytes(88)
        src=C.create_string_buffer(raw,128);out=C.create_string_buffer(160)
        rc=self.provider.entry(src,128,out,128,self.provider_ctx,512);r=out.raw[:128]
        assert rc==0 and r[:8]==b'HIAFRR03',(rc,r.hex())
        assert src.raw==raw and all(get(r,p)<=1 for p in(96,104,112))
        if want is not None:assert get(r,8)==want,(want,r.hex())
        return r
    def borrowed(self,owned):
        raw=b'HIAFRQ01'+struct.pack('<4Q',3,*owned)+bytes(88);r=self.producer(raw)
        return cap(r,48),cap(r,72)
    def release_raw(self,fac,fut):
        facts(self.public.typed(26,*fut),1);self.public.futures.remove(fut)
        r=self.public.typed(27,*fac);assert get(r,96)==1;r=self.public.factories.remove(fac)
    def close(self):
        assert get(self.engine.q(47),48)==self.baseline_caps,self.engine.q(47)[:128].hex()
        assert get(self.provider_ctx,272)==0 and get(self.provider_ctx,112)==0
        self.control(1);self.control(3)
        facts(self.public.typed(29),1)
        assert get(self.engine.q(47),48)==0, self.engine.q(47)[:128].hex()
        # Finalizer binding remains valid until all actual context tokens retire.
        r=self.engine.q(30);assert (get(r,80),get(r,88),get(r,96))==(0,1,1),r[:128].hex()

def self_cycle(out):
    f=Fixture(out);v=f.v;p=f.public
    fac,fut,owned,resource,weak=f.make();print('MANAGED_CYCLE_CREATED',flush=True)
    typ=v.keep(v.raw(36,a=resource));canonical=cap(f.engine.q(57,arg0=37),24)
    assert v.same(typ,canonical);v.drop(typ);f.engine.q(29,a=canonical)
    p.call(22,*fut,value=resource,kind=1);print('MANAGED_SELF_RESULT_COMMITTED',flush=True)
    returned=v.keep(p.call(10,*fut),72);assert v.same(returned,resource);v.drop(returned)
    f.release_raw(fac,fut);print('MANAGED_CALLER_RAW_ALIASES_RETIRED',flush=True)
    borrowed=f.borrowed(owned);assert borrowed[0]==fut[0]
    before=get(f.engine.q(47),48);assert before>=2
    v.drop(resource);print('MANAGED_LAST_EXTERNAL_DROP_RETURNED',flush=True)
    assert get(f.engine.q(47),48)==f.baseline_caps,f.engine.q(47)[:128].hex()
    f.engine.q(80,a=weak,arg0=1,want=3)
    assert get(f.provider_ctx,272)==0 and get(f.provider_ctx,112)==0
    f.close()
    return dict(case='actual-self-result-cycle-native-finalizer-and-registry-retirement',passed=True,
                value_image=f.build['products']['hia-result-value.core.bin'],same_physical_value_entry=True,
                native_finalizer=True,actual_gc_edges=True,actual_weak_stale=True)


def finish_cycle(f,weak_caps):
    assert not f.v.held, f.v.held
    assert get(f.engine.q(47),48)==f.baseline_caps,f.engine.q(47)[:128].hex()
    for weak in weak_caps:f.engine.q(80,a=weak,arg0=1,want=3)
    assert get(f.provider_ctx,272)==0 and get(f.provider_ctx,112)==0
    f.close()

def container_cycle(out):
    f=Fixture(out);fac,fut,owned,resource,weak=f.make()
    nested=f.v.lst([resource]);f.public.call(22,*fut,value=nested,kind=1)
    actual=f.v.keep(f.public.call(10,*fut),72);assert f.v.same(actual,nested)
    f.v.drop(actual);f.v.drop(nested);f.release_raw(fac,fut)
    f.v.drop(resource);finish_cycle(f,[weak])
    return dict(case='actual-Future-list-Future-cycle',passed=True,native_finalizer=True,actual_managed_edge=True)

def mutual_cycle(out):
    f=Fixture(out);a=f.make();b=f.make()
    f.public.call(22,*a[1],value=b[3],kind=1);f.public.call(22,*b[1],value=a[3],kind=1)
    for item,expected in((a,b),(b,a)):
        actual=f.v.keep(f.public.call(10,*item[1]),72);assert f.v.same(actual,expected[3]);f.v.drop(actual)
        f.release_raw(item[0],item[1])
    f.v.drop(a[3])
    promoted=cap(f.engine.q(80,a=a[4],arg0=1),24)
    assert promoted[0] and get(f.engine.q(7,a=promoted),16)==8
    # The first caller cap is consumed, but the second Future's true managed
    # edge still makes the first resource promotable.
    f.engine.q(29,a=promoted)
    f.v.drop(b[3]);finish_cycle(f,[a[4],b[4]])
    return dict(case='actual-two-Future-mutual-cycle-with-live-weak-promotion',passed=True,native_finalizers=2)

def exception_cycle(out):
    f=Fixture(out);fac,fut,owned,resource,weak=f.make()
    f.public.call(23,*fut,value=resource,kind=2)
    actual=f.v.keep(f.public.call(11,*fut),72);assert f.v.same(actual,resource);f.v.drop(actual)
    f.release_raw(fac,fut);f.v.drop(resource);finish_cycle(f,[weak])
    return dict(case='actual-self-exception-cycle',passed=True,native_finalizer=True,actual_managed_edge=True)

def retained_return(out):
    f=Fixture(out);fac,fut,owned,resource,weak=f.make()
    f.public.call(22,*fut,value=resource,kind=1)
    returned=f.v.keep(f.public.call(10,*fut),72)
    identity=(get(f.v.raw(7,a=resource),104),get(f.v.raw(7,a=resource),112))
    f.release_raw(fac,fut);f.v.drop(resource)
    assert (get(f.v.raw(7,a=returned),104),get(f.v.raw(7,a=returned),112))==identity
    promoted=cap(f.engine.q(80,a=weak,arg0=1),24)
    assert f.v.same(promoted,returned);f.engine.q(29,a=promoted)
    f.v.drop(returned);finish_cycle(f,[weak])
    return dict(case='returned-result-is-external-root-until-its-real-last-drop',passed=True,native_finalizer=True)

def callback_environment_cycle(out):
    f=Fixture(out);fac,fut,owned,resource,weak=f.make();calls=[]
    @ENTRY
    def callback(s,sn,o,on,w,wn):
        calls.append('unexpected-invocation')
        return 0xffffffff
    f.public.call(13,*fut,value=resource,fn=address(callback))
    assert calls==[]
    f.release_raw(fac,fut);f.v.drop(resource)
    finish_cycle(f,[weak]);assert calls==[]
    return dict(case='pending-callback-environment-self-cycle-retires-without-invocation',
                passed=True,actual_managed_edge=True,native_finalizer=True,callback_invocations=0)

def callback_active_pin(out):
    f=Fixture(out);fac,fut,owned,resource,weak=f.make();calls=[];errors=[]
    value=f.v.scalar(None)
    @ENTRY
    def callback(s,sn,o,on,w,wn):
        try:
            raw=C.string_at(s,sn);assert raw[:8]==b'HIAFCBQ1' and sn==192
            assert cap(raw,64)!=resource
            actual_env=cap(raw,64);assert f.v.same(actual_env,resource)
            f.v.drop(resource)
            promoted=cap(f.engine.q(80,a=weak,arg0=1),24)
            assert get(f.engine.q(49,a=promoted),16)==7
            f.engine.q(29,a=promoted)
            reply=bytearray(128);reply[:8]=b'HIAFCBR1'
            C.memmove(o,bytes(reply),128);calls.append('same-live-Future-after-caller-last-drop');return 0
        except BaseException as e:errors.append(repr(e));return 0xffffffff
    f.public.call(13,*fut,value=resource,fn=address(callback))
    f.release_raw(fac,fut);borrowed=f.borrowed(owned)
    f.public.call(22,*borrowed,value=value,kind=1)
    assert calls==['same-live-Future-after-caller-last-drop'] and not errors,(calls,errors)
    # This component call returns the actual deferred queue to its enclosing
    # owner; the same native Value entry performs the actual finalizer drain.
    f.engine.q(56);f.v.drop(value);finish_cycle(f,[weak])
    return dict(case='callback-execution-holds-real-Future-Value-pin-through-caller-drop',
                passed=True,native_finalizer=True,callback_fixture='explicit-QA-oracle-only',
                native_callable_dispatcher_closed=False)

def callback_diagnostic_cycle(out):
    import tempfile
    f=Fixture(out);fac,fut,owned,resource,weak=f.make();calls=[];errors=[]
    value=f.v.scalar(None)
    error=f.v.dictionary([('class','ValueError'),('message','callback env cycle Ω')])
    @ENTRY
    def callback(s,sn,o,on,w,wn):
        try:
            raw=C.string_at(s,sn);assert raw[:8]==b'HIAFCBQ1' and sn==192
            assert f.v.same(cap(raw,64),resource)
            returned=cap(f.engine.q(91,a=error),24)
            f.v.drop(resource)
            reply=bytearray(128);reply[:8]=b'HIAFCBR1';put(reply,8,1);put(reply,24,*returned)
            C.memmove(o,bytes(reply),128);calls.append('actual-owned-error-return');return 0
        except BaseException as e:errors.append(repr(e));return 0xffffffff
    f.public.call(13,*fut,value=resource,fn=address(callback))
    f.release_raw(fac,fut);borrowed=f.borrowed(owned)
    with tempfile.TemporaryFile() as log:
        saved=os.dup(2)
        try:
            os.dup2(log.fileno(),2)
            f.public.call(22,*borrowed,value=value,kind=1)
        finally:os.dup2(saved,2);os.close(saved)
        log.seek(0);text=log.read()
    assert calls==['actual-owned-error-return']and not errors,(calls,errors)
    assert text=='exception calling callback\nValueError: callback env cycle Ω\n'.encode(),text
    f.engine.q(56)
    for held in list(f.v.held):f.v.drop(held)
    finish_cycle(f,[weak])
    return dict(case='caught-callback-error-native-diagnostic-and-all-temporary-custody',
                passed=True,native_utf8_diagnostic=text.decode(),native_finalizer=True,
                callback_fixture='explicit-QA-oracle-only',native_callable_dispatcher_closed=False)

def actual_callback_cycles(out):
    rows=[]
    for test in(callback_environment_cycle,callback_active_pin,callback_diagnostic_cycle):
        row=test(out);rows.append(row);print('MANAGED_CALLBACK_CYCLE_PASS',row['case'],flush=True)
    return rows

def native_canonical_constructor(out):
    f=Fixture(out);fac=f.public.factory()
    r=f.create_native(fac);assert (get(r,16),get(r,96),get(r,104),get(r,112))==(7,1,1,0),r.hex()
    resource=f.v.keep(r);weak=cap(f.engine.q(80,a=resource),24)
    typ=f.v.keep(f.v.raw(36,a=resource));canonical=cap(f.engine.q(57,arg0=37),24)
    assert f.v.same(typ,canonical);f.v.drop(typ);f.engine.q(29,a=canonical)
    private=f.engine.q(49,a=resource);assert get(private,16)==7;owned=cap(private,24)
    refused=f.producer(b'HIAFRQ01'+struct.pack('<4Q',3,*owned)+bytes(88),want=6)
    assert get(refused,104)==0
    facts(f.public.typed(27,*fac),1);f.public.factories.remove(fac)
    f.v.drop(resource);finish_cycle(f,[weak])
    return dict(case='native-fresh-Future-constructor-true-class37-and-no-raw-alias-export',
                passed=True,constructor_policy='actual-HIA-production-code',native_value_capture=True,
                canonical_binding_before_return=True,native_finalizer=True)

def native_canonical_independent(out):
    f=Fixture(out);fac=f.public.factory();objects=[]
    for _ in range(2):
        r=f.create_native(fac);assert get(r,104)==1
        c=f.v.keep(r);objects.append((c,cap(f.engine.q(80,a=c),24)))
    assert not f.v.same(objects[0][0],objects[1][0])
    facts(f.public.typed(27,*fac),1);f.public.factories.remove(fac)
    f.v.drop(objects[0][0]);f.engine.q(80,a=objects[0][1],arg0=1,want=3)
    assert get(f.engine.q(49,a=objects[1][0]),16)==7
    f.v.drop(objects[1][0]);finish_cycle(f,[objects[1][1]])
    return dict(case='native-fresh-Futures-share-factory-with-distinct-canonical-identities',
                passed=True,independent_finalizers=2)

def native_canonical_refusals(out):
    rows=[]
    for mode in ('absent-factory','wrong-factory-lease','kind7-binding-disabled'):
        f=Fixture(out)
        fac=((1,2,3),(4,5,6))if mode=='absent-factory'else f.public.factory()
        before=get(f.engine.q(47),48)
        source=fac
        if mode=='wrong-factory-lease':source=(fac[0],(fac[1][0],fac[1][1]^1,fac[1][2]))
        if mode=='kind7-binding-disabled':put(f.engine.context,168,0)
        r=f.create_native(source,want=None)
        assert get(r,8)!=0 and get(r,96)==1 and get(r,104)==0 and cap(r,24)==ZERO,r.hex()
        if mode=='kind7-binding-disabled':put(f.engine.context,168,128)
        assert get(f.engine.q(47),48)==before,(mode,f.engine.q(47)[:128].hex())
        assert get(f.provider_ctx,272)==0 and get(f.provider_ctx,112)==0
        if mode!='absent-factory':
            facts(f.public.typed(27,*fac),1);f.public.factories.remove(fac)
        f.close();rows.append(dict(case=mode,passed=True,actual_native_rollback=True))
    return dict(case='canonical-constructor-refusal-preserves-input-lease-and-retires-all-new-custody',
                passed=True,controls=rows)

def native_canonical_pin_cycle(out):
    f=Fixture(out);fac=f.public.factory();resource=f.v.keep(f.create_native(fac))
    weak=cap(f.engine.q(80,a=resource),24)
    acquired=f.acquire_native(resource)
    assert (get(acquired,16),get(acquired,96),get(acquired,104),get(acquired,112))==(7,1,1,0)
    pin_value=f.v.keep(acquired);assert f.v.same(pin_value,resource)
    borrowed=(cap(acquired,48),cap(acquired,72));assert borrowed[0]==fac[0]
    f.public.call(22,*borrowed,value=resource,kind=1)
    facts(f.public.typed(27,*fac),1);f.public.factories.remove(fac)
    f.v.drop(resource)
    returned=f.v.keep(f.public.call(10,*borrowed),72)
    assert f.v.same(returned,pin_value)
    f.v.drop(returned);f.v.drop(pin_value);finish_cycle(f,[weak])
    return dict(case='native-canonical-acquire-owns-real-Value-pin-for-borrowed-worker-call',
                passed=True,canonical_identity_preserved=True,actual_self_cycle_retired=True)

def native_canonical_pin_refusals(out):
    f=Fixture(out);ordinary=f.v.scalar(42);before=get(f.engine.q(47),48)
    r=f.acquire_native(ordinary,want=1)
    assert get(r,104)==0 and cap(r,24)==ZERO and cap(r,48)==ZERO and cap(r,72)==ZERO
    assert get(f.engine.q(47),48)==before
    f.v.drop(ordinary)
    r=f.acquire_native(ordinary,want=1);assert get(r,104)==0
    f.close()
    return dict(case='canonical-acquire-rejects-nonresource-and-stale-real-Value-caps-without-new-custody',
                passed=True,controls=2)

def native_canonical_parallel_acquire(out):
    from concurrent.futures import ThreadPoolExecutor
    f=Fixture(out);fac=f.public.factory();resource=f.v.keep(f.create_native(fac))
    weak=cap(f.engine.q(80,a=resource),24)
    identity=(get(f.engine.q(7,a=resource),104),get(f.engine.q(7,a=resource),112))
    before=get(f.engine.q(47),48)
    def worker(_):
        for _ in range(8):
            r=f.acquire_native(resource);pin_value=cap(r,24)
            assert get(r,104)==1 and (get(f.engine.q(7,a=pin_value),104),get(f.engine.q(7,a=pin_value),112))==identity
            borrowed=(cap(r,48),cap(r,72))
            assert get(f.public.call(9,*borrowed),96)==0
            dropped=f.engine.q(29,a=pin_value)
            assert (get(dropped,88),get(dropped,96))==(1,1)
        return 8
    with ThreadPoolExecutor(max_workers=8) as pool:count=sum(pool.map(worker,range(8)))
    assert count==64 and get(f.engine.q(47),48)==before
    facts(f.public.typed(27,*fac),1);f.public.factories.remove(fac)
    f.v.drop(resource);finish_cycle(f,[weak])
    return dict(case='eight-threads-64-actual-canonical-worker-acquires-and-read-calls',
                passed=True,threads=8,actual_acquires=count,unchanged_live_cap_count=True)

def actual_canonical_constructors(out):
    rows=[]
    for test in(native_canonical_constructor,native_canonical_independent,native_canonical_refusals,native_canonical_pin_cycle,native_canonical_pin_refusals,native_canonical_parallel_acquire):
        row=test(out);rows.append(row);print('NATIVE_CANONICAL_FUTURE_PASS',row['case'],flush=True)
    return rows

def actual_cycles(out):
    rows=[]
    for test in(self_cycle,container_cycle,mutual_cycle,exception_cycle,retained_return):
        row=test(out);rows.append(row);print('MANAGED_FUTURE_CYCLE_PASS',row['case'],flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--input-build',required=True,type=Path)
    ap.add_argument('--compiler',required=True,type=Path)
    ap.add_argument('--value',required=True,type=Path)
    ap.add_argument('--value-qualification',type=Path)
    ap.add_argument('--output',required=True,type=Path)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    construction=build(args.input_build,args.compiler,args.value,args.output/'build',args.value_qualification)
    signal.alarm(120)
    cases=actual_cycles(args.output/'build')+actual_callback_cycles(args.output/'build')+actual_canonical_constructors(args.output/'build')
    signal.alarm(0)
    report=dict(schema='hepta.hia.future-managed-native-component.v2',component_qualified=True,
                canonical_native_constructor_qualified=True,canonical_worker_acquire_qualified=True,
                cases=cases,construction=construction,qualifier=pin(Path(__file__).read_bytes()),
                whole_public_future_closed=False,whole_background_closed=False,native_callable_dispatcher_closed=False,
                production_trusted_initializer_closed=False,unknown_delivery_recovery_campaign_qualified=False)
    save(args.output/'report.json',report)
    print('ACTUAL_NATIVE_FUTURE_MANAGED_COMPONENT_PASS',len(cases),flush=True)
if __name__=='__main__':main()
