"""Actual fixed BG RFQ finalizer over registered native objects."""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,traceback
from tools import qualify_hia_background_native_objects as objects
from tools import qualify_hia_background_native_context as context
from tools.qualify_hia_background_native_methods import Methods
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_background_public_constructor import make
get=context.get;cap=context.cap;put=context.put;pin=context.pin;E=context.E;B=context.B
class Finalizer:
    def __init__(self,lib,f):
        self.entry=lib.hia_background_native_finalizer
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.f=f;self.calls=[]
    def call(self,owned,op=0,want=0,nonce=None,known=1,consumed=1,pending=0):
        raw=bytearray(128);raw[:8]=b'HIAVRFQ1'
        put(raw,8,op,get(self.f.ctx,136)if nonce is None else nonce,6,*owned)
        s=C.create_string_buffer(bytes(raw),128);o=C.create_string_buffer((1<<20)+32);C.memset(o,0xa5,len(o))
        rc=self.entry(s,128,o,1<<20,self.f.ctx,512);r=o.raw
        assert rc==0 and r[:8]==b'HIAVRFR1' and s.raw==bytes(raw) and r[1<<20:]==b'\xa5'*32,(rc,r[:128].hex())
        facts=tuple(get(r,x)for x in(8,16,24,32))
        assert facts==(want,known,consumed,pending),(facts,r[:128].hex())
        assert r[40:128]==bytes(88)
        self.calls.append(dict(op=op,status=facts[0],known=facts[1],consumed=facts[2],pending=facts[3]))
        return r
def qualify(a):
    f=context.Fixture(a);f.init();owner=f.f.bound.owner;v=f.f.v;carrier=q.Carrier(owner)
    files=[]
    for n in('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
        raw=(E/'shared-custody'/n).read_bytes();files.append((q.old.sealed(raw),raw))
    parent=a.output/'native-runtime';parent.mkdir()
    raw_runtime=q.old.create(carrier,files,parent)
    cloned=carrier.q(2,raw_runtime);assert cloned['row']['kind']==1
    raw=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']))
    assert (get(raw,80),get(raw,88),get(raw,96))==(0,1,1)
    runtime=v.keep(raw)
    bridge={'binary':str(E/'shared-custody/builder-539ce9.bin'),'build_receipt':str(B/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs=[runtime,make(v,q.old.scalar_program(None)),make(v,'calculate'),make(v,bridge),(0,0,0),(0,0,0),(0,0,0)]
    native=objects.Objects(a.objects,f);final=Finalizer(native.lib,f);methods=Methods(native)
    before=get(v.raw(47),48);fd_before=context.open_fds();rows=[]
    r=native.call(0,caps=inputs);owned=cap(r,24);assert get(r,56)==511
    methods.call(3,owned)
    assert methods.snapshot(owned,v)['worker_alive'] is True
    original=bytes(f.ctx)
    final.call(owned,nonce=get(f.ctx,136)^1,want=11,known=0,consumed=0,pending=0)
    assert bytes(f.ctx)==original and get(native.call(1,owned),48)==2
    rows.append(dict(case='fixed-binding-nonce-refusal-preserves-live-object',passed=True))
    final.call(owned)
    assert get(f.ctx,184)==get(f.ctx,192)==0 and get(v.raw(47),48)==before and context.open_fds()==fd_before
    rows.append(dict(case='real-RFQ-custody-ack-after-all-native-children-retire',passed=True))
    r=native.call(0,caps=inputs);owned=cap(r,24)
    methods.call(3,owned)
    alias=cap(f.reg(2,owned));assert all(alias)
    final.call(owned,want=11,known=1,consumed=0,pending=1)
    assert get(f.ctx,192)==1 and get(native.call(1,owned),48)==2
    ack=f.reg(3,alias);assert (get(ack,80),get(ack,88))==(1,1)
    final.call(owned,op=1)
    assert get(f.ctx,184)==get(f.ctx,192)==0 and get(v.raw(47),48)==before and context.open_fds()==fd_before
    rows.append(dict(case='real-registry-alias-busy-retains-custody-and-native-retry-closes',passed=True))
    assert get(f.control(1),24)==2 and get(f.control(3),24)==3
    carrier.q(3,raw_runtime)
    for fd,_ in files:os.close(fd)
    f.finish();assert not list(parent.iterdir())
    return dict(schema='hia.BG.fixed-finalizer.component.v1',passed=True,component_qualified=True,
       whole_background_closed=False,kind6_Value_published=False,production_worker_started=True,actual_pthread_join=True,
       actual_fixed_objects_call=True,host_product_callbacks=False,cases=rows,finalizer_calls=final.calls,
       raw_object_calls=native.calls,product=dict(path=str(a.objects),**pin(a.objects.read_bytes())),dependencies=f.pins)
def main():
    p=argparse.ArgumentParser()
    for n in('owner','context','dependencies','ledger','jobs','core','consumers','snapshot','nested','constructor','pure','objects','worker','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True);r=dict(passed=False,whole_background_closed=False)
    try:r=qualify(a)
    except BaseException as e:r.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print('ACTUAL_BG_FIXED_FINALIZER_PASS',len(r['cases']),flush=True)
if __name__=='__main__':main()
