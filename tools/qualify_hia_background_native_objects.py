"""Actual native registered BG construction and retirement on the one arena."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_background_native_context as context
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools.qualify_hia_background_public_constructor import make,path_values
from hepta.hia_program import verify_program
get=context.get;cap=context.cap;put=context.put;pin=context.pin
E=context.E;B=context.B
class Objects:
    def __init__(self,path,f):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_native_objects
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.f=f;self.calls=[];self.last=None
    def call(self,op,owned=(0,0,0),caps=None,want=0):
        raw=bytearray(192);raw[:8]=b'HIABGOQ1';put(raw,8,op)
        if op==0:
            assert len(caps)==7
            for i,a in enumerate(caps):put(raw,24+24*i,*a)
        else:put(raw,24,*owned)
        s=C.create_string_buffer(bytes(raw),192);o=C.create_string_buffer((1<<20)+32);C.memset(o,0xa5,len(o))
        rc=self.entry(s,192,o,1<<20,self.f.ctx,512);r=o.raw[:1<<20];self.last=r
        assert s.raw==bytes(raw)and o.raw[1<<20:]==b'\xa5'*32
        row=dict(op=op,rc=rc,status=get(r,8),known=get(r,16),cap=cap(r,24),state=get(r,48),stages=get(r,56),
                 detail=get(r,64),unknown=get(r,72),delivered=get(r,80),consumed=get(r,88),mapping=get(r,96),queue=get(r,104))
        self.calls.append(row)
        if rc!=0 or r[:8]!=b'HIABGOR1' or get(r,8)!=want:
            print('BG_OBJECT_DIAGNOSTIC',json.dumps(dict(row=row,child=[get(r,32768+i)for i in range(0,192,8)],
              dependency=[get(r,32768+65536+i)for i in range(0,256,8)],
              constructor_state=[get(r,32768+65536+i)for i in range(256,800,8)],
              constructor_child=[get(r,32768+65536+262144+i)for i in range(0,256,8)],
              last_value=[get(r,32768+65536+98304+i)for i in range(0,128,8)])),flush=True)
        assert rc==0 and r[:8]==b'HIABGOR1'and get(r,8)==want,row
        return r
    def record(self,owned):
        p=self.f.reg(6,owned);assert get(p,40)==32
        row=C.string_at(get(p,64),32);address=get(row,0);extent=get(row,8)
        assert extent==2097152
        return (C.c_char*extent).from_address(address)
def qualify(a):
    f=context.Fixture(a);f.init();owner=f.f.bound.owner;v=f.f.v;carrier=q.Carrier(owner)
    files=[]
    for n in ('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
        raw=(E/'shared-custody'/n).read_bytes();files.append((q.old.sealed(raw),raw))
    parent=a.output/'native-runtime';parent.mkdir()
    raw_runtime=q.old.create(carrier,files,parent)
    # The bound sidecar owns one real active guard, so the retained raw
    # owner.op7 correctly refuses. Exercise the actual native component seam:
    # clone a verified Runtime carrier and transfer that owned clone to Value.
    refused=owner.call(7,b'HIAGLOB1'+struct.pack('<7Q',1,*raw_runtime,0,0,0))
    assert refused['status']==2 and refused['active']==1
    cloned=carrier.q(2,raw_runtime)
    assert cloned['row']['kind']==1 and all(cloned['cap'])
    captured=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']))
    assert (get(captured,80),get(captured,88),get(captured,96))==(0,1,1)
    runtime=v.keep(captured)
    runtime_type=v.keep(v.raw(36,a=runtime));canonical_runtime=v.builtin(20)
    assert v.same(runtime_type,canonical_runtime)
    v.drop(runtime_type);v.drop(canonical_runtime)
    baseline=q.old.scalar_program(None);verified=verify_program(baseline)
    bridge={'binary':str(E/'shared-custody/builder-539ce9.bin'),'build_receipt':str(B/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs=[runtime,make(v,baseline),make(v,'calculate'),make(v,bridge),make(v,8),make(v,2000),make(v,10.0)]
    object_owner=Objects(a.objects,f);before=get(v.raw(47),48);fd_before=context.open_fds()
    r=object_owner.call(0,caps=inputs);owned=cap(r,24)
    assert all(owned)and get(r,80)==1 and get(r,16)==1 and get(r,48)==1 and get(r,56)==511,r[:128].hex()
    assert get(f.ctx,184)==0 and get(f.ctx,192)==1
    record=object_owner.record(owned)
    assert record.raw[:8]==b'HIABGOB1'and get(record,8)==os.getpid()
    assert get(record,16)==C.addressof(record)and get(record,32)==C.addressof(f.ctx)
    assert get(record,40)==get(f.ctx,128)and get(record,48)!=0 and cap(record,80)==owned
    assert v.same(cap(record,336),runtime)and v.same(cap(record,288),inputs[2])
    assert path_values(v,cap(record,312))=={k:str(Path(p).resolve())for k,p in bridge.items()}
    assert record.raw[512:544].hex()==verified.sha256 and record.raw[544:576].hex()==verified.input_sha256
    assert (get(record,576),get(record,584),get(record,592),get(record,600))==(8,2000,struct.unpack('<Q',struct.pack('<d',10.0))[0],0)
    # These are the actual native initializers' state, not a Python-built prefix.
    for at,magic in ((4096,b'HIABGQS1'),(8192,b'HIABJS02'),(8704,b'HIABGWS2'),(9216,b'HIABLMS1')):
        assert record.raw[at:at+8]==magic,(at,record.raw[at:at+32].hex())
    assert get(record,8704+24)==0 # publication has not yet started a worker
    assert get(record,1089536+64)==get(record,240) # true Runtime carrier, not function cap
    q1=object_owner.call(1,owned);assert get(q1,48)==1 and get(q1,80)==0
    end=object_owner.call(2,owned);assert get(end,88)==1 and cap(end,24)==(0,0,0)
    assert get(f.ctx,184)==get(f.ctx,192)==0
    assert get(v.raw(47),48)==before and context.open_fds()==fd_before
    # The caller-owned native Runtime remains callable after BG retirement.
    snap=carrier.q(4,raw_runtime,q.old.public_request(10),child=0)
    assert json.loads(q.old.release_detached(snap))['closed'] is False
    rows=[dict(case='actual-native-record-construction-and-all-child-retirement',passed=True,
               true_runtime_identity=True,true_PosixPath_values=True,
               actual_carrier_clone_to_Value48_component_input=True,sidecar_op7_busy_unchanged=True,actual_factory_and_queue_init=True,
               worker_not_started_before_canonical_owner=True,all_local_native_refs_consumed=True,calls=list(object_owner.calls))]
    # Omitted optional arguments go through the same original constructor
    # defaults and become actual retained int/float Values for worker ranking.
    defaults=inputs[:4]+[(0,0,0)]*3
    r=object_owner.call(0,caps=defaults);owned=cap(r,24);record=object_owner.record(owned)
    assert get(r,56)==511 and get(r,48)==1
    assert (get(record,576),get(record,584),get(record,592),get(record,600))==(8,2000,4621819117588971520,0)
    assert v.python_value(cap(record,608))==2000 and v.python_value(cap(record,632))==10.0
    assert get(v.raw(7,a=cap(record,608)),16)==2 and get(v.raw(7,a=cap(record,632)),16)==3
    end=object_owner.call(2,owned);assert get(end,88)==1 and get(f.ctx,192)==0
    assert get(v.raw(47),48)==before and context.open_fds()==fd_before
    rows.append(dict(case='actual-original-defaults-retained-for-native-worker',passed=True))
    # Original ordering: invalid runtime wins before every later invalid option.
    bad=[make(v,None),make(v,None),make(v,None),make(v,{}),make(v,False),make(v,False),make(v,0)]
    r=object_owner.call(0,caps=bad,want=1);owned=cap(r,24);record=object_owner.record(owned)
    descriptor=v.python_value(cap(record,456))
    assert descriptor=={'class':'BackgroundOptimizationRejected','message':'E_HIA_BACKGROUND: a ScalarMultiversionRuntime is required'},descriptor
    r=object_owner.call(2,owned);assert get(r,88)==1 and get(f.ctx,192)==0
    rows.append(dict(case='ordered-constructor-rejection-with-actual-retirement',passed=True,descriptor=descriptor))
    # Never free the registry/global token before all actual records disappear.
    assert get(f.control(1),24)==2
    assert get(f.control(3),24)==3
    carrier.q(3,raw_runtime)
    for fd,_ in files:os.close(fd)
    f.finish()
    assert not list(parent.iterdir()),list(parent.iterdir())
    return dict(schema='hia.BG.native-registered-objects.component.v1',passed=True,component_qualified=True,
      whole_background_closed=False,public_kind6_publication=False,production_worker_started=False,
      products=dict(objects=dict(path=str(a.objects),**pin(a.objects.read_bytes())),dependencies=f.pins),
      cases=rows,all_calls=object_owner.calls)
def main():
    p=argparse.ArgumentParser()
    for n in ('owner','context','dependencies','ledger','jobs','core','consumers','snapshot','nested','constructor','pure','objects','output'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    r=dict(passed=False,component_qualified=False,whole_background_closed=False)
    try:r=qualify(a)
    except BaseException as e:r.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print('ACTUAL_BG_REGISTERED_OBJECTS_PASS',len(r['cases']),flush=True)
if __name__=='__main__':main()
