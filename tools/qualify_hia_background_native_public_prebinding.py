"""Native BG public boundary custody before kind-6 finalizer binding.

This gate deliberately retains the formal owner mask. It proves real constructor
errors and refusal compensation without enabling an unbound resource kind.
"""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,traceback,signal
from tools import qualify_hia_background_native_context as context
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_background_public_constructor import make
get=context.get;cap=context.cap;put=context.put;pin=context.pin;E=context.E;B=context.B
class Public:
    def __init__(self,path,f):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_native_public
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.f=f;self.calls=[]
    def call(self,op,caps=(),magic=b'HIABGPQ1'):
        b=bytearray(192);b[:8]=magic;put(b,8,op)
        for i,c in enumerate(caps):put(b,24+24*i,*c)
        s=C.create_string_buffer(bytes(b),192);o=C.create_string_buffer((2<<20)+32);C.memset(o,0xa5,len(o))
        rc=self.entry(s,192,o,2<<20,self.f.ctx,512);r=o.raw
        assert rc==0 and r[:8]==b'HIABGPR1' and s.raw==bytes(b) and r[2<<20:]==b'\xa5'*32,(rc,r[:128].hex())
        row=dict(op=op,status=get(r,8),primary_kind=get(r,16),delivered=get(r,48),known=get(r,56),
                 mapping=get(r,64),queue=get(r,72),unknown=get(r,80),cleanup_status=get(r,88),
                 detail=get(r,96),raw_owned=get(r,104),error_format=get(r,112),error_bytes=get(r,120))
        self.calls.append(row);print('ACTUAL_BG_PUBLIC_REPLY',row,flush=True)
        assert get(r,56)==1 and get(r,80)==0,row
        return r
def qualify(a):
    f=context.Fixture(a);f.init();owner=f.f.bound.owner;v=f.f.v;carrier=q.Carrier(owner);files=[]
    for n in('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
        raw=(E/'shared-custody'/n).read_bytes();files.append((q.old.sealed(raw),raw))
    parent=a.output/'native-runtime';parent.mkdir();raw_runtime=q.old.create(carrier,files,parent)
    cloned=carrier.q(2,raw_runtime);assert cloned['row']['kind']==1
    r=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']));runtime=v.keep(r)
    bridge={'binary':str(E/'shared-custody/builder-539ce9.bin'),'build_receipt':str(B/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs=[runtime,make(v,q.old.scalar_program(None)),make(v,'calculate'),make(v,bridge),(0,0,0),(0,0,0),(0,0,0)]
    native=Public(a.public,f);rows=[];before=get(v.raw(47),48);fd_before=context.open_fds()
    wrong=make(v,0);bad=[wrong,*inputs[1:]];r=native.call(0,bad)
    assert get(r,8)==1 and get(r,16)==2 and get(r,48)==1 and get(r,104)==0
    err=v.keep(r);desc=v.python_value(err)
    from hepta.hia_background_optimizer import BackgroundOptimizer
    try:BackgroundOptimizer(0,q.old.scalar_program(None),function='calculate',bridge=bridge)
    except Exception as e:expected=dict(**{'class':type(e).__name__},message=str(e))
    else:raise AssertionError('original accepted non-Runtime')
    assert desc==expected,(desc,expected)
    v.drop(err);v.drop(wrong)
    assert get(f.ctx,192)==0 and get(v.raw(47),48)==before and context.open_fds()==fd_before
    rows.append(dict(case='actual-original-error-retained-after-native-raw-record-compensation',passed=True,descriptor=desc))
    before=get(v.raw(47),48);mask=get(owner.context,512+168)
    assert mask==190 and mask&64==0
    r=native.call(0,inputs)
    assert get(r,8)!=0 and get(r,48)==0 and get(r,104)==0 and get(r,64)==get(r,72)==get(r,80)==get(r,88)==0
    assert get(owner.context,512+168)==mask and get(f.ctx,192)==get(f.ctx,184)==0 and get(v.raw(47),48)==before and context.open_fds()==fd_before
    rows.append(dict(case='unbound-kind6-refused-with-real-complete-native-compensation-no-mask-write',passed=True))
    r=native.call(1,[inputs[2]])
    assert get(r,8)==1 and get(r,48)==0 and get(r,104)==0 and get(r,80)==0
    assert get(v.raw(47),48)==before
    rows.append(dict(case='wrong-resource-query-retains-and-releases-actual-temporary-pin',passed=True))
    assert get(f.control(1),24)==2 and get(f.control(3),24)==3
    carrier.q(3,raw_runtime)
    for fd,_ in files:os.close(fd)
    f.finish();assert not list(parent.iterdir())
    return dict(schema='hia.BG.native-public-prebinding-custody.v1',passed=True,component_qualified=True,
                whole_background_closed=False,kind6_Value_published=False,public_exception_translation_complete=False,
                host_prefix_or_mask_writes=False,cases=rows,calls=native.calls,
                product=dict(path=str(a.public),**pin(a.public.read_bytes())),dependencies=f.pins)
def main():
    p=argparse.ArgumentParser()
    for n in('owner','context','dependencies','ledger','jobs','core','consumers','snapshot','nested','constructor','pure','public','worker','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True);signal.alarm(400)
    r=dict(passed=False,whole_background_closed=False)
    try:r=qualify(a)
    except BaseException as e:r.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print('ACTUAL_BG_NATIVE_PUBLIC_PREBINDING_PASS',len(r['cases']),flush=True)
if __name__=='__main__':main()
