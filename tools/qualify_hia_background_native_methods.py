"""Actual registered BG worker, snapshot and shutdown against the original."""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,traceback
from concurrent.futures import ThreadPoolExecutor
from tools import qualify_hia_background_native_objects as objects
from tools import qualify_hia_background_native_context as context
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_background_public_constructor import make
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta.hia_background_optimizer import BackgroundOptimizer
get=context.get;cap=context.cap;put=context.put;pin=context.pin;E=context.E;B=context.B
class Methods:
    def __init__(self,native):self.native=native;self.calls=[]
    def call(self,op,owned,args=(),want=0):
        raw=bytearray(192);raw[:8]=b'HIABGOQ2';put(raw,8,op);put(raw,24,*owned)
        for i,c in enumerate(args):put(raw,48+24*i,*c)
        s=C.create_string_buffer(bytes(raw),192);o=C.create_string_buffer((1<<20)+32);C.memset(o,0xa5,len(o))
        rc=self.native.entry(s,192,o,1<<20,self.native.f.ctx,512);r=o.raw
        assert rc==0 and r[:8]==b'HIABGOR1' and s.raw==bytes(raw) and r[1<<20:]==b'\xa5'*32,(rc,r[:128].hex())
        child=r[32768:32768+786432]
        row=dict(op=op,status=get(r,8),known=get(r,16),state=get(r,48),stages=get(r,56),
          map=get(r,96),queue=get(r,104),unknown=get(r,72),detail=get(r,64),
          child_status=get(child,8),primary_kind=get(child,24),delivered=get(child,56),
          child_detail=get(child,64),child_unknown=get(child,88))
        self.calls.append(row)
        assert get(r,8)==want and get(r,16)==1 and get(r,72)==0,row
        assert child[:8]==b'HIABGMR1' and get(child,16)==op and get(child,8)==want,row
        assert get(child,72)==get(child,80)==get(child,88)==0,row
        assert get(self.native.f.ctx,184)==0 or op==4 # other snapshot calls may remain active
        return child
    def snapshot(self,owned,v):
        r=self.call(4,owned);assert get(r,56)==1 and get(r,24)==1
        value=v.keep(r,32);result=v.python_value(value);v.drop(value);return result
def qualify(a):
    f=context.Fixture(a);f.init();owner=f.f.bound.owner;v=f.f.v;carrier=q.Carrier(owner);files=[]
    for n in('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
        raw=(E/'shared-custody'/n).read_bytes();files.append((q.old.sealed(raw),raw))
    parent=a.output/'native-runtime';parent.mkdir();raw_runtime=q.old.create(carrier,files,parent)
    cloned=carrier.q(2,raw_runtime);assert cloned['row']['kind']==1
    r=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']))
    assert (get(r,80),get(r,88),get(r,96))==(0,1,1);runtime=v.keep(r)
    baseline=q.old.scalar_program(None)
    bridge={'binary':str(E/'shared-custody/builder-539ce9.bin'),'build_receipt':str(B/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs=[runtime,make(v,baseline),make(v,'calculate'),make(v,bridge),(0,0,0),(0,0,0),(0,0,0)]
    oracle_parent=a.output/'original-runtime';oracle_parent.mkdir()
    original_runtime=ScalarMultiversionRuntime(baseline,oracle_parent)
    original=BackgroundOptimizer(original_runtime,baseline,function='calculate',bridge=bridge)
    native=objects.Objects(a.objects,f);methods=Methods(native)
    before=get(v.raw(47),48);fds=context.open_fds();rows=[]
    r=native.call(0,caps=inputs);owned=cap(r,24);record=native.record(owned)
    assert get(record,56)==511 and get(record,8704+24)==0
    methods.call(3,owned)
    assert get(record,56)==1023 and get(record,64)==2 and get(record,72)==0
    observed=methods.snapshot(owned,v);expected=original.snapshot()
    assert observed==expected,(observed,expected)
    assert observed['worker_alive'] is True and observed['closed'] is False
    rows.append(dict(case='actual-pthread-start-and-initial-snapshot-original-equality',passed=True,snapshot=observed))
    # Every concurrent result is a distinct real external Value reference.
    with ThreadPoolExecutor(max_workers=8)as pool:replies=list(pool.map(lambda _:methods.call(4,owned),range(32)))
    for reply in replies:
        assert get(reply,56)==1;value=v.keep(reply,32)
        assert v.python_value(value)==expected
        v.drop(value)
    assert get(record,72)==get(f.ctx,184)==0
    rows.append(dict(case='eight-threads-32-real-snapshots-with-record-custody',passed=True,calls=32))
    wrong=make(v,1);r=methods.call(5,owned,args=(wrong,(0,0,0)),want=1)
    assert get(r,56)==1 and get(r,24)==2
    error=v.keep(r,32);descriptor=v.python_value(error);v.drop(error);v.drop(wrong)
    assert descriptor=={'class':'BackgroundOptimizationRejected','message':'E_HIA_BACKGROUND: shutdown flags must be exact booleans'},descriptor
    try:original.shutdown(wait=1)
    except Exception as e:assert type(e).__name__==descriptor['class'] and str(e)==descriptor['message']
    else:raise AssertionError('original accepted non-exact bool')
    assert methods.snapshot(owned,v)==original.snapshot()
    rows.append(dict(case='original-shutdown-error-order-preserves-live-worker',passed=True))
    r=methods.call(5,owned);assert get(r,56)==0
    original.shutdown()
    observed=methods.snapshot(owned,v);expected=original.snapshot()
    assert observed==expected and observed['closed'] is True and observed['worker_alive'] is False,(observed,expected)
    assert get(record,8704+24)==4,'only a real pthread join sets this state'
    rows.append(dict(case='actual-cancel-drain-join-and-closed-snapshot-original-equality',passed=True,snapshot=observed))
    end=native.call(2,owned)
    assert get(end,88)==1 and get(f.ctx,184)==get(f.ctx,192)==0
    assert get(v.raw(47),48)==before and context.open_fds()==fds
    rows.append(dict(case='all-joined-record-native-resources-and-FDs-retire',passed=True))
    original_runtime.close()
    assert get(f.control(1),24)==2 and get(f.control(3),24)==3
    carrier.q(3,raw_runtime)
    for fd,_ in files:os.close(fd)
    f.finish();assert not list(parent.iterdir())and not list(oracle_parent.iterdir())
    return dict(schema='hia.BG.registered-worker-methods.component.v1',passed=True,component_qualified=True,
       whole_background_closed=False,kind6_Value_published=False,task_submission_qualified=False,
       actual_pthread_worker=True,actual_pthread_join=True,host_product_callbacks=False,cases=rows,method_calls=methods.calls,
       raw_object_calls=native.calls,product=dict(path=str(a.objects),**pin(a.objects.read_bytes())),dependencies=f.pins)
def main():
    p=argparse.ArgumentParser()
    for n in('owner','context','dependencies','ledger','jobs','core','consumers','snapshot','nested','constructor','pure','objects','worker','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True);r=dict(passed=False,whole_background_closed=False)
    try:r=qualify(a)
    except BaseException as e:r.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:(a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print('ACTUAL_BG_REGISTERED_WORKER_METHODS_PASS',len(r['cases']),flush=True)
if __name__=='__main__':main()
