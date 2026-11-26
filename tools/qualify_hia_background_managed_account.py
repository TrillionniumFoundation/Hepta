"""Actual same-arena managed ledger and accounting; no product callbacks."""
from pathlib import Path
import argparse,collections,copy,ctypes as C,hashlib,json,os,struct,time,traceback,types
from tools import qualify_hia_future_native_callbacks as callbacks
import tools
if str(Path(__file__).resolve().parent)not in tools.__path__:tools.__path__.insert(0,str(Path(__file__).resolve().parent))
from tools import qualify_hia_background_managed_jobs as managed_jobs
from tools.qualify_hia_multiversion_values import Owner as Decimal
from tools.qualify_hia_multiversion_components import Image
ZERO=(0,0,0)
get=lambda b,p:struct.unpack_from("<Q",b,p)[0]
cap=lambda b,p=16:struct.unpack_from("<3Q",b,p)
def put(b,p,*v):struct.pack_into("<"+"Q"*len(v),b,p,*v)
def address(x):return C.cast(x,C.c_void_p).value
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
ENTRY=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def load(path,name):
    lib=C.CDLL(str(path));fn=getattr(lib,name);fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
    return lib,fn
def invoke(fn,ctx,wire,on,cn=None):
    s=C.create_string_buffer(wire,len(wire));o=C.create_string_buffer(on+32);C.memset(o,0xa5,on+32)
    rc=fn(s,len(wire),o,on,ctx,len(ctx)if cn is None else cn)
    assert s.raw==wire and o.raw[on:]==b"\xa5"*32,(rc,"frame or guard mutation")
    return rc,o.raw[:on]
class Payload:
    def __init__(self,fixture):
        p=C.addressof(fixture.bound.owner.context)+1280
        prefix=C.string_at(p,128);self.entry=ENTRY(get(prefix,104))
        self.ctx=(C.c_char*256).from_address(get(prefix,112));assert get(prefix,120)==256
    def q(self,op,a=ZERO,data=b"",count=0,want=0):
        r=bytearray(128+len(data));r[:8]=b"HIABPY01";put(r,8,op);put(r,24,*a)
        if op==1:put(r,72,len(data));r[128:]=data
        if op==4:put(r,56,count)
        rc,b=invoke(self.entry,self.ctx,bytes(r),max(512,512+count))
        assert rc==0 and b[:8]==b"HIABPYR1"and get(b,8)==want,(op,rc,b[:128].hex())
        return b
    def create(self,data):return cap(self.q(1,data=data))
    def drop(self,a):self.q(3,a)
    def copy(self,a,n):return self.q(4,a,count=n)[512:512+n]
class Ledger:
    def __init__(self,path,jobs,decimal,payload):
        self.lib,self.entry=load(path,"hia_background_ledger_managed");self.ctx=C.create_string_buffer(4096)
        self.jobs=jobs;self.decimal=decimal;self.payload=payload;self.calls=[]
        r=self.packet(0);put(r,24,address(decimal.f),C.addressof(decimal.w),256,address(payload.entry),C.addressof(payload.ctx),256,address(jobs.entry),C.addressof(jobs.ctx),256)
        self.raw(bytes(r))
    def packet(self,op,job=ZERO,receipt=ZERO,cost=ZERO,status=0,ordered=False):
        r=bytearray(128);r[:8]=b"HIABLM02"if ordered else b"HIABLM01";put(r,8,op)
        put(r,24,*job);put(r,48,*receipt);put(r,72,*cost);put(r,96,status);return r
    def raw(self,wire,want=0):
        rc,r=invoke(self.entry,self.ctx,wire,8192);assert rc==0 and r[:8]==b"HIABLMR1"and get(r,8)==want,(rc,want,r[:192].hex())
        assert all(get(r,p)<=1 for p in(128,136,144,152,160))and get(r,168)==1,r[:192].hex()
        self.calls.append(dict(op=get(wire,8),status=get(r,8),transfer=get(r,40),already=get(r,48),queue=get(r,128),map=get(r,136),unknown=get(r,144),local=get(r,152),retained=get(r,160)))
        return r
    def q(self,op,**kw):return self.raw(bytes(self.packet(op,**kw)))
    def snapshot(self):
        r=self.q(2,ordered=True);n=get(r,32);assert n==8+get(r,16)
        counters=[];receipts=[]
        for i in range(n):
            p=4096+i*48;k=get(r,p);a=cap(r,p+16);size=get(r,p+40)
            if k==1:
                counters.append(int(self.decimal.copy(a,size)));self.decimal.drop(a)
            else:
                assert k==2;receipts.append(self.payload.copy(a,size));self.payload.drop(a)
        return dict(counters=counters,receipts=receipts,order=[get(r,72+i*8)for i in range(get(r,64))])
    def close(self):
        r=self.q(5);assert get(r,160)==0
        self.q(3);assert get(self.ctx,24)==1
        assert self.ctx.raw[256:2048]==bytes(1792)
class Queue:
    def __init__(self,path,refs_path,jobs):
        self.lib,self.entry=load(path,"hia_mv_background_queue");self.ctx=C.create_string_buffer(4096)
        self.refs_lib,self.refs_entry=load(refs_path,"hia_background_job_refs_managed");self.refs_ctx=C.create_string_buffer(64)
        self.refs_ctx[:]=struct.pack("<8s7Q",b"HIABJRC2",address(jobs.entry),C.addressof(jobs.ctx),256,0,0,0,0)
        self.q(0,fields={16:8,64:address(self.refs_entry),80:C.addressof(self.refs_ctx),88:64})
        self.q(7)
    def q(self,op,fields=None,tx=False):
        r=bytearray(128);r[:8]=b"HIABGQ02"if tx else b"HIABGQ01";put(r,8,op)
        for p,v in(fields or {}).items():put(r,p,v)
        rc,b=invoke(self.entry,self.ctx,bytes(r),4096)
        assert rc==0 and b[:8]==b"HIABGQR1"and get(b,8)==0,(op,rc,b[:128].hex())
        return b
    def admit(self,owned,kernel):
        return self.q(1,{24:owned[0],32:owned[1],40:owned[2],48:kernel,56:512})
    def settle(self,active,jobs):
        p=512;owned=cap(active,p);slot=get(active,p+40)
        r=self.q(3,{16:slot,24:owned[0],32:owned[1],40:owned[2]})
        retired=[cap(r,512+i*64)for i in range(get(r,56))]
        for held in retired:jobs.drop(held)
        return retired
    def close(self):
        self.q(4);assert get(self.q(2),16)==2**64-1
        self.q(8);self.q(9)
def make(v,value):
    if type(value)is list:return v.lst([make(v,x)for x in value])
    if type(value)is dict:
        d=v.keep(v.raw(4))
        for k,x in value.items():v.raw(10,a=d,b=make(v,k),c=make(v,x))
        return d
    return v.scalar(value)
def setup(a):
    f=callbacks.Fixture(a.owner);fac=f.public.factory();resource,weak=f.resource(fac);strong,pair=f.acquire(resource)
    jobs=managed_jobs.Jobs(a.jobs,f,fac);decimal=Decimal(a.dependencies/"multiversion_values.so")
    payload=Payload(f);ledger=Ledger(a.ledger,jobs,decimal,payload)
    return f,fac,resource,weak,strong,pair,jobs,decimal,payload,ledger
def finish(state):
    f,fac,resource,weak,strong,pair,jobs,decimal,payload,ledger=state
    ledger.close();jobs.close();decimal.run(9)
    f.v.drop(strong);f.v.drop(resource);f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
def ledger_case(a):
    state=setup(a);f,fac,resource,weak,strong,pair,jobs,decimal,payload,ledger=state
    empty=ledger.snapshot();assert empty==dict(counters=[0]*8,receipts=[],order=[])
    expected=[];cost=0
    for i in range(70):
        owned=cap(jobs.q(10,a=pair[1],data=("actual-job-"+str(i)).encode()))
        receipt=json.dumps(dict(job=i,paid=i+1),separators=(",",":")).encode()
        row=payload.create(receipt);number=decimal.create(str(i+1).encode())
        out=ledger.q(1,job=owned,receipt=row,cost=number,status=i%6)
        assert (get(out,40),get(out,48))==(1,0);decimal.drop(number)
        again=ledger.q(4,job=owned);assert get(again,48)==1
        jobs.drop(owned);expected.append(receipt);cost+=i+1
    snapshot=ledger.snapshot();assert snapshot["counters"][:2]==[70,cost]and snapshot["receipts"]==expected[-64:]and snapshot["order"]==list(range(6)),snapshot
    assert sum(snapshot["counters"][2:])==70
    calls=list(ledger.calls);finish(state)
    return dict(case="real-managed-Jobs-guard-and-70-receipt-ring",passed=True,receipts=70,ring=64,calls=calls,all_native_refs_retired=True)
def account_case(a,state_name,started):
    from hepta import hia_background_optimizer as bg
    state=setup(a);f,fac,resource,weak,strong,pair,jobs,decimal,payload,ledger=state;v=f.v
    q=Queue(a.dependencies/"multiversion_background_queue.so",a.core/"job_refs.so",jobs)
    owned=cap(jobs.q(10,a=pair[1],data=b"native account integration input"))
    kernel=get(jobs.q(6,a=owned),64);q.admit(owned,kernel);active=q.q(2)
    if state_name=="cancelled":f.public.call(7,*pair)
    elif state_name=="finished":
        val=v.scalar("completed before accounting");f.public.call(22,*pair,value=val,kind=1);v.drop(val)
    now=time.perf_counter_ns();meta=dict(job=7,generation=3,epoch=4,function="calculate",before_sha256="1"*64,before_input_sha256="2"*64,original_baseline_sha256="3"*64,submit_work_ns=97,submitted_ns=now-500000,enqueued_ns=now-400000,work_started_ns=(now-300000 if started else None))
    original=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);original._function="calculate";original._baseline=types.SimpleNamespace(sha256="3"*64)
    token=bg.PublicationCancellation();future=bg._OptimizationFuture(token)
    if state_name=="cancelled":future.cancel()
    if state_name=="finished":future.set_result("completed before accounting")
    job=types.SimpleNamespace(number=7,generation=3,epoch=4,baseline=types.SimpleNamespace(sha256="1"*64,input_sha256="2"*64),submit_work_ns=97,submitted_ns=meta["submitted_ns"],enqueued_ns=meta["enqueued_ns"],work_started_ns=meta["work_started_ns"],accounted=False,cancellation=token,future=future)
    initial=original._report(job,"abstained","no profitable candidate");initial["detail"]={"message":"native data","rows":[1,2]}
    original._condition=__import__("threading").Condition();original._recent_jobs=collections.deque(maxlen=64);original._settled_jobs=0;original._observed_work_ns=0;original._outcomes={}
    meta_cap=make(v,meta);result=make(v,initial)
    freeze_lib,freeze=load(a.nested/"freeze.so","hia_background_value_freeze_deferred")
    transport_lib,transport=load(a.nested/"transport.so","hia_background_value_transport_deferred")
    capture_image=Image(a.nested_inputs/"background_optimizer_json_capture.flat")
    checked_image=Image(a.nested_inputs/"background_optimizer_freeze.flat")
    freezectx=C.create_string_buffer(2048)
    put(freezectx,0,int.from_bytes(b"HIABFZC3","little"),get(f.bound.owner.context,40),C.addressof(v.engine.context),256,address(transport),address(capture_image.entry),address(checked_image.entry),address(payload.entry),C.addressof(payload.ctx),256,4300)
    report_lib,report=load(a.core/"report.so","hia_background_report_deferred")
    account_lib,account=load(a.consumers/"account.so","hia_background_account_managed")
    ctx=C.create_string_buffer(36864)
    fields=[int.from_bytes(b"HIABACC3","little"),get(f.bound.owner.context,40),C.addressof(v.engine.context),256,address(report),address(freeze),C.addressof(freezectx),2048,address(ledger.entry),C.addressof(ledger.ctx),4096,address(jobs.entry),C.addressof(jobs.ctx),256,address(f.public.image.entry),C.addressof(f.public.ctx),256,*fac[0],get(f.public.ctx,64),address(decimal.f),C.addressof(decimal.w),256,get(f.public.ctx,80),fac[0][0]+256,256,0,address(q.entry),C.addressof(q.ctx),4096]
    put(ctx,0,*fields)
    wire=bytearray(128);wire[:8]=b"HIABACQ3";put(wire,24,*owned);put(wire,48,*meta_cap);put(wire,72,*result);put(wire,96,*pair[1])
    q.q(10,tx=True)
    try:rc,out=invoke(account,ctx,bytes(wire),524288)
    finally:q.q(11,tx=True)
    if rc!=0 or out[:8]!=b"HIABACR3"or get(out,8)!=0:
        print("ACCOUNT_REPORT_DIAGNOSTIC",json.dumps(dict(account=[get(out,p)for p in range(0,256,8)],report=[get(out,p)for p in range(147456,147648,8)],work=[get(ctx,p)for p in range(4096,4480,8)],value=[get(ctx,p)for p in range(4096+12288,4096+12416,8)])),flush=True)
    assert rc==0 and out[:8]==b"HIABACR3"and get(out,8)==0,(rc,out[:256].hex(),ctx.raw[:256].hex())
    assert get(out,144)==0 and get(out,136)==0 and get(out,152)==1
    changed=v.python_value(meta_cap);native=v.python_value(result);fixed=changed["now_ns"]
    oracle=copy.deepcopy(initial);saved=bg.time.perf_counter_ns
    try:bg.time.perf_counter_ns=lambda:fixed;original._account_job(job,oracle)
    finally:bg.time.perf_counter_ns=saved
    assert native==oracle,(state_name,native,oracle)
    observed=ledger.snapshot();assert observed["counters"][0]==1 and observed["counters"][1]==original._observed_work_ns
    assert observed["receipts"]==list(original._recent_jobs),(observed["receipts"],list(original._recent_jobs))
    # The actual accounted bit in the native Jobs metadata makes a second call a no-op.
    q.q(10,tx=True)
    try:rc,again=invoke(account,ctx,bytes(wire),524288)
    finally:q.q(11,tx=True)
    assert rc==0 and get(again,8)==0 and get(again,16)==1,again[:192].hex()
    assert ledger.snapshot()==observed
    retired=q.settle(active,jobs);assert owned in retired,(owned,retired)
    q.close();assert get(jobs.q(6,a=owned,want=1),136)==1
    row=dict(case="actual-account-"+state_name+("-started"if started else "-queued"),passed=True,oracle_equal=True,receipt_bytes_equal=True,settled_once=True,actual_future_observation=True,counters=observed["counters"],receipt=json.loads(observed["receipts"][0]))
    finish(state);return row
def main():
    p=argparse.ArgumentParser()
    for n in("owner","jobs","ledger","dependencies","core","consumers","nested","nested-inputs","output"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--ledger-only",action="store_true");a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    r=dict(schema="hia.background-managed-ledger-account.component.v1",passed=False,component_qualified=False,whole_background_closed=False,production_callbacks=False,same_arena=True,cases=[],products={})
    for n in("owner","jobs","ledger"):r["products"][n]=dict(path=str(getattr(a,n)),**pin(getattr(a,n).read_bytes()))
    target=a.output/"report.json"
    try:
        r["cases"].append(ledger_case(a));target.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n");print("NATIVE_LEDGER_ACCOUNT_CASE",r["cases"][-1]["case"],flush=True)
        if not a.ledger_only:
            for state,started in (("pending",True),("pending",False),("cancelled",False),("finished",True)):
                r["cases"].append(account_case(a,state,started));target.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n");print("NATIVE_LEDGER_ACCOUNT_CASE",r["cases"][-1]["case"],flush=True)
        r["passed"]=r["component_qualified"]=True
    except BaseException as e:r["error"]=repr(e);r["traceback"]=traceback.format_exc();raise
    finally:target.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    print("ACTUAL_MANAGED_LEDGER_ACCOUNT_PASS",len(r["cases"]),flush=True)
if __name__=="__main__":main()
