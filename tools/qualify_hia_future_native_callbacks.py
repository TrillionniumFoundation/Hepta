"""Actual native HIA callable registration on one native-bound Future/Value arena."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,sys
from concurrent.futures import Future
from tools import generate_hia_generation_lease_owner_sidecar_callback_capsule_packer as capsule
from tools import qualify_hia_generation_future_managed_binding as binding
from tools import qualify_hia_result_value_invocations as inv
from tools.qualify_hia_future_retirement import facts
ZERO=(0,0,0)
def word(b,p):return struct.unpack_from('<Q',b,p)[0]
def cap(b,p=24):return struct.unpack_from('<3Q',b,p)
def put(b,p,*v):struct.pack_into('<'+'Q'*len(v),b,p,*v)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def append_future_source():
    # Compiled HIA obtains its real closure and argument through native Value.
    text='''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=%d or length(o)<NC_LIMIT:
        return 2
    phase=get(w,0)
    if phase>0:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
            return 2
'''%inv.INPUT
    def fresh(next_,digit):
        return f'''        put(w,0,{next_})
        zero(o,128,129)
        put(o,0,NC_BODY_VALUE)
        put(o,8,129)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,224,1)
        put(o,232,2)
        store(o,256,{48+digit})
        return 1
'''
    def take(at):
        return ''.join(f'        put(w,{at+i},get(o,{524312+i}))\n'for i in(0,8,16))
    def operation(next_,op,a,b=None,frame=False):
        t=f'''        put(w,0,{next_})
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,{op})
'''
        if frame:
            t+=''.join(f'        put(o,{152+i},readword(s,{24+i}))\n'for i in(0,8,16))
        elif a is not None:
            t+=''.join(f'        put(o,{152+i},get(w,{a+i}))\n'for i in(0,8,16))
        if b is not None:t+=''.join(f'        put(o,{176+i},get(w,{b+i}))\n'for i in(0,8,16))
        return t+'        return 1\n'
    text+='    if phase==0:\n'+fresh(1,1)
    text+='    if phase==1:\n'+take(96)+operation(2,12,None,96,True)
    text+='    if phase==2:\n'+take(32)+fresh(3,3)
    text+='    if phase==3:\n'+take(120)+operation(4,12,None,120,True)
    text+='    if phase==4:\n'+take(56)+fresh(5,0)
    text+='    if phase==5:\n'+take(144)+operation(6,12,56,144)
    text+='    if phase==6:\n'+take(80)+operation(7,16,32,80)
    text+='    if phase==7:\n'+operation(8,2,None)
    text+='''    if phase!=8:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
'''
    return inv.policy('actual_Future_callback_append_identity',text)
SOURCE=append_future_source()
class Fixture(binding.Fixture):
    def __init__(self,path):
        previous=binding.capsule;binding.capsule=capsule
        try:super().__init__(path)
        finally:binding.capsule=previous
        self.registrations=[]
    def register(self,resource,fn):
        raw=bytearray(128);raw[:8]=b'HIAFRQ04';put(raw,16,*resource);put(raw,40,*fn)
        source=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(320)
        rc=self.provider.entry(source,128,out,320,self.provider_ctx,512);r=out.raw
        assert rc==0 and r[:8]==b'HIAFRR04',(rc,r.hex())
        if word(r,104)==1:
            owned=self.v.keep(r)
        else:owned=None
        row=dict(status=word(r,8),kind=word(r,16),future_status=word(r,72),
                 future_class=word(r,80),future_known=word(r,88),known=word(r,96),
                 delivered=word(r,104),pending=word(r,112),attempted=word(r,120))
        self.registrations.append(row)
        assert (row['status'],row['kind'],row['future_status'],row['future_class'],row['future_known'],
                row['known'],row['delivered'],row['pending'],row['attempted'])==(0,7,0,0,1,1,1,0,1),(row,r.hex())
        assert cap(r,48)==ZERO
        self.v.drop(owned)
    def length(self,values):
        r=self.v.raw(7,a=values);assert word(r,16)==5
        return word(r,48)
    def assert_events(self,events,resource,n):
        assert self.length(events)==n
        for i in range(n):
            key=self.v.scalar(i);item=self.v.keep(self.v.raw(12,a=events,b=key))
            assert self.v.same(item,resource)
            self.v.drop(item);self.v.drop(key)
def actual(path,out,completed=False,duplicates=1,cancel=False):
    f=Fixture(path);fac=f.public.factory();resource,weak=f.resource(fac)
    strong,pair=f.acquire(resource);events=f.v.lst([]);fn=f.v.function(SOURCE,env=events)
    value=f.v.scalar(None)
    oracle=Future();seen=[]
    if completed:oracle.set_result(None);f.public.call(22,*pair,value=value,kind=1)
    for _ in range(duplicates):
        oracle.add_done_callback(lambda x:seen.append(x))
        f.register(resource,fn)
    f.v.drop(fn)
    if not completed:
        assert f.length(events)==0
        if cancel:
            assert oracle.cancel() is True
            reply=f.public.call(7,*pair)
            assert word(reply,16)==1,reply[:192].hex()
        else:
            oracle.set_result(None);f.public.call(22,*pair,value=value,kind=1)
    assert len(seen)==duplicates and all(x is oracle for x in seen)
    f.assert_events(events,resource,duplicates)
    f.v.drop(value);f.v.drop(strong);f.v.drop(resource)
    # The exact Future stays live through the external events list.
    promoted=f.v.keep(f.v.raw(80,a=weak,arg0=1));f.v.drop(promoted)
    f.v.drop(events);f.v.raw(80,a=weak,arg0=1,want=3)
    calls=f.registrations;f.finish()
    return dict(case=('cancel'if cancel else'completed-immediate'if completed else'pending-completion')+'-native-callable-'+str(duplicates),
                passed=True,callbacks=duplicates,actual_code_source=pin(SOURCE),registrations=calls,
                original_cpython_callback_count=len(seen),same_actual_Future_argument=True,
                caller_callable_cap_dropped_before_completion=True,real_lastdrop_and_no_shadow_arena=True)
def normal(path,out):return actual(path,out)
def immediate(path,out):return actual(path,out,completed=True)
def duplicate(path,out):return actual(path,out,duplicates=3)
def cancellation(path,out):return actual(path,out,cancel=True)
CASES=(normal,immediate,duplicate,cancellation)
def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--cases',nargs='*');a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    wanted=set(a.cases or [fn.__name__ for fn in CASES])
    r=dict(schema='hia.Future-native-callable-component.v1',passed=False,component_qualified=False,
           whole_public_Future_closed=False,whole_background_closed=False,native_initializer=True,
           python_callback_handlers=False,actual_source_bound_Value70=True,
           exception_diagnostic_qualified=False,product=pin(a.owner.read_bytes()),cases=[])
    save(a.output/'report.json',r)
    for fn in CASES:
        if fn.__name__ not in wanted:continue
        row=fn(a.owner,a.output);r['cases'].append(row);save(a.output/'report.json',r)
        print('ACTUAL_NATIVE_CALLABLE_CASE',row['case'],flush=True)
    r['passed']=r['component_qualified']=True;save(a.output/'report.json',r)
    print('ACTUAL_NATIVE_CALLABLE_PASS',len(r['cases']),flush=True)
if __name__=='__main__':main()
