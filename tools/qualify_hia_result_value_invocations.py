"""Actual same-arena source-bound HIA callable execution and resource retirement.

The native sidecar initializes code and Value custody. Python supplies original
oracle data and canonical HIA programs; it never installs a function handler,
writes a binding, performs a continuation, or polls a production finalizer.
"""
from pathlib import Path
import argparse, concurrent.futures, ctypes as C, hashlib, json, platform, struct, sys, types
from tools.qualify_hia_result_value_exceptions import Values as PriorValues, frame, word, ZERO
from tools.qualify_hia_native_callable_code_owner import policy, wire as code_wire
import tools

SHARED=Path('/home/qian-qi/hia-native-followthrough-20261126-620a')
if str(SHARED/'tools') not in tools.__path__:tools.__path__.append(str(SHARED/'tools'))
from tools.qualify_hia_generation_lease_owner_sidecar import Bound

ENTRY=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
INPUT=int.from_bytes(b'HIACIN01','little')

def echo_field(index,disposition=1):
    return policy('actual_value_frame_'+str(index)+'_'+str(disposition),f'''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!={INPUT} or length(o)<NC_LIMIT:
        return 2
    phase=get(w,0)
    if phase==0:
        put(w,0,1)
        zero(o,128,129)
        put(o,0,NC_BODY_VALUE)
        put(o,8,129)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,224,1)
        put(o,232,2)
        store(o,256,{48+index})
        return 1
    if phase==1:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
            return 2
        put(w,0,2)
        put(w,32,get(o,524312))
        put(w,40,get(o,524320))
        put(w,48,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,12)
        put(o,152,readword(s,24))
        put(o,160,readword(s,32))
        put(o,168,readword(s,40))
        put(o,176,get(w,32))
        put(o,184,get(w,40))
        put(o,192,get(w,48))
        return 1
    if phase!=2 or get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,{disposition})
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
''')

FRESH=policy('actual_native_new_list','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,0)==0:
        put(w,0,1)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,3)
        return 1
    if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
''')
REFUSED_PRIVATE=policy('private_value_operation_refused','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,128,128)
    put(o,0,NC_BODY_VALUE)
    put(o,8,128)
    put(o,128,3832652713812904264)
    put(o,136,94)
    return 1
''')
BORROWED_DROP=policy('borrowed_frame_cannot_be_consumed','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    if phase==0:
        put(w,0,1)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,6)
        put(o,152,readword(s,24))
        put(o,160,readword(s,32))
        put(o,168,readword(s,40))
        return 1
    if phase==1:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=1:
            return 2
        put(w,0,2)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,232,1)
        put(o,240,1)
        return 1
    if get(o,112)!=0 or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
''')


def environment_operation(op):
    # A dynamic HIA body obtains its actual closure and performs the selected
    # ordinary Value operation. Every output token must enter native call custody.
    returned=524288+(8192+40 if op==23 else 8248)
    return policy('actual_multi_cap_upcall_'+str(op),f'''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    if phase==0:
        put(w,0,1)
        zero(o,128,129)
        put(o,0,NC_BODY_VALUE)
        put(o,8,129)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,224,1)
        put(o,232,2)
        store(o,256,49)
        return 1
    if phase==1:
        if get(o,112)!=0 or get(o,524296)!=0:
            return 2
        put(w,0,2)
        put(w,32,get(o,524312))
        put(w,40,get(o,524320))
        put(w,48,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,12)
        put(o,152,readword(s,24))
        put(o,160,readword(s,32))
        put(o,168,readword(s,40))
        put(o,176,get(w,32))
        put(o,184,get(w,40))
        put(o,192,get(w,48))
        return 1
    if phase==2:
        if get(o,112)!=0 or get(o,524296)!=0:
            return 2
        put(w,0,3)
        put(w,56,get(o,524312))
        put(w,64,get(o,524320))
        put(w,72,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,{int.from_bytes(b'HIABVQ01'if op==23 else b'HIABVQ02','little')})
        put(o,136,{op})
        put(o,152,get(w,56))
        put(o,160,get(w,64))
        put(o,168,get(w,72))
        put(o,240,{100 if op==23 else 0})
        return 1
    if phase!=3 or get(o,112)!=0 or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(o,{returned}))
    put(o,32,get(o,{returned+8}))
    put(o,40,get(o,{returned+16}))
    return 0
''')

NESTED=policy('actual_reentrant_value_callable','''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    if phase==0 or phase==2:
        put(w,0,phase+1)
        zero(o,128,129)
        put(o,0,NC_BODY_VALUE)
        put(o,8,129)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,224,1)
        put(o,232,2)
        store(o,256,49+phase)
        return 1
    if phase==1 or phase==3:
        if get(o,112)!=0 or get(o,524296)!=0:
            return 2
        put(w,0,phase+1)
        put(w,32,get(o,524312))
        put(w,40,get(o,524320))
        put(w,48,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,12)
        put(o,152,readword(s,24))
        put(o,160,readword(s,32))
        put(o,168,readword(s,40))
        put(o,176,get(w,32))
        put(o,184,get(w,40))
        put(o,192,get(w,48))
        if phase==1:
            put(w,0,6)
        return 1
    if phase==6:
        if get(o,112)!=0 or get(o,524296)!=0:
            return 2
        put(w,56,get(o,524312))
        put(w,64,get(o,524320))
        put(w,72,get(o,524328))
        put(w,0,2)
        return callback(s,o,w)
    if phase==4:
        if get(o,112)!=0 or get(o,524296)!=0:
            return 2
        put(w,80,get(o,524312))
        put(w,88,get(o,524320))
        put(w,96,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,3832652713812904264)
        put(o,136,70)
        put(o,152,get(w,56))
        put(o,160,get(w,64))
        put(o,168,get(w,72))
        put(o,176,get(w,80))
        put(o,184,get(w,88))
        put(o,192,get(w,96))
        put(w,0,5)
        return 1
    if phase!=5 or get(o,112)!=0 or get(o,524296)!=0 or get(o,524384)!=1:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,get(o,524352))
    put(o,24,get(o,524312))
    put(o,32,get(o,524320))
    put(o,40,get(o,524328))
    return 0
''')

class Engine:
    def __init__(self,bound):
        self.bound=bound
        self.context=(C.c_ubyte*256).from_address(C.addressof(bound.owner.context)+512)
        self.entry=ENTRY(bound.value);self.calls=0
    def call(self,request,on=16384):
        source=C.create_string_buffer(request);output=C.create_string_buffer(b'\xa5'*(on+64))
        rc=int(self.entry(source,len(request),output,on,self.context,256))&0xffffffff
        assert source.raw==request+b'\0' and output.raw[on:]==b'\xa5'*64+b'\0'
        self.calls+=1
        return rc,output.raw[:on]

class Values(PriorValues):
    def function(self,source,env=ZERO,name='function'):
        text=self.scalar(name);raw=self.raw(68,a=env,b=text,tail=source);self.drop(text)
        assert (word(raw,16),word(raw,64),word(raw,80),word(raw,88),word(raw,96),word(raw,104))==(8,1,0,1,1,0),raw[:128].hex()
        return self.keep(raw)
    def method(self,function,receiver):
        raw=self.raw(69,a=function,b=receiver)
        assert word(raw,64)==1 and word(raw,96)==1 and word(raw,80)==0 and word(raw,104)==0,raw[:128].hex()
        return self.keep(raw)
    def invoke(self,function,args,kwargs=ZERO,disposition=1):
        raw=self.raw(70,a=function,b=args,c=kwargs)
        assert (word(raw,64),word(raw,80),word(raw,88),word(raw,96),word(raw,104))==(disposition,0,1,1,0),raw[:128].hex()
        return self.keep(raw)

def code_call(bound,op):
    ctx=word(bound.owner.context,712)
    entry=ENTRY(word(bound.owner.context,704));request=code_wire(op)
    source=C.create_string_buffer(request);out=C.create_string_buffer(8192)
    rc=int(entry(source,len(request),out,len(out),ctx,256))
    assert rc==0 and out.raw[:8]==b'HIACODR1' and word(out.raw,8)==0 and word(out.raw,88)==1
    return out.raw

def sweep(v,b):
    for cap in list(v.held):v.drop(cap)
    assert word(v.raw(47),48)==1
    code=code_call(b,7)
    assert tuple(word(code,i)for i in(48,56,64,80))==(0,0,0,0),code[:128].hex()
    assert word(v.engine.context,176)==word(v.engine.context,184)==0

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert platform.python_version()=='3.14.4'
    args.output.mkdir(parents=True,exist_ok=False)
    b=Bound(args.owner);row=b.call(0);assert row['status']==0 and row['state']==2 and row['pending']==0,row
    assert word(b.owner.context,680)==62
    ctx=C.string_at(word(b.owner.context,712),256)
    assert word(ctx,136)==C.addressof(b.owner.context)+512 and word(ctx,144)==b.value
    v=Values(Engine(b));rows=[]
    def passed(name,**kw):
        rows.append(dict(case=name,**kw));(args.output/'partial.json').write_text(json.dumps(rows,indent=2)+'\n');print('INVOCATION_CASE',name,flush=True)
    f=v.function(FRESH,name='fresh')
    actualtype=v.keep(v.raw(36,a=f));expected=v.builtin(32);assert v.same(actualtype,expected)
    empty=v.tuple([]);one=v.invoke(f,empty);two=v.invoke(f,empty)
    assert word(v.raw(7,a=one),16)==5 and v.python_value(one)==[] and not v.same(one,two)
    sweep(v,b);passed('native-source-compile-real-function-two-actual-allocating-invocations')
    source=echo_field(3);f=v.function(source);items=[None,True,-10**80,'a\ud800\U0001f600',b'\x00\xff']
    arguments=v.tuple([v.scalar(x)for x in items]);result=v.invoke(f,arguments)
    assert v.python_value(result)==tuple(items)
    assert not v.same(result,arguments)
    sweep(v,b);passed('generic-tuple-parameters-and-detached-call-frame')
    f=v.function(echo_field(4));kwargs=v.dictionary([('a',1),('b','text')]);result=v.invoke(f,v.tuple([]),kwargs)
    assert v.python_value(result)==dict(a=1,b='text') and not v.same(result,kwargs)
    v.set(kwargs,'a',99);assert v.python_value(result)==dict(a=1,b='text')
    sweep(v,b);passed('actual-keyword-dictionary-snapshot')
    env=v.lst([v.scalar('captured')]);f=v.function(echo_field(1),env=env)
    v.drop(env);result=v.invoke(f,v.tuple([]));assert v.python_value(result)==['captured']
    sweep(v,b);passed('function-strong-environment-survives-original-cap-drop')
    receiver=v.dictionary([('self',7)]);f=v.function(source);m=v.method(f,receiver)
    typ=v.keep(v.raw(36,a=m));assert v.same(typ,v.builtin(33))
    v.drop(f);v.drop(receiver)
    result=v.invoke(m,v.tuple([v.scalar('argument')]))
    oracle=types.MethodType(lambda *args,**kwargs:args,{'self':7})('argument')
    assert v.python_value(result)==oracle
    sweep(v,b);passed('bound-method-real-code-clone-strong-self-and-function')
    f=v.function(source);first=v.method(f,v.scalar('first'));second=v.method(first,v.scalar('second'))
    result=v.invoke(second,v.tuple([v.scalar(9)]))
    oracle=types.MethodType(types.MethodType(lambda *args:args,'first'),'second')(9)
    assert v.python_value(result)==oracle
    sweep(v,b);passed('nested-bound-method-argument-order-original-oracle')
    cls=v.builtin(23);exception=v.exception(cls,v.tuple([v.scalar('failure')]),v.dictionary([('code','E_TYPED')]))
    f=v.function(echo_field(1,2),env=exception);v.drop(exception)
    result=v.invoke(f,v.tuple([]),disposition=2)
    assert v.isinst(result,cls);env,args_,name=v.parts(result)
    assert v.python_value(args_)==('failure',) and v.python_value(env)=={'code':'E_TYPED'}
    sweep(v,b);passed('actual-exception-object-propagated-separately-from-return')
    f=v.function(BORROWED_DROP);result=v.invoke(f,v.tuple([]));assert v.python(result)is True
    sweep(v,b);passed('native-body-cannot-consume-borrowed-frame-capability')
    f=v.function(REFUSED_PRIVATE);arguments=v.tuple([]);raw=v.raw(70,a=f,b=arguments,want=11)
    assert raw[24:48]==bytes(24) and word(raw,96)==0 and word(raw,80)==0
    sweep(v,b);passed('code-cannot-enter-private-value-custody-operations')
    text=v.scalar('bad');raw=v.raw(68,b=text,tail=b'not canonical HIA',want=3)
    assert raw[24:48]==bytes(24) and word(raw,96)==0 and word(raw,80)==0
    sweep(v,b);passed('native-compiler-rejects-invalid-source-without-hidden-code')
    env=v.lst([]);f=v.function(FRESH,env=env);v.raw(16,a=env,b=f)
    sweep(v,b);passed('function-environment-cycle-last-drop-drives-native-code-finalizer')
    child=v.function(echo_field(3));outer=v.function(NESTED,env=child);v.drop(child)
    result=v.invoke(outer,v.tuple([v.scalar('nested'),v.scalar(7)]))
    assert v.python_value(result)==('nested',7)
    sweep(v,b);passed('same-value-entry-reentrant-native-invocation')
    env=v.dictionary([('a',7),('b',8),('c',9)])
    f=v.function(environment_operation(23),env=env);result=v.invoke(f,v.tuple([]))
    assert v.python(result)==7
    sweep(v,b);passed('all-dictionary-enumeration-output-caps-native-adopted-and-retired')
    ex=v.exception(v.builtin(24),v.tuple([v.scalar('descriptor')]),v.dictionary([('tag','capture')]))
    f=v.function(environment_operation(26),env=ex);result=v.invoke(f,v.tuple([]))
    assert v.python_value(result)==('descriptor',)
    sweep(v,b);passed('all-native-descriptor-output-caps-native-adopted-and-retired')
    f=v.function(source);arguments=v.tuple([v.scalar(123)])
    def run(_):
        raw=v.raw(70,a=f,b=arguments)
        assert word(raw,64)==1 and word(raw,96)==1 and word(raw,80)==0
        return struct.unpack_from('<3Q',raw,24)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:results=list(pool.map(run,range(64)))
    for cap in results:assert v.python_value(cap)==(123,);v.raw(29,a=cap)
    sweep(v,b);passed('eight-threads-real-native-code-and-value-custody',calls=64)
    b.close()
    report=dict(schema='hia.native-value-invocations.component.v1',native_initialized_binding=True,same_value_arena=True,actual_source_compilation_and_execution=True,groups=rows,oracle=platform.python_version(),image_sha256=hashlib.sha256(args.owner.read_bytes()).hexdigest(),component_qualified=True,public_owner_whitelist_qualified=False,custom_protocol_dispatch_qualified=False,whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows))))
if __name__=='__main__':main()
