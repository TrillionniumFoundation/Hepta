"""Native BG context custody: fixed parent arena, actual registry and tool FDs.

Only the trusted root initializer calls HIABGNI1. Public BG method requests are
a separate owner domain and cannot populate this binding.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_future_resource_registry as registry
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INIT="HIABGNI1",CONTROL="HIABGCQ1",REPLY="HIABGCR1",STATE="HIABGNC1",CONFIG="HIABGCF1",
 OWNER="HIAGLOW1",PROVIDER="HIAGPCX1",FUT_PROVIDER="HIAFRCX2",
 FUT_STATE="HIABFPS1",VALUE_QUERY="HIABVQ06",VALUE_PRIVATE="HIABVQ05",VALUE_REPLY="HIABVR01",VALUE_ACK="HIABVR02",
 REG_INPUT="HIABGRG1",REG_REPLY="HIABGRR1").items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,PH=128,FB=136,OP=144,FAMILY=152,ERROR=160,
 HELD=168,NEXT=176,PID=184,SELF=192,ACTUAL_ENTRY=200,INDEX=208,RANDOM_USED=216,
 KNOWN=224,PENDING=232,MAP_PENDING=240,QUEUE_PENDING=248,UNKNOWN=256,
 FACT_SELF=1024,FACT_ENTRY=1032,HEADER=1152,VALUES=2176,FUTURE=2432,RUNTIME=2944,
 TEMP=3456,RQ=4096,RP=4608,OUT=16384,CONFIG_BYTES=1024,ENTRIES=40)
ENTRY_NAMES=["queue","ledger","decimal","jobs","job_refs","worker","submission","business","execution","account","snapshot","shutdown","report","structure_deferred","transport_deferred","freeze_deferred","constructor","options","bridge_paths","constructor_binding","path_value","path_resolve","path_error","path_string_codec","posix_factory","verifier","json_capture","sha256","checked_freezer","prepare_process","verify_raw","decision","registry","future_provider_deferred","structure_compat","transport_compat","freeze_compat","rank","admission","decision_policy"]
SOURCE=r'''
def background_native_context(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 and length(s)!=256:
        return 4294967293
    if length(o)<OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        magic=word_load(s,0)
        family=0
        if magic==INIT:
            if length(s)!=256 or word_load(s,8)!=0 or word_load(s,24)!=2048 or word_load(s,16)==0:
                return 4294967293
            if word_load(s,32)<3 or word_load(s,40)<3 or word_load(s,48)<3 or word_load(s,80)<3:
                return 4294967293
            if word_load(s,56)==0 or word_load(s,64)!=10100891 or word_load(s,88)==0 or word_load(s,96)!=ENTRIES*8:
                return 4294967293
            if word_load(s,72)!=0 and word_load(s,72)<640:
                return 4294967293
            if word_load(s,72)>2147483647 or read_zero(s,104,152)==0:
                return 4294967293
            family=1
        elif magic==CONTROL:
            if length(s)!=128 or word_load(s,8)>4 or read_zero(s,16,112)==0:
                return 4294967293
        else:
            return 4294967293
        zero(o,128,896)
        put(o,FAMILY,family)
        put(o,OP,word_load(s,8))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return locks(o,w,phase)
    if phase<300:
        return initializing(s,o,w,phase)
    if phase<400:
        return closing(s,o,w,phase)
    return ending(o,w,phase)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return finish(o,w,11)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(o,FACT_SELF)==0 or get(o,FACT_ENTRY)==0:
            return finish(o,w,11)
        put(o,SELF,get(o,FACT_SELF))
        put(o,ACTUAL_ENTRY,get(o,FACT_ENTRY))
        if get(o,FAMILY)==1:
            if word_load(s,16)>MAX-2048 or word_load(s,56)>MAX-10100891 or word_load(s,88)>MAX-ENTRIES*8:
                return finish(o,w,11)
            return memory(o,4,0,word_load(s,16),3,HEADER,1024)
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=get(o,SELF) or get(w,24)!=get(o,ACTUAL_ENTRY):
            return finish(o,w,11)
        if get(w,232)==0 or get(w,232)>MAX-2048 or get(w,168)>4:
            return finish(o,w,11)
        return memory(o,4,0,get(w,232),3,HEADER,1024)
    if phase==4:
        parent=choose(get(o,FAMILY)==1,word_load(s,16),get(w,232))
        if get(o,HEADER)!=OWNER or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+16)!=parent or get(o,HEADER+80)!=1:
            return finish(o,w,11)
        if get(o,HEADER+40)==0 or get(o,HEADER+48)!=parent+512 or get(o,HEADER+56)!=256 or get(o,HEADER+664)==0:
            return finish(o,w,11)
        return memory(o,5,0,parent+512,3,VALUES,256)
    if phase==5:
        if get(o,VALUES+152)!=get(o,HEADER+664):
            return finish(o,w,11)
        if get(o,FAMILY)==0:
            if get(w,32)!=get(o,HEADER+40) or get(w,40)!=get(o,HEADER+48) or get(w,48)!=256 or get(w,136)!=get(o,VALUES+152):
                return finish(o,w,11)
            return lock(o,300)
        if get(o,VALUES+224)==0 or get(o,VALUES+232)==0 or get(o,VALUES+240)!=512 or get(o,VALUES+248)==0:
            return finish(o,w,11)
        return memory(o,6,0,get(o,VALUES+232),3,FUTURE,512)
    if phase==6:
        if get(o,FUTURE)!=FUT_PROVIDER or get(o,FUTURE+8)!=get(o,PID) or get(o,FUTURE+16)!=get(o,VALUES+232):
            return finish(o,w,11)
        if get(o,FUTURE+24)!=get(o,VALUES+224) or get(o,FUTURE+80)!=get(o,VALUES+248) or get(o,FUTURE+96)!=1:
            return finish(o,w,11)
        if get(o,FUTURE+32)==0 or get(o,FUTURE+40)==0 or get(o,FUTURE+48)!=256 or get(o,FUTURE+56)!=get(o,HEADER+40) or get(o,FUTURE+64)!=get(o,HEADER+48) or get(o,FUTURE+72)!=256:
            return finish(o,w,11)
        return memory(o,7,0,word_load(s,16)+1280,3,RUNTIME,512)
    if phase==7:
        if get(o,RUNTIME)!=PROVIDER or get(o,RUNTIME+8)!=get(o,PID) or get(o,RUNTIME+16)!=1:
            return finish(o,w,11)
        if get(o,RUNTIME+40)!=word_load(s,16) or get(o,RUNTIME+48)!=word_load(s,16)+1280 or get(o,RUNTIME+56)==0:
            return finish(o,w,11)
        if get(o,RUNTIME+80)!=get(o,HEADER+40) or get(o,RUNTIME+88)!=get(o,HEADER+48) or get(o,RUNTIME+96)!=256:
            return finish(o,w,11)
        return memory(o,8,0,word_load(s,88),3,TEMP,ENTRIES*8)
    if phase==8:
        i=0
        while i<ENTRIES:
            if get(o,TEMP+i*8)==0:
                return finish(o,w,11)
            i=i+1
        return lock(o,200)
    return finish(o,w,11)

def locks(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FB)==0:
            put(o,HELD,1)
            return again(o,get(o,NEXT))
        return system(o,101,202,1,176,128,1,0,0,0)
    if phase==101:
        if get(o,FB)!=0 and get(o,FB)!=MAX-3 and get(o,FB)!=MAX-10:
            return system(o,104,24,0,0,0,0,0,0,0)
        return lock(o,get(o,NEXT))
    if phase==104:
        return lock(o,get(o,NEXT))
    if phase==102:
        return system(o,103,202,1,176,129,2147483647,0,0,0)
    if phase==103:
        return again(o,get(o,NEXT))
    return finish(o,w,11)

def initializing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        i=0
        while i<512:
            if i!=176 and get(w,i)!=0:
                return fail(o,w,6)
            i=i+8
        put(w,0,STATE)
        put(w,8,get(o,PID))
        put(w,16,get(o,SELF))
        put(w,24,get(o,ACTUAL_ENTRY))
        put(w,32,get(o,HEADER+40))
        put(w,40,get(o,HEADER+48))
        put(w,48,256)
        put(w,56,get(o,FUTURE+32))
        put(w,64,get(o,FUTURE+40))
        put(w,72,256)
        put(w,80,get(o,RUNTIME+56))
        put(w,88,word_load(s,16)+1280)
        put(w,96,768)
        put(w,104,get(o,VALUES+224))
        put(w,112,get(o,VALUES+232))
        put(w,120,512)
        put(w,136,get(o,VALUES+152))
        put(w,144,get(o,TEMP+32*8))
        put(w,152,get(o,SELF)+256)
        put(w,160,256)
        put(w,168,4)
        put(w,232,word_load(s,16))
        put(o,KNOWN,1)
        return system(o,201,318,1,128,8,0,0,0,0)
    if phase==201:
        got=get(o,FB)
        used=get(o,RANDOM_USED)
        if got==MAX-3:
            return system(o,201,318,1,128+used,8-used,0,0,0,0)
        if got==0 or got>=NEGATIVE or got>8-used:
            return fail(o,w,11)
        used=used+got
        put(o,RANDOM_USED,used)
        if used<8:
            return system(o,201,318,1,128+used,8-used,0,0,0,0)
        if get(w,128)==0:
            put(o,RANDOM_USED,0)
            return system(o,201,318,1,128,8,0,0,0,0)
        put(o,PH,202)
        put(o,0,CONFIG_BYTES)
        return 6
    if phase==202:
        p=get(o,FB)
        if p==0 or p>=NEGATIVE or p>MAX-CONFIG_BYTES:
            return fail(o,w,5)
        put(w,240,p)
        put(w,248,CONFIG_BYTES)
        put(w,200,get(w,200)|4)
        zero(o,HEADER,CONFIG_BYTES)
        put(o,HEADER,CONFIG)
        put(o,HEADER+8,get(o,PID))
        put(o,HEADER+16,get(o,SELF))
        put(o,HEADER+24,get(w,128))
        put(o,HEADER+32,word_load(s,56))
        put(o,HEADER+40,10100891)
        put(o,HEADER+48,word_load(s,72))
        put(o,HEADER+128,ENTRIES)
        within(o,HEADER+136,TEMP,ENTRIES*8)
        return memory(o,203,3,HEADER,0,p,CONFIG_BYTES)
    if phase==203:
        put(o,INDEX,0)
        return again(o,204)
    if phase==204:
        i=get(o,INDEX)
        if i==4:
            request(o,VALUE_QUERY,21)
            return values(o,w,206)
        fd=word_load(s,choose(i==3,80,32+i*8))
        return system(o,205,72,0,fd,1030,3,0,0,0)
    if phase==205:
        fd=get(o,FB)
        if fd<3 or fd>=NEGATIVE:
            return fail(o,w,11)
        i=get(o,INDEX)
        put(o,HEADER+64+i*8,fd)
        put(w,200,get(w,200)|(8<<i))
        put(o,INDEX,i+1)
        return memory(o,204,3,HEADER+64+i*8,0,get(w,240)+64+i*8,8)
    if phase==206:
        if value_valid(o)==0 or get(o,RP+8)!=0 or get(o,RP+24)==0:
            return fail(o,w,11)
        between(o,RP+24,w,208,24)
        put(w,200,get(w,200)|2)
        request(o,REG_INPUT,0)
        return registry(o,w,207)
    if phase==207:
        if reg_valid(o)==0 or get(o,RP+8)!=0:
            return fail(o,w,11)
        put(w,200,get(w,200)|1)
        put(w,168,1)
        return fail(o,w,0)
    return fail(o,w,11)

def closing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        put(o,KNOWN,1)
        state=get(w,168)
        op=get(o,OP)
        if op==0:
            return fail(o,w,0)
        if op==1:
            if state!=1 or get(w,184)!=0 or get(w,192)!=0 or get(w,272)!=0:
                return fail(o,w,6)
            put(w,168,2)
            return fail(o,w,0)
        if op==2:
            if state!=2 or (get(w,200)&3)!=3:
                return fail(o,w,6)
            put(w,168,1)
            return fail(o,w,0)
        if (get(w,200)&256)!=0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if state==3:
            return fail(o,w,0)
        if (op!=3 and op!=4) or (state!=2 and state!=4):
            return fail(o,w,6)
        if get(w,184)!=0 or get(w,192)!=0 or get(w,272)!=0:
            return fail(o,w,6)
        put(w,168,2)
        if (get(w,200)&1)!=0:
            request(o,REG_INPUT,5)
            return registry(o,w,301)
        return again(o,302)
    if phase==301:
        if reg_valid(o)==0 or get(o,RP+8)!=0:
            return fail(o,w,11)
        put(w,200,get(w,200)&(MAX-1))
        return again(o,302)
    if phase==302:
        put(o,INDEX,0)
        if (get(w,200)&4)!=0:
            return memory(o,303,0,get(w,240),3,HEADER,CONFIG_BYTES)
        return again(o,306)
    if phase==303:
        i=get(o,INDEX)
        if i==4:
            return again(o,305)
        bit=8<<i
        if (get(w,200)&bit)==0:
            put(o,INDEX,i+1)
            return again(o,303)
        return system(o,304,3,0,get(o,HEADER+64+i*8),0,0,0,0,0)
    if phase==304:
        # Linux close consumes this descriptor even on EINTR. Never close a
        # recycled numeric FD a second time.
        i=get(o,INDEX)
        put(w,200,get(w,200)&(MAX-(8<<i)))
        put(o,INDEX,i+1)
        return again(o,303)
    if phase==305:
        put(o,PH,307)
        put(o,0,get(w,240))
        return 7
    if phase==307:
        put(w,240,0)
        put(w,248,0)
        put(w,200,get(w,200)&(MAX-4))
        return again(o,306)
    if phase==306:
        if (get(w,200)&2)!=0:
            request(o,VALUE_PRIVATE,92)
            between(w,208,o,RQ+24,24)
            return values(o,w,308)
        if (get(w,200)&128)!=0:
            request(o,VALUE_PRIVATE,93)
            return values(o,w,309)
        put(w,168,3)
        return fail(o,w,0)
    if phase==308:
        if value_ack(o,1)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+96)!=0:
            zero(w,208,24)
            put(w,200,get(w,200)&(MAX-2))
        if pending(o,w)==0:
            return fail(o,w,11)
        if get(o,RP+96)==0:
            return fail(o,w,11)
        return again(o,306)
    if phase==309:
        if value_ack(o,0)==0 or pending(o,w)==0:
            return fail(o,w,11)
        if get(o,RP+104)!=0:
            return fail(o,w,11)
        if get(o,RP+8)!=0 and get(o,RP+8)!=6 and get(o,RP+112)==0:
            return fail(o,w,11)
        if get(o,RP+8)==6 and get(o,RP+112)!=0:
            return fail(o,w,11)
        put(w,200,get(w,200)&(MAX-128))
        put(o,MAP_PENDING,0)
        return again(o,306)
    return fail(o,w,11)

def ending(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,11)
def pending(o:mutbuf,w:mutbuf) -> u64:
    if get(o,RP+80)>1 or get(o,RP+104)>1 or get(o,RP+112)>1 or get(o,RP+120)!=1:
        put(o,UNKNOWN,1)
        return 0
    combined=choose(get(o,RP+104)!=0 or get(o,RP+112)!=0,1,0)
    if get(o,RP+80)!=combined:
        put(o,UNKNOWN,1)
        return 0
    if get(o,RP+104)!=0:
        put(w,200,get(w,200)|128)
        put(o,MAP_PENDING,1)
    if get(o,RP+112)!=0:
        put(o,QUEUE_PENDING,1)
    return 1
def value_ack(o:mutbuf,consuming:u64) -> u64:
    if get(o,FB)!=0 or get(o,RP)!=VALUE_ACK or get(o,RP+88)!=1 or get(o,RP+96)>1:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=6 and status!=11:
        return 0
    if consuming==0 and get(o,RP+96)!=0:
        return 0
    if get(o,RP+96)!=0 and status!=0 and status!=11:
        return 0
    if status==0 and get(o,RP+96)!=consuming:
        return 0
    return 1
def value_valid(o:mutbuf) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==VALUE_REPLY,1,0)
def reg_valid(o:mutbuf) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==REG_REPLY and get(o,RP+80)==1,1,0)
def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,32),51,RQ,128,RP,8192,get(w,40),256)
def registry(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,144),51,RQ,128,RP,2048,get(w,152),256)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def fail(o:mutbuf,w:mutbuf,status:u64) -> u32:
    if get(o,UNKNOWN)!=0:
        put(w,200,get(w,200)|256)
    put(o,ERROR,status)
    if get(o,HELD)!=0:
        return unlock(o,400)
    return finish(o,w,status)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,KNOWN))
    put(o,24,get(w,168))
    put(o,32,get(w,128))
    put(o,40,get(w,184))
    put(o,48,get(w,192))
    put(o,56,get(w,200))
    put(o,64,get(o,MAP_PENDING))
    put(o,72,get(o,QUEUE_PENDING))
    put(o,80,get(o,UNKNOWN))
    incomplete=choose(get(w,168)==2 or get(w,168)==4,1,0)
    put(o,88,incomplete)
    return 0
def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PH,100)
    put(o,0,176)
    put(o,8,0)
    put(o,16,1)
    return 2
def unlock(o:mutbuf,next:u64) -> u32:
    put(o,HELD,0)
    put(o,NEXT,next)
    put(o,PH,102)
    put(o,0,176)
    put(o,8,0)
    return 3
def invoke(o:mutbuf,next:u64,entry:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,entry)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 9
def memory(o:mutbuf,next:u64,sk:u64,source:u64,dk:u64,target:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sk)
    put(o,8,source)
    put(o,16,dk)
    put(o,24,target)
    put(o,32,n)
    return 8
def system(o:mutbuf,next:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    invoke(o,next,number,mask,a,b,c,d,e,f)
    return 1
def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10
def read_zero(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return 0
        i=i+1
    return 1
def get(b:mutbuf,at:u64) -> u64:
    return word_load(b,at)
def put(b:mutbuf,at:u64,v:u64) -> u64:
    i=0
    while i<8:
        store(b,at+i,(v>>(8*i))&255)
        i=i+1
    return 0
def zero(b:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,at+i,0)
        i=i+1
    return 0
def between(a:mutbuf,source:u64,b:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,target+i,byte(a,source+i))
        i=i+1
    return 0
def within(b:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,target+i,byte(b,source+i))
        i=i+1
    return 0
def choose(c:bool,a:u64,b:u64) -> u64:
    if c:
        return a
    return b
'''
def source_program():return M.render(SOURCE,C,"background_native_context")
def registry_source():
    old=dict(registry.C)
    try:
        registry.C.update({k:int.from_bytes(v.encode(),"little")for k,v in dict(MAGIC="HIABGRG1",REPLY="HIABGRR1",STATE="HIABGRS1",OBJECT="HIABGRO1",NODE_MAGIC="HIABGRN1").items()})
        text=registry.source_program().replace("def future_resource_registry(","def background_native_registry(")
        before="            put(w,8,pid)\n            return finish(o,w,0)"
        assert text.count(before)==1
        return text.replace(before,"            put(w,8,pid)\n            put(o,496,1)\n            return finish(o,w,0)")
    finally:registry.C.clear();registry.C.update(old)
def main():
    for name,source in [("background_optimizer_native_context",source_program()),("background_optimizer_native_registry",registry_source())]:
        d=document(source,name);p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
