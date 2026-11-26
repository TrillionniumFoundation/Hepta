"""Native construction of an actual registered BackgroundOptimizer record.

The caller owns the record through the native BG registry. This initializer
never publishes a kind-6 Value or starts the worker before that canonical owner.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_bind import LAYOUT
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABGOQ1",REPLY="HIABGIR1",OBJECT="HIABGOB1",BIND="HIABNBD1",BIND_REPLY="HIABNBR1",
 CTOR="HIABPCQ1",CTOR_REPLY="HIABPCR1",PAYLOAD="HIABPY01",PAYLOAD_REPLY="HIABPYR1",
 FP="HIABFP04",FR="HIABFRP3",JOBS="HIABJM01",JOBS_REPLY="HIABJMR1",
 DECIMAL="HIAMVU01",DECIMAL_REPLY="HIAMVUR1",LEDGER="HIABLM01",LEDGER_REPLY="HIABLMR1",
 QUEUE="HIABGQ01",QUEUE_REPLY="HIABGQR1",WORKER="HIABGW04",WORKER_REPLY="HIABGWO2",
 VQUERY="HIABVQ06",VPRIVATE="HIABVQ05",VR="HIABVR01").items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,PH=128,FB=136,STATUS=144,DETAIL=152,
 DEST=160,INDEX=168,VALUE_QUEUE=176,VALUE_MAP=184,UNKNOWN=192,
 RQ=4096,SMALL=61440,RP=65536,OUT=786432,
 CONFIG_AT=LAYOUT["config"],GLOBAL_AT=LAYOUT["global_copy"],
 RUNTIME_AT=LAYOUT["runtime_copy"],FUTURE_AT=LAYOUT["future_copy"])
C.update({k.upper():v for k,v in LAYOUT.items()})
SOURCE=r'''
def background_native_object_construct(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or word_load(s,0)!=INPUT or word_load(s,8)!=0 or word_load(s,16)!=0:
        return 4294967293
    if length(o)<OUT or length(w)!=RECORD_BYTES:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if get(w,0)!=OBJECT or get(w,16)==0 or get(w,24)!=RECORD_BYTES or get(w,64)!=0 or get(w,80)==0:
            return 4294967293
        zero(o,128,896)
        put(w,64,5)
        request(o,BIND,0)
        put(o,PH,10)
        return 16
    if phase<100:
        return constructing(s,o,w,phase)
    if phase<200:
        return children(s,o,w,phase)
    if phase<300:
        return constants(s,o,w,phase)
    return finish(o,w,11,phase)

def constructing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if get(o,FB)!=0 or get(o,SMALL)!=BIND_REPLY:
            return unknown(o,w,10)
        put(w,56,get(w,56)|1)
        request(o,CTOR,0)
        copy_s(s,24,o,RQ+24,168)
        return entry(o,w,11,16,RQ,192,RP,524288,CONSTRUCTOR,294912)
    if phase==11:
        if valid(o,CTOR_REPLY)==0:
            return unknown(o,w,11)
        put(w,688,get(o,RP+8))
        put(w,696,get(o,RP+248))
        if get(o,RP+240)!=0:
            if get(o,RP+240)>2:
                return unknown(o,w,11)
            return finish(o,w,11,11)
        status=get(o,RP+8)
        if status==1 or status==2:
            between(o,RP+16,w,480,24)
            between(o,RP+72,w,456,24)
            put(w,672,get(o,RP+48))
            put(w,680,get(o,RP+40))
            return finish(o,w,status,11)
        if status!=0:
            return finish(o,w,11,11)
        if get(o,RP+16)==0 or get(o,RP+48)==0 or get(o,RP+72)==0 or get(o,RP+96)==0 or get(o,RP+120)==0:
            return unknown(o,w,11)
        between(o,RP+16,w,264,24)
        between(o,RP+48,w,240,24)
        between(o,RP+72,w,288,24)
        between(o,RP+96,w,312,24)
        between(o,RP+120,w,336,24)
        between(o,RP+176,w,512,64)
        put(w,576,get(o,RP+144))
        put(w,584,get(o,RP+152))
        put(w,592,get(o,RP+160))
        put(w,600,get(o,RP+168))
        put(w,56,get(w,56)|2)
        request(o,PAYLOAD,2)
        between(w,264,o,RQ+24,24)
        return payload(o,w,12)
    if phase==12:
        if valid(o,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)==0:
            return finish(o,w,11,12)
        between(o,RP+16,w,408,24)
        request(o,FP,1)
        return future(o,w,13)
    if phase==13:
        if valid(o,FR)==0:
            return unknown(o,w,13)
        if get(o,RP+16)==3 and get(o,RP+24)!=0 and get(o,RP+48)!=0:
            between(o,RP+24,w,192,24)
            between(o,RP+48,w,216,24)
            put(w,56,get(w,56)|4)
        if get(o,RP+8)!=0 or (get(w,56)&4)==0 or get(o,RP+144)!=0 or get(o,RP+128)!=0:
            return finish(o,w,11,13)
        if get(o,RP+136)!=0:
            put(o,VALUE_QUEUE,1)
        request(o,JOBS,13)
        put(o,RQ+24,get(w,FUTURE_AT+64))
        put(o,RQ+32,get(w,RUNTIME_AT+104))
        put(o,RQ+40,get(w,RUNTIME_AT+112))
        put(o,RQ+48,256)
        put(o,RQ+56,get(w,FUTURE_AT+80))
        put(o,RQ+64,get(w,192)+256)
        put(o,RQ+72,256)
        return entry(o,w,100,3,RQ,128,RP,16384,JOBS_AT,256)
    return finish(o,w,11,phase)

def children(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+136)!=1 or get(o,RP+176)!=1 or get(o,RP+168)!=0:
            return unknown(o,w,100)
        put(w,56,get(w,56)|8)
        request(o,DECIMAL,0)
        return entry(o,w,101,2,RQ,128,RP,16384,DECIMAL_AT,256)
    if phase==101:
        if valid(o,DECIMAL_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,101)
        put(w,56,get(w,56)|16)
        request(o,LEDGER,0)
        put(o,RQ+24,ep(w,2))
        put(o,RQ+32,get(w,16)+DECIMAL_AT)
        put(o,RQ+40,256)
        put(o,RQ+48,get(w,RUNTIME_AT+104))
        put(o,RQ+56,get(w,RUNTIME_AT+112))
        put(o,RQ+64,256)
        put(o,RQ+72,ep(w,3))
        put(o,RQ+80,get(w,16)+JOBS_AT)
        put(o,RQ+88,256)
        put(w,56,get(w,56)|32)
        return entry(o,w,102,1,RQ,128,RP,8192,LEDGER_AT,4096)
    if phase==102:
        if valid(o,LEDGER_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+160)!=0:
            return finish(o,w,11,102)
        request(o,VQUERY,2)
        put(o,RQ+96,1)
        put(o,RQ+104,2)
        store(o,RQ+128,49)
        return values(o,w,200,129)
    if phase==110:
        if get(o,FB)!=0 or get(o,SMALL)!=BIND_REPLY:
            return unknown(o,w,110)
        put(w,56,get(w,56)|64)
        request(o,QUEUE,0)
        put(o,RQ+16,get(w,576))
        put(o,RQ+64,ep(w,4))
        put(o,RQ+80,get(w,16)+JOB_REFS)
        put(o,RQ+88,64)
        return entry(o,w,111,0,RQ,128,RP,4096,QUEUE_AT,4096)
    if phase==111:
        if valid(o,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,111)
        put(w,56,get(w,56)|128)
        request(o,WORKER,0)
        put(o,RQ+16,ep(w,0))
        put(o,RQ+24,get(w,16)+QUEUE_AT)
        put(o,RQ+32,4096)
        put(o,RQ+40,ep(w,7))
        put(o,RQ+48,get(w,16)+BUSINESS)
        put(o,RQ+56,1064960)
        put(o,RQ+64,get(w,GLOBAL_AT+32))
        put(o,RQ+72,get(w,GLOBAL_AT+40))
        put(o,RQ+80,256)
        return entry(o,w,112,5,RQ,128,RP,8192,WORKER_AT,512)
    if phase==112:
        if valid(o,WORKER_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,112)
        put(w,56,get(w,56)|256)
        put(w,64,1)
        return finish(o,w,0,0)
    return finish(o,w,11,phase)

def constants(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if valid(o,VR)==0 or get(o,RP+8)!=0 or get(o,RP+24)==0:
            return finish(o,w,11,200)
        between(o,RP+24,w,360,24)
        request(o,VPRIVATE,91)
        between(w,360,o,RQ+24,24)
        return values(o,w,201,128)
    if phase==201:
        if retained(o,w,384)==0:
            return finish(o,w,11,201)
        if word_load(s,144)==0:
            request(o,VQUERY,2)
            put(o,RQ+96,4)
            put(o,RQ+104,2)
            put(o,RQ+128,808464434)
            return values(o,w,204,132)
        request(o,VPRIVATE,91)
        copy_s(s,144,o,RQ+24,24)
        return values(o,w,202,128)
    if phase==202:
        if retained(o,w,608)==0:
            return finish(o,w,11,202)
        return bridge_constant(s,o,w)
    if phase==203:
        if retained(o,w,632)==0:
            return finish(o,w,11,203)
        return finish_binding(o)
    if phase==204:
        if created(o,w,608)==0:
            return finish(o,w,11,204)
        return bridge_constant(s,o,w)
    if phase==205:
        if created(o,w,632)==0:
            return finish(o,w,11,205)
        return finish_binding(o)
    return finish(o,w,11,phase)
def bridge_constant(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word_load(s,168)==0:
        request(o,VQUERY,2)
        put(o,RQ+96,8)
        put(o,RQ+104,3)
        put(o,RQ+128,4621819117588971520)
        return values(o,w,205,136)
    request(o,VPRIVATE,91)
    copy_s(s,168,o,RQ+24,24)
    return values(o,w,203,128)
def finish_binding(o:mutbuf) -> u32:
    request(o,BIND,1)
    put(o,PH,110)
    return 16
def created(o:mutbuf,w:mutbuf,dest:u64) -> u64:
    if valid(o,VR)==0 or get(o,RP+8)!=0 or get(o,RP+24)==0 or get(w,dest)!=0:
        return 0
    between(o,RP+24,w,dest,24)
    return 1

def retained(o:mutbuf,w:mutbuf,dest:u64) -> u64:
    if valid(o,VR)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1:
        put(w,160,1)
        return 0
    if get(o,RP+96)==1:
        if get(o,RP+24)==0 or get(w,dest)!=0:
            put(w,160,1)
            return 0
        between(o,RP+24,w,dest,24)
    elif get(o,RP+24)!=0 or get(o,RP+32)!=0 or get(o,RP+40)!=0:
        put(w,160,1)
        return 0
    if get(o,RP+104)>1 or get(o,RP+112)>1 or get(o,RP+120)!=1:
        put(w,160,1)
        return 0
    if get(o,RP+104)!=0:
        put(w,152,1)
    if get(o,RP+112)!=0:
        put(o,VALUE_QUEUE,1)
    return choose(get(o,RP+96)==1 and get(o,RP+8)==0 and get(o,RP+104)==0,1,0)
def unknown(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,160,1)
    return finish(o,w,11,detail)
def finish(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(w,56))
    put(o,24,get(w,64))
    put(o,32,detail)
    put(o,40,get(w,688))
    put(o,48,get(w,696))
    put(o,64,get(w,152))
    put(o,72,get(o,VALUE_QUEUE))
    put(o,80,get(w,160))
    return 0
def entry(o:mutbuf,w:mutbuf,next:u64,index:u64,src:u64,n:u64,dst:u64,on:u64,ctx:u64,wn:u64) -> u32:
    return invoke(o,next,ep(w,index),51,src,n,dst,on,get(w,16)+ctx,wn)
def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+32),51,RQ,n,RP,16384,get(w,GLOBAL_AT+40),256)
def future(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+56),51,RQ,192,RP,65536,get(w,GLOBAL_AT+64),256)
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,RUNTIME_AT+104),51,RQ,128,RP,512,get(w,RUNTIME_AT+112),256)
def ep(w:mutbuf,index:u64) -> u64:
    return get(w,CONFIG_AT+136+index*8)
def valid(o:mutbuf,magic:u64) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==magic,1,0)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
'''
HELPERS=r'''
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
def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10
def copy_s(a:readbuf,at:u64,b:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(a,at+i))
        i=i+1
    return 0
def between(a:mutbuf,at:u64,b:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(a,at+i))
        i=i+1
    return 0
def get(b:mutbuf,at:u64) -> u64:
    return word_load(b,at)
def put(b:mutbuf,at:u64,v:u64) -> u64:
    i=0
    while i<8:
        store(b,at+i,(v>>(i*8))&255)
        i=i+1
    return 0
def zero(b:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,at+i,0)
        i=i+1
    return 0
def choose(c:bool,a:u64,b:u64) -> u64:
    if c:
        return a
    return b
'''
# Keep operation magic names distinct from subcontext offsets.
for key in ("jobs","decimal","ledger","queue","worker"):C[key.upper()+"_AT"]=LAYOUT[key]
def source_program():
    constants=dict(C)
    # The input op names are used as magic constants; layout offsets are *_AT.
    constants.update({k:int.from_bytes(v.encode(),"little")for k,v in dict(
      JOBS="HIABJM01",DECIMAL="HIAMVU01",LEDGER="HIABLM01",QUEUE="HIABGQ01",WORKER="HIABGW04").items()})
    return M.render(SOURCE+HELPERS,constants,"background_native_object_construct")
def main():
    name="background_optimizer_native_object_construct";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
