"""Registered native BackgroundOptimizer object custody.

Private raw-domain calls are used only by the enclosing public resource producer.
Every record pointer is obtained from a newly owned allocation or the real
nonce-qualified native registry; public caller pointers are never accepted.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_bind import LAYOUT
from tools.generate_hia_background_optimizer_native_object_construct import HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABGOQ1",PRIVATE="HIABGOQ2",METHOD_REPLY="HIABGMR1",REPLY="HIABGOR1",STATE="HIABGNC1",OBJECT="HIABGOB1",
 REG="HIABGRG1",REG_REPLY="HIABGRR1",INIT_REPLY="HIABGIR1",RETIRE="HIABGRT1",RETIRE_REPLY="HIABGTR1").items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,PH=128,FB=136,OP=144,ERROR=152,DETAIL=160,
 HELD=168,NEXT=176,ACTIVE=184,KNOWN=192,DELIVERED=200,CONSUMED=208,PID=216,P=224,
 RANDOM_USED=232,ALLOCATION=240,OWNED_REG=248,MAP_PENDING=256,QUEUE_PENDING=264,UNKNOWN=272,RECORD_ACTIVE=280,
 FACT_SELF=1024,FACT_ENTRY=1032,ROW=2048,CAP=2112,RQ=4096,RP=8192,HEADER=16384,CHILD=32768,OUT=1048576)
C.update({k.upper():v for k,v in LAYOUT.items()})
SOURCE=r'''
def background_native_objects(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or word_load(s,16)!=0 or length(o)<OUT or length(w)!=512:
        return 4294967293
    op=word_load(s,8)
    magic=word_load(s,0)
    if magic==INPUT:
        if op>2 or (op!=0 and read_zero(s,48,144)==0):
            return 4294967293
    elif magic==PRIVATE:
        if op<3 or op>8:
            return 4294967293
        end=48
        if op==5:
            end=96
        elif op==6:
            end=144
        elif op==7:
            end=72
        if read_zero(s,end,192-end)==0:
            return 4294967293
    else:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        zero(o,128,32640)
        put(o,OP,op)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return enter(s,o,w,phase)
    if phase<200:
        return locks(o,w,phase)
    if phase<300:
        return allocate_record(s,o,w,phase)
    if phase<400:
        return find_record(s,o,w,phase)
    if phase<500:
        return destroy_record(o,w,phase)
    if phase>=600:
        return methods(o,w,phase)
    return ending(o,w,phase)

def enter(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return finish(o,w,11)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=get(o,FACT_SELF) or get(w,24)==0:
            return finish(o,w,11)
        if get(w,32)==0 or get(w,40)==0 or get(w,48)!=256 or get(w,128)==0 or get(w,136)==0:
            return finish(o,w,11)
        if get(w,144)==0 or get(w,152)!=get(w,16)+256 or get(w,160)!=256 or get(w,240)==0 or get(w,248)!=1024:
            return finish(o,w,11)
        return lock(o,10)
    if phase==10:
        if get(w,168)!=1 or get(w,184)==MAX or (get(w,200)&7)!=7:
            return fail(o,w,6)
        put(w,184,get(w,184)+1)
        put(o,ACTIVE,1)
        if get(o,OP)==0:
            return unlock(o,200)
        request(o,REG,6)
        copy_s(s,24,o,RQ+24,24)
        return registry(o,w,300)
    return fail(o,w,11)

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
    return fail(o,w,11)

def allocate_record(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        put(o,PH,201)
        put(o,0,RECORD_BYTES)
        return 6
    if phase==201:
        p=get(o,FB)
        if p==0 or p>=NEGATIVE or p>MAX-RECORD_BYTES:
            return fail(o,w,5)
        put(o,P,p)
        put(o,ALLOCATION,1)
        put(o,0,p)
        put(o,8,RECORD_BYTES)
        put(o,PH,202)
        return 11
    if phase==202:
        zero(o,HEADER,1024)
        put(o,HEADER,OBJECT)
        put(o,HEADER+8,get(o,PID))
        put(o,HEADER+16,get(o,P))
        put(o,HEADER+24,RECORD_BYTES)
        put(o,HEADER+32,get(w,16))
        put(o,HEADER+40,get(w,128))
        return system(o,203,318,3,HEADER+48,8,0,0,0,0)
    if phase==203:
        n=get(o,FB)
        used=get(o,RANDOM_USED)
        if n==MAX-3:
            return system(o,203,318,3,HEADER+48+used,8-used,0,0,0,0)
        if n==0 or n>=NEGATIVE or n>8-used:
            return allocation_failed(o,w,11)
        used=used+n
        put(o,RANDOM_USED,used)
        if used<8:
            return system(o,203,318,3,HEADER+48+used,8-used,0,0,0,0)
        if get(o,HEADER+48)==0:
            put(o,RANDOM_USED,0)
            return system(o,203,318,3,HEADER+48,8,0,0,0,0)
        return memory(o,204,3,HEADER,0,get(o,P),1024)
    if phase==204:
        return memory(o,205,1,0,0,get(o,P)+GLOBAL_COPY,512)
    if phase==205:
        return memory(o,206,0,get(w,240),0,get(o,P)+CONFIG,1024)
    if phase==206:
        return memory(o,207,0,get(w,88),0,get(o,P)+RUNTIME_COPY,512)
    if phase==207:
        return memory(o,208,0,get(w,64),0,get(o,P)+FUTURE_COPY,256)
    if phase==208:
        return memory(o,209,0,get(w,112)+80,0,get(o,P)+704,8)
    if phase==209:
        return lock(o,210)
    if phase==210:
        if get(w,168)!=1 or get(w,192)==MAX:
            return allocation_failed(o,w,6)
        request(o,REG,1)
        put(o,RQ+72,32)
        put(o,RQ+128,get(o,P))
        put(o,RQ+136,RECORD_BYTES)
        put(o,RQ+144,get(o,HEADER+48))
        put(o,RQ+152,get(w,128))
        return registry_n(o,w,211,160)
    if phase==211:
        if reg_valid(o)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+8)!=0:
            return allocation_failed(o,w,11)
        if get(o,RP+16)==0 or get(o,RP+24)==0 or get(o,RP+32)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        within(o,CAP,RP+16,24)
        put(o,OWNED_REG,1)
        put(o,DELIVERED,1)
        put(o,KNOWN,1)
        put(w,192,get(w,192)+1)
        return memory(o,212,3,CAP,0,get(o,P)+80,24)
    if phase==212:
        return unlock(o,213)
    if phase==213:
        put(o,PH,214)
        return 16
    if phase==214:
        if get(o,FB)!=0 or get(o,CHILD)!=INIT_REPLY:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        put(o,MAP_PENDING,get(o,CHILD+64))
        put(o,QUEUE_PENDING,get(o,CHILD+72))
        put(o,UNKNOWN,get(o,CHILD+80))
        put(o,DETAIL,get(o,CHILD+32))
        put(o,ERROR,get(o,CHILD+8))
        return memory(o,215,0,get(o,P),3,HEADER,1024)
    if phase==215:
        return fail(o,w,get(o,ERROR))
    if phase==290:
        put(o,P,0)
        put(o,ALLOCATION,0)
        return fail(o,w,get(o,ERROR))
    return fail(o,w,11)

def find_record(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if reg_valid(o)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+8)!=0:
            put(o,KNOWN,1)
            return fail(o,w,get(o,RP+8))
        if get(o,RP+40)!=32 or get(o,RP+64)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        return memory(o,301,0,get(o,RP+64),3,ROW,32)
    if phase==301:
        p=get(o,ROW)
        if p==0 or p>=NEGATIVE or p>MAX-RECORD_BYTES or get(o,ROW+8)!=RECORD_BYTES or get(o,ROW+16)==0 or get(o,ROW+24)!=get(w,128):
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        put(o,P,p)
        copy_s(s,24,o,CAP,24)
        return memory(o,302,0,p,3,HEADER,1024)
    if phase==302:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+16)!=get(o,P) or get(o,HEADER+24)!=RECORD_BYTES:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,HEADER+32)!=get(w,16) or get(o,HEADER+40)!=get(w,128) or get(o,HEADER+48)!=get(o,ROW+16):
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if same(o,CAP,HEADER+80)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        put(o,KNOWN,1)
        if get(o,OP)==1:
            return fail(o,w,0)
        if get(o,OP)>=3:
            if get(o,HEADER+64)!=1 and get(o,HEADER+64)!=2:
                if get(o,OP)!=8 or get(o,HEADER+64)!=5:
                    return fail(o,w,6)
            if get(o,HEADER+752)!=0 or get(o,HEADER+72)==MAX:
                return fail(o,w,6)
            if get(o,OP)==3 and get(o,HEADER+72)!=0:
                return fail(o,w,6)
            put(o,HEADER+72,get(o,HEADER+72)+1)
            put(o,RECORD_ACTIVE,1)
            return memory(o,305,3,HEADER+72,0,get(o,P)+72,8)
        request(o,REG,7)
        within(o,RQ+24,CAP,24)
        return registry(o,w,303)
    if phase==303:
        if reg_valid(o)==0 or get(o,RP+8)!=0 or get(o,RP+72)>1:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+72)!=1 or get(o,HEADER+72)!=0 or get(o,HEADER+752)!=0:
            return fail(o,w,6)
        put(o,HEADER+752,1)
        return memory(o,304,3,HEADER+752,0,get(o,P)+752,8)
    if phase==304:
        return unlock(o,400)
    if phase==305:
        return unlock(o,600)
    return fail(o,w,11)

def destroy_record(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        request(o,RETIRE,0)
        put(o,PH,401)
        return 17
    if phase==401:
        if get(o,FB)!=0 or get(o,CHILD)!=RETIRE_REPLY:
            put(o,UNKNOWN,1)
            put(o,HEADER+160,1)
            return memory(o,408,3,HEADER+160,0,get(o,P)+160,8)
        put(o,MAP_PENDING,get(o,CHILD+64))
        put(o,QUEUE_PENDING,get(o,CHILD+72))
        put(o,UNKNOWN,get(o,CHILD+80))
        put(o,DETAIL,get(o,CHILD+32))
        if get(o,CHILD+8)!=0 or get(o,CHILD+24)!=4 or get(o,CHILD+16)!=0 or get(o,CHILD+64)!=0 or get(o,CHILD+80)!=0:
            return again(o,408)
        return lock(o,402)
    if phase==402:
        request(o,REG,3)
        within(o,RQ+24,CAP,24)
        return registry(o,w,403)
    if phase==403:
        if reg_valid(o)==0 or get(o,RP+88)>1:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+88)==1:
            put(o,CONSUMED,1)
            zero(o,CAP,24)
        if get(o,RP+8)!=0 or get(o,CONSUMED)!=1 or get(w,192)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        put(w,192,get(w,192)-1)
        return unlock(o,404)
    if phase==404:
        put(o,0,get(o,P))
        put(o,PH,405)
        return 7
    if phase==405:
        put(o,P,0)
        zero(o,HEADER,1024)
        return fail(o,w,0)
    if phase==408:
        zero(o,HEADER+752,8)
        return memory(o,409,3,HEADER+752,0,get(o,P)+752,8)
    if phase==409:
        return memory(o,410,0,get(o,P),3,HEADER,1024)
    if phase==410:
        return fail(o,w,11)
    return fail(o,w,11)

def methods(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        put(o,PH,601)
        return 18
    if phase==601:
        if get(o,FB)!=0 or get(o,CHILD)!=METHOD_REPLY:
            put(o,UNKNOWN,1)
            put(o,ERROR,11)
        else:
            put(o,MAP_PENDING,get(o,CHILD+72))
            put(o,QUEUE_PENDING,get(o,CHILD+80))
            put(o,UNKNOWN,get(o,CHILD+88))
            put(o,DETAIL,get(o,CHILD+64))
            put(o,ERROR,get(o,CHILD+8))
        return lock(o,602)
    if phase==602:
        return memory(o,603,0,get(o,P),3,HEADER,1024)
    if phase==603:
        if get(o,RECORD_ACTIVE)!=1 or get(o,HEADER+72)==0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        put(o,HEADER+72,get(o,HEADER+72)-1)
        put(o,RECORD_ACTIVE,0)
        return memory(o,604,3,HEADER+72,0,get(o,P)+72,8)
    if phase==604:
        return fail(o,w,get(o,ERROR))
    return fail(o,w,11)

def ending(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,ACTIVE)!=0:
            if get(w,184)==0:
                put(o,UNKNOWN,1)
                put(o,ERROR,11)
            else:
                put(w,184,get(w,184)-1)
                put(o,ACTIVE,0)
        return unlock(o,501)
    if phase==501:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,11)
def allocation_failed(o:mutbuf,w:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    if get(o,OWNED_REG)!=0:
        return fail(o,w,status)
    if get(o,ALLOCATION)!=0:
        put(o,0,get(o,P))
        put(o,PH,290)
        return 7
    return fail(o,w,status)
def fail(o:mutbuf,w:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    if get(o,HELD)!=0:
        return again(o,500)
    if get(o,ACTIVE)!=0:
        return lock(o,500)
    return finish(o,w,status)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,KNOWN))
    within(o,24,CAP,24)
    put(o,48,choose(get(o,P)!=0,get(o,HEADER+64),4))
    put(o,56,choose(get(o,P)!=0,get(o,HEADER+56),0))
    put(o,64,get(o,DETAIL))
    put(o,72,get(o,UNKNOWN))
    put(o,80,get(o,DELIVERED))
    put(o,88,get(o,CONSUMED))
    put(o,96,get(o,MAP_PENDING))
    put(o,104,get(o,QUEUE_PENDING))
    return 0
def reg_valid(o:mutbuf) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==REG_REPLY and get(o,RP+80)==1,1,0)
def registry(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return registry_n(o,w,next,128)
def registry_n(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,144),51,RQ,n,RP,2048,get(w,152),256)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
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
def within(b:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(b,at+i))
        i=i+1
    return 0
def same(b:mutbuf,a:u64,c:u64) -> u64:
    return choose(get(b,a)==get(b,c) and get(b,a+8)==get(b,c+8) and get(b,a+16)==get(b,c+16),1,0)
def read_zero(b:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(b,at+i)!=0:
            return 0
        i=i+1
    return 1
'''
def source_program():return M.render(SOURCE+HELPERS,C,"background_native_objects")
def main():
    name="background_optimizer_native_objects";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
