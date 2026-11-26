"""Fixed public BG Value producer and method boundary.

Native component replies separate primary delivery from retained cleanup.
Only the enclosing initializer supplies the one Value/global context. No
request contains an entry address, context pointer, worker or finalizer callback.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_construct import HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABGPQ1",CLEANUP="HIABGPX1",REPLY="HIABGPR1",STATE="HIABGNC1",
 RAW="HIABGOQ1",METHOD="HIABGOQ2",RAW_REPLY="HIABGOR1",METHOD_REPLY="HIABGMR1",
 QUERY="HIABVQ06",PRIVATE="HIABVQ05",CAPTURE="HIABVQ08",VR="HIABVR01",ACK="HIABVR02").items()}
C.update(PH=128,FB=136,OP=144,STATUS=152,DETAIL=160,MAP=168,QUEUE=176,UNKNOWN=184,
 RESULT_KIND=192,DELIVERED=200,RAW_OWNED=208,NEXT=216,CLEAN_STATUS=224,PID=232,ERROR_FORMAT=240,ERROR_N=248,
 PIN=512,RESULT=536,RAWCAP=560,FACT_SELF=3072,RQ=4096,RP=65536,VALUE_OUT=1179648,OUT=2097152)
SOURCE=r'''
def background_native_public(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        magic=word_load(s,0)
        op=word_load(s,8)
        if word_load(s,16)!=0:
            return 4294967293
        if magic==INPUT:
            if op>3:
                return 4294967293
            if op==1 and empty(s,48,144)==0:
                return 4294967293
            if op==2 and empty(s,96,96)==0:
                return 4294967293
            if op==3 and empty(s,120,72)==0:
                return 4294967293
        elif magic==CLEANUP:
            if op!=0 or empty(s,48,144)==0:
                return 4294967293
            op=4
        else:
            return 4294967293
        zero(o,128,8064)
        zero(o,VALUE_OUT,192)
        put(o,OP,op)
        return syscall(o,1,39,0,0,0,0,0,0,0)
    if phase<10:
        return enter(s,o,w,phase)
    if phase<30:
        return constructing(s,o,w,phase)
    if phase<60:
        return methods(s,o,w,phase)
    return cleaning(o,w,phase)
def enter(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FB)<2 or get(o,FB)>=18446744073709547521:
            return fail(o,11,1)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=get(o,FACT_SELF) or get(w,168)!=1:
            return fail(o,11,2)
        if get(w,32)==0 or get(w,40)==0 or get(w,48)!=256 or get(w,128)==0 or get(w,136)==0:
            return fail(o,11,2)
        if get(o,OP)==4:
            copy_s(s,24,o,RAWCAP,24)
            put(o,RAW_OWNED,1)
            put(o,STATUS,0)
            return raw_cleanup(o)
        if get(o,OP)==0:
            request(o,RAW,0)
            copy_s(s,24,o,RQ+24,168)
            return raw(o,10)
        request(o,PRIVATE,91)
        copy_s(s,24,o,RQ+24,24)
        return values(o,w,30,128)
    return fail(o,11,phase)
def constructing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if valid_raw(o)==0 or get(o,RP+80)>1:
            return unknown(o,10)
        if get(o,RP+80)==1:
            if get(o,RP+16)!=1 or copy_cap(o,RAWCAP,RP+24)==0:
                return unknown(o,10)
            put(o,RAW_OWNED,1)
        if raw_pending(o)==0:
            return unknown(o,10)
        if get(o,RP+8)!=0:
            put(o,STATUS,get(o,RP+8))
            put(o,DETAIL,get(o,RP+64))
            if get(o,RAW_OWNED)!=0:
                request(o,METHOD,8)
                within(o,RQ+24,RAWCAP,24)
                return raw(o,14)
            return finish(o)
        if get(o,RAW_OWNED)!=1 or get(o,RP+48)!=1 or get(o,RP+56)!=511:
            return unknown(o,10)
        request(o,CAPTURE,48)
        copy_s(s,24,o,RQ+24,24)
        put(o,RQ+96,24)
        put(o,RQ+104,6)
        within(o,RQ+128,RAWCAP,24)
        return values(o,w,11,152)
    if phase==11:
        if valid_value(o,VR)==0 or get(o,VALUE_OUT+88)!=1 or get(o,VALUE_OUT+96)>1:
            return unknown(o,11)
        if get(o,VALUE_OUT+96)==1:
            put(o,RAW_OWNED,0)
            if copy_cap(o,RESULT,VALUE_OUT+24)==0:
                return unknown(o,11)
            put(o,DELIVERED,1)
            put(o,RESULT_KIND,1)
        if extended_pending(o)==0:
            return unknown(o,11)
        if get(o,VALUE_OUT+96)==0:
            put(o,STATUS,get(o,VALUE_OUT+8))
            return raw_cleanup(o)
        if get(o,VALUE_OUT+8)!=0 or get(o,MAP)!=0:
            put(o,STATUS,11)
            put(o,DETAIL,11)
            return finish(o)
        request(o,METHOD,7)
        within(o,RQ+24,RAWCAP,24)
        within(o,RQ+48,RESULT,24)
        return raw(o,12)
    if phase==12:
        if valid_raw(o)==0 or raw_pending(o)==0 or get(o,RP+32768)!=METHOD_REPLY:
            return unknown(o,12)
        if get(o,RP+8)!=0:
            put(o,STATUS,get(o,RP+8))
            put(o,DETAIL,12)
            return result_cleanup(o,w)
        request(o,METHOD,3)
        within(o,RQ+24,RAWCAP,24)
        return raw(o,13)
    if phase==13:
        if valid_raw(o)==0 or raw_pending(o)==0 or get(o,RP+32768)!=METHOD_REPLY:
            return unknown(o,13)
        if get(o,RP+8)!=0:
            put(o,STATUS,get(o,RP+8))
            put(o,DETAIL,13)
            return result_cleanup(o,w)
        if get(o,RP+48)!=2 or (get(o,RP+56)&1536)!=1536:
            return unknown(o,13)
        return finish(o)
    if phase==14:
        if valid_raw(o)==0 or raw_pending(o)==0 or get(o,RP+32768)!=METHOD_REPLY:
            return unknown(o,14)
        child=RP+32768
        if get(o,child+56)>1:
            return unknown(o,14)
        if get(o,child+56)==1:
            if get(o,child+24)!=2 and get(o,child+24)!=3:
                return unknown(o,14)
            if copy_cap(o,RESULT,child+32)==0:
                return unknown(o,14)
            put(o,RESULT_KIND,get(o,child+24))
            put(o,DELIVERED,1)
            put(o,ERROR_FORMAT,get(o,child+112))
            put(o,ERROR_N,get(o,child+64))
        return raw_cleanup(o)
    return unknown(o,phase)
def methods(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==30:
        if valid_value(o,VR)==0 or get(o,VALUE_OUT+88)!=1 or get(o,VALUE_OUT+96)>1:
            return unknown(o,30)
        if get(o,VALUE_OUT+96)==1:
            if copy_cap(o,PIN,VALUE_OUT+24)==0:
                return unknown(o,30)
        if extended_pending(o)==0:
            return unknown(o,30)
        if get(o,VALUE_OUT+96)!=1 or get(o,MAP)!=0:
            put(o,STATUS,11)
            return pin_cleanup(o,w)
        request(o,QUERY,49)
        within(o,RQ+24,PIN,24)
        return values(o,w,31,128)
    if phase==31:
        if valid_value(o,VR)==0:
            return unknown(o,31)
        if get(o,VALUE_OUT+8)!=0 or get(o,VALUE_OUT+16)!=6:
            put(o,STATUS,1)
            put(o,DETAIL,31)
            return pin_cleanup(o,w)
        if copy_cap(o,RAWCAP,VALUE_OUT+24)==0:
            return unknown(o,31)
        op=get(o,OP)
        request(o,METHOD,op+3)
        within(o,RQ+24,RAWCAP,24)
        if op==2:
            copy_s(s,48,o,RQ+48,48)
        if op==3:
            copy_s(s,48,o,RQ+48,72)
            within(o,RQ+120,PIN,24)
        return raw(o,32)
    if phase==32:
        if valid_raw(o)==0 or raw_pending(o)==0 or get(o,RP+32768)!=METHOD_REPLY:
            return unknown(o,32)
        child=RP+32768
        if get(o,child+56)>1:
            return unknown(o,32)
        if get(o,child+56)==1:
            if copy_cap(o,RESULT,child+32)==0:
                return unknown(o,32)
            put(o,DELIVERED,1)
            put(o,RESULT_KIND,get(o,child+24))
        put(o,STATUS,get(o,RP+8))
        put(o,DETAIL,get(o,RP+64))
        if get(o,STATUS)==0 and get(o,OP)==2:
            request(o,QUERY,2)
            return values(o,w,33,128)
        return pin_cleanup(o,w)
    if phase==33:
        if valid_value(o,VR)==0 or get(o,VALUE_OUT+8)!=0 or copy_cap(o,RESULT,VALUE_OUT+24)==0:
            put(o,STATUS,11)
        else:
            put(o,RESULT_KIND,1)
            put(o,DELIVERED,1)
        return pin_cleanup(o,w)
    return unknown(o,phase)
def cleaning(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==60:
        if valid_raw(o)==0 or get(o,RP+16)!=1 or get(o,RP+88)>1:
            return unknown(o,60)
        if get(o,RP+88)==1:
            put(o,RAW_OWNED,0)
            zero(o,RAWCAP,24)
        if raw_pending(o)==0:
            return unknown(o,60)
        if get(o,RP+8)!=0 or get(o,RAW_OWNED)!=0:
            put(o,CLEAN_STATUS,11)
        return finish(o)
    if phase==61 or phase==62:
        at=PIN
        if phase==62:
            at=RESULT
        if valid_value(o,ACK)==0 or get(o,VALUE_OUT+88)!=1 or get(o,VALUE_OUT+96)>1:
            return unknown(o,phase)
        if get(o,VALUE_OUT+96)==1:
            zero(o,at,24)
            if phase==62:
                put(o,DELIVERED,0)
                put(o,RESULT_KIND,0)
        if extended_pending(o)==0:
            return unknown(o,phase)
        if get(o,VALUE_OUT+96)==0 or get(o,MAP)!=0:
            put(o,CLEAN_STATUS,11)
        if get(o,VALUE_OUT+8)==11 and get(o,VALUE_OUT+80)==0:
            put(o,UNKNOWN,1)
            put(o,CLEAN_STATUS,11)
        return finish(o)
    return unknown(o,phase)
def pin_cleanup(o:mutbuf,w:mutbuf) -> u32:
    if get(o,PIN)==0:
        return finish(o)
    request(o,PRIVATE,78)
    within(o,RQ+24,PIN,24)
    return values(o,w,61,128)
def result_cleanup(o:mutbuf,w:mutbuf) -> u32:
    request(o,PRIVATE,78)
    within(o,RQ+24,RESULT,24)
    return values(o,w,62,128)
def raw_cleanup(o:mutbuf) -> u32:
    request(o,RAW,2)
    within(o,RQ+24,RAWCAP,24)
    return raw(o,60)
def raw_pending(o:mutbuf) -> u64:
    if get(o,RP+72)>1 or get(o,RP+96)>1 or get(o,RP+104)>1:
        return 0
    if get(o,RP+72)!=0:
        put(o,UNKNOWN,1)
    if get(o,RP+96)!=0:
        put(o,MAP,1)
    if get(o,RP+104)!=0:
        put(o,QUEUE,1)
    return 1
def extended_pending(o:mutbuf) -> u64:
    if get(o,VALUE_OUT+104)>1 or get(o,VALUE_OUT+112)>1 or get(o,VALUE_OUT+120)!=1:
        return 0
    both=choose(get(o,VALUE_OUT+104)!=0 or get(o,VALUE_OUT+112)!=0,1,0)
    if get(o,VALUE_OUT+80)!=both:
        return 0
    if get(o,VALUE_OUT+104)!=0:
        put(o,MAP,1)
    if get(o,VALUE_OUT+112)!=0:
        put(o,QUEUE,1)
    return 1
def valid_raw(o:mutbuf) -> u64:
    if get(o,FB)==0 and get(o,RP)==RAW_REPLY:
        return 1
    return 0
def valid_value(o:mutbuf,magic:u64) -> u64:
    if get(o,FB)==0 and get(o,VALUE_OUT)==magic:
        return 1
    return 0
def copy_cap(o:mutbuf,to:u64,at:u64) -> u64:
    if get(o,to)!=0 or get(o,at)==0 or get(o,at+8)==0 or get(o,at+16)==0:
        return 0
    within(o,to,at,24)
    return 1
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    return finish(o)
def unknown(o:mutbuf,detail:u64) -> u32:
    put(o,UNKNOWN,1)
    return fail(o,11,detail)
def finish(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,RESULT_KIND))
    within(o,24,RESULT,24)
    put(o,48,get(o,DELIVERED))
    put(o,56,1)
    put(o,64,get(o,MAP))
    put(o,72,get(o,QUEUE))
    put(o,80,get(o,UNKNOWN))
    put(o,88,get(o,CLEAN_STATUS))
    put(o,96,get(o,DETAIL))
    put(o,104,get(o,RAW_OWNED))
    put(o,112,get(o,ERROR_FORMAT))
    put(o,120,get(o,ERROR_N))
    within(o,4096,RAWCAP,24)
    within(o,4120,PIN,24)
    return 0
def raw(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 16
def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,32),51,RQ,n,VALUE_OUT,16384,get(w,40),256)
def syscall(o:mutbuf,next:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    invoke(o,next,number,mask,a,b,c,d,e,f)
    return 1
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def within(b:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(b,at+i))
        i=i+1
    return 0
def empty(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return 0
        i=i+1
    return 1
'''
def source_program():return M.render(SOURCE+HELPERS,C,"background_native_public")
def main():
    name="background_optimizer_native_public";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
