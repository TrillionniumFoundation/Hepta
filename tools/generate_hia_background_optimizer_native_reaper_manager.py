"""Native kind-6 retirement scheduling and owned reaper registry.

The fixed RFQ path never joins a live BG worker while the shared finalizer is
held. Its independent native record stays owned until the actual reaper thread
has returned and pthread_join has consumed the thread handle.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools import generate_hia_background_optimizer_native_context as context
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 RFQ="HIAVRFQ1",RFR="HIAVRFR1",CONTROL="HIABRMQ1",REPLY="HIABRMR1",STATE="HIABGNC1",
 CONFIG="HIABGCF1",LIST="HIABRL01",OWNER="HIAGLOW1",OBJECT="HIABGOB1",
 RECORD="HIABRTC1",THREAD="HIABRTQ1",THREAD_REPLY="HIABRTR1",
 REG="HIABGRG1",REG_REPLY="HIABGRR1",QUERY="HIABVQ06",VR="HIABVR01",
 WORKER="HIABGW04",WORKER_REPLY="HIABGWO2").items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,PH=128,FB=136,OP=144,NEXT=152,HELD=160,
 PID=168,ACTIVE=176,KNOWN=184,CONSUMED=192,PENDING=200,UNKNOWN=208,DETAIL=216,
 REAPER_P=224,TARGET_P=232,NEW=240,REGISTERED=248,RANDOM_USED=256,STATUS=264,
 FACT_SELF=1024,FACT_ENTRY=1032,FACT_THREAD=1040,FACT_OLD=1048,
 PARENT=1152,CFG=2176,ROW=2816,HEADER=3072,CURSOR=512,TARGET_CAP=536,
 RQ=4096,RP=8192,RECORD_BYTES=1048576,OBJECT_BYTES=2097152)
SOURCE=r'''
def background_native_reaper_manager(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<16384 or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if word_load(s,0)==RFQ:
            if length(o)<1048576 or word_load(s,8)>1 or word_load(s,16)==0 or word_load(s,24)!=6:
                return 4294967293
            if word_load(s,32)==0 or word_load(s,40)==0 or word_load(s,48)==0 or read_zero(s,56,72)==0:
                return 4294967293
        elif word_load(s,0)==CONTROL:
            if word_load(s,8)!=1 or read_zero(s,16,112)==0:
                return 4294967293
        else:
            return 4294967293
        zero(o,128,3968)
        put(o,OP,choose(word_load(s,0)==CONTROL,1,0))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return locks(o,w,phase)
    if phase<300:
        return scan(s,o,w,phase)
    if phase<400:
        return inspect_target(s,o,w,phase)
    if phase<500:
        return allocate(s,o,w,phase)
    if phase<600:
        return start_thread(o,w,phase)
    if phase<700:
        return finalizing(s,o,w,phase)
    if phase<800:
        return sweeping(o,w,phase)
    return ending(o,w,phase)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return finish(o,w,11)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=get(o,FACT_SELF) or get(w,24)==0:
            return finish(o,w,11)
        if get(w,232)==0 or get(w,232)>MAX-2048 or get(w,128)==0 or get(w,136)==0:
            return finish(o,w,11)
        if get(w,32)==0 or get(w,40)!=get(w,232)+512 or get(w,48)!=256 or get(w,240)==0 or get(w,248)!=1024:
            return finish(o,w,11)
        if get(w,144)==0 or get(w,152)!=get(w,16)+256 or get(w,160)!=256:
            return finish(o,w,11)
        if get(o,OP)==0 and word_load(s,16)!=get(w,136):
            return finish(o,w,11)
        return memory(o,3,0,get(w,232),3,PARENT,1024)
    if phase==3:
        if get(o,PARENT)!=OWNER or get(o,PARENT+8)!=get(o,PID) or get(o,PARENT+16)!=get(w,232) or get(o,PARENT+80)!=1:
            return finish(o,w,11)
        if get(o,PARENT+40)!=get(w,32) or get(o,PARENT+48)!=get(w,40) or get(o,PARENT+56)!=256 or get(o,PARENT+664)!=get(w,136):
            return finish(o,w,11)
        if get(o,PARENT+872)!=get(w,16) or get(o,PARENT+880)!=512 or get(o,PARENT+888)!=get(w,128):
            return finish(o,w,11)
        return system(o,4,186,0,0,0,0,0,0,0)
    if phase==4:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return finish(o,w,11)
        put(o,568,get(o,FB))
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
    return fail(o,w,11,phase)

def scan(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(w,168)!=1 and get(w,168)!=2:
            return fail(o,w,6,200)
        if get(w,184)==MAX:
            return fail(o,w,6,200)
        put(w,184,get(w,184)+1)
        put(o,ACTIVE,1)
        put(o,KNOWN,1)
        return memory(o,201,0,get(w,240),3,CFG,512)
    if phase==201:
        if get(o,CFG)!=CONFIG or get(o,CFG+8)!=get(o,PID) or get(o,CFG+16)!=get(w,16) or get(o,CFG+24)!=get(w,128):
            return unknown(o,w,201)
        if get(o,CFG+128)!=40 or get(o,CFG+456)!=LIST or get(o,CFG+496)!=0:
            return unknown(o,w,201)
        within(o,CURSOR,CFG+464,24)
        put(o,280,get(o,CFG+488))
        if get(o,OP)==0:
            copy_s(s,32,o,TARGET_CAP,24)
        return again(o,210)
    if phase==210:
        if get(o,CURSOR)==0:
            if get(o,OP)==1:
                if get(o,CFG+488)!=0:
                    return unknown(o,w,210)
                return fail(o,w,0,0)
            request(o,REG,6)
            within(o,RQ+24,TARGET_CAP,24)
            return registry(o,w,300,128)
        if get(o,280)==0:
            return unknown(o,w,210)
        put(o,280,get(o,280)-1)
        request(o,REG,6)
        within(o,RQ+24,CURSOR,24)
        return registry(o,w,211,128)
    if phase==211:
        if reg_valid(o)==0 or get(o,RP+8)!=0 or get(o,RP+40)!=32 or get(o,RP+64)==0:
            return unknown(o,w,211)
        return memory(o,212,0,get(o,RP+64),3,ROW,32)
    if phase==212:
        if get(o,ROW)==0 or get(o,ROW)>=NEGATIVE or get(o,ROW)>MAX-RECORD_BYTES or get(o,ROW+8)!=RECORD_BYTES:
            return unknown(o,w,212)
        if get(o,ROW+16)==0 or get(o,ROW+24)!=get(w,128):
            return unknown(o,w,212)
        put(o,REAPER_P,get(o,ROW))
        return memory(o,213,0,get(o,ROW),3,HEADER,512)
    if phase==213:
        if get(o,HEADER)!=RECORD or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+16)!=get(o,REAPER_P):
            return unknown(o,w,213)
        if get(o,HEADER+24)!=get(w,16) or get(o,HEADER+32)!=get(w,128) or get(o,HEADER+400)!=get(o,ROW+16):
            return unknown(o,w,213)
        if same(o,CURSOR,HEADER+64)==0 or get(o,HEADER+344)!=get(o,FACT_THREAD) or get(o,HEADER+328)!=1:
            return unknown(o,w,213)
        if get(o,OP)==1:
            return again(o,700)
        if same(o,TARGET_CAP,HEADER+112)==0:
            within(o,CURSOR,HEADER+88,24)
            return again(o,210)
        if get(o,HEADER+336)!=0 or get(o,HEADER+248)!=0:
            put(o,PENDING,1)
            return fail(o,w,11,214)
        if get(o,HEADER+232)!=0:
            if get(o,HEADER+224)==1 and get(o,HEADER+240)==0:
                put(o,CONSUMED,1)
                return fail(o,w,0,0)
            put(o,PENDING,1)
            return fail(o,w,11,215)
        if get(o,HEADER+176)==0:
            return again(o,500)
        request(o,THREAD,2)
        return thread(o,214)
    if phase==214:
        if thread_valid(o)==0:
            return unknown(o,w,214)
        if get(o,RP+8)!=0 or get(o,RP+64)!=0:
            put(o,PENDING,1)
            return receipt(o,w,11,0,1,214)
        if get(o,RP+16)==4 or get(o,RP+16)==5:
            return unlock(o,600)
        return receipt(o,w,11,0,1,0)
    return unknown(o,w,phase)

def inspect_target(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if reg_valid(o)==0 or get(o,RP+8)!=0 or get(o,RP+40)!=32 or get(o,RP+64)==0:
            return unknown(o,w,300)
        return memory(o,301,0,get(o,RP+64),3,ROW,32)
    if phase==301:
        if get(o,ROW)==0 or get(o,ROW)>=NEGATIVE or get(o,ROW)>MAX-OBJECT_BYTES or get(o,ROW+8)!=OBJECT_BYTES:
            return unknown(o,w,301)
        if get(o,ROW+16)==0 or get(o,ROW+24)!=get(w,128):
            return unknown(o,w,301)
        put(o,TARGET_P,get(o,ROW))
        return memory(o,302,0,get(o,ROW),3,HEADER,1024)
    if phase==302:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+16)!=get(o,TARGET_P) or get(o,HEADER+24)!=OBJECT_BYTES:
            return unknown(o,w,302)
        if get(o,HEADER+32)!=get(w,16) or get(o,HEADER+40)!=get(w,128) or get(o,HEADER+48)!=get(o,ROW+16):
            return unknown(o,w,302)
        if same(o,TARGET_CAP,HEADER+80)==0:
            return unknown(o,w,302)
        put(o,560,get(o,HEADER+48))
        if (get(o,HEADER+56)&512)==0:
            put(o,REAPER_P,0)
            return unlock(o,600)
        request(o,WORKER,3)
        return invoke(o,303,get(o,CFG+136+5*8),51,RQ,128,RP,8192,get(o,TARGET_P)+8704,512)
    if phase==303:
        if get(o,FB)!=0 or get(o,RP)!=WORKER_REPLY or get(o,RP+8)!=0 or get(o,RP+64)!=0:
            return unknown(o,w,303)
        if get(o,RP+24)==4:
            put(o,REAPER_P,0)
            return unlock(o,600)
        return again(o,400)
    return unknown(o,w,phase)

def allocate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if get(o,CFG+488)==MAX:
            return fail(o,w,11,400)
        put(o,0,RECORD_BYTES)
        put(o,PH,401)
        return 6
    if phase==401:
        if get(o,FB)==0 or get(o,FB)>=NEGATIVE or get(o,FB)>MAX-RECORD_BYTES:
            put(o,PENDING,1)
            return fail(o,w,11,401)
        put(o,REAPER_P,get(o,FB))
        put(o,NEW,1)
        put(o,0,get(o,FB))
        put(o,8,RECORD_BYTES)
        put(o,PH,402)
        return 11
    if phase==402:
        zero(o,HEADER,512)
        put(o,HEADER,RECORD)
        put(o,HEADER+8,get(o,PID))
        put(o,HEADER+16,get(o,REAPER_P))
        put(o,HEADER+24,get(w,16))
        put(o,HEADER+32,get(w,128))
        put(o,HEADER+40,get(w,32))
        put(o,HEADER+48,get(w,40))
        put(o,HEADER+56,256)
        within(o,HEADER+88,CFG+464,24)
        within(o,HEADER+112,TARGET_CAP,24)
        put(o,HEADER+136,get(o,TARGET_P))
        put(o,HEADER+144,OBJECT_BYTES)
        put(o,HEADER+152,get(o,560))
        put(o,HEADER+160,1)
        put(o,HEADER+328,1)
        put(o,HEADER+344,get(o,FACT_THREAD))
        put(o,HEADER+352,get(o,CFG+136+5*8))
        put(o,HEADER+360,get(o,CFG+136+11*8))
        put(o,HEADER+392,get(o,CFG+136))
        put(o,HEADER+408,get(o,568))
        return system(o,403,318,3,HEADER+400,8,0,0,0,0)
    if phase==403:
        if get(o,FB)==MAX-3:
            return system(o,403,318,3,HEADER+400+get(o,RANDOM_USED),8-get(o,RANDOM_USED),0,0,0,0)
        if get(o,FB)==0 or get(o,FB)>=NEGATIVE or get(o,FB)>8-get(o,RANDOM_USED):
            return free_new(o,w,403)
        put(o,RANDOM_USED,get(o,RANDOM_USED)+get(o,FB))
        if get(o,RANDOM_USED)<8:
            return system(o,403,318,3,HEADER+400+get(o,RANDOM_USED),8-get(o,RANDOM_USED),0,0,0,0)
        if get(o,HEADER+400)==0:
            put(o,RANDOM_USED,0)
            return system(o,403,318,3,HEADER+400,8,0,0,0,0)
        return memory(o,404,3,HEADER,0,get(o,REAPER_P),512)
    if phase==404:
        request(o,REG,1)
        put(o,RQ+72,32)
        put(o,RQ+128,get(o,REAPER_P))
        put(o,RQ+136,RECORD_BYTES)
        put(o,RQ+144,get(o,HEADER+400))
        put(o,RQ+152,get(w,128))
        return registry(o,w,405,160)
    if phase==405:
        if reg_valid(o)==0:
            return unknown(o,w,405)
        if get(o,RP+8)!=0:
            return free_new(o,w,405)
        if get(o,RP+16)==0 or get(o,RP+24)==0 or get(o,RP+32)==0:
            return unknown(o,w,405)
        put(o,REGISTERED,1)
        within(o,HEADER+64,RP+16,24)
        within(o,CURSOR,RP+16,24)
        within(o,CFG+464,RP+16,24)
        put(o,CFG+488,get(o,CFG+488)+1)
        return memory(o,406,3,HEADER+64,0,get(o,REAPER_P)+64,24)
    if phase==406:
        return memory(o,407,3,CFG+464,0,get(w,240)+464,32)
    if phase==407:
        put(o,NEW,0)
        return again(o,500)
    if phase==490:
        put(o,NEW,0)
        put(o,REAPER_P,0)
        put(o,PENDING,1)
        return fail(o,w,11,get(o,DETAIL))
    return unknown(o,w,phase)

def start_thread(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,HEADER+184)!=0:
            return again(o,503)
        request(o,QUERY,21)
        return invoke(o,501,get(w,32),51,RQ,128,RP,8192,get(w,40),256)
    if phase==501:
        if get(o,FB)!=0 or get(o,RP)!=VR:
            return unknown(o,w,501)
        if get(o,RP+8)!=0:
            if get(o,RP+24)!=0:
                within(o,HEADER+184,RP+24,24)
                put(o,HEADER+336,1)
                return memory(o,502,3,HEADER,0,get(o,REAPER_P),512)
            return receipt(o,w,11,0,1,501)
        if get(o,RP+24)==0 or get(o,RP+32)==0 or get(o,RP+40)==0:
            return unknown(o,w,501)
        within(o,HEADER+184,RP+24,24)
        return memory(o,502,3,HEADER+184,0,get(o,REAPER_P)+184,24)
    if phase==502:
        if get(o,HEADER+336)!=0:
            return receipt(o,w,11,0,1,502)
        return again(o,503)
    if phase==503:
        request(o,THREAD,0)
        return memory(o,504,3,RQ,0,get(o,REAPER_P)+1024,128)
    if phase==504:
        put(o,HEADER+160,2)
        return memory(o,505,3,HEADER+160,0,get(o,REAPER_P)+160,8)
    if phase==505:
        put(o,PH,506)
        return 17
    if phase==506:
        if get(o,FB)!=0:
            return receipt(o,w,11,0,1,506)
        put(o,HEADER+176,1)
        return memory(o,507,3,HEADER+176,0,get(o,REAPER_P)+176,8)
    if phase==507:
        return receipt(o,w,11,0,1,0)
    return unknown(o,w,phase)

def finalizing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        put(o,PH,601)
        return 16
    if phase==601:
        if get(o,FB)!=0 or get(o,RP)!=RFR or get(o,RP+16)>1 or get(o,RP+24)>1 or get(o,RP+32)>1:
            put(o,UNKNOWN,1)
            put(o,STATUS,11)
            return lock(o,602)
        put(o,STATUS,get(o,RP+8))
        put(o,KNOWN,get(o,RP+16))
        put(o,CONSUMED,get(o,RP+24))
        put(o,PENDING,get(o,RP+32))
        if get(o,RP+16)==0:
            put(o,UNKNOWN,1)
        return lock(o,602)
    if phase==602:
        if get(o,REAPER_P)==0:
            return fail(o,w,get(o,STATUS),0)
        return receipt(o,w,get(o,STATUS),get(o,CONSUMED),get(o,PENDING),0)
    if phase==610:
        if thread_valid(o)==0 or get(o,RP+8)!=0:
            return unknown(o,w,610)
        return fail(o,w,get(o,STATUS),get(o,DETAIL))
    return unknown(o,w,phase)

def sweeping(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        request(o,THREAD,3)
        return thread(o,701)
    if phase==701:
        if thread_valid(o)==0:
            return unknown(o,w,701)
        if get(o,RP+8)!=0:
            put(o,PENDING,1)
            return fail(o,w,6,701)
        if get(o,RP+16)!=9 or get(o,RP+104)!=1 or get(o,RP+72)!=0 or get(o,RP+80)!=0:
            return unknown(o,w,701)
        request(o,REG,3)
        within(o,RQ+24,CURSOR,24)
        return registry(o,w,702,128)
    if phase==702:
        if reg_valid(o)==0 or get(o,RP+8)!=0 or get(o,RP+88)!=1 or get(o,CFG+488)==0:
            return unknown(o,w,702)
        within(o,CFG+464,HEADER+88,24)
        put(o,CFG+488,get(o,CFG+488)-1)
        return memory(o,703,3,CFG+464,0,get(w,240)+464,32)
    if phase==703:
        put(o,0,get(o,REAPER_P))
        put(o,PH,704)
        return 7
    if phase==704:
        put(o,REAPER_P,0)
        within(o,CURSOR,CFG+464,24)
        return again(o,210)
    return unknown(o,w,phase)

def ending(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,ACTIVE)!=0:
            if get(w,184)==0:
                put(o,UNKNOWN,1)
                put(o,STATUS,11)
            else:
                put(w,184,get(w,184)-1)
                put(o,ACTIVE,0)
        return unlock(o,901)
    return finish(o,w,get(o,STATUS))

def free_new(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,DETAIL,detail)
    if get(o,NEW)!=1 or get(o,REGISTERED)!=0:
        return unknown(o,w,detail)
    put(o,0,get(o,REAPER_P))
    put(o,PH,490)
    return 7

def receipt(o:mutbuf,w:mutbuf,status:u64,consumed:u64,pending:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,CONSUMED,consumed)
    put(o,PENDING,pending)
    put(o,DETAIL,detail)
    request(o,THREAD,1)
    put(o,RQ+16,status)
    put(o,RQ+24,get(o,KNOWN))
    put(o,RQ+32,consumed)
    put(o,RQ+40,pending)
    put(o,RQ+48,get(o,UNKNOWN))
    return thread(o,610)

def thread(o:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(o,FACT_THREAD),51,RQ,128,RP,8192,get(o,REAPER_P),512)

def registry(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,144),51,RQ,n,RP,2048,get(w,152),256)

def reg_valid(o:mutbuf) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==REG_REPLY and get(o,RP+80)==1,1,0)

def thread_valid(o:mutbuf) -> u64:
    return choose(get(o,FB)==0 and get(o,RP)==THREAD_REPLY,1,0)

def unknown(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,UNKNOWN,1)
    put(o,PENDING,1)
    return fail(o,w,11,detail)

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    if get(o,HELD)!=0:
        return again(o,900)
    if get(o,ACTIVE)!=0:
        return lock(o,900)
    return finish(o,w,status)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,8,status)
    if get(o,OP)==0:
        put(o,0,RFR)
        put(o,16,get(o,KNOWN))
        put(o,24,get(o,CONSUMED))
        put(o,32,get(o,PENDING))
    else:
        put(o,0,REPLY)
        put(o,16,get(o,KNOWN))
        put(o,24,get(o,PENDING))
        put(o,32,get(o,UNKNOWN))
        put(o,40,get(o,DETAIL))
        put(o,48,get(o,CFG+488))
    return 0

def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0

def copy_s(s:readbuf,source:u64,o:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0

def same(o:mutbuf,a:u64,b:u64) -> u64:
    return choose(get(o,a)==get(o,b) and get(o,a+8)==get(o,b+8) and get(o,a+16)==get(o,b+16),1,0)

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
'''
NEEDED=('invoke','memory','system','again','read_zero','get','put','zero','between','within','choose')
HELPERS='\n\n'.join(ast.get_source_segment(context.SOURCE,n)for n in ast.parse(context.SOURCE).body if isinstance(n,ast.FunctionDef)and n.name in NEEDED)
def source_program():return M.render(SOURCE+'\n'+HELPERS,C,'background_native_reaper_manager')
def main():
    d=document(source_program(),'background_optimizer_native_reaper_manager')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_native_reaper_manager.hepta'
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
