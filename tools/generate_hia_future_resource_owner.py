"""Native compound owner for a Future factory lease and Future cell.

The private resource cap is an independently registered native capability.
Future and Value entries are fixed ELF imports; their contexts are captured by
the trusted enclosing initializer.  The original raw Future protocol is kept.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_provider as helpers
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),'little')for k,v in dict(
 REQUEST='HIAFRQ01',REPLY='HIAFRR01',CONTROL='HIAFRCQ1',STATE='HIAFRCX1',
 RECORD='HIAFROX1',REG_REQUEST='HIAFRG01',REG_REPLY='HIAFRGR1',
 FUT_REQUEST='HIABFP01',FUT_TYPED='HIABFP03',FUT_REPLY='HIABFRP1',FUT_ACK='HIABFRP2',
 FUT_STATE='HIABFPS1',V_REQUEST='HIABVQ01',V_TYPED='HIABVQ02',
 V_REPLY='HIABVR01',V_ACK='HIABVR02',FINAL_REQUEST='HIAVRFQ1',FINAL_REPLY='HIAVRFR1').items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,
 PH=128,FB=136,OP=144,FAMILY=152,STATUS=160,KIND=168,PID=176,SELF=184,
 HELD=192,LOCK_NEXT=200,ACTIVE=208,KNOWN=216,CONSUMED=224,PENDING=232,
 PTR=240,SOLE=248,RESUMING=256,NEW_RECORD=264,ERROR=272,QUAR=280,
 CAP=288,RESULT=312,SAVED_NEXT=336,RANDOM=360,FREE_PTR=368,
 FACT_SELF=384,FACT_ENTRY=392,FACT_FUTURE=400,FACT_VALUES=408,FACT_REG=416,
 V_PENDING=424,FINISH_NEXT=432,DROP_MODE=440,EXTRA=448,RANDOM_USED=456,
 ROW=512,RQ=1024,TEMP=1536,RP=2048,FP=4096,VP=69632,OUT=102400)
SOURCE=r'''
def future_resource_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return start(s,o,w,phase)
    if phase<200:
        return locks(s,o,w,phase)
    if phase<300:
        return admission(s,o,w,phase)
    if phase<400:
        return capture(s,o,w,phase)
    if phase<500:
        return lookup(s,o,w,phase)
    if phase<700:
        return retirement(s,o,w,phase)
    if phase<800:
        return controls(s,o,w,phase)
    return complete(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128:
        return 4294967293
    family=0
    op=word(s,8)
    if word(s,0)==CONTROL:
        family=1
        if op>4:
            return 4294967293
        if read_zero(s,16,112)==False:
            return 4294967293
    elif word(s,0)==FINAL_REQUEST:
        family=2
        if op>1 or word(s,24)!=7 or read_zero(s,56,72)==False:
            return 4294967293
    elif word(s,0)==REQUEST:
        if op>3:
            return 4294967293
        if op==0:
            if read_zero(s,88,40)==False:
                return 4294967293
        elif read_zero(s,40,88)==False:
            return 4294967293
    else:
        return 4294967293
    zero(o,128,3968)
    put(o,OP,op)
    put(o,FAMILY,family)
    if family==2:
        readcopy(s,32,o,CAP,24)
    elif family==0 and op!=0:
        readcopy(s,16,o,CAP,24)
    return system(o,1,39,0,0,0,0,0,0,0)

def start(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FB)
        if pid==0 or pid>=NEGATIVE:
            return rejected(o)
        put(o,PID,pid)
        put(o,PH,2)
        return 15
    if phase==2:
        own=get(o,FACT_SELF)
        if own==0 or own>MAX-512 or get(w,0)!=STATE or get(w,8)!=get(o,PID):
            return rejected(o)
        if get(w,16)!=own or get(w,24)!=get(o,FACT_ENTRY):
            return rejected(o)
        if get(w,32)!=get(o,FACT_FUTURE) or get(w,40)==0 or get(w,48)!=256:
            return rejected(o)
        if get(w,56)!=get(o,FACT_VALUES) or get(w,64)==0 or get(w,72)!=256:
            return rejected(o)
        if get(w,136)!=get(o,FACT_REG) or get(w,144)!=own+256 or get(w,152)!=256:
            return rejected(o)
        if get(w,160)==0 or get(w,96)>4:
            return rejected(o)
        if get(w,40)>MAX-256 or get(w,64)>MAX-256:
            return rejected(o)
        if get(w,168)>1:
            return rejected(o)
        at=176
        while at<256:
            if get(w,at)!=0:
                return rejected(o)
            at=at+8
        if get(o,FAMILY)==2 and (get(w,80)==0 or word(s,16)!=get(w,80)):
            return rejected(o)
        put(o,SELF,own)
        return memory(o,3,0,get(w,64)+152,3,TEMP,8)
    if phase==3:
        if get(o,TEMP)!=get(w,160):
            return rejected(o)
        return memory(o,4,0,get(w,40),3,TEMP,256)
    if phase==4:
        if get(o,TEMP)!=FUT_STATE or get(o,TEMP+8)!=get(o,PID) or get(o,TEMP+24)!=0:
            return rejected(o)
        if get(o,TEMP+72)!=get(w,56) or get(o,TEMP+112)!=get(w,64) or get(o,TEMP+120)!=256:
            return rejected(o)
        if get(o,TEMP+208)!=get(w,40):
            return rejected(o)
        return lock(o,200)
    return rejected(o)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FB)==0:
            put(o,HELD,1)
            return again(o,get(o,LOCK_NEXT))
        return system(o,101,202,1,88,128,1,0,0,0)
    if phase==101:
        value=get(o,FB)
        if value!=0 and value!=MAX-3 and value!=MAX-10:
            return system(o,104,24,0,0,0,0,0,0,0)
        return atom(o,100,2,0,1)
    if phase==104:
        return atom(o,100,2,0,1)
    if phase==102:
        return system(o,103,202,1,88,129,2147483647,0,0,0)
    if phase==103:
        return again(o,get(o,LOCK_NEXT))
    return rejected(o)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        put(o,KNOWN,1)
        if get(o,FAMILY)==1:
            return again(o,700)
        if get(w,96)!=1 or get(w,80)==0:
            return failure(o,6,0)
        if get(o,FAMILY)==2 and get(o,OP)==1:
            return failure(o,1,0)
        if get(o,FAMILY)==0 and get(o,OP)==0:
            if get(w,104)==MAX:
                return failure(o,6,1)
            put(w,104,get(w,104)+1)
            put(o,ACTIVE,1)
            return unlock(o,300)
        registry_packet(o,7)
        copy(o,RQ+24,CAP,24)
        return registry(o,w,400,128)
    return rejected(o)

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return allocate(o,301,512)
    if phase==301:
        if get(o,FB)==0:
            return failure(o,5,0)
        put(o,PTR,get(o,FB))
        put(o,NEW_RECORD,1)
        zero(o,ROW,512)
        put(o,ROW,RECORD)
        put(o,ROW+8,get(o,PID))
        put(o,ROW+16,get(o,PTR))
        put(o,ROW+24,get(o,SELF))
        put(o,ROW+32,get(w,80))
        readcopy(s,16,o,ROW+64,24)
        return memory(o,302,3,ROW,0,get(o,PTR),512)
    if phase==302:
        registry_packet(o,1)
        put(o,RQ+72,24)
        put(o,RQ+128,get(o,PTR))
        put(o,RQ+136,get(w,80))
        put(o,RQ+144,512)
        return registry(o,w,303,152)
    if phase==303:
        if registry_valid(o)==False:
            put(o,QUAR,1)
            return failure(o,11,0)
        if get(o,RP+8)!=0:
            put(o,FREE_PTR,get(o,PTR))
            put(o,PTR,0)
            return deallocate(o,304,get(o,FREE_PTR))
        copy(o,CAP,RP+16,24)
        copy(o,ROW+208,CAP,24)
        return memory(o,305,3,ROW,0,get(o,PTR),512)
    if phase==304:
        return failure(o,5,0)
    if phase==305:
        value_packet(o,V_REQUEST,21)
        return values(o,w,306)
    if phase==306:
        if value_valid(o)==False:
            put(o,QUAR,1)
            return capture_failed(o,11)
        if get(o,VP+8)!=0:
            return capture_failed(o,5)
        copy(o,ROW+136,VP+24,24)
        future_packet(o,5,False)
        readcopy(s,16,o,RQ+16,24)
        readcopy(s,40,o,RQ+40,24)
        return futures(o,w,307)
    if phase==307:
        if future_valid(o)==False:
            put(o,QUAR,1)
            return capture_failed(o,11)
        harvest_error(o)
        if get(o,FP+16)==2:
            copy(o,ROW+88,FP+48,24)
        if get(o,FP+8)!=0 or get(o,FP+16)!=2 or same(o,FP+24,ROW+64,24)==False:
            return capture_failed(o,3)
        future_packet(o,2,False)
        readcopy(s,16,o,RQ+16,24)
        readcopy(s,64,o,RQ+40,24)
        return futures(o,w,308)
    if phase==308:
        if future_valid(o)==False:
            put(o,QUAR,1)
            return capture_failed(o,11)
        harvest_error(o)
        if get(o,FP+16)==3:
            copy(o,ROW+112,FP+48,24)
        if get(o,FP+8)!=0 or get(o,FP+16)!=3 or same(o,FP+24,ROW+64,24)==False:
            return capture_failed(o,3)
        put(o,ROW+40,1)
        return memory(o,309,3,ROW,0,get(o,PTR),512)
    if phase==309:
        copy(o,RESULT,CAP,24)
        put(o,KIND,1)
        put(o,NEW_RECORD,0)
        return failure(o,0,0)
    if phase==310:
        put(o,DROP_MODE,1)
        return again(o,500)
    return rejected(o)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if registry_valid(o)==False:
            put(o,QUAR,1)
            return failure(o,11,0)
        if get(o,RP+8)!=0:
            return failure(o,1,0)
        if get(o,RP+40)!=24 or get(o,RP+64)==0 or get(o,RP+72)>1:
            put(o,QUAR,1)
            return failure(o,11,0)
        put(o,SOLE,get(o,RP+72))
        return memory(o,401,0,get(o,RP+64),3,TEMP,24)
    if phase==401:
        ptr=get(o,TEMP)
        if ptr==0 or ptr>MAX-512 or get(o,TEMP+8)!=get(w,80) or get(o,TEMP+16)!=512:
            put(o,QUAR,1)
            return failure(o,11,0)
        put(o,PTR,ptr)
        return memory(o,402,0,ptr,3,ROW,512)
    if phase==402:
        if get(o,ROW)!=RECORD or get(o,ROW+8)!=get(o,PID) or get(o,ROW+16)!=get(o,PTR):
            put(o,QUAR,1)
            return failure(o,11,0)
        if get(o,ROW+24)!=get(o,SELF) or get(o,ROW+32)!=get(w,80):
            put(o,QUAR,1)
            return failure(o,11,0)
        state=get(o,ROW+40)
        if state==3 or state==4:
            return failure(o,11,0)
        if get(o,RESUMING)!=0:
            if state!=2:
                return failure(o,6,1)
            copy(o,SAVED_NEXT,ROW+184,24)
            put(o,DROP_MODE,1)
            return claim(o,w)
        if state!=1:
            if state==2 and dropping(o):
                return claim(o,w)
            return failure(o,6,1)
        if get(o,FAMILY)==0 and get(o,OP)==3:
            put(o,KIND,2)
            return failure(o,0,0)
        if get(o,FAMILY)==0 and get(o,OP)==1:
            registry_packet(o,2)
            copy(o,RQ+24,CAP,24)
            return registry(o,w,410,128)
        if get(o,SOLE)==0:
            registry_packet(o,3)
            copy(o,RQ+24,CAP,24)
            return registry(o,w,411,128)
        return claim(o,w)
    if phase==403:
        return unlock(o,500)
    if phase==410:
        if registry_valid(o)==False:
            put(o,QUAR,1)
            return failure(o,11,0)
        if get(o,RP+8)!=0:
            return failure(o,5,0)
        copy(o,RESULT,RP+16,24)
        put(o,KIND,1)
        return failure(o,0,0)
    if phase==411:
        if registry_valid(o)==False or get(o,RP+88)>1:
            put(o,QUAR,1)
            return failure(o,11,0)
        put(o,CONSUMED,get(o,RP+88))
        if get(o,RP+8)!=0 or get(o,RP+88)!=1:
            return failure(o,11,0)
        return failure(o,0,0)
    return rejected(o)

def retirement(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,QUAR)!=0:
            return park(o,11)
        if get(o,ROW+160)!=0:
            value_packet(o,V_TYPED,29)
            copy(o,RQ+24,ROW+160,24)
            return values(o,w,501)
        return again(o,510)
    if phase==501:
        if value_drop(o,True)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,VP+96)!=0:
            zero(o,ROW+160,24)
        if get(o,VP+80)!=0:
            put(o,ROW+56,1)
        if get(o,VP+8)!=0:
            return park(o,11)
        return again(o,510)
    if phase==510:
        if get(o,ROW+88)!=0:
            future_packet(o,26,True)
            copy(o,RQ+16,ROW+64,24)
            copy(o,RQ+40,ROW+88,24)
            return futures(o,w,511)
        return again(o,520)
    if phase==511:
        if future_drop(o,True)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,FP+96)!=0:
            zero(o,ROW+88,24)
        if get(o,FP+112)!=0:
            put(o,ROW+48,1)
        if get(o,FP+96)==0:
            return park(o,11)
        return again(o,520)
    if phase==520:
        if get(o,ROW+112)!=0:
            future_packet(o,27,True)
            copy(o,RQ+16,ROW+64,24)
            copy(o,RQ+40,ROW+112,24)
            return futures(o,w,521)
        return again(o,530)
    if phase==521:
        if future_drop(o,True)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,FP+96)!=0:
            zero(o,ROW+112,24)
        if get(o,FP+112)!=0:
            put(o,ROW+48,1)
        if get(o,FP+96)==0:
            return park(o,11)
        return again(o,530)
    if phase==530:
        if get(o,ROW+48)!=0:
            future_packet(o,28,True)
            copy(o,RQ+16,ROW+64,24)
            return futures(o,w,531)
        return again(o,540)
    if phase==531:
        if future_drop(o,False)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,FP+8)!=0 or get(o,FP+112)!=0:
            return park(o,11)
        put(o,ROW+48,0)
        return again(o,540)
    if phase==540:
        if get(o,ROW+136)!=0:
            value_packet(o,V_TYPED,30)
            copy(o,RQ+24,ROW+136,24)
            return values(o,w,541)
        return again(o,550)
    if phase==541:
        if value_drop(o,True)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,VP+96)!=0:
            zero(o,ROW+136,24)
        if get(o,VP+80)!=0:
            put(o,ROW+56,1)
        if get(o,VP+96)==0:
            return park(o,11)
        return again(o,550)
    if phase==550:
        if get(o,ROW+56)!=0:
            value_packet(o,V_TYPED,31)
            return values(o,w,551)
        return lock(o,560)
    if phase==551:
        if value_drop(o,False)==False:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,VP+8)!=0 or get(o,VP+80)!=0:
            return park(o,11)
        put(o,ROW+56,0)
        return lock(o,560)
    if phase==560:
        registry_packet(o,3)
        copy(o,RQ+24,CAP,24)
        return registry(o,w,561,128)
    if phase==561:
        if registry_valid(o)==False or get(o,RP+88)>1:
            put(o,QUAR,1)
            return park(o,11)
        if get(o,RP+88)!=1:
            return park(o,11)
        if get(o,RESUMING)!=0:
            between(o,SAVED_NEXT,w,112,24)
        if get(o,DROP_MODE)==0:
            put(o,CONSUMED,1)
        put(o,NEW_RECORD,0)
        put(o,FREE_PTR,get(o,PTR))
        put(o,PTR,0)
        return unlock(o,562)
    if phase==562:
        return deallocate(o,563,get(o,FREE_PTR))
    if phase==563:
        if get(o,RESUMING)!=0:
            return lock(o,720)
        return failure(o,get(o,ERROR),0)
    if phase==590:
        if get(o,NEW_RECORD)!=0 and get(o,RESUMING)==0:
            if get(o,HELD)!=0:
                return again(o,591)
            return lock(o,591)
        return failure(o,11,1)
    if phase==591:
        between(w,112,o,ROW+184,24)
        between(o,CAP,w,112,24)
        put(o,NEW_RECORD,0)
        return memory(o,592,3,ROW,0,get(o,PTR),512)
    if phase==592:
        return failure(o,11,1)
    return rejected(o)

def controls(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        op=get(o,OP)
        state=get(w,96)
        if state==4:
            return failure(o,11,0)
        if op==0:
            if state!=0 or get(w,104)!=0 or get(w,112)!=0:
                return failure(o,6,0)
            if get(w,168)!=0:
                return random_nonce(o)
            registry_packet(o,0)
            return registry(o,w,701,128)
        if op==4:
            if state!=1 or get(w,104)!=0:
                return failure(o,6,1)
            return again(o,720)
        if op==1:
            if state>1 or get(w,104)!=0 or get(w,112)!=0 or get(w,272)!=0:
                return failure(o,6,1)
            put(w,96,2)
            return failure(o,0,0)
        if op==2:
            if state!=2:
                return failure(o,6,0)
            put(w,96,1)
            return failure(o,0,0)
        if op==3:
            if state==3:
                return failure(o,0,0)
            if state!=2 or get(w,104)!=0 or get(w,112)!=0:
                return failure(o,6,1)
            if get(w,168)==0:
                put(w,96,3)
                return failure(o,0,0)
            registry_packet(o,5)
            return registry(o,w,704,128)
        return failure(o,1,0)
    if phase==701:
        if registry_valid(o)==False or get(o,RP+8)!=0:
            put(o,QUAR,1)
            return failure(o,11,0)
        put(w,168,1)
        return random_nonce(o)
    if phase==702:
        if get(o,FB)==MAX-3:
            return random_nonce(o)
        received=get(o,FB)
        used=get(o,RANDOM_USED)
        if received==0 or received>=NEGATIVE or received>8-used:
            return failure(o,11,1)
        used=used+received
        put(o,RANDOM_USED,used)
        if used<8:
            return random_nonce(o)
        if get(o,RANDOM)==0:
            put(o,RANDOM_USED,0)
            return random_nonce(o)
        put(w,80,get(o,RANDOM))
        put(w,96,1)
        return failure(o,0,0)
    if phase==704:
        if registry_valid(o)==False or get(o,RP+8)!=0:
            return failure(o,11,1)
        put(w,96,3)
        return failure(o,0,0)
    if phase==720:
        if get(o,ACTIVE)!=0:
            if get(w,104)==0:
                put(o,QUAR,1)
                return failure(o,11,0)
            put(w,104,get(w,104)-1)
            put(o,ACTIVE,0)
        zero(o,ROW,512)
        zero(o,CAP,24)
        put(o,PTR,0)
        put(o,CONSUMED,0)
        put(o,ERROR,0)
        if get(w,112)==0:
            return failure(o,0,0)
        between(w,112,o,CAP,24)
        put(o,RESUMING,1)
        registry_packet(o,7)
        copy(o,RQ+24,CAP,24)
        return registry(o,w,400,128)
    return rejected(o)

def complete(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==800:
        if get(o,HELD)!=0:
            return again(o,801)
        return lock(o,801)
    if phase==801:
        if get(o,QUAR)!=0:
            put(w,96,4)
            put(o,KNOWN,0)
        if get(o,ACTIVE)!=0:
            if get(w,104)==0:
                put(w,96,4)
                put(o,KNOWN,0)
                put(o,STATUS,11)
            else:
                put(w,104,get(w,104)-1)
            put(o,ACTIVE,0)
        return unlock(o,802)
    if phase==802:
        return finish(o)
    return rejected(o)

def claim(o:mutbuf,w:mutbuf) -> u32:
    if get(w,104)==MAX:
        return failure(o,6,1)
    put(w,104,get(w,104)+1)
    put(o,ACTIVE,1)
    put(o,ROW+40,5)
    return memory(o,403,3,ROW,0,get(o,PTR),512)

def capture_failed(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,310)

def park(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    put(o,ROW+40,choose(get(o,QUAR)!=0,3,2))
    return memory(o,590,3,ROW,0,get(o,PTR),512)

def failure(o:mutbuf,status:u64,pending:u64) -> u32:
    put(o,STATUS,status)
    put(o,PENDING,pending)
    return again(o,800)

def rejected(o:mutbuf) -> u32:
    put(o,STATUS,11)
    put(o,KNOWN,0)
    return finish(o)

def finish(o:mutbuf) -> u32:
    zero(o,0,128)
    if get(o,FAMILY)==2:
        put(o,0,FINAL_REPLY)
        put(o,8,get(o,STATUS))
        put(o,16,get(o,KNOWN))
        put(o,24,get(o,CONSUMED))
        put(o,32,get(o,PENDING))
        return 0
    put(o,0,REPLY)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,KIND))
    copy(o,24,RESULT,24)
    if get(o,KIND)==2:
        copy(o,48,ROW+64,24)
        copy(o,72,ROW+88,24)
    put(o,96,get(o,KNOWN))
    put(o,104,get(o,CONSUMED))
    put(o,112,get(o,PENDING))
    return 0

def dropping(o:mutbuf) -> bool:
    if get(o,FAMILY)==2:
        return True
    return get(o,OP)==2

def random_nonce(o:mutbuf) -> u32:
    used=get(o,RANDOM_USED)
    return system(o,702,318,3,RANDOM+used,8-used,0,0,0,0)

def registry_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,REG_REQUEST)
    put(o,RQ+8,op)
    return 0

def registry(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    zero(o,RP,512)
    return role(o,next,14,3,RQ,n,3,RP,512,1,256,256)

def registry_valid(o:mutbuf) -> bool:
    if get(o,FB)!=0 or get(o,RP)!=REG_REPLY:
        return False
    if get(o,RP+80)>1 or get(o,RP+88)>1:
        return False
    return True

def future_packet(o:mutbuf,op:u64,typed:bool) -> u64:
    zero(o,RQ,192)
    put(o,RQ,choose(typed,FUT_TYPED,FUT_REQUEST))
    put(o,RQ+8,op)
    return 0

def futures(o:mutbuf,w:mutbuf,next:u64) -> u32:
    zero(o,FP,65536)
    return role(o,next,12,3,RQ,192,3,FP,65536,0,get(w,40),256)

def future_valid(o:mutbuf) -> bool:
    return get(o,FB)==0 and get(o,FP)==FUT_REPLY

def future_drop(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,FB)!=0 or get(o,FP)!=FUT_ACK:
        return False
    if get(o,FP+104)!=1 or get(o,FP+96)>1 or get(o,FP+112)>1:
        return False
    if allow_consumed==False and get(o,FP+96)!=0:
        return False
    return True

def harvest_error(o:mutbuf) -> u64:
    if get(o,FP+16)==200:
        copy(o,ROW+160,FP+72,24)
    return 0

def value_packet(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0

def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    zero(o,VP,32768)
    return role(o,next,13,3,RQ,128,3,VP,32768,0,get(w,64),256)

def value_valid(o:mutbuf) -> bool:
    return get(o,FB)==0 and get(o,VP)==V_REPLY

def value_drop(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,FB)!=0 or get(o,VP)!=V_ACK:
        return False
    status=get(o,VP+8)
    if get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+80)>1:
        return False
    if allow_consumed==False and get(o,VP+96)!=0:
        return False
    if get(o,VP+96)!=0 and status!=0 and status!=11:
        return False
    if status==0 and get(o,VP+80)!=0:
        return False
    return status==0 or status==1 or status==6 or status==11

def lock(o:mutbuf,next:u64) -> u32:
    put(o,LOCK_NEXT,next)
    return atom(o,100,2,0,1)

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,LOCK_NEXT,next)
    put(o,HELD,0)
    return atom(o,102,3,0,0)

def atom(o:mutbuf,next:u64,action:u64,expected:u64,value:u64) -> u32:
    put(o,PH,next)
    put(o,0,88)
    put(o,8,expected)
    put(o,16,value)
    return action

def copy(o:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(o,source+i))
        i=i+1
    return 0

def between(a:mutbuf,at:u64,b:mutbuf,bt:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,bt+i,byte(a,at+i))
        i=i+1
    return 0

def readcopy(a:readbuf,at:u64,b:mutbuf,bt:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,bt+i,byte(a,at+i))
        i=i+1
    return 0

def same(o:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(o,a+i)!=byte(o,b+i):
            return False
        i=i+1
    return True

def read_zero(s:readbuf,at:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return False
        i=i+1
    return True
'''
def source_program():
    text=SOURCE
    needed={'again','allocate','deallocate','memory','system','role','zero','word','get','put'}
    for node in ast.parse(helpers.source_program()).body:
        if isinstance(node,ast.FunctionDef)and node.name in needed:
            text+=chr(10)+ast.unparse(node)+chr(10)
    text+='\ndef choose(flag:bool,a:u64,b:u64) -> u64:\n    if flag:\n        return a\n    return b\n'
    for key,value in sorted(C.items(),key=lambda p:-len(p[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    doc=document(source_program(),'future_resource_owner')
    p=ROOT/'examples/hia_bootstrap/future_resource_owner.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
