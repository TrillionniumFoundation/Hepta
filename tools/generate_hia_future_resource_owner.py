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
 DEFER=464,VALUE_QUEUE=472,VALUE_UNMAP=480,VALUE_BAD=488,
 ROW=512,RQ=1024,TEMP=1536,RP=2048,FP=4096,VP=69632,OUT=102400)
C.update(STATE2=int.from_bytes(b'HIAFRCX2','little'),FUT_PRIVATE=int.from_bytes(b'HIABFP04','little'),FUT_ACK3=int.from_bytes(b'HIABFRP3','little'),V_PRIVATE=int.from_bytes(b'HIABVQ05','little'),V_QUERY=int.from_bytes(b'HIABVQ06','little'))
C.update(REQUEST3=int.from_bytes(b'HIAFRQ03','little'),REPLY3=int.from_bytes(b'HIAFRR03','little'))
C.update(REQUEST4=int.from_bytes(b'HIAFRQ04','little'),REPLY4=int.from_bytes(b'HIAFRR04','little'),
 FIXED_CALLBACK=1808,CALLER_OUTPUT=1816,REPLY_BYTES=1824,R_STATUS=1832,R_CLASS=1840,R_KNOWN=1848,
 R_ATTEMPT=1856,R_ERROR=1864,R_FINAL=3072)
C.update(REQUEST2=int.from_bytes(b'HIAFRQ02','little'),REPLY2=int.from_bytes(b'HIAFRR02','little'),
 C_NEED_DRAIN=1568,C_RETRY=1576,C_CAPTURE_TAKEN=1584)
SOURCE=r'''
def future_resource_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        return begin(s,o,w)
    if phase>=990:
        return registration(s,o,w,phase)
    if phase>=900:
        return canonical(s,o,w,phase)
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
    elif word(s,0)==REQUEST4:
        family=5
        if op!=0 or read_zero(s,64,64)==False:
            return 4294967293
    elif word(s,0)==REQUEST3:
        family=4
        if op!=0 or read_zero(s,40,88)==False:
            return 4294967293
    elif word(s,0)==REQUEST2:
        family=3
        if op!=0 or read_zero(s,40,24)==False or read_zero(s,88,40)==False:
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
    put(o,REPLY_BYTES,128)
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
        if own==0 or own>MAX-512 or (get(w,0)!=STATE and get(w,0)!=STATE2) or get(w,8)!=get(o,PID):
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
        if get(w,0)==STATE2:
            if get(w,176)>1:
                return rejected(o)
            at=184
        if (get(o,FAMILY)==3 or get(o,FAMILY)==4 or get(o,FAMILY)==5) and get(w,0)!=STATE2:
            return rejected(o)
        if get(o,FAMILY)==5:
            if get(o,FIXED_CALLBACK)==0:
                return rejected(o)
            if get(o,CALLER_OUTPUT)<320:
                return 4294967294
            put(o,REPLY_BYTES,320)
        while at<256:
            if get(w,at)!=0:
                return rejected(o)
            at=at+8
        if get(o,FAMILY)==2 and (get(w,80)==0 or word(s,16)!=get(w,80)):
            return rejected(o)
        put(o,SELF,own)
        put(o,DEFER,choose(get(w,0)==STATE2,1,0))
        return memory(o,3,0,get(w,64),3,TEMP,256)
    if phase==3:
        if get(o,TEMP+152)!=get(w,160):
            return rejected(o)
        if get(o,DEFER)!=0 and get(o,FAMILY)!=1:
            if get(o,TEMP+224)!=get(o,FACT_ENTRY) or get(o,TEMP+232)!=get(o,SELF) or get(o,TEMP+240)!=512 or get(o,TEMP+248)!=get(w,80):
                return rejected(o)
        return memory(o,4,0,get(w,40),3,TEMP,256)
    if phase==4:
        if get(o,TEMP)!=FUT_STATE or get(o,TEMP+8)!=get(o,PID) or get(o,TEMP+24)!=0:
            return rejected(o)
        if get(o,TEMP+72)!=get(w,56) or get(o,TEMP+112)!=get(w,64) or get(o,TEMP+120)!=256:
            return rejected(o)
        if get(o,TEMP+208)!=get(w,40):
            return rejected(o)
        put(o,C_NEED_DRAIN,0)
        put(o,C_RETRY,0)
        put(o,C_CAPTURE_TAKEN,0)
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
        if get(o,FAMILY)==4 or get(o,FAMILY)==5:
            if get(w,176)!=0 or get(w,104)==MAX:
                return failure(o,6,1)
            put(w,104,get(w,104)+1)
            put(o,ACTIVE,1)
            value_packet(o,V_QUERY,49)
            readcopy(s,16,o,RQ+24,24)
            return values(o,w,980)
        if (get(o,FAMILY)==0 or get(o,FAMILY)==3) and get(o,OP)==0:
            if get(o,DEFER)!=0 and get(w,176)!=0:
                return failure(o,6,1)
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
        if value_local_status(o)!=0:
            return capture_failed(o,5)
        copy(o,ROW+136,VP+24,24)
        future_packet(o,choose(get(o,FAMILY)==3,4,5),False)
        readcopy(s,16,o,RQ+16,24)
        if get(o,FAMILY)==3:
            readcopy(s,64,o,RQ+40,24)
        else:
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
        if get(o,FAMILY)==3:
            return again(o,900)
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
            if state==6 and get(o,DEFER)!=0 and get(o,ROW+280)==1:
                if get(w,104)==MAX:
                    return failure(o,6,1)
                copy(o,SAVED_NEXT,ROW+184,24)
                put(w,104,get(w,104)+1)
                put(o,ACTIVE,1)
                return unlock(o,931)
            if state!=2:
                return failure(o,6,1)
            copy(o,SAVED_NEXT,ROW+184,24)
            put(o,DROP_MODE,1)
            return claim(o,w)
        if state!=1:
            if state==2 and dropping(o):
                return claim(o,w)
            return failure(o,6,1)
        if get(o,FAMILY)==4 or get(o,FAMILY)==5:
            if get(o,ROW+232)==0:
                return failure(o,3,0)
            value_packet(o,V_PRIVATE,80)
            readcopy(s,16,o,RQ+24,24)
            return values(o,w,981)
        if get(o,ROW+232)!=0 and get(o,FAMILY)==0:
            # Canonical records never export an independently usable raw
            # provider alias; their only owner is the actual Value resource.
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
        if value_local_pending(o)!=0:
            put(o,ROW+56,1)
        if value_local_status(o)!=0:
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
        if value_local_pending(o)!=0:
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
        if value_local_status(o)!=0 or value_local_pending(o)!=0:
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
            if get(o,DEFER)!=0:
                if get(w,176)!=0:
                    return failure(o,6,1)
                put(w,176,1)
                put(o,C_RETRY,1)
            return again(o,720)
        if op==1:
            if get(o,DEFER)!=0 and get(w,176)!=0:
                return failure(o,6,1)
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
        if get(o,C_RETRY)!=0:
            put(w,176,0)
            put(o,C_RETRY,0)
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
        if get(o,C_NEED_DRAIN)!=0:
            put(o,C_NEED_DRAIN,0)
            value_packet(o,V_PRIVATE,56)
            return values(o,w,803)
        return finish(o)
    if phase==803:
        if value_valid(o)==False or get(o,VP+8)!=0:
            put(o,STATUS,11)
            put(o,PENDING,1)
            return finish(o)
        value_packet(o,V_TYPED,31)
        return values(o,w,804)
    if phase==804:
        if value_drop(o,False)==False or get(o,VP+104)!=0 or get(o,VP+112)!=0:
            put(o,STATUS,11)
            put(o,PENDING,1)
        else:
            put(o,PENDING,choose(get(w,112)!=0,1,0))
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
    if get(o,FAMILY)==5:
        return finish_registration(o)
    zero(o,0,128)
    if get(o,FAMILY)==2:
        put(o,0,FINAL_REPLY)
        put(o,8,get(o,STATUS))
        put(o,16,get(o,KNOWN))
        put(o,24,get(o,CONSUMED))
        put(o,32,get(o,PENDING))
        return 0
    put(o,0,choose(get(o,FAMILY)==4,REPLY3,choose(get(o,FAMILY)==3,REPLY2,REPLY)))
    put(o,8,get(o,STATUS))
    put(o,16,get(o,KIND))
    copy(o,24,RESULT,24)
    if get(o,KIND)==2 or (get(o,FAMILY)==4 and get(o,KIND)==7):
        copy(o,48,ROW+64,24)
        copy(o,72,ROW+88,24)
    put(o,96,get(o,KNOWN))
    put(o,104,get(o,CONSUMED))
    put(o,112,get(o,PENDING))
    return 0


def canonical(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        value_packet(o,V_PRIVATE,48)
        put(o,RQ+96,24)
        put(o,RQ+104,7)
        copy(o,RQ+128,CAP,24)
        return values(o,w,901)
    if phase==901:
        if canonical_capture_record(o)==False:
            put(o,QUAR,1)
            return capture_failed(o,11)
        if get(o,C_CAPTURE_TAKEN)==0:
            return capture_failed(o,choose(get(o,VP+8)==5,5,3))
        put(o,NEW_RECORD,0)
        return memory(o,902,3,ROW,0,get(o,PTR),512)
    if phase==902:
        value_packet(o,V_PRIVATE,80)
        copy(o,RQ+24,ROW+256,24)
        return values(o,w,903)
    if phase==903:
        if value_valid(o)==False or get(o,VP+8)!=0 or get(o,VP+16)!=8 or get(o,VP+48)!=7:
            return canonical_failed(o,11)
        copy(o,ROW+232,VP+24,24)
        return memory(o,904,3,ROW,0,get(o,PTR),512)
    if phase==904:
        future_packet(o,30,False)
        copy(o,RQ+16,ROW+64,24)
        copy(o,RQ+40,ROW+88,24)
        copy(o,RQ+64,ROW+256,24)
        put(o,RQ+88,get(w,80))
        copy(o,RQ+104,CAP,24)
        return futures(o,w,905)
    if phase==905:
        if future_valid(o)==False:
            return canonical_failed(o,11)
        harvest_error(o)
        if get(o,FP+8)!=0 or get(o,FP+16)!=7:
            return canonical_failed(o,3)
        copy(o,RESULT,ROW+256,24)
        zero(o,ROW+256,24)
        put(o,KIND,7)
        put(o,CONSUMED,1)
        return memory(o,906,3,ROW,0,get(o,PTR),512)
    if phase==906:
        put(o,C_NEED_DRAIN,1)
        return failure(o,0,0)
    if phase==930:
        return again(o,931)
    if phase==931:
        if get(o,ROW+160)!=0:
            if get(o,ROW+296)!=0:
                value_packet(o,V_QUERY,7)
                copy(o,RQ+24,ROW+160,24)
                return values(o,w,960)
            value_packet(o,V_TYPED,29)
            copy(o,RQ+24,ROW+160,24)
            return values(o,w,932)
        return again(o,940)
    if phase==932:
        if value_drop(o,True)==False:
            put(o,ROW+296,1)
            return canonical_park(o)
        if get(o,VP+96)!=1:
            return canonical_park(o)
        zero(o,ROW+160,24)
        if value_local_pending(o)!=0:
            put(o,ROW+56,1)
        return memory(o,933,3,ROW,0,get(o,PTR),512)
    if phase==933:
        return again(o,940)
    if phase==940:
        if get(o,ROW+256)==0:
            return again(o,945)
        if get(o,ROW+288)!=0:
            value_packet(o,V_QUERY,7)
            copy(o,RQ+24,ROW+256,24)
            return values(o,w,970)
        value_packet(o,V_TYPED,29)
        copy(o,RQ+24,ROW+256,24)
        return values(o,w,941)
    if phase==941:
        if value_drop(o,True)==False:
            put(o,ROW+288,1)
            return canonical_park(o)
        if get(o,VP+96)!=1:
            return canonical_park(o)
        zero(o,ROW+256,24)
        if value_local_pending(o)!=0:
            put(o,ROW+56,1)
        return again(o,945)
    if phase==945:
        put(o,ROW+40,1)
        put(o,ROW+280,0)
        put(o,ROW+288,0)
        put(o,ROW+296,0)
        return lock(o,946)
    if phase==946:
        if get(o,RESUMING)!=0:
            if same_context_cap(o,CAP,w,112)==False:
                put(o,QUAR,1)
                return failure(o,11,1)
            between(o,SAVED_NEXT,w,112,24)
            zero(o,ROW+184,24)
        return memory(o,947,3,ROW,0,get(o,PTR),512)
    if phase==947:
        return unlock(o,948)
    if phase==948:
        # From this point the actual Value queue owns the record. No caller
        # dereferences it after the finalizer is permitted to retire it.
        put(o,PTR,0)
        value_packet(o,V_PRIVATE,56)
        return values(o,w,949)
    if phase==949:
        if value_valid(o)==False or get(o,VP+8)!=0:
            return failure(o,11,1)
        value_packet(o,V_TYPED,31)
        return values(o,w,952)
    if phase==952:
        if value_drop(o,False)==False or get(o,VP+104)!=0 or get(o,VP+112)!=0:
            return failure(o,11,1)
        if get(o,RESUMING)!=0:
            return lock(o,720)
        return failure(o,get(o,ERROR),0)
    if phase==950:
        if get(o,RESUMING)==0:
            between(w,112,o,ROW+184,24)
            between(o,CAP,w,112,24)
        return memory(o,951,3,ROW,0,get(o,PTR),512)
    if phase==951:
        return failure(o,11,1)
    if phase==960:
        if value_valid(o)==False:
            return canonical_park(o)
        if get(o,VP+8)==0:
            put(o,ROW+296,0)
            return again(o,931)
        if get(o,VP+8)!=1:
            return canonical_park(o)
        value_packet(o,V_TYPED,31)
        return values(o,w,961)
    if phase==961:
        if value_drop(o,False)==False or value_local_pending(o)!=0 or value_local_status(o)!=0:
            return canonical_park(o)
        # The exact private token no longer exists and actual mapping retry
        # is complete. Any resource child queue remains owned by Value.
        zero(o,ROW+160,24)
        put(o,ROW+296,0)
        return memory(o,933,3,ROW,0,get(o,PTR),512)
    if phase==970:
        if value_valid(o)==False:
            return canonical_park(o)
        if get(o,VP+8)==0:
            value_packet(o,V_QUERY,49)
            copy(o,RQ+24,ROW+256,24)
            return values(o,w,971)
        if get(o,VP+8)!=1 or get(o,ROW+232)==0:
            return canonical_park(o)
        value_packet(o,V_TYPED,31)
        return values(o,w,972)
    if phase==971:
        if value_valid(o)==False or get(o,VP+8)!=0 or get(o,VP+16)!=7 or same(o,VP+24,CAP,24)==False:
            return canonical_park(o)
        put(o,ROW+288,0)
        return again(o,940)
    if phase==972:
        if value_drop(o,False)==False or value_local_pending(o)!=0 or value_local_status(o)!=0:
            return canonical_park(o)
        value_packet(o,V_PRIVATE,80)
        copy(o,RQ+24,ROW+232,24)
        put(o,RQ+104,1)
        return values(o,w,973)
    if phase==973:
        if value_valid(o)==False:
            return canonical_park(o)
        if get(o,VP+8)==6:
            zero(o,ROW+256,24)
            put(o,ROW+288,0)
            return again(o,945)
        if get(o,VP+8)==0 and get(o,VP+16)==8 and get(o,VP+48)==7:
            copy(o,ROW+256,VP+24,24)
            return memory(o,974,3,ROW,0,get(o,PTR),512)
        return canonical_park(o)
    if phase==974:
        value_packet(o,V_QUERY,49)
        copy(o,RQ+24,ROW+256,24)
        return values(o,w,971)
    if phase==980:
        if value_valid(o)==False or get(o,VP+8)!=0 or get(o,VP+16)!=7:
            return failure(o,1,0)
        copy(o,CAP,VP+24,24)
        registry_packet(o,7)
        copy(o,RQ+24,CAP,24)
        return registry(o,w,400,128)
    if phase==981:
        if value_valid(o)==False or get(o,VP+8)!=0 or get(o,VP+16)!=8 or get(o,VP+48)!=7:
            return failure(o,1,0)
        if same(o,VP+24,ROW+232,24)==False:
            return failure(o,3,0)
        value_packet(o,V_PRIVATE,91)
        readcopy(s,16,o,RQ+24,24)
        return values(o,w,982)
    if phase==982:
        if canonical_pin_record(o)==False:
            # Retain the exact uncertain delivery record in a real registry
            # object; no guessed token is replayed or reported as consumed.
            copy(o,ROW+320,VP,128)
            put(o,ROW+312,1)
            put(o,ROW+40,4)
            put(o,QUAR,1)
            return memory(o,983,3,ROW,0,get(o,PTR),512)
        if get(o,VP+96)==0:
            return failure(o,choose(get(o,VP+8)==5,5,1),get(o,VP+80))
        copy(o,RESULT,VP+24,24)
        put(o,KIND,7)
        put(o,CONSUMED,1)
        put(o,C_NEED_DRAIN,1)
        if get(o,FAMILY)==5:
            if get(o,VP+104)!=0:
                return failure(o,11,1)
            return unlock(o,990)
        return failure(o,0,get(o,VP+80))
    if phase==983:
        return failure(o,11,1)
    return rejected(o)


def registration(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==990:
        future_packet(o,31,False)
        copy(o,RQ+16,ROW+64,24)
        copy(o,RQ+40,ROW+88,24)
        readcopy(s,40,o,RQ+64,24)
        put(o,RQ+88,get(o,FIXED_CALLBACK))
        put(o,R_ATTEMPT,1)
        return futures(o,w,991)
    if phase==991:
        if future_valid(o)==False:
            put(o,R_KNOWN,0)
            return failure(o,11,1)
        put(o,R_STATUS,get(o,FP+8))
        put(o,R_CLASS,get(o,FP+16))
        put(o,R_KNOWN,1)
        if get(o,FP+16)==200:
            if get(o,FP+72)==0 or get(o,FP+80)==0 or get(o,FP+88)==0:
                put(o,R_KNOWN,0)
                return failure(o,11,1)
            copy(o,R_ERROR,FP+72,24)
        pending=0
        if get(o,VALUE_UNMAP)!=0 or get(o,VALUE_QUEUE)!=0:
            pending=1
        return failure(o,0,pending)
    return rejected(o)

def finish_registration(o:mutbuf) -> u32:
    zero(o,R_FINAL,320)
    put(o,R_FINAL,REPLY4)
    put(o,R_FINAL+8,get(o,STATUS))
    put(o,R_FINAL+16,get(o,KIND))
    copy(o,R_FINAL+24,RESULT,24)
    copy(o,R_FINAL+48,R_ERROR,24)
    put(o,R_FINAL+72,get(o,R_STATUS))
    put(o,R_FINAL+80,get(o,R_CLASS))
    put(o,R_FINAL+88,get(o,R_KNOWN))
    put(o,R_FINAL+96,get(o,KNOWN))
    put(o,R_FINAL+104,get(o,CONSUMED))
    put(o,R_FINAL+112,get(o,PENDING))
    put(o,R_FINAL+120,get(o,R_ATTEMPT))
    if get(o,R_ATTEMPT)!=0:
        copy(o,R_FINAL+128,FP,192)
    copy(o,0,R_FINAL,320)
    return 0

def canonical_pin_record(o:mutbuf) -> bool:
    if value_valid(o)==False or get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+120)!=1:
        return False
    mapping=get(o,VP+104)
    queue=get(o,VP+112)
    if mapping>1 or queue>1 or get(o,VP+80)!=choose(mapping!=0 or queue!=0,1,0):
        return False
    status=get(o,VP+8)
    if get(o,VP+96)==0:
        return status!=0 and get(o,VP+24)==0 and get(o,VP+32)==0 and get(o,VP+40)==0
    return (status==0 or status==11) and get(o,VP+16)==8 and get(o,VP+24)!=0 and get(o,VP+32)!=0 and get(o,VP+40)!=0

def canonical_capture_record(o:mutbuf) -> bool:
    if value_valid(o)==False or get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+80)>1:
        return False
    status=get(o,VP+8)
    if get(o,VP+96)==0:
        return status!=0 and get(o,VP+24)==0 and get(o,VP+32)==0 and get(o,VP+40)==0
    if status!=0 and status!=11:
        return False
    if get(o,VP+16)!=8 or get(o,VP+24)==0 or get(o,VP+32)==0 or get(o,VP+40)==0:
        return False
    copy(o,ROW+256,VP+24,24)
    put(o,C_CAPTURE_TAKEN,1)
    return True

def canonical_failed(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    put(o,STATUS,status)
    put(o,KIND,0)
    put(o,CONSUMED,0)
    zero(o,RESULT,24)
    put(o,ROW+40,6)
    put(o,ROW+280,1)
    return memory(o,930,3,ROW,0,get(o,PTR),512)

def canonical_park(o:mutbuf) -> u32:
    put(o,C_NEED_DRAIN,0)
    put(o,ROW+40,6)
    put(o,ROW+280,1)
    if get(o,HELD)!=0:
        return again(o,950)
    return lock(o,950)

def same_context_cap(o:mutbuf,at:u64,w:mutbuf,to:u64) -> bool:
    return get(o,at)==get(w,to) and get(o,at+8)==get(w,to+8) and get(o,at+16)==get(w,to+16)

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
    put(o,RQ,choose(get(o,DEFER)!=0,FUT_PRIVATE,choose(typed,FUT_TYPED,FUT_REQUEST)))
    put(o,RQ+8,op)
    return 0

def futures(o:mutbuf,w:mutbuf,next:u64) -> u32:
    zero(o,FP,65536)
    return role(o,next,12,3,RQ,192,3,FP,65536,0,get(w,40),256)

def future_valid(o:mutbuf) -> bool:
    if get(o,DEFER)!=0:
        return private_future_valid(o)
    return get(o,FB)==0 and get(o,FP)==FUT_REPLY

def future_drop(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,DEFER)!=0 and private_future_valid(o)==False:
        return False
    if get(o,FB)!=0 or get(o,FP)!=choose(get(o,DEFER)!=0,FUT_ACK3,FUT_ACK):
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
    if get(o,DEFER)!=0:
        put(o,RQ,choose(magic==V_PRIVATE and op>=48,V_PRIVATE,V_QUERY))
        if op==29:
            put(o,RQ,V_PRIVATE)
            put(o,RQ+8,78)
        elif op==30:
            put(o,RQ,V_PRIVATE)
            put(o,RQ+8,92)
        elif op==31:
            put(o,RQ,V_PRIVATE)
            put(o,RQ+8,93)
    return 0

def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    zero(o,VP,32768)
    return role(o,next,13,3,RQ,choose(get(o,RQ+8)==48,152,128),3,VP,32768,0,get(w,64),256)

def value_valid(o:mutbuf) -> bool:
    return get(o,FB)==0 and get(o,VP)==V_REPLY

def value_drop(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,DEFER)!=0:
        return private_value_drop(o,allow_consumed)
    if get(o,FB)!=0 or get(o,VP)!=V_ACK:
        return False
    status=value_local_status(o)
    if get(o,VP+88)!=1 or get(o,VP+96)>1 or value_local_pending(o)>1:
        return False
    if allow_consumed==False and get(o,VP+96)!=0:
        return False
    if get(o,VP+96)!=0 and status!=0 and status!=11:
        return False
    if status==0 and value_local_pending(o)!=0:
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
PRIVATE_SOURCE='\ndef value_local_pending(o:mutbuf) -> u64:\n    if get(o,DEFER)!=0 and get(o,VP)==V_ACK and get(o,VP+120)==1:\n        return get(o,VP+104)\n    return get(o,VP+80)\ndef value_local_status(o:mutbuf) -> u64:\n    status=get(o,VP+8)\n    if get(o,DEFER)!=0 and get(o,VP)==V_ACK and get(o,VP+88)==1 and get(o,VP+120)==1:\n        if status==11 and get(o,VP+104)==0 and get(o,VP+112)==1 and (get(o,VP+96)==1 or get(o,RQ+8)==93):\n            return 0\n    return status\ndef private_future_valid(o:mutbuf) -> bool:\n    if get(o,FB)!=0 or get(o,FP)!=FUT_ACK3 or get(o,FP+128)>1 or get(o,FP+136)>1 or get(o,FP+144)!=0:\n        put(o,VALUE_BAD,1)\n        return False\n    if get(o,FP+128)!=0:\n        put(o,VALUE_UNMAP,1)\n    if get(o,FP+136)!=0:\n        put(o,VALUE_QUEUE,1)\n    return True\ndef private_value_drop(o:mutbuf,allow_consumed:bool) -> bool:\n    if get(o,FB)!=0 or get(o,VP)!=V_ACK or get(o,VP+88)!=1 or get(o,VP+120)!=1:\n        return False\n    status=get(o,VP+8)\n    consumed=get(o,VP+96)\n    mapping=get(o,VP+104)\n    queued=get(o,VP+112)\n    if consumed>1 or mapping>1 or queued>1 or get(o,VP+80)!=choose(mapping!=0 or queued!=0,1,0):\n        return False\n    if allow_consumed==False and consumed!=0:\n        return False\n    if consumed!=0 and status!=0 and status!=11:\n        return False\n    if status!=0 and status!=1 and status!=6 and status!=11:\n        return False\n    if status==0 and allow_consumed and consumed!=1:\n        return False\n    at=16\n    while at<80:\n        if get(o,VP+at)!=0:\n            return False\n        at=at+8\n    if queued!=0:\n        put(o,VALUE_QUEUE,1)\n    if mapping!=0:\n        put(o,VALUE_UNMAP,1)\n    return True\n'
SOURCE += PRIVATE_SOURCE

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
