"""Private native array observer owner; public iterable adapter is separate."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v,'little')for k,v in {'REQ':b'HIABFO01','REQ2':b'HIABFO02','REP':b'HIABFOR1','GLOBAL':b'HIABFPS1','NODEMAGIC':b'HIABFOB1','PUBLIC':b'HIABFP01','PUBLICREP':b'HIABFRP1','KERNEL':b'HIAMVFQ1','KERNELREP':b'HIAMVFR1','VALUE':b'HIABVQ01','VALUEREP':b'HIABVR01','MATH':b'HIABFM01','MATHREP':b'HIABFMR1','TIMEREP':b'HIAPFTR1'}.items()}
C.update({'MAX':18446744073709551615,'NEGATIVE':18446744073709547521,'OUT':131072,'PHASE':128,'PID':136,'ROOTPTR':144,'NODE':152,'NINPUT':160,'INPUTI':168,'UNIQUE':176,'TABLECAP':184,'VECTOR':192,'QUEUE':200,'TABLE':208,'OP':216,'WHEN':224,'ERROR':232,'CLASS':240,'DETAIL':248,'HELD':256,'NEXTLOCK':264,'NEXTUNLOCK':272,'PREV':280,'CURSOR':288,'SLOT':296,'PROBE':304,'INDEX':312,'COUNT':320,'TEMP':328,'AFTER':336,'TIMEBITS':344,'TIMEFLAG':352,'CLOCKBITS':360,'RAND':368,'TIMERREADY':384,'DEADLINE':392,'TIMEOUTNS':400,'FOUND':408,'KIND':416,'RAWN':424,'BUSY':432,'FEEDBACK':448,'TEMPHELD':456,'REGISTERED':464,'SCAN':472,'INITIAL':480,'PRESERVE':488,'STATUS':496,'HEADER':512,'CLOCK':768,'VALUECAP':800,'ROW':1024,'HASHCELL':1152,'OUTROW':1536,'RQ':2048,'CHILD':8192,'MI':74496,'MO':75008,'MW':75264})
SOURCE=r'''
def observers(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        if (word(s,0)!=REQ and word(s,0)!=REQ2) or word(s,8)>4:
            return 4294967293
        op=word(s,8)
        if word(s,0)==REQ2 and op!=1:
            return 4294967293
        if op<2:
            n=word(s,16)
            if n>(MAX-128)//48 or length(s)!=128+n*48 or word(s,24)>3:
                return 4294967293
            if op==1 and word(s,24)!=0:
                return 4294967293
            first=56
        else:
            if length(s)!=128:
                return 4294967293
            first=48
            if op!=3 and word(s,40)!=0:
                return 4294967293
        i=first
        while i<128:
            if word(s,i)!=0:
                return 4294967293
            i=i+8
        zero(o,128,3968)
        put(o,OP,op)
        put(o,WHEN,word(s,24))
        if op<2:
            put(o,NINPUT,word(s,16))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<30:
        return initialize(s,o,w,phase)
    if phase<100:
        return capture(s,o,w,phase)
    if phase<150:
        return snapshot(s,o,w,phase)
    if phase<250:
        return lookup(s,o,w,phase)
    if phase<400:
        return waiting(s,o,w,phase)
    if phase<500:
        return exceptions(s,o,w,phase)
    if phase<600:
        return iteration(s,o,w,phase)
    if phase<700:
        return sleeping(s,o,w,phase)
    if phase<800:
        return timeout_start(s,o,w,phase)
    if phase<1000:
        return synchronizing(s,o,w,phase)
    return cleanup(s,o,w,phase)

def initialize(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE or get(w,0)!=GLOBAL or get(w,8)!=pid or get(w,24)!=0:
            return reply_error(o,1,107)
        if get(w,64)==0 or get(w,72)==0 or get(w,88)==0 or get(w,112)==0:
            return reply_error(o,1,107)
        put(o,PID,pid)
        return waddress(o,2,0)
    if phase==2:
        put(o,ROOTPTR,get(o,FEEDBACK))
        if get(o,OP)>=2:
            return lock(o,200)
        if word(s,0)==REQ2:
            return lock(o,150)
        if get(o,OP)==0:
            return again(o,30)
        if word(s,32)==0 and word(s,40)==0 and word(s,48)==0:
            put(o,TIMEFLAG,1)
            return again(o,30)
        value_packet(o,5)
        copy_input(s,32,o,RQ+24,24)
        return value(o,w,10)
    if phase==10:
        if value_ok(o)==False:
            return failure(o,choose(get(o,CHILD+8)==1,3,1),choose(get(o,CHILD+8)==5,103,107))
        within(o,VALUECAP,CHILD+24,24)
        value_packet(o,7)
        within(o,RQ+24,VALUECAP,24)
        return value(o,w,11)
    if phase==11:
        if value_ok(o)==False:
            return failure(o,1,107)
        kind=get(o,CHILD+16)
        put(o,KIND,kind)
        if kind==0:
            put(o,TIMEFLAG,1)
            return again(o,26)
        n=get(o,CHILD+72)
        put(o,RAWN,n)
        if kind==1 or kind==2 or kind==3:
            value_packet(o,19)
            within(o,RQ+24,VALUECAP,24)
            put(o,RQ+112,choose(n<310,n,310))
            return value(o,w,12)
        return system(o,13,228,12,1,CLOCK,0,0,0,0)
    if phase==12:
        if value_ok(o)==False:
            return failure(o,1,107)
        return system(o,13,228,12,1,CLOCK,0,0,0,0)
    if phase==13:
        if clock_ok(o)==False:
            return failure(o,1,107)
        math_packet(o,2,clock_ns(o),0)
        return math(o,14,128)
    if phase==14:
        if math_ok(o)==False:
            return failure(o,1,107)
        put(o,CLOCKBITS,get(o,MO+24))
        kind=get(o,KIND)
        if kind==1:
            put(o,TIMEBITS,choose(byte(o,CHILD+8192)==0,0,4607182418800017408))
            return again(o,24)
        if kind==3:
            put(o,TIMEBITS,get(o,CHILD+8192))
            return again(o,24)
        if kind!=2:
            put(o,DETAIL,kind)
            return failure(o,1,104)
        if get(o,RAWN)>310:
            put(o,DETAIL,1)
            return failure(o,1,106)
        math_packet(o,3,get(o,RAWN),0)
        within(o,MI+128,CHILD+8192,get(o,RAWN))
        return math(o,23,128+get(o,RAWN))
    if phase==23:
        if get(o,FEEDBACK)!=0 or get(o,MO)!=MATHREP:
            return failure(o,1,107)
        if get(o,MO+8)!=0:
            put(o,DETAIL,get(o,MO+32))
            return failure(o,1,get(o,MO+16))
        put(o,TIMEBITS,get(o,MO+24))
        return again(o,24)
    if phase==24:
        math_packet(o,0,get(o,TIMEBITS),get(o,CLOCKBITS))
        return math(o,25,128)
    if phase==25:
        if math_ok(o)==False:
            return failure(o,1,107)
        put(o,TIMEBITS,get(o,MO+24))
        return again(o,26)
    if phase==26:
        if get(o,VALUECAP)==0:
            return again(o,30)
        value_packet(o,6)
        within(o,RQ+24,VALUECAP,24)
        return value(o,w,27)
    if phase==27:
        zero(o,VALUECAP,24)
        if value_ok(o)==False:
            return failure(o,1,107)
        return again(o,30)
    return failure(o,1,107)

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==30:
        n=get(o,NINPUT)
        if n>MAX//96 or n>MAX//16:
            return failure(o,3,103)
        capacity=1
        while capacity<n*2:
            if capacity>MAX//2:
                return failure(o,3,103)
            capacity=capacity*2
        if capacity>MAX//8:
            return failure(o,3,103)
        put(o,TABLECAP,capacity)
        return allocate(o,31,256)
    if phase==31:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,NODE,ptr)
        if get(o,NINPUT)==0:
            return again(o,36)
        return allocate(o,32,get(o,NINPUT)*96)
    if phase==32:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,VECTOR,ptr)
        return allocate(o,33,get(o,NINPUT)*8)
    if phase==33:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,QUEUE,ptr)
        return allocate(o,34,get(o,TABLECAP)*8)
    if phase==34:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,TABLE,ptr)
        return again(o,36)
    if phase==36:
        return system(o,37,318,3,RAND,16,0,0,0,0)
    if phase==37:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return again(o,36)
        if raw!=16:
            return failure(o,1,107)
        if get(o,RAND)==0 and get(o,RAND+8)==0:
            return again(o,36)
        return again(o,40)
    if phase==40:
        if get(o,INPUTI)==get(o,NINPUT):
            return lock(o,100)
        public_packet(o,5)
        copy_input(s,128+get(o,INPUTI)*48,o,RQ+16,48)
        return public(o,w,41)
    if phase==41:
        if public_ok(o)==False:
            return public_failure(o)
        if get(o,CHILD+16)!=2:
            return failure(o,1,107)
        zero(o,ROW,96)
        within(o,ROW,CHILD+24,24)
        within(o,ROW+24,CHILD+48,24)
        put(o,TEMPHELD,1)
        public_packet(o,21)
        within(o,RQ+16,ROW,48)
        return public(o,w,42)
    if phase==42:
        if public_ok(o)==False:
            return public_failure(o)
        if get(o,CHILD+16)!=7 or get(o,CHILD+96)==0:
            return failure(o,1,107)
        key=get(o,CHILD+96)
        put(o,ROW+48,key)
        put(o,SLOT,hash(key)&(get(o,TABLECAP)-1))
        put(o,PROBE,0)
        return again(o,43)
    if phase==43:
        if get(o,PROBE)>=get(o,TABLECAP):
            return failure(o,1,107)
        return memory(o,44,0,get(o,TABLE)+get(o,SLOT)*8,3,HASHCELL,8)
    if phase==44:
        index=get(o,HASHCELL)
        if index==0:
            return again(o,50)
        if index>get(o,UNIQUE):
            return failure(o,1,107)
        return memory(o,45,0,get(o,VECTOR)+(index-1)*96+48,3,HASHCELL,8)
    if phase==45:
        if get(o,HASHCELL)==get(o,ROW+48):
            public_packet(o,6)
            within(o,RQ+16,ROW,48)
            return public(o,w,46)
        put(o,PROBE,get(o,PROBE)+1)
        put(o,SLOT,(get(o,SLOT)+1)&(get(o,TABLECAP)-1))
        return again(o,43)
    if phase==46:
        put(o,TEMPHELD,0)
        if public_ok(o)==False:
            return public_failure(o)
        put(o,INPUTI,get(o,INPUTI)+1)
        return again(o,40)
    if phase==50:
        put(o,ROW+56,1)
        put(o,ROW+64,get(o,INPUTI))
        return memory(o,51,3,ROW,0,get(o,VECTOR)+get(o,UNIQUE)*96,96)
    if phase==51:
        put(o,TEMPHELD,0)
        return write_pointer(o,52,get(o,TABLE)+get(o,SLOT)*8,get(o,UNIQUE)+1)
    if phase==52:
        put(o,UNIQUE,get(o,UNIQUE)+1)
        put(o,INPUTI,get(o,INPUTI)+1)
        return again(o,40)
    return failure(o,1,107)

def snapshot(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        put(o,INDEX,0)
        put(o,COUNT,0)
        return again(o,101)
    if phase==101:
        if get(o,INDEX)==get(o,UNIQUE):
            return again(o,120)
        return memory(o,102,0,get(o,VECTOR)+get(o,INDEX)*96,3,ROW,96)
    if phase==102:
        zero(o,RQ,64)
        put(o,RQ,KERNEL)
        put(o,RQ+8,5)
        return invoke(o,103,get(w,64),RQ,64,CHILD,512,get(o,ROW+48),512)
    if phase==103:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=KERNELREP or get(o,CHILD+8)!=0 or get(o,CHILD+24)>2:
            return failure(o,1,107)
        state=get(o,CHILD+24)
        put(o,ROW+72,state)
        put(o,ROW+80,get(o,CHILD+32))
        if state==0:
            return memory(o,108,3,ROW,0,get(o,VECTOR)+get(o,INDEX)*96,96)
        put(o,ROW+56,0)
        return write_pointer(o,104,get(o,QUEUE)+get(o,COUNT)*8,get(o,INDEX))
    if phase==104:
        put(o,COUNT,get(o,COUNT)+1)
        return memory(o,108,3,ROW,0,get(o,VECTOR)+get(o,INDEX)*96,96)
    if phase==108:
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,101)
    if phase==120:
        zero(o,HEADER,256)
        put(o,HEADER,NODEMAGIC)
        put(o,HEADER+8,get(w,48))
        put(o,HEADER+16,get(o,ROOTPTR))
        put(o,HEADER+24,get(o,PID))
        put(o,HEADER+32,get(o,UNIQUE))
        put(o,HEADER+40,get(o,VECTOR))
        put(o,HEADER+48,get(o,UNIQUE)*96)
        put(o,HEADER+56,get(o,QUEUE))
        put(o,HEADER+64,get(o,UNIQUE)*8)
        put(o,HEADER+72,get(o,COUNT))
        put(o,HEADER+88,get(o,UNIQUE)-get(o,COUNT))
        put(o,HEADER+96,choose(get(o,UNIQUE)!=get(o,COUNT),1,0))
        put(o,HEADER+104,get(o,TABLE))
        put(o,HEADER+112,get(o,TABLECAP))
        put(o,HEADER+120,choose(get(o,TABLE)!=0,get(o,TABLECAP)*8,0))
        put(o,HEADER+128,get(o,RAND))
        put(o,HEADER+136,get(o,RAND+8))
        put(o,HEADER+144,get(o,OP))
        put(o,HEADER+152,1)
        put(o,HEADER+160,get(o,COUNT))
        put(o,HEADER+168,get(o,COUNT))
        put(o,HEADER+176,get(o,UNIQUE))
        put(o,HEADER+184,get(o,TIMEBITS))
        put(o,HEADER+192,get(o,TIMEFLAG))
        return memory(o,121,3,HEADER,0,get(o,NODE),256)
    if phase==121:
        put(w,48,get(o,NODE))
        put(o,REGISTERED,1)
        if get(o,OP)==1:
            return write_pointer(o,122,get(o,NODE)+152,0)
        return unlock(o,300)
    if phase==122:
        return unlock(o,980)
    return failure(o,1,107)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==150:
        put(o,CURSOR,get(w,48))
        return again(o,151)
    if phase==151:
        if get(o,CURSOR)==0:
            return failure(o,1,102)
        return memory(o,152,0,get(o,CURSOR),3,HEADER,256)
    if phase==152:
        if get(o,HEADER)!=NODEMAGIC or get(o,HEADER+16)!=get(o,ROOTPTR) or get(o,HEADER+24)!=get(o,PID):
            return failure(o,1,107)
        if get(o,CURSOR)!=word(s,32):
            put(o,CURSOR,get(o,HEADER+8))
            return again(o,151)
        if get(o,HEADER+128)!=word(s,40) or get(o,HEADER+136)!=word(s,48) or get(o,HEADER+144)!=1 or get(o,HEADER+32)!=0 or get(o,HEADER+152)!=0:
            return failure(o,1,102)
        put(o,TIMEBITS,get(o,HEADER+184))
        put(o,TIMEFLAG,get(o,HEADER+192))
        return unlock(o,30)
    if phase==200:
        put(o,CURSOR,get(w,48))
        put(o,PREV,0)
        return again(o,201)
    if phase==201:
        if get(o,CURSOR)==0:
            put(o,ERROR,1)
            put(o,CLASS,102)
            return unlock(o,997)
        return memory(o,202,0,get(o,CURSOR),3,HEADER,256)
    if phase==202:
        if get(o,HEADER)!=NODEMAGIC or get(o,HEADER+16)!=get(o,ROOTPTR) or get(o,HEADER+24)!=get(o,PID):
            put(o,ERROR,1)
            put(o,CLASS,107)
            return unlock(o,997)
        if get(o,CURSOR)!=word(s,16):
            put(o,PREV,get(o,CURSOR))
            put(o,CURSOR,get(o,HEADER+8))
            return again(o,201)
        bad=get(o,HEADER+128)!=word(s,24) or get(o,HEADER+136)!=word(s,32) or get(o,HEADER+152)!=0 or get(o,HEADER+144)>1
        if get(o,OP)==2 and get(o,HEADER+144)!=1:
            bad=True
        if get(o,OP)==3 and (get(o,HEADER+144)!=0 or word(s,40)>=get(o,HEADER+32)):
            bad=True
        if bad:
            put(o,ERROR,1)
            put(o,CLASS,102)
            return unlock(o,997)
        put(o,NODE,get(o,CURSOR))
        put(o,UNIQUE,get(o,HEADER+32))
        put(o,VECTOR,get(o,HEADER+40))
        put(o,QUEUE,get(o,HEADER+56))
        put(o,TABLE,get(o,HEADER+104))
        put(o,REGISTERED,1)
        put(o,RAND,get(o,HEADER+128))
        put(o,RAND+8,get(o,HEADER+136))
        put(o,TIMEBITS,get(o,HEADER+184))
        put(o,TIMEFLAG,get(o,HEADER+192))
        return write_pointer(o,210,get(o,NODE)+152,1)
    if phase==210:
        if get(o,OP)==4:
            return again(o,1000)
        if get(o,OP)==2:
            return again(o,500)
        put(o,INDEX,word(s,40))
        return memory(o,220,0,get(o,VECTOR)+get(o,INDEX)*96,3,ROW,96)
    if phase==220:
        if get(o,ROW+88)!=0 or get(o,ROW+24)==0:
            put(o,ERROR,1)
            put(o,CLASS,102)
            return write_pointer(o,245,get(o,NODE)+152,0)
        within(o,OUTROW,ROW,96)
        put(o,ROW+88,1)
        zero(o,ROW+24,24)
        return memory(o,221,3,ROW,0,get(o,VECTOR)+get(o,INDEX)*96,96)
    if phase==221:
        return write_pointer(o,222,get(o,NODE)+152,0)
    if phase==222:
        return unlock(o,981)
    if phase==245:
        return unlock(o,997)
    return failure(o,1,107)

def waiting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return lock(o,301)
    if phase==301:
        return memory(o,302,0,get(o,NODE),3,HEADER,256)
    if phase==302:
        pending=get(o,HEADER+88)
        if pending==0 or (get(o,WHEN)==0 and get(o,HEADER+72)!=0) or get(o,FOUND)!=0:
            return again(o,390)
        if get(o,WHEN)>2:
            return failure(o,1,105)
        if get(o,WHEN)==1 and get(o,HEADER+200)<get(o,HEADER+72):
            return memory(o,401,0,get(o,QUEUE)+get(o,HEADER+200)*8,3,HASHCELL,8)
        if get(o,TIMERREADY)==0:
            return unlock(o,700)
        if get(o,TIMEFLAG)==0 and get(o,TIMEOUTNS)==0:
            return again(o,390)
        return write_pointer(o,303,get(o,NODE)+248,0)
    if phase==303:
        return unlock(o,600)
    if phase==390:
        put(o,HEADER+96,0)
        put(o,HEADER+152,0)
        return memory(o,391,3,HEADER,0,get(o,NODE),256)
    if phase==391:
        return unlock(o,982)
    return failure(o,1,107)

def exceptions(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==401:
        if get(o,HASHCELL)>=get(o,UNIQUE):
            return failure(o,1,107)
        put(o,INDEX,get(o,HASHCELL))
        return write_pointer(o,402,get(o,NODE)+200,get(o,HEADER+200)+1)
    if phase==402:
        return memory(o,403,0,get(o,VECTOR)+get(o,INDEX)*96,3,ROW,96)
    if phase==403:
        return unlock(o,404)
    if phase==404:
        public_packet(o,9)
        within(o,RQ+16,ROW,48)
        return public(o,w,405)
    if phase==405:
        if public_ok(o)==False:
            return public_failure(o)
        if get(o,CHILD+96)==1:
            return again(o,300)
        if get(o,CHILD+96)!=2:
            return failure(o,1,107)
        public_packet(o,11)
        within(o,RQ+16,ROW,48)
        return public(o,w,406)
    if phase==406:
        if public_ok(o)==False:
            return public_failure(o)
        if get(o,CHILD+16)==0:
            return again(o,300)
        if get(o,CHILD+16)!=4:
            return failure(o,1,107)
        put(o,FOUND,1)
        value_packet(o,6)
        within(o,RQ+24,CHILD+72,24)
        return value(o,w,407)
    if phase==407:
        if value_ok(o)==False:
            return failure(o,1,107)
        return again(o,300)
    return failure(o,1,107)

def iteration(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,HEADER+80)==get(o,UNIQUE):
            put(o,KIND,4)
            return again(o,1000)
        if get(o,HEADER+80)<get(o,HEADER+168):
            return again(o,530)
        return unlock(o,510)
    if phase==510:
        if get(o,TIMEFLAG)!=0:
            return lock(o,523)
        return system(o,511,228,12,1,CLOCK,0,0,0,0)
    if phase==511:
        if clock_ok(o)==False:
            return failure(o,1,107)
        math_packet(o,2,clock_ns(o),0)
        return math(o,512,128)
    if phase==512:
        if math_ok(o)==False:
            return failure(o,1,107)
        math_packet(o,1,get(o,TIMEBITS),get(o,MO+24))
        return math(o,513,128)
    if phase==513:
        if math_ok(o)==False:
            return failure(o,1,107)
        bits=get(o,MO+24)
        if negative_float(bits):
            put(o,DETAIL,get(o,UNIQUE)-get(o,HEADER+80))
            return failure(o,1,101)
        put(o,TIMEOUTNS,bits)
        return lock(o,523)
    if phase==523:
        return memory(o,524,0,get(o,NODE),3,HEADER,256)
    if phase==524:
        if get(o,HEADER+80)<get(o,HEADER+72):
            return write_pointer(o,525,get(o,NODE)+168,get(o,HEADER+72))
        return write_pointer(o,526,get(o,NODE)+248,0)
    if phase==525:
        put(o,HEADER+168,get(o,HEADER+72))
        return again(o,530)
    if phase==526:
        return unlock(o,550)
    if phase==530:
        return memory(o,531,0,get(o,QUEUE)+get(o,HEADER+80)*8,3,HASHCELL,8)
    if phase==531:
        if get(o,HASHCELL)>=get(o,UNIQUE):
            return failure(o,1,107)
        put(o,INDEX,get(o,HASHCELL))
        return memory(o,532,0,get(o,VECTOR)+get(o,INDEX)*96,3,ROW,96)
    if phase==532:
        if get(o,ROW+88)!=0 or get(o,ROW+24)==0:
            return failure(o,1,107)
        within(o,OUTROW,ROW,96)
        put(o,ROW+88,1)
        zero(o,ROW+24,24)
        return memory(o,533,3,ROW,0,get(o,VECTOR)+get(o,INDEX)*96,96)
    if phase==533:
        return write_pointer(o,534,get(o,NODE)+80,get(o,HEADER+80)+1)
    if phase==534:
        return write_pointer(o,535,get(o,NODE)+152,0)
    if phase==535:
        return unlock(o,981)
    if phase==550:
        if get(o,TIMEFLAG)!=0:
            return again(o,610)
        math_packet(o,4,get(o,TIMEOUTNS),0)
        return math(o,551,128)
    if phase==551:
        if get(o,FEEDBACK)!=0 or get(o,MO)!=MATHREP:
            return failure(o,1,107)
        if get(o,MO+8)!=0:
            put(o,DETAIL,get(o,MO+32))
            return failure(o,1,get(o,MO+16))
        ns=get(o,MO+24)
        put(o,TIMEOUTNS,ns)
        if ns==0:
            return again(o,510)
        put(o,CLOCK,ns//1000000000)
        put(o,CLOCK+8,ns%1000000000)
        return system(o,611,202,192,get(o,NODE)+248,128,0,CLOCK,0,0)
    return failure(o,1,107)

def sleeping(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        if get(o,TIMEFLAG)!=0:
            return system(o,601,202,0,get(o,NODE)+248,128,0,0,0,0)
        put(o,CLOCK,get(o,DEADLINE)//1000000000)
        put(o,CLOCK+8,get(o,DEADLINE)%1000000000)
        return system(o,601,202,192,get(o,NODE)+248,137,0,CLOCK,0,4294967295)
    if phase==601:
        raw=get(o,FEEDBACK)
        if raw==MAX-109:
            put(o,TIMEOUTNS,0)
        elif raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return failure(o,1,107)
        return again(o,300)
    if phase==610:
        return system(o,611,202,0,get(o,NODE)+248,128,0,0,0,0)
    if phase==611:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10 and raw!=MAX-109:
            return failure(o,1,107)
        return again(o,510)
    return failure(o,1,107)

def timeout_start(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if word(s,32)==0 and word(s,40)==0 and word(s,48)==0:
            put(o,TIMERREADY,1)
            put(o,TIMEFLAG,1)
            return again(o,300)
        if get(w,168)==0:
            return failure(o,1,107)
        public_packet(o,0)
        copy_input(s,32,o,RQ+104,24)
        return invoke(o,701,get(w,168),RQ,192,CHILD,16384,get(o,ROOTPTR),256)
    if phase==701:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=TIMEREP:
            return failure(o,1,107)
        if get(o,CHILD+8)!=0:
            put(o,DETAIL,get(o,CHILD+40))
            return failure(o,get(o,CHILD+8),get(o,CHILD+16))
        put(o,TIMERREADY,1)
        put(o,TIMEFLAG,get(o,CHILD+32))
        put(o,TIMEOUTNS,get(o,CHILD+24))
        if get(o,TIMEFLAG)!=0 or get(o,TIMEOUTNS)==0:
            return again(o,300)
        return system(o,702,228,12,1,CLOCK,0,0,0,0)
    if phase==702:
        if clock_ok(o)==False:
            return failure(o,1,107)
        now=clock_ns(o)
        ns=get(o,TIMEOUTNS)
        if ns>MAX-now:
            put(o,DEADLINE,MAX)
        else:
            put(o,DEADLINE,now+ns)
        return again(o,300)
    return failure(o,1,107)

def synchronizing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,NEXTLOCK))
        return system(o,901,202,1,32,128,1,0,0,0)
    if phase==901:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return system(o,902,24,0,0,0,0,0,0,0)
        return atom(o,2,900,0,1)
    if phase==902:
        return atom(o,2,900,0,1)
    if phase==920:
        return system(o,921,202,1,32,129,2147483647,0,0,0)
    if phase==921:
        if get(o,FEEDBACK)==MAX-3:
            return again(o,920)
        if get(o,FEEDBACK)>=NEGATIVE:
            put(o,504,1)
        return again(o,get(o,NEXTUNLOCK))
    if phase==980:
        return reply_handle(o,2)
    if phase==981:
        return reply_future(o)
    if phase==982:
        return reply_handle(o,1)
    if phase==997:
        return reply_error(o,get(o,ERROR),get(o,CLASS))
    return failure(o,1,107)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        if get(o,REGISTERED)!=0:
            if get(o,HELD)==0:
                return lock(o,1000)
            put(o,CURSOR,get(w,48))
            put(o,PREV,0)
            return again(o,1001)
        if get(o,HELD)!=0:
            return unlock(o,1010)
        return again(o,1010)
    if phase==1001:
        if get(o,CURSOR)==0:
            put(o,504,1)
            return unlock(o,997)
        return memory(o,1002,0,get(o,CURSOR),3,HEADER,256)
    if phase==1002:
        if get(o,CURSOR)!=get(o,NODE):
            put(o,PREV,get(o,CURSOR))
            put(o,CURSOR,get(o,HEADER+8))
            return again(o,1001)
        if get(o,PREV)==0:
            put(w,48,get(o,HEADER+8))
            return again(o,1003)
        return write_pointer(o,1003,get(o,PREV)+8,get(o,HEADER+8))
    if phase==1003:
        put(o,REGISTERED,0)
        return unlock(o,1010)
    if phase==1010:
        if get(o,TEMPHELD)!=0:
            put(o,TEMPHELD,0)
            public_packet(o,6)
            within(o,RQ+16,ROW,48)
            return public(o,w,1011)
        return again(o,1012)
    if phase==1011:
        if public_ok(o)==False:
            put(o,504,1)
        return again(o,1012)
    if phase==1012:
        if get(o,VALUECAP)!=0:
            value_packet(o,6)
            within(o,RQ+24,VALUECAP,24)
            zero(o,VALUECAP,24)
            return value(o,w,1013)
        put(o,INDEX,0)
        return again(o,1020)
    if phase==1013:
        if value_ok(o)==False:
            put(o,504,1)
        put(o,INDEX,0)
        return again(o,1020)
    if phase==1020:
        if get(o,INDEX)==get(o,UNIQUE):
            return again(o,1060)
        return memory(o,1021,0,get(o,VECTOR)+get(o,INDEX)*96,3,ROW,96)
    if phase==1021:
        if get(o,ROW+24)==0:
            put(o,INDEX,get(o,INDEX)+1)
            return again(o,1020)
        public_packet(o,6)
        within(o,RQ+16,ROW,48)
        return public(o,w,1022)
    if phase==1022:
        if public_ok(o)==False:
            put(o,504,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,1020)
    if phase==1060:
        return deallocate(o,1061,get(o,TABLE))
    if phase==1061:
        put(o,TABLE,0)
        return deallocate(o,1062,get(o,QUEUE))
    if phase==1062:
        put(o,QUEUE,0)
        return deallocate(o,1063,get(o,VECTOR))
    if phase==1063:
        put(o,VECTOR,0)
        return deallocate(o,1064,get(o,NODE))
    if phase==1064:
        put(o,NODE,0)
        if get(o,504)!=0 and get(o,ERROR)==0:
            put(o,ERROR,1)
            put(o,CLASS,107)
        if get(o,ERROR)!=0:
            return reply_error(o,get(o,ERROR),get(o,CLASS))
        kind=get(o,KIND)
        zero(o,0,128)
        put(o,0,REP)
        put(o,16,choose(kind==4,4,0))
        return 0
    return reply_error(o,1,107)

def reply_handle(o:mutbuf,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REP)
    put(o,16,kind)
    put(o,24,get(o,NODE))
    put(o,32,get(o,RAND))
    put(o,40,get(o,RAND+8))
    put(o,48,get(o,UNIQUE)-get(o,HEADER+88))
    put(o,56,get(o,HEADER+88))
    put(o,64,get(o,UNIQUE))
    put(o,120,get(o,504))
    return 0

def reply_future(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REP)
    put(o,16,3)
    within(o,24,OUTROW,48)
    put(o,72,get(o,INDEX))
    put(o,80,get(o,OUTROW+64))
    put(o,96,choose(get(o,OUTROW+56)==0,1,0))
    put(o,120,get(o,504))
    return 0

def reply_error(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REP)
    put(o,8,status)
    put(o,16,kind)
    within(o,72,832,24)
    put(o,96,get(o,DETAIL))
    put(o,104,get(o,UNIQUE))
    put(o,120,get(o,504))
    return 0

def failure(o:mutbuf,status:u64,kind:u64) -> u32:
    put(o,ERROR,status)
    put(o,CLASS,kind)
    return again(o,1000)

def public_failure(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=PUBLICREP:
        return failure(o,1,107)
    if get(o,CHILD+16)==200:
        within(o,832,CHILD+72,24)
    return failure(o,get(o,CHILD+8),get(o,CHILD+16))

def public_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==PUBLICREP and get(o,CHILD+8)==0

def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==VALUEREP and get(o,CHILD+8)==0

def math_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,MO)==MATHREP and get(o,MO+8)==0

def clock_ok(o:mutbuf) -> bool:
    sec=get(o,CLOCK)
    ns=get(o,CLOCK+8)
    return get(o,FEEDBACK)==0 and sec<=MAX//1000000000 and ns<1000000000 and ns<=MAX-sec*1000000000

def clock_ns(o:mutbuf) -> u64:
    return get(o,CLOCK)*1000000000+get(o,CLOCK+8)

def negative_float(bits:u64) -> bool:
    return (bits>>63)!=0 and (bits&9223372036854775807)!=0 and not_nan(bits)

def not_nan(bits:u64) -> bool:
    return ((bits>>52)&2047)!=2047 or (bits&4503599627370495)==0

def hash(key:u64) -> u64:
    return ((key>>4)^(key>>32))*11400714819323198485

def public_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,PUBLIC)
    put(o,RQ+8,op)
    return 0

def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,VALUE)
    put(o,RQ+8,op)
    return 0

def math_packet(o:mutbuf,op:u64,a:u64,b:u64) -> u64:
    zero(o,MI,128)
    put(o,MI,MATH)
    put(o,MI+8,op)
    put(o,MI+16,a)
    put(o,MI+24,b)
    return 0

def math(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 11

def public(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,88),RQ,192,CHILD,65536,get(o,ROOTPTR),256)

def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,CHILD,65536,get(w,112),get(w,120))

def invoke(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,51)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9

def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6

def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7

def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXTLOCK,next)
    return atom(o,2,900,0,1)

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,HELD,0)
    put(o,NEXTUNLOCK,next)
    return atom(o,3,920,0,0)

def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,a)
    put(o,16,b)
    return action

def waddress(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 5

def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)

def memory(o:mutbuf,next:u64,a:u64,at:u64,b:u64,bt:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,at)
    put(o,16,b)
    put(o,24,bt)
    put(o,32,n)
    return 8

def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0

def copy_input(s:readbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)

def put(o:mutbuf,at:u64,value:u64) -> u64:
    word_store(o,at,value)
    return 0

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
 s=SOURCE
 for name,value in sorted(C.items(),key=lambda item:-len(item[0])):s=re.sub(r'\b'+name+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_observers')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),max(len(f['blocks'])for f in d['functions']))
if __name__=='__main__':main()
