"""Native owned Iterable/iterator adapter for Future wait and as_completed."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v,'little')for k,v in {'REQ':b'HIABFA01','REP':b'HIABFAR1','GLOBAL':b'HIABFPS1','NODEMAGIC':b'HIABFOB1','PUBLIC':b'HIABFP01','PUBLICREP':b'HIABFRP1','VALUE':b'HIABVQ01','VALUEREP':b'HIABVR01','ARRAY':b'HIABFO01','ARRAY2':b'HIABFO02','ARRAYREP':b'HIABFOR1','ITER':b'HIABFIQ1','ITERREP':b'HIABFIR1'}.items()}
C.update({'MAX':18446744073709551615,'NEGATIVE':18446744073709547521,
'OUT':262144,'PHASE':128,'PID':136,'ROOTPTR':144,'NODE':152,'OP':160,'NINPUT':168,
'INDEX':176,'HELD':184,'NEXTLOCK':192,'NEXTUNLOCK':200,'PREV':208,'CURSOR':216,
'TEMP':224,'REGISTERED':232,'ERROR':240,'CLASS':248,'DETAIL':256,'AFTER':264,
'TEMPHELD':272,'NEWVEC':280,'OLDCAP':288,'OLDBUF':296,'ENTRY':304,'RELEASE_STEP':312,
'VECTOR_AFTER':320,'FINISH_KIND':328,'CLEANFAIL':336,'TOTAL':344,'CONSUMED':352,'WRAPI':360,'WRAPPER':1152,'KEYCAP':1176,'VALCAP':1200,'DISCARD':1224,'FEEDBACK':448,'HEADER':512,
'ROW':1056,'ERRCAP':1120,'RETAINED':1152,'SAVED':1536,'RQ':2048,'CHILD':8192})
SOURCE=r'''
def iterable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<192 or length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        if word(s,0)!=REQ or word(s,8)>5:
            return 4294967293
        op=word(s,8)
        if op==2 or op==3:
            if length(s)!=192:
                return 4294967293
            first=40
        else:
            if word(s,72)>3:
                return 4294967293
            if (op==1 or op==5) and word(s,72)!=0:
                return 4294967293
            if op<2:
                if length(s)!=192 or word(s,16)==0 or word(s,80)!=0:
                    return 4294967293
            else:
                if word(s,16)!=0 or word(s,24)!=0 or word(s,32)!=0 or word(s,40)!=0:
                    return 4294967293
                n=word(s,80)
                if n>(MAX-192)//48 or length(s)!=192+n*48:
                    return 4294967293
            first=88
        i=first
        while i<192:
            if word(s,i)!=0:
                return 4294967293
            i=i+8
        zero(o,128,3968)
        put(o,OP,op)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<50:
        return initialize(s,o,w,phase)
    if phase<100:
        return list_capture(s,o,w,phase)
    if phase<150:
        return publish(s,o,w,phase)
    if phase<250:
        return lookup(s,o,w,phase)
    if phase<350:
        return enumeration(s,o,w,phase)
    if phase<450:
        return collecting(s,o,w,phase)
    if phase<550:
        return arrays(s,o,w,phase)
    if phase<650:
        return collection_release(s,o,w,phase)
    if phase<900:
        return retaining(s,o,w,phase)
    if phase<1000:
        return synchronizing(s,o,w,phase)
    return cleanup(s,o,w,phase)

def initialize(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE or get(w,0)!=GLOBAL or get(w,8)!=pid or get(w,24)!=0:
            return reply_error(o,1,107)
        if get(w,72)==0 or get(w,88)==0 or get(w,112)==0:
            return reply_error(o,1,107)
        put(o,PID,pid)
        return waddress(o,2,0)
    if phase==2:
        put(o,ROOTPTR,get(o,FEEDBACK))
        if get(o,OP)==2 or get(o,OP)==3:
            return lock(o,200)
        return allocate(o,3,512)
    if phase==3:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,NODE,ptr)
        zero(o,HEADER,512)
        put(o,HEADER,NODEMAGIC)
        put(o,HEADER+16,get(o,ROOTPTR))
        put(o,HEADER+24,get(o,PID))
        put(o,HEADER+144,2)
        put(o,HEADER+152,1)
        put(o,HEADER+256,word(s,16))
        as_mode=get(o,OP)==1 or get(o,OP)==5
        put(o,HEADER+408,choose(as_mode,1,0))
        put(o,HEADER+416,word(s,72))
        put(o,HEADER+432,choose(get(o,OP)>=4,1,0))
        return system(o,4,318,3,HEADER+128,16,0,0,0,0)
    if phase==4:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return system(o,4,318,3,HEADER+128,16,0,0,0,0)
        if raw!=16:
            return failure(o,1,107)
        if get(o,HEADER+128)==0 and get(o,HEADER+136)==0:
            return system(o,4,318,3,HEADER+128,16,0,0,0,0)
        if get(o,HEADER+432)!=0:
            return again(o,12)
        value_packet(o,5)
        copy_input(s,24,o,RQ+24,24)
        return value(o,w,10)
    if phase==10:
        if value_ok(o)==False:
            return value_failure(o)
        within(o,HEADER+264,CHILD+24,24)
        return again(o,12)
    if phase==12:
        if word(s,48)==0 and word(s,56)==0 and word(s,64)==0:
            return again(o,20)
        value_packet(o,5)
        copy_input(s,48,o,RQ+24,24)
        return value(o,w,13)
    if phase==13:
        if value_ok(o)==False:
            return value_failure(o)
        within(o,HEADER+288,CHILD+24,24)
        return again(o,20)
    if phase==20:
        if get(o,HEADER+432)==0:
            return lock(o,100)
        n=word(s,80)
        put(o,NINPUT,n)
        if n==0:
            return lock(o,100)
        if n>(MAX-128)//48:
            return failure(o,3,103)
        return allocate(o,21,128+n*48)
    if phase==21:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,HEADER+384,ptr)
        put(o,HEADER+392,get(o,NINPUT))
        put(o,INDEX,0)
        return again(o,50)
    return failure(o,1,107)

def list_capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==50:
        if get(o,INDEX)==get(o,NINPUT):
            return lock(o,100)
        public_packet(o,5)
        copy_input(s,192+get(o,INDEX)*48,o,RQ+16,48)
        return public(o,w,51)
    if phase==51:
        if public_ok(o)==False:
            return public_failure(o)
        if get(o,CHILD+16)!=2:
            return failure(o,1,107)
        within(o,ROW,CHILD+24,48)
        put(o,TEMPHELD,1)
        return memory(o,52,3,ROW,0,get(o,HEADER+384)+128+get(o,INDEX)*48,48)
    if phase==52:
        put(o,TEMPHELD,0)
        put(o,INDEX,get(o,INDEX)+1)
        put(o,HEADER+400,get(o,INDEX))
        return again(o,50)
    return failure(o,1,107)

def publish(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(w,24)!=0:
            return failure(o,1,107)
        put(o,HEADER+8,get(w,48))
        if get(o,HEADER+408)!=0:
            put(o,HEADER+152,0)
        return memory(o,101,3,HEADER,0,get(o,NODE),512)
    if phase==101:
        put(w,48,get(o,NODE))
        put(o,REGISTERED,1)
        if get(o,HEADER+408)!=0:
            return unlock(o,980)
        return unlock(o,300)
    if phase==120:
        return memory(o,121,3,HEADER+256,0,get(o,NODE)+256,256)
    if phase==121:
        return write_pointer(o,122,get(o,NODE)+152,0)
    if phase==122:
        return unlock(o,981)
    return failure(o,1,107)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        put(o,CURSOR,get(w,48))
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
            put(o,CURSOR,get(o,HEADER+8))
            return again(o,201)
        if get(o,HEADER+128)!=word(s,24) or get(o,HEADER+136)!=word(s,32) or get(o,HEADER+144)!=2:
            put(o,ERROR,1)
            put(o,CLASS,102)
            return unlock(o,997)
        if get(o,HEADER+152)!=0:
            put(o,ERROR,1)
            put(o,CLASS,105)
            put(o,DETAIL,2)
            return unlock(o,997)
        return memory(o,203,0,get(o,CURSOR)+256,3,HEADER+256,256)
    if phase==203:
        if get(o,HEADER+408)!=1:
            put(o,ERROR,1)
            put(o,CLASS,102)
            return unlock(o,997)
        put(o,NODE,get(o,CURSOR))
        put(o,REGISTERED,1)
        put(o,HEADER+152,1)
        return write_pointer(o,204,get(o,NODE)+152,1)
    if phase==204:
        if get(o,OP)==3:
            put(o,FINISH_KIND,0)
            return unlock(o,1000)
        if get(o,HEADER+424)==2:
            return unlock(o,450)
        if get(o,HEADER+424)!=0:
            return failure(o,1,107)
        return unlock(o,250)
    if phase==250:
        return failure(o,1,107)
    return failure(o,1,107)

def enumeration(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==250:
        array_packet(o,1)
        within(o,RQ+32,HEADER+288,24)
        return array(o,251,3,RQ,128)
    if phase==251:
        if array_ok(o)==False:
            return array_failure(o)
        if get(o,CHILD+16)!=2:
            return failure(o,1,107)
        within(o,HEADER+360,CHILD+24,24)
        return again(o,300)
    if phase==300:
        put(o,HEADER+424,1)
        if get(o,HEADER+432)!=0:
            return again(o,400)
        iterator_packet(o,0,HEADER+264)
        return iterator(o,w,301)
    if phase==301:
        if iterator_ok(o)==False:
            return iterator_failure(o,w,False)
        if get(o,CHILD+16)!=1 or get(o,CHILD+24)==0:
            return failure(o,1,107)
        within(o,HEADER+312,CHILD+24,24)
        return again(o,310)
    if phase==310:
        iterator_packet(o,1,HEADER+312)
        return iterator(o,w,311)
    if phase==311:
        if get(o,FEEDBACK)==0 and get(o,CHILD)==ITERREP and get(o,CHILD+8)==3:
            return again(o,330)
        if iterator_ok(o)==False:
            return iterator_failure(o,w,True)
        if get(o,CHILD+16)!=2 or get(o,CHILD+48)==0:
            return failure(o,1,107)
        within(o,ROW,CHILD+24,48)
        put(o,TEMPHELD,1)
        return again(o,350)
    if phase==330:
        value_packet(o,6)
        within(o,RQ+24,HEADER+312,24)
        zero(o,HEADER+312,24)
        return value(o,w,331)
    if phase==331:
        if value_ok(o)==False:
            return value_failure(o)
        if get(o,HEADER+264)==0:
            return again(o,400)
        value_packet(o,6)
        within(o,RQ+24,HEADER+264,24)
        zero(o,HEADER+264,24)
        return value(o,w,332)
    if phase==332:
        if value_ok(o)==False:
            return value_failure(o)
        return again(o,400)
    if phase==333:
        if value_ok(o)==False:
            return value_failure(o)
        return again(o,330)
    return failure(o,1,107)

def collecting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==350:
        n=get(o,HEADER+400)
        capacity=get(o,HEADER+392)
        if n<capacity:
            return memory(o,360,3,ROW,0,get(o,HEADER+384)+128+n*48,48)
        if n!=capacity or capacity>(MAX-128)//96:
            return failure(o,3,103)
        newer=choose(capacity==0,8,capacity*2)
        put(o,OLDCAP,newer)
        return allocate(o,351,128+newer*48)
    if phase==351:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return failure(o,3,103)
        put(o,NEWVEC,ptr)
        if get(o,HEADER+400)==0:
            return again(o,353)
        return memory(o,353,0,get(o,HEADER+384)+128,0,ptr+128,get(o,HEADER+400)*48)
    if phase==353:
        put(o,OLDBUF,get(o,HEADER+384))
        put(o,HEADER+384,get(o,NEWVEC))
        put(o,HEADER+392,get(o,OLDCAP))
        put(o,NEWVEC,0)
        return deallocate(o,354,get(o,OLDBUF))
    if phase==354:
        put(o,OLDBUF,0)
        return again(o,350)
    if phase==360:
        put(o,TEMPHELD,0)
        put(o,HEADER+400,get(o,HEADER+400)+1)
        return again(o,310)
    if phase==400:
        n=get(o,HEADER+400)
        array_packet(o,choose(get(o,HEADER+408)==0,0,1))
        put(o,RQ+16,n)
        if get(o,HEADER+408)==0:
            put(o,RQ+24,get(o,HEADER+416))
            within(o,RQ+32,HEADER+288,24)
        else:
            put(o,RQ,ARRAY2)
            within(o,RQ+32,HEADER+360,24)
        if get(o,HEADER+384)==0:
            return array(o,402,3,RQ,128)
        return memory(o,401,3,RQ,0,get(o,HEADER+384),128)
    if phase==401:
        return array(o,402,0,get(o,HEADER+384),128+get(o,HEADER+400)*48)
    if phase==402:
        if array_ok(o)==False:
            return array_failure(o)
        if get(o,HEADER+408)==0:
            if get(o,CHILD+16)!=1:
                return failure(o,1,107)
            within(o,SAVED,CHILD,128)
            put(o,FINISH_KIND,1)
            return again(o,1000)
        if get(o,CHILD+16)!=2:
            return failure(o,1,107)
        within(o,HEADER+336,CHILD+24,24)
        put(o,HEADER+424,2)
        put(o,VECTOR_AFTER,430)
        put(o,INDEX,0)
        return again(o,550)
    if phase==430:
        if get(o,HEADER+360)==0:
            return again(o,450)
        array_packet(o,4)
        within(o,RQ+16,HEADER+360,24)
        zero(o,HEADER+360,24)
        return array(o,431,3,RQ,128)
    if phase==431:
        if array_ok(o)==False:
            return array_failure(o)
        return again(o,450)
    return failure(o,1,107)

def arrays(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==450:
        array_packet(o,2)
        within(o,RQ+16,HEADER+336,24)
        return array(o,451,3,RQ,128)
    if phase==451:
        if array_ok(o)==False:
            zero(o,HEADER+336,24)
            return array_failure(o)
        kind=get(o,CHILD+16)
        if kind==4:
            zero(o,HEADER+336,24)
            put(o,FINISH_KIND,4)
            return again(o,1000)
        if kind!=3:
            return failure(o,1,107)
        within(o,SAVED,CHILD,128)
        return lock(o,120)
    return failure(o,1,107)

def collection_release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==550:
        if get(o,INDEX)==get(o,HEADER+400):
            return again(o,554)
        return memory(o,551,0,get(o,HEADER+384)+128+get(o,INDEX)*48,3,ROW,48)
    if phase==551:
        if get(o,ROW+24)==0:
            put(o,INDEX,get(o,INDEX)+1)
            return again(o,550)
        public_packet(o,6)
        within(o,RQ+16,ROW,48)
        return public(o,w,552)
    if phase==552:
        if public_ok(o)==False:
            put(o,CLEANFAIL,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,550)
    if phase==554:
        put(o,HEADER+400,0)
        return deallocate(o,555,get(o,HEADER+384))
    if phase==555:
        put(o,HEADER+384,0)
        put(o,HEADER+392,0)
        return again(o,get(o,VECTOR_AFTER))
    return failure(o,1,107)

def retaining(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==650:
        value_packet(o,4)
        return value(o,w,651)
    if phase==651:
        if value_ok(o)==False:
            return wrapper_failure(o)
        within(o,WRAPPER,CHILD+24,24)
        put(o,WRAPI,0)
        return again(o,652)
    if phase==652:
        i=get(o,WRAPI)
        if i==5:
            value_packet(o,6)
            within(o,RQ+24,ERRCAP,24)
            return value(o,w,680)
        value_packet(o,2)
        n=literal(o,RQ+128,i)
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_n(o,w,653,128+n)
    if phase==653:
        if value_ok(o)==False:
            return wrapper_failure(o)
        within(o,KEYCAP,CHILD+24,24)
        i=get(o,WRAPI)
        if i==2 or i==3:
            return again(o,660)
        value_packet(o,2)
        if i==4:
            put(o,RQ+104,1)
            put(o,RQ+112,1)
            return value(o,w,654)
        n=literal(o,RQ+128,choose(i==0,5,6))
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_n(o,w,654,128+n)
    if phase==654:
        if value_ok(o)==False:
            return wrapper_failure(o)
        within(o,VALCAP,CHILD+24,24)
        return again(o,660)
    if phase==660:
        value_packet(o,10)
        within(o,RQ+24,WRAPPER,24)
        within(o,RQ+48,KEYCAP,24)
        i=get(o,WRAPI)
        if i==2 or i==3:
            within(o,RQ+72,ERRCAP,24)
        else:
            within(o,RQ+72,VALCAP,24)
        return value(o,w,661)
    if phase==661:
        if value_ok(o)==False:
            return wrapper_failure(o)
        value_packet(o,6)
        within(o,RQ+24,KEYCAP,24)
        zero(o,KEYCAP,24)
        return value(o,w,662)
    if phase==662:
        if value_ok(o)==False:
            return wrapper_failure(o)
        if get(o,VALCAP)==0:
            return again(o,664)
        value_packet(o,6)
        within(o,RQ+24,VALCAP,24)
        zero(o,VALCAP,24)
        return value(o,w,663)
    if phase==663:
        if value_ok(o)==False:
            return wrapper_failure(o)
        return again(o,664)
    if phase==664:
        put(o,WRAPI,get(o,WRAPI)+1)
        return again(o,652)
    if phase==680:
        zero(o,ERRCAP,24)
        if value_ok(o)==False:
            return wrapper_failure(o)
        within(o,ERRCAP,WRAPPER,24)
        zero(o,WRAPPER,24)
        return failure(o,1,200)
    return failure(o,1,107)

def wrapper_failure(o:mutbuf) -> u32:
    within(o,DISCARD,ERRCAP,24)
    zero(o,ERRCAP,24)
    return value_failure(o)


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
            put(o,CLEANFAIL,1)
        return again(o,get(o,NEXTUNLOCK))
    if phase==980:
        zero(o,0,128)
        put(o,0,REP)
        put(o,16,2)
        put(o,24,get(o,NODE))
        put(o,32,get(o,HEADER+128))
        put(o,40,get(o,HEADER+136))
        return 0
    if phase==981:
        within(o,0,SAVED,128)
        put(o,0,REP)
        put(o,112,get(o,CONSUMED))
        put(o,120,get(o,CLEANFAIL))
        return 0
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
            put(o,CLEANFAIL,1)
            return unlock(o,997)
        return memory(o,1002,0,get(o,CURSOR),3,RQ,256)
    if phase==1002:
        if get(o,CURSOR)!=get(o,NODE):
            put(o,PREV,get(o,CURSOR))
            put(o,CURSOR,get(o,RQ+8))
            return again(o,1001)
        if get(o,PREV)==0:
            put(w,48,get(o,RQ+8))
            return again(o,1003)
        return write_pointer(o,1003,get(o,PREV)+8,get(o,RQ+8))
    if phase==1003:
        put(o,REGISTERED,0)
        return unlock(o,1010)
    if phase==1010:
        if get(o,HEADER+336)==0:
            return again(o,1012)
        array_packet(o,4)
        within(o,RQ+16,HEADER+336,24)
        zero(o,HEADER+336,24)
        return array(o,1011,3,RQ,128)
    if phase==1011:
        if array_ok(o)==False:
            put(o,CLEANFAIL,1)
        return again(o,1012)
    if phase==1012:
        if get(o,HEADER+360)==0:
            return again(o,1014)
        array_packet(o,4)
        within(o,RQ+16,HEADER+360,24)
        zero(o,HEADER+360,24)
        return array(o,1013,3,RQ,128)
    if phase==1013:
        if array_ok(o)==False:
            put(o,CLEANFAIL,1)
        return again(o,1014)
    if phase==1014:
        if get(o,TEMPHELD)==0:
            return again(o,1020)
        put(o,TEMPHELD,0)
        public_packet(o,6)
        within(o,RQ+16,ROW,48)
        return public(o,w,1015)
    if phase==1015:
        if public_ok(o)==False:
            put(o,CLEANFAIL,1)
        return again(o,1020)
    if phase==1020:
        put(o,INDEX,0)
        put(o,VECTOR_AFTER,1030)
        return again(o,550)
    if phase==1030:
        put(o,RELEASE_STEP,0)
        return again(o,1031)
    if phase==1031:
        step=get(o,RELEASE_STEP)
        if step==7:
            return again(o,1050)
        at=choose(step==0,HEADER+312,choose(step==1,HEADER+264,HEADER+288))
        if step>=3:
            at=WRAPPER+(step-3)*24
        if get(o,at)==0:
            put(o,RELEASE_STEP,step+1)
            return again(o,1031)
        value_packet(o,6)
        within(o,RQ+24,at,24)
        zero(o,at,24)
        return value(o,w,1032)
    if phase==1032:
        if value_ok(o)==False:
            put(o,CLEANFAIL,1)
        put(o,RELEASE_STEP,get(o,RELEASE_STEP)+1)
        return again(o,1031)
    if phase==1050:
        return deallocate(o,1051,get(o,NEWVEC))
    if phase==1051:
        put(o,NEWVEC,0)
        return deallocate(o,1052,get(o,NODE))
    if phase==1052:
        if get(o,OP)==2 or get(o,OP)==3:
            put(o,CONSUMED,1)
        put(o,NODE,0)
        if get(o,ERROR)!=0:
            return reply_error(o,get(o,ERROR),get(o,CLASS))
        kind=get(o,FINISH_KIND)
        if kind==1:
            within(o,0,SAVED,128)
            put(o,0,REP)
            put(o,112,get(o,CONSUMED))
            put(o,120,get(o,CLEANFAIL))
            return 0
        zero(o,0,128)
        put(o,0,REP)
        put(o,16,kind)
        put(o,112,get(o,CONSUMED))
        put(o,120,get(o,CLEANFAIL))
        return 0
    return reply_error(o,1,107)

def reply_error(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REP)
    put(o,8,status)
    put(o,16,kind)
    within(o,72,ERRCAP,24)
    put(o,96,get(o,DETAIL))
    put(o,104,get(o,TOTAL))
    put(o,112,get(o,CONSUMED))
    put(o,120,get(o,CLEANFAIL))
    return 0

def failure(o:mutbuf,status:u64,kind:u64) -> u32:
    put(o,ERROR,status)
    put(o,CLASS,kind)
    return again(o,1000)

def public_failure(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=PUBLICREP:
        return failure(o,1,107)
    if get(o,CHILD+16)==200:
        within(o,ERRCAP,CHILD+72,24)
    put(o,DETAIL,get(o,CHILD+96))
    put(o,TOTAL,get(o,CHILD+104))
    return failure(o,get(o,CHILD+8),get(o,CHILD+16))

def array_failure(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=ARRAYREP:
        return failure(o,1,107)
    if get(o,CHILD+16)==200:
        within(o,ERRCAP,CHILD+72,24)
    put(o,DETAIL,get(o,CHILD+96))
    put(o,TOTAL,get(o,CHILD+104))
    return failure(o,get(o,CHILD+8),get(o,CHILD+16))

def value_failure(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=VALUEREP:
        return failure(o,1,107)
    if get(o,CHILD+8)==5:
        return failure(o,3,103)
    return failure(o,1,107)

def iterator_failure(o:mutbuf,w:mutbuf,next_call:bool) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=ITERREP:
        return failure(o,1,107)
    status=get(o,CHILD+8)
    if status==4:
        if get(o,CHILD+16)!=200 or get(o,CHILD+24)==0:
            return failure(o,1,107)
        within(o,ERRCAP,CHILD+24,24)
        if next_call:
            value_packet(o,6)
            within(o,RQ+24,ERRCAP,24)
            zero(o,ERRCAP,24)
            return value(o,w,333)
        if get(o,HEADER+408)==0:
            return failure(o,1,200)
        return again(o,650)
    if status!=1 and status!=2:
        return failure(o,1,107)
    kind=get(o,CHILD+16)
    if kind>=100 and kind<=107 and status==1 and get(o,CHILD+24)==0 and get(o,CHILD+32)==0 and get(o,CHILD+40)==0:
        put(o,DETAIL,get(o,CHILD+96))
        return failure(o,status,kind)
    if kind!=200 or get(o,CHILD+24)==0:
        return failure(o,1,107)
    within(o,ERRCAP,CHILD+24,24)
    return failure(o,status,200)

def public_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==PUBLICREP and get(o,CHILD+8)==0
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==VALUEREP and get(o,CHILD+8)==0
def array_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==ARRAYREP and get(o,CHILD+8)==0
def iterator_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==ITERREP and get(o,CHILD+8)==0

def literal(o:mutbuf,at:u64,which:u64) -> u64:
    if which==0:
        store(o,at+0,99)
        store(o,at+1,108)
        store(o,at+2,97)
        store(o,at+3,115)
        store(o,at+4,115)
        return 5
    if which==1:
        store(o,at+0,109)
        store(o,at+1,101)
        store(o,at+2,115)
        store(o,at+3,115)
        store(o,at+4,97)
        store(o,at+5,103)
        store(o,at+6,101)
        return 7
    if which==2:
        put(o,at+0,6874027354233200479)
        store(o,at+8,95)
        return 9
    if which==3:
        put(o,at+0,8675468274863136607)
        store(o,at+8,116)
        store(o,at+9,95)
        store(o,at+10,95)
        return 11
    if which==4:
        put(o,at+0,7310028773484879711)
        put(o,at+8,7310589519816782707)
        store(o,at+16,120)
        store(o,at+17,116)
        store(o,at+18,95)
        store(o,at+19,95)
        return 20
    if which==5:
        put(o,at+0,5000523260957193554)
        store(o,at+8,114)
        store(o,at+9,114)
        store(o,at+10,111)
        store(o,at+11,114)
        return 12
    if which==6:
        put(o,at+0,8031151179464336743)
        put(o,at+8,7234315272884199538)
        put(o,at+16,7310548842384216864)
        store(o,at+24,114)
        store(o,at+25,97)
        store(o,at+26,116)
        store(o,at+27,105)
        store(o,at+28,111)
        store(o,at+29,110)
        return 30
    return 0

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
def array_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,ARRAY)
    put(o,RQ+8,op)
    return 0
def iterator_packet(o:mutbuf,op:u64,at:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,ITER)
    put(o,RQ+8,op)
    within(o,RQ+16,at,24)
    return 0

def public(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,88),RQ,192,CHILD,65536,get(o,ROOTPTR),256)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,CHILD,65536,get(w,112),get(w,120))
def value_n(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,n,CHILD,65536,get(w,112),get(w,120))

def iterator(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(o,HEADER+256),RQ,192,CHILD,8192,get(o,ROOTPTR),256)
def array(o:mutbuf,next:u64,selector:u64,ptr:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,selector)
    put(o,8,ptr)
    put(o,16,n)
    return 11
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
def program():return document(source_program(),'background_optimizer_future_public_observers_iterable')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers_iterable.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),max(len(f['blocks'])for f in d['functions']))
if __name__=='__main__':main()
