"""Fixed BG-to-runtime provider. HIA owns admission, locks and all lifetimes.
The mechanical adapter only executes declared effects and fixed role calls.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={
'REQUEST':int.from_bytes(b'HIAMVBQ1','little'),'CONTROL':int.from_bytes(b'HIAMVBC1','little'),
'REPLY':int.from_bytes(b'HIAMVBO1','little'),'STATE':int.from_bytes(b'HIAMBPC1','little'),
'HREQMAG':int.from_bytes(b'HIAMVHQ1','little'),'HREPMAG':int.from_bytes(b'HIAMVHR1','little'),
'PREQMAG':int.from_bytes(b'HIABPY01','little'),'PREPMAG':int.from_bytes(b'HIABPYR1','little'),
'EXMAG':int.from_bytes(b'HIAMVEX3','little'),'TIMED_EXMAG':int.from_bytes(b'HIAMVEX4','little'),'EXREPLY':int.from_bytes(b'HIAMVER1','little'),
'INFORMATION':int.from_bytes(b'HIAMVIR2','little'),'BGSNAP':int.from_bytes(b'HIAMVBS1','little'),
'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'CHILD_BYTES':96<<20,
'PH':128,'FB':136,'OP':144,'FAMILY':152,'STATUS':160,'KIND':168,'COMMITTED':176,
'LOCK_NEXT':184,'HELD':192,'ACTIVE':200,'PIN':208,'PACKET':216,'PACKET_N':224,
'OWNED':232,'OWNED_N':240,'DATA':248,'DATA_N':256,
'CLONE':264,'OBJ':288,'CHILD':296,'ERROR':304,'PID':312,'HAVE_CLONE':320,
'CAPTURE':328,'FD0':336,'FD1':344,'HANDLE_ACTION':352,'PAY_ACTION':360,
'RETURN_CAP':368,'RETURN_N':392,'RETURN_POINTER':400,'DROP_RESULT':408,
'STARTED':464,'CLOCK':704,'NEXT':416,'TEMP':424,'OP_RC':432,'SAVE_STATUS':440,'SAVE_KIND':448,
'PIN_ROW':512,'NEIGHBOR':576,'TIMEOUT':672,'HREQ':1024,'RBUF':1536,
'POUT':2048,'SMALL':2688,'FRAME_HEADER':2816,
}
SOURCE=r'''
def multiversion_background_runtime(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<4096 or length(w)<1024:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return start(s,o,w,phase)
    if phase<200:
        return lock_step(s,o,w,phase)
    if phase<300:
        return dispatch(s,o,w,phase)
    if phase<400:
        return handle_step(s,o,w,phase)
    if phase<500:
        return effect_step(s,o,w,phase)
    if phase<600:
        return payload_step(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128:
        return 4294967293
    magic=word(s,0)
    op=word(s,8)
    family=0
    if magic==CONTROL:
        family=1
        if op>2:
            return 4294967293
        n=word(s,72)
        if n!=length(s)-128:
            return 4294967293
        at=16
        while at<128:
            if at!=72 and word(s,at)!=0:
                return 4294967293
            at=at+8
        if op==1:
            if n<256 or n>20971520 or word(s,128)!=EXMAG or word(s,136)!=0:
                return 4294967293
        elif n!=0:
            return 4294967293
    elif magic==REQUEST:
        if op==0 or op>5:
            return 4294967293
        if op==2:
            gn=word(s,56)
            en=word(s,64)
            raw=word(s,72)
            measure=word(s,80)
            if gn==0 or en==0 or raw>8388608 or measure>8388608 or word(s,88)>=9223372036854775808:
                return 4294967293
            if word(s,40)==0 or word(s,48)!=512 or word(s,104)>1 or word(s,112)!=0 or word(s,120)!=0:
                return 4294967293
            if word(s,104)==0 and measure!=0:
                return 4294967293
            remain=length(s)-128
            if gn>remain or en>remain-gn or raw>remain-gn-en or measure!=remain-gn-en-raw:
                return 4294967293
            if length(s)>NONE-128:
                return 4294967293
        else:
            if length(s)!=128:
                return 4294967293
            start=40
            if op==5:
                start=64
            while start<128:
                if word(s,start)!=0:
                    return 4294967293
                start=start+8
    else:
        return 4294967293
    zero(o,128,3968)
    put(o,OP,op)
    put(o,FAMILY,family)
    put(o,FD0,NONE)
    put(o,FD1,NONE)
    put(o,KIND,4)
    return system(o,10,228,12,1,CLOCK,0,0,0,0)

def start(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if get(o,FB)==NONE-3:
            return system(o,10,228,12,1,CLOCK,0,0,0,0)
        if get(o,FB)!=0 or get(o,CLOCK)>18446744073 or get(o,CLOCK+8)>=1000000000:
            return fail(o,3)
        now=get(o,CLOCK)*1000000000
        if get(o,CLOCK+8)>NONE-now:
            return fail(o,3)
        put(o,STARTED,now+get(o,CLOCK+8))
        if get(o,FAMILY)==0 and get(o,OP)==2:
            if decimal(s,128,word(s,56))==0 or decimal(s,128+word(s,56),word(s,64))==0:
                return 4294967293
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        pid=get(o,FB)
        if pid==0 or pid>=NEGATIVE:
            return fail(o,3)
        put(o,PID,pid)
        return address(o,2,3,PIN_ROW)
    if phase==2:
        put(o,PIN,get(o,FB))
        return allocate(o,3,CHILD_BYTES)
    if phase==3:
        if get(o,FB)==0:
            return fail(o,2)
        put(o,CHILD,get(o,FB))
        return lock(o,110)
    return fail(o,3)

def lock(o:mutbuf,next:u64) -> u32:
    put(o,LOCK_NEXT,next)
    return atom(o,100,2,0,1)

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,LOCK_NEXT,next)
    put(o,HELD,0)
    return atom(o,102,3,0,0)

def lock_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FB)==0:
            put(o,HELD,1)
            return again(o,get(o,LOCK_NEXT))
        put(o,TIMEOUT,0)
        put(o,TIMEOUT+8,1000000)
        return system(o,101,202,193,24,128,1,TIMEOUT,0,0)
    if phase==101:
        return atom(o,100,2,0,1)
    if phase==102:
        return system(o,103,202,1,24,129,2147483647,0,0,0)
    if phase==103:
        return again(o,get(o,LOCK_NEXT))
    if phase==110:
        op=get(o,OP)
        family=get(o,FAMILY)
        if family==1 and op==0:
            if get(w,0)!=0:
                return fail(o,3)
            zero(w,32,992)
            put(w,0,STATE)
            put(w,8,get(o,PID))
            put(w,16,2)
        elif get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=0:
            return fail(o,3)
        if family==1 and op==2:
            if get(w,32)!=0 or get(w,256+16)!=0 or get(w,256+40)!=0 or get(w,256+64)!=0 or get(w,512+16)!=0:
                return fail(o,3)
            put(w,16,2)
        zero(o,PIN_ROW,64)
        put(o,PIN_ROW,get(o,PID))
        put(o,PIN_ROW+24,get(w,32))
        if get(w,32)!=0:
            return write_pointer(o,111,get(w,32)+16,get(o,PIN))
        return again(o,111)
    if phase==111:
        put(w,32,get(o,PIN))
        put(o,ACTIVE,1)
        return unlock(o,200)
    return fail(o,3)

def dispatch(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        family=get(o,FAMILY)
        op=get(o,OP)
        if family==1:
            if op==0:
                handles_request(o,0)
                return handles(o,210)
            if op==2:
                handles_request(o,5)
                return handles(o,212)
            n=word(s,72)
            put(o,PACKET_N,128+n)
            return allocate(o,220,128+n)
        if op==5:
            payload_request(o,3)
            put(o,HREQ+24,word(s,40))
            put(o,HREQ+32,word(s,48))
            put(o,HREQ+40,word(s,56))
            return payload(o,530)
        handles_request(o,2)
        if op==4:
            handles_request(o,6)
        put(o,HREQ+24,word(s,16))
        put(o,HREQ+32,word(s,24))
        put(o,HREQ+40,word(s,32))
        put(o,HANDLE_ACTION,op)
        return handles(o,300)
    if phase==210:
        if get(o,FB)!=0:
            return fail(o,3)
        return memory(o,211,0,get(o,CHILD),3,RBUF,128)
    if phase==211:
        if get(o,RBUF)!=HREPMAG or get(o,RBUF+8)!=0:
            return fail(o,3)
        payload_request(o,0)
        return payload(o,214)
    if phase==212:
        if get(o,FB)!=0:
            return fail(o,3)
        return memory(o,213,0,get(o,CHILD),3,RBUF,128)
    if phase==213:
        if get(o,RBUF)!=HREPMAG or get(o,RBUF+8)!=0:
            return fail(o,3)
        payload_request(o,5)
        return payload(o,215)
    if phase==214 or phase==215:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG or get(o,POUT+8)!=0:
            return fail(o,3)
        put(w,16,choose(phase==214,0,1))
        return fail(o,0)
    if phase==220:
        if get(o,FB)==0:
            return fail(o,2)
        put(o,PACKET,get(o,FB))
        handles_request(o,1)
        put(o,HREQ+72,word(s,72))
        return memory(o,221,3,HREQ,0,get(o,PACKET),128)
    if phase==221:
        return memory(o,222,2,128,0,get(o,PACKET)+128,word(s,72))
    if phase==222:
        return role(o,223,12,0,get(o,PACKET),get(o,PACKET_N),0,get(o,CHILD),CHILD_BYTES,1,256,256)
    if phase==223:
        if get(o,FB)!=0:
            return fail(o,3)
        return memory(o,224,0,get(o,CHILD),3,RBUF,128)
    if phase==224:
        if get(o,RBUF)!=HREPMAG:
            return fail(o,3)
        if get(o,RBUF+24)!=0:
            within(o,RBUF+24,RETURN_CAP,24)
            put(o,KIND,3)
        status=0
        if get(o,RBUF+8)!=0:
            status=choose(get(o,RBUF+8)==4,2,3)
        elif get(o,RBUF+16)!=1 or get(o,RBUF+24)==0:
            status=3
        put(o,SAVE_STATUS,status)
        if get(o,RBUF+56)!=0:
            at=get(o,RBUF+56)
            if at>CHILD_BYTES or 160>CHILD_BYTES-at or get(o,RBUF+64)<160:
                return fail(o,3)
            return memory(o,225,0,get(o,CHILD)+at,3,RBUF,160)
        return fail(o,status)
    if phase==225:
        if get(o,RBUF)!=EXREPLY:
            return fail(o,3)
        put(o,FD0,get(o,RBUF+96))
        put(o,FD1,get(o,RBUF+104))
        put(o,OWNED,get(o,RBUF+144))
        put(o,OWNED_N,get(o,RBUF+152))
        return fail(o,get(o,SAVE_STATUS))
    return fail(o,3)

def handle_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,FB)!=0:
            return fail(o,3)
        return memory(o,301,0,get(o,CHILD),3,RBUF,128)
    if phase==301:
        if get(o,RBUF)!=HREPMAG:
            return fail(o,3)
        if get(o,RBUF+8)!=0:
            return fail(o,choose(get(o,RBUF+8)==4,2,3))
        op=get(o,HANDLE_ACTION)
        if op==4:
            if get(o,RBUF+16)!=1:
                return fail(o,3)
            handles_request(o,3)
            put(o,HREQ+24,word(s,16))
            put(o,HREQ+32,word(s,24))
            put(o,HREQ+40,word(s,32))
            return handles(o,310)
        if get(o,RBUF+24)==0:
            return fail(o,3)
        within(o,RBUF+24,CLONE,24)
        put(o,HAVE_CLONE,1)
        if get(o,RBUF+16)!=1:
            return fail(o,3)
        if op==3:
            within(o,CLONE,RETURN_CAP,24)
            put(o,HAVE_CLONE,0)
            put(o,KIND,3)
            return fail(o,0)
        return memory(o,302,0,get(o,CLONE)+8,3,OBJ,8)
    if phase==302:
        if get(o,OBJ)==0:
            return fail(o,3)
        n=256
        if get(o,OP)==2:
            n=length(s)+128
        put(o,PACKET_N,n)
        return allocate(o,303,n)
    if phase==303:
        if get(o,FB)==0:
            return fail(o,2)
        put(o,PACKET,get(o,FB))
        zero(o,FRAME_HEADER,256)
        put(o,FRAME_HEADER,EXMAG)
        put(o,FRAME_HEADER+8,14)
        put(o,FRAME_HEADER+72,NONE)
        if get(o,OP)==2:
            put(o,FRAME_HEADER,TIMED_EXMAG)
            put(o,FRAME_HEADER+216,get(o,STARTED))
            put(o,FRAME_HEADER+8,2)
            put(o,FRAME_HEADER+56,word(s,88))
            put(o,FRAME_HEADER+64,word(s,40))
            put(o,FRAME_HEADER+72,word(s,96))
            put(o,FRAME_HEADER+80,word(s,72))
            put(o,FRAME_HEADER+112,word(s,80))
            put(o,FRAME_HEADER+120,word(s,104))
            put(o,FRAME_HEADER+224,word(s,56))
            put(o,FRAME_HEADER+232,word(s,64))
        return memory(o,304,3,FRAME_HEADER,0,get(o,PACKET),256)
    if phase==304:
        if get(o,OP)==1:
            return again(o,400)
        gn=word(s,56)
        en=word(s,64)
        raw=word(s,72)
        measure=word(s,80)
        return memory(o,305,2,128+gn+en,0,get(o,PACKET)+256,raw+measure)
    if phase==305:
        return memory(o,400,2,128,0,get(o,PACKET)+256+word(s,72)+word(s,80),word(s,56)+word(s,64))
    if phase==310:
        if get(o,FB)!=0:
            return fail(o,3)
        return memory(o,311,0,get(o,CHILD),3,RBUF,128)
    if phase==311:
        if get(o,RBUF)!=HREPMAG or get(o,RBUF+8)!=0:
            return fail(o,3)
        return fail(o,0)
    return fail(o,3)

def effect_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        return role(o,401,14,0,get(o,PACKET),get(o,PACKET_N),0,get(o,CHILD),41943040,0,get(o,OBJ)+256,131072)
    if phase==401:
        put(o,OP_RC,get(o,FB))
        return memory(o,402,0,get(o,CHILD),3,RBUF,160)
    if phase==402:
        if get(o,RBUF)!=EXREPLY:
            return fail(o,3)
        put(o,COMMITTED,get(o,RBUF+24))
        put(o,FD0,get(o,RBUF+96))
        put(o,FD1,get(o,RBUF+104))
        put(o,OWNED,get(o,RBUF+144))
        put(o,OWNED_N,get(o,RBUF+152))
        if get(o,OP_RC)!=get(o,RBUF+8):
            return fail(o,3)
        if get(o,RBUF+8)!=0:
            put(o,ERROR,get(o,RBUF+8))
            return error_payload(o)
        if get(o,OWNED)==0 or get(o,OWNED_N)==0:
            return fail(o,3)
        put(o,KIND,choose(get(o,OP)==1,1,2))
        if get(o,OP)==1:
            if get(o,OWNED_N)<256:
                return fail(o,3)
            return memory(o,403,0,get(o,OWNED),3,SMALL,256)
        if get(o,OWNED_N)<32:
            return fail(o,3)
        return memory(o,404,0,get(o,OWNED),3,SMALL,32)
    if phase==403:
        if get(o,SMALL)!=BGSNAP or get(o,SMALL+8)!=0 or get(o,SMALL+40)!=get(o,OWNED_N):
            return fail(o,3)
        put(o,DATA,get(o,OWNED))
        put(o,DATA_N,get(o,OWNED_N))
        return again(o,500)
    if phase==404:
        if get(o,SMALL)!=INFORMATION or get(o,SMALL+8)!=1 or get(o,SMALL+16)!=0 or get(o,SMALL+24)!=get(o,OWNED_N)-32:
            return fail(o,3)
        put(o,DATA,get(o,OWNED)+32)
        put(o,DATA_N,get(o,OWNED_N)-32)
        return again(o,500)
    if phase==410:
        put(o,DATA,get(o,FB))
        return again(o,500)
    return fail(o,3)

def payload_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,DATA_N)>NONE-128:
            return fail(o,2)
        if get(o,PACKET)!=0:
            old=get(o,PACKET)
            put(o,PACKET,0)
            return deallocate(o,500,old)
        return allocate(o,501,128+get(o,DATA_N))
    if phase==501:
        if get(o,FB)==0:
            return fail(o,2)
        put(o,PACKET,get(o,FB))
        put(o,PACKET_N,128+get(o,DATA_N))
        payload_request(o,1)
        put(o,HREQ+72,get(o,DATA_N))
        return memory(o,502,3,HREQ,0,get(o,PACKET),128)
    if phase==502:
        return memory(o,503,0,get(o,DATA),0,get(o,PACKET)+128,get(o,DATA_N))
    if phase==503:
        return role(o,504,13,0,get(o,PACKET),get(o,PACKET_N),3,POUT,512,1,512,256)
    if phase==504:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG:
            return fail(o,3)
        if get(o,POUT+8)!=0:
            return fail(o,choose(get(o,POUT+8)==4,2,3))
        if get(o,POUT+16)==0:
            return fail(o,3)
        within(o,POUT+16,RETURN_CAP,24)
        put(o,RETURN_N,get(o,POUT+40))
        put(o,DROP_RESULT,1)
        payload_request(o,6)
        within(o,RETURN_CAP,HREQ+24,24)
        return payload(o,505)
    if phase==505:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG or get(o,POUT+8)!=0 or get(o,POUT+40)!=get(o,RETURN_N) or get(o,POUT+64)==0:
            return fail(o,3)
        put(o,RETURN_POINTER,get(o,POUT+64))
        put(o,DROP_RESULT,0)
        return fail(o,get(o,STATUS))
    if phase==530:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG or get(o,POUT+8)!=0:
            return fail(o,3)
        return fail(o,0)
    return fail(o,3)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,FD0)!=NONE:
            fd=get(o,FD0)
            put(o,FD0,NONE)
            return system(o,900,3,0,fd,0,0,0,0,0)
        if get(o,FD1)!=NONE:
            fd=get(o,FD1)
            put(o,FD1,NONE)
            return system(o,900,3,0,fd,0,0,0,0,0)
        if get(o,PACKET)!=0:
            ptr=get(o,PACKET)
            put(o,PACKET,0)
            return deallocate(o,900,ptr)
        if get(o,OWNED)!=0:
            ptr=get(o,OWNED)
            put(o,OWNED,0)
            return deallocate(o,900,ptr)
        if get(o,DROP_RESULT)!=0:
            put(o,DROP_RESULT,0)
            payload_request(o,3)
            within(o,RETURN_CAP,HREQ+24,24)
            zero(o,RETURN_CAP,24)
            put(o,RETURN_N,0)
            put(o,RETURN_POINTER,0)
            return payload(o,901)
        if get(o,HAVE_CLONE)!=0:
            put(o,HAVE_CLONE,0)
            handles_request(o,3)
            within(o,CLONE,HREQ+24,24)
            return handles(o,902)
        if get(o,ACTIVE)!=0:
            if get(o,HELD)==0:
                return lock(o,910)
            return again(o,910)
        if get(o,HELD)!=0:
            return unlock(o,900)
        if get(o,CHILD)!=0:
            ptr=get(o,CHILD)
            put(o,CHILD,0)
            return deallocate(o,900,ptr)
        return finish(o)
    if phase==901:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG or get(o,POUT+8)!=0:
            put(o,STATUS,3)
        return again(o,900)
    if phase==902:
        if get(o,FB)!=0:
            put(o,STATUS,3)
            return again(o,900)
        return memory(o,903,0,get(o,CHILD),3,RBUF,128)
    if phase==903:
        if get(o,RBUF)!=HREPMAG or get(o,RBUF+8)!=0:
            put(o,STATUS,3)
        return again(o,900)
    if phase==910:
        if get(o,PIN_ROW+16)!=0:
            return write_pointer(o,911,get(o,PIN_ROW+16)+24,get(o,PIN_ROW+24))
        put(w,32,get(o,PIN_ROW+24))
        return again(o,911)
    if phase==911:
        if get(o,PIN_ROW+24)!=0:
            return write_pointer(o,912,get(o,PIN_ROW+24)+16,get(o,PIN_ROW+16))
        return again(o,912)
    if phase==912:
        put(o,ACTIVE,0)
        return unlock(o,900)
    return fail(o,3)

def error_payload(o:mutbuf) -> u32:
    code=get(o,ERROR)
    put(o,STATUS,1)
    put(o,KIND,2)
    size=exception_text(o,SMALL,code)
    if size==0:
        return fail(o,3)
    put(o,DATA_N,size)
    return address(o,410,3,SMALL)

def handles_request(o:mutbuf,op:u64) -> u64:
    zero(o,HREQ,128)
    put(o,HREQ,HREQMAG)
    put(o,HREQ+8,op)
    return 0

def payload_request(o:mutbuf,op:u64) -> u64:
    zero(o,HREQ,128)
    zero(o,POUT,512)
    put(o,HREQ,PREQMAG)
    put(o,HREQ+8,op)
    return 0

def handles(o:mutbuf,next:u64) -> u32:
    return role(o,next,12,3,HREQ,128,0,get(o,CHILD),CHILD_BYTES,1,256,256)

def payload(o:mutbuf,next:u64) -> u32:
    return role(o,next,13,3,HREQ,128,3,POUT,512,1,512,256)

def fail(o:mutbuf,status:u64) -> u32:
    put(o,STATUS,status)
    return again(o,900)

def finish(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,KIND))
    put(o,24,get(o,RETURN_POINTER))
    put(o,32,get(o,RETURN_N))
    within(o,RETURN_CAP,40,24)
    put(o,64,get(o,COMMITTED))
    return 0

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10

def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,n)
    return 6

def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PH,next)
    put(o,0,ptr)
    return 7

def address(o:mutbuf,next:u64,base:u64,at:u64) -> u32:
    put(o,PH,next)
    put(o,0,base)
    put(o,8,at)
    return 4

def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)

def memory(o:mutbuf,next:u64,source:u64,first:u64,target:u64,second:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,source)
    put(o,8,first)
    put(o,16,target)
    put(o,24,second)
    put(o,32,n)
    return 8

def atom(o:mutbuf,next:u64,action:u64,expected:u64,value:u64) -> u32:
    put(o,PH,next)
    put(o,0,24)
    put(o,8,expected)
    put(o,16,value)
    return action

def system(o:mutbuf,next:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,number)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def role(o:mutbuf,next:u64,action:u64,sbase:u64,sat:u64,sn:u64,obase:u64,oat:u64,on:u64,wbase:u64,wat:u64,wn:u64) -> u32:
    put(o,PH,next)
    put(o,0,sbase)
    put(o,8,sat)
    put(o,16,sn)
    put(o,24,obase)
    put(o,32,oat)
    put(o,40,on)
    put(o,48,wbase)
    put(o,56,wat)
    put(o,64,wn)
    return action

def decimal(s:readbuf,at:u64,n:u64) -> u64:
    if n==0 or (n>1 and byte(s,at)==48):
        return 0
    i=0
    while i<n:
        b=byte(s,at+i)
        if b<48 or b>57:
            return 0
        i=i+1
    return 1

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def within(o:mutbuf,first:u64,second:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,second+i,byte(o,first+i))
        i=i+1
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0

def word(s:readbuf,at:u64) -> u64:
    v=0
    i=0
    while i<8:
        v=v|(byte(s,at+i)<<(i*8))
        i=i+1
    return v

def get(w:mutbuf,at:u64) -> u64:
    v=0
    i=0
    while i<8:
        v=v|(byte(w,at+i)<<(i*8))
        i=i+1
    return v

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
MESSAGES={
18:'runtime is closed',
19:'stale generation or selection epoch',
20:'actual preparation budget exceeded before selection',
21:'publication cancelled before selection',
22:'publication cancellation token was already committed',
26:'live artifact budget exhausted; existing generations remain selected',
}
def source_program():
    import json
    source=SOURCE
    text=['def exception_text(o:mutbuf,at:u64,code:u64) -> u64:']
    for code,message in MESSAGES.items():
        raw=json.dumps({'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: '+message},ensure_ascii=True,separators=(',',':')).encode()
        text.append(f'    if code=={code}:')
        for i in range(0,len(raw),8):
            piece=raw[i:i+8]
            if len(piece)==8:text.append(f'        put(o,at+{i},{int.from_bytes(piece,"little")})')
            else:
                for j,b in enumerate(piece):text.append(f'        store(o,at+{i+j},{b})')
        text.append(f'        return {len(raw)}')
    text.append('    return 0')
    source+='\n'+'\n'.join(text)+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    result=document(source_program(),'multiversion_background_runtime')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_runtime.hepta'
    p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),flush=True)
if __name__=='__main__':main()
