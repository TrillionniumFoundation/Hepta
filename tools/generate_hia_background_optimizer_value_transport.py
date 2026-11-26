"""Lossless native value-capability transport for checked background freezing.

This private owner reads only the qualified mutable-value capability API.
It does not enforce finite/Unicode/int-digit/structure policy. A caller must
apply the original typed structure and checked sorted freezer in their order.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.hia_background_retirement_source import selected as retirement_source
ROOT=Path(__file__).resolve().parents[1]
C={
'MAGIC':int.from_bytes(b'HIABIQ01','little'),'REPLY':int.from_bytes(b'HIABIO01','little'),
'CONTEXT':int.from_bytes(b'HIABIC01','little'),'VREQUEST':int.from_bytes(b'HIABVQ01','little'),
'VREPLY':int.from_bytes(b'HIABVR01','little'),'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'PHASE':128,'ERROR':136,'DETAIL':144,'FD':152,'TOTAL':160,'USED':168,
'CURRENT':176,'NEW':184,'SCAN':192,'FLAG':200,'KIND':208,'SIZE':216,
'OFFSET':224,'CHUNK':232,'READPOS':240,'AFTER':248,'FLUSHPOS':256,'AFTER_FLUSH':264,
'RETRY':272,'PID':280,'FAILED_DROP':288,'SAVED_PARENT':296,
'FEEDBACK':448,'FR':512,'AR':640,'OWN':768,'RQ':1024,'VP':2048,'VOUT':12288,
'DIGITS':16384,'TEXT':18432,'TEXTN':304,'TEXTAT':312,
'BUF':32768,'BUFSIZE':65536,'OUT':131072}
C.update({'MODERN':320,'VALUE_PENDING':328,'DROP_ACTIVE':336,'DROP_KNOWN':344,'QUARANTINE_KIND':352,'RELEASE_RESULT':360,'RP':2048})
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {'NEW_MAGIC':'HIABIQ02','NEW_REPLY':'HIABIO02','NEW_CONTEXT':'HIABIC02','VALUE_DROP_INPUT':'HIABVQ02','VALUE_DROP_REPLY':'HIABVR02'}.items()})
SOURCE=r'''
def value_transport(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return opening(s,o,w,phase)
    if phase<200:
        return pushing(s,o,w,phase)
    if phase<300:
        return containers(s,o,w,phase)
    if phase<400:
        return scalars(s,o,w,phase)
    if phase<500:
        return popping(s,o,w,phase)
    if phase<600:
        return flushing(s,o,w,phase)
    if phase<700:
        return sealing(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or (word_load(s,0)!=MAGIC and word_load(s,0)!=NEW_MAGIC) or word_load(s,8)>1:
        return 4294967293
    at=16
    while at<128:
        used=word_load(s,8)==0 and at>=24 and at<=40
        if used==False and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    modern=word_load(s,0)==NEW_MAGIC
    if get(w,0)!=choose(modern,NEW_CONTEXT,CONTEXT) or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if modern and (get(w,88)>2 or get(w,96)>1):
        return 4294967293
    at=choose(modern,112,88)
    while at<256:
        if get(w,at)!=0:
            return 4294967293
        at=at+8
    zero(o,128,OUT-128)
    put(o,MODERN,choose(modern,1,0))
    put(o,RETRY,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def opening(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE:
            return finish(o,w,8)
        if get(w,80)!=0 and get(w,80)!=pid:
            return finish(o,w,6)
        put(w,80,pid)
        put(o,PID,pid)
        if get(o,RETRY)!=0:
            put(o,CURRENT,get(w,32))
            put(o,OWN,get(w,40))
            put(o,OWN+8,get(w,48))
            put(o,OWN+16,get(w,56))
            put(o,FD,get(w,64))
            put(o,ERROR,get(w,72))
            zero(w,32,48)
            if get(o,MODERN)!=0:
                put(o,QUARANTINE_KIND,get(w,88))
                put(o,VALUE_PENDING,get(w,96))
                put(o,NEW,get(w,104))
                zero(w,88,24)
                if get(o,QUARANTINE_KIND)==2:
                    return quarantine(o,w,7,2)
                put(o,QUARANTINE_KIND,0)
            return again(o,700)
        if get(w,32)!=0 or get(w,40)!=0 or get(w,64)!=0:
            return finish(o,w,6)
        if get(o,MODERN)!=0 and (get(w,88)!=0 or get(w,96)!=0 or get(w,104)!=0):
            return finish(o,w,6)
        packet(o,5)
        put(o,RQ+24,word_load(s,24))
        put(o,RQ+32,word_load(s,32))
        put(o,RQ+40,word_load(s,40))
        return value(o,w,2)
    if phase==2:
        if value_ok(o)==False:
            return fail(o,7,get(o,VP+8))
        within(o,OWN,VP+24,24)
        put(o,TEXT,0)
        return system(o,3,319,3,TEXT,3,0,0,0,0)
    if phase==3:
        raw=get(o,FEEDBACK)
        if raw>=NEGATIVE:
            return fail(o,8,raw)
        put(o,FD,raw+1)
        put(o,FLAG,0)
        return again(o,100)
    return fail(o,9,phase)

def pushing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,OWN)==0:
            return fail(o,9,100)
        return allocate(o,101,128)
    if phase==101:
        if get(o,FEEDBACK)==0:
            return fail(o,5,0)
        put(o,NEW,get(o,FEEDBACK))
        zero(o,FR,128)
        put(o,FR,get(o,CURRENT))
        within(o,FR+8,OWN,24)
        put(o,FR+120,get(o,FLAG))
        return memory(o,102,3,FR,0,get(o,NEW),128)
    if phase==102:
        put(o,CURRENT,get(o,NEW))
        put(o,NEW,0)
        zero(o,OWN,24)
        packet(o,7)
        within(o,RQ+24,FR+8,24)
        return value(o,w,103)
    if phase==103:
        if value_ok(o)==False:
            return fail(o,7,get(o,VP+8))
        kind=get(o,VP+16)
        if kind>6 or (get(o,FR+120)!=0 and kind!=4):
            return fail(o,2,kind)
        put(o,FR+32,kind)
        put(o,FR+56,get(o,VP+104))
        put(o,FR+64,get(o,VP+112))
        put(o,KIND,kind)
        put(o,SIZE,get(o,VP+72))
        if kind==5 or kind==6:
            put(o,SCAN,get(o,FR))
            return memory(o,104,3,FR,0,get(o,CURRENT),128)
        return memory(o,130,3,FR,0,get(o,CURRENT),128)
    if phase==104:
        if get(o,SCAN)==0:
            return room(o,200,1)
        return memory(o,105,0,get(o,SCAN),3,AR,128)
    if phase==105:
        if get(o,AR+56)==get(o,FR+56) and get(o,AR+64)==get(o,FR+64):
            return fail(o,3,0)
        put(o,SCAN,get(o,AR))
        return again(o,104)
    if phase==130:
        put(o,OFFSET,0)
        kind=get(o,KIND)
        if kind==0:
            return room(o,131,4)
        if kind==1:
            return room(o,140,5)
        if kind==3:
            return room(o,150,1024)
        if kind==4:
            return room(o,160,1)
        return again(o,300)
    if phase==131:
        emit(o,110)
        emit(o,117)
        emit(o,108)
        emit(o,108)
        return again(o,400)
    if phase==140:
        return scalar_read(o,w,141,1)
    if phase==141:
        if scalar_ok(o,1)==False:
            return fail(o,7,get(o,VP+8))
        if byte(o,VP+8192)==0:
            emit(o,102)
            emit(o,97)
            emit(o,108)
            emit(o,115)
            emit(o,101)
        else:
            emit(o,116)
            emit(o,114)
            emit(o,117)
            emit(o,101)
        return again(o,400)
    if phase==150:
        return scalar_read(o,w,151,8)
    if phase==151:
        if scalar_ok(o,8)==False:
            return fail(o,7,get(o,VP+8))
        bits=get(o,VP+8192)
        if float_text(o,bits)==0:
            return fail(o,9,151)
        put(o,TEXTAT,0)
        return again(o,152)
    if phase==152:
        n=get(o,TEXTN)
        i=0
        while i<n:
            emit(o,byte(o,TEXT+i))
            i=i+1
        return again(o,400)
    if phase==160:
        emit(o,34)
        return again(o,300)
    return fail(o,9,phase)

def containers(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(o,FR+32)==5:
            emit(o,91)
        else:
            emit(o,123)
        put(o,FR+40,1)
        return memory(o,201,3,FR,0,get(o,CURRENT),128)
    if phase==201:
        if get(o,CURRENT)==0:
            return flush(o,600)
        return memory(o,202,0,get(o,CURRENT),3,FR,128)
    if phase==202:
        if get(o,FR+40)==2:
            return room(o,230,1)
        return room(o,210,1)
    if phase==210:
        packet(o,23)
        within(o,RQ+24,FR+8,24)
        put(o,RQ+104,get(o,FR+48))
        put(o,RQ+112,1)
        return value(o,w,211)
    if phase==211:
        if value_ok(o)==False:
            return fail(o,7,get(o,VP+8))
        n=get(o,VP+64)
        if n==0:
            if get(o,FR+32)==5:
                emit(o,93)
            else:
                emit(o,125)
            return again(o,400)
        if n!=1:
            return fail(o,9,n)
        within(o,FR+72,VP+8192+16,24)
        within(o,FR+96,VP+8192+40,24)
        if get(o,FR+48)!=0:
            emit(o,44)
        if get(o,FR+48)==MAX:
            return fail(o,9,MAX)
        put(o,FR+48,get(o,FR+48)+1)
        if get(o,FR+32)==6:
            put(o,FR+40,2)
            return memory(o,220,3,FR,0,get(o,CURRENT),128)
        return memory(o,240,3,FR,0,get(o,CURRENT),128)
    if phase==220:
        within(o,OWN,FR+72,24)
        zero(o,FR+72,24)
        put(o,FLAG,1)
        return memory(o,100,3,FR,0,get(o,CURRENT),128)
    if phase==230:
        emit(o,58)
        put(o,FR+40,1)
        return again(o,240)
    if phase==240:
        within(o,OWN,FR+96,24)
        zero(o,FR+96,24)
        put(o,FLAG,0)
        return memory(o,100,3,FR,0,get(o,CURRENT),128)
    return fail(o,9,phase)

def scalars(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,OFFSET)==get(o,SIZE):
            if get(o,KIND)==4:
                return room(o,330,1)
            return again(o,400)
        if get(o,OFFSET)>get(o,SIZE):
            return fail(o,9,300)
        n=get(o,SIZE)-get(o,OFFSET)
        if n>4096:
            n=4096
        put(o,CHUNK,n)
        return room(o,301,n*6)
    if phase==301:
        return scalar_read(o,w,302,get(o,CHUNK))
    if phase==302:
        if scalar_ok(o,get(o,CHUNK))==False:
            return fail(o,7,get(o,VP+8))
        n=get(o,CHUNK)
        i=0
        while i<n:
            ch=byte(o,VP+8192+i)
            if get(o,KIND)==4:
                if ch==34 or ch==92:
                    emit(o,92)
                    emit(o,ch)
                elif ch<32:
                    emit(o,92)
                    emit(o,117)
                    emit(o,48)
                    emit(o,48)
                    emit(o,hex_digit(ch//16))
                    emit(o,hex_digit(ch%16))
                else:
                    emit(o,ch)
            else:
                emit(o,ch)
            i=i+1
        put(o,OFFSET,get(o,OFFSET)+n)
        return again(o,300)
    if phase==330:
        emit(o,34)
        return again(o,400)
    return fail(o,9,phase)

def popping(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        return memory(o,401,0,get(o,CURRENT),3,FR,128)
    if phase==401:
        if get(o,FR+72)!=0 or get(o,FR+96)!=0:
            return fail(o,9,401)
        packet(o,6)
        within(o,RQ+24,FR+8,24)
        return value(o,w,402)
    if phase==402:
        if get(o,MODERN)!=0:
            released=release_value(o,FR+8)
            put(o,RELEASE_RESULT,released)
            return memory(o,403,3,FR,0,get(o,CURRENT),128)
        if value_ok(o)==False:
            return quarantine(o,w,7,get(o,VP+8))
        ptr=get(o,CURRENT)
        put(o,CURRENT,get(o,FR))
        return deallocate(o,201,ptr)
    if phase==403:
        if get(o,RELEASE_RESULT)==0 or get(o,VALUE_PENDING)!=0:
            return release_blocked(o,w)
        ptr=get(o,CURRENT)
        put(o,CURRENT,get(o,FR))
        return deallocate(o,201,ptr)
    return fail(o,9,phase)

def flushing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        n=get(o,USED)-get(o,FLUSHPOS)
        if n==0:
            put(o,USED,0)
            return again(o,get(o,AFTER_FLUSH))
        return system(o,501,1,12,get(o,FD)-1,BUF+get(o,FLUSHPOS),n,0,0,0)
    if phase==501:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return again(o,500)
        if raw==0 or raw>=NEGATIVE or raw>get(o,USED)-get(o,FLUSHPOS):
            return fail(o,8,raw)
        if get(o,TOTAL)>MAX-raw:
            return fail(o,9,MAX)
        put(o,TOTAL,get(o,TOTAL)+raw)
        put(o,FLUSHPOS,get(o,FLUSHPOS)+raw)
        return again(o,500)
    return fail(o,9,phase)

def sealing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        return system(o,601,72,0,get(o,FD)-1,1033,15,0,0,0)
    if phase==601:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return again(o,600)
        if raw!=0:
            return fail(o,8,raw)
        return system(o,602,72,0,get(o,FD)-1,1034,0,0,0,0)
    if phase==602:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return system(o,602,72,0,get(o,FD)-1,1034,0,0,0,0)
        if raw!=15:
            return fail(o,8,raw)
        return finish(o,w,0)
    return fail(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,MODERN)!=0 and get(o,VALUE_PENDING)!=0:
            packet(o,31)
            return value(o,w,760)
        if get(o,OWN)!=0:
            packet(o,6)
            within(o,RQ+24,OWN,24)
            return value(o,w,701)
        if get(o,NEW)!=0:
            ptr=get(o,NEW)
            put(o,NEW,0)
            return deallocate(o,700,ptr)
        if get(o,CURRENT)!=0:
            return memory(o,710,0,get(o,CURRENT),3,FR,128)
        if get(o,FD)!=0:
            fd=get(o,FD)-1
            if get(o,MODERN)!=0:
                return system(o,750,436,0,fd,fd,0,0,0,0)
            put(o,FD,0)
            return system(o,750,3,0,fd,0,0,0,0,0)
        return finish(o,w,get(o,ERROR))
    if phase==701:
        if get(o,MODERN)!=0:
            released=release_value(o,OWN)
            if released==0 or get(o,VALUE_PENDING)!=0:
                return release_blocked(o,w)
            return again(o,700)
        if value_ok(o)==False:
            return quarantine(o,w,7,get(o,VP+8))
        zero(o,OWN,24)
        return again(o,700)
    if phase==710:
        at=8
        if get(o,FR+8)==0:
            at=72
        if get(o,FR+8)==0 and get(o,FR+72)==0:
            at=96
        if get(o,FR+at)==0:
            ptr=get(o,CURRENT)
            put(o,CURRENT,get(o,FR))
            return deallocate(o,700,ptr)
        put(o,READPOS,at)
        packet(o,6)
        within(o,RQ+24,FR+at,24)
        return value(o,w,711)
    if phase==711:
        if get(o,MODERN)!=0:
            released=release_value(o,FR+get(o,READPOS))
            put(o,RELEASE_RESULT,released)
            return memory(o,712,3,FR,0,get(o,CURRENT),128)
        if value_ok(o)==False:
            return quarantine(o,w,7,get(o,VP+8))
        zero(o,FR+get(o,READPOS),24)
        return memory(o,700,3,FR,0,get(o,CURRENT),128)
    if phase==712:
        if get(o,RELEASE_RESULT)==0 or get(o,VALUE_PENDING)!=0:
            return release_blocked(o,w)
        return again(o,700)
    if phase==760:
        if release_value_retry(o)==0:
            return release_blocked(o,w)
        return again(o,700)
    if phase==750:
        raw=get(o,FEEDBACK)
        if get(o,MODERN)!=0:
            if raw!=0:
                put(o,QUARANTINE_KIND,1)
                return quarantine(o,w,8,raw)
            put(o,FD,0)
            return again(o,700)
        if raw!=0:
            put(o,DETAIL,raw)
            put(o,ERROR,8)
        return finish(o,w,get(o,ERROR))
    return finish(o,w,9)

def release_blocked(o:mutbuf,w:mutbuf) -> u32:
    put(o,QUARANTINE_KIND,choose(get(o,DROP_KNOWN)==1,1,2))
    return quarantine(o,w,7,get(o,VP+8))

def quarantine(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,MODERN)!=0:
        if get(o,QUARANTINE_KIND)==0:
            put(o,QUARANTINE_KIND,1)
        put(w,88,get(o,QUARANTINE_KIND))
        put(w,96,get(o,VALUE_PENDING))
        put(w,104,get(o,NEW))
    put(w,32,get(o,CURRENT))
    put(w,40,get(o,OWN))
    put(w,48,get(o,OWN+8))
    put(w,56,get(o,OWN+16))
    put(w,64,get(o,FD))
    put(w,72,get(o,ERROR))
    put(o,DETAIL,detail)
    put(o,FAILED_DROP,1)
    return finish(o,w,status)

def float_text(o:mutbuf,bits:u64) -> u64:
    put(o,TEXTN,0)
    sign=bits>>63
    exponent=(bits>>52)&2047
    mantissa=bits&4503599627370495
    if exponent==2047:
        if mantissa!=0:
            text_byte(o,78)
            text_byte(o,97)
            text_byte(o,78)
            return 1
        if sign!=0:
            text_byte(o,45)
        text_byte(o,73)
        text_byte(o,110)
        text_byte(o,102)
        text_byte(o,105)
        text_byte(o,110)
        text_byte(o,105)
        text_byte(o,116)
        text_byte(o,121)
        return 1
    if sign!=0:
        text_byte(o,45)
    if exponent==0 and mantissa==0:
        text_byte(o,48)
        text_byte(o,46)
        text_byte(o,48)
        return 1
    negative=False
    power=0
    if exponent==0:
        power=1074
        negative=True
    else:
        mantissa=mantissa+4503599627370496
        if exponent<1075:
            negative=True
            power=1075-exponent
        else:
            power=exponent-1075
    n=0
    while mantissa!=0:
        store(o,DIGITS+n,mantissa%10)
        n=n+1
        mantissa=mantissa//10
    multiplier=2
    if negative:
        multiplier=5
    k=0
    while k<power:
        carry=0
        i=0
        while i<n:
            number=byte(o,DIGITS+i)*multiplier+carry
            store(o,DIGITS+i,number%10)
            carry=number//10
            i=i+1
        while carry!=0:
            if n>=1024:
                return 0
            store(o,DIGITS+n,carry%10)
            n=n+1
            carry=carry//10
        k=k+1
    i=n
    while i!=0:
        i=i-1
        text_byte(o,48+byte(o,DIGITS+i))
    if negative:
        text_byte(o,101)
        text_byte(o,45)
        decimal_text(o,power)
    else:
        text_byte(o,46)
        text_byte(o,48)
    return 1

def decimal_text(o:mutbuf,n:u64) -> u64:
    i=0
    while n!=0:
        store(o,DIGITS+1024+i,n%10)
        n=n//10
        i=i+1
    if i==0:
        text_byte(o,48)
    while i!=0:
        i=i-1
        text_byte(o,48+byte(o,DIGITS+1024+i))
    return 0
def text_byte(o:mutbuf,ch:u64) -> u64:
    n=get(o,TEXTN)
    store(o,TEXT+n,ch)
    put(o,TEXTN,n+1)
    return 0
def emit(o:mutbuf,ch:u64) -> u64:
    n=get(o,USED)
    store(o,BUF+n,ch)
    put(o,USED,n+1)
    return 0
def room(o:mutbuf,next:u64,n:u64) -> u32:
    if get(o,USED)<=BUFSIZE and n<=BUFSIZE-get(o,USED):
        return again(o,next)
    return flush(o,next)
def flush(o:mutbuf,next:u64) -> u32:
    put(o,AFTER_FLUSH,next)
    put(o,FLUSHPOS,0)
    return again(o,500)
def scalar_read(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    packet(o,19)
    within(o,RQ+24,FR+8,24)
    put(o,RQ+104,get(o,OFFSET))
    put(o,RQ+112,n)
    return value(o,w,next)
def scalar_ok(o:mutbuf,n:u64) -> bool:
    return value_ok(o) and get(o,VP+56)==get(o,OFFSET) and get(o,VP+64)==n and get(o,VP+72)==get(o,SIZE)
def packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    if get(o,MODERN)!=0 and (op==6 or op==31):
        put(o,RQ,VALUE_DROP_INPUT)
        put(o,RQ+8,choose(op==6,29,31))
        release_begin(o)
    return 0

def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,get(w,8))
    put(o,8,51)
    put(o,16,RQ)
    put(o,24,128)
    put(o,32,VP)
    put(o,40,VOUT)
    put(o,48,get(w,16))
    put(o,56,get(w,24))
    return 9
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0
def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6
def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7
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
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,700)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    fd=MAX
    n=0
    seals=0
    if status==0 and get(o,RETRY)==0:
        fd=get(o,FD)-1
        n=get(o,TOTAL)
        seals=15
        put(o,FD,0)
    zero(o,0,128)
    put(o,0,choose(get(o,MODERN)!=0,NEW_REPLY,REPLY))
    put(o,8,status)
    put(o,16,fd)
    put(o,24,n)
    put(o,32,seals)
    put(o,40,get(o,DETAIL))
    put(o,48,get(o,FAILED_DROP))
    if get(o,MODERN)!=0 and get(o,FAILED_DROP)!=0:
        put(o,56,get(o,QUARANTINE_KIND))
        put(o,64,get(o,VALUE_PENDING))
    return 0
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10
def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(n>>(i*8))&255)
        i=i+1
    return 0
def hex_digit(n:u64) -> u64:
    if n<10:
        return 48+n
    return 87+n

def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    if get(o,FEEDBACK)!=0 or get(o,at)!=magic:
        return 0
    return 1

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

'''
SOURCE += '\n' + retirement_source('release_begin', 'release_value', 'release_value_retry')
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def main():
 d=document(source_program(),'background_optimizer_value_transport')
 p=ROOT/'examples/hia_bootstrap/background_optimizer_value_transport.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
