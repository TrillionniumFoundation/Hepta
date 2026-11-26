"""Typed value-cap structure/snapshot continuation for the BG owner.

All object observations and ownership effects use the fixed captured native
result-value owner. No caller-supplied type, length, identity, or child arena is
accepted. The enclosing owner supplies the fixed decimal threshold data.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_structure import SOURCE as structural
from tools.generate_hia_background_optimizer_structure import ERRORS as structure_errors
from tools.hia_background_retirement_source import selected as retirement_source
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIABTC01','little'),'REPLY':int.from_bytes(b'HIABTV01','little'),
'RETRY_REQUEST':int.from_bytes(b'HIABTC02','little'),'CONTEXT':int.from_bytes(b'HIABVC01','little'),'VREQUEST':int.from_bytes(b'HIABVQ01','little'),'VREPLY':int.from_bytes(b'HIABVR01','little'),
'NONE':(1<<64)-1,'BAD':4294967293,'MAX_NODES':262144,'MAX_DEPTH':64,'MAX_BYTES':8388608,
'THRESHOLD_N':10100891,'OUTPUT':96<<20,'NODES':65536,'STRIDE':160,'FRAMES':44<<20,'RP':48<<20,'RQ':1024,
'PHASE':128,'FEEDBACK':136,'CUR':144,'ALLOCATED':152,'VISITED':160,'QUEUED':168,'SIZE':176,'DEPTH':184,'PASS':192,
'ERR':200,'NEXT':208,'KEY_INDEX':216,'SCALAR_KIND':224,'SCALAR_N':232,'SCALAR_CHARS':240,'SCALAR_IS_KEY':248,
'COPY_N':256,'CHILDREN':264,'CHILD_FIRST':272,'OVERFLOW_N':280,'DROP_INDEX':288,'DROP_SLOT':296,'ROOT':304,
'MODE':336,'LIMIT':344,'PROVIDER_ERROR':352,'CLEANUP_ERRORS':360,'BUILD_INDEX':368,'BUILD_CHILD':376,'LIVE_ERROR':384,
'FIRST_BYTE':392,'SIGNED':400,'COPIED':408,'SCALAR_CAP':416,'STEP_AFTER':440,
}
ERRORS={**structure_errors,21:'E_HIA_LIMIT: caller-owned tree exceeds snapshot budget',22:'E_HIA_LIMIT: caller-owned tree exceeds queued-node budget',23:'E_HIA_FORMAT: cyclic caller-owned HIA tree',24:'E_HIA_FORMAT: non-string caller-owned JSON key',25:'E_HIA_FORMAT: unsupported caller-owned JSON node'}
C.update({'MODERN':448,'DROP_ACTIVE':456,'DROP_KNOWN':464,'VALUE_PENDING':472,'QUARANTINE_KIND':480})
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {'NEW_REQUEST':'HIABTC03','NEW_RETRY':'HIABTC04','NEW_REPLY':'HIABTV02','NEW_CONTEXT':'HIABVC02','VALUE_DROP_INPUT':'HIABVQ02','VALUE_DROP_REPLY':'HIABVR02'}.items()})
SOURCE=r'''
def background_optimizer_value_structure(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128+THRESHOLD_N or length(o)<OUTPUT or length(w)<128:
        return BAD
    profile=read64(s,0)
    op=read64(s,8)
    modern=profile==NEW_REQUEST or profile==NEW_RETRY
    retry=profile==RETRY_REQUEST or profile==NEW_RETRY
    if profile!=REQUEST and profile!=RETRY_REQUEST and modern==False:
        return BAD
    if (retry==False and op>1) or (retry and op!=2) or read64(s,48)!=THRESHOLD_N:
        return BAD
    if retry and (read64(s,16)!=0 or read64(s,24)!=0 or read64(s,32)!=0):
        return BAD
    if get(w,0)!=choose(modern,NEW_CONTEXT,CONTEXT) or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    limit=read64(s,40)
    if limit!=0 and (limit<640 or limit>2147483647):
        return BAD
    at=56
    while at<128:
        if read64(s,at)!=0:
            return BAD
        at=at+8
    phase=get(o,PHASE)
    if retry:
        if get(o,0)==choose(modern,NEW_REPLY,REPLY) and get(o,8)==3:
            if get(o,CLEANUP_ERRORS)==0 or get(o,ALLOCATED)>MAX_NODES or get(o,OVERFLOW_N)>MAX_NODES+1:
                return BAD
            if get(o,LIMIT)!=limit or get(o,MODERN)!=choose(modern,1,0):
                return BAD
            if modern and get(o,QUARANTINE_KIND)==2:
                return finish(o)
            zero(o,0,128)
            put(o,CLEANUP_ERRORS,0)
            put(o,DROP_INDEX,0)
            put(o,DROP_SLOT,0)
            put(o,512,1)
            put(o,QUARANTINE_KIND,0)
            if modern and get(o,VALUE_PENDING)!=0:
                request(o,31)
                return invoke_overflow(o,w,310)
            return again(o,choose(get(o,OVERFLOW_N)!=0,330,300))
        if get(o,512)!=1 or (phase!=300 and phase!=301 and phase!=330 and phase!=331 and (modern==False or phase!=310)):
            return BAD
        return cleanup(o,w,phase)
    if phase==0:
        zero(o,128,896)
        put(o,MODERN,choose(modern,1,0))
        put(o,MODE,read64(s,8))
        put(o,PASS,read64(s,8))
        put(o,LIMIT,limit)
        zero(o,NODES,STRIDE)
        request(o,5)
        copy_input(s,16,o,RQ+24,24)
        return invoke(o,w,10)
    if phase==10:
        if value_ok(o)==False:
            return provider_failure(o,0)
        within(o,NODES,RP+24,24)
        put(o,ALLOCATED,1)
        put(o,QUEUED,1)
        put(o,CUR,0)
        return enter(o,w)
    if phase>=20 and phase<100:
        return visiting(s,o,w,phase)
    if phase>=100 and phase<200:
        return scalar(s,o,w,phase)
    if phase>=200 and phase<300:
        return building(o,w,phase)
    if phase>=300 and phase<400:
        return cleanup(o,w,phase)
    return BAD

def enter(o:mutbuf,w:mutbuf) -> u32:
    put(o,SCALAR_IS_KEY,0)
    put(o,QUEUED,get(o,QUEUED)-1)
    put(o,VISITED,get(o,VISITED)+1)
    if get(o,VISITED)>MAX_NODES or get(o,DEPTH)>MAX_DEPTH:
        return fail(o,choose(get(o,PASS)==1,21,1))
    if get(o,PASS)==2:
        return again(o,21)
    request(o,7)
    within(o,RQ+24,node(get(o,CUR)),24)
    return invoke(o,w,20)

def visiting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if value_ok(o)==False:
            return provider_failure(o,0)
        row=node(get(o,CUR))
        kind=get(o,RP+16)
        if kind>7:
            return provider_failure(o,65)
        put(o,row+72,kind)
        put(o,row+80,get(o,RP+104))
        put(o,row+88,get(o,RP+112))
        put(o,row+144,get(o,RP+48))
        put(o,row+152,get(o,RP+72))
        return again(o,21)
    if phase==21:
        row=node(get(o,CUR))
        kind=get(o,row+72)
        if kind==5 or kind==6:
            i=0
            while i<get(o,DEPTH):
                parent=node(get(o,FRAMES+i*24))
                if get(o,row+80)==get(o,parent+80) and get(o,row+88)==get(o,parent+88):
                    return fail(o,choose(get(o,PASS)==1,23,3))
                i=i+1
            count=choose(get(o,PASS)==2,get(o,row+112),get(o,row+144))
            available=MAX_NODES-get(o,VISITED)-get(o,QUEUED)
            if count>available:
                return fail(o,choose(get(o,PASS)==1,22,2))
            if get(o,PASS)==2:
                put(o,CHILDREN,count)
                put(o,CHILD_FIRST,get(o,row+104))
                return begin_container(o)
            request(o,23)
            within(o,RQ+24,row,24)
            put(o,RQ+112,MAX_NODES+1)
            return invoke(o,w,30)
        if get(o,PASS)==1:
            if kind==3 or kind==7:
                return fail(o,25)
            return advance(o,w)
        if kind==3 or kind==7:
            return fail(o,5)
        if kind==0:
            put(o,SIZE,get(o,SIZE)+4)
            return after_size(o,w)
        within(o,SCALAR_CAP,row,24)
        put(o,SCALAR_IS_KEY,0)
        put(o,SCALAR_KIND,kind)
        put(o,SCALAR_CHARS,get(o,row+144))
        put(o,SCALAR_N,get(o,row+152))
        return start_scalar(o,w)
    if phase==30:
        if value_ok(o)==False:
            return provider_failure(o,0)
        count=get(o,RP+64)
        current=get(o,RP+48)
        if count>MAX_NODES+1 or count!=choose(current<MAX_NODES+1,current,MAX_NODES+1):
            return provider_failure(o,65)
        put(o,OVERFLOW_N,count)
        available=MAX_NODES-get(o,VISITED)-get(o,QUEUED)
        if current>available:
            put(o,ERR,choose(get(o,PASS)==1,22,2))
            put(o,DROP_INDEX,0)
            put(o,DROP_SLOT,0)
            return again(o,330)
        if count!=current or count>MAX_NODES-get(o,ALLOCATED):
            return provider_failure(o,65)
        first=get(o,ALLOCATED)
        zero(o,node(first),count*STRIDE)
        i=0
        while i<count:
            entry=RP+8192+i*64
            row=node(first+i)
            within(o,row,entry+40,24)
            within(o,row+24,entry+16,24)
            put(o,row+96,get(o,CUR))
            i=i+1
        put(o,ALLOCATED,first+count)
        put(o,OVERFLOW_N,0)
        put(o,CHILDREN,count)
        put(o,CHILD_FIRST,first)
        row=node(get(o,CUR))
        put(o,row+104,first)
        put(o,row+112,count)
        return begin_container(o)
    if phase==40:
        if get(o,KEY_INDEX)==get(o,CHILDREN):
            if get(o,PASS)!=1 and get(o,SIZE)>MAX_BYTES:
                return fail(o,7)
            return descend(o,w)
        child=node(get(o,CHILD_FIRST)+get(o,KEY_INDEX))
        if get(o,PASS)==2:
            within(o,SCALAR_CAP,child+24,24)
            put(o,SCALAR_IS_KEY,1)
            put(o,SCALAR_KIND,4)
            put(o,SCALAR_CHARS,get(o,child+128))
            put(o,SCALAR_N,get(o,child+136))
            return start_scalar(o,w)
        request(o,7)
        within(o,RQ+24,child+24,24)
        return invoke(o,w,41)
    if phase==41:
        if value_ok(o)==False:
            return provider_failure(o,0)
        if get(o,RP+16)!=4:
            return fail(o,choose(get(o,PASS)==1,24,4))
        child=node(get(o,CHILD_FIRST)+get(o,KEY_INDEX))
        put(o,child+128,get(o,RP+48))
        put(o,child+136,get(o,RP+72))
        if get(o,PASS)==1:
            put(o,KEY_INDEX,get(o,KEY_INDEX)+1)
            return again(o,40)
        within(o,SCALAR_CAP,child+24,24)
        put(o,SCALAR_IS_KEY,1)
        put(o,SCALAR_KIND,4)
        put(o,SCALAR_CHARS,get(o,child+128))
        put(o,SCALAR_N,get(o,child+136))
        return start_scalar(o,w)
    return BAD

def begin_container(o:mutbuf) -> u32:
    count=get(o,CHILDREN)
    put(o,QUEUED,get(o,QUEUED)+count)
    if get(o,PASS)!=1:
        amount=2
        if count!=0:
            amount=amount+count-1
        if get(o,node(get(o,CUR))+72)==6:
            amount=amount+count
        put(o,SIZE,get(o,SIZE)+amount)
    put(o,KEY_INDEX,0)
    if get(o,node(get(o,CUR))+72)==6:
        return again(o,40)
    return again(o,42)

def descend(o:mutbuf,w:mutbuf) -> u32:
    count=get(o,CHILDREN)
    if count==0:
        return advance(o,w)
    depth=get(o,DEPTH)
    put(o,FRAMES+depth*24,get(o,CUR))
    put(o,FRAMES+depth*24+8,choose(get(o,PASS)==1,0,count-1))
    put(o,FRAMES+depth*24+16,count)
    put(o,DEPTH,depth+1)
    put(o,CUR,get(o,CHILD_FIRST)+choose(get(o,PASS)==1,0,count-1))
    return enter(o,w)

def advance(o:mutbuf,w:mutbuf) -> u32:
    depth=get(o,DEPTH)
    while depth!=0:
        slot=FRAMES+(depth-1)*24
        parent=get(o,slot)
        index=get(o,slot+8)
        count=get(o,slot+16)
        if get(o,PASS)==1:
            more=index+1<count
            index=index+1
        else:
            more=index!=0
            if more:
                index=index-1
        if more:
            put(o,slot+8,index)
            put(o,CUR,get(o,node(parent)+104)+index)
            return enter(o,w)
        depth=depth-1
        put(o,DEPTH,depth)
    if get(o,PASS)==1:
        put(o,PASS,2)
        put(o,VISITED,0)
        put(o,QUEUED,1)
        put(o,SIZE,0)
        put(o,CUR,0)
        return enter(o,w)
    put(o,PASS,3)
    put(o,BUILD_INDEX,get(o,ALLOCATED))
    return again(o,200)

def after_size(o:mutbuf,w:mutbuf) -> u32:
    if get(o,SIZE)>MAX_BYTES:
        return fail(o,7)
    if get(o,SCALAR_IS_KEY)!=0:
        put(o,KEY_INDEX,get(o,KEY_INDEX)+1)
        return again(o,40)
    return advance(o,w)

def start_scalar(o:mutbuf,w:mutbuf) -> u32:
    kind=get(o,SCALAR_KIND)
    n=get(o,SCALAR_N)
    if kind==4:
        if get(o,SIZE)>MAX_BYTES:
            return fail(o,7)
        remaining=MAX_BYTES-get(o,SIZE)
        if get(o,SCALAR_CHARS)>remaining or remaining-get(o,SCALAR_CHARS)<2:
            return fail(o,7)
        if n>33554432:
            return provider_failure(o,65)
        return scalar_copy(o,w,110,n)
    if kind==1:
        if n!=1:
            return provider_failure(o,65)
        return scalar_copy(o,w,100,1)
    if kind==2:
        if n==0:
            return provider_failure(o,65)
        return scalar_copy(o,w,101,1)
    return provider_failure(o,65)

def scalar_copy(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    request(o,19)
    within(o,RQ+24,SCALAR_CAP,24)
    put(o,RQ+112,n)
    put(o,COPY_N,n)
    return invoke(o,w,next)

def scalar(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100 or phase==101 or phase==102 or phase==110:
        if value_ok(o)==False:
            return provider_failure(o,0)
        if get(o,RP+64)!=get(o,COPY_N) or get(o,RP+72)!=get(o,SCALAR_N):
            return provider_failure(o,65)
    if phase==100:
        value=byte(o,RP+8192)
        if value>1:
            return provider_failure(o,65)
        put(o,SIZE,get(o,SIZE)+choose(value==1,4,5))
        return after_size(o,w)
    if phase==101:
        first=byte(o,RP+8192)
        if first!=45 and (first<48 or first>57):
            return provider_failure(o,65)
        skip=choose(first==45,1,0)
        put(o,SIGNED,skip)
        n=get(o,SCALAR_N)
        if n<=skip:
            return provider_failure(o,65)
        digits=n-skip
        if digits>THRESHOLD_N:
            return fail(o,8)
        if digits==THRESHOLD_N:
            return scalar_copy(o,w,102,n)
        return integer_size(o,w)
    if phase==102:
        n=get(o,SCALAR_N)
        skip=get(o,SIGNED)
        i=0
        decided=0
        while i<THRESHOLD_N and decided==0:
            a=byte(o,RP+8192+skip+i)
            b=byte(s,128+i)
            if a>b:
                return fail(o,8)
            if a<b:
                decided=1
            i=i+1
        if decided==0:
            return fail(o,8)
        return integer_size(o,w)
    if phase==110:
        error=typed_string_bytes(o,RP+8192,get(o,SCALAR_N))
        if error==64:
            return provider_failure(o,65)
        if error!=0:
            return fail(o,error)
        return after_size(o,w)
    return BAD

def integer_size(o:mutbuf,w:mutbuf) -> u32:
    n=get(o,SCALAR_N)
    digits=n-get(o,SIGNED)
    limit=get(o,LIMIT)
    if limit!=0 and digits>limit:
        return fail(o,9)
    put(o,SIZE,get(o,SIZE)+n)
    return after_size(o,w)

def typed_string_bytes(o:mutbuf,at:u64,n:u64) -> u64:
    remaining=MAX_BYTES-get(o,SIZE)
    total=2
    i=0
    while i<n:
        ch=byte(o,at+i)
        width=typed_utf8_width(o,at+i,n-i)
        if width==0:
            return 64
        if ch<32:
            if ch==8 or ch==9 or ch==10 or ch==12 or ch==13:
                total=total+2
            else:
                total=total+6
        elif ch==34 or ch==92:
            total=total+2
        elif width==3 and ch==237 and byte(o,at+i+1)>=160:
            return 6
        else:
            total=total+width
        if total>remaining:
            return 7
        i=i+width
    put(o,SIZE,get(o,SIZE)+total)
    return 0

def building(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(o,BUILD_INDEX)==0:
            within(o,ROOT,NODES+48,24)
            zero(o,NODES+48,24)
            return begin_cleanup(o)
        index=get(o,BUILD_INDEX)-1
        put(o,BUILD_INDEX,index)
        row=node(index)
        kind=get(o,row+72)
        if kind!=5 and kind!=6:
            within(o,row+48,row,24)
            zero(o,row,24)
            return again(o,200)
        request(o,choose(kind==5,3,4))
        return invoke(o,w,201)
    if phase==201:
        if value_ok(o)==False:
            return provider_failure(o,0)
        row=node(get(o,BUILD_INDEX))
        within(o,row+48,RP+24,24)
        put(o,BUILD_CHILD,0)
        return again(o,202)
    if phase==202:
        row=node(get(o,BUILD_INDEX))
        index=get(o,BUILD_CHILD)
        if index==get(o,row+112):
            return again(o,200)
        child=node(get(o,row+104)+index)
        request(o,choose(get(o,row+72)==5,16,10))
        within(o,RQ+24,row+48,24)
        if get(o,row+72)==6:
            within(o,RQ+48,child+24,24)
            within(o,RQ+72,child+48,24)
        else:
            within(o,RQ+48,child+48,24)
        return invoke(o,w,203)
    if phase==203:
        if value_ok(o)==False:
            return provider_failure(o,0)
        put(o,BUILD_CHILD,get(o,BUILD_CHILD)+1)
        return again(o,202)
    return BAD

def fail(o:mutbuf,error:u64) -> u32:
    put(o,ERR,error)
    return begin_cleanup(o)

def provider_failure(o:mutbuf,status:u64) -> u32:
    put(o,ERR,1000)
    put(o,PROVIDER_ERROR,choose(status==0,get(o,RP+8),status))
    within(o,LIVE_ERROR,RP,128)
    if get(o,OVERFLOW_N)!=0:
        put(o,DROP_INDEX,0)
        put(o,DROP_SLOT,0)
        return again(o,330)
    return begin_cleanup(o)

def begin_cleanup(o:mutbuf) -> u32:
    put(o,DROP_INDEX,0)
    put(o,DROP_SLOT,0)
    return again(o,300)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,DROP_INDEX)==get(o,ALLOCATED):
            return finish(o)
        row=node(get(o,DROP_INDEX))+get(o,DROP_SLOT)*24
        if get(o,row)==0:
            return next_drop(o)
        request(o,6)
        within(o,RQ+24,row,24)
        return invoke(o,w,301)
    if phase==301:
        if get(o,MODERN)!=0:
            at=node(get(o,DROP_INDEX))+get(o,DROP_SLOT)*24
            released=release_value(o,at)
            if released==0 or get(o,VALUE_PENDING)!=0:
                return release_blocked(o)
            return next_drop(o)
        if value_ok(o)==False:
            put(o,CLEANUP_ERRORS,get(o,CLEANUP_ERRORS)+1)
        else:
            zero(o,node(get(o,DROP_INDEX))+get(o,DROP_SLOT)*24,24)
        return next_drop(o)
    if phase==330:
        if get(o,DROP_INDEX)==get(o,OVERFLOW_N):
            if get(o,CLEANUP_ERRORS)==0:
                put(o,OVERFLOW_N,0)
            return begin_cleanup(o)
        entry=RP+8192+get(o,DROP_INDEX)*64
        at=choose(get(o,DROP_SLOT)==0,entry+16,entry+40)
        if get(o,at)==0:
            return overflow_next(o)
        within(o,896,at,24)
        request(o,6)
        within(o,RQ+24,896,24)
        return invoke_overflow(o,w,331)
    if phase==331:
        if get(o,MODERN)!=0:
            entry=RP+8192+get(o,DROP_INDEX)*64
            at=choose(get(o,DROP_SLOT)==0,entry+16,entry+40)
            released=release_value(o,at)
            if released==0 or get(o,VALUE_PENDING)!=0:
                return release_blocked(o)
            return overflow_next(o)
        if value_ok(o)==False:
            put(o,CLEANUP_ERRORS,get(o,CLEANUP_ERRORS)+1)
        else:
            entry=RP+8192+get(o,DROP_INDEX)*64
            zero(o,choose(get(o,DROP_SLOT)==0,entry+16,entry+40),24)
        return overflow_next(o)
    if phase==310:
        if release_value_retry(o)==0:
            return release_blocked(o)
        return again(o,choose(get(o,OVERFLOW_N)!=0,330,300))
    return BAD

def release_blocked(o:mutbuf) -> u32:
    put(o,CLEANUP_ERRORS,1)
    put(o,QUARANTINE_KIND,choose(get(o,DROP_KNOWN)==1,1,2))
    return finish(o)

def next_drop(o:mutbuf) -> u32:
    slot=get(o,DROP_SLOT)+1
    if slot==3:
        slot=0
        put(o,DROP_INDEX,get(o,DROP_INDEX)+1)
    put(o,DROP_SLOT,slot)
    return again(o,300)

def overflow_next(o:mutbuf) -> u32:
    slot=get(o,DROP_SLOT)+1
    if slot==2:
        slot=0
        put(o,DROP_INDEX,get(o,DROP_INDEX)+1)
    put(o,DROP_SLOT,slot)
    return again(o,330)

def request(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    if get(o,MODERN)!=0 and (op==6 or op==31):
        put(o,RQ,VALUE_DROP_INPUT)
        put(o,RQ+8,choose(op==6,29,31))
        release_begin(o)
    return 0

def invoke(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,get(w,8))
    put(o,8,51)
    put(o,16,RQ)
    put(o,24,128)
    put(o,32,RP)
    put(o,40,OUTPUT-RP)
    put(o,48,get(w,16))
    put(o,56,get(w,24))
    return 4

def invoke_overflow(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,get(w,8))
    put(o,8,51)
    put(o,16,RQ)
    put(o,24,128)
    put(o,32,RP)
    put(o,40,8192)
    put(o,48,get(w,16))
    put(o,56,get(w,24))
    return 4

def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VREPLY and get(o,RP+8)==0

def finish(o:mutbuf) -> u32:
    put(o,512,0)
    error=get(o,ERR)
    zero(o,0,128)
    put(o,0,choose(get(o,MODERN)!=0,NEW_REPLY,REPLY))
    put(o,8,choose(get(o,CLEANUP_ERRORS)!=0,3,choose(error>=1000,2,choose(error==0,0,1))))
    put(o,16,error)
    within(o,24,ROOT,24)
    put(o,48,get(o,VISITED))
    put(o,56,get(o,SIZE))
    put(o,64,get(o,ALLOCATED))
    put(o,72,get(o,MODE))
    put(o,80,get(o,PASS))
    put(o,88,get(o,LIMIT))
    put(o,96,get(o,PROVIDER_ERROR))
    put(o,104,get(o,CLEANUP_ERRORS))
    if get(o,MODERN)!=0 and get(o,CLEANUP_ERRORS)!=0:
        put(o,112,get(o,QUARANTINE_KIND))
        put(o,120,get(o,VALUE_PENDING))
    return 0

def node(index:u64) -> u64:
    return NODES+index*STRIDE
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10
def within(o:mutbuf,to:u64,src:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,src+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,o:mutbuf,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dest+i,byte(s,at+i))
        i=i+1
    return 0

def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    if get(o,FEEDBACK)!=0 or get(o,at)!=magic:
        return 0
    return 1

'''
SOURCE += '\n' + retirement_source('release_begin', 'release_value', 'release_value_retry')
def source_program():
    tree=ast.parse(structural)
    helpers=[]
    for f in tree.body:
        if f.name in {'read64','get','put','zero','choose'}:helpers.append(ast.unparse(f))
        if f.name=='utf8_width':helpers.append(ast.unparse(f).replace('utf8_width','typed_utf8_width').replace('s: readbuf','s: mutbuf'))
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'
    # No recursion or calls to the HIA semantic compiler exist at runtime.
    text=text.replace('    if phase==40:\n','    if phase==42:\n        if get(o,PASS)!=1 and get(o,SIZE)>MAX_BYTES:\n            return fail(o,7)\n        return descend(o,w)\n    if phase==40:\n')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_value_structure')
def main():
    tree=program();target=ROOT/'examples/hia_bootstrap/background_optimizer_value_structure.hepta';target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
