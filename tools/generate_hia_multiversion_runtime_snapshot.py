"""Pure detached MV snapshot / retirement JSON from captured native facts.

The envelope is a private fixed-producer interface. It cannot grant retirement,
publication, proof, or filesystem authority. All counts remain decimal strings
until emitted; only bounded record extents are represented by machine words.
"""
from pathlib import Path
import ast,json,os,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C={'NONE':(1<<64)-1,'MAGIC':int.from_bytes(b'HIAMVSP1','little'),'STATE_MAGIC':int.from_bytes(b'HIARSTA1','little')}
SOURCE=r'''
def runtime_snapshot(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<65536:
        if length(w)>=16:
            put(w,8,65536)
        return 4294967292
    zero(w,0,256)
    put(w,8,65536)
    if length(s)<96:
        invalid(w,0,1)
        return 4294967293
    if word(s,0)!=MAGIC or word(s,16)!=length(s)-64:
        invalid(w,0,2)
        return 4294967293
    i=24
    while i<64:
        if word(s,i)!=0:
            invalid(w,i,3)
            return 4294967293
        i=i+8
    kind=word(s,8)
    if kind<1 or (kind>7 and kind!=12) or word(s,64)!=kind:
        invalid(w,8,4)
        return 4294967293
    initialize(w)
    render_root(s,o,w,64,length(s)-64,kind)
    if get(w,48)!=0:
        return choose(get(w,48)==2,4294967292,4294967293)
    required=get(w,32)
    put(w,0,required)
    if required>length(o):
        return 4294967294
    put(w,32,0)
    put(w,40,1)
    render_root(s,o,w,64,length(s)-64,kind)
    if get(w,48)!=0 or get(w,32)!=required:
        return 4294967293
    return 0

def render_root(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64,kind:u64) -> u64:
    if kind==1:
        snapshot(s,o,w,p,n)
    elif kind==2:
        cleanup(s,o,w,p,n)
    elif kind==3:
        pin(s,o,w,p,n)
    elif kind==4:
        task(s,o,w,p,n)
    elif kind==5:
        observation(s,o,w,p,n)
    elif kind==6:
        directory(s,o,w,p,n)
    else:
        error_record(s,o,w,p,n)
    return 0

def invalid(w:mutbuf,at:u64,reason:u64) -> u64:
    if get(w,48)==0:
        put(w,16,at)
        put(w,24,reason)
        put(w,48,1)
    return NONE

def frame(s:readbuf,w:mutbuf,p:u64,n:u64,kind:u64,count:u64,allowed:u64) -> bool:
    if p>length(s) or n>length(s)-p or n<32:
        invalid(w,p,10)
        return False
    if word(s,p)!=kind or word(s,p+24)!=n or (word(s,p+8)&(NONE^allowed))!=0:
        invalid(w,p,11)
        return False
    fields=word(s,p+16)
    if count!=NONE and count!=fields:
        invalid(w,p+16,12)
        return False
    if fields>(n-32)//16:
        invalid(w,p+16,13)
        return False
    cursor=32+fields*16
    i=0
    while i<fields:
        q=p+32+i*16
        at=word(s,q)
        size=word(s,q+8)
        if at!=cursor or size>n-cursor:
            invalid(w,q,14)
            return False
        cursor=cursor+size
        i=i+1
    if cursor!=n:
        invalid(w,p+24,15)
        return False
    return True

def fp(s:readbuf,p:u64,index:u64) -> u64:
    return p+word(s,p+32+index*16)

def fn(s:readbuf,p:u64,index:u64) -> u64:
    return word(s,p+40+index*16)

def decimal(s:readbuf,w:mutbuf,p:u64,n:u64,signed:bool) -> bool:
    if n==0 or p>length(s) or n>length(s)-p:
        invalid(w,p,20)
        return False
    at=p
    end=p+n
    if signed and byte(s,at)==45:
        at=at+1
        if at==end or byte(s,at)==48:
            invalid(w,p,21)
            return False
    if end-at>1 and byte(s,at)==48:
        invalid(w,p,22)
        return False
    while at<end:
        x=byte(s,at)
        if x<48 or x>57:
            invalid(w,at,23)
            return False
        at=at+1
    return True

def number_field(s:readbuf,o:mutbuf,w:mutbuf,p:u64,index:u64,optional:bool,signed:bool) -> u64:
    at=fp(s,p,index)
    n=fn(s,p,index)
    if optional and n==0:
        LIT(o,w,"null")
    elif decimal(s,w,at,n,signed):
        raw(s,o,w,at,n)
    return 0

def equal(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> bool:
    if an!=bn:
        return False
    i=0
    while i<an:
        if byte(s,a+i)!=byte(s,b+i):
            return False
        i=i+1
    return True

def raw(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    at=get(w,32)
    if n>NONE-at:
        invalid(w,p,24)
        return 0
    if get(w,40)!=0:
        i=0
        while i<n:
            store(o,at+i,byte(s,p+i))
            i=i+1
    put(w,32,at+n)
    return 0

def emit(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(w,32)
    if at==NONE:
        invalid(w,0,25)
        return 0
    if get(w,40)!=0:
        store(o,at,value)
    put(w,32,at+1)
    return 0

def literal(o:mutbuf,w:mutbuf,index:u64) -> u64:
    p=get(w,8192+index*16)
    n=get(w,8200+index*16)
    i=0
    while i<n:
        emit(o,w,byte(w,16384+p+i))
        i=i+1
    return 0

def boolean(o:mutbuf,w:mutbuf,flag:bool) -> u64:
    if flag:
        LIT(o,w,"true")
    else:
        LIT(o,w,"false")
    return 0

def uint(o:mutbuf,w:mutbuf,value:u64) -> u64:
    count=0
    x=value
    while x>=10:
        store(w,128+count,x%10+48)
        count=count+1
        x=x//10
    emit(o,w,x+48)
    while count>0:
        count=count-1
        emit(o,w,byte(w,128+count))
    return 0

def inode(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if n==0:
        LIT(o,w,"null")
    elif n==16:
        emit(o,w,91)
        uint(o,w,word(s,p))
        emit(o,w,44)
        uint(o,w,word(s,p+8))
        emit(o,w,93)
    else:
        invalid(w,p,26)
    return 0

def decode(s:readbuf,w:mutbuf,at:u64,end:u64,filesystem:bool) -> u64:
    put(w,64,1)
    first=byte(s,at)
    if first<128:
        return first
    if first<194 or first>244:
        return bad_decode(w,at,first,filesystem)
    width=choose(first<224,2,choose(first<240,3,4))
    if width>end-at:
        return bad_decode(w,at,first,filesystem)
    cp=first&choose(width==2,31,choose(width==3,15,7))
    i=1
    while i<width:
        b=byte(s,at+i)
        if b<128 or b>191:
            return bad_decode(w,at,first,filesystem)
        if i==1 and ((first==224 and b<160) or (first==240 and b<144) or (first==244 and b>143) or (filesystem and first==237 and b>=160)):
            return bad_decode(w,at,first,filesystem)
        cp=(cp<<6)|(b&63)
        i=i+1
    put(w,64,width)
    return cp

def bad_decode(w:mutbuf,at:u64,first:u64,filesystem:bool) -> u64:
    if filesystem:
        return 56320+first
    invalid(w,at,30)
    return 0

def hex4(o:mutbuf,w:mutbuf,cp:u64) -> u64:
    emit(o,w,92)
    emit(o,w,117)
    i=4
    while i>0:
        i=i-1
        d=(cp>>(i*4))&15
        emit(o,w,choose(d<10,48+d,87+d))
    return 0

def json_cp(o:mutbuf,w:mutbuf,cp:u64) -> u64:
    if cp==34 or cp==92:
        emit(o,w,92)
        emit(o,w,cp)
    elif cp==8 or cp==9 or cp==10 or cp==12 or cp==13:
        emit(o,w,92)
        emit(o,w,choose(cp==8,98,choose(cp==9,116,choose(cp==10,110,choose(cp==12,102,114)))))
    elif cp>=32 and cp<127:
        emit(o,w,cp)
    elif cp<65536:
        hex4(o,w,cp)
    else:
        x=cp-65536
        hex4(o,w,55296+(x>>10))
        hex4(o,w,56320+(x&1023))
    return 0

def string(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64,filesystem:bool,limit:u64) -> u64:
    emit(o,w,34)
    at=p
    end=p+n
    count=0
    while at<end:
        cp=decode(s,w,at,end,filesystem)
        if count<limit:
            json_cp(o,w,cp)
        count=count+1
        at=at+get(w,64)
    emit(o,w,34)
    return 0

def string_field(s:readbuf,o:mutbuf,w:mutbuf,p:u64,index:u64,filesystem:bool) -> u64:
    return string(s,o,w,fp(s,p,index),fn(s,p,index),filesystem,NONE)

def printable(w:mutbuf,cp:u64) -> bool:
    lo=0
    hi=PRINTABLE_COUNT
    while lo<hi:
        middle=(lo+hi)>>1
        pair=get(w,49152+(middle>>1)*8)
        value=(pair>>((middle&1)*32))&4294967295
        lower=value&2097151
        upper=lower+(value>>21)
        if cp<lower:
            hi=middle
        elif cp>upper:
            lo=middle+1
        else:
            return True
    return False

def message_cp(o:mutbuf,w:mutbuf,cp:u64) -> u64:
    count=get(w,112)
    if count<1024:
        json_cp(o,w,cp)
        put(w,112,count+1)
    return 0

def message_literal(o:mutbuf,w:mutbuf,index:u64) -> u64:
    p=get(w,8192+index*16)
    n=get(w,8200+index*16)
    i=0
    while i<n:
        message_cp(o,w,byte(w,16384+p+i))
        i=i+1
    return 0

def message_digits(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    i=0
    while i<n:
        message_cp(o,w,byte(s,p+i))
        i=i+1
    return 0

def message_hex(o:mutbuf,w:mutbuf,cp:u64,count:u64) -> u64:
    i=count
    while i>0:
        i=i-1
        d=(cp>>(i*4))&15
        message_cp(o,w,choose(d<10,48+d,87+d))
    return 0

def repr_path(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    single=False
    double=False
    i=0
    while i<n:
        b=byte(s,p+i)
        if b==39:
            single=True
        if b==34:
            double=True
        i=i+1
    quote=choose(single and double==False,34,39)
    message_cp(o,w,quote)
    at=p
    end=p+n
    while at<end:
        cp=decode(s,w,at,end,True)
        if cp==quote or cp==92:
            message_cp(o,w,92)
            message_cp(o,w,cp)
        elif cp==9 or cp==10 or cp==13:
            message_cp(o,w,92)
            message_cp(o,w,choose(cp==9,116,choose(cp==10,110,114)))
        elif printable(w,cp):
            message_cp(o,w,cp)
        else:
            message_cp(o,w,92)
            if cp<256:
                message_cp(o,w,120)
                message_hex(o,w,cp,2)
            elif cp<65536:
                message_cp(o,w,117)
                message_hex(o,w,cp,4)
            else:
                message_cp(o,w,85)
                message_hex(o,w,cp,8)
        at=at+get(w,64)
    message_cp(o,w,quote)
    return 0

def opaque(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64,object_only:bool) -> u64:
    if n==0:
        invalid(w,p,31)
        return 0
    if object_only and (n<2 or byte(s,p)!=123 or byte(s,p+n-1)!=125):
        invalid(w,p,32)
        return 0
    raw(s,o,w,p,n)
    return 0

def json_list(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64,bounded:bool) -> u64:
    if frame(s,w,p,n,10,NONE,0)==False:
        return 0
    count=word(s,p+16)
    if bounded and count>128:
        invalid(w,p,33)
        return 0
    emit(o,w,91)
    i=0
    while i<count:
        if i!=0:
            emit(o,w,44)
        opaque(s,o,w,fp(s,p,i),fn(s,p,i),False)
        i=i+1
    emit(o,w,93)
    return 0

def error_field(s:readbuf,o:mutbuf,w:mutbuf,p:u64,index:u64) -> u64:
    n=fn(s,p,index)
    if n==0:
        LIT(o,w,"null")
    else:
        error_record(s,o,w,fp(s,p,index),n)
    return 0

def error_record(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if n<32:
        invalid(w,p,34)
        return 0
    kind=word(s,p)
    if kind==11:
        if frame(s,w,p,n,11,1,0):
            opaque(s,o,w,fp(s,p,0),fn(s,p,0),True)
        return 0
    if kind==12:
        return os_error(s,o,w,p,n)
    if frame(s,w,p,n,7,3,0)==False:
        return 0
    LIT(o,w,"{\"type\":")
    string_field(s,o,w,p,0,False)
    LIT(o,w,",\"errno\":")
    number_field(s,o,w,p,1,True,True)
    LIT(o,w,",\"message\":")
    string(s,o,w,fp(s,p,2),fn(s,p,2),False,1024)
    emit(o,w,125)
    return 0

def os_error(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,12,2,1)==False:
        return 0
    at=fp(s,p,0)
    count=fn(s,p,0)
    if decimal(s,w,at,count,True)==False:
        return 0
    code=134
    if count<=3 and byte(s,at)!=45:
        code=0
        i=0
        while i<count:
            code=code*10+byte(s,at+i)-48
            i=i+1
    LIT(o,w,"{\"type\":")
    errno_type(o,w,code)
    LIT(o,w,",\"errno\":")
    raw(s,o,w,at,count)
    LIT(o,w,",\"message\":\"")
    put(w,112,0)
    MLIT(o,w,"[Errno ")
    message_digits(s,o,w,at,count)
    MLIT(o,w,"] ")
    if code<=133:
        errno_message(o,w,code)
    else:
        MLIT(o,w,"Unknown error ")
        message_digits(s,o,w,at,count)
    if word(s,p+8)!=0:
        MLIT(o,w,": ")
        repr_path(s,o,w,fp(s,p,1),fn(s,p,1))
    elif fn(s,p,1)!=0:
        invalid(w,fp(s,p,1),35)
    LIT(o,w,"\"}")
    return 0

def state(s:readbuf,w:mutbuf,p:u64,n:u64) -> bool:
    if n!=4608 or word(s,p)!=STATE_MAGIC:
        invalid(w,p,40)
        return False
    if word(s,p+24)>1 or word(s,p+32)>1 or word(s,p+40)>1 or word(s,p+56)>1 or word(s,p+80)>1 or word(s,p+88)>1 or word(s,p+176)>1 or word(s,p+320)>1 or word(s,p+344)>1:
        invalid(w,p,41)
        return False
    if word(s,p+96)>3 or word(s,p+184)>3 or word(s,p+192)>3 or word(s,p+232)>6:
        invalid(w,p,42)
        return False
    return True

def status(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value==0:
        LIT(o,w,"\"not_acquired\"")
    elif value==1:
        LIT(o,w,"\"open\"")
    elif value==2:
        LIT(o,w,"\"unknown\"")
    else:
        LIT(o,w,"\"closed\"")
    return 0

def observed_status(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value==0:
        LIT(o,w,"\"pending\"")
    elif value==1:
        LIT(o,w,"\"absent\"")
    elif value==2:
        LIT(o,w,"\"owned_present\"")
    elif value==3:
        LIT(o,w,"\"replaced\"")
    elif value==4:
        LIT(o,w,"\"unbound\"")
    elif value==5:
        LIT(o,w,"\"recreated_after_release\"")
    else:
        LIT(o,w,"\"error\"")
    return 0

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def choose(condition:bool,a:u64,b:u64) -> u64:
    if condition:
        return a
    return b

def zero(w:mutbuf,p:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,p+i,0)
        i=i+1
    return 0
'''

SOURCE+=r'''
def pin(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,3,7,31)==False:
        return 0
    q=fp(s,p,1)
    if state(s,w,q,fn(s,p,1))==False:
        return 0
    flags=word(s,p+8)
    if fn(s,p,4)==0 and (fn(s,p,5)!=0 or fn(s,p,6)!=0):
        invalid(w,p,43)
        return 0
    LIT(o,w,"{\"path\":")
    string_field(s,o,w,p,0,True)
    LIT(o,w,",\"directory\":")
    boolean(o,w,word(s,q+24)!=0)
    LIT(o,w,",\"inode\":")
    inode(s,o,w,q+64,choose(word(s,q+56)!=0,16,0))
    LIT(o,w,",\"acquisition_attempted\":")
    boolean(o,w,word(s,q+32)!=0)
    LIT(o,w,",\"acquisition_error\":")
    error_field(s,o,w,p,2)
    LIT(o,w,",\"identity_bound\":")
    boolean(o,w,word(s,q+56)!=0)
    LIT(o,w,",\"identity_fd_held\":")
    boolean(o,w,(flags&2)!=0)
    LIT(o,w,",\"path_released\":")
    boolean(o,w,word(s,q+80)!=0)
    LIT(o,w,",\"close_attempted\":")
    boolean(o,w,word(s,q+88)!=0)
    LIT(o,w,",\"close\":")
    pin_close(s,o,w,p,q,flags)
    LIT(o,w,",\"release_succeeded\":")
    boolean(o,w,(flags&1)!=0)
    LIT(o,w,",\"close_retry_permitted\":false,\"rebind_permitted\":false")
    if fn(s,p,5)!=0:
        LIT(o,w,",\"quarantined_open_result\":")
        opaque(s,o,w,fp(s,p,5),fn(s,p,5),False)
    if fn(s,p,6)!=0:
        LIT(o,w,",\"foreign_open_result_slot\":")
        opaque(s,o,w,fp(s,p,6),fn(s,p,6),True)
    policy_error(s,o,w,p)
    emit(o,w,125)
    return 0

def pin_close(s:readbuf,o:mutbuf,w:mutbuf,p:u64,q:u64,flags:u64) -> u64:
    LIT(o,w,"{\"status\":")
    status(o,w,word(s,q+96))
    if word(s,q+88)!=0:
        LIT(o,w,",\"attempted_ns\":")
        uint(o,w,word(s,q+328))
    if (flags&16)==0 and fn(s,p,3)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,3)
    if word(s,q+344)!=0:
        LIT(o,w,",\"finished_ns\":")
        uint(o,w,word(s,q+336))
    if (flags&16)!=0 and fn(s,p,3)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,3)
    emit(o,w,125)
    return 0

def policy_error(s:readbuf,o:mutbuf,w:mutbuf,p:u64) -> u64:
    if fn(s,p,4)!=0:
        LIT(o,w,",\"native_policy_error\":")
        error_field(s,o,w,p,4)
        LIT(o,w,",\"native_policy_fields_are_last_attested\":true")
    return 0

def observation(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,5,4,23)==False:
        return 0
    flags=word(s,p+8)
    if (flags&7)>6:
        invalid(w,p,44)
        return 0
    LIT(o,w,"{\"path\":")
    string_field(s,o,w,p,0,True)
    LIT(o,w,",\"observed_ns\":")
    number_field(s,o,w,p,1,False,False)
    if fn(s,p,2)!=0:
        LIT(o,w,",\"actual_inode\":")
        inode(s,o,w,fp(s,p,2),fn(s,p,2))
    if (flags&16)!=0 and fn(s,p,3)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,3)
    LIT(o,w,",\"status\":")
    observed_status(o,w,flags&7)
    if (flags&16)==0 and fn(s,p,3)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,3)
    emit(o,w,125)
    return 0

def directory(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,6,6,23)==False:
        return 0
    flags=word(s,p+8)
    status=flags&7
    if status==0:
        i=0
        while i<6:
            if fn(s,p,i)!=0:
                invalid(w,p,45)
                return 0
            i=i+1
        LIT(o,w,"{\"status\":\"not_attempted\"}")
        return 0
    if status!=1 and status!=3 and status!=4 and status!=5:
        invalid(w,p,46)
        return 0
    LIT(o,w,"{\"path\":")
    string_field(s,o,w,p,0,True)
    LIT(o,w,",\"attempted_ns\":")
    number_field(s,o,w,p,1,False,False)
    LIT(o,w,",\"before\":")
    observation(s,o,w,fp(s,p,2),fn(s,p,2))
    if (flags&16)!=0 and fn(s,p,5)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,5)
    LIT(o,w,",\"status\":")
    if status==1:
        LIT(o,w,"\"already_absent\"")
    elif status==3:
        LIT(o,w,"\"refused_unowned_or_unobservable\"")
    elif status==4:
        LIT(o,w,"\"removed\"")
    else:
        LIT(o,w,"\"error\"")
    if (flags&16)==0 and fn(s,p,5)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,5)
    LIT(o,w,",\"after\":")
    observation(s,o,w,fp(s,p,3),fn(s,p,3))
    LIT(o,w,",\"identity_pin\":")
    if fn(s,p,4)!=0:
        pin(s,o,w,fp(s,p,4),fn(s,p,4))
    else:
        LIT(o,w,"null")
    emit(o,w,125)
    return 0

def task(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,4,12,31)==False:
        return 0
    q=fp(s,p,3)
    if state(s,w,q,fn(s,p,3))==False:
        return 0
    flags=word(s,p+8)
    LIT(o,w,"{\"generation\":")
    number_field(s,o,w,p,0,False,False)
    LIT(o,w,",\"cause\":")
    string_field(s,o,w,p,1,False)
    LIT(o,w,",\"artifact\":")
    string_field(s,o,w,p,2,True)
    LIT(o,w,",\"recorded_inode\":")
    inode(s,o,w,fp(s,p,11),fn(s,p,11))
    LIT(o,w,",\"native_attempted\":")
    boolean(o,w,word(s,q+176)!=0)
    LIT(o,w,",\"native_release_succeeded\":")
    boolean(o,w,(flags&4)!=0)
    LIT(o,w,",\"native\":")
    task_native(s,o,w,p,q)
    LIT(o,w,",\"disk\":")
    task_disk(s,o,w,p,q)
    LIT(o,w,",\"artifact_identity_pin\":")
    pin(s,o,w,fp(s,p,4),fn(s,p,4))
    LIT(o,w,",\"disk_attempts\":")
    number_field(s,o,w,p,5,False,False)
    LIT(o,w,",\"complete\":")
    boolean(o,w,(flags&8)!=0)
    LIT(o,w,",\"native_retry_permitted\":false")
    if fn(s,p,10)!=0:
        LIT(o,w,",\"quarantined_foreign_resources\":")
        opaque(s,o,w,fp(s,p,10),fn(s,p,10),True)
    if get(w,48)==0:
        policy_error(s,o,w,fp(s,p,4))
    emit(o,w,125)
    return 0

def task_native(s:readbuf,o:mutbuf,w:mutbuf,p:u64,q:u64) -> u64:
    if word(s,q+176)==0:
        if fn(s,p,6)!=0 or fn(s,p,7)!=0:
            invalid(w,p,47)
        LIT(o,w,"{}")
        return 0
    LIT(o,w,"{\"attempted_ns\":")
    uint(o,w,word(s,q+304))
    LIT(o,w,",\"library\":{\"status\":")
    status(o,w,word(s,q+184))
    if fn(s,p,6)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,6)
    LIT(o,w,"},\"fd\":{\"status\":")
    status(o,w,word(s,q+192))
    if fn(s,p,7)!=0:
        LIT(o,w,",\"error\":")
        error_field(s,o,w,p,7)
    emit(o,w,125)
    if word(s,q+320)!=0:
        LIT(o,w,",\"finished_ns\":")
        uint(o,w,word(s,q+312))
    emit(o,w,125)
    return 0

def task_disk(s:readbuf,o:mutbuf,w:mutbuf,p:u64,q:u64) -> u64:
    at=fp(s,p,5)
    n=fn(s,p,5)
    if decimal(s,w,at,n,False)==False:
        return 0
    started=n!=1 or byte(s,at)!=48
    emit(o,w,123)
    if started:
        LIT(o,w,"\"attempted_ns\":")
        uint(o,w,word(s,q+352))
        if fn(s,p,8)!=0:
            LIT(o,w,",\"before\":")
            observation(s,o,w,fp(s,p,8),fn(s,p,8))
    elif fn(s,p,8)!=0:
        invalid(w,p,48)
    status=word(s,q+232)
    if status!=6:
        if started:
            emit(o,w,44)
        LIT(o,w,"\"status\":")
        disk_status(o,w,status)
    if fn(s,p,9)!=0:
        if started or status!=6:
            emit(o,w,44)
        LIT(o,w,"\"error\":")
        error_field(s,o,w,p,9)
    emit(o,w,125)
    return 0

def disk_status(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value==0:
        LIT(o,w,"\"not_attempted\"")
    elif value==1:
        LIT(o,w,"\"absent\"")
    elif value==2:
        LIT(o,w,"\"blocked_by_uncertain_native_release\"")
    elif value==3:
        LIT(o,w,"\"refused_unowned\"")
    elif value==4:
        LIT(o,w,"\"removed\"")
    else:
        LIT(o,w,"\"error\"")
    return 0

def compare(s:readbuf,a:u64,b:u64,key:u64) -> u64:
    ap=fp(s,a,key)
    an=fn(s,a,key)
    bp=fp(s,b,key)
    bn=fn(s,b,key)
    if an<bn:
        return 0
    if an>bn:
        return 2
    i=0
    while i<an:
        av=byte(s,ap+i)
        bv=byte(s,bp+i)
        if av<bv:
            return 0
        if av>bv:
            return 2
        i=i+1
    return 1

def sorted_array(s:readbuf,w:mutbuf,p:u64,n:u64,kind:u64,fields:u64,key:u64) -> bool:
    if frame(s,w,p,n,9,NONE,0)==False:
        return False
    count=word(s,p+16)
    if count>(NONE-65536)//16:
        invalid(w,p,50)
        return False
    needed=65536+count*16
    if needed>get(w,8):
        put(w,8,needed)
    if needed>length(w):
        put(w,48,2)
        return False
    i=0
    while i<count:
        child=fp(s,p,i)
        size=fn(s,p,i)
        if frame(s,w,child,size,kind,fields,choose(kind==8,1,31))==False:
            return False
        if decimal(s,w,fp(s,child,key),fn(s,child,key),False)==False:
            return False
        put(w,65536+i*8,child)
        i=i+1
    width=1
    source=65536
    target=65536+count*8
    while width<count:
        left=0
        while left<count:
            middle=left+choose(width<count-left,width,count-left)
            right=middle+choose(width<count-middle,width,count-middle)
            merge(s,w,source,target,left,middle,right,key)
            left=right
        swap=source
        source=target
        target=swap
        if width>count//2:
            width=count
        else:
            width=width*2
    if source!=65536:
        i=0
        while i<count:
            put(w,65536+i*8,get(w,source+i*8))
            i=i+1
    i=1
    while i<count:
        if compare(s,get(w,65536+(i-1)*8),get(w,65536+i*8),key)==1:
            invalid(w,p,51)
            return False
        i=i+1
    return True

def merge(s:readbuf,w:mutbuf,source:u64,target:u64,left:u64,middle:u64,right:u64,key:u64) -> u64:
    a=left
    b=middle
    out=left
    while out<right:
        take=False
        if a<middle:
            if b==right:
                take=True
            elif compare(s,get(w,source+a*8),get(w,source+b*8),key)!=2:
                take=True
        if take:
            put(w,target+out*8,get(w,source+a*8))
            a=a+1
        else:
            put(w,target+out*8,get(w,source+b*8))
            b=b+1
        out=out+1
    return 0

def generation(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,8,5,1)==False:
        return 0
    info=fp(s,p,0)
    size=fn(s,p,0)
    if size<16 or byte(s,info)!=123 or byte(s,info+size-1)!=125:
        invalid(w,p,52)
        return 0
    expected=fp(s,p,1)
    en=fn(s,p,1)
    if decimal(s,w,expected,en,False)==False:
        return 0
    if info_prefix(s,info,size,expected,en)==False:
        invalid(w,info,53)
        return 0
    raw(s,o,w,info,size-1)
    LIT(o,w,",\"active_leases\":")
    number_field(s,o,w,p,2,False,False)
    LIT(o,w,",\"retired\":")
    boolean(o,w,word(s,p+8)!=0)
    LIT(o,w,",\"artifact_identity_pin\":")
    pin(s,o,w,fp(s,p,3),fn(s,p,3))
    LIT(o,w,",\"totality_evidence\":")
    json_list(s,o,w,fp(s,p,4),fn(s,p,4),False)
    emit(o,w,125)
    return 0

def info_prefix(s:readbuf,p:u64,n:u64,key:u64,kn:u64) -> bool:
    if kn>n or n-kn<15:
        return False
    if byte(s,p)!=123 or byte(s,p+1)!=34 or byte(s,p+2)!=103 or byte(s,p+3)!=101 or byte(s,p+4)!=110 or byte(s,p+5)!=101 or byte(s,p+6)!=114 or byte(s,p+7)!=97 or byte(s,p+8)!=116 or byte(s,p+9)!=105 or byte(s,p+10)!=111 or byte(s,p+11)!=110 or byte(s,p+12)!=34 or byte(s,p+13)!=58:
        return False
    if equal(s,p+14,kn,key,kn)==False:
        return False
    return byte(s,p+14+kn)==44 or byte(s,p+14+kn)==125

def snapshot(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,1,6,1)==False:
        return 0
    gp=fp(s,p,3)
    gn=fn(s,p,3)
    if sorted_array(s,w,gp,gn,8,5,1)==False:
        return 0
    count=word(s,gp+16)
    cp=fp(s,p,5)
    cn=fn(s,p,5)
    if frame(s,w,cp,cn,2,6,3)==False:
        return 0
    if (word(s,cp+8)&1)!=word(s,p+8) or ((word(s,cp+8)&2)!=0)!=(count==0):
        invalid(w,cp,54)
        return 0
    LIT(o,w,"{\"schema\":")
    string_field(s,o,w,p,0,False)
    LIT(o,w,",\"closed\":")
    boolean(o,w,word(s,p+8)!=0)
    LIT(o,w,",\"selection_epoch\":")
    number_field(s,o,w,p,1,False,False)
    LIT(o,w,",\"current_generation\":")
    number_field(s,o,w,p,2,True,False)
    LIT(o,w,",\"generations\":[")
    i=0
    while i<count:
        if i!=0:
            emit(o,w,44)
        child=get(w,65536+i*8)
        generation(s,o,w,child,word(s,child+24))
        i=i+1
    LIT(o,w,"],\"recent_events\":")
    json_list(s,o,w,fp(s,p,4),fn(s,p,4),True)
    LIT(o,w,",\"cleanup\":")
    cleanup(s,o,w,cp,cn)
    LIT(o,w,",\"claims\":{\"sealed_artifact_generations\":true,\"per_call_generation_snapshot\":true,\"general_live_code_patch\":false,\"state_layout_migration\":false,\"backend_refinement_proved\":false,\"whole_language_soundness_proved\":false}}")
    return 0

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    if frame(s,w,p,n,2,6,3)==False:
        return 0
    pending=fp(s,p,1)
    pn=fn(s,p,1)
    if sorted_array(s,w,pending,pn,4,12,0)==False:
        return 0
    count=word(s,pending+16)
    dp=fp(s,p,5)
    dn=fn(s,p,5)
    if frame(s,w,dp,dn,3,7,31)==False:
        return 0
    ready=word(s,p+8)==3
    native_complete=ready
    identity_complete=ready and (word(s,dp+8)&1)!=0
    i=0
    while i<count:
        child=fp(s,pending,i)
        if (word(s,child+8)&4)==0:
            native_complete=False
        pinp=fp(s,child,4)
        pinn=fn(s,child,4)
        if frame(s,w,pinp,pinn,3,7,31)==False:
            return 0
        if (word(s,pinp+8)&1)==0:
            identity_complete=False
        i=i+1
    directory_pending=ready and (word(s,dp+8)&1)==0
    LIT(o,w,"{\"schema\":\"hepta.hia.native-retirement-observation.v1\",\"attempts\":")
    number_field(s,o,w,p,0,False,False)
    LIT(o,w,",\"history_limit\":128,\"pending\":[")
    i=0
    while i<count:
        if i!=0:
            emit(o,w,44)
        child=get(w,65536+i*8)
        task(s,o,w,child,word(s,child+24))
        i=i+1
    LIT(o,w,"],\"pending_identity_releases\":[")
    emitted=False
    i=0
    while i<count:
        child=fp(s,pending,i)
        pinp=fp(s,child,4)
        if (word(s,pinp+8)&1)==0:
            if emitted:
                emit(o,w,44)
            LIT(o,w,"{\"generation\":")
            number_field(s,o,w,child,0,False,False)
            LIT(o,w,",\"kind\":\"artifact\",\"pin\":")
            pin(s,o,w,pinp,fn(s,child,4))
            emit(o,w,125)
            emitted=True
        i=i+1
    if directory_pending:
        if emitted:
            emit(o,w,44)
        LIT(o,w,"{\"generation\":null,\"kind\":\"directory\",\"pin\":")
        pin(s,o,w,dp,dn)
        emit(o,w,125)
    LIT(o,w,"],\"pending_resource_count\":")
    uint(o,w,count+choose(directory_pending,1,0))
    LIT(o,w,",\"recent_attempts\":")
    json_list(s,o,w,fp(s,p,2),fn(s,p,2),True)
    LIT(o,w,",\"directory_cleanup\":")
    directory(s,o,w,fp(s,p,3),fn(s,p,3))
    LIT(o,w,",\"directory_observation\":")
    op=fp(s,p,4)
    on=fn(s,p,4)
    observation(s,o,w,op,on)
    LIT(o,w,",\"directory_identity_pin\":")
    pin(s,o,w,dp,dn)
    LIT(o,w,",\"owned_native_release_complete\":")
    boolean(o,w,native_complete)
    LIT(o,w,",\"owned_identity_release_complete\":")
    boolean(o,w,identity_complete)
    LIT(o,w,",\"observed_closed_and_directory_absent\":")
    absent=False
    if get(w,48)==0:
        absent=(word(s,op+8)&7)==1
    boolean(o,w,native_complete and identity_complete and count==0 and absent)
    LIT(o,w,",\"absence_is_a_permanent_filesystem_guarantee\":false,\"native_release_failures_are_retried\":false}")
    return 0
'''

SOURCE+=r'''
def errno_type(o:mutbuf,w:mutbuf,code:u64) -> u64:
    if code<=133:
        literal(o,w,get(w,61000+code*8))
    else:
        LIT(o,w,"\"OSError\"")
    return 0

def errno_message(o:mutbuf,w:mutbuf,code:u64) -> u64:
    return message_literal(o,w,get(w,59904+code*8))
'''

def source_program():
    literals=[];known={}
    def register(raw):
        raw=raw.encode('utf-8') if isinstance(raw,str) else raw
        if raw not in known:
            known[raw]=len(literals);literals.append(raw)
        return known[raw]
    def replace(m):
        name='literal' if m.group(1)=='LIT' else 'message_literal'
        index=register(json.loads(m.group(2)))
        return name+'(o,w,'+str(index)+')'
    text=re.sub(r'\b(MLIT|LIT)\(o,w,("(?:\\.|[^"\\])*")\)',replace,SOURCE)
    errno_messages=[register(os.strerror(i))for i in range(134)]
    errno_types=[register(json.dumps(type(OSError(i,os.strerror(i))).__name__))for i in range(134)]
    assert len(literals)<=512
    rows=[];data=bytearray()
    for raw in literals:
        rows.append((len(data),len(raw)));data.extend(raw)
    assert len(data)<=32768
    ranges=json.loads((ROOT/'tools/hia_cli_unicode_tables.json').read_text())['profiles']['314']['printable_ranges']
    assert len(ranges)==736
    writes=[]
    for i,(at,n)in enumerate(rows):writes.extend([(8192+i*16,at),(8200+i*16,n)])
    for i in range(0,len(data),8):writes.append((16384+i,int.from_bytes(data[i:i+8].ljust(8,b'\0'),'little')))
    packed=[]
    for lo,hi in ranges:
        while lo<=hi:
            end=min(hi,lo+2047);packed.append(lo|((end-lo)<<21));lo=end+1
    for i in range(0,len(packed),2):writes.append((49152+(i//2)*8,packed[i]|((packed[i+1]if i+1<len(packed)else 0)<<32)))
    text=text.replace('PRINTABLE_COUNT',str(len(packed)))
    for i,value in enumerate(errno_messages):writes.append((59904+i*8,value))
    for i,value in enumerate(errno_types):writes.append((61000+i*8,value))
    chunks=[writes[i:i+96]for i in range(0,len(writes),96)]
    text+='\ndef initialize(w:mutbuf) -> u64:\n'+''.join('    initialize_'+str(i)+'(w)\n'for i in range(len(chunks)))+'    return 0\n'
    for i,chunk in enumerate(chunks):
        text+='\ndef initialize_'+str(i)+'(w:mutbuf) -> u64:\n'
        text+=''.join('    put(w,'+str(at)+','+str(value)+')\n'for at,value in chunk)
        text+='    return 0\n'
    for name,value in C.items():text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text

def program():
    return document(source_program(),'multiversion_runtime_snapshot')

def main():
    tree=program();target=ROOT/'examples/hia_bootstrap/multiversion_runtime_snapshot.hepta'
    target.write_text(render_assembly(tree))
    report={'functions':len(tree['functions']),'blocks':sum(len(f['blocks'])for f in tree['functions']),'ops':sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),'max_function_blocks':max(len(f['blocks'])for f in tree['functions']),'max_args':max(len(f['params'])for f in tree['functions']),'bytes':target.stat().st_size}
    print(json.dumps(report),flush=True)
if __name__=='__main__':main()
