"""NDU execution owner. All admission, custody, budget and cleanup decisions are HIA."""
from pathlib import Path
import json,re
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C={
'NONE':2**64-1,'EINTR':2**64-4,'AT_FDCWD':2**64-100,'ENAMETOOLONG':2**64-36,
'MAGIC':int.from_bytes(b'HIANBO01','little'),'REPLY':int.from_bytes(b'HIANOR01','little'),
'BRIDGE_MAGIC':int.from_bytes(b'HIANBI01','little'),'RECEIPT_MAGIC':int.from_bytes(b'HIANRI01','little'),
'SOURCE_MAGIC':int.from_bytes(b'HIANSF01','little'),'IDENTITY_MAGIC':int.from_bytes(b'HIANID01','little'),
'PATH_MAGIC':int.from_bytes(b'HIAPTR01','little'),'PATH_BORROW':int.from_bytes(b'HIAPTB01','little'),
'PUMP_INPUT':int.from_bytes(b'HIANBP01','little'),'PUMP_REPLY':int.from_bytes(b'HIANPR01','little'),
'WORK':192<<20,'PATH_WORK':145<<20,'ID_WORK':149<<20,'SHA_WORK':150<<20,'PUMP_WORK':160<<20,
'JSON_OUT':152<<20,'JSON_MAGIC':int.from_bytes(b'HIANJD01','little'),'UNICODE_MAGIC':int.from_bytes(b'HIAPUE01','little'),'PATH':4096,'ARG_Q':8192,'SHA_OUT':32768,'STAT0':40960,'STAT1':41152,'CLOCK':41472,'NAME':41504,
'ID_OUT':131072,'IO':262144,'REQUEST':1<<20,'IDENTITY':6<<20,'BODY':8<<20,'IMAGE':16<<20}
SOURCE=r'''
def owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<WORK:
        return 4294967293
    p=get(w,0)
    r=get(w,8)
    if p==0:
        return begin(s,o,w)
    if p<10:
        return admission(s,o,w,p,r)
    if p<16:
        return identity_phase(s,o,w,p,r)
    if p<30:
        return execution(s,o,w,p,r)
    if p==30:
        return json_finished(o,w,r)
    if p>=300 and p<310:
        return path_read(o,w,p,r)
    if p>=400 and p<410:
        return read_step(o,w,p,r)
    if p>=800 and p<810:
        return hash_step(o,w,p,r)
    if p>=900 and p<910:
        return closing(o,w,p,r)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or word_load(s,0)!=MAGIC:
        return 4294967293
    n=word_load(s,8)
    if n>length(s)-128 or word_load(s,16)!=length(s)-128-n or word_load(s,24)>60000000000:
        return 4294967293
    i=32
    while i<128:
        if word_load(s,i)!=0:
            return 4294967293
        i=i+8
    digits=4300
    if get(w,2240)==3544411265436830024:
        digits=get(w,2248)
        if digits!=0 and (digits<640 or digits>2147483647):
            return 4294967293
    zero(w,40,4056)
    put(w,2240,3544411265436830024)
    put(w,2248,digits)
    put(w,40,n)
    put(w,48,word_load(s,16))
    put(w,56,word_load(s,24))
    put(w,112,NONE)
    put(w,216,NONE)
    put(w,224,NONE)
    put(w,256,NONE)
    put(w,576,NONE)
    put(w,NAME,0)
    expected_binary(w)
    return call(o,w,1,228,12,1,CLOCK,0,0,0,0)

def admission(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==1:
        if failed(r):
            return fail(o,w,2,90,r,1,0)
        now=clock(w)
        put(w,64,now)
        put(w,128,now)
        if get(w,56)>NONE-now:
            return fail(o,w,2,90,0,1,0)
        put(w,72,now+get(w,56))
        return call(o,w,2,5,12,get(w,24),STAT0,0,0,0,0)
    if p==2:
        if failed(r) or (get(w,STAT0+24)&61440)!=16384:
            return fail(o,w,2,90,r,2,0)
        if get(w,32)!=0:
            return cancel(o,w)
        put(w,ID_WORK,1)
        return internal(o,w,3,2,1,128+get(w,40),get(w,48),ID_OUT,65536,ID_WORK,65536)
    if p==3:
        if r!=128 or get(w,ID_OUT)!=BRIDGE_MAGIC:
            return fail(o,w,2,90,0,3,0)
        status=get(w,ID_OUT+8)
        if status==1:
            return fail(o,w,1,10,0,0,0)
        if status>2:
            return fail(o,w,2,90,0,3,0)
        if status==2:
            which=get(w,ID_OUT+16)
            typ=get(w,ID_OUT+24)
            if which==0:
                return fail(o,w,1,11,0,typ,0)
            put(w,200,1)
            put(w,208,typ)
        i=0
        while i<4:
            put(w,1152+i*8,get(w,ID_OUT+32+i*8))
            i=i+1
        return resolve_path(o,w,0,4)
    if p==4:
        if r!=0 or get(w,ID_OUT)!=PATH_MAGIC:
            return fail(o,w,2,90,0,4,0)
        if get(w,ID_OUT+8)!=0:
            return path_error(o,w,0)
        put(w,216,get(w,ID_OUT+32))
        put(w,232,get(w,ID_OUT+40))
        if get(w,32)!=0:
            return cancel(o,w)
        if get(w,200)!=0:
            return fail(o,w,1,12,0,get(w,208),0)
        return resolve_path(o,w,1,5)
    if p==5:
        if r!=0 or get(w,ID_OUT)!=PATH_MAGIC:
            return fail(o,w,2,90,0,5,0)
        if get(w,ID_OUT+8)!=0:
            return path_error(o,w,1)
        put(w,224,get(w,ID_OUT+32))
        put(w,240,get(w,ID_OUT+40))
        if get(w,32)!=0:
            return cancel(o,w)
        return begin_path_read(o,w,0,4194304,BODY,384,10)
    return 4294967293

def resolve_path(o:mutbuf,w:mutbuf,which:u64,next:u64) -> u32:
    at=get(w,1152+which*16)
    end=get(w,1160+which*16)
    if end<at or end>get(w,48):
        return fail(o,w,2,90,0,4,0)
    put(w,PATH_WORK,0)
    put(w,PATH_WORK+512,PATH_BORROW)
    put(w,PATH_WORK+520,1)
    put(w,PATH_WORK+528,0)
    put(w,PATH_WORK+536,end-at)
    put(w,PATH_WORK+544,get(w,32))
    return internal(o,w,next,3,1,128+get(w,40)+at,end-at,ID_OUT,128,PATH_WORK,4194304)

def path_error(o:mutbuf,w:mutbuf,which:u64) -> u32:
    status=get(w,ID_OUT+8)
    if status==6:
        return cancel(o,w)
    code=16
    if status==2:
        code=13
    elif status==3:
        if get(w,ID_OUT+80)!=1:
            return fail(o,w,2,90,0,14,0)
        put(w,2048,UNICODE_MAGIC)
        put(w,2056,get(w,ID_OUT+56))
        put(w,2064,get(w,ID_OUT+64))
        put(w,2072,get(w,ID_OUT+72))
        code=14
    elif status==4:
        code=15
    return fail(o,w,1,code,get(w,ID_OUT+16),which,0)

def identity_phase(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==10:
        put(w,272,get(w,552))
        put(w,IMAGE+2240,3544411265436830024)
        put(w,IMAGE+2248,get(w,2248))
        return internal(o,w,30,5,3,BODY,get(w,552),JSON_OUT,8388608,IMAGE,134217728)
    if p==11:
        if r!=128 or get(w,ID_OUT)!=RECEIPT_MAGIC:
            return fail(o,w,2,90,0,11,0)
        if get(w,ID_OUT+8)!=0:
            return fail(o,w,1,30,0,0,2)
        put(w,184,0)
        return source_next(o,w)
    if p==12:
        if r<128 or r>65536 or get(w,ID_OUT)!=SOURCE_MAGIC or get(w,ID_OUT+8)!=SOURCE_COUNT:
            return fail(o,w,2,90,0,12,0)
        n=get(w,ID_OUT+16)
        if n==0 or n>=4096 or r!=128+n:
            return fail(o,w,2,90,0,12,0)
        copyw(w,ID_OUT+128,PATH,n)
        store(w,PATH+n,0)
        copyw(w,ID_OUT+32,448,32)
        put(w,608,n)
        put(w,280,1)
        return begin_file(o,w,get(w,24),4194304,BODY,416,13)
    if p==13:
        if equal(w,416,448,32)==0:
            return fail(o,w,1,31,0,get(w,184),3)
        put(w,184,get(w,184)+1)
        return source_next(o,w)
    if p==14:
        put(w,264,get(w,552))
        if equal(w,352,2304,32)==0:
            return fail(o,w,1,32,0,0,1)
        put(w,ID_WORK,4)
        return internal(o,w,15,2,3,ARG_Q,0,ID_OUT,65536,ID_WORK,65536)
    if p==15:
        n=get(w,ID_OUT+16)
        if r!=128+n or n<2 or n>8192 or get(w,ID_OUT)!=IDENTITY_MAGIC:
            return fail(o,w,2,90,0,15,0)
        copyw(w,ID_OUT+128,IDENTITY,n-1)
        n=n-1
        n=identity_binary(w,IDENTITY+n)-IDENTITY
        n=hex32(w,352,IDENTITY+n)-IDENTITY
        n=identity_receipt(w,IDENTITY+n)-IDENTITY
        n=hex32(w,384,IDENTITY+n)-IDENTITY
        store(w,IDENTITY+n,34)
        store(w,IDENTITY+n+1,125)
        put(w,136,n+2)
        put(w,168,get(w,168)|1)
        if get(w,32)!=0:
            return cancel(o,w)
        if get(w,40)>1048576:
            return fail(o,w,1,40,0,0,0)
        return call(o,w,16,228,12,1,CLOCK,0,0,0,0)
    return 4294967293


def json_finished(o:mutbuf,w:mutbuf,r:u64) -> u32:
    if r<128 or r>8388608 or get(w,JSON_OUT)!=JSON_MAGIC:
        return fail(o,w,2,90,0,30,0)
    n=get(w,JSON_OUT+16)
    status=get(w,JSON_OUT+8)
    if status>6 or n!=r-128:
        return fail(o,w,2,90,0,30,0)
    if status!=0:
        copyw(w,JSON_OUT,2048,128)
        put(w,2176,JSON_OUT+128)
        put(w,2184,n)
        put(w,2192,BODY)
        put(w,2200,get(w,272))
        return fail(o,w,1,33,0,0,2)
    put(w,ID_WORK,2)
    return internal(o,w,11,2,3,JSON_OUT+128,n,ID_OUT,128,ID_WORK,65536)

def source_next(o:mutbuf,w:mutbuf) -> u32:
    if get(w,32)!=0:
        return cancel(o,w)
    index=get(w,184)
    if index==SOURCE_COUNT:
        return begin_path_read(o,w,2,134217728,IMAGE,352,14)
    put(w,ARG_Q,index)
    put(w,ID_WORK,3)
    return internal(o,w,12,2,3,ARG_Q,8,ID_OUT,65536,ID_WORK,65536)

def begin_path_read(o:mutbuf,w:mutbuf,kind:u64,cap:u64,target:u64,digest:u64,next:u64) -> u32:
    put(w,280,kind)
    put(w,528,cap)
    put(w,536,target)
    put(w,568,next)
    put(w,592,digest)
    fd=get(w,216)
    n=get(w,232)
    if kind==0:
        fd=get(w,224)
        n=get(w,240)
    put(w,600,fd)
    put(w,608,n)
    put(w,616,0)
    if n>=4096:
        return fail(o,w,1,23,ENAMETOOLONG,kind,path_kind(w))
    return path_more(o,w)

def path_more(o:mutbuf,w:mutbuf) -> u32:
    done=get(w,616)
    n=get(w,608)
    if done==n:
        store(w,PATH+n,0)
        return begin_file(o,w,AT_FDCWD,get(w,528),get(w,536),get(w,592),get(w,568))
    return call(o,w,300,17,12,get(w,600),PATH+done,n-done,done,0,0)

def path_read(o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if r==EINTR:
        return path_more(o,w)
    if failed(r) or r==0 or r>get(w,608)-get(w,616):
        return fail(o,w,2,90,r,300,0)
    put(w,616,get(w,616)+r)
    return path_more(o,w)

def begin_file(o:mutbuf,w:mutbuf,root:u64,cap:u64,target:u64,digest:u64,next:u64) -> u32:
    put(w,512,root)
    put(w,528,cap)
    put(w,536,target)
    put(w,568,next)
    put(w,592,digest)
    put(w,576,NONE)
    return call(o,w,400,257,12,root,PATH,657408,0,0,0)

def read_step(o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==400:
        if r==EINTR:
            return call(o,w,400,257,12,get(w,512),PATH,657408,0,0,0)
        if failed(r):
            return fail(o,w,1,23,r,get(w,280),path_kind(w))
        put(w,576,r)
        if get(w,32)!=0:
            return cancel(o,w)
        return call(o,w,401,5,12,r,STAT0,0,0,0,0)
    if p==401:
        if r==EINTR:
            return call(o,w,401,5,12,get(w,576),STAT0,0,0,0,0)
        if failed(r):
            return fail(o,w,1,23,r,get(w,280),path_kind(w))
        n=get(w,STAT0+48)
        if (get(w,STAT0+24)&61440)!=32768 or n==0 or n>get(w,528):
            return fail(o,w,1,choose(get(w,280)==1,31,20),0,get(w,280),path_kind(w))
        put(w,544,n)
        put(w,552,0)
        return read_more(o,w)
    if p==402:
        if r==EINTR:
            return read_more(o,w)
        if failed(r):
            return fail(o,w,1,23,r,get(w,280),path_kind(w))
        if r>get(w,560):
            return fail(o,w,2,90,0,402,0)
        put(w,552,get(w,552)+r)
        if r==0 or get(w,552)==get(w,544)+1:
            return call(o,w,403,5,12,get(w,576),STAT1,0,0,0,0)
        return read_more(o,w)
    if p==403:
        if r==EINTR:
            return call(o,w,403,5,12,get(w,576),STAT1,0,0,0,0)
        if failed(r):
            return fail(o,w,1,23,r,get(w,280),path_kind(w))
        if same_stat(w)==0:
            return fail(o,w,1,21,0,get(w,280),path_kind(w))
        if get(w,552)!=get(w,544):
            return fail(o,w,1,22,0,get(w,280),path_kind(w))
        fd=get(w,576)
        put(w,576,NONE)
        return call(o,w,404,3,0,fd,0,0,0,0,0)
    if p==404:
        if failed(r):
            return fail(o,w,1,50,r,get(w,280),0)
        if get(w,32)!=0:
            return cancel(o,w)
        return hash_begin(o,w,get(w,536),get(w,552),get(w,592),get(w,568))
    return 4294967293

def read_more(o:mutbuf,w:mutbuf) -> u32:
    if get(w,32)!=0:
        return cancel(o,w)
    amount=minimum(1048576,get(w,544)+1-get(w,552))
    put(w,560,amount)
    return call(o,w,402,0,12,get(w,576),get(w,536)+get(w,552),amount,0,0,0)

def same_stat(w:mutbuf) -> u64:
    if get(w,STAT0)!=get(w,STAT1) or get(w,STAT0+8)!=get(w,STAT1+8) or get(w,STAT0+48)!=get(w,STAT1+48):
        return 0
    at=88
    while at<120:
        if get(w,STAT0+at)!=get(w,STAT1+at):
            return 0
        at=at+8
    return 1

def path_kind(w:mutbuf) -> u64:
    kind=get(w,280)
    if kind==0:
        return 2
    if kind==1:
        return 3
    return 1

def execution(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==16 or p==26:
        if failed(r):
            return fail(o,w,2,90,r,p,0)
        put(w,128,clock(w))
        if get(w,32)!=0:
            return cancel(o,w)
        if get(w,128)>=get(w,72):
            return fail(o,w,1,41,0,0,0)
        if p==16:
            return call(o,w,17,319,3,NAME,3,0,0,0,0)
        return invoke_pump(s,o,w)
    if p==17:
        if failed(r):
            return fail(o,w,1,42,r,17,0)
        put(w,256,r)
        if r<3:
            return call(o,w,18,72,0,r,1030,3,0,0,0)
        return call(o,w,20,91,0,r,448,0,0,0,0)
    if p==18:
        if failed(r):
            return fail(o,w,1,42,r,18,0)
        old=get(w,256)
        put(w,256,r)
        return call(o,w,19,3,0,old,0,0,0,0,0)
    if p==19:
        if failed(r):
            return fail(o,w,1,42,r,19,0)
        return call(o,w,20,91,0,get(w,256),448,0,0,0,0)
    if p==20:
        if failed(r):
            return fail(o,w,1,42,r,20,0)
        put(w,704,0)
        return image_write(o,w)
    if p==21:
        if r==EINTR:
            return image_write(o,w)
        if failed(r) or r==0 or r>get(w,712):
            return fail(o,w,1,42,r,choose(r==0,1001,21),0)
        put(w,704,get(w,704)+r)
        return image_write(o,w)
    if p==22:
        if failed(r):
            return fail(o,w,1,42,r,22,0)
        return call(o,w,23,72,0,get(w,256),1034,0,0,0,0)
    if p==23:
        if r!=15:
            return fail(o,w,1,42,r,choose(failed(r),23,1002),0)
        return call(o,w,24,5,12,get(w,256),STAT0,0,0,0,0)
    if p==24:
        if failed(r) or (get(w,STAT0+24)&61440)!=32768 or get(w,STAT0+48)!=get(w,264):
            return fail(o,w,1,42,r,choose(failed(r),24,1002),0)
        put(w,704,0)
        return image_check(o,w)
    if p==25:
        if r==EINTR:
            return image_check(o,w)
        if failed(r) or r==0 or r>get(w,712):
            return fail(o,w,1,42,r,choose(r==0,1002,25),0)
        if equal(w,IO+1,IMAGE+get(w,704),r)==0:
            return fail(o,w,1,42,0,1002,0)
        put(w,704,get(w,704)+r)
        return image_check(o,w)
    if p==27:
        return pump_finished(o,w,r)
    if p==28:
        if equal(w,416,352,32)==0:
            return fail(o,w,1,48,0,0,1)
        put(w,168,get(w,168)|256)
        return finish(o,w)
    return 4294967293

def image_write(o:mutbuf,w:mutbuf) -> u32:
    if get(w,32)!=0:
        return cancel(o,w)
    at=get(w,704)
    if at==get(w,264):
        return call(o,w,22,72,0,get(w,256),1033,15,0,0,0)
    n=minimum(65536,get(w,264)-at)
    put(w,712,n)
    return call(o,w,21,1,12,get(w,256),IMAGE+at,n,0,0,0)

def image_check(o:mutbuf,w:mutbuf) -> u32:
    if get(w,32)!=0:
        return cancel(o,w)
    at=get(w,704)
    if at==get(w,264):
        put(w,168,get(w,168)|32)
        return call(o,w,26,228,12,1,CLOCK,0,0,0,0)
    n=minimum(65536,get(w,264)-at)
    put(w,712,n)
    return call(o,w,25,17,12,get(w,256),IO+1,n,at,0,0)

def invoke_pump(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(w,REQUEST,128)
    put(w,REQUEST,PUMP_INPUT)
    put(w,REQUEST+8,get(w,256))
    put(w,REQUEST+16,get(w,72))
    put(w,REQUEST+24,get(w,40))
    copy(s,w,128,REQUEST+128,get(w,40))
    put(w,PUMP_WORK,0)
    put(w,PUMP_WORK+336,get(w,32))
    return internal(o,w,27,4,3,REQUEST,128+get(w,40),ID_OUT,128,PUMP_WORK,5242880)

def pump_finished(o:mutbuf,w:mutbuf,r:u64) -> u32:
    if r!=0 or get(w,ID_OUT)!=PUMP_REPLY:
        return fail(o,w,2,90,0,27,0)
    put(w,144,get(w,ID_OUT+32))
    put(w,152,get(w,ID_OUT+40))
    put(w,160,get(w,ID_OUT+48))
    flags=get(w,168)
    if get(w,ID_OUT+56)!=0:
        flags=flags|2
    if get(w,ID_OUT+64)==1:
        flags=flags|4
    if get(w,ID_OUT+112)==1:
        flags=flags|8
    flags=flags|((get(w,ID_OUT+72)&3)<<6)
    put(w,168,flags)
    status=get(w,ID_OUT+8)
    if status==6:
        return cancel(o,w)
    if status==1:
        return fail(o,w,1,43,0,0,0)
    if status==2:
        return fail(o,w,1,44,0,0,0)
    if status==4:
        return fail(o,w,1,46,get(w,ID_OUT+24),get(w,ID_OUT+16),0)
    if status==3 or status==5:
        return fail(o,w,1,45,get(w,ID_OUT+24),get(w,ID_OUT+16),0)
    if status!=0 or get(w,ID_OUT+64)!=1 or get(w,ID_OUT+112)!=1 or get(w,ID_OUT+72)!=7:
        return fail(o,w,2,90,0,27,0)
    if get(w,160)!=0 or get(w,144)>1048576 or get(w,152)>1048576:
        return fail(o,w,1,47,0,0,0)
    if get(w,32)!=0:
        return cancel(o,w)
    return begin_path_read(o,w,3,134217728,IMAGE,416,28)

def hash_begin(o:mutbuf,w:mutbuf,at:u64,n:u64,target:u64,next:u64) -> u32:
    put(w,768,at)
    put(w,776,n)
    put(w,784,target)
    put(w,792,next)
    put(w,800,0)
    store(w,IO,0)
    return internal(o,w,800,1,3,IO,1,SHA_OUT,32,SHA_WORK,1184)

def hash_step(o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==802:
        if r!=32:
            return fail(o,w,2,90,0,802,0)
        copyw(w,SHA_OUT,get(w,784),32)
        put(w,0,get(w,792))
        put(w,8,0)
        return 3
    if r!=0:
        return fail(o,w,2,90,r,p,0)
    if p==801:
        put(w,800,get(w,800)+get(w,808))
    if get(w,32)!=0:
        return cancel(o,w)
    done=get(w,800)
    if done==get(w,776):
        store(w,IO,2)
        return internal(o,w,802,1,3,IO,1,SHA_OUT,32,SHA_WORK,1184)
    n=minimum(65536,get(w,776)-done)
    store(w,IO,1)
    copyw(w,get(w,768)+done,IO+1,n)
    put(w,808,n)
    return internal(o,w,801,1,3,IO,n+1,SHA_OUT,32,SHA_WORK,1184)

def fail(o:mutbuf,w:mutbuf,status:u64,code:u64,raw:u64,detail:u64,which:u64) -> u32:
    if get(w,80)==0:
        put(w,80,status)
        put(w,88,code)
        put(w,96,raw)
        put(w,104,detail)
        if which==1 and get(w,216)!=NONE:
            put(w,112,get(w,216))
            put(w,120,get(w,232))
            put(w,216,NONE)
        elif which==2 and get(w,224)!=NONE:
            put(w,112,get(w,224))
            put(w,120,get(w,240))
            put(w,224,NONE)
        elif which==3:
            put(w,104,256+get(w,184))
    return finish(o,w)

def cancel(o:mutbuf,w:mutbuf) -> u32:
    return fail(o,w,3,0,0,0,0)

def finish(o:mutbuf,w:mutbuf) -> u32:
    put(w,304,0)
    return close_next(o,w)

def close_slot(i:u64) -> u64:
    return choose(i==0,576,choose(i==1,256,choose(i==2,216,224)))

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,304)
    while i<4:
        at=close_slot(i)
        fd=get(w,at)
        put(w,304,i+1)
        if fd!=NONE:
            put(w,at,NONE)
            return call(o,w,900,3,0,fd,0,0,0,0,0)
        i=i+1
    return call(o,w,901,228,12,1,CLOCK,0,0,0,0)

def closing(o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p==900:
        if failed(r):
            put(w,80,2)
            put(w,88,50)
            put(w,96,r)
            put(w,312,1)
        return close_next(o,w)
    if p==901:
        if failed(r):
            put(w,80,2)
            put(w,88,90)
            put(w,96,r)
        else:
            put(w,128,clock(w))
        if get(w,312)==0:
            put(w,168,get(w,168)|512)
        zero(o,0,128)
        put(o,0,REPLY)
        put(o,8,get(w,80))
        put(o,16,get(w,88))
        put(o,24,get(w,96))
        put(o,32,get(w,144))
        put(o,40,get(w,152))
        put(o,48,get(w,136))
        elapsed=0
        if get(w,128)>=get(w,64):
            elapsed=get(w,128)-get(w,64)
        put(o,56,elapsed)
        put(o,64,get(w,160))
        put(o,72,get(w,168))
        put(o,80,PUMP_WORK+1048576)
        put(o,88,PUMP_WORK+2097184)
        put(o,96,IDENTITY)
        put(o,104,get(w,104))
        put(o,112,get(w,112))
        put(o,120,get(w,120))
        return 0
    return 4294967293

def internal(o:mutbuf,w:mutbuf,next:u64,role:u64,selector:u64,at:u64,n:u64,to:u64,cap:u64,work:u64,size:u64) -> u32:
    put(w,0,next)
    put(o,0,role)
    put(o,8,selector)
    put(o,16,at)
    put(o,24,n)
    put(o,32,to)
    put(o,40,cap)
    put(o,48,work)
    put(o,56,size)
    return 2

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,next)
    put(o,0,nr)
    put(o,8,a)
    put(o,16,b)
    put(o,24,c)
    put(o,32,d)
    put(o,40,e)
    put(o,48,f)
    put(o,56,flags)
    return 1

def clock(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,v:u64) -> u64:
    word_store(w,at,v)
    return 0

def copy(s:readbuf,w:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,to+i,word_load(s,at+i))
        i=i+8
    while i<n:
        store(w,to+i,byte(s,at+i))
        i=i+1
    return 0

def copyw(w:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,to+i,word_load(w,at+i))
        i=i+8
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        if word_load(w,a+i)!=word_load(w,b+i):
            return 0
        i=i+8
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def hex32(w:mutbuf,at:u64,to:u64) -> u64:
    i=0
    while i<32:
        v=byte(w,at+i)
        a=v>>4
        b=v&15
        store(w,to+2*i,choose(a<10,48+a,87+a))
        store(w,to+2*i+1,choose(b<10,48+b,87+b))
        i=i+1
    return to+64

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,at+i,0)
        i=i+8
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def failed(v:u64) -> bool:
    return v>=18446744073709547520

def minimum(a:u64,b:u64) -> u64:
    return choose(a<b,a,b)
'''
def literal(name,raw):
    lines=[f'def {name}(w:mutbuf,at:u64) -> u64:']
    for i in range(0,len(raw)//8*8,8):lines.append(f'    word_store(w,at+{i},{int.from_bytes(raw[i:i+8],"little")})')
    for i in range(len(raw)//8*8,len(raw)):lines.append(f'    store(w,at+{i},{raw[i]})')
    lines.append(f'    return at+{len(raw)}')
    return '\n'.join(lines)
def program():
    receipt=json.loads((ROOT/'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json').read_text())
    parts=[SOURCE,literal('identity_binary',b',"binary_sha256":"'),literal('identity_receipt',b'","build_receipt_sha256":"')]
    digest=bytes.fromhex(receipt['binary_sha256'])
    parts.append('\n'.join(['def expected_binary(w:mutbuf) -> u64:']+[f'    word_store(w,{2304+i},{int.from_bytes(digest[i:i+8],"little")})'for i in range(0,32,8)]+['    return 0']))
    values=dict(C,SOURCE_COUNT=len(receipt['source_files']))
    s='\n\n'.join(parts)
    for k,v in values.items():s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
if __name__=='__main__':
    d=document(program(),'ndu_rank_native_owner');p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
