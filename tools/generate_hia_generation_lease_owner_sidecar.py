"""Native trusted sidecar binding for the sole generation owner.

The core profile keeps its 2048-byte context. This separate entry exclusively
owns reserved bytes 1136..1279 and an actual native mapping; no request supplies
an entry, context, nonce, or environment pointer.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIAGSCQ1','little'),R=int.from_bytes(b'HIAGSCR1','little'),
 TAG=int.from_bytes(b'HIAGSCX1','little'),OWNER=int.from_bytes(b'HIAGLOW1','little'),
 V1=int.from_bytes(b'HIABVQ01','little'),V2=int.from_bytes(b'HIABVQ02','little'),
 V5=int.from_bytes(b'HIABVQ05','little'),VR=int.from_bytes(b'HIABVR01','little'),
 VR2=int.from_bytes(b'HIABVR02','little'),CQ=int.from_bytes(b'HIACODQ1','little'),
 CR=int.from_bytes(b'HIACODR1','little'),TQ=int.from_bytes(b'HIAGTDQ1','little'),
 TR=int.from_bytes(b'HIAGTDR1','little'),BAD=4294967293,NONE=(1<<64)-1,
 SIZE=212992,PH=128,FB=136,OP=144,STATUS=152,ERROR=160,PENDING=168,RETIRED=176,
 HELD=184,KNOWN=192,RETURN_FD=200,RETURN_N=208,AFTER=216,RELOCK=224,PID=232,
 STATE=1144,PTR=1152,EXTENT=1160,NONCE=1168,SELF=1176,TOKEN=1184,ACTIVE=1208,
 STAGE=1216,TEMP=1232,CODE=1248,LAST=1256,FLAGS=1272,REQUEST=4096,CHILD=16384)
SOURCE=r'''
def sidecar(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        return system(o,2,39,0,0,0,0,0,0,0)
    if phase==2:
        if r<2 or r>2147483647:
            put(o,STATUS,4)
            put(o,ERROR,r)
            return reply(o,w)
        put(o,PID,r)
        if get(w,0)!=OWNER or get(w,8)!=r or get(w,16)!=get(o,512) or get(w,24)!=get(o,520):
            return BAD
        if get(w,40)!=get(o,528) or get(w,48)!=get(o,512)+512 or get(w,56)!=256:
            return BAD
        if get(w,640)!=get(o,552) or get(w,648)!=get(o,512)+768 or get(w,656)!=256:
            return BAD
        if get(w,80)!=1 or get(w,664)==0:
            return BAD
        return lock(o,3)
    if phase==3:
        if r==0:
            put(o,HELD,1)
            return locked(o,w)
        if r!=1:
            return BAD
        return wait(o,4)
    if phase==4:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            put(o,STATUS,4)
            put(o,ERROR,r)
            return reply(o,w)
        return lock(o,3)
    if phase==20:
        return init_next(o,w)
    if phase==21:
        if r!=8 or get(w,NONCE)==0:
            put(w,NONCE,0)
            return parked(o,w,4,r,4)
        put(w,STAGE,10)
        return init_next(o,w)
    if phase==22:
        if failed(r):
            return parked(o,w,5,r,4)
        put(w,PTR,r)
        put(w,EXTENT,SIZE)
        put(w,FLAGS,get(w,FLAGS)|2)
        put(w,STAGE,20)
        return init_next(o,w)
    if phase==23:
        return token_created(o,w,r,False)
    if phase==24:
        if r!=0 or get(o,CHILD)!=CR:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0:
            if get(o,CHILD+88)!=1 or get(o,CHILD+24)!=0 or get(o,CHILD+32)!=0 or get(o,CHILD+40)!=0:
                return parked(o,w,11,get(o,CHILD+8),5)
            return parked(o,w,11,get(o,CHILD+8),4)
        if get(o,CHILD+48)==0 or get(o,CHILD+80)!=0 or get(o,CHILD+120)!=0:
            return parked(o,w,11,24,5)
        put(w,FLAGS,get(w,FLAGS)|4)
        put(w,704,get(o,536))
        put(w,712,get(w,PTR)+1024)
        put(w,720,256)
        put(w,728,get(o,CHILD+48))
        put(o,704,get(o,512)+512)
        put(o,712,get(o,528))
        put(w,STAGE,40)
        return memory(o,25,3,704,0,get(w,PTR)+1160,16)
    if phase==25:
        if r!=0:
            return parked(o,w,11,r,5)
        if (get(w,FLAGS)&8)!=0:
            put(w,STAGE,100)
            return again(o,100)
        return relock(o,80)
    if phase==80:
        put(w,STATE,2)
        put(w,STAGE,0)
        return operation_done(o,w)
    if phase==81:
        put(w,STATE,get(o,240))
        put(w,LAST,get(o,ERROR))
        return operation_done(o,w)
    if phase==82:
        put(w,STATE,2)
        put(w,STAGE,0)
        put(w,FLAGS,get(w,FLAGS)&18446744073709551591)
        put(o,STATUS,6)
        put(o,PENDING,0)
        return operation_done(o,w)
    if phase==83:
        if get(w,72)==0 or (get(w,FLAGS)&1)==0:
            return parked_locked(o,w,83)
        put(w,72,get(w,72)-1)
        zero(w,1136,144)
        put(o,RETIRED,1)
        put(o,PENDING,0)
        return unlock(o,0)
    if phase==100:
        return close_next(o,w)
    if phase==101:
        if code_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,STAGE,110)
        return close_next(o,w)
    if phase==102:
        if code_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)==6 and get(o,CHILD+80)==0:
            return relock(o,82)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,CHILD+120)!=4:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,FLAGS,get(w,FLAGS)|16)
        put(w,STAGE,120)
        return close_next(o,w)
    if phase==103:
        if r!=0 or get(o,CHILD)!=VR2:
            return parked(o,w,11,r,5)
        if get(o,CHILD+88)!=1 or get(o,CHILD+96)>1 or get(o,CHILD+80)>1:
            return parked(o,w,11,103,5)
        if get(o,CHILD+96)==0:
            return parked(o,w,11,get(o,CHILD+8),4)
        zero(w,TOKEN,24)
        if get(o,CHILD+80)!=0:
            put(w,STAGE,125)
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,STAGE,130)
        return close_next(o,w)
    if phase==104:
        if r!=0 or get(o,CHILD)!=VR:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,STAGE,130)
        return close_next(o,w)
    if phase==105:
        if r!=0 or get(o,CHILD)!=VR:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)==6:
            put(w,STAGE,131)
            return close_next(o,w)
        if get(o,CHILD+8)!=0:
            return parked(o,w,11,get(o,CHILD+8),5)
        put(w,FLAGS,get(w,FLAGS)|32)
        put(w,STAGE,140)
        return close_next(o,w)
    if phase==106:
        return token_created(o,w,r,True)
    if phase==107:
        if code_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,CHILD+120)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        return relock(o,82)
    if phase==108:
        if temp_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+72)==1 and get(o,CHILD+56)==0 and get(o,CHILD+80)==1:
            if get(o,CHILD+8)!=0:
                put(o,STATUS,11)
                put(o,ERROR,get(o,CHILD+16))
            put(w,FLAGS,get(w,FLAGS)|64)
            put(w,STAGE,150)
            return close_next(o,w)
        return parked(o,w,11,get(o,CHILD+16),choose(get(o,CHILD+80)==1,4,5))
    if phase==109:
        if code_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,CHILD+120)!=3:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,FLAGS,get(w,FLAGS)|128)
        put(w,STAGE,160)
        return close_next(o,w)
    if phase==110:
        if r!=0 or get(o,CHILD)!=VR or get(o,CHILD+8)!=0:
            return parked(o,w,11,r,5)
        put(w,FLAGS,get(w,FLAGS)&18446744073709551583)
        put(w,STAGE,180)
        return close_next(o,w)
    if phase==111:
        if r!=0:
            return parked(o,w,11,r,4)
        put(w,PTR,0)
        put(w,EXTENT,0)
        put(w,FLAGS,get(w,FLAGS)&18446744073709551613)
        return relock(o,83)
    if phase==300:
        return temp(o,301,w,0)
    if phase==301:
        return got_temp(o,w,r,False)
    if phase==302:
        return temp(o,303,w,2)
    if phase==303:
        return got_temp(o,w,r,True)
    if phase==304:
        if get(o,240)!=0:
            put(w,STATE,get(o,240))
            put(w,STAGE,choose(get(o,240)==2,0,300))
        return operation_done(o,w)
    if phase==850:
        if r==0:
            put(o,HELD,1)
            return again(o,get(o,RELOCK))
        if r!=1:
            return BAD
        return wait(o,851)
    if phase==851:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            put(o,STATUS,11)
            put(o,ERROR,r)
            return system(o,852,24,0,0,0,0,0,0,0)
        return lock(o,850)
    if phase==852:
        return lock(o,850)
    if phase==900:
        put(o,HELD,0)
        return system(o,901,202,1,64,129,2147483647,0,0,0)
    if phase==901:
        if failed(r) and get(o,STATUS)==0:
            put(o,STATUS,11)
            put(o,ERROR,r)
        if get(o,AFTER)!=0:
            return again(o,get(o,AFTER))
        return reply(o,w)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)!=32768 or length(w)!=2048:
        return BAD
    if word_load(s,0)!=Q or word_load(s,8)>4:
        return BAD
    i=16
    while i<128:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    zero(o,144,368)
    put(o,OP,word_load(s,8))
    put(o,KNOWN,1)
    put(o,RETURN_FD,NONE)
    put(o,PH,1)
    return 15

def locked(o:mutbuf,w:mutbuf) -> u32:
    if get(w,1136)!=0:
        if get(w,1136)!=TAG or get(w,SELF)!=get(o,560) or get(w,CODE)!=get(o,536) or get(w,TEMP)!=get(o,544):
            return parked_locked(o,w,5)
    op=get(o,OP)
    state=get(w,STATE)
    if op==4:
        return unlock(o,0)
    if op==0:
        i=1136
        while i<1280:
            if get(w,i)!=0:
                put(o,STATUS,6)
                return unlock(o,0)
            i=i+8
        if get(w,72)==NONE:
            put(o,STATUS,6)
            return unlock(o,0)
        put(w,1136,TAG)
        put(w,STATE,1)
        put(w,SELF,get(o,560))
        put(w,CODE,get(o,536))
        put(w,TEMP,get(o,544))
        put(w,FLAGS,1)
        put(w,ACTIVE,1)
        put(w,72,get(w,72)+1)
        return unlock(o,20)
    if state==0:
        if op==1 or op==2:
            put(o,RETIRED,1)
        else:
            put(o,STATUS,6)
        return unlock(o,0)
    if state==5:
        put(o,STATUS,11)
        put(o,PENDING,1)
        put(o,KNOWN,0)
        return unlock(o,0)
    if op==3:
        if state!=2 or get(w,PTR)==0 or get(w,ACTIVE)==NONE:
            put(o,STATUS,6)
            return unlock(o,0)
        put(w,ACTIVE,get(w,ACTIVE)+1)
        return unlock(o,300)
    if get(w,ACTIVE)!=0:
        put(o,STATUS,6)
        return unlock(o,0)
    if op==2 and state==2:
        return unlock(o,0)
    put(w,ACTIVE,1)
    if op==1:
        if get(w,PTR)==0 and get(w,TOKEN)==0 and (get(w,FLAGS)&4)==0:
            return again(o,83)
        if get(w,STAGE)<100 and state!=2:
            put(w,FLAGS,get(w,FLAGS)|8)
            return unlock(o,20)
        put(w,STATE,3)
        if state==2 or get(w,STAGE)==300:
            put(w,STAGE,100)
        return unlock(o,100)
    if state!=4:
        put(w,ACTIVE,0)
        put(o,STATUS,6)
        return unlock(o,0)
    if get(w,STAGE)==300:
        return unlock(o,302)
    if get(w,STAGE)>=100:
        return unlock(o,100)
    return unlock(o,20)

def init_next(o:mutbuf,w:mutbuf) -> u32:
    stage=get(w,STAGE)
    if get(w,NONCE)==0:
        return system(o,21,318,1,NONCE,8,0,0,0,0)
    if get(w,PTR)==0:
        put(w,STAGE,10)
        return system(o,22,9,0,0,SIZE,3,34,NONE,0)
    if get(w,TOKEN)==0:
        put(w,STAGE,20)
        return value(o,23,w,V1,21)
    if (get(w,FLAGS)&4)==0:
        put(w,STAGE,30)
        return code(o,24,w,0)
    if (get(w,FLAGS)&8)!=0:
        put(w,STAGE,100)
        return again(o,100)
    return relock(o,80)

def token_created(o:mutbuf,w:mutbuf,r:u64,rollback:bool) -> u32:
    if r!=0 or get(o,CHILD)!=VR:
        return parked(o,w,11,r,5)
    a=get(o,CHILD+24)
    b=get(o,CHILD+32)
    c=get(o,CHILD+40)
    if a!=0 and b!=0 and c!=0:
        put(w,TOKEN,a)
        put(w,TOKEN+8,b)
        put(w,TOKEN+16,c)
        if get(o,CHILD+8)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        if rollback:
            put(w,STAGE,132)
            return close_next(o,w)
        put(w,STAGE,30)
        return init_next(o,w)
    if a!=0 or b!=0 or c!=0:
        return parked(o,w,11,23,5)
    if get(o,CHILD+8)==0:
        return parked(o,w,11,23,5)
    return parked(o,w,11,get(o,CHILD+8),4)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    stage=get(w,STAGE)
    if stage==100:
        return code(o,101,w,5)
    if stage==110:
        return code(o,102,w,10)
    if stage==120:
        if get(w,TOKEN)!=0:
            return value(o,103,w,V2,30)
        put(w,STAGE,130)
        stage=130
    if stage==125:
        return value(o,104,w,V5,56)
    if stage==130:
        return value(o,105,w,V5,52)
    if stage==131:
        if get(w,TOKEN)!=0:
            put(w,STAGE,132)
            return code(o,107,w,11)
        return value(o,106,w,V1,21)
    if stage==132:
        return code(o,107,w,11)
    if stage==140:
        return temp(o,108,w,1)
    if stage==150:
        return code(o,109,w,6)
    if stage==160:
        zero(w,704,32)
        put(w,680,get(w,680)&18446744073709551559)
        put(w,STAGE,170)
        stage=170
    if stage==170:
        return value(o,110,w,V5,53)
    if stage==180:
        return system(o,111,11,0,get(w,PTR),get(w,EXTENT),0,0,0,0)
    return parked(o,w,11,stage,5)

def got_temp(o:mutbuf,w:mutbuf,r:u64,retry:bool) -> u32:
    if temp_reply(o,r)==0:
        return parked(o,w,11,r,5)
    fd=get(o,CHILD+32)
    if fd!=NONE:
        if fd>2147483647 or get(o,CHILD+48)!=15 or retry:
            return parked(o,w,11,301,5)
        put(o,RETURN_FD,fd)
        put(o,RETURN_N,get(o,CHILD+40))
    if get(o,CHILD+8)!=0:
        put(o,STATUS,get(o,CHILD+8))
        put(o,ERROR,get(o,CHILD+16))
    if get(o,CHILD+56)!=0:
        put(o,PENDING,1)
        put(o,KNOWN,get(o,CHILD+80))
        put(o,240,choose(get(o,CHILD+80)==1,4,5))
    elif retry:
        put(o,240,2)
    return relock(o,304)

def code_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=CR or get(o,CHILD+88)!=1 or get(o,CHILD+80)>1 or get(o,CHILD+96)>1:
        return 0
    return 1

def temp_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=TR or get(o,CHILD+56)>1 or get(o,CHILD+72)>1 or get(o,CHILD+80)>1:
        return 0
    return 1

def parked(o:mutbuf,w:mutbuf,status:u64,error:u64,state:u64) -> u32:
    put(o,STATUS,status)
    put(o,ERROR,error)
    put(o,PENDING,1)
    put(o,KNOWN,choose(state==5,0,1))
    put(o,240,state)
    return relock(o,81)

def parked_locked(o:mutbuf,w:mutbuf,error:u64) -> u32:
    put(o,STATUS,11)
    put(o,ERROR,error)
    put(o,PENDING,1)
    put(o,KNOWN,0)
    return unlock(o,0)

def operation_done(o:mutbuf,w:mutbuf) -> u32:
    if get(w,ACTIVE)==0:
        return parked_locked(o,w,84)
    put(w,ACTIVE,get(w,ACTIVE)-1)
    return unlock(o,0)

def value(o:mutbuf,next:u64,w:mutbuf,magic:u64,op:u64) -> u32:
    zero(o,REQUEST,128)
    zero(o,CHILD,8192)
    put(o,REQUEST,magic)
    put(o,REQUEST+8,op)
    if magic==V2 and op==30:
        copy(w,TOKEN,o,REQUEST+24,24)
    return role(o,next,12,3,REQUEST,128,3,CHILD,8192,1,512,256)

def code(o:mutbuf,next:u64,w:mutbuf,op:u64) -> u32:
    zero(o,REQUEST,128)
    zero(o,CHILD,8192)
    put(o,REQUEST,CQ)
    put(o,REQUEST+8,op)
    return role(o,next,13,3,REQUEST,128,3,CHILD,8192,0,get(w,PTR)+1024,256)

def temp(o:mutbuf,next:u64,w:mutbuf,op:u64) -> u32:
    zero(o,REQUEST,128)
    zero(o,CHILD,128)
    put(o,REQUEST,TQ)
    put(o,REQUEST+8,op)
    return role(o,next,14,3,REQUEST,32,3,CHILD,128,0,get(w,PTR)+4096,204800)

def role(o:mutbuf,next:u64,action:u64,sb:u64,so:u64,sn:u64,ob:u64,oo:u64,on:u64,wb:u64,wo:u64,wn:u64) -> u32:
    put(o,PH,next)
    put(o,0,sb)
    put(o,8,so)
    put(o,16,sn)
    put(o,24,ob)
    put(o,32,oo)
    put(o,40,on)
    put(o,48,wb)
    put(o,56,wo)
    put(o,64,wn)
    return action

def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def memory(o:mutbuf,next:u64,sb:u64,so:u64,db:u64,do:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sb)
    put(o,8,so)
    put(o,16,db)
    put(o,24,do)
    put(o,32,n)
    return 8

def lock(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 2

def wait(o:mutbuf,next:u64) -> u32:
    put(o,288,0)
    put(o,296,1000000)
    return system(o,next,202,193,64,128,1,288,0,0)

def relock(o:mutbuf,next:u64) -> u32:
    put(o,RELOCK,next)
    return lock(o,850)

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,AFTER,next)
    put(o,PH,900)
    return 3

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10

def reply(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,ERROR))
    put(o,24,get(o,PENDING))
    put(o,32,get(o,RETIRED))
    put(o,40,get(o,KNOWN))
    put(o,48,get(w,STATE))
    put(o,56,get(w,EXTENT))
    put(o,64,get(w,ACTIVE))
    put(o,72,choose(get(w,TOKEN)!=0,1,0))
    put(o,80,choose((get(w,FLAGS)&4)!=0,1,0))
    put(o,88,choose((get(w,FLAGS)&32)!=0,1,0))
    put(o,96,get(o,RETURN_FD))
    put(o,104,get(o,RETURN_N))
    if get(o,RETURN_FD)!=NONE:
        put(o,112,15)
    put(o,120,get(w,STAGE))
    return 0

def failed(value:u64) -> bool:
    return value>=18446744073709547520

def choose(condition:bool,a:u64,b:u64) -> u64:
    if condition:
        return a
    return b

def get(w:mutbuf,offset:u64) -> u64:
    return word_load(w,offset)

def put(w:mutbuf,offset:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,offset+i,(value>>(i*8))&255)
        i=i+1
    return 0

def zero(w:mutbuf,offset:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,offset+i,0)
        i=i+1
    return 0

def copy(s:mutbuf,si:u64,o:mutbuf,oi:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(o,oi+i,byte(s,si+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for name,value in sorted(C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),
          sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
