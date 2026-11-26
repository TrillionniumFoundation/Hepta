"""Native enclosing owner for the registered GenerationLease lifecycle.

The HIA policy constructs and binds its carrier registry and lifecycle context.
Only the fixed mechanical bridge supplies current PID and its own code/data
addresses. Request data contains operations and capabilities, never callbacks.
Typed call and immutable GenerationInfo are deliberately separate obligations.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIAGLOQ1','little'),
'REPLY':int.from_bytes(b'HIAGLOR1','little'),
'OWNER':int.from_bytes(b'HIAGLOW1','little'),
'LIFECYCLE':int.from_bytes(b'HIAGLC01','little'),
'HANDLES':int.from_bytes(b'HIAMVHQ1','little'),
'HREPLY':int.from_bytes(b'HIAMVHR1','little'),
'LREQUEST':int.from_bytes(b'HIAGLQ01','little'),
'TCALL':int.from_bytes(b'HIAMVTC1','little'),
'TOOLS':int.from_bytes(b'HIAGLTB1','little'),
'FINALIZER':int.from_bytes(b'HIAVRFC1','little'),
'RESOURCE':int.from_bytes(b'HIAGLOB1','little'),
'INFO_REQUEST':int.from_bytes(b'HIAGLIQ1','little'),
'EFFECTS_REQUEST':int.from_bytes(b'HIAMVEX3','little'),
'EFFECTS_REPLY':int.from_bytes(b'HIAMVER1','little'),
'INFO_FRAME':32768,
'ACKREQUEST':int.from_bytes(b'HIAMVHA1','little'),
'ACKREPLY':int.from_bytes(b'HIAMVHA2','little'),
'FREQUEST':int.from_bytes(b'HIAVRFQ1','little'),
'FREPLY':int.from_bytes(b'HIAVRFR1','little'),
'VALUE1':int.from_bytes(b'HIABVQ01','little'),
'VALUE2':int.from_bytes(b'HIABVQ02','little'),
'VALUE4':int.from_bytes(b'HIABVQ04','little'),
'VALUE5':int.from_bytes(b'HIABVQ05','little'),
'VREPLY1':int.from_bytes(b'HIABVR01','little'),
'VREPLY2':int.from_bytes(b'HIABVR02','little'),
'OUT':(96<<20)+32768,'CHILD':16384,'RQ':4096,
'PHASE':256,'FEEDBACK':384,'BAD':4294967293}
SOURCE=r'''
def owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<OUT or length(w)!=2048:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o)
    if phase==1:
        if get(o,FEEDBACK)==0 or get(o,FEEDBACK)>=18446744073709547521:
            return finish(o,3,0)
        put(o,400,get(o,FEEDBACK))
        put(o,PHASE,2)
        return 4
    if phase==2:
        if get(w,0)!=0:
            if get(w,0)!=OWNER:
                return finish(o,1,0)
            if get(w,8)!=get(o,400):
                return finish(o,3,0)
            if get(w,16)!=get(o,512) or get(w,24)!=get(o,520) or get(w,32)!=get(o,528):
                return finish(o,1,0)
        elif word_load(s,8)!=0:
            return finish(o,1,0)
        put(o,PHASE,3)
        return 2
    if phase==3:
        if get(o,FEEDBACK)!=0:
            if get(o,FEEDBACK)!=1 or get(o,576)>=1048576:
                return finish(o,2,0)
            put(o,576,get(o,576)+1)
            return 2
        return locked(s,o,w)
    if phase==4:
        if word_load(s,8)==1 and length(s)==448:
            if word_load(s,72)==4 and word_load(s,192)==TCALL:
                return typed_begin(s,o)
        put(o,PHASE,12)
        put(o,560,0)
        zero(o,CHILD,128)
        if word_load(s,8)==1:
            return 12
        if word_load(s,8)==2:
            return 13
        return 14
    if phase==10:
        put(o,608,get(o,FEEDBACK))
        if carrier_ok(o)==False:
            return unlock(o,w,5,1)
        return value_control(o,VALUE1,0,14)
    if phase==11:
        put(o,608,get(o,FEEDBACK))
        if carrier_ok(o)==False:
            within(o,2048,CHILD,128)
            put(o,592,get(o,608))
            return value_control(o,VALUE5,53,46)
        put(w,80,5)
        return value_control(o,VALUE2,30,16)
    if phase==14:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY1):
            put(w,848,1)
            put(o,PHASE,42)
            return 18
        return unlock(o,w,5,4)
    if phase==15:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)==0 and get(o,CHILD)==VREPLY1 and get(o,CHILD+8)==6:
            return unlock(o,w,2,4)
        if value_ok(o,VREPLY1)==False:
            put(w,80,9)
            return unlock(o,w,5,4)
        put(o,584,get(w,80))
        put(w,80,2)
        return private_cleanup(o)
    if phase==16:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)!=0 or get(o,CHILD)!=VREPLY2:
            put(w,80,7)
            return unlock(o,w,5,4)
        if get(o,CHILD+88)!=1 or get(o,CHILD+96)!=1:
            put(w,80,7)
            return unlock(o,w,5,4)
        put(w,80,6)
        return value_control(o,VALUE2,31,17)
    if phase==18:
        put(o,608,get(o,FEEDBACK))
        if carrier_ok(o)==False:
            return unlock(o,w,5,1)
        i=512
        empty=True
        while i<768:
            if get(w,i)!=0:
                empty=False
            i=i+8
        if empty:
            put(w,80,8)
            return finalizer_release(o,w)
        if get(w,848)==1:
            put(w,80,5)
            return value_control(o,VALUE2,30,16)
        put(w,80,6)
        return value_control(o,VALUE2,31,17)
    if phase==17:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY2)==False or get(o,CHILD+80)!=0 or get(o,CHILD+88)!=1 or get(o,CHILD+96)!=0:
            return unlock(o,w,5,4)
        put(w,80,8)
        return finalizer_release(o,w)
    if phase==12:
        put(o,608,get(o,FEEDBACK))
        put(o,PHASE,13)
        return 2
    if phase==13:
        if get(o,FEEDBACK)!=0:
            return 2
        if get(w,72)==0:
            return unlock(o,w,5,0)
        put(w,72,get(w,72)-1)
        status=0
        if get(o,608)!=0:
            status=5
        kind=word_load(s,8)
        if get(o,784)!=0:
            kind=get(o,704)
            if get(o,696)!=0:
                status=get(o,696)
        return unlock(o,w,status,kind)
    if phase==30 or phase==31:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1 or get(o,8200)!=0 or get(o,8216)==0:
            put(o,696,1)
            put(o,704,0)
            return typed_cleanup(o)
        if phase==30:
            within(o,640,8216,24)
            within(o,4520,8216,24)
            put(o,688,1)
            return typed_retain(s,o,256,31)
        within(o,664,8216,24)
        within(o,4544,8216,24)
        put(o,688,3)
        put(o,560,2)
        put(o,568,384)
        put(o,PHASE,32)
        zero(o,CHILD,128)
        return 12
    if phase==32:
        put(o,608,get(o,FEEDBACK))
        put(o,704,1)
        if get(o,608)!=0:
            put(o,696,5)
        return typed_cleanup(o)
    if phase==33:
        bit=get(o,712)
        at=640
        if bit==2:
            at=664
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY2 or get(o,8280)!=1 or get(o,8288)!=1:
            count=get(o,720)
            within(o,736+count*24,at,24)
            put(o,720,count+1)
            put(o,696,5)
        if get(o,FEEDBACK)!=0 or get(o,8200)!=0 or get(o,8272)!=0:
            put(o,728,get(o,8200))
        put(o,688,get(o,688)&(3-bit))
        return typed_cleanup(o)
    if phase==34:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1:
            put(o,696,5)
        elif get(o,8200)!=0:
            put(o,728,get(o,8200))
        put(o,PHASE,13)
        return 2
    if phase>=40 and phase<=57:
        return ownership_phases(s,o,w,phase)
    if phase>=60 and phase<=70:
        return info_phases(s,o,w,phase)
    if phase==20:
        return finish(o,get(o,600),get(o,616))
    return BAD

def ownership_phases(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        fd=get(o,FEEDBACK)
        if fd<3 or fd>2147483647:
            put(w,120,fd)
            put(o,800,0)
            put(o,816,0)
            return bank_close(o,w)
        index=get(o,800)
        put(w,88+index*8,fd)
        put(o,800,index+1)
        if index==2:
            put(w,112,1)
            put(w,120,0)
            return unlock(o,w,0,0)
        return bank_duplicate(s,o)
    if phase==41:
        if get(o,FEEDBACK)!=0:
            put(w,112,2)
            put(w,120,get(o,FEEDBACK))
            return unlock(o,w,5,0)
        put(w,88+get(o,800)*8,0)
        put(o,800,get(o,800)+1)
        return bank_close(o,w)
    if phase==42:
        pointer=get(o,FEEDBACK)
        if pointer==0 or pointer>=18446744073709547521:
            return unlock(o,w,5,0)
        put(w,800,pointer)
        put(w,808,100663296)
        put(o,824,0)
        put(o,PHASE,43)
        return 19
    if phase==43:
        count=get(o,FEEDBACK)
        if count==18446744073709551612:
            return 19
        used=get(o,824)
        if count==0 or count>8-used:
            return unlock(o,w,5,0)
        used=used+count
        put(o,824,used)
        if used<8:
            return 19
        if get(w,832)==0:
            return unlock(o,w,5,0)
        put(w,768,FINALIZER)
        put(w,784,get(o,400))
        put(w,792,get(o,512)+768)
        put(w,816,get(o,512)+256)
        put(w,824,get(o,528))
        put(w,840,1)
        put(w,864,get(w,800)^get(w,832))
        put(w,640,get(o,544))
        put(w,648,get(o,512)+768)
        put(w,656,256)
        put(w,664,get(w,832))
        put(w,680,6)
        put(w,80,1)
        return unlock(o,w,0,4)
    if phase==44:
        if get(o,FEEDBACK)!=0:
            put(w,856,get(o,FEEDBACK))
            return unlock(o,w,5,0)
        zero(w,800,16)
        put(w,856,0)
        put(o,800,0)
        put(o,816,1)
        return bank_close(o,w)
    if phase==46:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY1)==False:
            put(w,80,9)
            return unlock(o,w,5,4)
        within(o,CHILD,2048,128)
        put(o,608,get(o,592))
        put(w,80,get(o,584))
        return unlock(o,w,2,1)
    if phase==47:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY1)==False:
            return unlock(o,w,5,4)
        put(w,80,1)
        return unlock(o,w,5,4)
    if phase==48:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)!=0 or get(o,CHILD)!=ACKREPLY:
            put(w,80,9)
            return unlock(o,w,5,1)
        if get(o,CHILD+96)!=1 or get(o,CHILD+104)!=0 or get(o,CHILD+112)>1:
            put(w,80,9)
            return unlock(o,w,5,1)
        if get(o,CHILD+8)!=0 or get(o,CHILD+112)!=0:
            within(o,2048,CHILD,128)
            put(o,592,get(o,608))
            return value_control(o,VALUE5,53,46)
        return control(o,5,11)
    if phase==50:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)!=0 or get(o,CHILD)!=HREPLY:
            put(w,80,7)
            return unlock(o,w,5,1)
        if get(o,CHILD+8)!=0:
            if get(o,CHILD+24)!=0:
                put(w,80,7)
                return unlock(o,w,5,1)
            return unlock(o,w,1,1)
        kind=get(o,CHILD+16)
        if kind<1 or kind>2 or get(o,CHILD+24)==0:
            put(w,80,7)
            return unlock(o,w,5,1)
        put(w,1024,1)
        put(w,1032,kind)
        put(w,1040,get(o,CHILD+24))
        put(w,1048,get(o,CHILD+32))
        put(w,1056,get(o,CHILD+40))
        if kind!=word_load(s,72):
            put(o,920,1)
            put(o,928,1)
            put(o,936,0)
            return resource_drop(o,w)
        if kind==2:
            return resource_parent(s,o)
        return resource_capture(s,o,w)
    if phase==51:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)!=0 or get(o,CHILD)!=VREPLY1:
            return resource_quarantine(o,w,4)
        known=get(o,CHILD+88)
        consumed=get(o,CHILD+96)
        pending=get(o,CHILD+80)
        if known!=1 or consumed>1 or pending>1:
            return resource_quarantine(o,w,4)
        if consumed==1:
            if get(o,CHILD+24)==0:
                return resource_quarantine(o,w,4)
            zero(w,1024,64)
            if get(o,CHILD+8)==0 and pending==0:
                return unlock(o,w,0,4)
            return unlock(o,w,5,4)
        if get(o,CHILD+24)!=0:
            return resource_quarantine(o,w,4)
        put(o,920,5)
        put(o,928,4)
        put(o,936,0)
        return resource_drop(o,w)
    if phase==52:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=FREPLY:
            return resource_quarantine(o,w,get(o,928))
        if get(o,8208)!=1 or get(o,8216)>1 or get(o,8224)>1:
            return resource_quarantine(o,w,get(o,928))
        if get(o,8216)==0:
            put(w,80,10)
            return unlock(o,w,5,get(o,928))
        zero(w,1024,64)
        put(w,80,1)
        if get(o,936)!=0:
            return value_control(o,VALUE5,56,54)
        if get(o,8200)!=0 or get(o,8224)!=0:
            put(o,920,5)
        return unlock(o,w,get(o,920),get(o,928))
    if phase==55:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1 or get(o,8200)!=0:
            return resource_binding_error(o,w)
        if get(o,8208)!=1 or get(o,8216)==0:
            return resource_binding_error(o,w)
        zero(o,RQ,128)
        zero(o,CHILD,128)
        put(o,RQ,ACKREQUEST)
        put(o,RQ+8,6)
        put(o,RQ+16,1)
        within(o,RQ+24,8216,24)
        put(o,560,1)
        put(o,PHASE,56)
        return 12
    if phase==56:
        if resource_query_ok(o,1)==False:
            return resource_binding_error(o,w)
        put(o,992,get(o,CHILD+40))
        put(o,1000,get(o,CHILD+24))
        put(o,1008,get(o,CHILD+32))
        zero(o,RQ,128)
        zero(o,CHILD,128)
        put(o,RQ,ACKREQUEST)
        put(o,RQ+8,6)
        put(o,RQ+16,2)
        put(o,RQ+24,get(w,1040))
        put(o,RQ+32,get(w,1048))
        put(o,RQ+40,get(w,1056))
        put(o,560,1)
        put(o,PHASE,57)
        return 12
    if phase==57:
        if resource_query_ok(o,2)==False:
            return resource_binding_error(o,w)
        if get(o,CHILD+40)!=get(o,992) or get(o,CHILD+24)!=get(o,1000) or get(o,CHILD+32)!=get(o,1008):
            return resource_binding_error(o,w)
        return resource_capture(s,o,w)
    if phase==54:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY1)==False:
            return unlock(o,w,5,4)
        return value_control(o,VALUE5,52,15)
    return BAD

def begin(s:readbuf,o:mutbuf) -> u32:
    if word_load(s,0)!=MAGIC or (word_load(s,8)>8 or word_load(s,8)==5) or word_load(s,16)!=length(s)-64:
        return BAD
    i=24
    while i<64:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    op=word_load(s,8)
    size=word_load(s,16)
    if op==0 or op==3:
        if size!=0:
            return BAD
    elif op==1:
        if size<128 or word_load(s,64)!=HANDLES:
            return BAD
        action=word_load(s,72)
        if action==0 or action==5 or action>7:
            return BAD
    elif op==2:
        if size!=64 or word_load(s,64)!=LREQUEST:
            return BAD
    elif op==4:
        if size<128:
            return BAD
        magic=word_load(s,64)
        action=word_load(s,72)
        if magic==VALUE1 and (action==0 or action==20):
            return BAD
        if magic==VALUE2 and (action==30 or action==31):
            return BAD
        if magic==VALUE5 and action!=50 and action!=51 and action!=57:
            return BAD
    elif op==6:
        if size!=32 or word_load(s,64)!=TOOLS:
            return BAD
        i=72
        while i<96:
            if word_load(s,i)<3 or word_load(s,i)>2147483647:
                return BAD
            i=i+8
    elif op==7:
        if size!=64 or word_load(s,64)!=RESOURCE:
            return BAD
        if word_load(s,72)<1 or word_load(s,72)>2:
            return BAD
        if word_load(s,72)==1:
            i=104
            while i<128:
                if word_load(s,i)!=0:
                    return BAD
                i=i+8
        elif word_load(s,104)==0:
            return BAD
    elif op==8:
        if size!=32 or word_load(s,64)!=INFO_REQUEST:
            return BAD
    zero(o,128,8192-128)
    zero(o,CHILD,128)
    put(o,PHASE,1)
    return 1

def locked(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=word_load(s,8)
    if get(w,64)!=1:
        return unlock(o,w,1,0)
    if get(w,0)==0:
        if op!=0:
            return unlock(o,w,1,0)
        i=0
        while i<2048:
            if i!=64 and get(w,i)!=0:
                return unlock(o,w,1,0)
            i=i+8
        put(w,8,get(o,400))
        put(w,16,get(o,512))
        put(w,24,get(o,520))
        put(w,32,get(o,528))
        put(w,40,get(o,536))
        put(w,48,get(o,512)+512)
        put(w,56,256)
        put(w,80,4)
        put(w,128,LIFECYCLE)
        put(w,136,get(o,528))
        put(w,144,get(o,512)+256)
        put(w,152,256)
        put(w,160,get(o,400))
        put(w,0,OWNER)
        return control(o,0,10)
    if get(w,0)!=OWNER or get(w,8)!=get(o,400) or get(w,16)!=get(o,512) or get(w,24)!=get(o,520) or get(w,32)!=get(o,528):
        return unlock(o,w,1,0)
    if get(w,40)!=get(o,536) or get(w,48)!=get(o,512)+512 or get(w,56)!=256:
        return unlock(o,w,1,0)
    bank=get(w,112)
    if bank>2:
        return unlock(o,w,1,0)
    i=88
    while i<112:
        fd=get(w,i)
        if bank==0 and fd!=0:
            return unlock(o,w,1,0)
        if bank==1 and (fd<3 or fd>2147483647):
            return unlock(o,w,1,0)
        if bank==2 and fd!=0 and (fd<3 or fd>2147483647):
            return unlock(o,w,1,0)
        i=i+8
    if bank!=2 and get(w,120)!=0:
        return unlock(o,w,1,0)
    state=get(w,80)
    if state==3:
        if op==3:
            return unlock(o,w,0,0)
        return unlock(o,w,4,0)
    if get(w,128)!=LIFECYCLE or get(w,136)!=get(o,528) or get(w,144)!=get(o,512)+256 or get(w,152)!=256 or get(w,160)!=get(o,400):
        return unlock(o,w,1,0)
    i=168
    while i<256:
        if get(w,i)!=0:
            return unlock(o,w,1,0)
        i=i+8
    if state==1:
        if get(w,768)!=FINALIZER or get(w,784)!=get(o,400) or get(w,792)!=get(o,512)+768 or get(w,840)!=1:
            return unlock(o,w,1,0)
        if get(w,816)!=get(o,512)+256 or get(w,824)!=get(o,528) or get(w,800)==0 or get(w,808)!=100663296:
            return unlock(o,w,1,0)
        if get(w,640)!=get(o,544) or get(w,648)!=get(o,512)+768 or get(w,656)!=256 or get(w,664)!=get(w,832):
            return unlock(o,w,1,0)
        if get(w,680)!=6:
            return unlock(o,w,1,0)
        if get(w,848)!=1 or get(w,856)!=0 or (get(w,800)^get(w,832))!=get(w,864):
            return unlock(o,w,1,0)
    if op==0:
        if state==1:
            return unlock(o,w,0,0)
        return unlock(o,w,5,0)
    if op==3:
        if get(w,72)!=0:
            return unlock(o,w,2,0)
        if state==10:
            if get(w,1024)!=1 or get(w,1032)<1 or get(w,1032)>2 or get(w,1040)==0:
                return unlock(o,w,5,0)
            put(o,928,0)
            put(o,936,1)
            return resource_drop(o,w)
        if state==8:
            return finalizer_release(o,w)
        if state==9:
            return value_control(o,VALUE5,53,47)
        if state==4:
            return control(o,5,18)
        if state==6:
            return value_control(o,VALUE2,31,17)
        if state==5:
            return value_control(o,VALUE2,30,16)
        if state!=1:
            return unlock(o,w,5,0)
        if get(w,1120)!=0 or get(w,1128)!=0:
            put(o,1152,1)
            return info_fds(o,w)
        return value_control(o,VALUE5,56,54)
    if state!=1:
        return unlock(o,w,4,0)
    if op==6:
        if bank!=0 or get(w,72)!=0:
            return unlock(o,w,2,0)
        put(w,112,2)
        put(o,800,0)
        return bank_duplicate(s,o)
    if op==8:
        if get(w,1104)!=0 or get(w,1112)!=0 or get(w,1120)!=0 or get(w,1128)!=0:
            return unlock(o,w,5,0)
        return info_begin(s,o)
    if op==7:
        if get(w,72)!=0:
            return unlock(o,w,2,0)
        if get(w,1024)!=0:
            return unlock(o,w,5,0)
        return resource_begin(s,o)
    if get(w,72)==18446744073709551615:
        return unlock(o,w,2,0)
    put(w,72,get(w,72)+1)
    put(o,PHASE,4)
    return 3


def info_begin(s:readbuf,o:mutbuf) -> u32:
    put(o,704,4)
    zero(o,RQ,128)
    zero(o,8192,128)
    put(o,RQ,VALUE1)
    put(o,RQ+8,5)
    copy_source(s,o,72,RQ+24,24)
    put(o,PHASE,60)
    return 15

def info_phases(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==60:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1 or get(o,8200)!=0 or get(o,8216)==0:
            within(o,CHILD,8192,128)
            put(o,1144,1)
            return info_tempdrop(o,w)
        within(o,640,8216,24)
        put(o,688,1)
        zero(o,RQ,128)
        zero(o,8192,128)
        put(o,RQ,VALUE5)
        put(o,RQ+8,49)
        put(o,RQ+104,2)
        within(o,RQ+24,640,24)
        put(o,PHASE,61)
        return 15
    if phase==61:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1 or get(o,8200)!=0 or get(o,8208)!=2 or get(o,8216)==0:
            within(o,CHILD,8192,128)
            put(o,1144,1)
            return info_tempdrop(o,w)
        within(o,960,8216,24)
        zero(o,RQ,128)
        zero(o,CHILD,128)
        put(o,RQ,ACKREQUEST)
        put(o,RQ+8,6)
        put(o,RQ+16,2)
        within(o,RQ+24,960,24)
        put(o,560,1)
        put(o,PHASE,62)
        return 12
    if phase==62:
        if resource_query_ok(o,2)==False:
            put(o,1144,5)
            put(o,704,1)
            return info_tempdrop(o,w)
        put(o,1088,get(o,CHILD+24))
        put(o,1096,get(o,CHILD+32))
        zero(o,4352,384)
        put(o,4352,HANDLES)
        put(o,4360,4)
        within(o,4376,960,24)
        put(o,4424,256)
        put(o,4480,EFFECTS_REQUEST)
        put(o,4488,6)
        put(o,4552,18446744073709551615)
        put(o,560,2)
        put(o,568,384)
        zero(o,CHILD,128)
        put(o,PHASE,63)
        return 12
    if phase==63:
        put(o,608,get(o,FEEDBACK))
        if carrier_ok(o)==False:
            put(o,1144,5)
            put(o,704,1)
            return info_tempdrop(o,w)
        at=get(o,CHILD+56)
        if at==0 or at>100663296-160 or get(o,CHILD+64)<160:
            put(o,1144,5)
            put(o,704,1)
            return info_tempdrop(o,w)
        at=CHILD+at
        if get(o,at)!=EFFECTS_REPLY:
            put(o,1144,5)
            put(o,704,1)
            return info_tempdrop(o,w)
        put(w,1104,get(o,at+144))
        put(w,1112,get(o,at+152))
        put(o,1104,get(w,1104))
        put(o,1112,get(w,1112))
        i=0
        while i<2:
            fd=get(o,at+96+i*8)
            if fd!=18446744073709551615:
                if fd>2147483647:
                    put(w,80,7)
                    return unlock(o,w,5,1)
                put(w,1120+i*8,fd+1)
            i=i+1
        if get(o,at+8)!=0 or get(w,1104)==0 or get(w,1112)<32 or get(w,1112)>OUT-INFO_FRAME-128:
            put(o,1144,5)
            put(o,704,1)
            return info_release(o,w)
        zero(o,INFO_FRAME,128)
        put(o,INFO_FRAME,VALUE5)
        put(o,INFO_FRAME+8,60)
        put(o,INFO_FRAME+96,get(w,1112))
        put(o,INFO_FRAME+104,get(o,1088))
        put(o,INFO_FRAME+112,get(o,1096))
        put(o,PHASE,64)
        return 23
    if phase==64:
        zero(o,CHILD,128)
        put(o,PHASE,65)
        return 24
    if phase==65:
        put(o,608,get(o,FEEDBACK))
        if get(o,608)!=0 or get(o,CHILD)!=VREPLY1:
            put(o,1144,5)
        elif get(o,CHILD+8)!=0:
            put(o,1144,5)
        elif get(o,CHILD+16)!=12 or get(o,CHILD+24)==0:
            put(o,1144,5)
        put(o,704,4)
        return info_release(o,w)
    if phase==66:
        zero(w,1104,16)
        return info_fds(o,w)
    if phase==68:
        if get(o,FEEDBACK)!=0:
            put(o,728,11)
            if get(o,1152)==1:
                return unlock(o,w,5,0)
            return info_tempdrop(o,w)
        put(w,1120+get(o,1136)*8,0)
        return info_fds(o,w)
    if phase==69:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY2 or get(o,8280)!=1 or get(o,8288)!=1:
            within(o,736,640,24)
            put(o,720,1)
            put(o,1144,5)
        if get(o,FEEDBACK)!=0 or get(o,8200)!=0 or get(o,8272)!=0:
            put(o,728,get(o,8200))
        put(o,688,0)
        return info_tempdrop(o,w)
    if phase==70:
        if get(o,FEEDBACK)!=0 or get(o,8192)!=VREPLY1:
            put(o,1144,5)
        elif get(o,8200)!=0:
            put(o,728,get(o,8200))
        return unlock(o,w,get(o,1144),get(o,704))
    return BAD

def info_release(o:mutbuf,w:mutbuf) -> u32:
    if get(w,1104)!=0:
        put(o,1104,get(w,1104))
        put(o,PHASE,66)
        return 25
    zero(w,1104,16)
    return info_fds(o,w)

def info_fds(o:mutbuf,w:mutbuf) -> u32:
    i=0
    while i<2:
        if get(w,1120+i*8)!=0:
            put(o,808,get(w,1120+i*8)-1)
            put(o,1136,i)
            put(o,PHASE,68)
            return 17
        i=i+1
    if get(o,1152)==1:
        return value_control(o,VALUE5,56,54)
    return info_tempdrop(o,w)

def info_tempdrop(o:mutbuf,w:mutbuf) -> u32:
    zero(o,RQ,128)
    zero(o,8192,128)
    if get(o,688)!=0:
        put(o,RQ,VALUE2)
        put(o,RQ+8,29)
        within(o,RQ+24,640,24)
        put(o,PHASE,69)
        return 15
    put(o,RQ,VALUE5)
    put(o,RQ+8,56)
    put(o,PHASE,70)
    return 15

def private_cleanup(o:mutbuf) -> u32:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,ACKREQUEST)
    put(o,RQ+8,7)
    put(o,560,1)
    put(o,PHASE,48)
    return 12

def resource_begin(s:readbuf,o:mutbuf) -> u32:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,HANDLES)
    put(o,RQ+8,2)
    copy_source(s,o,80,RQ+24,24)
    put(o,560,1)
    put(o,PHASE,50)
    return 12

def resource_parent(s:readbuf,o:mutbuf) -> u32:
    zero(o,RQ,128)
    zero(o,8192,128)
    put(o,RQ,VALUE5)
    put(o,RQ+8,49)
    put(o,RQ+104,1)
    copy_source(s,o,104,RQ+24,24)
    put(o,PHASE,55)
    return 15

def resource_query_ok(o:mutbuf,kind:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=ACKREPLY or get(o,CHILD+8)!=0:
        return False
    if get(o,CHILD+16)!=kind or get(o,CHILD+40)==0:
        return False
    if get(o,CHILD+96)!=1 or get(o,CHILD+104)!=0 or get(o,CHILD+112)!=0:
        return False
    return get(o,CHILD+24)!=0 or get(o,CHILD+32)!=0

def resource_binding_error(o:mutbuf,w:mutbuf) -> u32:
    put(o,920,1)
    put(o,928,0)
    put(o,936,0)
    return resource_drop(o,w)

def resource_capture(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,RQ,152)
    zero(o,CHILD,128)
    put(o,RQ,VALUE5)
    put(o,RQ+8,48)
    put(o,RQ+96,24)
    put(o,RQ+104,get(w,1032))
    if get(w,1032)==2:
        copy_source(s,o,104,RQ+24,24)
    put(o,RQ+128,get(w,1040))
    put(o,RQ+136,get(w,1048))
    put(o,RQ+144,get(w,1056))
    put(o,PHASE,51)
    return 21

def resource_drop(o:mutbuf,w:mutbuf) -> u32:
    zero(o,RQ,128)
    zero(o,8192,128)
    put(o,RQ,FREQUEST)
    put(o,RQ+16,get(w,832))
    put(o,RQ+24,get(w,1032))
    put(o,RQ+32,get(w,1040))
    put(o,RQ+40,get(w,1048))
    put(o,RQ+48,get(w,1056))
    put(o,PHASE,52)
    return 22

def resource_quarantine(o:mutbuf,w:mutbuf,kind:u64) -> u32:
    put(w,1024,2)
    put(w,80,7)
    return unlock(o,w,5,kind)

def finalizer_release(o:mutbuf,w:mutbuf) -> u32:
    put(w,840,0)
    if get(w,800)!=0:
        put(o,PHASE,44)
        return 20
    put(o,800,0)
    put(o,816,1)
    return bank_close(o,w)

def bank_duplicate(s:readbuf,o:mutbuf) -> u32:
    put(o,808,word_load(s,72+get(o,800)*8))
    put(o,PHASE,40)
    return 16

def bank_close(o:mutbuf,w:mutbuf) -> u32:
    index=get(o,800)
    while index<3:
        fd=get(w,88+index*8)
        if fd!=0:
            put(o,800,index)
            put(o,808,fd)
            put(o,PHASE,41)
            return 17
        index=index+1
    zero(w,88,40)
    if get(o,816)==0:
        return unlock(o,w,5,0)
    put(w,80,3)
    zero(w,128,1920)
    return unlock(o,w,0,0)

def typed_begin(s:readbuf,o:mutbuf) -> u32:
    put(o,784,1)
    put(o,704,0)
    copy_source(s,o,64,4352,384)
    return typed_retain(s,o,232,30)

def typed_retain(s:readbuf,o:mutbuf,at:u64,next:u64) -> u32:
    zero(o,RQ,128)
    zero(o,8192,128)
    put(o,RQ,VALUE1)
    put(o,RQ+8,5)
    copy_source(s,o,at,RQ+24,24)
    put(o,PHASE,next)
    return 15

def typed_cleanup(o:mutbuf) -> u32:
    mask=get(o,688)
    if mask==0:
        zero(o,RQ,128)
        zero(o,8192,128)
        put(o,RQ,VALUE5)
        put(o,RQ+8,56)
        put(o,PHASE,34)
        return 15
    bit=1
    at=640
    if (mask&2)!=0:
        bit=2
        at=664
    zero(o,RQ,128)
    zero(o,8192,128)
    put(o,RQ,VALUE2)
    put(o,RQ+8,29)
    within(o,RQ+24,at,24)
    put(o,712,bit)
    put(o,PHASE,33)
    return 15

def control(o:mutbuf,op:u64,next:u64) -> u32:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,HANDLES)
    put(o,RQ+8,op)
    put(o,560,1)
    put(o,PHASE,next)
    return 12

def carrier_ok(o:mutbuf) -> bool:
    return get(o,608)==0 and get(o,CHILD)==HREPLY and get(o,CHILD+8)==0

def value_control(o:mutbuf,magic:u64,op:u64,next:u64) -> u32:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    put(o,560,1)
    put(o,PHASE,next)
    return 14

def value_ok(o:mutbuf,magic:u64) -> bool:
    return get(o,608)==0 and get(o,CHILD)==magic and get(o,CHILD+8)==0

def unlock(o:mutbuf,w:mutbuf,status:u64,kind:u64) -> u32:
    put(o,600,status)
    put(o,616,kind)
    put(o,624,get(w,80))
    put(o,632,get(w,72))
    put(o,PHASE,20)
    return 3

def finish(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    if kind!=0:
        put(o,24,CHILD)
        size=100663296
        if kind==2:
            size=100679680
        put(o,32,size)
    put(o,40,get(o,608))
    put(o,48,get(o,624))
    put(o,56,get(o,632))
    put(o,64,get(o,720))
    put(o,72,get(o,728))
    within(o,80,736,get(o,720)*24)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def copy_source(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def within(w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    fill_range(w,at,n,0)
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size)
if __name__=='__main__':
    main()
