"""Actual native path coercion with a persistent owned continuation.

The entry consumes no caller-supplied type/verification facts. All value types,
class descriptors and method results come from the fixed captured value owner.
"""
from pathlib import Path
import re,ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAX=(1<<64)-1,BAD=4294967293,PHASE=256,HELD=264,FEED=3840,RQ=4096,RP=8192,
       STATE=128,GUARD=136,MODE=144,OUTCOME=152,DETAIL=160,DEPENDENCY=168,OUTSLOT=176,
       CALLSTATUS=184,INPUTKIND=192,RESULTKIND=200,INPUTBASE=208,RESULTBASE=216,METHOD=224,
       ERRKIND=232,NAME1=240,NAME2=248,MAP0=256,MAP1=272,MAP2=288,MAP3=304,
       N1=320,N2=328,NAMEK1=336,NAMEK2=344,NAMED1=352,NAMED2=360,
       INDEX=368,OFFSET=376,AMOUNT=384,REQUIRED=392,CLEAN=400,MAPCLEAN=408,
       VPENDING=416,INPUTDETAIL=424,RESULTDETAIL=432,REFS=512)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
    MAGIC='HIANPV01',REPLY='HIANPVR1',CONTEXT='HIANPVC1',CALLCONTEXT='HIANPFC1',
    CALLRQ='HIAPFSP1',CALLRP='HIAPFSR1',ERRQ='HIANPER1',VQ='HIABVQ01',VQ2='HIABVQ02',
    VR='HIABVR01',VR2='HIABVR02',DESCRIPTOR='HIAVNO01').items()})
SOURCE=r'''
def native_path_value(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32768 or length(w)<4096:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==10 or phase==20 or phase==21 or phase==40 or phase==41 or phase==42 or phase==101 or phase==104 or phase==116 or phase==201 or phase==202:
        to_work(o,w,2048,RP,128)
        put(w,2304,phase)
        if phase==20 or phase==41:
            to_work(o,w,2176,RP+8192,128)
    if phase<10:
        return enter(s,o,w,phase)
    if phase<50:
        return coercion(s,o,w,phase)
    if phase<100:
        return callback(s,o,w,phase)
    if phase<200:
        return make_error(o,w,phase)
    if phase<300:
        return cleanup(o,w,phase)
    return final_reply(o,w)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=MAGIC or readword(s,8)>2:
        return BAD
    i=40
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    op=readword(s,8)
    if op==2:
        if readword(s,16)!=0 or readword(s,24)!=0 or readword(s,32)!=0:
            return BAD
    elif readword(s,16)==0:
        return BAD
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,16)>MAX-get(w,24) or get(w,32)<2 or get(w,32)>2147483647:
        return BAD
    i=40
    while i<128:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,128,3968)
    return system(o,1,39,0,0,0,0,0,0,0)

def enter(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FEED)!=get(w,32):
            return detached(o,4,1)
        return atomic(o,2,2,GUARD,0,1)
    if phase==2:
        if get(o,FEED)!=0:
            return detached(o,4,2)
        put(o,HELD,1)
        if readword(s,8)==2:
            if get(w,STATE)==3:
                return finish(o,w)
            if get(w,STATE)!=2:
                put(o,DETAIL,3)
                return unlock_error(o,w)
            return again(o,200)
        if get(w,STATE)!=0:
            put(o,DETAIL,4)
            return unlock_error(o,w)
        zero(w,144,3952)
        put(w,STATE,1)
        put(w,MODE,readword(s,8))
        put(w,OUTSLOT,MAX)
        request(o,5)
        from_source(s,o,RQ+24,16,24)
        return value(o,w,10,128)
    return quarantine(o,w,phase)

def coercion(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if value_ok(o)==False:
            return value_failure(o,w,10)
        if capture(o,w,0,RP+24)==False:
            return quarantine(o,w,10)
        put(w,INPUTKIND,get(o,RP+16))
        put(w,INPUTDETAIL,get(o,RP+56))
        if get(w,INPUTKIND)>9:
            return quarantine(o,w,11)
        if get(w,INPUTKIND)==8:
            request(o,26)
            ref_request(o,w,0)
            return value(o,w,20,128)
        if get(w,INPUTKIND)==9:
            request(o,7)
            ref_request(o,w,0)
            return value(o,w,21,128)
        if get(w,INPUTKIND)==4 or get(w,INPUTKIND)==7:
            if get(w,MODE)==0 or get(w,INPUTKIND)==4:
                return outcome(o,w,0,0)
        return error_for(o,w,choose(get(w,MODE)==0,0,2),0,False)
    if phase==20:
        if value_ok(o)==False:
            return value_failure(o,w,20)
        if descriptor(o,w,1)==False:
            return quarantine(o,w,20)
        put(w,INPUTBASE,get(o,RP+8200))
        put(w,METHOD,get(o,RP+8208))
        base=get(w,INPUTBASE)
        if base==4 or base==7:
            if get(w,MODE)==0 or base==4:
                return outcome(o,w,0,0)
            return error_for(o,w,2,0,False)
        if base!=0:
            return quarantine(o,w,21)
        if get(w,METHOD)==0:
            return error_for(o,w,choose(get(w,MODE)==0,0,2),0,False)
        return mapped(o,50,36864)
    if phase==21:
        if value_ok(o)==False:
            return value_failure(o,w,21)
        if get(o,RP+16)!=9 or get(o,RP+56)>2 or get(o,RP+72)!=0:
            return quarantine(o,w,22)
        put(w,INPUTDETAIL,get(o,RP+56))
        return error_for(o,w,choose(get(w,MODE)==0,0,2),0,False)
    if phase==40:
        if value_ok(o)==False:
            return value_failure(o,w,40)
        put(w,RESULTKIND,get(o,RP+16))
        put(w,RESULTDETAIL,get(o,RP+56))
        kind=get(w,RESULTKIND)
        if kind>9:
            return quarantine(o,w,40)
        if kind==8:
            request(o,26)
            ref_request(o,w,4)
            return value(o,w,41,128)
        return inspect_result(o,w,kind)
    if phase==41:
        if value_ok(o)==False:
            return value_failure(o,w,41)
        if descriptor(o,w,5)==False:
            return quarantine(o,w,41)
        base=get(o,RP+8200)
        put(w,RESULTBASE,base)
        if base!=0 and base!=4 and base!=7:
            return quarantine(o,w,42)
        return inspect_result(o,w,base)
    if phase==42:
        if value_ok(o)==False:
            return value_failure(o,w,42)
        if get(w,CALLSTATUS)==1 and get(w,MODE)==1:
            return error_for(o,w,2,0,False)
        return outcome(o,w,2,4)
    return quarantine(o,w,phase)

def inspect_result(o:mutbuf,w:mutbuf,base:u64) -> u32:
    if base==4 or base==7:
        if get(w,MODE)==0 or base==4:
            return outcome(o,w,0,4)
        return error_for(o,w,2,4,False)
    if get(w,MODE)==1:
        return error_for(o,w,2,0,False)
    return error_for(o,w,1,0,True)

def callback(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==50:
        if bad_address(get(o,FEED)):
            return outcome(o,w,3,MAX)
        put(w,MAP0,get(o,FEED))
        put(w,MAP0+8,36864)
        zero(o,RQ,4096)
        put(o,RQ,CALLCONTEXT)
        from_work(w,o,RQ+8,8,32)
        return copied(o,51,3,RQ,0,get(w,MAP0)+32768,4096)
    if phase==51:
        zero(o,RQ,128)
        put(o,RQ,CALLRQ)
        from_work(w,o,RQ+16,REFS,24)
        from_work(w,o,RQ+40,REFS+32,24)
        return invoke(o,52,get(w,METHOD),3,RQ,128,get(w,MAP0),32768,get(w,MAP0)+32768,4096)
    if phase==52:
        if get(o,FEED)!=0:
            return quarantine(o,w,52)
        return copied(o,53,0,get(w,MAP0),3,RP,128)
    if phase==53:
        to_work(o,w,2432,RP,128)
        if get(o,RP)!=CALLRP or get(o,RP+8)>2:
            return quarantine(o,w,53)
        i=40
        while i<128:
            if get(o,RP+i)!=0:
                return quarantine(o,w,53)
            i=i+8
        if capture(o,w,4,RP+16)==False:
            return quarantine(o,w,54)
        put(w,CALLSTATUS,get(o,RP+8))
        return copied(o,54,0,get(w,MAP0)+32768,3,RP,128)
    if phase==54:
        if get(o,RP)!=CALLCONTEXT:
            return quarantine(o,w,55)
        i=8
        while i<40:
            if get(o,RP+i)!=get(w,i):
                return quarantine(o,w,55)
            i=i+8
        while i<128:
            if get(o,RP+i)!=0:
                return quarantine(o,w,55)
            i=i+8
        request(o,7)
        ref_request(o,w,4)
        return value(o,w,choose(get(w,CALLSTATUS)==0,40,42),128)
    return quarantine(o,w,phase)

def descriptor(o:mutbuf,w:mutbuf,start:u64) -> bool:
    if get(o,RP+16)!=8 or get(o,RP+8192)!=DESCRIPTOR or get(o,RP+8216)!=0:
        return False
    i=104
    while i<128:
        if get(o,RP+8192+i)!=0:
            return False
        i=i+8
    i=0
    while i<3:
        if capture(o,w,start+i,RP+8224+i*24)==False:
            return False
        i=i+1
    return True

def error_for(o:mutbuf,w:mutbuf,kind:u64,source:u64,two:bool) -> u32:
    put(w,ERRKIND,kind)
    put(w,NAME1,MAX)
    put(w,NAME2,MAX)
    if source==0:
        put(w,NAMEK1,get(w,INPUTKIND))
        put(w,NAMED1,get(w,INPUTDETAIL))
        if get(w,INPUTKIND)==8:
            put(w,NAME1,3)
    else:
        put(w,NAMEK1,get(w,RESULTKIND))
        put(w,NAMED1,get(w,RESULTDETAIL))
        if get(w,RESULTKIND)==8:
            put(w,NAME1,7)
    if two:
        put(w,NAMEK2,get(w,RESULTKIND))
        put(w,NAMED2,get(w,RESULTDETAIL))
        if get(w,RESULTKIND)==8:
            put(w,NAME2,7)
    put(w,INDEX,0)
    return again(o,100)

def make_error(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        i=get(w,INDEX)
        if i==choose(get(w,ERRKIND)==1,2,1):
            first=get(w,N1)
            second=get(w,N2)
            if first>MAX-64 or second>MAX-64-first:
                return outcome(o,w,3,MAX)
            return mapped(o,102,64+first+second)
        slot=get(w,NAME1+i*8)
        if slot==MAX:
            n=builtin_name(o,RQ,get(w,NAMEK1+i*8),get(w,NAMED1+i*8))
            if n==MAX:
                return quarantine(o,w,100)
            put(w,N1+i*8,n)
            put(w,INDEX,i+1)
            return again(o,100)
        request(o,7)
        ref_request(o,w,slot)
        return value(o,w,101,128)
    if phase==101:
        if value_ok(o)==False:
            return value_failure(o,w,101)
        if get(o,RP+16)!=4:
            return quarantine(o,w,101)
        i=get(w,INDEX)
        put(w,N1+i*8,get(o,RP+72))
        put(w,INDEX,i+1)
        return again(o,100)
    if phase==102:
        if bad_address(get(o,FEED)):
            return outcome(o,w,3,MAX)
        put(w,MAP1,get(o,FEED))
        put(w,MAP1+8,64+get(w,N1)+get(w,N2))
        zero(o,RQ,64)
        put(o,RQ,ERRQ)
        put(o,RQ+8,get(w,ERRKIND))
        put(o,RQ+16,get(w,N1))
        put(o,RQ+24,get(w,N2))
        put(w,INDEX,0)
        put(w,OFFSET,0)
        return copied(o,103,3,RQ,0,get(w,MAP1),64)
    if phase==103:
        i=get(w,INDEX)
        if i==choose(get(w,ERRKIND)==1,2,1):
            return mapped(o,110,65536)
        n=get(w,N1+i*8)
        offset=get(w,OFFSET)
        if offset==n:
            put(w,INDEX,i+1)
            put(w,OFFSET,0)
            return again(o,103)
        slot=get(w,NAME1+i*8)
        if slot==MAX:
            amount=builtin_name(o,RQ,get(w,NAMEK1+i*8),get(w,NAMED1+i*8))
            if amount!=n:
                return quarantine(o,w,103)
            put(w,AMOUNT,amount)
            return copied(o,105,3,RQ,0,get(w,MAP1)+64+choose(i==0,0,get(w,N1)),amount)
        amount=n-offset
        if amount>8192:
            amount=8192
        put(w,AMOUNT,amount)
        request(o,19)
        ref_request(o,w,slot)
        put(o,RQ+104,offset)
        put(o,RQ+112,amount)
        return value(o,w,104,128)
    if phase==104:
        if value_ok(o)==False:
            return value_failure(o,w,104)
        if get(o,RP+16)!=4 or get(o,RP+64)!=get(w,AMOUNT):
            return quarantine(o,w,104)
        position=get(w,MAP1)+64+get(w,OFFSET)
        if get(w,INDEX)!=0:
            position=position+get(w,N1)
        return copied(o,105,3,RP+8192,0,position,get(w,AMOUNT))
    if phase==105:
        put(w,OFFSET,get(w,OFFSET)+get(w,AMOUNT))
        return again(o,103)
    if phase==110:
        if bad_address(get(o,FEED)):
            return outcome(o,w,3,MAX)
        put(w,MAP2,get(o,FEED))
        put(w,MAP2+8,65536)
        return formatter(o,w,111,0,0)
    if phase==111:
        if get(o,FEED)!=4294967294:
            return quarantine(o,w,111)
        return copied(o,112,0,get(w,MAP2),3,RP,16)
    if phase==112:
        n=get(o,RP)
        if n==0:
            return quarantine(o,w,112)
        if n>MAX-128:
            return outcome(o,w,3,MAX)
        put(w,REQUIRED,n)
        return mapped(o,113,128+n)
    if phase==113:
        if bad_address(get(o,FEED)):
            return outcome(o,w,3,MAX)
        put(w,MAP3,get(o,FEED))
        put(w,MAP3+8,128+get(w,REQUIRED))
        request(o,2)
        put(o,RQ+96,get(w,REQUIRED))
        put(o,RQ+104,7)
        return copied(o,114,3,RQ,0,get(w,MAP3),128)
    if phase==114:
        return formatter(o,w,115,get(w,MAP3)+128,get(w,REQUIRED))
    if phase==115:
        if get(o,FEED)!=0:
            return quarantine(o,w,115)
        zero(o,RP,128)
        return invoke(o,116,get(w,8),48,get(w,MAP3),get(w,MAP3+8),RP,24576,get(w,16),get(w,24))
    if phase==116:
        if value_ok(o)==False:
            return value_failure(o,w,116)
        if get(o,RP+16)!=7 or get(o,RP+72)!=get(w,REQUIRED):
            return quarantine(o,w,116)
        if capture(o,w,8,RP+24)==False:
            return quarantine(o,w,117)
        return outcome(o,w,1,8)
    return quarantine(o,w,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(w,VPENDING)!=0:
            request(o,31)
            return value(o,w,202,128)
        i=get(w,CLEAN)
        if i==16:
            return again(o,205)
        if i==get(w,OUTSLOT) or get(w,REFS+i*32+24)==0:
            put(w,CLEAN,i+1)
            return again(o,200)
        if get(w,REFS+i*32+24)!=1:
            return quarantine(o,w,200)
        request(o,29)
        ref_request(o,w,i)
        return value(o,w,201,128)
    if phase==201:
        if drop_ok(o,29)==False:
            return quarantine(o,w,201)
        status=get(o,RP+8)
        known=get(o,RP+88)
        consumed=get(o,RP+96)
        pending=get(o,RP+80)
        if known==0:
            return quarantine(o,w,202)
        if consumed!=0:
            zero(w,REFS+get(w,CLEAN)*32,32)
            put(w,CLEAN,get(w,CLEAN)+1)
        if pending!=0:
            put(w,VPENDING,1)
            if consumed==0:
                return quarantine(o,w,206)
        if status!=0:
            put(w,DEPENDENCY,status)
            if consumed!=0 and pending==0:
                return quarantine(o,w,203)
            if status==1 or status==6:
                return quarantine(o,w,204)
            return suspended(o,w)
        return again(o,200)
    if phase==202:
        if drop_ok(o,31)==False:
            return quarantine(o,w,205)
        if get(o,RP+8)!=0:
            put(w,DEPENDENCY,get(o,RP+8))
            return suspended(o,w)
        put(w,VPENDING,0)
        return again(o,200)
    if phase==205:
        i=get(w,MAPCLEAN)
        if i==4:
            return publish(o,w)
        at=MAP0+i*16
        if get(w,at)==0:
            put(w,MAPCLEAN,i+1)
            return again(o,205)
        return system(o,206,11,0,get(w,at),get(w,at+8),0,0,0,0)
    if phase==206:
        if get(o,FEED)!=0:
            put(w,DEPENDENCY,get(o,FEED))
            return suspended(o,w)
        zero(w,MAP0+get(w,MAPCLEAN)*16,16)
        put(w,MAPCLEAN,get(w,MAPCLEAN)+1)
        return again(o,205)
    return quarantine(o,w,phase)

def drop_ok(o:mutbuf,op:u64) -> bool:
    if get(o,FEED)!=0 or get(o,RP)!=VR2:
        return False
    i=16
    while i<128:
        if i!=80 and i!=88 and i!=96 and get(o,RP+i)!=0:
            return False
        i=i+8
    status=get(o,RP+8)
    pending=get(o,RP+80)
    known=get(o,RP+88)
    consumed=get(o,RP+96)
    if pending>1 or known>1 or consumed>1:
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        return False
    if op==31 and (status==1 or known!=1 or consumed!=0):
        return False
    if status==0:
        return known==1 and pending==0 and consumed==choose(op==31,0,1)
    if status==1:
        return known==1 and consumed==0 and pending==0
    if status==6:
        return known==1 and consumed==0
    if known==0:
        return consumed==0 and pending==0
    return True

def outcome(o:mutbuf,w:mutbuf,status:u64,slot:u64) -> u32:
    put(w,OUTCOME,status)
    put(w,OUTSLOT,slot)
    put(w,CLEAN,0)
    put(w,MAPCLEAN,0)
    return again(o,200)

def value_failure(o:mutbuf,w:mutbuf,at:u64) -> u32:
    if get(o,FEED)!=0 or get(o,RP)!=VR:
        return quarantine(o,w,at)
    status=get(o,RP+8)
    if status==5:
        return outcome(o,w,3,MAX)
    put(w,DEPENDENCY,status)
    put(w,DETAIL,at)
    return outcome(o,w,4,MAX)

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,STATE,3)
    put(w,DEPENDENCY,detail)
    return finish(o,w)

def suspended(o:mutbuf,w:mutbuf) -> u32:
    put(w,STATE,2)
    return finish(o,w)

def publish(o:mutbuf,w:mutbuf) -> u32:
    status=get(w,OUTCOME)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,88,get(w,DETAIL))
    put(o,112,get(w,DEPENDENCY))
    slot=get(w,OUTSLOT)
    if slot!=MAX:
        if slot>=16 or get(w,REFS+slot*32+24)!=1:
            return quarantine(o,w,290)
        at=16
        if status==1:
            at=64
        elif status==2:
            at=40
        elif status!=0:
            return quarantine(o,w,291)
        from_work(w,o,at,REFS+slot*32,24)
        zero(w,REFS+slot*32,32)
    put(w,STATE,0)
    return atomic(o,3,300,GUARD,0,0)

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,4)
    put(o,88,get(w,DETAIL))
    put(o,96,1)
    put(o,104,choose(get(w,STATE)==3,1,0))
    put(o,112,get(w,DEPENDENCY))
    return atomic(o,3,300,GUARD,0,0)

def unlock_error(o:mutbuf,w:mutbuf) -> u32:
    detail=get(o,DETAIL)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,4)
    put(o,88,detail)
    put(o,96,choose(get(w,STATE)!=0,1,0))
    put(o,104,choose(get(w,STATE)==3,1,0))
    return atomic(o,3,300,GUARD,0,0)

def final_reply(o:mutbuf,w:mutbuf) -> u32:
    return 0

def detached(o:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,88,detail)
    return 0

def capture(o:mutbuf,w:mutbuf,slot:u64,at:u64) -> bool:
    if slot>=16 or get(w,REFS+slot*32+24)!=0 or get(o,at)==0:
        return False
    i=0
    while i<16:
        p=REFS+i*32
        if get(w,p+24)!=0 and get(w,p)==get(o,at) and get(w,p+8)==get(o,at+8) and get(w,p+16)==get(o,at+16):
            return False
        i=i+1
    to_work(o,w,REFS+slot*32,at,24)
    put(w,REFS+slot*32+24,1)
    return True

def value_ok(o:mutbuf) -> bool:
    return get(o,FEED)==0 and get(o,RP)==VR and get(o,RP+8)==0

def request(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,choose(op>=25,VQ2,VQ))
    put(o,RQ+8,op)
    return 0

def ref_request(o:mutbuf,w:mutbuf,slot:u64) -> u64:
    from_work(w,o,RQ+24,REFS+slot*32,24)
    return 0

def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    zero(o,RP,128)
    return invoke(o,next,get(w,8),51,RQ,n,RP,24576,get(w,16),get(w,24))

def formatter(o:mutbuf,w:mutbuf,next:u64,out:u64,n:u64) -> u32:
    invoke(o,next,0,0,get(w,MAP1),get(w,MAP1+8),out,n,get(w,MAP2),65536)
    return 11

def mapped(o:mutbuf,next:u64,n:u64) -> u32:
    return system(o,next,9,0,0,n,3,34,MAX,0)

def bad_address(p:u64) -> bool:
    return p==0 or p>=18446744073709547521

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def atomic(o:mutbuf,action:u64,next:u64,offset:u64,expected:u64,value:u64) -> u32:
    put(o,PHASE,next)
    put(o,128,offset)
    put(o,136,expected)
    put(o,144,value)
    return action

def copied(o:mutbuf,next:u64,sr:u64,source:u64,tr:u64,target:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,128,sr)
    put(o,136,source)
    put(o,144,tr)
    put(o,152,target)
    put(o,160,n)
    return 8

def system(o:mutbuf,next:u64,id:u64,selectors:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    invoke(o,next,id,selectors,a,b,c,d,e,f)
    return 1

def invoke(o:mutbuf,next:u64,id:u64,selectors:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,128,id)
    put(o,136,selectors)
    put(o,144,a)
    put(o,152,b)
    put(o,160,c)
    put(o,168,d)
    put(o,176,e)
    put(o,184,f)
    return 9

def get(w:mutbuf,p:u64) -> u64:
    return word_load(w,p)
def readword(s:readbuf,p:u64) -> u64:
    return word_load(s,p)
def put(w:mutbuf,p:u64,v:u64) -> u64:
    word_store(w,p,v)
    return 0
def choose(flag:bool,a:u64,b:u64) -> u64:
    if flag:
        return a
    return b
def zero(w:mutbuf,p:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,p+i,0)
        i=i+1
    return 0
def from_source(s:readbuf,o:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0
def from_work(w:mutbuf,o:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(w,source+i))
        i=i+1
    return 0
def to_work(o:mutbuf,w:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(o,source+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    source+='\ndef builtin_name(o:mutbuf,at:u64,kind:u64,detail:u64) -> u64:\n'
    names={0:'NoneType',1:'bool',2:'int',3:'float',4:'str',5:'list',6:'dict',7:'bytes'}
    for kind,name in names.items():
        source+='    if kind=='+str(kind)+':\n'+''.join('        store(o,at+'+str(i)+','+str(b)+')\n'for i,b in enumerate(name.encode()))+'        return '+str(len(name))+'\n'
    for detail,name in enumerate(('dict_keyiterator','dict_itemiterator','dict_valueiterator')):
        source+='    if kind==9 and detail=='+str(detail)+':\n'+''.join('        store(o,at+'+str(i)+','+str(b)+')\n'for i,b in enumerate(name.encode()))+'        return '+str(len(name))+'\n'
    source+='    return MAX\n'
    for key,value in sorted(C.items(),key=lambda p:-len(p[0])):source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def program():return document(source_program(),'native_path_value')
if __name__=='__main__':
    data=render_assembly(program()).encode();p=ROOT/'examples/hia_bootstrap/native_path_value.hepta';p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);print(p,len(data),flush=True)
