"""Actual VFY diagnostic payload to a native HIAProgramRejected instance.

The input is an independently owned immutable payload capability from the
captured VFY3/4 owner. Both descriptor domains are parsed by the sole native
Value arena. A driver envelope's E_DRIVER is never used as the HIA code.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,OUT=65536,WORK=8192,
 PHASE=128,OP=136,STATUS=144,DETAIL=152,QUAR=160,PENDING=168,FORMAT=176,CLEAN=184,
 FRAMEN=192,FRAME=200,RAWN=208,CURSOR=216,CODEN=224,CHUNK=232,RETURN=240,AFTER=248,
 REFS=256,PAYCAP=256,TREE=280,STATUSVAL=304,OKVAL=328,DIAGS=352,INDEX=376,ROW=400,
 DRIVER=424,DRIVERPHASE=448,MESSAGE=472,DECLCLASS=496,CODE=520,NAMESPACE=544,
 CLASS=568,LIST=592,TUPLE=616,PRIMARY=640,KEY=664,
 LOOKOBJ=704,LOOKDEST=712,LOOKNEXT=720,FIELD=728,TEXTAT=736,TEXTID=744,TEXTNEXT=752,
 PREVIOUS=760,MAP_PENDING=768,COPYN=776,PTR=784,
 RQ=4096,RP=8192,RAWBUF=32768,FEEDBACK=1024)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 Q='HIARTXQ1',R='HIARTXR1',CTX='HIARTVC1',ERTAG='HIARTXC1',V6='HIABVQ06',V7='HIABVQ07',
 V5='HIABVQ05',V10='HIABVQ10',V11='HIABVQ11',VR='HIABVR01',VR2='HIABVR02',
 PQ='HIABPY01',PR='HIABPYR1').items()})
SOURCE=r'''
def exception(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<=9:
        return importing(s,o,w,phase)
    if phase<30:
        return selecting(o,w,phase)
    if phase<40:
        return field_result(o,w,phase)
    if phase>=70 and phase<80:
        return code_prefix(o,w,phase)
    if phase>=80 and phase<90:
        return text_result(o,w,phase)
    if phase>=90 and phase<100:
        return constructing(o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)!=WORK or word_load(s,0)!=Q or word_load(s,8)>1:
        return BAD
    if word_load(s,8)==0:
        if word_load(s,16)<1 or word_load(s,16)>2 or word_load(s,24)==0:
            return BAD
    at=16
    while at<128:
        if word_load(s,8)!=0 or at>40:
            if word_load(s,at)!=0:
                return BAD
        at=at+8
    if get(w,0)!=CTX or get(w,8)==0 or get(w,16)==0 or get(w,24)!=256:
        return BAD
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)!=256 or get(w,144)==0 or get(w,152)>1 or get(w,160)>2:
        return BAD
    if get(w,152)!=0 and get(w,184)!=ERTAG:
        return BAD
    if get(w,152)==0 and get(w,184)!=0:
        return BAD
    at=192
    while at<256:
        if get(w,at)!=0:
            return BAD
        at=at+8
    zero(o,128,896)
    put(o,OP,word_load(s,8))
    put(o,FORMAT,word_load(s,16))
    return system(o,1,39,0,0,0,0,0,0,0)

def importing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FEEDBACK)!=get(w,144):
            return finish(o,w,6)
        put(o,0,0)
        put(o,PHASE,2)
        return 4
    if phase==2:
        pointer=get(o,FEEDBACK)
        if get(w,152)!=0 and get(w,168)!=pointer:
            return finish(o,w,6)
        put(w,168,pointer)
        if get(o,OP)==1:
            if get(w,152)==0:
                return finish(o,w,0)
            if get(w,160)!=1:
                put(o,QUAR,2)
                return finish(o,w,9)
            from_work(w,o,256,128,896)
            put(o,OP,1)
            put(o,QUAR,0)
            put(w,152,0)
            put(w,160,0)
            return again(o,100)
        if get(w,152)!=0:
            return finish(o,w,6)
        request(o,PQ,2)
        copy_source(s,o,24,RQ+24,24)
        return payload(o,w,3)
    if phase==3:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PR:
            return isolate(o,w,2,3)
        if get(o,RP+16)!=0:
            within(o,PAYCAP,RP+16,24)
        if get(o,RP+8)!=0:
            return failed(o,7,get(o,RP+8))
        if get(o,PAYCAP)==0:
            return isolate(o,w,2,4)
        request(o,PQ,6)
        within(o,RQ+24,PAYCAP,24)
        return payload(o,w,4)
    if phase==4:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PR or get(o,RP+8)!=0:
            return failed(o,7,4)
        n=get(o,RP+40)
        if n==0 or n>67108864 or get(o,RP+64)==0:
            return failed(o,7,5)
        put(o,PTR,get(o,RP+64))
        put(o,FRAMEN,n+128)
        return system(o,5,9,0,0,n+128,3,34,MAX,0)
    if phase==5:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=MAX-4094:
            return failed(o,5,raw)
        put(o,FRAME,raw)
        request(o,V10,1)
        put(o,RQ+96,get(o,FRAMEN)-128)
        return memory(o,6,3,RQ,0,raw,128)
    if phase==6:
        return memory(o,7,0,get(o,PTR),0,get(o,FRAME)+128,get(o,FRAMEN)-128)
    if phase==7:
        return invoke(o,8,get(w,8),48,get(o,FRAME),get(o,FRAMEN),RP,32768,get(w,16),256)
    if phase==8:
        if take(o,TREE)==False:
            return dependency(o,w)
        request(o,V6,7)
        within(o,RQ+24,TREE,24)
        return value(o,w,9,128)
    if phase==9:
        if okay(o)==False or get(o,RP+16)!=6 or get(o,RP+48)!=3:
            return failed(o,7,9)
        if get(o,FORMAT)==1:
            return field(o,w,TREE,1,STATUSVAL,10)
        return field(o,w,TREE,7,DECLCLASS,20)
    return failed(o,7,phase)

def selecting(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        return exact_text(o,w,STATUSVAL,8,11)
    if phase==11:
        return field(o,w,TREE,2,OKVAL,12)
    if phase==12:
        request(o,V6,7)
        within(o,RQ+24,OKVAL,24)
        return value(o,w,13,128)
    if phase==13:
        if okay(o)==False or get(o,RP+16)!=1 or get(o,RP+72)!=1:
            return failed(o,7,13)
        request(o,V6,19)
        within(o,RQ+24,OKVAL,24)
        put(o,RQ+112,1)
        return value(o,w,14,128)
    if phase==14:
        if okay(o)==False or get(o,RP+64)!=1 or byte(o,RP+8192)!=0:
            return failed(o,7,14)
        return field(o,w,TREE,3,DIAGS,15)
    if phase==15:
        request(o,V6,7)
        within(o,RQ+24,DIAGS,24)
        return value(o,w,16,128)
    if phase==16:
        if okay(o)==False or get(o,RP+16)!=5 or get(o,RP+48)!=1:
            return failed(o,7,16)
        request(o,V6,2)
        put(o,RQ+104,2)
        put(o,RQ+96,1)
        store(o,RQ+128,48)
        return value(o,w,17,129)
    if phase==17:
        if take(o,INDEX)==False:
            return dependency(o,w)
        request(o,V7,12)
        within(o,RQ+24,DIAGS,24)
        within(o,RQ+48,INDEX,24)
        return value(o,w,18,128)
    if phase==18:
        if take(o,ROW)==False:
            return dependency(o,w)
        request(o,V6,7)
        within(o,RQ+24,ROW,24)
        return value(o,w,19,128)
    if phase==19:
        if okay(o)==False or get(o,RP+16)!=6 or get(o,RP+48)!=3:
            return failed(o,7,19)
        return field(o,w,ROW,4,DRIVER,21)
    if phase==20:
        return exact_text(o,w,DECLCLASS,11,22)
    if phase==21:
        return exact_text(o,w,DRIVER,9,23)
    if phase==22:
        return field(o,w,TREE,4,CODE,24)
    if phase==23:
        return field(o,w,ROW,5,DRIVERPHASE,25)
    if phase==24:
        return field(o,w,TREE,6,MESSAGE,26)
    if phase==25:
        return exact_text(o,w,DRIVERPHASE,10,27)
    if phase==27:
        return field(o,w,ROW,6,MESSAGE,26)
    if phase==26:
        request(o,V6,7)
        within(o,RQ+24,MESSAGE,24)
        return value(o,w,28,128)
    if phase==28:
        n=get(o,RP+72)
        if okay(o)==False or get(o,RP+16)!=4 or n<8 or n>get(o,FRAMEN)-128:
            return failed(o,7,28)
        put(o,RAWN,n)
        put(o,CURSOR,0)
        put(o,CODEN,MAX)
        put(o,PREVIOUS,0)
        return prefix_read(o,w)
    return failed(o,7,phase)

def field(o:mutbuf,w:mutbuf,obj:u64,id:u64,dest:u64,next:u64) -> u32:
    if get(o,KEY)!=0:
        return failed(o,7,30)
    put(o,LOOKOBJ,obj)
    put(o,LOOKDEST,dest)
    put(o,LOOKNEXT,next)
    put(o,FIELD,id)
    request(o,V6,2)
    put(o,RQ+104,4)
    n=literal(o,RQ+128,id)
    put(o,RQ+96,n)
    return value(o,w,30,128+n)

def field_result(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==30:
        if take(o,KEY)==False:
            return dependency(o,w)
        request(o,V6,9)
        within(o,RQ+24,get(o,LOOKOBJ),24)
        within(o,RQ+48,KEY,24)
        return value(o,w,31,128)
    if phase==31:
        if take(o,get(o,LOOKDEST))==False:
            return dependency(o,w)
        request(o,V5,78)
        within(o,RQ+24,KEY,24)
        return value(o,w,32,128)
    if phase==32:
        if released(o,KEY)==False:
            return isolate(o,w,choose(release_known(o),1,2),32)
        if get(o,MAP_PENDING)!=0:
            return isolate(o,w,1,32)
        return again(o,get(o,LOOKNEXT))
    return failed(o,7,phase)

def exact_text(o:mutbuf,w:mutbuf,at:u64,id:u64,next:u64) -> u32:
    put(o,TEXTAT,at)
    put(o,TEXTID,id)
    put(o,TEXTNEXT,next)
    request(o,V6,7)
    within(o,RQ+24,at,24)
    return value(o,w,80,128)

def text_result(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==80:
        n=literal(o,RAWBUF,get(o,TEXTID))
        if okay(o)==False or get(o,RP+16)!=4 or get(o,RP+72)!=n:
            return failed(o,7,80)
        put(o,CHUNK,n)
        request(o,V6,19)
        within(o,RQ+24,get(o,TEXTAT),24)
        put(o,RQ+112,n)
        return value(o,w,81,128)
    if phase==81:
        if okay(o)==False or get(o,RP+64)!=get(o,CHUNK):
            return failed(o,7,81)
        i=0
        while i<get(o,CHUNK):
            if byte(o,RP+8192+i)!=byte(o,RAWBUF+i):
                return failed(o,7,82)
            i=i+1
        return again(o,get(o,TEXTNEXT))
    return failed(o,7,phase)

def prefix_read(o:mutbuf,w:mutbuf) -> u32:
    n=get(o,RAWN)-get(o,CURSOR)
    if n>16384:
        n=16384
    if n==0:
        return failed(o,7,70)
    put(o,CHUNK,n)
    request(o,V6,19)
    within(o,RQ+24,MESSAGE,24)
    put(o,RQ+104,get(o,CURSOR))
    put(o,RQ+112,n)
    return value(o,w,71,128)

def code_prefix(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==71:
        n=get(o,CHUNK)
        if okay(o)==False or get(o,RP+64)!=n or get(o,RP+72)!=get(o,RAWN):
            return failed(o,7,71)
        if get(o,CURSOR)==0:
            if byte(o,RP+8192)!=69 or byte(o,RP+8193)!=95 or byte(o,RP+8194)!=72 or byte(o,RP+8195)!=73 or byte(o,RP+8196)!=65 or byte(o,RP+8197)!=95:
                return failed(o,7,72)
        i=0
        previous=get(o,PREVIOUS)
        while i<n:
            ch=byte(o,RP+8192+i)
            if previous==58 and ch==32:
                put(o,CODEN,get(o,CURSOR)+i-1)
                i=n
            else:
                previous=ch
                i=i+1
        put(o,PREVIOUS,previous)
        count=n
        if get(o,CODEN)!=MAX:
            if get(o,CODEN)<6:
                return failed(o,7,73)
            count=0
            if get(o,CODEN)>get(o,CURSOR):
                count=get(o,CODEN)-get(o,CURSOR)
        put(o,COPYN,count)
        return memory(o,72,3,RP+8192,0,get(o,FRAME)+128+get(o,CURSOR),count)
    if phase==72:
        if get(o,CODEN)==MAX:
            put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
            return prefix_read(o,w)
        if get(o,FORMAT)==2:
            request(o,V6,7)
            within(o,RQ+24,CODE,24)
            return value(o,w,74,128)
        request(o,V6,2)
        put(o,RQ+104,4)
        put(o,RQ+96,get(o,CODEN))
        return memory(o,73,3,RQ,0,get(o,FRAME),128)
    if phase==73:
        return invoke(o,76,get(w,8),48,get(o,FRAME),128+get(o,CODEN),RP,32768,get(w,16),256)
    if phase==74:
        if okay(o)==False or get(o,RP+16)!=4 or get(o,RP+72)!=get(o,CODEN):
            return failed(o,7,74)
        put(o,CURSOR,0)
        return compare_code(o,w)
    if phase==75:
        if okay(o)==False or get(o,RP+64)!=get(o,CHUNK) or get(o,RP+72)!=get(o,CODEN):
            return failed(o,7,75)
        return memory(o,77,0,get(o,FRAME)+128+get(o,CURSOR),3,RAWBUF,get(o,CHUNK))
    if phase==76:
        if take(o,CODE)==False:
            return dependency(o,w)
        return again(o,90)
    if phase==77:
        i=0
        while i<get(o,CHUNK):
            if byte(o,RP+8192+i)!=byte(o,RAWBUF+i):
                return failed(o,7,77)
            i=i+1
        put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
        return compare_code(o,w)
    return failed(o,7,phase)

def compare_code(o:mutbuf,w:mutbuf) -> u32:
    if get(o,CURSOR)==get(o,CODEN):
        return again(o,90)
    n=get(o,CODEN)-get(o,CURSOR)
    if n>16384:
        n=16384
    put(o,CHUNK,n)
    request(o,V6,19)
    within(o,RQ+24,CODE,24)
    put(o,RQ+104,get(o,CURSOR))
    put(o,RQ+112,n)
    return value(o,w,75,128)

def constructing(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==90:
        request(o,V11,87)
        put(o,RQ+104,42)
        return value(o,w,91,128)
    if phase==91:
        if take(o,CLASS)==False:
            return dependency(o,w)
        request(o,V6,4)
        return value(o,w,92,128)
    if phase==92:
        if take(o,NAMESPACE)==False:
            return dependency(o,w)
        request(o,V6,2)
        put(o,RQ+104,4)
        n=literal(o,RQ+128,4)
        put(o,RQ+96,n)
        return value(o,w,93,128+n)
    if phase==93:
        if take(o,KEY)==False:
            return dependency(o,w)
        request(o,V6,10)
        within(o,RQ+24,NAMESPACE,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,CODE,24)
        return value(o,w,94,128)
    if phase==94:
        if okay(o)==False:
            return dependency(o,w)
        request(o,V7,3)
        return value(o,w,95,128)
    if phase==95:
        if take(o,LIST)==False:
            return dependency(o,w)
        request(o,V7,16)
        within(o,RQ+24,LIST,24)
        within(o,RQ+48,MESSAGE,24)
        return value(o,w,96,128)
    if phase==96:
        if okay(o)==False:
            return dependency(o,w)
        request(o,V11,40)
        within(o,RQ+24,LIST,24)
        return value(o,w,97,128)
    if phase==97:
        if take(o,TUPLE)==False:
            return dependency(o,w)
        request(o,V11,75)
        within(o,RQ+24,CLASS,24)
        within(o,RQ+48,TUPLE,24)
        within(o,RQ+72,NAMESPACE,24)
        return value(o,w,98,128)
    if phase==98:
        if take(o,PRIMARY)==False:
            return dependency(o,w)
        put(o,STATUS,0)
        return again(o,100)
    return failed(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        i=get(o,CLEAN)
        if i==18:
            if get(o,MAP_PENDING)!=0:
                request(o,V5,93)
                return value(o,w,103,128)
            if get(o,FRAME)!=0:
                return system(o,104,11,0,get(o,FRAME),get(o,FRAMEN),0,0,0,0)
            put(w,152,0)
            put(w,160,0)
            put(w,184,0)
            return finish(o,w,get(o,STATUS))
        at=REFS+i*24
        if at==PRIMARY or get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,100)
        if at==PAYCAP:
            request(o,PQ,3)
            within(o,RQ+24,at,24)
            return payload(o,w,102)
        request(o,V5,78)
        within(o,RQ+24,at,24)
        return value(o,w,101,128)
    if phase==101:
        if released(o,REFS+get(o,CLEAN)*24)==False:
            return isolate(o,w,choose(release_known(o),1,2),101)
        if get(o,MAP_PENDING)!=0:
            return isolate(o,w,1,101)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,100)
    if phase==102:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PR:
            return isolate(o,w,2,102)
        if get(o,RP+8)!=0:
            return isolate(o,w,1,get(o,RP+8))
        zero(o,PAYCAP,24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,100)
    if phase==103:
        if release_known(o)==False or get(o,RP+96)!=0:
            return isolate(o,w,2,103)
        put(o,MAP_PENDING,get(o,RP+104))
        if get(o,RP+112)!=0:
            put(o,PENDING,1)
        if get(o,MAP_PENDING)!=0:
            return isolate(o,w,1,103)
        return again(o,100)
    if phase==104:
        if get(o,FEEDBACK)!=0:
            return isolate(o,w,1,get(o,FEEDBACK))
        put(o,FRAME,0)
        put(o,FRAMEN,0)
        return again(o,100)
    return isolate(o,w,2,phase)

def release_known(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR2 and get(o,RP+88)==1 and get(o,RP+96)<=1 and get(o,RP+80)<=1 and get(o,RP+104)<=1 and get(o,RP+112)<=1 and get(o,RP+120)==1
def released(o:mutbuf,at:u64) -> bool:
    if release_known(o)==False:
        return False
    if get(o,RP+96)==1:
        zero(o,at,24)
    if get(o,RP+104)!=0:
        put(o,MAP_PENDING,1)
    if get(o,RP+112)!=0:
        put(o,PENDING,1)
    return get(o,RP+96)==1
def take(o:mutbuf,at:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
        return False
    if get(o,RP+24)!=0:
        within(o,at,RP+24,24)
    return get(o,RP+8)==0 and get(o,at)!=0
def okay(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==0
def dependency(o:mutbuf,w:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
        return isolate(o,w,2,get(o,FEEDBACK))
    return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
def failed(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    return again(o,100)
def isolate(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,128,256,896)
    put(w,152,1)
    put(w,160,kind)
    put(w,184,ERTAG)
    return finish(o,w,9)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,status)
    put(o,16,choose(get(o,PRIMARY)!=0,2,0))
    put(o,80,choose(get(w,152)!=0,1,get(o,PENDING)))
    put(o,88,choose(get(o,QUAR)==2,0,1))
    put(o,96,choose(get(o,PRIMARY)!=0,1,0))
    put(o,104,get(o,QUAR))
    put(o,112,get(o,DETAIL))
    if get(o,PRIMARY)!=0:
        within(o,24,PRIMARY,24)
        zero(o,PRIMARY,24)
        if get(w,152)!=0:
            zero(w,256+PRIMARY-128,24)
    return 0
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,32768,get(w,16),256)
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,40),51,RQ,128,RP,512,get(w,48),256)
'''
def source_program():
    names={'request','invoke','system','again','copy_source','within','zero','get','put','to_work','from_work','choose','memory'}
    text=SOURCE+'\n'+'\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    text+='\ndef literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
    values={1:b'status',2:b'ok',3:b'diagnostics',4:b'code',5:b'phase',6:b'message',7:b'class',8:b'error',9:b'E_DRIVER',10:b'driver',11:b'HIAProgramRejected'}
    for id,value in values.items():
        text+='    if id=='+str(id)+':\n'
        for at in range(0,len(value),8):
            text+='        put(o,at+'+str(at)+','+str(int.from_bytes(value[at:at+8].ljust(8,b'\0'),'little'))+')\n'
        text+='        return '+str(len(value))+'\n'
    text+='    return 0\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    tree=document(source_program(),'generation_runtime_verify_exception')
    path=ROOT/'examples/hia_bootstrap/generation_runtime_verify_exception.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
