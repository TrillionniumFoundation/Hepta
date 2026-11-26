"""Live BG bridge dictionary construction with actual Path coercion/resolution."""
from pathlib import Path
import ast
import json
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT = Path(__file__).resolve().parents[1]
C = dict(MAX=(1 << 64) - 1, BAD=4294967293,
         PHASE=256, ERROR=264, DETAIL=272, QUAR=280,
         INPUTFD=288, INPUTMAP=296, INPUTN=304, PATHFD=312, PATHN=320, RAWMAP=328,
         OUTFD=336, OUTMAP=344, OUTN=352, SCALARN=360, OFFSET=368, BODY_N=376,
         ENC_N=384, STRSLOT=392, V_PENDING=400, PATH_PENDING=408, AFTER_CLEAN=416,
         CLEAN=424, WRFD=432, WRAT=440, WRN=448, WRDONE=456, WRNEXT=464,
         RAWPOS=480, RAWCHUNK=488, RAWUSED=496,
         ROOTCAP=512, ITER=536, KEY=560, ITEM=584, COERCED=608,
         ENV=632, BASE=656, NAME=680, RESOLVED=704, ERR_CAP=728, EXC_CAP=752,
         WRMODE=1000, COMPLETE=1008, ERRCODE=1016, ERRNO=1024, ERRCP=1032,
         ERRSTART=1040, ERREND=1048, FEEDBACK=3840,
         RQ=8192, RP=16384, SY=49152, TMP=49408, BUF=65536, ENC=131072,
         ERQ=229376, ERO=230400, PATH_WORK=16384, ERROR_WORK=225280,
         CONVERTER_WORK=4096, CODEC_WORK=2048)
C.update({key: int.from_bytes(value.encode(), 'little') for key, value in {
    'MAGIC': 'HIABBPQ1', 'CONTEXT': 'HIABBPC1', 'REPLY': 'HIABBPR1',
    'VQ': 'HIABVQ01', 'VR': 'HIABVR01', 'VQ2': 'HIABVQ02', 'VR2': 'HIABVR02',
    'PQ': 'HIANPV01', 'PC': 'HIANPVC1', 'PR': 'HIANPVR1', 'NATIVE_INFO': 'HIAVNO01',
    'RESOLVE_INPUT': 'HIAPTH01', 'RESOLVE_REPLY': 'HIAPTR01',
    'CQ': 'HIAPCDQ1', 'CR': 'HIAPCDR1', 'EQ': 'HIANER01', 'UE': 'HIAPUE01',
}.items()})
SOURCE = r'''
def bridge_paths(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<262144 or length(w)<262144:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        return enter(s,o,w)
    if phase<20:
        return iterate(s,o,w,phase)
    if phase<40:
        return coerce(o,w,phase)
    if phase<60:
        return quote_path(o,w,phase)
    if phase<70:
        return resolve_path(o,w,phase)
    if phase<110:
        return decode_path(o,w,phase)
    if phase<120:
        return insert_path(o,w,phase)
    if phase>=200 and phase<210:
        return render_error(o,w,phase)
    if phase>=300 and phase<310:
        return write_step(o,phase)
    if phase>=400 and phase<600:
        return cleanup(o,w,phase)
    return quarantine(o,w,2,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return BAD
    if word_load(s,8)==1:
        if word_load(s,16)!=0 or word_load(s,24)!=0 or word_load(s,32)!=0:
            return BAD
    elif word_load(s,16)==0:
        return BAD
    i=40
    while i<128:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,16)>MAX-get(w,24) or get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,72)==0:
        return BAD
    if get(w,56)<2 or get(w,56)>2147483647 or get(w,64)>2:
        return BAD
    i=80
    while i<128:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,128,3968)
    return system(o,1,39,0,0,0,0,0,0,0)

def enter(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,FEEDBACK)!=get(w,56):
        return present(o,6)
    state=get(w,64)
    if word_load(s,8)==1:
        if state==0:
            return present(o,0)
        if state==2:
            from_work(w,o,128,256,1792)
            put(o,QUAR,2)
            return present(o,9)
        from_work(w,o,128,256,1792)
        put(w,64,0)
        put(o,QUAR,0)
        if get(o,PATH_PENDING)!=0:
            request(o,PQ,2)
            return converter(o,w,23)
        put(o,CLEAN,0)
        return again(o,400)
    if state!=0:
        put(o,QUAR,state)
        return present(o,6)
    put(o,INPUTFD,MAX)
    put(o,PATHFD,MAX)
    put(o,OUTFD,MAX)
    request(o,VQ2,27)
    copy_source(s,o,16,RQ+24,24)
    put(o,RQ+104,1)
    return value(o,w,2)

def iterate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+16)!=9 or get(o,RP+24)==0:
            return quarantine(o,w,2,2)
        within(o,ITER,RP+24,24)
        request(o,VQ,4)
        return value(o,w,3)
    if phase==3:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+16)!=6 or get(o,RP+24)==0:
            return quarantine(o,w,2,3)
        within(o,ROOTCAP,RP+24,24)
        return again(o,10)
    if phase==10:
        request(o,VQ2,28)
        within(o,RQ+24,ITER,24)
        return value(o,w,11)
    if phase==11:
        if value_ok(o)==False:
            status=get(o,RP+8)
            if get(o,FEEDBACK)==0 and get(o,RP)==VR and (status==14 or status==15):
                request(o,VQ,2)
                put(o,RQ+104,7)
                n=iteration_error(o,RQ+128,status)
                put(o,RQ+96,n)
                return value_n(o,w,201,128+n)
            return dependency(o,w)
        count=get(o,RP+64)
        if count==0:
            put(o,COMPLETE,1)
            return begin_cleanup(o,900)
        if count!=1 or get(o,RP+72)!=8256 or get(o,RP+8208)==0 or get(o,RP+8232)==0:
            return quarantine(o,w,2,11)
        within(o,KEY,RP+8208,24)
        within(o,ITEM,RP+8232,24)
        return again(o,20)
    return fail(o,7,phase)

def coerce(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        zero(w,CONVERTER_WORK,4096)
        put(w,CONVERTER_WORK,PC)
        put(w,CONVERTER_WORK+8,get(w,8))
        put(w,CONVERTER_WORK+16,get(w,16))
        put(w,CONVERTER_WORK+24,get(w,24))
        put(w,CONVERTER_WORK+32,get(w,56))
        request(o,PQ,1)
        within(o,RQ+16,ITEM,24)
        return converter(o,w,21)
    if phase==21 or phase==23:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PR or get(o,RP+8)>4 or get(o,RP+96)>1 or get(o,RP+104)>1 or get(o,RP+120)!=0:
            return quarantine(o,w,2,phase)
        if get(o,RP+96)!=0 or get(o,RP+104)!=0:
            if cap_zero(o,RP+16)==False or cap_zero(o,RP+40)==False or cap_zero(o,RP+64)==False:
                return quarantine(o,w,2,phase)
            put(o,PATH_PENDING,1)
            return quarantine(o,w,choose(get(o,RP+104)!=0,2,1),get(o,RP+112))
        put(o,PATH_PENDING,0)
        status=get(o,RP+8)
        if status==0:
            if get(o,RP+16)==0 or cap_zero(o,RP+40)==False or cap_zero(o,RP+64)==False:
                return quarantine(o,w,2,phase)
            within(o,COERCED,RP+16,24)
            request(o,VQ,7)
            within(o,RQ+24,COERCED,24)
            return value(o,w,30)
        if status==1:
            if get(o,RP+64)==0 or cap_zero(o,RP+16)==False or cap_zero(o,RP+40)==False:
                return quarantine(o,w,2,phase)
            within(o,ERR_CAP,RP+64,24)
            return fail(o,1,get(o,RP+88))
        if status==2:
            if get(o,RP+40)==0 or cap_zero(o,RP+16)==False or cap_zero(o,RP+64)==False:
                return quarantine(o,w,2,phase)
            within(o,EXC_CAP,RP+40,24)
            return fail(o,2,get(o,RP+88))
        if cap_zero(o,RP+16)==False or cap_zero(o,RP+40)==False or cap_zero(o,RP+64)==False:
            return quarantine(o,w,2,phase)
        return fail(o,choose(status==3,5,7),get(o,RP+112))
    if phase==30:
        if value_ok(o)==False:
            return dependency(o,w)
        kind=get(o,RP+16)
        if kind==4:
            put(o,SCALARN,get(o,RP+72))
            put(o,STRSLOT,COERCED)
            return again(o,40)
        if kind!=8:
            return fail(o,7,30)
        request(o,VQ2,26)
        within(o,RQ+24,COERCED,24)
        return value(o,w,31)
    if phase==31:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+8192)!=NATIVE_INFO or get(o,RP+8224)==0 or get(o,RP+8248)==0 or get(o,RP+8272)==0:
            return quarantine(o,w,2,31)
        within(o,ENV,RP+8224,24)
        within(o,BASE,RP+8248,24)
        within(o,NAME,RP+8272,24)
        if get(o,RP+8200)!=4:
            return fail(o,7,31)
        request(o,VQ,7)
        within(o,RQ+24,BASE,24)
        return value(o,w,32)
    if phase==32:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+16)!=4:
            return fail(o,7,32)
        put(o,SCALARN,get(o,RP+72))
        put(o,STRSLOT,BASE)
        return again(o,40)
    return fail(o,7,phase)

def quote_path(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        descriptor_name(o)
        return system(o,41,319,3,TMP,3,0,0,0,0)
    if phase==41:
        result=get(o,FEEDBACK)
        if failed(result):
            return io_failure(o,result)
        if result>2147483647:
            return quarantine(o,w,2,41)
        put(o,INPUTFD,result)
        zero(o,TMP,40)
        put(o,TMP,RESOLVE_INPUT)
        put(o,TMP+8,1)
        store(o,TMP+32,34)
        put(o,BODY_N,1)
        put(o,OFFSET,0)
        return writing(o,result,TMP,33,42,0)
    if phase==42:
        at=get(o,OFFSET)
        n=get(o,SCALARN)
        if at==n:
            store(o,TMP,34)
            put(o,BODY_N,get(o,BODY_N)+1)
            return writing(o,get(o,INPUTFD),TMP,1,45,0)
        if at>n:
            return fail(o,7,42)
        count=choose(n-at>8192,8192,n-at)
        put(o,RAWCHUNK,count)
        request(o,VQ,19)
        within(o,RQ+24,get(o,STRSLOT),24)
        put(o,RQ+104,at)
        put(o,RQ+112,count)
        return value(o,w,43)
    if phase==43:
        if value_ok(o)==False:
            return dependency(o,w)
        count=get(o,RAWCHUNK)
        if get(o,RP+64)!=count or get(o,RP+72)!=get(o,SCALARN):
            return fail(o,7,43)
        zero(o,RP+8064,128)
        put(o,RP+8064,CQ)
        put(o,RP+8080,count)
        put(o,RP+8088,count)
        return invoke(o,44,get(w,72),307,RP+8064,128+count,ENC,65536,CODEC_WORK,32)
    if phase==44:
        if codec_ok(o)==False or get(o,ENC+8)!=get(o,RAWCHUNK):
            return fail(o,7,44)
        count=get(o,ENC+16)
        if get(o,BODY_N)>MAX-33 or count>MAX-get(o,BODY_N)-33:
            return fail(o,5,44)
        put(o,BODY_N,get(o,BODY_N)+count)
        put(o,OFFSET,get(o,OFFSET)+get(o,RAWCHUNK))
        return writing(o,get(o,INPUTFD),ENC+128,count,42,0)
    if phase==45:
        n=get(o,BODY_N)
        if n>9223372036854775775:
            return fail(o,5,45)
        put(o,INPUTN,n+32)
        zero(o,TMP,32)
        put(o,TMP,RESOLVE_INPUT)
        put(o,TMP+8,1)
        put(o,TMP+16,n)
        return writing(o,get(o,INPUTFD),TMP,32,46,1)
    if phase==46:
        return system(o,47,72,0,get(o,INPUTFD),1033,15,0,0,0)
    if phase==47:
        if get(o,FEEDBACK)!=0:
            return io_failure(o,get(o,FEEDBACK))
        return system(o,48,72,0,get(o,INPUTFD),1034,0,0,0,0)
    if phase==48:
        if get(o,FEEDBACK)!=15:
            return fail(o,7,48)
        return system(o,49,9,0,0,get(o,INPUTN),1,1,get(o,INPUTFD),0)
    if phase==49:
        result=get(o,FEEDBACK)
        if failed(result) or result==0:
            return io_failure(o,result)
        put(o,INPUTMAP,result)
        return again(o,60)
    return fail(o,7,phase)
'''
SOURCE += r'''
def resolve_path(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==60:
        put(w,PATH_WORK,0)
        put(w,PATH_WORK+544,0)
        return invoke(o,61,get(w,40),304,get(o,INPUTMAP),get(o,INPUTN),SY,128,PATH_WORK,200704)
    if phase==61:
        if get(o,FEEDBACK)!=0 or get(o,SY)!=RESOLVE_REPLY:
            return quarantine(o,w,2,61)
        status=get(o,SY+8)
        if status==0:
            fd=get(o,SY+32)
            n=get(o,SY+40)
            if fd>2147483647 or n==0 or get(o,SY+48)!=15:
                return quarantine(o,w,2,61)
            put(o,PATHFD,fd)
            put(o,PATHN,n)
            return system(o,62,72,0,fd,1034,0,0,0,0)
        if status<2 or status>6 or get(o,SY+32)!=MAX:
            return quarantine(o,w,2,61)
        put(o,ERRNO,get(o,SY+16))
        if status==2:
            put(o,ERRCODE,13)
        elif status==3:
            if get(o,SY+80)!=1:
                return quarantine(o,w,2,61)
            put(o,ERRCODE,14)
            put(o,ERRCP,get(o,SY+56))
            put(o,ERRSTART,get(o,SY+64))
            put(o,ERREND,get(o,SY+72))
        elif status==4:
            put(o,ERRCODE,15)
        elif status==5:
            put(o,ERRCODE,16)
        else:
            put(o,ERRCODE,99)
        return again(o,200)
    if phase==62:
        if get(o,FEEDBACK)!=15:
            return fail(o,7,62)
        if get(o,PATHN)>9223372036854775807:
            return fail(o,5,62)
        return system(o,63,9,0,0,get(o,PATHN),1,1,get(o,PATHFD),0)
    if phase==63:
        result=get(o,FEEDBACK)
        if failed(result) or result==0:
            return io_failure(o,result)
        put(o,RAWMAP,result)
        return again(o,70)
    return fail(o,7,phase)

def decode_path(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==70:
        descriptor_name(o)
        return system(o,71,319,3,TMP,3,0,0,0,0)
    if phase==71:
        result=get(o,FEEDBACK)
        if failed(result):
            return io_failure(o,result)
        if result>2147483647:
            return quarantine(o,w,2,71)
        put(o,OUTFD,result)
        zero(o,TMP,128)
        put(o,TMP,VQ)
        put(o,TMP+8,2)
        put(o,TMP+104,4)
        put(o,RAWPOS,0)
        put(o,BODY_N,0)
        return writing(o,result,TMP,128,72,0)
    if phase==72:
        at=get(o,RAWPOS)
        n=get(o,PATHN)
        if at==n:
            return again(o,76)
        if at>n:
            return fail(o,7,72)
        count=choose(n-at>8195,8195,n-at)
        put(o,RAWCHUNK,count)
        zero(o,BUF,128)
        put(o,BUF,CQ)
        put(o,BUF+8,1)
        put(o,BUF+16,count)
        put(o,BUF+24,choose(count>8192,8192,count))
        put(o,BUF+32,choose(count==n-at,1,0))
        return memory(o,73,0,get(o,RAWMAP)+at,3,BUF+128,count)
    if phase==73:
        return invoke(o,74,get(w,72),307,BUF,128+get(o,RAWCHUNK),ENC,65536,CODEC_WORK,32)
    if phase==74:
        if codec_ok(o)==False:
            return fail(o,7,74)
        used=get(o,ENC+8)
        n=get(o,ENC+16)
        if used==0 or used>get(o,RAWCHUNK) or used>get(o,PATHN)-get(o,RAWPOS):
            return fail(o,7,74)
        if get(o,BODY_N)>MAX-128 or n>MAX-get(o,BODY_N)-128:
            return fail(o,5,74)
        put(o,RAWPOS,get(o,RAWPOS)+used)
        put(o,BODY_N,get(o,BODY_N)+n)
        return writing(o,get(o,OUTFD),ENC+128,n,72,0)
    if phase==76:
        n=get(o,BODY_N)
        if n>9223372036854775679:
            return fail(o,5,76)
        put(o,OUTN,128+n)
        zero(o,TMP,128)
        put(o,TMP,VQ)
        put(o,TMP+8,2)
        put(o,TMP+96,n)
        put(o,TMP+104,4)
        return writing(o,get(o,OUTFD),TMP,128,77,1)
    if phase==77:
        return system(o,78,72,0,get(o,OUTFD),1033,15,0,0,0)
    if phase==78:
        if get(o,FEEDBACK)!=0:
            return io_failure(o,get(o,FEEDBACK))
        return system(o,79,72,0,get(o,OUTFD),1034,0,0,0,0)
    if phase==79:
        if get(o,FEEDBACK)!=15:
            return fail(o,7,79)
        return system(o,80,9,0,0,get(o,OUTN),1,1,get(o,OUTFD),0)
    if phase==80:
        result=get(o,FEEDBACK)
        if failed(result) or result==0:
            return io_failure(o,result)
        put(o,OUTMAP,result)
        return invoke(o,81,get(w,8),48,result,get(o,OUTN),RP,32768,get(w,16),get(w,24))
    if phase==81:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+16)!=4 or get(o,RP+24)==0:
            return quarantine(o,w,2,81)
        within(o,RESOLVED,RP+24,24)
        return again(o,110)
    return fail(o,7,phase)

def insert_path(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==110:
        request(o,VQ,10)
        within(o,RQ+24,ROOTCAP,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,RESOLVED,24)
        return value(o,w,111)
    if phase==111:
        if value_ok(o)==False:
            return dependency(o,w)
        return begin_cleanup(o,10)
    return fail(o,7,phase)

def render_error(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        zero(o,ERQ,256)
        put(o,ERQ,EQ)
        put(o,ERQ+8,get(o,ERRCODE))
        put(o,ERQ+16,get(o,ERRNO))
        n=128
        if get(o,ERRCODE)==14:
            put(o,ERQ+40,128)
            put(o,ERQ+128,UE)
            put(o,ERQ+136,get(o,ERRCP))
            put(o,ERQ+144,get(o,ERRSTART))
            put(o,ERQ+152,get(o,ERREND))
            n=256
        return invoke(o,202,get(w,48),307,ERQ,n,ERO,4096,ERROR_WORK,32768)
    if phase==202:
        n=get(w,ERROR_WORK)
        if get(o,FEEDBACK)!=0 or n==0 or n>4096:
            return fail(o,7,202)
        request(o,VQ,2)
        put(o,RQ+104,7)
        put(o,RQ+96,n)
        within(o,RQ+128,ERO,n)
        return value_n(o,w,201,128+n)
    if phase==201:
        if value_ok(o)==False:
            return dependency(o,w)
        if get(o,RP+16)!=7 or get(o,RP+24)==0:
            return quarantine(o,w,2,201)
        within(o,ERR_CAP,RP+24,24)
        return fail(o,1,get(o,ERRCODE))
    return fail(o,7,phase)

def writing(o:mutbuf,fd:u64,at:u64,n:u64,next:u64,mode:u64) -> u32:
    put(o,WRFD,fd)
    put(o,WRAT,at)
    put(o,WRN,n)
    put(o,WRDONE,0)
    put(o,WRNEXT,next)
    put(o,WRMODE,mode)
    return again(o,300)

def write_step(o:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,WRDONE)==get(o,WRN):
            return again(o,get(o,WRNEXT))
        nr=choose(get(o,WRMODE)==0,1,18)
        return system(o,301,nr,12,get(o,WRFD),get(o,WRAT)+get(o,WRDONE),get(o,WRN)-get(o,WRDONE),get(o,WRDONE),0,0)
    if phase==301:
        result=get(o,FEEDBACK)
        if result==MAX-3:
            return again(o,300)
        if failed(result):
            return io_failure(o,result)
        if result==0 or result>get(o,WRN)-get(o,WRDONE):
            return fail(o,7,301)
        put(o,WRDONE,get(o,WRDONE)+result)
        return again(o,300)
    return fail(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        i=get(o,CLEAN)
        if i==3:
            put(o,CLEAN,0)
            return again(o,402)
        at=map_slot(i)
        if get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,400)
        return system(o,401,11,0,get(o,at),get(o,map_length_slot(i)),0,0,0,0)
    if phase==401:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,1,get(o,FEEDBACK))
        put(o,map_slot(get(o,CLEAN)),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,400)
    if phase==402:
        i=get(o,CLEAN)
        if i==3:
            put(o,CLEAN,0)
            return again(o,500)
        fd=get(o,fd_slot(i))
        if fd==MAX:
            put(o,CLEAN,i+1)
            return again(o,402)
        return system(o,403,3,0,fd,0,0,0,0,0)
    if phase==403:
        put(o,fd_slot(get(o,CLEAN)),MAX)
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,2,get(o,FEEDBACK))
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,402)
    if phase==500:
        i=get(o,CLEAN)
        if i==11:
            if get(o,V_PENDING)!=0:
                request(o,VQ2,31)
                return value(o,w,502)
            return cleanup_finished(o,w)
        at=ROOTCAP+i*24
        keep=False
        status=get(o,ERROR)
        if at==ROOTCAP and status==0:
            keep=True
        if at==ITER and status==0 and get(o,AFTER_CLEAN)==10:
            keep=True
        if at==ERR_CAP and status==1:
            keep=True
        if at==EXC_CAP and status==2:
            keep=True
        if get(o,at)==0 or keep:
            put(o,CLEAN,i+1)
            return again(o,500)
        request(o,VQ2,29)
        within(o,RQ+24,at,24)
        return value(o,w,501)
    if phase==501:
        if cleanup_facts(o,29)==False or get(o,RP+88)==0:
            return quarantine(o,w,2,501)
        consumed=get(o,RP+96)
        pending=get(o,RP+80)
        status=get(o,RP+8)
        if consumed!=0:
            zero(o,ROOTCAP+get(o,CLEAN)*24,24)
        if pending!=0:
            put(o,V_PENDING,1)
        if status!=0:
            kind=1
            if (consumed!=0 and pending==0) or (consumed==0 and pending!=0):
                kind=2
            return quarantine(o,w,kind,status)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,500)
    if phase==502:
        if cleanup_facts(o,31)==False:
            return quarantine(o,w,2,502)
        if get(o,RP+8)!=0:
            return quarantine(o,w,1,get(o,RP+8))
        put(o,V_PENDING,0)
        return cleanup_finished(o,w)
    return quarantine(o,w,2,phase)

def cleanup_finished(o:mutbuf,w:mutbuf) -> u32:
    if get(o,ERROR)==0 and get(o,AFTER_CLEAN)==10:
        return again(o,10)
    put(w,64,0)
    zero(w,128,1792)
    return present(o,get(o,ERROR))

def map_slot(i:u64) -> u64:
    return choose(i==0,INPUTMAP,choose(i==1,RAWMAP,OUTMAP))

def map_length_slot(i:u64) -> u64:
    return choose(i==0,INPUTN,choose(i==1,PATHN,OUTN))

def fd_slot(i:u64) -> u64:
    return choose(i==0,INPUTFD,choose(i==1,PATHFD,OUTFD))

def cleanup_facts(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR2:
        return False
    known=get(o,RP+88)
    consumed=get(o,RP+96)
    pending=get(o,RP+80)
    status=get(o,RP+8)
    if known>1 or consumed>1 or pending>1:
        return False
    if status!=0 and status!=6 and status!=11 and (op==31 or status!=1):
        return False
    if op==31 and (known!=1 or consumed!=0):
        return False
    if known==0 and (status!=11 or consumed!=0 or pending!=0):
        return False
    if consumed!=0 and status!=0 and status!=11:
        return False
    if status==0 and (known!=1 or consumed!=choose(op==31,0,1) or pending!=0):
        return False
    if status==1 and (known!=1 or consumed!=0 or pending!=0):
        return False
    if status==6 and (known!=1 or consumed!=0):
        return False
    i=16
    while i<80:
        if get(o,RP+i)!=0:
            return False
        i=i+8
    i=104
    while i<128:
        if get(o,RP+i)!=0:
            return False
        i=i+8
    return True

def codec_ok(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,ENC)!=CR or get(o,ENC+16)>65408 or get(o,ENC+24)!=128+get(o,ENC+16):
        return False
    i=32
    while i<128:
        if get(o,ENC+i)!=0:
            return False
        i=i+8
    return True

def cap_zero(o:mutbuf,at:u64) -> bool:
    return get(o,at)==0 and get(o,at+8)==0 and get(o,at+16)==0

def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==0

def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return value_n(o,w,next,128)

def value_n(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,32768,get(w,16),get(w,24))

def converter(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,32),307,RQ,128,RP,32768,CONVERTER_WORK,4096)

def dependency(o:mutbuf,w:mutbuf) -> u32:
    status=get(o,RP+8)
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR or status==0 or status>15 or cap_zero(o,RP+24)==False:
        return quarantine(o,w,2,status)
    return fail(o,choose(status==5,5,7),status)

def failed(value:u64) -> bool:
    return value>=18446744073709547521

def io_failure(o:mutbuf,result:u64) -> u32:
    return fail(o,choose(result==MAX-11 or result==0,5,8),result)

def begin_cleanup(o:mutbuf,next:u64) -> u32:
    put(o,AFTER_CLEAN,next)
    put(o,CLEAN,0)
    return again(o,400)

def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return begin_cleanup(o,900)

def quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,256,128,1792)
    to_work(o,w,SY,8192,128)
    to_work(o,w,RP,8320,128)
    to_work(o,w,RP+8192,8448,128)
    put(w,64,kind)
    return present(o,9)

def present(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0 and get(o,COMPLETE)!=0:
        within(o,16,ROOTCAP,24)
        zero(o,ROOTCAP,24)
        put(o,104,1)
    elif status==1:
        within(o,40,ERR_CAP,24)
        zero(o,ERR_CAP,24)
    elif status==2:
        within(o,64,EXC_CAP,24)
        zero(o,EXC_CAP,24)
    put(o,88,get(o,QUAR))
    put(o,96,get(o,DETAIL))
    return 0

def descriptor_name(o:mutbuf) -> u64:
    put(o,TMP,8099005324620622184)
    put(o,TMP+8,26740)
    return 0

def choose(condition:bool,yes:u64,no:u64) -> u64:
    if condition:
        return yes
    return no
'''

def source_program():
    names = {'request', 'invoke', 'system', 'again', 'memory', 'copy_source',
             'within', 'zero', 'get', 'put', 'to_work', 'from_work'}
    helpers = '\n'.join(ast.unparse(node) for node in ast.parse(HELPERS).body
                        if isinstance(node, ast.FunctionDef) and node.name in names)
    source = SOURCE + '\n' + helpers
    source += '\ndef iteration_error(o:mutbuf,at:u64,status:u64) -> u64:\n'
    for status, message in ((14, 'dictionary changed size during iteration'),
                            (15, 'dictionary keys changed during iteration')):
        raw = json.dumps({'type': 'RuntimeError', 'message': message},
                         sort_keys=True, separators=(',', ':')).encode()
        source += '    if status==' + str(status) + ':\n'
        for at in range(0, len(raw), 8):
            number = int.from_bytes(raw[at:at + 8].ljust(8, b'\0'), 'little')
            source += f'        put(o,at+{at},{number})\n'
        source += '        return ' + str(len(raw)) + '\n'
    source += '    return 0\n'
    for key, value in sorted(C.items(), key=lambda item: -len(item[0])):
        source = re.sub(r'\b' + key + r'\b', str(value), source)
    return source

def program():
    return document(source_program(), 'background_optimizer_bridge_paths')

if __name__ == '__main__':
    tree = program()
    path = ROOT / 'examples/hia_bootstrap/background_optimizer_bridge_paths.hepta'
    path.write_text(render_assembly(tree))
    print(path.name, path.stat().st_size, len(tree['functions']),
          sum(len(f['blocks']) for f in tree['functions']),
          sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']), flush=True)
