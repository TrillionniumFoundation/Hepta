"""Captured original verify_program over actual native values and immutable payloads."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
from tools.generate_hia_background_optimizer_value_structure import ERRORS as STRUCTURE_ERRORS
from tools.hia_background_retirement_source import selected as retirement_source
ROOT=Path(__file__).resolve().parents[1]
C={"PHASE":128,"ERROR":136,"DETAIL":144,"PID":152,"CAP":160,"CANON":184,"DET":208,"FROZCAP":232,"RESULTCAP":256,"RAWN":280,"RAWCHARS":288,"KIND":296,"TSRC":304,"TSCN":312,"TOUT":320,"TOUTN":328,"PFRAME":336,"PFRAMEN":344,"PWORK":352,"PWORKN":360,"PREF":384,"PREFN":392,"OUTMAP":400,"OUTMAPN":408,"FDIN":416,"STDOUT":424,"STDERR":432,"ROLE":440,"CURSOR":448,"CHUNK":456,"CP":464,"NEED":472,"CPCHUNK":480,"CLEAN":536,"QUARANTINED":544,"OP":552,"PROFILE":560,"MODE":568,"COMPARE":576,"RESULTN":600,"CLEAN_AT":624,"AFTER_CLOSE":632,"SRC_PTR":648,"FREEZE_ACTIVE":664,"TYPED_PENDING":672,"RESUME_CLEAN":688,"STRUCTCAP":704,"ORIGINAL_N":728,"CORE_N":736,"CORE_PROFILE":744,"COMPARE_PART":752,"CLEAN_OWNER":760,"FEEDBACK":1024,"TMP":1536,"RQ":2048,"RP":4096,"HEAD":8192,"CHECKBUF":32768,"ERRBUF":65536}
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {"MAGIC":"HIABVFY1","VERIFIED":"HIABVFY2","REPLY":"HIABVFR1","CONTEXT":"HIABVYC1","VREQUEST":"HIABVQ01","VREPLY":"HIABVR01","BREQUEST":"HIABPY01","BREPLY":"HIABPYR1","TREQUEST":"HIABTC01","TRETRY":"HIABTC02","TREPLY":"HIABTV01","TCONTEXT":"HIABVC01","FREQUEST":"HIABFZQ1","FREPLY":"HIABFZR1","FCONTEXT":"HIABFZC1","PREQUEST":"HIAMVPS2","PREPLY":"HIAMVPO1","NORM":"HIAVCF01"}.items()})
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,NEG4=(1<<64)-4,NEG12=(1<<64)-12,BAD=4294967293)
C.update({'MODERN':768,'QUARANTINE_KIND':776,'VALUE_PENDING':784,'DROP_ACTIVE':792,'DROP_KNOWN':800,'NESTED_PENDING':808})
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {'NEW_MAGIC':'HIABVFY3','NEW_VERIFIED':'HIABVFY4','NEW_REPLY':'HIABVFR2','NEW_CONTEXT':'HIABVYC2','NEW_TREQUEST':'HIABTC03','NEW_TRETRY':'HIABTC04','NEW_TREPLY':'HIABTV02','NEW_TCONTEXT':'HIABVC02','NEW_FREQUEST':'HIABFZQ2','NEW_FREPLY':'HIABFZR2','NEW_FCONTEXT':'HIABFZC2','VALUE_DROP_INPUT':'HIABVQ02','VALUE_DROP_REPLY':'HIABVR02'}.items()})
SOURCE=r'''
def verify_program(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<262144 or length(w)<4096:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return entering(s,o,w,phase)
    if phase<40:
        return text_preflight(s,o,w,phase)
    if phase<100:
        return input_copy(s,o,w,phase)
    if phase<200:
        return typed_structure(s,o,w,phase)
    if phase<300:
        return freeze_capture(s,o,w,phase)
    if phase<400:
        return normalizing(s,o,w,phase)
    if phase<500:
        return output_capture(s,o,w,phase)
    if phase<600:
        return comparing(s,o,w,phase)
    if phase<700:
        return errors(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128:
        return BAD
    profile=word_load(s,0)
    modern=profile==NEW_MAGIC or profile==NEW_VERIFIED
    verified=profile==VERIFIED or profile==NEW_VERIFIED
    if (profile!=MAGIC and profile!=VERIFIED and modern==False) or word_load(s,8)>1:
        return BAD
    at=16
    while at<128:
        used=word_load(s,8)==0 and at>=24 and at<=40
        if verified and word_load(s,8)==0 and at>=48 and at<=64:
            used=True
        if used==False and word_load(s,at)!=0:
            return BAD
        at=at+8
    if get(w,0)!=choose(modern,NEW_CONTEXT,CONTEXT) or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)==0 or get(w,64)==0 or get(w,72)<256:
        return BAD
    if (get(w,80)!=0 and get(w,80)<640) or get(w,80)>2147483647:
        return BAD
    if get(w,88)<3 or get(w,88)>2147483647 or get(w,96)==0 or get(w,104)!=10100891:
        return BAD
    if get(w,112)==0 or get(w,120)==0 or get(w,128)==0 or get(w,136)==0 or get(w,152)>1:
        return BAD
    at=160
    while at<256:
        if get(w,at)!=0:
            return BAD
        at=at+8
    zero(o,128,896)
    put(o,OP,word_load(s,8))
    put(o,PROFILE,choose(verified,VERIFIED,MAGIC))
    put(o,MODERN,choose(modern,1,0))
    return system(o,1,39,0,0,0,0,0,0,0)

def entering(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,144)!=0 and get(w,144)!=pid):
            return finish(o,6)
        put(w,144,pid)
        if get(o,OP)==1:
            if get(w,152)==0:
                return finish(o,0)
            from_work(w,o,256,128,896)
            put(w,152,0)
            put(o,QUARANTINED,0)
            put(o,OP,1)
            put(o,CLEAN,0)
            if get(o,MODERN)!=0:
                if get(o,QUARANTINE_KIND)==2:
                    return quarantine(o,w,get(o,DETAIL))
                put(o,QUARANTINE_KIND,0)
            return again(o,700)
        if get(w,152)!=0:
            return finish(o,6)
        put(o,PID,pid)
        return system(o,2,72,0,get(w,88),1030,3,0,0,0)
    if phase==2:
        raw=get(o,FEEDBACK)
        if raw<3 or raw>=NEGATIVE:
            return fail(o,8,raw)
        put(o,FDIN,raw+1)
        request(o,VREQUEST,5)
        copy_source(s,o,24,RQ+24,24)
        return value(o,w,3)
    if phase==3:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CAP,RP+24,24)
        if get(o,PROFILE)==VERIFIED and (word_load(s,48)!=0 or word_load(s,56)!=0 or word_load(s,64)!=0):
            request(o,VREQUEST,5)
            copy_source(s,o,48,RQ+24,24)
            return value(o,w,4)
        return root_type(o,w)
    if phase==4:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,STRUCTCAP,RP+24,24)
        request(o,VREQUEST,7)
        within(o,RQ+24,STRUCTCAP,24)
        return value(o,w,5)
    if phase==5:
        if value_ok(o)==False:
            return value_fail(o)
        if get(o,RP+16)==0:
            return root_type(o,w)
        if get(o,RP+16)!=7:
            return original_error(o,30)
        within(o,CANON,CAP,24)
        within(o,CAP,STRUCTCAP,24)
        zero(o,STRUCTCAP,24)
        put(o,COMPARE,1)
        return root_type(o,w)
    if phase==10:
        if value_ok(o)==False:
            return value_fail(o)
        kind=get(o,RP+16)
        put(o,KIND,kind)
        put(o,RAWN,get(o,RP+72))
        put(o,RAWCHARS,get(o,RP+48))
        if kind==4:
            if get(o,RAWCHARS)>8388608:
                return original_error(o,32)
            put(o,CURSOR,0)
            put(o,CP,0)
            put(o,NEED,0)
            put(o,CPCHUNK,0)
            return again(o,20)
        if kind==7:
            if get(o,RAWN)>8388608:
                return original_error(o,32)
            return again(o,40)
        put(o,MODE,choose(kind==5 or kind==6,1,0))
        put(o,TSCN,10101019)
        return mapping(o,100,get(o,TSCN))
    return fail(o,9,phase)

def root_type(o:mutbuf,w:mutbuf) -> u32:
    request(o,VREQUEST,7)
    within(o,RQ+24,CAP,24)
    return value(o,w,10)

def text_preflight(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(o,CURSOR)==get(o,RAWN):
            if get(o,NEED)!=0:
                return fail(o,7,20)
            if get(o,RAWN)>8388608:
                return original_error(o,32)
            return again(o,40)
        return raw_read(o,w,21,CAP)
    if phase==21:
        if scalar_ok(o)==False:
            return value_fail(o)
        at=0
        while at<get(o,CHUNK):
            ch=byte(o,RP+8192+at)
            if get(o,NEED)==0:
                cp=ch
                need=0
                if ch>=194 and ch<=223:
                    cp=ch&31
                    need=1
                elif ch>=224 and ch<=239:
                    cp=ch&15
                    need=2
                elif ch>=240 and ch<=244:
                    cp=ch&7
                    need=3
                elif ch>=128:
                    return fail(o,7,21)
                put(o,CP,cp)
                put(o,NEED,need)
            else:
                if ch<128 or ch>191:
                    return fail(o,7,22)
                put(o,CP,get(o,CP)*64+(ch&63))
                put(o,NEED,get(o,NEED)-1)
            if get(o,NEED)==0:
                cp=get(o,CP)
                if cp>=55296 and cp<=57343:
                    return original_error(o,31)
                put(o,CPCHUNK,get(o,CPCHUNK)+1)
                if get(o,CPCHUNK)==4096:
                    if get(o,CURSOR)+at+1>8388608:
                        return original_error(o,32)
                    put(o,CPCHUNK,0)
            at=at+1
        put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
        return again(o,20)
    return fail(o,9,phase)

def input_copy(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        if get(o,RAWN)>8388608:
            return fail(o,9,40)
        put(o,PFRAMEN,128+get(o,RAWN))
        return mapping(o,41,get(o,PFRAMEN))
    if phase==41:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,PFRAME,raw)
        put(o,CURSOR,0)
        if get(o,SRC_PTR)!=0:
            return memory(o,45,0,get(o,SRC_PTR),0,raw+128,get(o,RAWN))
        return again(o,42)
    if phase==42:
        if get(o,CURSOR)==get(o,RAWN):
            return again(o,45)
        return raw_read(o,w,43,CAP)
    if phase==43:
        if scalar_ok(o)==False:
            return value_fail(o)
        return memory(o,44,3,RP+8192,0,get(o,PFRAME)+128+get(o,CURSOR),get(o,CHUNK))
    if phase==44:
        put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
        return again(o,42)
    if phase==45:
        put(o,PREFN,4198400)
        return mapping(o,46,get(o,PREFN))
    if phase==46:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,PREF,raw)
        put(o,TMP,get(w,80))
        return memory(o,47,3,TMP,0,raw+4194304+80,8)
    if phase==47:
        return invoke(o,48,get(w,136),0,get(o,PFRAME)+128,get(o,RAWN),get(o,PREF),4194304,get(o,PREF)+4194304,4096)
    if phase==48:
        status=get(o,FEEDBACK)
        if status==5:
            return original_error(o,35)
        if status==2:
            return original_error(o,33)
        if status==1 or status==4:
            return original_error(o,31)
        if status!=0:
            return fail(o,7,status)
        return again(o,300)
    return fail(o,9,phase)

def typed_structure(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,TSRC,raw)
        return memory(o,101,0,get(w,96),0,raw+128,10100891)
    if phase==101:
        typed_request(o,w,0)
        return memory(o,102,3,RQ,0,get(o,TSRC),128)
    if phase==102:
        put(o,TOUTN,100663296)
        return mapping(o,103,get(o,TOUTN))
    if phase==103:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,TOUT,raw)
        zero(w,1152,128)
        put(w,1152,choose(get(o,MODERN)!=0,NEW_TCONTEXT,TCONTEXT))
        put(w,1160,get(w,8))
        put(w,1168,get(w,16))
        put(w,1176,get(w,24))
        put(o,TYPED_PENDING,2)
        return typed_call(o,w)
    if phase==110:
        rc=get(o,FEEDBACK)
        if rc==10:
            return typed_call(o,w)
        if rc==4:
            return memory(o,111,0,get(o,TOUT),3,HEAD,64)
        if rc==0:
            return memory(o,114,0,get(o,TOUT),3,HEAD,128)
        if get(o,RESUME_CLEAN)!=0:
            return quarantine(o,w,rc)
        return fail(o,7,rc)
    if phase==111:
        if get(o,HEAD)!=get(w,8) or get(o,HEAD+8)!=51 or get(o,HEAD+24)!=128:
            return fail(o,9,111)
        if get(o,HEAD+48)!=get(w,16) or get(o,HEAD+56)!=get(w,24):
            return fail(o,9,112)
        at=get(o,HEAD+16)
        dest=get(o,HEAD+32)
        n=get(o,HEAD+40)
        if at>get(o,TOUTN)-128 or dest>get(o,TOUTN) or n>get(o,TOUTN)-dest:
            return fail(o,9,113)
        return invoke(o,112,get(w,8),0,get(o,TOUT)+at,128,get(o,TOUT)+dest,n,get(w,16),get(w,24))
    if phase==112:
        put(o,TMP,get(o,FEEDBACK))
        return memory(o,113,3,TMP,0,get(o,TOUT)+136,8)
    if phase==113:
        return typed_call(o,w)
    if phase==114:
        if get(o,HEAD)!=choose(get(o,MODERN)!=0,NEW_TREPLY,TREPLY):
            return fail(o,7,114)
        status=get(o,HEAD+8)
        if get(o,MODERN)!=0:
            kind=get(o,HEAD+112)
            pending=get(o,HEAD+120)
            if kind>2 or pending>1 or (status==3 and kind==0) or (status!=3 and (kind!=0 or pending!=0)):
                return quarantine(o,w,114)
            put(o,NESTED_PENDING,pending)
        if status==3:
            put(o,TYPED_PENDING,1)
            if get(o,MODERN)!=0:
                put(o,TYPED_PENDING,get(o,HEAD+112))
            if get(o,ERROR)==0:
                put(o,ERROR,9)
            return quarantine(o,w,114)
        if status>2:
            return fail(o,7,status)
        put(o,TYPED_PENDING,0)
        put(o,NESTED_PENDING,0)
        within(o,DET,HEAD+24,24)
        if get(o,RESUME_CLEAN)!=0:
            put(o,RESUME_CLEAN,0)
            return again(o,700)
        if status==2:
            return fail(o,choose(get(o,HEAD+96)==5,5,7),get(o,HEAD+96))
        if status==1:
            return original_error(o,get(o,HEAD+16))
        if get(o,DET)==0:
            return fail(o,9,115)
        return again(o,200)
    if phase==120:
        return typed_call(o,w)
    return fail(o,9,phase)

def typed_request(o:mutbuf,w:mutbuf,retry:u64) -> u64:
    magic=choose(retry==0,TREQUEST,TRETRY)
    if get(o,MODERN)!=0:
        magic=choose(retry==0,NEW_TREQUEST,NEW_TRETRY)
    request(o,magic,choose(retry==0,get(o,MODE),2))
    if retry==0:
        within(o,RQ+16,CAP,24)
    put(o,RQ+40,get(w,80))
    put(o,RQ+48,10100891)
    return 0

def typed_call(o:mutbuf,w:mutbuf) -> u32:
    return invoke(o,110,get(w,112),256,get(o,TSRC),get(o,TSCN),get(o,TOUT),get(o,TOUTN),1152,128)

def freeze_capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        zero(w,2048,2048)
        put(w,2048,choose(get(o,MODERN)!=0,NEW_FCONTEXT,FCONTEXT))
        at=8
        while at<88:
            put(w,2048+at,get(w,at))
            at=at+8
        request(o,choose(get(o,MODERN)!=0,NEW_FREQUEST,FREQUEST),0)
        within(o,RQ+24,DET,24)
        put(o,FREEZE_ACTIVE,2)
        return invoke(o,201,get(w,120),259,RQ,128,get(o,TOUT),get(o,TOUTN),2048,2048)
    if phase==201:
        if get(o,FEEDBACK)!=0:
            if get(o,RESUME_CLEAN)!=0:
                return quarantine(o,w,get(o,FEEDBACK))
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,202,0,get(o,TOUT),3,HEAD,128)
    if phase==202:
        if get(o,HEAD)!=choose(get(o,MODERN)!=0,NEW_FREPLY,FREPLY):
            return fail(o,7,202)
        status=get(o,HEAD+8)
        if get(o,MODERN)!=0:
            retained=get(o,HEAD+56)
            kind=get(o,HEAD+104)
            pending=get(o,HEAD+112)
            if retained>1 or kind>2 or pending>1 or get(w,2144)!=retained:
                return quarantine(o,w,202)
            if (retained==0 and (kind!=0 or pending!=0)) or (retained==1 and kind==0):
                return quarantine(o,w,202)
            put(o,NESTED_PENDING,pending)
        if get(w,2144)!=0 or get(o,HEAD+56)!=0:
            put(o,FREEZE_ACTIVE,1)
            if get(o,MODERN)!=0:
                put(o,FREEZE_ACTIVE,get(o,HEAD+104))
            if get(o,ERROR)==0:
                put(o,ERROR,9)
            return quarantine(o,w,status)
        put(o,FREEZE_ACTIVE,0)
        put(o,NESTED_PENDING,0)
        if status==0:
            within(o,FROZCAP,HEAD+16,24)
        if get(o,RESUME_CLEAN)!=0:
            put(o,RESUME_CLEAN,0)
            return again(o,700)
        if status==1:
            return original_error(o,31)
        if status!=0:
            return fail(o,status,get(o,HEAD+64))
        if get(o,FROZCAP)==0:
            return fail(o,9,203)
        request(o,BREQUEST,6)
        within(o,RQ+24,FROZCAP,24)
        return payload(o,w,203)
    if phase==203:
        if payload_ok(o)==False:
            return payload_fail(o)
        n=get(o,RP+40)
        if n>8388608 or get(o,RP+64)==0:
            return fail(o,9,204)
        put(o,SRC_PTR,get(o,RP+64))
        put(o,RAWN,n)
        return again(o,40)
    return fail(o,9,phase)

def normalizing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        put(o,PWORKN,20971520)
        return mapping(o,301,get(o,PWORKN))
    if phase==301:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,PWORK,raw)
        put(o,ROLE,1)
        return again(o,302)
    if phase==302:
        request(o,PREQUEST,get(o,ROLE))
        put(o,RQ+16,get(o,FDIN)-1)
        put(o,RQ+32,get(o,RAWN))
        put(o,RQ+40,choose(get(o,ROLE)==1,16777280,67108864))
        put(o,RQ+48,67108864)
        return memory(o,303,3,RQ,0,get(o,PFRAME),128)
    if phase==303:
        return invoke(o,304,get(w,128),48,get(o,PFRAME),get(o,PFRAMEN),RP,128,get(o,PWORK),get(o,PWORKN))
    if phase==304:
        rc=get(o,FEEDBACK)
        if get(o,RP)!=PREPLY or get(o,RP+8)!=rc:
            return fail(o,7,rc)
        if rc!=0:
            return fail(o,choose(get(o,RP+40)==NEG12,5,8),get(o,RP+40))
        a=get(o,RP+48)
        b=get(o,RP+56)
        if a<3 or a>2147483647 or b<3 or b>2147483647 or a==b:
            return fail(o,9,304)
        put(o,STDOUT,a+1)
        put(o,STDERR,b+1)
        if get(o,RP+96)!=1 or get(o,RP+104)!=7 or get(o,RP+112)!=15:
            return fail(o,9,305)
        wait=get(o,RP+24)
        n=get(o,RP+64)
        if get(o,RP+72)!=0:
            return fail(o,7,306)
        if get(o,ROLE)==1:
            if wait==512 or wait==768:
                put(o,ROLE,4)
                put(o,AFTER_CLOSE,302)
                return again(o,350)
            if wait!=0 or n<64 or n>16777280:
                return fail(o,7,wait)
            put(o,ERROR,0)
        else:
            if wait!=512 or n==0 or n>67108864:
                return fail(o,7,wait)
            put(o,ERROR,1)
        put(o,RESULTN,n)
        put(o,OUTMAPN,128+n)
        return mapping(o,400,get(o,OUTMAPN))
    if phase==350:
        if get(o,STDOUT)!=0:
            raw=get(o,STDOUT)-1
            if get(o,MODERN)!=0:
                return system(o,351,436,0,raw,raw,0,0,0,0)
            put(o,STDOUT,0)
            return system(o,351,3,0,raw,0,0,0,0,0)
        return again(o,352)
    if phase==351:
        if get(o,FEEDBACK)!=0:
            return fail(o,8,get(o,FEEDBACK))
        if get(o,MODERN)!=0:
            put(o,STDOUT,0)
        return again(o,352)
    if phase==352:
        if get(o,STDERR)!=0:
            raw=get(o,STDERR)-1
            if get(o,MODERN)!=0:
                return system(o,353,436,0,raw,raw,0,0,0,0)
            put(o,STDERR,0)
            return system(o,353,3,0,raw,0,0,0,0,0)
        return again(o,get(o,AFTER_CLOSE))
    if phase==353:
        if get(o,FEEDBACK)!=0:
            return fail(o,8,get(o,FEEDBACK))
        if get(o,MODERN)!=0:
            put(o,STDERR,0)
        return again(o,get(o,AFTER_CLOSE))
    return fail(o,9,phase)

def output_capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,OUTMAP,raw)
        put(o,CURSOR,0)
        return again(o,401)
    if phase==401:
        if get(o,CURSOR)==get(o,RESULTN):
            put(o,AFTER_CLOSE,403)
            return again(o,350)
        return system(o,402,17,0,get(o,STDOUT)-1,get(o,OUTMAP)+128+get(o,CURSOR),get(o,RESULTN)-get(o,CURSOR),get(o,CURSOR),0,0)
    if phase==402:
        n=get(o,FEEDBACK)
        if n==NEG4:
            return again(o,401)
        if n==0 or n>=NEGATIVE or n>get(o,RESULTN)-get(o,CURSOR):
            return fail(o,8,n)
        put(o,CURSOR,get(o,CURSOR)+n)
        return again(o,401)
    if phase==403:
        if get(o,ROLE)==4:
            return again(o,420)
        return memory(o,404,0,get(o,OUTMAP)+128,3,HEAD,64)
    if phase==404:
        if get(o,HEAD)!=NORM or get(o,HEAD+8)!=0 or get(o,HEAD+16)!=0 or get(o,HEAD+48)!=0 or get(o,HEAD+56)!=0:
            return fail(o,7,404)
        n=get(o,HEAD+32)
        c=get(o,HEAD+40)
        if get(o,HEAD+24)>4 or n==0 or n>8388608 or c==0 or c>8388608:
            return fail(o,7,405)
        if n>get(o,RESULTN)-64 or c!=get(o,RESULTN)-64-n:
            return fail(o,7,406)
        put(o,ORIGINAL_N,n)
        put(o,CORE_N,c)
        put(o,CORE_PROFILE,get(o,HEAD+24))
        if get(o,COMPARE)!=0:
            return again(o,500)
        return again(o,420)
    if phase==420:
        request(o,BREQUEST,1)
        put(o,RQ+72,get(o,RESULTN))
        return memory(o,421,3,RQ,0,get(o,OUTMAP),128)
    if phase==421:
        return invoke(o,422,get(w,56),48,get(o,OUTMAP),get(o,OUTMAPN),RP,512,get(w,64),get(w,72))
    if phase==422:
        if payload_ok(o)==False:
            return payload_fail(o)
        within(o,RESULTCAP,RP+16,24)
        if get(o,RESULTCAP)==0 or get(o,RP+40)!=get(o,RESULTN):
            return fail(o,9,422)
        return again(o,700)
    return fail(o,9,phase)

def comparing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,CORE_PROFILE)==0 or get(o,RAWN)!=get(o,ORIGINAL_N):
            return original_error(o,34)
        request(o,VREQUEST,7)
        within(o,RQ+24,CANON,24)
        return value(o,w,501)
    if phase==501:
        if value_ok(o)==False:
            return value_fail(o)
        if get(o,RP+16)!=7 or get(o,RP+72)!=get(o,CORE_N):
            return original_error(o,34)
        put(o,COMPARE_PART,0)
        put(o,CURSOR,0)
        return again(o,502)
    if phase==502:
        n=choose(get(o,COMPARE_PART)==0,get(o,ORIGINAL_N),get(o,CORE_N))
        if get(o,CURSOR)==n:
            if get(o,COMPARE_PART)==0:
                put(o,COMPARE_PART,1)
                put(o,CURSOR,0)
                return again(o,502)
            return again(o,420)
        count=n-get(o,CURSOR)
        if count>16384:
            count=16384
        put(o,CHUNK,count)
        request(o,VREQUEST,19)
        within(o,RQ+24,choose(get(o,COMPARE_PART)==0,CAP,CANON),24)
        put(o,RQ+104,get(o,CURSOR))
        put(o,RQ+112,count)
        return value(o,w,503)
    if phase==503:
        if value_ok(o)==False or get(o,RP+64)!=get(o,CHUNK):
            return value_fail(o)
        offset=192+get(o,CURSOR)
        if get(o,COMPARE_PART)!=0:
            offset=offset+get(o,ORIGINAL_N)
        return memory(o,504,0,get(o,OUTMAP)+offset,3,CHECKBUF,get(o,CHUNK))
    if phase==504:
        at=0
        while at<get(o,CHUNK):
            if byte(o,RP+8192+at)!=byte(o,CHECKBUF+at):
                return original_error(o,34)
            at=at+1
        put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
        return again(o,502)
    return fail(o,9,phase)

def errors(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        n=error_text(o,get(o,DETAIL))
        if n==0:
            return fail(o,7,get(o,DETAIL))
        put(o,RESULTN,n)
        zero(o,ERRBUF-128,128)
        put(o,ERRBUF-128,BREQUEST)
        put(o,ERRBUF-120,1)
        put(o,ERRBUF-56,n)
        return invoke(o,601,get(w,56),51,ERRBUF-128,128+n,RP,512,get(w,64),get(w,72))
    if phase==601:
        if payload_ok(o)==False:
            return payload_fail(o)
        within(o,RESULTCAP,RP+16,24)
        if get(o,RESULTCAP)==0 or get(o,RP+40)!=get(o,RESULTN):
            return fail(o,9,601)
        return again(o,700)
    return fail(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,TYPED_PENDING)!=0:
            if get(o,OP)!=1 or get(o,TYPED_PENDING)!=1:
                return quarantine(o,w,700)
            typed_request(o,w,1)
            put(o,RESUME_CLEAN,1)
            return memory(o,120,3,RQ,0,get(o,TSRC),128)
        if get(o,FREEZE_ACTIVE)!=0:
            if get(o,OP)!=1 or get(o,FREEZE_ACTIVE)!=1:
                return quarantine(o,w,701)
            request(o,choose(get(o,MODERN)!=0,NEW_FREQUEST,FREQUEST),1)
            put(o,RESUME_CLEAN,1)
            return invoke(o,201,get(w,120),259,RQ,128,get(o,TOUT),get(o,TOUTN),2048,2048)
        if get(o,MODERN)!=0 and get(o,VALUE_PENDING)!=0:
            request(o,VALUE_DROP_INPUT,31)
            release_begin(o)
            return value(o,w,705)
        put(o,CLEAN,0)
        return again(o,710)
    if phase==705:
        if release_value_retry(o)==0:
            return quarantine(o,w,get(o,RP+8))
        return again(o,700)
    if phase==710:
        index=get(o,CLEAN)
        if index>=7:
            put(o,CLEAN,0)
            return again(o,720)
        at=CAP
        owner=0
        if index==0:
            at=RESULTCAP
            owner=1
            if get(o,ERROR)<5:
                put(o,CLEAN,index+1)
                return again(o,710)
        elif index==1:
            at=FROZCAP
            owner=1
        elif index==2:
            at=DET
        elif index==3:
            at=STRUCTCAP
        elif index==4:
            at=CANON
        elif index==5:
            at=CAP
        else:
            put(o,CLEAN,index+1)
            return again(o,710)
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,710)
        put(o,CLEAN_AT,at)
        put(o,CLEAN_OWNER,owner)
        request(o,choose(owner==1,BREQUEST,VREQUEST),choose(owner==1,3,6))
        if get(o,MODERN)!=0 and owner==0:
            request(o,VALUE_DROP_INPUT,29)
            release_begin(o)
        within(o,RQ+24,at,24)
        if owner==1:
            return payload(o,w,711)
        return value(o,w,711)
    if phase==711:
        if get(o,MODERN)!=0:
            if get(o,CLEAN_OWNER)==0:
                released=release_value(o,get(o,CLEAN_AT))
                if released==0 or get(o,VALUE_PENDING)!=0:
                    return quarantine(o,w,get(o,RP+8))
            else:
                if payload_ok(o)==False:
                    known=get(o,FEEDBACK)==0 and get(o,RP)==BREPLY
                    status=get(o,RP+8)
                    retryable=known and (status==1 or status==5 or status==6)
                    put(o,QUARANTINE_KIND,choose(retryable,1,2))
                    return quarantine(o,w,status)
                zero(o,get(o,CLEAN_AT),24)
            put(o,CLEAN,get(o,CLEAN)+1)
            return again(o,710)
        good=choose(get(o,CLEAN_OWNER)==1,1,0)
        if (good==1 and payload_ok(o)==False) or (good==0 and value_ok(o)==False):
            return quarantine(o,w,get(o,RP+8))
        zero(o,get(o,CLEAN_AT),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,710)
    if phase==720:
        index=get(o,CLEAN)
        if index>=3:
            put(o,CLEAN,0)
            return again(o,730)
        at=FDIN
        if index==1:
            at=STDOUT
        if index==2:
            at=STDERR
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,720)
        fd=get(o,at)-1
        if get(o,MODERN)!=0:
            put(o,CLEAN_AT,at)
            return system(o,721,436,0,fd,fd,0,0,0,0)
        put(o,at,0)
        return system(o,721,3,0,fd,0,0,0,0,0)
    if phase==721:
        if get(o,MODERN)!=0:
            if get(o,FEEDBACK)!=0:
                return quarantine(o,w,get(o,FEEDBACK))
            put(o,get(o,CLEAN_AT),0)
            put(o,CLEAN,get(o,CLEAN)+1)
            return again(o,720)
        if get(o,FEEDBACK)!=0:
            put(o,ERROR,8)
            put(o,DETAIL,get(o,FEEDBACK))
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,720)
    if phase==730:
        index=get(o,CLEAN)
        if index>=6:
            if get(o,ERROR)>=5 and get(o,RESULTCAP)!=0:
                return again(o,700)
            return finish(o,get(o,ERROR))
        at=OUTMAP
        if index==1:
            at=PREF
        elif index==2:
            at=PWORK
        elif index==3:
            at=PFRAME
        elif index==4:
            at=TOUT
        elif index==5:
            at=TSRC
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,730)
        put(o,CLEAN_AT,at)
        return system(o,731,11,0,get(o,at),get(o,at+8),0,0,0,0)
    if phase==731:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,get(o,FEEDBACK))
        zero(o,get(o,CLEAN_AT),16)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,730)
    return fail(o,9,phase)

def original_error(o:mutbuf,code:u64) -> u32:
    put(o,ERROR,2)
    put(o,DETAIL,code)
    return again(o,600)
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    if get(o,MODERN)!=0:
        if get(o,QUARANTINE_KIND)==0:
            put(o,QUARANTINE_KIND,1)
        if get(o,TYPED_PENDING)==2 or get(o,FREEZE_ACTIVE)==2:
            put(o,QUARANTINE_KIND,2)
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            put(o,QUARANTINE_KIND,2)
    put(o,DETAIL,detail)
    to_work(o,w,128,256,896)
    put(w,152,1)
    put(o,QUARANTINED,1)
    return finish(o,9)

def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,700)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,choose(get(o,MODERN)!=0,NEW_REPLY,REPLY))
    put(o,8,status)
    if status<=2:
        within(o,16,RESULTCAP,24)
        put(o,40,get(o,RESULTN))
        zero(o,RESULTCAP,24)
    put(o,48,get(o,DETAIL))
    put(o,56,get(o,QUARANTINED))
    if get(o,MODERN)!=0 and get(o,QUARANTINED)!=0:
        put(o,64,get(o,QUARANTINE_KIND))
        pending=get(o,VALUE_PENDING)!=0 or get(o,NESTED_PENDING)!=0
        put(o,72,choose(pending,1,0))
    return 0
def raw_read(o:mutbuf,w:mutbuf,next:u64,cap:u64) -> u32:
    count=get(o,RAWN)-get(o,CURSOR)
    if count>16384:
        count=16384
    put(o,CHUNK,count)
    request(o,VREQUEST,19)
    within(o,RQ+24,cap,24)
    put(o,RQ+104,get(o,CURSOR))
    put(o,RQ+112,count)
    return value(o,w,next)
def scalar_ok(o:mutbuf) -> bool:
    return value_ok(o) and get(o,RP+64)==get(o,CHUNK) and get(o,RP+72)==get(o,RAWN)
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VREPLY and get(o,RP+8)==0
def payload_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==BREPLY and get(o,RP+8)==0
def value_fail(o:mutbuf) -> u32:
    return fail(o,choose(get(o,RP+8)==5,5,6),get(o,RP+8))
def payload_fail(o:mutbuf) -> u32:
    return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,128,RP,32768,get(w,16),get(w,24))
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,56),51,RQ,128,RP,512,get(w,64),get(w,72))

def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    if get(o,FEEDBACK)!=0 or get(o,at)!=magic:
        return 0
    return 1
'''
SOURCE += '\n' + retirement_source('release_begin', 'release_value', 'release_value_retry')
def source_program():
    selected={'mapping','request','invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'}
    helpers='\n'.join(ast.unparse(f) for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef) and f.name in selected)
    errors={**STRUCTURE_ERRORS,9:'E_HIA_FORMAT: invalid/deep UTF-8 JSON',30:'E_HIA_FORMAT: structured input must be immutable canonical bytes',31:'E_HIA_FORMAT: invalid/deep UTF-8 JSON',32:'E_HIA_LIMIT: program exceeds byte budget',33:'E_HIA_LIMIT: program exceeds structural budget before JSON allocation',34:'E_HIA_CORE: structured input and executable core differ',35:'E_HIA_VERSION_COLLISION: historical nominal v2 requires import_legacy_composite_v2; the primitive v2 namespace cannot infer a producer profile'}
    text=SOURCE+'\n'+helpers+'\ndef error_text(o:mutbuf,code:u64) -> u64:\n'
    for code,message in sorted(errors.items()):
        payload=json.dumps({'class':'HIAProgramRejected','code':message.split(':',1)[0],'message':message},ensure_ascii=False,separators=(',',':'),sort_keys=True).encode()
        text+='    if code=='+str(code)+':\n'
        for at in range(0,len(payload),8):
            text+='        put(o,ERRBUF+'+str(at)+','+str(int.from_bytes(payload[at:at+8].ljust(8,b'\0'),'little'))+')\n'
        text+='        return '+str(len(payload))+'\n'
    text+='    return 0\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():
    return document(source_program(),'background_optimizer_verify_program')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_verify_program.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
