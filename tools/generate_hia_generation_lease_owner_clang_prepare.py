"""Native Clang preparation, fresh artifact admission and same-holder custody.

This is an independent fixed native child. The trusted root binds its one Value
arena and actual source directory; no public operation selects an entry.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_prepare_proof import SOURCE as PROOF
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIAMVGF2','little'),R=int.from_bytes(b'HIAMVGR2','little'),
 BIND=int.from_bytes(b'HIAMVGB1','little'),BINDR=int.from_bytes(b'HIAMVGBR','little'),
 EXQ=int.from_bytes(b'HIAMVGE1','little'),EXR=int.from_bytes(b'HIAMVGER','little'),
 TAG=int.from_bytes(b'HIAMVGW2','little'),CB=int.from_bytes(b'HIAMVCB2','little'),
 CBR=int.from_bytes(b'HIAMVCBR','little'),CQ=int.from_bytes(b'HIAMVBC1','little'),CR=int.from_bytes(b'HIAMVCR1','little'),
 CEQ=int.from_bytes(b'HIAMVCE1','little'),CER=int.from_bytes(b'HIAMVCER','little'),
 IQ=int.from_bytes(b'HIAMVI04','little'),IR=int.from_bytes(b'HIAMVIR1','little'),ITAG=int.from_bytes(b'HIAMVIS1','little'),
 ABI_MAGIC=int.from_bytes(b'HIAMVAB1','little'),PR=int.from_bytes(b'HIAMVPR1','little'),
 RETQ=int.from_bytes(b'HIAMVRT1','little'),RETR=int.from_bytes(b'HIAMVTR1','little'),
 V5=int.from_bytes(b'HIABVQ05','little'),V6=int.from_bytes(b'HIABVQ06','little'),
 VR=int.from_bytes(b'HIABVR01','little'),VR2=int.from_bytes(b'HIABVR02','little'),
 BAD=4294967293,NONE=(1<<64)-1,WORK=512<<20,CWORK=538968064,
 CTRL=400<<20,FRAME=402<<20,CORE=448<<20,ABI=456<<20,PATH=473<<20,
 BOUT=386<<20,IOUT=388<<20,PROUT=(388<<20)+512,ROUT=(388<<20)+1024,
 CLEANOUT=(388<<20)+2048,BOUT_BIND=(388<<20)+4096,REQUEST=(388<<20)+8192,
 VALUEOUT=(388<<20)+16384,
 PH=(400<<20),FB=(400<<20)+8,CONTEXT=(400<<20)+16,SELF=(400<<20)+24,
 PID=(400<<20)+32,ENTRY=(400<<20)+40,MODE=(400<<20)+48,STATE=(400<<20)+56,
 VE=(400<<20)+64,VC=(400<<20)+72,VN=(400<<20)+80,NONCE=(400<<20)+88,SOURCEFD=(400<<20)+96,
 CP=(400<<20)+104,CA=(400<<20)+112,CRET=(400<<20)+120,
 ERROR=(400<<20)+128,DETAIL=(400<<20)+136,CHILD=(400<<20)+144,
 CSTATUS=(400<<20)+152,CDETAIL=(400<<20)+160,
 CN=(400<<20)+168,AN=(400<<20)+176,PN=(400<<20)+184,RN=(400<<20)+192,
 PREPARED=(400<<20)+200,HOLDER=(400<<20)+208,REGISTER=(400<<20)+216,RETSTATUS=(400<<20)+224,
 PENDING=(400<<20)+232,UNKNOWN=(400<<20)+240,CLEANERROR=(400<<20)+248,CLEANERRNO=(400<<20)+256,
 EXCAP=(400<<20)+264,EXHELD=(400<<20)+288,OP=(400<<20)+296,BUSY=(400<<20)+312,
 TOKEN=(400<<20)+320,TOKEN_HELD=(400<<20)+344,TOKEN_PENDING=(400<<20)+352,
 RETIRED_IMAGE=(400<<20)+360,RAW_N=(400<<20)+368,CONTINUE=(400<<20)+376,
 SAVED_IMAGE_SHA=(400<<20)+512,SAVED_NATIVE_SHA=(400<<20)+544,SAVED_SIZE=(400<<20)+576,
)
C.update(OBS_ID=(400<<20)+384,OBS_CHILD=(400<<20)+392,OBS_DONE=(400<<20)+400,
 MAPSFD=(400<<20)+408,MAPS_HELD=(400<<20)+416,MRES=(400<<20)+424,MERROR=(400<<20)+432,
 MPREFIX_N=(400<<20)+440,MTOKENS=(400<<20)+448,MINTOKEN=(400<<20)+456,MPREFIX_DONE=(400<<20)+464,
 PARSE_FIELDS=(400<<20)+768,PARSE_VALUE=(400<<20)+856,PARSE_MAJOR=(400<<20)+864,PARSE_MINOR=(400<<20)+872,
 OBS_STAT=(400<<20)+1024,MAPSPATH=(388<<20)+24576,MPREFIX=(388<<20)+25088,MCHUNK=389<<20)
SOURCE=r'''
def prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PH)
    raw=get(w,FB)
    if phase==0:
        if get(w,MODE)==0:
            return bind(s,o,w)
        if get(w,MODE)==2:
            return exception(s,o,w)
        return begin(s,o,w)
    if phase>=1 and phase<10:
        return binding(s,o,w,phase,raw)
    if phase>=10 and phase<20:
        return preparing(o,w,phase,raw)
    if phase>=20 and phase<30:
        return clang_cleanup(o,w,phase,raw)
    if phase>=40 and phase<50:
        return retiring(o,w,phase,raw)
    if phase>=70 and phase<80:
        return observing(o,w,phase,raw)
    return BAD

def bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=BIND or get(w,CONTEXT)!=0:
        return BAD
    if readword(s,8)==0 or readword(s,16)==0 or readword(s,24)!=256 or readword(s,32)==0 or readword(s,40)>2147483647:
        return BAD
    i=48
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    i=0
    while i<4096:
        if i!=48 and i!=312 and get(w,CTRL+i)!=0:
            return BAD
        i=i+8
    put(w,CONTEXT,TAG)
    put(w,STATE,8)
    put(w,VE,readword(s,8))
    put(w,VC,readword(s,16))
    put(w,VN,256)
    put(w,NONCE,readword(s,32))
    put(w,SOURCEFD,readword(s,40))
    put(w,RETSTATUS,NONE)
    put(w,PH,1)
    return 2

def binding(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==1:
        put(w,SELF,raw)
        put(w,PH,2)
        return 3
    if phase==2:
        put(w,ENTRY,raw)
        put(w,PH,3)
        return 11
    if phase==3:
        if raw==0 or failed(raw):
            return bind_error(o,w,1,raw)
        put(w,PID,raw)
        value_frame(w,V6,21)
        return value(o,w,4)
    if phase==4:
        if raw!=0 or get(w,VALUEOUT)!=VR:
            return unknown(o,w,4)
        if get(w,VALUEOUT+24)!=0:
            copy(w,VALUEOUT+24,TOKEN,24)
            put(w,TOKEN_HELD,1)
        if get(w,VALUEOUT+8)!=0 or get(w,TOKEN_HELD)!=1:
            return bind_error(o,w,1,get(w,VALUEOUT+8))
        return system(o,w,5,9,0,0,CWORK,3,34,NONE,0)
    if phase==5:
        if failed(raw):
            return bind_error(o,w,9,raw)
        put(w,CP,raw)
        zero(w,REQUEST,128)
        put(w,REQUEST,CB)
        put(w,REQUEST+8,get(w,VE))
        put(w,REQUEST+16,get(w,VC))
        put(w,REQUEST+24,256)
        put(w,REQUEST+32,get(w,NONCE))
        put(w,REQUEST+40,get(w,SOURCEFD))
        put(w,CA,1)
        return role(o,w,6,4,REQUEST,128,BOUT_BIND,128,0,CWORK)
    if phase==6:
        if raw!=0 or get(w,BOUT_BIND)!=CBR or get(w,BOUT_BIND+88)!=1 or get(w,BOUT_BIND+96)>1:
            return unknown(o,w,6)
        if get(w,BOUT_BIND+8)!=0 or get(w,BOUT_BIND+96)!=1:
            return bind_error(o,w,get(w,BOUT_BIND+8),get(w,BOUT_BIND+16))
        put(w,STATE,1)
        return bind_reply(o,w,0,0)
    return BAD

def bind_error(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,ERROR,status)
    put(w,DETAIL,detail)
    return bind_reply(o,w,status,detail)

def bind_reply(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,BINDR)
    put(o,8,status)
    put(o,16,detail)
    put(o,24,get(w,STATE))
    put(o,80,choose(get(w,STATE)==1,0,1))
    put(o,88,choose(get(w,UNKNOWN)==0,1,0))
    put(o,96,choose(get(w,STATE)==1,1,0))
    put(w,PH,0)
    return 0

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or readword(s,0)!=Q or readword(s,8)>2 or get(w,CONTEXT)!=TAG:
        return BAD
    op=readword(s,8)
    if op!=0:
        if length(s)!=256:
            return BAD
        i=16
        while i<256:
            if readword(s,i)!=0:
                return BAD
            i=i+8
        put(w,OP,op)
        if op==2:
            return finish(o,w)
        if get(w,STATE)==6 or get(w,UNKNOWN)!=0:
            return finish(o,w)
        put(w,STATE,5)
        put(w,CLEANERROR,0)
        put(w,CLEANERRNO,0)
        put(w,PENDING,0)
        return retire_image(o,w)
    if get(w,STATE)!=1:
        return BAD
    n=readword(s,40)
    ab=readword(s,48)
    pn=readword(s,56)
    if readword(s,16)!=0 or readword(s,24)==0 or readword(s,64)==0 or readword(s,88)!=0:
        return BAD
    if readword(s,32)!=0 and (readword(s,32)&7)!=0:
        return BAD
    if n==0 or n>8388608 or n>length(s)-256 or ab>length(s)-256-n or pn!=length(s)-256-n-ab:
        return BAD
    if ab<336 or ab>5136 or pn==0 or pn>4095 or readword(s,256+n)!=ABI_MAGIC:
        return BAD
    count=readword(s,264+n)
    if count==0 or count>16 or ab!=16+320*count or abi_valid(s,256+n,count)==False:
        return BAD
    if byte(s,256+n+ab)!=47:
        return BAD
    i=0
    while i<pn:
        if byte(s,256+n+ab+i)==0:
            return BAD
        i=i+1
    i=96
    while i<256:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    put(w,OP,0)
    put(w,STATE,2)
    put(w,RAW_N,length(s))
    put(w,CN,n)
    put(w,AN,ab)
    put(w,PN,pn)
    copy_input(s,256,w,CORE,n)
    copy_input(s,256+n,w,ABI,ab)
    copy_input(s,256+n+ab,w,PATH,pn)
    store(w,PATH+pn,0)
    copy_input(s,0,w,FRAME,length(s))
    put(w,FRAME,CQ)
    zero(w,BOUT,512)
    put(w,BOUT+88,NONE)
    put(w,BOUT+96,NONE)
    zero(w,IOUT,2048)
    return role(o,w,10,5,FRAME,length(s),BOUT,1049088,0,CWORK)

def preparing(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==10:
        put(w,CHILD,raw)
        if raw!=0 or get(w,BOUT)!=CR or get(w,BOUT+344)!=1 or get(w,BOUT+360)>1:
            return unknown(o,w,10)
        put(w,CSTATUS,get(w,BOUT+8))
        put(w,CDETAIL,get(w,BOUT+16))
        if get(w,BOUT+8)!=0:
            error(w,1,get(w,BOUT+16))
            return empty_holder(o,w)
        rn=get(w,BOUT+80)
        if rn==0 or rn>1048576 or get(w,BOUT+48)==0 or get(w,BOUT+48)>7:
            error(w,1,11)
            return empty_holder(o,w)
        if get(w,BOUT+56)!=get(w,CN) or get(w,BOUT+64)!=get(w,AN) or get(w,BOUT+72)!=get(w,PN):
            error(w,1,12)
            return empty_holder(o,w)
        if get(w,BOUT+104)!=0 or get(w,BOUT+320)!=1 or get(w,BOUT+328)!=0:
            error(w,1,13)
            return empty_holder(o,w)
        if equal(w,BOUT+128,BOUT+160,32)==0:
            error(w,1,14)
            return empty_holder(o,w)
        put(w,RN,rn)
        n=get(w,CN)
        ab=get(w,AN)
        pn=get(w,PN)
        zero(w,FRAME,256)
        put(w,FRAME,IQ)
        put(w,FRAME+8,pn)
        put(w,FRAME+16,ab)
        put(w,FRAME+24,rn)
        copy(w,BOUT+160,FRAME+32,32)
        copy(w,BOUT+128,FRAME+64,32)
        copy(w,BOUT+288,FRAME+128,32)
        put(w,FRAME+160,n)
        copy(w,PATH,FRAME+256,pn)
        copy(w,ABI,FRAME+256+pn,ab)
        copy(w,BOUT+512,FRAME+256+pn+ab,rn)
        copy(w,CORE,FRAME+256+pn+ab+rn,n)
        zero(w,0,8192)
        return role(o,w,11,7,FRAME,256+pn+ab+rn+n,IOUT,512,0,352321536)
    if phase==11:
        put(w,CHILD,raw)
        if get(w,16)!=ITAG or (get(w,0)!=902 and get(w,0)!=999):
            if get(w,16)==0 and get(w,0)==0:
                error(w,2,raw)
                return empty_holder(o,w)
            return unknown(o,w,11)
        put(w,HOLDER,1)
        if raw!=0 or get(w,IOUT)!=IR or get(w,IOUT+8)!=0:
            error(w,2,get(w,IOUT+16))
            return start_clang_cleanup(o,w)
        copy(w,1872,SAVED_IMAGE_SHA,32)
        copy(w,1904,SAVED_NATIVE_SHA,32)
        put(w,SAVED_SIZE,get(w,248))
        return role(o,w,12,8,CORE,get(w,CN),PROUT,128,0,167772160)
    if phase==12:
        put(w,CHILD,raw)
        if raw!=0 or get(w,PROUT)!=PR or get(w,PROUT+8)!=0:
            error(w,3,get(w,PROUT+16))
        else:
            put(w,PREPARED,1)
        return start_clang_cleanup(o,w)
    return BAD

def empty_holder(o:mutbuf,w:mutbuf) -> u32:
    if get(w,HOLDER)==0:
        zero(w,0,8192)
        put(w,0,902)
        put(w,16,ITAG)
        put(w,24,get(w,PID))
        put(w,32,NONE)
        put(w,40,NONE)
        put(w,48,NONE)
        copy(w,PATH,8192,get(w,PN))
        store(w,8192+get(w,PN),0)
        put(w,HOLDER,1)
    return start_clang_cleanup(o,w)

def start_clang_cleanup(o:mutbuf,w:mutbuf) -> u32:
    if get(w,CP)==0:
        return clang_cleaned(o,w)
    if get(w,CRET)==1:
        return system(o,w,22,11,0,get(w,CP),CWORK,0,0,0,0)
    if get(w,EXHELD)==0:
        zero(w,REQUEST,128)
        put(w,REQUEST,CEQ)
        return role(o,w,20,6,REQUEST,128,CLEANOUT,128,0,CWORK)
    return clang_retire(o,w)

def clang_retire(o:mutbuf,w:mutbuf) -> u32:
    zero(w,REQUEST,256)
    put(w,REQUEST,CQ)
    put(w,REQUEST+8,1)
    return role(o,w,21,5,REQUEST,256,CLEANOUT,512,0,CWORK)

def clang_cleanup(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==20:
        if raw!=0 or get(w,CLEANOUT)!=CER or get(w,CLEANOUT+88)!=1 or get(w,CLEANOUT+96)>1:
            return unknown(o,w,20)
        d=get(w,CLEANOUT+16)
        if d!=0 and d!=2:
            return unknown(o,w,21)
        if get(w,CLEANOUT+96)==1:
            if d!=2 or get(w,CLEANOUT+24)==0:
                return unknown(o,w,22)
            copy(w,CLEANOUT+24,EXCAP,24)
            put(w,EXHELD,1)
        elif d!=0:
            return unknown(o,w,23)
        return clang_retire(o,w)
    if phase==21:
        if raw!=0 or get(w,CLEANOUT)!=CR or get(w,CLEANOUT+344)!=1:
            return unknown(o,w,24)
        if get(w,CLEANOUT+352)!=1 or get(w,CLEANOUT+360)!=0:
            return pending(o,w,get(w,CLEANOUT+368),get(w,CLEANOUT+376))
        put(w,CRET,1)
        return system(o,w,22,11,0,get(w,CP),CWORK,0,0,0,0)
    if phase==22:
        if raw!=0:
            return pending(o,w,9,raw)
        put(w,CP,0)
        put(w,CA,0)
        return clang_cleaned(o,w)
    return BAD

def clang_cleaned(o:mutbuf,w:mutbuf) -> u32:
    if get(w,OP)==1:
        return retire_values(o,w)
    if get(w,ERROR)==0 and get(w,PREPARED)==1:
        put(w,STATE,3)
    else:
        put(w,PREPARED,0)
        put(w,REGISTER,1)
        put(w,STATE,4)
    put(w,PENDING,0)
    return finish(o,w)

def retire_image(o:mutbuf,w:mutbuf) -> u32:
    if get(w,HOLDER)==0 or get(w,RETIRED_IMAGE)==1:
        return start_clang_cleanup(o,w)
    if get(w,OBS_CHILD)==1:
        return observe_mapping(o,w)
    if get(w,OBS_ID)==0:
        if get(w,48)!=NONE:
            zero(w,OBS_STAT,144)
            return system(o,w,70,5,4,get(w,48),OBS_STAT,0,0,0,0)
        if get(w,56)!=0:
            return unknown(o,w,70)
        put(w,OBS_ID,2)
    return legacy_retire(o,w)

def legacy_retire(o:mutbuf,w:mutbuf) -> u32:
    zero(w,REQUEST,24)
    put(w,REQUEST,RETQ)
    put(w,REQUEST+8,1)
    return role(o,w,40,9,REQUEST,24,ROUT,768,0,167772160)

def image_retired(o:mutbuf,w:mutbuf) -> u32:
    put(w,OBS_DONE,1)
    put(w,RETIRED_IMAGE,1)
    put(w,HOLDER,0)
    put(w,PREPARED,0)
    put(w,REGISTER,0)
    return start_clang_cleanup(o,w)

def retiring(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==40:
        put(w,RETSTATUS,raw)
        if raw!=0 or get(w,ROUT)!=RETR or get(w,ROUT+8)!=0:
            return pending(o,w,5,raw)
        if (get(w,ROUT+24)&8)==0:
            if get(w,ROUT+128+23*8)==2 or get(w,ROUT+128+24*8)==2 or get(w,ROUT+128+12*8)==2:
                return unknown(o,w,40)
            return pending(o,w,5,get(w,ROUT+24))
        put(w,OBS_CHILD,1)
        return observe_mapping(o,w)
    if phase==41:
        if drop_valid(w,raw)==0:
            return unknown(o,w,41)
        if get(w,VALUEOUT+96)==1:
            zero(w,EXCAP,24)
            put(w,EXHELD,0)
        if get(w,VALUEOUT+104)!=0:
            put(w,TOKEN_PENDING,1)
        if get(w,EXHELD)!=0:
            return pending(o,w,6,get(w,VALUEOUT+8))
        return retire_values(o,w)
    if phase==42:
        if drop_valid(w,raw)==0:
            return unknown(o,w,42)
        if get(w,VALUEOUT+96)==1:
            zero(w,TOKEN,24)
            put(w,TOKEN_HELD,0)
        if get(w,VALUEOUT+104)!=0:
            put(w,TOKEN_PENDING,1)
        if get(w,TOKEN_HELD)!=0:
            return pending(o,w,6,get(w,VALUEOUT+8))
        return retire_values(o,w)
    if phase==43:
        if drop_valid(w,raw)==0 or get(w,VALUEOUT+96)!=0:
            return unknown(o,w,43)
        if get(w,VALUEOUT+104)!=0:
            return pending(o,w,6,get(w,VALUEOUT+8))
        put(w,TOKEN_PENDING,0)
        return retire_values(o,w)
    return BAD

def observe_mapping(o:mutbuf,w:mutbuf) -> u32:
    if get(w,OBS_ID)==2:
        return image_retired(o,w)
    if get(w,OBS_ID)!=1:
        return unknown(o,w,71)
    if get(w,MAPS_HELD)==1:
        return close_maps(o,w)
    put(w,MRES,0)
    put(w,MERROR,0)
    put(w,MPREFIX_N,0)
    put(w,MTOKENS,0)
    put(w,MINTOKEN,0)
    put(w,MPREFIX_DONE,0)
    put(w,MAPSPATH,0x65732f636f72702f)
    put(w,MAPSPATH+8,0x007370616d2f666c)
    return system(o,w,74,257,4,18446744073709551516,MAPSPATH,524288,0,0,0)

def read_maps(o:mutbuf,w:mutbuf) -> u32:
    return system(o,w,75,0,4,get(w,MAPSFD),MCHUNK,65536,0,0,0)

def close_maps(o:mutbuf,w:mutbuf) -> u32:
    return system(o,w,76,436,0,get(w,MAPSFD),get(w,MAPSFD),0,0,0,0)

def observed_closed(o:mutbuf,w:mutbuf) -> u32:
    put(w,MAPS_HELD,0)
    put(w,MAPSFD,0)
    result=get(w,MRES)
    if result==1:
        return unknown(o,w,76)
    if result!=0:
        return pending(o,w,7,get(w,MERROR))
    return image_retired(o,w)

def observing(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==70:
        if raw!=0:
            return pending(o,w,7,raw)
        if (get(w,OBS_STAT+24)&61440)!=32768 or get(w,OBS_STAT+8)==0:
            return unknown(o,w,70)
        put(w,OBS_ID,1)
        return legacy_retire(o,w)
    if phase==74:
        if raw==18446744073709551612:
            return observe_mapping(o,w)
        if failed(raw):
            return pending(o,w,7,raw)
        put(w,MAPSFD,raw)
        put(w,MAPS_HELD,1)
        return read_maps(o,w)
    if phase==75:
        if raw==18446744073709551612:
            return read_maps(o,w)
        if failed(raw) or raw>65536:
            put(w,MRES,3)
            put(w,MERROR,raw)
            return close_maps(o,w)
        if raw==0:
            result=0
            if get(w,MPREFIX_N)!=0:
                result=mapping_present(w)
            put(w,MRES,result)
            if result==2:
                put(w,MERROR,22)
            return close_maps(o,w)
        result=maps_chunk(w,raw)
        if result!=0:
            put(w,MRES,result)
            if result==2:
                put(w,MERROR,22)
            return close_maps(o,w)
        return read_maps(o,w)
    if phase==76:
        if raw==18446744073709551578:
            return system(o,w,77,3,0,get(w,MAPSFD),0,0,0,0,0)
        if raw!=0:
            return pending(o,w,7,raw)
        return observed_closed(o,w)
    if phase==77:
        if raw!=0:
            return unknown(o,w,77)
        return observed_closed(o,w)
    return BAD

def maps_chunk(w:mutbuf,n:u64) -> u64:
    at=0
    while at<n:
        ch=byte(w,MCHUNK+at)
        if ch==10:
            if get(w,MPREFIX_N)==0:
                return 2
            result=mapping_present(w)
            if result!=0:
                return result
            put(w,MPREFIX_N,0)
            put(w,MTOKENS,0)
            put(w,MINTOKEN,0)
            put(w,MPREFIX_DONE,0)
        else:
            if get(w,MPREFIX_DONE)==0:
                used=get(w,MPREFIX_N)
                if used==256:
                    return 2
                store(w,MPREFIX+used,ch)
                put(w,MPREFIX_N,used+1)
                if maps_space(ch)==1:
                    if get(w,MINTOKEN)==1:
                        put(w,MTOKENS,get(w,MTOKENS)+1)
                        put(w,MINTOKEN,0)
                        if get(w,MTOKENS)==5:
                            put(w,MPREFIX_DONE,1)
                else:
                    put(w,MINTOKEN,1)
        at=at+1
    return 0

def mapping_present(w:mutbuf) -> u64:
    at=0
    end=get(w,MPREFIX_N)
    while at<end:
        first=at
        while at<end and byte(w,MPREFIX+at)!=10 and byte(w,MPREFIX+at)!=13:
            at=at+1
        last=at
        if at<end:
            sep=byte(w,MPREFIX+at)
            at=at+1
            if sep==13 and at<end and byte(w,MPREFIX+at)==10:
                at=at+1
        if first==last:
            return 2
        p=first
        field=0
        while field<5:
            while p<last and maps_space(byte(w,MPREFIX+p))==1:
                p=p+1
            if p==last:
                return 2
            start=p
            while p<last and maps_space(byte(w,MPREFIX+p))==0:
                p=p+1
            put(w,PARSE_FIELDS+field*16,start)
            put(w,PARSE_FIELDS+field*16+8,p)
            field=field+1
        p=get(w,PARSE_FIELDS+48)
        stop=get(w,PARSE_FIELDS+56)
        colon=NONE
        i=p
        while i<stop:
            if byte(w,MPREFIX+i)==58:
                if colon!=NONE:
                    return 2
                colon=i
            i=i+1
        if colon==NONE:
            return 2
        if maps_uint(w,p,colon,16)!=0:
            return 2
        put(w,PARSE_MAJOR,get(w,PARSE_VALUE))
        if maps_uint(w,colon+1,stop,16)!=0:
            return 2
        put(w,PARSE_MINOR,get(w,PARSE_VALUE))
        if maps_uint(w,get(w,PARSE_FIELDS+64),get(w,PARSE_FIELDS+72),10)!=0:
            return 2
        dev=get(w,OBS_STAT)
        major=((dev&1048320)>>8)|((dev&18446726481523507200)>>32)
        minor=(dev&255)|((dev&17592184995840)>>12)
        if get(w,PARSE_MAJOR)==major and get(w,PARSE_MINOR)==minor and get(w,PARSE_VALUE)==get(w,OBS_STAT+8):
            return 1
    return 0

def maps_space(value:u64) -> u64:
    if value==32 or value==9 or value==11 or value==12:
        return 1
    return 0

def maps_uint(w:mutbuf,first:u64,last:u64,base:u64) -> u64:
    if first==last:
        return 1
    value=0
    max=1844674407370955161
    tail=5
    if base==16:
        max=1152921504606846975
        tail=15
    while first<last:
        ch=byte(w,MPREFIX+first)
        digit=16
        if ch>=48 and ch<=57:
            digit=ch-48
        if ch>=65 and ch<=70:
            digit=ch-55
        if ch>=97 and ch<=102:
            digit=ch-87
        if digit>=base or value>max or (value==max and digit>tail):
            return 1
        value=value*base+digit
        first=first+1
    put(w,PARSE_VALUE,value)
    return 0


def retire_values(o:mutbuf,w:mutbuf) -> u32:
    if get(w,EXHELD)!=0:
        value_frame(w,V5,78)
        copy(w,EXCAP,REQUEST+24,24)
        return value(o,w,41)
    if get(w,TOKEN_HELD)!=0:
        value_frame(w,V5,92)
        copy(w,TOKEN,REQUEST+24,24)
        return value(o,w,42)
    if get(w,TOKEN_PENDING)!=0:
        value_frame(w,V5,93)
        return value(o,w,43)
    put(w,STATE,6)
    put(w,PENDING,0)
    put(w,RETSTATUS,0)
    return finish(o,w)

def drop_valid(w:mutbuf,raw:u64) -> u64:
    if raw!=0 or get(w,VALUEOUT)!=VR2 or get(w,VALUEOUT+88)!=1:
        return 0
    if get(w,VALUEOUT+80)>1 or get(w,VALUEOUT+96)>1 or get(w,VALUEOUT+104)>1 or get(w,VALUEOUT+112)>1 or get(w,VALUEOUT+120)!=1:
        return 0
    return 1

def exception(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=EXQ or readword(s,8)>1:
        return BAD
    i=16
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    zero(o,0,128)
    put(o,0,EXR)
    put(o,88,choose(get(w,UNKNOWN)==0,1,0))
    put(o,104,get(w,CLEANERROR))
    if get(w,EXHELD)==1:
        put(o,16,2)
        if readword(s,8)==0 and get(w,UNKNOWN)==0:
            copy_output(w,EXCAP,o,24,24)
            put(o,96,1)
            zero(w,EXCAP,24)
            put(w,EXHELD,0)
    put(w,PH,0)
    return 0

def error(w:mutbuf,status:u64,detail:u64) -> u64:
    if get(w,ERROR)==0:
        put(w,ERROR,status)
        put(w,DETAIL,detail)
    return 0

def pending(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,CLEANERROR,status)
    put(w,CLEANERRNO,detail)
    put(w,PENDING,1)
    if get(w,OP)!=1:
        error(w,4,detail)
        put(w,PREPARED,0)
        put(w,STATE,4)
        put(w,REGISTER,get(w,HOLDER))
    return finish(o,w)

def unknown(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,UNKNOWN,1)
    put(w,STATE,7)
    put(w,PENDING,1)
    put(w,CLEANERROR,19)
    put(w,CLEANERRNO,detail)
    if get(w,MODE)==0:
        return bind_reply(o,w,19,detail)
    return finish(o,w)

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,2048)
    put(o,0,R)
    status=get(w,ERROR)
    if get(w,OP)==1:
        status=choose(get(w,STATE)==6,0,choose(get(w,UNKNOWN)!=0,19,5))
    put(o,8,status)
    put(o,16,get(w,CHILD))
    put(o,24,get(w,DETAIL))
    put(o,32,get(w,RETSTATUS))
    put(o,40,get(w,PREPARED))
    put(o,48,get(w,CN))
    put(o,56,get(w,AN))
    put(o,64,get(w,PN))
    put(o,80,get(w,BOUT+48))
    put(o,88,get(w,PROUT+56))
    put(o,96,get(w,PROUT+64))
    put(o,104,NONE)
    put(o,112,NONE)
    put(o,120,get(w,BOUT+24))
    copy_output(w,BOUT+128,o,128,96)
    copy_output(w,IOUT+64,o,224,32)
    copy_output(w,SAVED_IMAGE_SHA,o,256,64)
    put(o,320,get(w,SAVED_SIZE))
    put(o,328,get(w,IOUT+48))
    put(o,336,get(w,STATE))
    put(o,344,choose(get(w,UNKNOWN)==0,1,0))
    put(o,352,choose(get(w,STATE)==6,1,0))
    put(o,360,get(w,PENDING))
    put(o,368,get(w,CLEANERROR))
    put(o,376,get(w,CLEANERRNO))
    put(o,384,get(w,HOLDER))
    put(o,392,get(w,REGISTER))
    put(o,400,get(w,EXHELD))
    put(o,408,get(w,CP))
    put(o,416,get(w,TOKEN_HELD))
    put(o,424,get(w,CSTATUS))
    put(o,432,get(w,CDETAIL))
    put(o,448,get(w,OBS_CHILD))
    put(o,456,get(w,OBS_ID))
    put(o,464,get(w,OBS_DONE))
    put(o,472,get(w,MAPS_HELD))
    put(o,480,get(w,MRES))
    put(o,488,get(w,MERROR))
    copy_output(w,IOUT,o,512,512)
    copy_output(w,PROUT,o,1024,128)
    copy_output(w,ROUT,o,1152,768)
    if get(w,OP)==0:
        n=get(w,RN)
        if n>length(o)-2048:
            return BAD
        put(o,72,n)
        copy_output(w,BOUT+512,o,2048,n)
    put(w,PH,0)
    return 0

def value_frame(w:mutbuf,magic:u64,op:u64) -> u64:
    zero(w,REQUEST,128)
    zero(w,VALUEOUT,8192)
    put(w,REQUEST,magic)
    put(w,REQUEST+8,op)
    return 0

def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return role(o,w,next,10,REQUEST,128,VALUEOUT,8192,0,256)

def role(o:mutbuf,w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,PH,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    put(o,32,wi)
    put(o,40,wn)
    return action

def system(o:mutbuf,w:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,PH,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def failed(n:u64) -> bool:
    return n>=18446744073709547521
def equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1
def choose(test:bool,a:u64,b:u64) -> u64:
    if test:
        return a
    return b
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
def copy(w:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,w:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(s,at+i))
        i=i+1
    return 0
def copy_output(w:mutbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(w,at+i))
        i=i+1
    return 0
def get(w:mutbuf,at:u64) -> u64:
    n=0
    i=0
    while i<8:
        n=n|(byte(w,at+i)<<(i*8))
        i=i+1
    return n
def readword(s:readbuf,at:u64) -> u64:
    n=0
    i=0
    while i<8:
        n=n|(byte(s,at+i)<<(i*8))
        i=i+1
    return n
def put(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(n>>(i*8))&255)
        i=i+1
    return 0
'''
SOURCE+='\n'+PROOF[PROOF.index('def abi_valid('):PROOF.index('def capture(')]
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_clang_prepare')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_clang_prepare.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
