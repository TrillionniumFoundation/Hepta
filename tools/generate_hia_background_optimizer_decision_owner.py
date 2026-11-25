"""Actual owned background decision, with ordered freezing and fresh verification."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
from tools.generate_hia_background_optimizer_decision import ERRORS,LABELS
ROOT=Path(__file__).resolve().parents[1]
C=dict(PHASE=256,ERROR=264,DETAIL=272,OP=280,QUAR=288,PID=296,CLEAN=304,ADMITTED=312,ERFORMAT=320,
 RETAIN_AT=328,GCROOT=336,GCID=344,GCDEST=352,GCAFTER=360,GCNONE=368,GCSET=376,GCVALUE=384,
 FZCAP=392,FZPAY=400,FZAFTER=408,FZACTIVE=416,VERIFYACTIVE=424,IOACTIVE=432,IOINDEX=440,IOAFTER=448,
 SCAP=456,SMAP=464,SAFTER=472,SKIND=480,SCURSOR=488,SCHUNK=496,
 CMETA=512,CINPUT=536,CRANK=560,CWALL=584,CFUNCTION=608,CEPOCH=632,CGEN=656,CBCORE=680,CBINPUT=704,
 COBS=728,CIOBJ=752,CROBJ=776,CCANDS=800,CROW=824,CCAND=848,CRANKSRC=872,CBOUND=896,CSCHEMA=920,
 CKEY=944,CTEMP=968,CONE=992,CINDEX=1016,CERROR=1040,CTYPE=1064,CMESSAGE=1088,CTYPED=1112,CNUM=1136,CERRDIAGS=1160,CFIRST=1184,CCODE=1208,CRESERVED=1232,CZERO=1256,
 POBS=1280,PROBJ=1328,PIOBJ=1376,PBOUND=1424,PCAND=1472,PRANK=1520,PERROR=1568,
 VCAP=1632,VPAY=1640,VAFTER=1648,VDIGEST=1656,VSTEP=1664,
 HPTR=1680,HN=1688,HDST=1696,HAFTER=1704,HCURSOR=1712,HCHUNK=1720,
 CAND_INPUT_SHA=1760,CAND_CORE_SHA=1792,WALL=1824,BINDINDEX=1832,DESTROY_AT=1840,DESTROY_KIND=1848,
 DAFTER=1856,DSTAGE=1864,DCOPY=1872,DAT=1880,SELECTNODE=1888,SELECTROW=1896,SELECTCUR=1904,SELECTINDEX=1912,
 ERRID=1920,ERRN=1928,ERRCONVERT=1936,UCHAR=1944,USTART=1952,UEND=1960,UCP=1968,ERRINDEX=1976,
 CAPTURES=2048,NESTED=2304,NESTEDN=2312,FN=2352,FNN=2360,GEN=2368,GENN=2376,
 DFRAME=2400,DFRAMEN=2408,DWORK=2416,DWORKN=2424,EFRAME=2432,EFRAMEN=2440,EOUT=2448,EOUTN=2456,
 RPTR=2464,RN=2472,RKIND=2480,RRAW=2488,RPREFIX=2496,
 FEEDBACK=3840,RQ=4096,RP=8192,HEAD=49152,DHEAD=50176,DOUT=51200,ERRBUF=53248,SMALL=55296,HBUF=65536,
 MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,BAD=4294967293)
C.update({k:int.from_bytes(v.encode(),"little") for k,v in {
"MAGIC":"HIABDO01","REPLY":"HIABDRP1","CONTEXT":"HIABDOC1","VREQUEST":"HIABVQ01","VREPLY":"HIABVR01",
"BREQUEST":"HIABPY01","BREPLY":"HIABPYR1","FREQUEST":"HIABFZQ1","FREPLY":"HIABFZR1","FCONTEXT":"HIABFZC1",
"IREQUEST":"HIABIQ01","IREPLY":"HIABIO01","ICONTEXT":"HIABIC01","SIZES":"HIANJS01",
"DREQUEST":"HIABDC01","DREPLY":"HIABDR01","YREQUEST":"HIABVFY1","YREPLY":"HIABVFR1","YCONTEXT":"HIABVYC1","NORM":"HIAVCF01",
"RREQUEST":"HIABRP01","RREPLY":"HIABRR01"}.items()})
SOURCE=r'''
def decision_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<262144 or length(w)<16384:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<10:
        return entering(s,o,w,phase)
    if phase<28:
        return metadata(s,o,w,phase)
    if phase<40:
        return objectives(s,o,w,phase)
    if phase<60:
        return sources(s,o,w,phase)
    if phase>=600 and phase<700:
        return capturing(s,o,w,phase)
    if phase>=800 and phase<900:
        return assembling(s,o,w,phase)
    if phase>=900 and phase<1000:
        return fields(s,o,w,phase)
    if phase>=1000 and phase<1100:
        return freezing(s,o,w,phase)
    if phase>=1100 and phase<1200:
        return scalar_copy(s,o,w,phase)
    if phase>=1200 and phase<1300:
        return verifying(s,o,w,phase)
    if phase>=1300 and phase<1400:
        return hashing(s,o,w,phase)
    if phase>=1500 and phase<1600:
        return converting(s,o,w,phase)
    if phase>=1700 and phase<1800:
        return errors(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return BAD
    i=16
    while i<128:
        used=word_load(s,8)==0 and i<112
        if used==False and word_load(s,i)!=0:
            return BAD
        i=i+8
    if get(w,0)!=CONTEXT or get(w,16)==0 or get(w,24)<256 or get(w,64)==0 or get(w,72)<256:
        return BAD
    if get(w,96)<3 or get(w,96)>2147483647 or get(w,104)==0 or get(w,112)!=10100891:
        return BAD
    if (get(w,80)!=0 and get(w,80)<640) or get(w,80)>2147483647 or get(w,184)>1:
        return BAD
    i=8
    while i<=168:
        if i!=24 and i!=72 and i!=80 and i!=96 and i!=112 and get(w,i)==0:
            return BAD
        i=i+8
    i=192
    while i<256:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,256,65280)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def entering(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,176)!=0 and get(w,176)!=pid):
            return finish(o,6)
        put(w,176,pid)
        if get(o,OP)==1:
            if get(w,184)==0:
                return finish(o,0)
            from_work(w,o,256,256,3840)
            put(w,184,0)
            put(o,QUAR,0)
            put(o,OP,1)
            return again(o,3000)
        if get(w,184)!=0:
            return finish(o,6)
        put(o,PID,pid)
        put(o,RETAIN_AT,0)
        return again(o,2)
    if phase==2:
        index=get(o,RETAIN_AT)
        if index==4:
            put(o,NESTEDN,262144)
            return mapping(o,4,262144)
        request(o,VREQUEST,5)
        copy_source(s,o,16+index*24,RQ+24,24)
        return value(o,w,3,128)
    if phase==3:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CMETA+get(o,RETAIN_AT)*24,RP+24,24)
        put(o,RETAIN_AT,get(o,RETAIN_AT)+1)
        return again(o,2)
    if phase==4:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,NESTED,raw)
        return field_get(o,CMETA,4,CFUNCTION,10,0)
    return fail(o,9,phase)

def metadata(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        return field_get(o,CMETA,28,CEPOCH,11,0)
    if phase==11:
        return field_get(o,CMETA,2,CBCORE,12,0)
    if phase==12:
        return field_get(o,CMETA,3,CBINPUT,13,0)
    if phase==13:
        request(o,VREQUEST,2)
        put(o,RQ+104,2)
        put(o,RQ+96,1)
        store(o,RQ+128,49)
        return value(o,w,14,129)
    if phase==14:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CONE,RP+24,24)
        request(o,VREQUEST,24)
        within(o,RQ+24,CEPOCH,24)
        within(o,RQ+48,CONE,24)
        return value(o,w,15,128)
    if phase==15:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CGEN,RP+24,24)
        return scalar_map(o,CFUNCTION,4,FN,16)
    if phase==16:
        return scalar_map(o,CGEN,2,GEN,17)
    if phase==17:
        return hash_text(o,w,CBCORE,18)
    if phase==18:
        if scalar_reply(o,64)==False or decode_hash(o,DHEAD+96)==False:
            return fail(o,7,18)
        return hash_text(o,w,CBINPUT,19)
    if phase==19:
        if scalar_reply(o,64)==False or decode_hash(o,DHEAD+128)==False:
            return fail(o,7,19)
        request(o,VREQUEST,7)
        within(o,RQ+24,CWALL,24)
        return value(o,w,20,128)
    if phase==20:
        if value_ok(o)==False or get(o,RP+16)!=2 or get(o,RP+72)==0 or get(o,RP+72)>20:
            return fail(o,7,20)
        put(o,SCHUNK,get(o,RP+72))
        request(o,VREQUEST,19)
        within(o,RQ+24,CWALL,24)
        put(o,RQ+112,get(o,SCHUNK))
        return value(o,w,21,128)
    if phase==21:
        if scalar_reply(o,get(o,SCHUNK))==False:
            return value_fail(o)
        n=get(o,SCHUNK)
        value=0
        i=0
        while i<n:
            ch=byte(o,RP+8192+i)
            if ch<48 or ch>57 or value>(MAX-(ch-48))//10:
                return fail(o,7,21)
            value=value*10+ch-48
            i=i+1
        put(o,WALL,value)
        return field_get(o,CINPUT,14,COBS,22,0)
    if phase==22:
        return freeze(o,COBS,POBS,23)
    if phase==23:
        return hash(o,get(o,POBS+32),get(o,POBS+24),DHEAD+160,24)
    if phase==24:
        return capture(o,0,25)
    if phase==25:
        return capture(o,1,26)
    if phase==26:
        return assemble(o,0,28)
    return fail(o,9,phase)

def objectives(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==28:
        if get(o,DOUT+8)!=0:
            return decision_error(o)
        if get(o,DOUT+64)!=1:
            return fail(o,7,28)
        return field_get(o,CRANK,7,CROBJ,29,1)
    if phase==29:
        return freeze(o,CROBJ,PROBJ,30)
    if phase==30:
        return field_get(o,CINPUT,7,CIOBJ,31,0)
    if phase==31:
        return freeze(o,CIOBJ,PIOBJ,32)
    if phase==32:
        request(o,VREQUEST,4)
        return value(o,w,33,128)
    if phase==33:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CBOUND,RP+24,24)
        request(o,VREQUEST,2)
        n=label(o,RQ+128,100)
        put(o,RQ+104,4)
        put(o,RQ+96,n)
        return value(o,w,34,128+n)
    if phase==34:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CSCHEMA,RP+24,24)
        put(o,BINDINDEX,0)
        return again(o,35)
    if phase==35:
        index=get(o,BINDINDEX)
        if index==5:
            return freeze(o,CBOUND,PBOUND,37)
        id=1
        cap=CSCHEMA
        if index==1:
            id=7
            cap=CIOBJ
        elif index==2:
            id=4
            cap=CFUNCTION
        elif index==3:
            id=2
            cap=CBCORE
        elif index==4:
            id=3
            cap=CBINPUT
        return field_set(o,CBOUND,id,cap,36)
    if phase==36:
        put(o,BINDINDEX,get(o,BINDINDEX)+1)
        return again(o,35)
    if phase==37:
        return hash(o,get(o,PBOUND+32),get(o,PBOUND+24),DHEAD+192,38)
    if phase==38:
        return assemble(o,1,39)
    if phase==39:
        if get(o,DOUT+8)!=0:
            return decision_error(o)
        if get(o,DOUT+64)==0:
            return again(o,3000)
        if get(o,DOUT+64)!=2:
            return fail(o,7,39)
        put(o,SELECTNODE,get(o,DOUT+120))
        return field_get(o,CINPUT,18,CCANDS,40,0)
    return fail(o,9,phase)

def sources(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        node=get(o,SELECTNODE)
        if node>=get(o,CAPTURES+48):
            return fail(o,7,40)
        return memory(o,41,0,get(o,CAPTURES+24)+64+node*72,3,HEAD,72)
    if phase==41:
        row=get(o,HEAD+8)
        if row>=get(o,CAPTURES+48):
            return fail(o,7,41)
        put(o,SELECTROW,row)
        return memory(o,42,0,get(o,CAPTURES+24)+64+row*72,3,HEAD,72)
    if phase==42:
        parent=get(o,HEAD+8)
        if parent>=get(o,CAPTURES+48):
            return fail(o,7,42)
        return memory(o,43,0,get(o,CAPTURES+24)+64+parent*72,3,HEAD,72)
    if phase==43:
        if get(o,HEAD)!=5:
            return fail(o,7,43)
        put(o,SELECTCUR,get(o,HEAD+24))
        put(o,SELECTINDEX,0)
        return again(o,44)
    if phase==44:
        if get(o,SELECTCUR)==get(o,SELECTROW):
            request(o,VREQUEST,2)
            put(o,RQ+104,2)
            n=decimal(o,RQ+128,get(o,SELECTINDEX))
            put(o,RQ+96,n)
            return value(o,w,46,128+n)
        node=get(o,SELECTCUR)
        if node>=get(o,CAPTURES+48):
            return fail(o,7,44)
        return memory(o,45,0,get(o,CAPTURES+24)+64+node*72,3,HEAD,72)
    if phase==45:
        put(o,SELECTCUR,get(o,HEAD+16))
        put(o,SELECTINDEX,get(o,SELECTINDEX)+1)
        return again(o,44)
    if phase==46:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CINDEX,RP+24,24)
        request(o,VREQUEST,12)
        within(o,RQ+24,CCANDS,24)
        within(o,RQ+48,CINDEX,24)
        return value(o,w,47,128)
    if phase==47:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CROW,RP+24,24)
        return field_get(o,CROW,20,CCAND,48,0)
    if phase==48:
        return verify(o,CCAND,PCAND,DHEAD+224,49)
    if phase==49:
        return field_get(o,CRANK,21,CRANKSRC,50,1)
    if phase==50:
        return verify(o,CRANKSRC,PRANK,DHEAD+256,51)
    if phase==51:
        return assemble(o,2,52)
    if phase==52:
        if get(o,DOUT+8)!=0:
            return decision_error(o)
        if get(o,DOUT+64)!=3:
            return fail(o,7,52)
        put(o,ADMITTED,1)
        within(o,CAND_CORE_SHA,DHEAD+224,32)
        return again(o,3000)
    return fail(o,9,phase)

def capture(o:mutbuf,index:u64,after:u64) -> u32:
    put(o,IOINDEX,index)
    put(o,IOAFTER,after)
    return again(o,600)
def capturing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    at=CAPTURES+get(o,IOINDEX)*96
    if phase==600:
        zero(w,10240,256)
        put(w,10240,ICONTEXT)
        put(w,10248,get(w,8))
        put(w,10256,get(w,16))
        put(w,10264,get(w,24))
        request(o,IREQUEST,0)
        within(o,RQ+24,choose(get(o,IOINDEX)==0,CINPUT,CRANK),24)
        put(o,IOACTIVE,2)
        return invoke(o,601,get(w,32),259,RQ,128,get(o,NESTED),262144,10240,256)
    if phase==601:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,602,0,get(o,NESTED),3,HEAD,128)
    if phase==602:
        if get(o,HEAD)!=IREPLY:
            return fail(o,7,602)
        if get(o,HEAD+48)!=0:
            put(o,IOACTIVE,1)
            return quarantine(o,w,602)
        put(o,IOACTIVE,0)
        if get(o,OP)==1:
            return again(o,3000)
        status=get(o,HEAD+8)
        if status!=0:
            return fail(o,choose(status==5,5,choose(status==8,8,7)),get(o,HEAD+40))
        fd=get(o,HEAD+16)
        if fd<3 or fd>2147483647 or get(o,HEAD+32)!=15 or get(o,HEAD+24)==0:
            return fail(o,7,603)
        put(o,at,fd+1)
        put(o,at+16,get(o,HEAD+24))
        return system(o,603,9,0,0,get(o,at+16),1,2,fd,0)
    if phase==603:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,at+8,raw)
        zero(o,SMALL,128)
        return invoke(o,604,get(w,40),816,raw,get(o,at+16),HEAD,64,SMALL,128)
    if phase==604:
        if get(o,FEEDBACK)!=0 or get(o,HEAD)!=SIZES or get(o,HEAD+48)!=get(o,at+16):
            return fail(o,7,604)
        put(o,at+40,get(o,HEAD+32))
        put(o,at+48,get(o,HEAD+8))
        put(o,at+56,get(o,HEAD+16))
        put(o,at+64,get(o,HEAD+24))
        wn=get(o,HEAD+40)
        if wn<131072:
            wn=131072
        put(o,at+80,wn)
        return mapping(o,605,get(o,at+40))
    if phase==605:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,at+24,raw)
        return mapping(o,606,get(o,at+80))
    if phase==606:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,at+72,raw)
        zero(o,SMALL,128)
        put(o,SMALL+48,get(o,at+48))
        put(o,SMALL+56,get(o,at+64))
        put(o,SMALL+96,get(o,at+56))
        put(o,SMALL+104,1)
        return memory(o,607,3,SMALL,0,raw,128)
    if phase==607:
        return invoke(o,608,get(w,40),0,get(o,at+8),get(o,at+16),get(o,at+24),get(o,at+40),get(o,at+72),get(o,at+80))
    if phase==608:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,609,0,get(o,at+24),3,HEAD,64)
    if phase==609:
        n=get(o,HEAD+24)
        if n<64 or n>get(o,at+40) or get(o,HEAD+8)==0 or get(o,HEAD+8)>get(o,at+48):
            return fail(o,7,609)
        put(o,at+32,n)
        put(o,at+48,get(o,HEAD+8))
        return again(o,get(o,IOAFTER))
    return fail(o,9,phase)

def assemble(o:mutbuf,stage:u64,after:u64) -> u32:
    put(o,DSTAGE,stage)
    put(o,DAFTER,after)
    return again(o,800)
def assembling(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==800:
        if get(o,DFRAME)!=0:
            return system(o,801,11,0,get(o,DFRAME),get(o,DFRAMEN),0,0,0,0)
        return again(o,802)
    if phase==801:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,get(o,FEEDBACK))
        zero(o,DFRAME,16)
        return again(o,802)
    if phase==802:
        put(o,DHEAD,DREQUEST)
        put(o,DHEAD+8,get(o,DSTAGE))
        put(o,DHEAD+16,get(o,CAPTURES+16))
        put(o,DHEAD+24,get(o,CAPTURES+32))
        put(o,DHEAD+32,get(o,CAPTURES+96+16))
        put(o,DHEAD+40,get(o,CAPTURES+96+32))
        put(o,DHEAD+48,get(o,FNN))
        put(o,DHEAD+56,get(o,GENN))
        put(o,DHEAD+64,choose(get(o,DSTAGE)==0,0,get(o,PROBJ+24)))
        put(o,DHEAD+72,choose(get(o,DSTAGE)==0,0,get(o,PIOBJ+24)))
        put(o,DHEAD+80,get(o,WALL))
        n=512
        i=16
        while i<=72:
            next=get(o,DHEAD+i)
            if next>MAX-n:
                return fail(o,5,802)
            n=n+next
            i=i+8
        put(o,DFRAMEN,n)
        return mapping(o,803,n)
    if phase==803:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,DFRAME,raw)
        put(o,DCOPY,0)
        put(o,DAT,0)
        return again(o,804)
    if phase==804:
        index=get(o,DCOPY)
        if index==9:
            if get(o,DWORK)==0:
                wn=131072
                if get(o,CAPTURES+48)>wn:
                    wn=get(o,CAPTURES+48)
                if get(o,CAPTURES+144)>wn:
                    wn=get(o,CAPTURES+144)
                put(o,DWORKN,wn)
                return mapping(o,806,wn)
            return again(o,807)
        ptr=DHEAD
        n=512
        base=3
        if index>0:
            base=0
            n=get(o,DHEAD+8+index*8)
        if index==1:
            ptr=get(o,CAPTURES+8)
        elif index==2:
            ptr=get(o,CAPTURES+24)
        elif index==3:
            ptr=get(o,CAPTURES+104)
        elif index==4:
            ptr=get(o,CAPTURES+120)
        elif index==5:
            ptr=get(o,FN)
        elif index==6:
            ptr=get(o,GEN)
        elif index==7:
            ptr=get(o,PROBJ+32)
        elif index==8:
            ptr=get(o,PIOBJ+32)
        put(o,SCHUNK,n)
        return memory(o,805,base,ptr,0,get(o,DFRAME)+get(o,DAT),n)
    if phase==805:
        put(o,DAT,get(o,DAT)+get(o,SCHUNK))
        put(o,DCOPY,get(o,DCOPY)+1)
        return again(o,804)
    if phase==806:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,DWORK,raw)
        return again(o,807)
    if phase==807:
        if get(o,DAT)!=get(o,DFRAMEN):
            return fail(o,9,807)
        return invoke(o,808,get(w,152),48,get(o,DFRAME),get(o,DFRAMEN),DOUT,256,get(o,DWORK),get(o,DWORKN))
    if phase==808:
        if get(o,FEEDBACK)!=0 or get(o,DOUT)!=DREPLY or get(o,DOUT+16)!=get(o,DSTAGE):
            return fail(o,7,get(o,FEEDBACK))
        return again(o,get(o,DAFTER))
    return fail(o,9,phase)

def field_get(o:mutbuf,root:u64,id:u64,dest:u64,after:u64,none:u64) -> u32:
    put(o,GCROOT,root)
    put(o,GCID,id)
    put(o,GCDEST,dest)
    put(o,GCAFTER,after)
    put(o,GCNONE,none)
    put(o,GCSET,0)
    return again(o,900)
def field_set(o:mutbuf,root:u64,id:u64,cap:u64,after:u64) -> u32:
    put(o,GCROOT,root)
    put(o,GCID,id)
    put(o,GCVALUE,cap)
    put(o,GCAFTER,after)
    put(o,GCSET,1)
    return again(o,900)
def fields(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,CKEY)!=0:
            return fail(o,9,900)
        request(o,VREQUEST,2)
        n=label(o,RQ+128,get(o,GCID))
        if n==0:
            return fail(o,9,901)
        put(o,RQ+104,4)
        put(o,RQ+96,n)
        return value(o,w,901,128+n)
    if phase==901:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CKEY,RP+24,24)
        request(o,VREQUEST,choose(get(o,GCSET)==0,9,10))
        within(o,RQ+24,get(o,GCROOT),24)
        within(o,RQ+48,CKEY,24)
        if get(o,GCSET)!=0:
            within(o,RQ+72,get(o,GCVALUE),24)
        return value(o,w,902,128)
    if phase==902:
        if value_ok(o)==False:
            if get(o,FEEDBACK)==0 and get(o,RP)==VREPLY and get(o,RP+8)==3 and get(o,GCSET)==0:
                if get(o,GCNONE)!=0:
                    request(o,VREQUEST,2)
                    return value(o,w,903,128)
                put(o,ERRID,200+get(o,GCID))
                return again(o,1700)
            return value_fail(o)
        if get(o,GCSET)==0:
            if get(o,get(o,GCDEST))!=0:
                return fail(o,9,902)
            within(o,get(o,GCDEST),RP+24,24)
        return again(o,904)
    if phase==903:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,get(o,GCDEST),RP+24,24)
        return again(o,904)
    if phase==904:
        request(o,VREQUEST,6)
        within(o,RQ+24,CKEY,24)
        return value(o,w,905,128)
    if phase==905:
        if value_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,CKEY,24)
        return again(o,get(o,GCAFTER))
    return fail(o,9,phase)

def freeze(o:mutbuf,cap:u64,pay:u64,after:u64) -> u32:
    put(o,FZCAP,cap)
    put(o,FZPAY,pay)
    put(o,FZAFTER,after)
    return again(o,1000)
def freezing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        zero(w,4096,2048)
        put(w,4096,FCONTEXT)
        i=8
        while i<88:
            put(w,4096+i,get(w,i))
            i=i+8
        request(o,FREQUEST,0)
        within(o,RQ+24,get(o,FZCAP),24)
        put(o,FZACTIVE,2)
        return invoke(o,1001,get(w,144),259,RQ,128,get(o,NESTED),262144,4096,2048)
    if phase==1001:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,1002,0,get(o,NESTED),3,HEAD,128)
    if phase==1002:
        if get(o,HEAD)!=FREPLY:
            return fail(o,7,1002)
        if get(o,HEAD+56)!=0 or get(w,4192)!=0:
            put(o,FZACTIVE,1)
            return quarantine(o,w,1002)
        put(o,FZACTIVE,0)
        status=get(o,HEAD+8)
        if get(o,OP)==1:
            if status==0 and get(o,HEAD+16)!=0:
                within(o,get(o,FZPAY),HEAD+16,24)
                put(o,get(o,FZPAY)+24,get(o,HEAD+40))
            return again(o,3000)
        if status==1:
            if get(o,ERRCONVERT)!=0:
                return fail(o,7,1003)
            n=get(o,HEAD+48)
            if n==0 or n>896:
                return fail(o,7,1004)
            put(o,ERRN,n)
            put(o,UCHAR,get(o,HEAD+72))
            put(o,USTART,get(o,HEAD+80))
            put(o,UEND,get(o,HEAD+88))
            put(o,UCP,get(o,HEAD+96))
            return memory(o,1500,0,get(o,NESTED)+128,3,ERRBUF,n)
        if status!=0:
            return fail(o,status,get(o,HEAD+64))
        within(o,get(o,FZPAY),HEAD+16,24)
        put(o,get(o,FZPAY)+24,get(o,HEAD+40))
        request(o,BREQUEST,6)
        within(o,RQ+24,get(o,FZPAY),24)
        return payload(o,w,1003)
    if phase==1003:
        if payload_ok(o)==False or get(o,RP+40)!=get(o,get(o,FZPAY)+24):
            return payload_fail(o)
        put(o,get(o,FZPAY)+32,get(o,RP+64))
        return again(o,get(o,FZAFTER))
    return fail(o,9,phase)

def scalar_map(o:mutbuf,cap:u64,kind:u64,map:u64,after:u64) -> u32:
    put(o,SCAP,cap)
    put(o,SKIND,kind)
    put(o,SMAP,map)
    put(o,SAFTER,after)
    return again(o,1100)
def scalar_copy(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1100:
        request(o,VREQUEST,7)
        within(o,RQ+24,get(o,SCAP),24)
        return value(o,w,1101,128)
    if phase==1101:
        if value_ok(o)==False:
            return value_fail(o)
        if get(o,RP+16)!=get(o,SKIND) or get(o,RP+72)==0:
            return fail(o,7,1101)
        put(o,get(o,SMAP)+8,get(o,RP+72))
        put(o,SCURSOR,0)
        return mapping(o,1102,get(o,RP+72))
    if phase==1102:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,get(o,SMAP),raw)
        return again(o,1103)
    if phase==1103:
        left=get(o,get(o,SMAP)+8)-get(o,SCURSOR)
        if left==0:
            return again(o,get(o,SAFTER))
        n=choose(left>16384,16384,left)
        put(o,SCHUNK,n)
        request(o,VREQUEST,19)
        within(o,RQ+24,get(o,SCAP),24)
        put(o,RQ+104,get(o,SCURSOR))
        put(o,RQ+112,n)
        return value(o,w,1104,128)
    if phase==1104:
        if scalar_reply(o,get(o,SCHUNK))==False:
            return value_fail(o)
        return memory(o,1105,3,RP+8192,0,get(o,get(o,SMAP))+get(o,SCURSOR),get(o,SCHUNK))
    if phase==1105:
        put(o,SCURSOR,get(o,SCURSOR)+get(o,SCHUNK))
        return again(o,1103)
    return fail(o,9,phase)

def verify(o:mutbuf,cap:u64,pay:u64,digest:u64,after:u64) -> u32:
    put(o,VCAP,cap)
    put(o,VPAY,pay)
    put(o,VDIGEST,digest)
    put(o,VAFTER,after)
    return again(o,1200)
def verifying(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1200:
        zero(w,6144,4096)
        put(w,6144,YCONTEXT)
        i=8
        while i<88:
            put(w,6144+i,get(w,i))
            i=i+8
        put(w,6232,get(w,96))
        put(w,6240,get(w,104))
        put(w,6248,get(w,112))
        put(w,6256,get(w,120))
        put(w,6264,get(w,144))
        put(w,6272,get(w,128))
        put(w,6280,get(w,136))
        request(o,YREQUEST,0)
        within(o,RQ+24,get(o,VCAP),24)
        put(o,VERIFYACTIVE,2)
        return invoke(o,1201,get(w,88),259,RQ,128,get(o,NESTED),262144,6144,4096)
    if phase==1201:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,1202,0,get(o,NESTED),3,HEAD,128)
    if phase==1202:
        if get(o,HEAD)!=YREPLY:
            return fail(o,7,1202)
        if get(o,HEAD+56)!=0 or get(w,6296)!=0:
            put(o,VERIFYACTIVE,1)
            return quarantine(o,w,1202)
        put(o,VERIFYACTIVE,0)
        status=get(o,HEAD+8)
        if status<=2 and get(o,HEAD+16)!=0:
            dest=choose(status==0,get(o,VPAY),PERROR)
            within(o,dest,HEAD+16,24)
            put(o,dest+24,get(o,HEAD+40))
        if get(o,OP)==1:
            return again(o,3000)
        if status==1:
            put(o,ERRCONVERT,2)
            request(o,BREQUEST,6)
            within(o,RQ+24,PERROR,24)
            return payload(o,w,1250)
        if status==2:
            put(o,ERROR,1)
            put(o,ERFORMAT,2)
            return again(o,3000)
        if status!=0:
            return fail(o,status,get(o,HEAD+48))
        request(o,BREQUEST,6)
        within(o,RQ+24,get(o,VPAY),24)
        return payload(o,w,1203)
    if phase==1203:
        if payload_ok(o)==False or get(o,RP+40)!=get(o,get(o,VPAY)+24):
            return payload_fail(o)
        put(o,get(o,VPAY)+32,get(o,RP+64))
        return memory(o,1204,0,get(o,RP+64),3,HEAD,64)
    if phase==1204:
        n=get(o,HEAD+32)
        core=get(o,HEAD+40)
        if get(o,HEAD)!=NORM or get(o,HEAD+8)!=0 or get(o,HEAD+24)>4 or n==0 or n>8388608 or core==0 or core>8388608:
            return fail(o,7,1204)
        if 64+n+core!=get(o,get(o,VPAY)+24):
            return fail(o,7,1205)
        put(o,VSTEP,n)
        return hash(o,get(o,get(o,VPAY)+32)+64+n,core,get(o,VDIGEST),1205)
    if phase==1205:
        if get(o,VPAY)==PCAND:
            return hash(o,get(o,PCAND+32)+64,get(o,VSTEP),CAND_INPUT_SHA,1206)
        return again(o,get(o,VAFTER))
    if phase==1206:
        return again(o,get(o,VAFTER))
    if phase==1250:
        if payload_ok(o)==False or get(o,RP+40)!=get(o,PERROR+24):
            return payload_fail(o)
        n=get(o,RP+40)
        if n>MAX-128:
            return fail(o,5,1250)
        put(o,RPTR,get(o,RP+64))
        put(o,EFRAMEN,128+n)
        return mapping(o,1251,get(o,EFRAMEN))
    if phase==1251:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,EFRAME,raw)
        request(o,VREQUEST,1)
        put(o,RQ+96,get(o,PERROR+24))
        return memory(o,1252,3,RQ,0,raw,128)
    if phase==1252:
        return memory(o,1253,0,get(o,RPTR),0,get(o,EFRAME)+128,get(o,PERROR+24))
    if phase==1253:
        return invoke(o,1254,get(w,8),48,get(o,EFRAME),get(o,EFRAMEN),RP,32768,get(w,16),get(w,24))
    if phase==1254:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CERROR,RP+24,24)
        return field_get(o,CERROR,36,CERRDIAGS,1255,0)
    if phase==1255:
        request(o,VREQUEST,2)
        put(o,RQ+104,2)
        put(o,RQ+96,1)
        store(o,RQ+128,48)
        return value(o,w,1256,129)
    if phase==1256:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CZERO,RP+24,24)
        request(o,VREQUEST,12)
        within(o,RQ+24,CERRDIAGS,24)
        within(o,RQ+48,CZERO,24)
        return value(o,w,1257,128)
    if phase==1257:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CFIRST,RP+24,24)
        return field_get(o,CFIRST,31,CMESSAGE,1258,0)
    if phase==1258:
        request(o,VREQUEST,2)
        n=label(o,RQ+128,37)
        put(o,RQ+104,4)
        put(o,RQ+96,n)
        return value(o,w,1259,128+n)
    if phase==1259:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CTYPE,RP+24,24)
        request(o,VREQUEST,7)
        within(o,RQ+24,CMESSAGE,24)
        return value(o,w,1260,128)
    if phase==1260:
        if value_ok(o)==False or get(o,RP+16)!=4:
            return fail(o,7,1260)
        n=choose(get(o,RP+72)>64,64,get(o,RP+72))
        put(o,SCHUNK,n)
        request(o,VREQUEST,19)
        within(o,RQ+24,CMESSAGE,24)
        put(o,RQ+112,n)
        return value(o,w,1261,128)
    if phase==1261:
        if scalar_reply(o,get(o,SCHUNK))==False:
            return value_fail(o)
        i=0
        while i<get(o,SCHUNK) and byte(o,RP+8192+i)!=58:
            ch=byte(o,RP+8192+i)
            if ch!=95 and (ch<65 or ch>90):
                return fail(o,7,1261)
            i=i+1
        if i<6 or i+1>=get(o,SCHUNK) or byte(o,RP+8192+i+1)!=32:
            return fail(o,7,1262)
        request(o,VREQUEST,2)
        put(o,RQ+104,4)
        put(o,RQ+96,i)
        within(o,RQ+128,RP+8192,i)
        return value(o,w,1262,128+i)
    if phase==1262:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CCODE,RP+24,24)
        return again(o,1503)
    return fail(o,9,phase)

def hash(o:mutbuf,ptr:u64,n:u64,dest:u64,after:u64) -> u32:
    put(o,HPTR,ptr)
    put(o,HN,n)
    put(o,HDST,dest)
    put(o,HAFTER,after)
    put(o,HCURSOR,0)
    return again(o,1300)
def hashing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1300:
        store(o,HBUF,0)
        return invoke(o,1301,get(w,160),307,HBUF,1,HEAD,32,11264,1184)
    if phase==1301:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return again(o,1302)
    if phase==1302:
        left=get(o,HN)-get(o,HCURSOR)
        if left==0:
            store(o,HBUF,2)
            return invoke(o,1305,get(w,160),307,HBUF,1,HEAD,32,11264,1184)
        n=choose(left>65536,65536,left)
        put(o,HCHUNK,n)
        store(o,HBUF,1)
        return memory(o,1303,0,get(o,HPTR)+get(o,HCURSOR),3,HBUF+1,n)
    if phase==1303:
        return invoke(o,1304,get(w,160),307,HBUF,1+get(o,HCHUNK),HEAD,32,11264,1184)
    if phase==1304:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        put(o,HCURSOR,get(o,HCURSOR)+get(o,HCHUNK))
        return again(o,1302)
    if phase==1305:
        if get(o,FEEDBACK)!=32:
            return fail(o,7,get(o,FEEDBACK))
        within(o,get(o,HDST),HEAD,32)
        return again(o,get(o,HAFTER))
    return fail(o,9,phase)

def converting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1500:
        put(o,ERRCONVERT,1)
        request(o,VREQUEST,1)
        put(o,RQ+96,get(o,ERRN))
        within(o,RQ+128,ERRBUF,get(o,ERRN))
        return value(o,w,1501,128+get(o,ERRN))
    if phase==1501:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CERROR,RP+24,24)
        return field_get(o,CERROR,29,CTYPE,1502,0)
    if phase==1502:
        return field_get(o,CERROR,31,CMESSAGE,1503,0)
    if phase==1503:
        request(o,VREQUEST,4)
        return value(o,w,1504,128)
    if phase==1504:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CTYPED,RP+24,24)
        return field_set(o,CTYPED,30,CTYPE,1505)
    if phase==1505:
        return field_set(o,CTYPED,31,CMESSAGE,1506)
    if phase==1506:
        put(o,ERRINDEX,0)
        if get(o,ERRCONVERT)==2:
            return field_set(o,CTYPED,38,CCODE,1507)
        return again(o,1510)
    if phase==1507:
        request(o,BREQUEST,3)
        within(o,RQ+24,PERROR,24)
        return payload(o,w,1508)
    if phase==1508:
        if payload_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,PERROR,48)
        return again(o,1510)
    if phase==1510:
        index=get(o,ERRINDEX)
        if index==4 or get(o,UCHAR)==0:
            return freeze(o,CTYPED,PERROR,1514)
        value=get(o,UCHAR+index*8)
        request(o,VREQUEST,2)
        put(o,RQ+104,2)
        n=decimal(o,RQ+128,value)
        put(o,RQ+96,n)
        return value_call(o,w,1511,128+n)
    if phase==1511:
        if value_ok(o)==False:
            return value_fail(o)
        within(o,CNUM,RP+24,24)
        return field_set(o,CTYPED,32+get(o,ERRINDEX),CNUM,1512)
    if phase==1512:
        request(o,VREQUEST,6)
        within(o,RQ+24,CNUM,24)
        return value(o,w,1513,128)
    if phase==1513:
        if value_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,CNUM,24)
        put(o,ERRINDEX,get(o,ERRINDEX)+1)
        return again(o,1510)
    if phase==1514:
        put(o,ERROR,1)
        put(o,ERFORMAT,2)
        return again(o,3000)
    return fail(o,9,phase)

def decision_error(o:mutbuf) -> u32:
    put(o,ERRID,get(o,DOUT+24))
    return again(o,1700)
def errors(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1700:
        code=get(o,ERRID)
        n=error_text(o,code)
        if n!=0:
            put(o,ERRN,n)
            return again(o,1750)
        if code==299:
            which=get(o,DOUT+32)
            node=get(o,DOUT+40)
            if which>1 or node>=get(o,CAPTURES+which*96+48):
                return fail(o,7,1700)
            put(o,RRAW,get(o,CAPTURES+which*96+24))
            return memory(o,1701,0,get(o,RRAW)+64+node*72,3,HEAD,72)
        if code>=200 and code<299:
            n=label(o,ERRBUF,code-200)
            if n==0:
                return fail(o,7,1701)
            put(o,RPTR,ERRBUF)
            put(o,RN,n)
            put(o,RKIND,3)
            return again(o,1702)
        return fail(o,7,code)
    if phase==1701:
        if get(o,HEAD)!=4:
            return fail(o,7,1702)
        put(o,RPTR,get(o,RRAW)+get(o,HEAD+24))
        put(o,RN,get(o,HEAD+32))
        put(o,RKIND,0)
        return again(o,1702)
    if phase==1702:
        if get(o,RN)>MAX-64:
            return fail(o,5,1702)
        put(o,EFRAMEN,64+get(o,RN))
        return mapping(o,1703,get(o,EFRAMEN))
    if phase==1703:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,EFRAME,raw)
        zero(o,HEAD,64)
        put(o,HEAD,RREQUEST)
        put(o,HEAD+16,1)
        put(o,HEAD+24,get(o,RN))
        return memory(o,1704,3,HEAD,0,raw,64)
    if phase==1704:
        return memory(o,1705,get(o,RKIND),get(o,RPTR),0,get(o,EFRAME)+64,get(o,RN))
    if phase==1705:
        return invoke(o,1706,get(w,168),48,get(o,EFRAME),get(o,EFRAMEN),HEAD,64,get(o,NESTED),262144)
    if phase==1706:
        if get(o,FEEDBACK)!=0 or get(o,HEAD)!=RREPLY or get(o,HEAD+16)>MAX-256:
            return fail(o,7,1706)
        put(o,ERRN,get(o,HEAD+16))
        put(o,EOUTN,256+get(o,ERRN))
        return mapping(o,1707,get(o,EOUTN))
    if phase==1707:
        raw=get(o,FEEDBACK)
        if bad_pointer(raw):
            return fail(o,5,raw)
        put(o,EOUT,raw)
        put(o,HEAD,1)
        return memory(o,1708,3,HEAD,0,get(o,EFRAME)+8,8)
    if phase==1708:
        return invoke(o,1709,get(w,168),0,get(o,EFRAME),get(o,EFRAMEN),get(o,EOUT)+128,get(o,EOUTN)-128,get(o,NESTED),262144)
    if phase==1709:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        n=keyerror_prefix(o)
        put(o,RPREFIX,n)
        return memory(o,1710,3,ERRBUF,0,get(o,EOUT)+192-n,n)
    if phase==1710:
        store(o,SMALL,125)
        return memory(o,1711,3,SMALL,0,get(o,EOUT)+192+get(o,ERRN),1)
    if phase==1711:
        n=get(o,RPREFIX)+get(o,ERRN)+1
        request(o,BREQUEST,1)
        put(o,RQ+72,n)
        put(o,ERRN,n)
        return memory(o,1712,3,RQ,0,get(o,EOUT)+64-get(o,RPREFIX),128)
    if phase==1712:
        return invoke(o,1751,get(w,56),48,get(o,EOUT)+64-get(o,RPREFIX),128+get(o,ERRN),RP,512,get(w,64),get(w,72))
    if phase==1750:
        zero(o,ERRBUF-128,128)
        put(o,ERRBUF-128,BREQUEST)
        put(o,ERRBUF-120,1)
        put(o,ERRBUF-56,get(o,ERRN))
        return invoke(o,1751,get(w,56),51,ERRBUF-128,128+get(o,ERRN),RP,512,get(w,64),get(w,72))
    if phase==1751:
        if payload_ok(o)==False:
            return payload_fail(o)
        within(o,PERROR,RP+16,24)
        put(o,PERROR+24,get(o,RP+40))
        put(o,ERROR,1)
        put(o,ERFORMAT,2)
        return again(o,3000)
    return fail(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3000:
        if get(o,IOACTIVE)!=0:
            if get(o,OP)!=1 or get(o,IOACTIVE)!=1:
                return quarantine(o,w,3000)
            request(o,IREQUEST,1)
            return invoke(o,601,get(w,32),259,RQ,128,get(o,NESTED),262144,10240,256)
        if get(o,FZACTIVE)!=0:
            if get(o,OP)!=1 or get(o,FZACTIVE)!=1:
                return quarantine(o,w,3001)
            request(o,FREQUEST,1)
            return invoke(o,1001,get(w,144),259,RQ,128,get(o,NESTED),262144,4096,2048)
        if get(o,VERIFYACTIVE)!=0:
            if get(o,OP)!=1 or get(o,VERIFYACTIVE)!=1:
                return quarantine(o,w,3002)
            request(o,YREQUEST,1)
            return invoke(o,1201,get(w,88),259,RQ,128,get(o,NESTED),262144,6144,4096)
        put(o,CLEAN,0)
        return again(o,3010)
    if phase==3010:
        index=get(o,CLEAN)
        if index==32:
            put(o,CLEAN,0)
            return again(o,3020)
        at=CMETA+index*24
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,3010)
        put(o,DESTROY_AT,at)
        request(o,VREQUEST,6)
        within(o,RQ+24,at,24)
        return value(o,w,3011,128)
    if phase==3011:
        if value_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,get(o,DESTROY_AT),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3010)
    if phase==3020:
        index=get(o,CLEAN)
        if index==7:
            put(o,CLEAN,0)
            return again(o,3030)
        at=POBS+index*48
        keep=(at==PCAND and get(o,ERROR)==0 and get(o,ADMITTED)!=0) or (at==PERROR and get(o,ERROR)==1)
        if keep or get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,3020)
        put(o,DESTROY_AT,at)
        request(o,BREQUEST,3)
        within(o,RQ+24,at,24)
        return payload(o,w,3021)
    if phase==3021:
        if payload_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,get(o,DESTROY_AT),48)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3020)
    if phase==3030:
        index=get(o,CLEAN)
        if index==2:
            put(o,CLEAN,0)
            return again(o,3040)
        at=CAPTURES+index*96
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,3030)
        fd=get(o,at)-1
        put(o,at,0)
        return system(o,3031,3,0,fd,0,0,0,0,0)
    if phase==3031:
        if get(o,FEEDBACK)!=0:
            put(o,ERROR,8)
            put(o,DETAIL,get(o,FEEDBACK))
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3030)
    if phase==3040:
        index=get(o,CLEAN)
        if index==13:
            if (get(o,ERROR)!=0 and get(o,PCAND)!=0) or (get(o,ERROR)!=1 and get(o,PERROR)!=0):
                return again(o,3000)
            return finish(o,get(o,ERROR))
        at=NESTED
        size_at=NESTEDN
        if index<6:
            a=CAPTURES+(index//3)*96
            part=index%3
            at=a+8
            size_at=a+16
            if part==1:
                at=a+24
                size_at=a+40
            elif part==2:
                at=a+72
                size_at=a+80
        elif index==6:
            at=FN
            size_at=FNN
        elif index==7:
            at=GEN
            size_at=GENN
        elif index==8:
            at=DFRAME
            size_at=DFRAMEN
        elif index==9:
            at=DWORK
            size_at=DWORKN
        elif index==10:
            at=EFRAME
            size_at=EFRAMEN
        elif index==11:
            at=EOUT
            size_at=EOUTN
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,3040)
        put(o,DESTROY_AT,at)
        put(o,DESTROY_KIND,size_at)
        return system(o,3041,11,0,get(o,at),get(o,size_at),0,0,0,0)
    if phase==3041:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,get(o,FEEDBACK))
        put(o,get(o,DESTROY_AT),0)
        put(o,get(o,DESTROY_KIND),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3040)
    return fail(o,9,phase)

def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,256)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0:
        put(o,16,get(o,ADMITTED))
        if get(o,ADMITTED)!=0:
            within(o,24,PCAND,24)
            put(o,48,get(o,PCAND+24))
            within(o,128,CAND_CORE_SHA,32)
            within(o,160,CAND_INPUT_SHA,32)
            zero(o,PCAND,48)
    elif status==1:
        within(o,56,PERROR,24)
        put(o,80,get(o,PERROR+24))
        put(o,104,get(o,ERFORMAT))
        zero(o,PERROR,48)
    put(o,88,get(o,QUAR))
    put(o,96,get(o,DETAIL))
    return 0
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,DETAIL,detail)
    if get(o,ERROR)==0 and get(o,ADMITTED)==0:
        put(o,ERROR,9)
    to_work(o,w,256,256,3840)
    put(w,184,1)
    put(o,QUAR,1)
    return finish(o,9)
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,3000)
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,32768,get(w,16),get(w,24))
def value_call(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return value(o,w,next,n)
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,56),51,RQ,128,RP,512,get(w,64),get(w,72))
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VREPLY and get(o,RP+8)==0
def payload_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==BREPLY and get(o,RP+8)==0
def value_fail(o:mutbuf) -> u32:
    return fail(o,choose(get(o,RP+8)==5,5,6),get(o,RP+8))
def payload_fail(o:mutbuf) -> u32:
    return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
def scalar_reply(o:mutbuf,n:u64) -> bool:
    return value_ok(o) and get(o,RP+64)==n
def hash_text(o:mutbuf,w:mutbuf,cap:u64,next:u64) -> u32:
    request(o,VREQUEST,19)
    within(o,RQ+24,cap,24)
    put(o,RQ+112,64)
    return value(o,w,next,128)
def decode_hash(o:mutbuf,to:u64) -> bool:
    if get(o,RP+72)!=64 or get(o,RP+16)!=4:
        return False
    i=0
    while i<32:
        a=unhex(byte(o,RP+8192+i*2))
        b=unhex(byte(o,RP+8192+i*2+1))
        if a==MAX or b==MAX:
            return False
        store(o,to+i,a*16+b)
        i=i+1
    return True
def unhex(ch:u64) -> u64:
    if ch>=48 and ch<=57:
        return ch-48
    if ch>=97 and ch<=102:
        return ch-87
    return MAX
def decimal(o:mutbuf,at:u64,n:u64) -> u64:
    size=0
    while n!=0 or size==0:
        store(o,SMALL+size,48+n%10)
        n=n//10
        size=size+1
    i=0
    while i<size:
        store(o,at+i,byte(o,SMALL+size-1-i))
        i=i+1
    return size
def bad_pointer(n:u64) -> bool:
    return n==0 or n>=NEGATIVE
'''
def source_program():
    names={'mapping','request','invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'}
    helpers='\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    text=SOURCE+'\n'+helpers
    labels={**LABELS,28:"epoch",29:"type",30:"class",31:"message",32:"unicode_character_count",33:"unicode_start",34:"unicode_end",35:"unicode_codepoint",36:"diagnostics",37:"HIAProgramRejected",38:"code"}
    text+='\ndef label(o:mutbuf,at:u64,id:u64) -> u64:\n'
    for id,label in sorted(labels.items()):
        raw=label.encode();text+='    if id=='+str(id)+':\n'
        for i in range(0,len(raw),8):text+=f'        put(o,at+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        text+='        return '+str(len(raw))+'\n'
    text+='    return 0\n'
    groups=[list(sorted(ERRORS.items()))[i:i+8] for i in range(0,len(ERRORS),8)]
    text+='\ndef error_text(o:mutbuf,code:u64) -> u64:\n'
    for i in range(len(groups)):
        text+=f'    n=error_text_{i}(o,code)\n    if n!=0:\n        return n\n'
    text+='    return 0\n'
    for group_index,group in enumerate(groups):
        text+=f'\ndef error_text_{group_index}(o:mutbuf,code:u64) -> u64:\n'
        for code,(kind,message) in group:
            raw=json.dumps({"class":kind,"message":message},ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()
            text+='    if code=='+str(code)+':\n'
            for i in range(0,len(raw),8):text+=f'        put(o,ERRBUF+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
            text+='        return '+str(len(raw))+'\n'
        text+='    return 0\n'
    raw=b'{"class":"KeyError","message":'
    text+='\ndef keyerror_prefix(o:mutbuf) -> u64:\n'
    for i in range(0,len(raw),8):text+=f'    put(o,ERRBUF+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
    text+='    return '+str(len(raw))+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_decision_owner')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_decision_owner.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),max(len(f['blocks'])for f in d['functions']),flush=True)
if __name__=='__main__':main()
