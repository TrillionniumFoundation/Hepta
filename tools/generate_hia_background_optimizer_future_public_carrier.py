"""Native typed callback closures and exact Future identity handoff."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={"MAGIC":int.from_bytes("HIAPFC01".encode(),'little'),
"REPLY":int.from_bytes("HIAPFCR1".encode(),'little'),
"STATE":int.from_bytes("HIABFPS1".encode(),'little'),
"FOBJECT":int.from_bytes("HIABFPO1".encode(),'little'),
"OBJECT":int.from_bytes("HIABFPC1".encode(),'little'),
"FMAGIC":int.from_bytes("HIABFPA1".encode(),'little'),
"FREQUEST":int.from_bytes("HIABFQ01".encode(),'little'),
"FREQUEST2":int.from_bytes("HIABFQ02".encode(),'little'),
"FREPLY":int.from_bytes("HIABFR01".encode(),'little'),
"VREQUEST":int.from_bytes("HIABVQ01".encode(),'little'),
"VREPLY":int.from_bytes("HIABVR01".encode(),'little'),
"VREQUEST2":int.from_bytes(b"HIABVQ02",'little'),
"VREPLY2":int.from_bytes(b"HIABVR02",'little'),
"KREQUEST":int.from_bytes("HIAMVFQ1".encode(),'little'),
"KREPLY":int.from_bytes("HIAMVFR1".encode(),'little'),
"CBREQUEST":int.from_bytes("HIAFCBQ1".encode(),'little'),
"CBREPLY":int.from_bytes("HIAFCBR1".encode(),'little'),
"LREQUEST":int.from_bytes("HIAFPL01".encode(),'little'),
"LREPLY":int.from_bytes("HIAFPLR1".encode(),'little'),
"MAX":(1<<64)-1,
"NEGATIVE":(1<<64)-4095,
"PHASE":128,
"OP":136,
"ERROR":144,
"CLASS":152,
"PID":160,
"TID":168,
"HELD":176,
"AFTER":184,
"F":192,
"CARRIER":200,
"CURSOR":208,
"FRAMEPTR":216,
"NEWC":224,
"REGISTERED":232,
"CALLBACK_RC":240,
"ENV_TEMP":272,
"FUTURE_TEMP":296,
"RETURN_TEMP":320,
"WPTR":344,
"KERNEL":352,
"THROW_KIND":360,
"THROW_CLASS":368,
"USER_KIND":376,
"FREEPTR":384,
"VD_CONSUMED":392,
"VD_PENDING":400,
"VD_STATUS":408,
"FEEDBACK":448,
"TEMP":456,
"RANDOM_USED":464,
"GMAGIC":int.from_bytes(b"HIABFC01",'little'),"GREPLY":int.from_bytes(b"HIABFCR1",'little'),
"GOBJECT":int.from_bytes(b"HIABFCT1",'little'),"GCOUNT":16,
"GCAP":512,"GPTR":536,"GBAD":544,"GNEXT":552,"GKIND":560,
"GKEEP":568,"GSTATUS":576,"GLOST":584,"GSCAN":608,"FACTORY_ID":632,
"GSHADOW":2304,"GREQUEST":2816,"GOUTPUT":3072,"GNODE":3200,
"RANDOM":704,
"FHEADER":1024,
"CHEADER":1280,
"FRAME":1536,
"RQ":2048,
"VP":4096,
"FP":16384,
"OUT":32768}
C.update(MAGIC2=int.from_bytes(b'HIAPFC02','little'),FREQUEST5=int.from_bytes(b'HIABFQ05','little'),
 FREQUEST6=int.from_bytes(b'HIABFQ06','little'),FREPLY3=int.from_bytes(b'HIABFR03','little'),
 VREQUEST5=int.from_bytes(b'HIABVQ05','little'),VREQUEST6=int.from_bytes(b'HIABVQ06','little'),
 GMAGIC2=int.from_bytes(b'HIABFC02','little'),GREPLY2=int.from_bytes(b'HIABFCR2','little'),
 GOBJECT2=int.from_bytes(b'HIABFCT2','little'),M_DEFER=656,M_QUEUE=664,M_UNMAP=672,
 M_BAD=680,M_CUSTODY=688,M_WEAK=728,M_PIN=752,M_BOUND=776,M_ADOPT=784,M_NEXT=792,
 M_LOGKEY=800,M_LOGSTR=824,M_LOGMAP=856,M_LOGQUEUE=864,M_LOGUNKNOWN=872,M_BIND=888)
C.update(LREQUEST4=int.from_bytes(b'HIAFPL04','little'),LREPLY2=int.from_bytes(b'HIAFPLR2','little'))
C.update(MAGIC3=int.from_bytes(b'HIAPFC03','little'),CBREQUEST2=int.from_bytes(b'HIAFCBQ2','little'),
 CBREPLY2=int.from_bytes(b'HIAFCBR2','little'),LREQUEST7=int.from_bytes(b'HIAFPL07','little'),
 M_NATIVE=920,M_CBCLASS=928)
SOURCE=r'''
def future_carrier(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1590:
        managed_cell_record(o)
        return again(o,get(o,M_NEXT))
    if phase>=1600:
        return guarded(s,o,w,phase)
    if phase<100:
        return locks(s,o,w,phase)
    if phase<200:
        return locate(s,o,w,phase)
    if phase<300:
        return register(s,o,w,phase)
    if phase<400:
        return invoke_user(s,o,w,phase)
    if phase<500:
        return classify(s,o,w,phase)
    if phase<600:
        return propagate(s,o,w,phase)
    if phase<700:
        return release(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if (readword(s,0)!=MAGIC and readword(s,0)!=MAGIC2 and readword(s,0)!=MAGIC3) or readword(s,8)>2:
        return 4294967293
    op=readword(s,8)
    if readword(s,0)==MAGIC3 and op!=0:
        return 4294967293
    at=16
    while at<192:
        used=False
        if op==0 and at>=16 and at<=88:
            used=True
        if op!=0 and (at==16 or (op==1 and at==24)):
            used=True
        if used==False and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if op==0 and readword(s,88)==0:
        return 4294967293
    zero(o,128,OUT-128)
    put(o,OP,op)
    if readword(s,0)==MAGIC2 or readword(s,0)==MAGIC3:
        put(o,M_DEFER,1)
    if readword(s,0)==MAGIC3:
        put(o,M_NATIVE,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FEEDBACK)==0 or get(o,FEEDBACK)>=NEGATIVE or get(w,0)!=STATE or get(w,8)!=get(o,FEEDBACK) or get(w,24)!=0:
            return finish(o,1,107)
        put(o,PID,get(o,FEEDBACK))
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        if get(o,FEEDBACK)==0 or get(o,FEEDBACK)>=NEGATIVE:
            return finish(o,1,107)
        put(o,TID,get(o,FEEDBACK))
        return waddress(o,3,0)
    if phase==3:
        put(o,WPTR,get(o,FEEDBACK))
        return lock(o,20)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,AFTER))
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        return atom(o,2,10,0,1)
    if phase==15:
        return system(o,16,202,1,32,129,2147483647,0,0,0)
    if phase==16:
        return again(o,get(o,AFTER))
    if phase==20:
        put(o,CURSOR,get(w,16))
        return again(o,100)
    return fail(o,1,107)

def locate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,1,107)
        put(o,F,get(o,CURSOR))
        return memory(o,101,0,get(o,F),3,FHEADER,256)
    if phase==101:
        if get(o,FHEADER)!=FOBJECT or get(o,FHEADER+8)!=get(o,PID):
            return fail(o,1,107)
        if get(o,OP)==0:
            if get(o,F)!=readword(s,16):
                put(o,CURSOR,get(o,FHEADER+24))
                return again(o,100)
            if get(o,FHEADER+32)!=readword(s,24) or get(o,FHEADER+40)!=readword(s,32) or get(o,FHEADER+112)!=1 or get(o,FHEADER+56)==0:
                return fail(o,1,107)
            put(o,FACTORY_ID,get(o,F))
            within(o,FACTORY_ID+8,FHEADER+32,16)
            return unlock(o,200)
        put(o,CURSOR,get(o,FHEADER+104))
        return again(o,110)
    if phase==110:
        if get(o,CURSOR)==0:
            put(o,CURSOR,get(o,FHEADER+24))
            return again(o,100)
        put(o,CARRIER,get(o,CURSOR))
        return memory(o,111,0,get(o,CARRIER),3,CHEADER,256)
    if phase==111:
        if get(o,CHEADER)!=OBJECT or get(o,CHEADER+8)!=get(o,PID) or get(o,CHEADER+16)!=get(o,F) or get(o,CHEADER+24)!=get(o,FHEADER+32) or get(o,CHEADER+32)!=get(o,FHEADER+40):
            return fail(o,1,107)
        if get(o,CARRIER)!=readword(s,16):
            put(o,CURSOR,get(o,CHEADER+88))
            return again(o,110)
        if get(o,CHEADER+112)>1 or get(o,CHEADER+144)>1 or get(o,CHEADER+152)>1 or get(o,CHEADER+160)>1:
            return fail(o,1,107)
        if get(o,CHEADER+160)!=0:
            if get(o,CHEADER+112)!=1 or get(o,CHEADER+144)!=1:
                return fail(o,1,107)
            put(o,M_NATIVE,1)
        if get(o,CHEADER+112)!=0:
            put(o,M_DEFER,1)
            put(o,M_BOUND,get(o,CHEADER+144))
            within(o,M_WEAK,CHEADER+120,24)
        if get(o,OP)==2:
            return again(o,600)
        if get(o,CHEADER+96)!=1 or get(o,CHEADER+104)!=0 or get(o,CHEADER+40)!=readword(s,24):
            put(o,CALLBACK_RC,2)
            return fail(o,1,107)
        put(o,FACTORY_ID,get(o,F))
        within(o,FACTORY_ID+8,FHEADER+32,16)
        put(o,CURSOR,get(o,FHEADER+96))
        return again(o,120)
    if phase==120:
        if get(o,CURSOR)==0:
            put(o,CALLBACK_RC,2)
            return fail(o,1,107)
        return memory(o,121,0,get(o,CURSOR),3,FRAME,128)
    if phase==121:
        if get(o,FRAME+88)!=FMAGIC or get(o,FRAME+24)!=get(o,F):
            return fail(o,1,107)
        if get(o,FRAME+16)!=get(o,TID):
            put(o,CURSOR,get(o,FRAME))
            return again(o,120)
        put(o,FRAMEPTR,get(o,CURSOR))
        return write_pointer(o,122,get(o,CARRIER)+104,1)
    if phase==122:
        return write_pointer(o,123,get(o,FRAMEPTR)+64,get(o,FRAME+64)+1)
    if phase==123:
        put(o,GNEXT,300)
        return unlock(o,1600)
    return fail(o,1,107)

def register(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        # Preserve the original invalid-environment ordering before reserve.
        value_packet(o,7)
        copy_input(s,64,o,RQ+24,24)
        return value(o,w,205)
    if phase==205:
        if value_ok(o)==False:
            return fail(o,1,choose(get(o,VP+8)==5,103,107))
        put(o,GNEXT,206)
        return again(o,1600)
    if phase==206:
        value_packet(o,5)
        copy_input(s,64,o,RQ+24,24)
        return value(o,w,201)
    if phase==201:
        if value_ok(o)==False:
            return fail(o,1,choose(get(o,VP+8)==5,103,107))
        within(o,ENV_TEMP,VP+24,24)
        cell_packet(o,6)
        copy_input(s,40,o,RQ+24,24)
        return cell(o,w,202)
    if phase==202:
        if cell_ok(o)==False:
            return fail(o,1,107)
        put(o,KERNEL,get(o,FP+64))
        if get(o,M_DEFER)!=0:
            return memory(o,223,0,get(w,112)+224,3,M_BIND,32)
        return allocate(o,203,33792)
    if phase==223:
        if get(o,M_BIND)==0 and get(o,M_BIND+8)==0 and get(o,M_BIND+16)==0 and get(o,M_BIND+24)==0:
            if get(o,M_NATIVE)!=0:
                return fail(o,1,107)
            return allocate(o,203,33792)
        if get(o,M_BIND)==0 or get(o,M_BIND+8)==0 or get(o,M_BIND+16)!=512 or get(o,M_BIND+24)==0:
            return fail(o,1,107)
        zero(o,RQ,192)
        put(o,RQ,FREQUEST5)
        put(o,RQ+8,23)
        copy_input(s,40,o,RQ+24,24)
        put(o,RQ+72,get(o,M_BIND+24))
        return cell(o,w,224)
    if phase==224:
        if cell_ok(o)==False or get(o,FP+64)!=get(o,KERNEL):
            return fail(o,1,107)
        if get(o,FP+16)==0:
            if get(o,FP+24)!=0 or get(o,FP+32)!=0 or get(o,FP+40)!=0:
                return fail(o,1,107)
            if get(o,M_NATIVE)!=0:
                return fail(o,1,107)
            return allocate(o,203,33792)
        if get(o,FP+16)!=7 or get(o,FP+48)!=get(o,M_BIND+24):
            return fail(o,1,107)
        within(o,M_WEAK,FP+24,24)
        value_packet(o,80)
        within(o,RQ+24,M_WEAK,24)
        put(o,RQ+104,1)
        return value(o,w,225)
    if phase==225:
        if value_ok(o)==False or get(o,VP+16)!=8 or get(o,VP+48)!=7:
            return fail(o,1,107)
        within(o,M_PIN,VP+24,24)
        put(o,M_BOUND,1)
        value_packet(o,77)
        within(o,RQ+24,M_PIN,24)
        within(o,RQ+48,ENV_TEMP,24)
        return value(o,w,226)
    if phase==226:
        if managed_adoption_record(o)==False:
            return fail(o,1,107)
        if get(o,VD_CONSUMED)!=0:
            put(o,M_ADOPT,1)
        if get(o,VD_CONSUMED)!=1:
            return fail(o,1,107)
        if get(o,VD_PENDING)!=0:
            value_packet(o,93)
            return value(o,w,227)
        if get(o,VD_STATUS)!=0:
            return fail(o,1,107)
        return allocate(o,203,33792)
    if phase==227:
        if managed_drop_record(o,False)==False or get(o,VD_STATUS)!=0 or get(o,VD_PENDING)!=0:
            return fail(o,1,107)
        return allocate(o,203,33792)
    if phase==203:
        if get(o,FEEDBACK)==0:
            return fail(o,1,103)
        put(o,NEWC,get(o,FEEDBACK))
        put(o,CARRIER,get(o,FEEDBACK))
        zero(o,CHEADER,256)
        put(o,CHEADER,OBJECT)
        put(o,CHEADER+8,get(o,PID))
        put(o,CHEADER+16,get(o,F))
        put(o,CHEADER+24,readword(s,24))
        put(o,CHEADER+32,readword(s,32))
        put(o,CHEADER+40,get(o,KERNEL))
        put(o,CHEADER+48,readword(s,88))
        within(o,CHEADER+56,ENV_TEMP,24)
        put(o,CHEADER+96,1)
        if get(o,M_DEFER)!=0:
            put(o,CHEADER+112,1)
            within(o,CHEADER+120,M_WEAK,24)
            put(o,CHEADER+144,get(o,M_BOUND))
            put(o,CHEADER+152,get(o,M_ADOPT))
            put(o,CHEADER+160,get(o,M_NATIVE))
        put(o,CHEADER+184,get(o,WPTR))
        return memory(o,204,3,CHEADER,0,get(o,CARRIER),256)
    if phase==204:
        if get(o,M_DEFER)==0:
            zero(o,ENV_TEMP,24)
        return lock(o,210)
    if phase==210:
        return memory(o,211,0,get(o,F),3,FHEADER,256)
    if phase==211:
        return write_pointer(o,212,get(o,CARRIER)+88,get(o,FHEADER+104))
    if phase==212:
        if get(o,FHEADER+104)!=0:
            return write_pointer(o,213,get(o,FHEADER+104)+80,get(o,CARRIER))
        return again(o,213)
    if phase==213:
        return write_pointer(o,214,get(o,F)+104,get(o,CARRIER))
    if phase==214:
        if get(o,M_DEFER)!=0:
            zero(o,ENV_TEMP,24)
        put(o,REGISTERED,1)
        return unlock(o,220)
    if phase==220:
        zero(o,RQ,192)
        put(o,RQ,KREQUEST)
        put(o,RQ+8,4)
        put(o,RQ+16,get(w,96))
        put(o,RQ+24,get(o,CARRIER))
        put(o,RQ+32,get(w,104))
        put(o,RQ+40,readword(s,88))
        # The actual kernel takes or drops the incoming closure on every
        # valid add_callback path, including allocation failure and immediate
        # invocation. Never touch the carrier after this call may free it.
        put(o,NEWC,0)
        put(o,REGISTERED,0)
        return invoke(o,221,get(w,64),RQ,64,FP,512,get(o,KERNEL),512)
    if phase==221:
        if get(o,FP)!=KREPLY or get(o,FEEDBACK)!=get(o,FP+8):
            return fail(o,1,107)
        if get(o,FP+8)!=0:
            return fail(o,1,choose(get(o,FP+8)==5,103,107))
        return fail(o,0,0)
    return fail(o,1,107)

def invoke_user(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,M_DEFER)!=0 and get(o,M_BOUND)!=0:
            value_packet(o,80)
            within(o,RQ+24,M_WEAK,24)
            put(o,RQ+104,1)
            return value(o,w,350)
        return again(o,351)
    if phase==350:
        if value_ok(o)==False or get(o,VP+16)!=8 or get(o,VP+48)!=7:
            return guard_error(o,107)
        within(o,M_PIN,VP+24,24)
        return again(o,351)
    if phase==351:
        cell_packet(o,14)
        put(o,RQ,choose(get(o,M_DEFER)!=0,FREQUEST6,FREQUEST2))
        put(o,RQ+24,get(o,CHEADER+40))
        return cell(o,w,301)
    if phase==301:
        if cell_ok(o)==False:
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,choose(get(o,FP+8)==4,103,107))
            return lock(o,500)
        within(o,FUTURE_TEMP,FP+16,24)
        zero(o,RQ,192)
        put(o,RQ,choose(get(o,M_NATIVE)!=0,CBREQUEST2,CBREQUEST))
        put(o,RQ+16,get(o,F))
        within(o,RQ+24,CHEADER+24,16)
        within(o,RQ+40,FUTURE_TEMP,24)
        within(o,RQ+64,CHEADER+56,24)
        if get(o,M_NATIVE)!=0:
            within(o,RQ+88,M_PIN,24)
        zero(o,VP,8192)
        return invoke(o,302,get(o,CHEADER+48),RQ,192,VP,8192,get(o,WPTR),256)
    if phase==302:
        if get(o,M_NATIVE)!=0:
            return native_callback_record(o)
        if get(o,FEEDBACK)!=0 or get(o,VP)!=CBREPLY or get(o,VP+8)>2:
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            return lock(o,500)
        if valid_callback_reply(o)==False:
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            return lock(o,500)
        put(o,USER_KIND,get(o,VP+8))
        within(o,RETURN_TEMP,VP+24,24)
        if get(o,RETURN_TEMP)==0:
            if get(o,USER_KIND)==0 and get(o,RETURN_TEMP+8)==0 and get(o,RETURN_TEMP+16)==0:
                return fail(o,0,0)
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            zero(o,RETURN_TEMP,24)
            return lock(o,500)
        if same_cap(o,RETURN_TEMP,CHEADER+56):
            # A callable returns an owned reference, never its borrowed
            # captured environment token.
            zero(o,RETURN_TEMP,24)
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            return lock(o,500)
        value_packet(o,7)
        within(o,RQ+24,RETURN_TEMP,24)
        return value(o,w,303)
    if phase==303:
        if value_ok(o)==False:
            # A failed observation does not prove the actual owned callback
            # result was consumed; cleanup must retain its complete fate.
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            return lock(o,500)
        if get(o,USER_KIND)==0:
            return fail(o,0,0)
        if get(o,VP+16)!=choose(get(o,M_NATIVE)!=0,8,6):
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,107)
            return lock(o,500)
        if get(o,USER_KIND)==2:
            put(o,THROW_KIND,2)
            put(o,THROW_CLASS,200)
            return lock(o,500)
        return again(o,400)
    if phase==340:
        put(o,CHEADER+208,get(o,VP+256))
        put(o,CHEADER+216,get(o,VP+120))
        put(o,CHEADER+224,get(o,VP+264))
        put(o,CHEADER+232,1)
        return memory(o,342,3,CHEADER+208,0,get(o,CARRIER)+208,32)
    if phase==342:
        return write_pointer(o,343,get(o,CARRIER)+200,1)
    if phase==343:
        return guard_error(o,107)
    if phase==341:
        return native_callback_continue(o,w)
    return fail(o,1,107)

def native_callback_record(o:mutbuf) -> u32:
    valid=get(o,FEEDBACK)==0 and get(o,VP)==CBREPLY2 and get(o,VP+8)<=2
    flags=get(o,VP+120)
    kind=get(o,VP+16)
    if flags>7 or get(o,VP+264)>1 or get(o,VP+272)!=0 or get(o,VP+280)!=0:
        valid=False
    if kind!=0 and kind!=103 and kind!=107 and kind!=200:
        valid=False
    if get(o,VP+8)==0 and kind!=0:
        valid=False
    if get(o,VP+8)==2 and kind!=200:
        valid=False
    at=24
    while at<120:
        if get(o,VP+at)==0:
            if get(o,VP+at+8)!=0 or get(o,VP+at+16)!=0:
                valid=False
        elif get(o,VP+at+8)==0 or get(o,VP+at+16)==0:
            valid=False
        at=at+24
    if (get(o,VP+8)==0 or kind==200) and get(o,VP+24)==0:
        valid=False
    if valid:
        within(o,RETURN_TEMP,VP+24,24)
        within(o,M_LOGKEY,VP+48,24)
        within(o,M_LOGSTR,VP+72,24)
        within(o,M_CBCLASS,VP+96,24)
        put(o,USER_KIND,get(o,VP+8))
        put(o,THROW_CLASS,kind)
        if (flags&1)!=0:
            put(o,M_UNMAP,1)
        if (flags&2)!=0:
            put(o,M_QUEUE,1)
    if valid==False or (flags&4)!=0:
        # The actual carrier allocation keeps the entire unresolved receipt.
        # Its unknown fence prevents later destruction or blind repeated drop.
        put(o,M_BAD,1)
        put(o,GBAD,1)
        return memory(o,340,3,VP,0,get(o,CARRIER)+256,256)
    if (flags&1)!=0:
        return write_pointer(o,341,get(o,CARRIER)+192,1)
    return again(o,341)

def native_callback_continue(o:mutbuf,w:mutbuf) -> u32:
    if get(o,M_LOGKEY)!=0 or get(o,M_LOGSTR)!=0 or get(o,M_CBCLASS)!=0 or get(o,VP+264)!=0:
        put(o,THROW_KIND,1)
        put(o,THROW_CLASS,107)
        return lock(o,500)
    if get(o,THROW_CLASS)==103 or get(o,THROW_CLASS)==107:
        put(o,THROW_KIND,1)
        return lock(o,500)
    if same_cap(o,RETURN_TEMP,CHEADER+56) or same_cap(o,RETURN_TEMP,M_PIN):
        put(o,M_BAD,1)
        put(o,GBAD,1)
        return memory(o,340,3,VP,0,get(o,CARRIER)+256,256)
    value_packet(o,7)
    within(o,RQ+24,RETURN_TEMP,24)
    return value(o,w,303)

def classify(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        zero(o,RQ,192)
        put(o,RQ,choose(get(o,M_NATIVE)!=0,LREQUEST7,choose(get(o,M_DEFER)!=0,LREQUEST4,LREQUEST)))
        within(o,RQ+24,RETURN_TEMP,24)
        return invoke(o,401,get(w,176),RQ,192,VP,16384,get(o,WPTR),256)
    if phase==401:
        if get(o,M_DEFER)!=0:
            if managed_log_record(o)==False:
                put(o,GBAD,1)
                return guard_error(o,107)
            if get(o,VP+72)!=0:
                return write_pointer(o,402,get(o,CARRIER)+192,1)
        return again(o,402)
    if phase==402:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=choose(get(o,M_DEFER)!=0,LREPLY2,LREPLY) or get(o,VP+8)!=0:
            code=107
            if get(o,VP)==choose(get(o,M_DEFER)!=0,LREPLY2,LREPLY):
                if get(o,VP+16)==103:
                    code=103
            put(o,THROW_KIND,1)
            put(o,THROW_CLASS,code)
            return lock(o,500)
        return lock(o,410)
    if phase==410:
        return memory(o,411,0,get(o,FRAMEPTR),3,FRAME,128)
    if phase==411:
        return write_pointer(o,412,get(o,FRAMEPTR)+72,get(o,FRAME+72)+1)
    if phase==412:
        put(o,CALLBACK_RC,1)
        return fail(o,0,0)
    return fail(o,1,107)

def propagate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        return memory(o,501,0,get(o,FRAMEPTR),3,FRAME,128)
    if phase==501:
        if get(o,FRAME+88)!=FMAGIC or get(o,FRAME+16)!=get(o,TID) or get(o,FRAME+24)!=get(o,F):
            put(o,CALLBACK_RC,2)
            return fail(o,1,107)
        if get(o,FRAME+32)!=0:
            put(o,CALLBACK_RC,2)
            return fail(o,0,0)
        return write_pointer(o,502,get(o,FRAMEPTR)+32,get(o,THROW_KIND))
    if phase==502:
        return write_pointer(o,503,get(o,FRAMEPTR)+80,get(o,THROW_CLASS))
    if phase==503:
        if get(o,THROW_CLASS)==200:
            return memory(o,504,3,RETURN_TEMP,0,get(o,FRAMEPTR)+40,24)
        return again(o,505)
    if phase==504:
        zero(o,RETURN_TEMP,24)
        return again(o,505)
    if phase==505:
        put(o,CALLBACK_RC,2)
        return fail(o,0,0)
    return fail(o,1,107)

def release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        if get(o,CHEADER+96)!=1 and get(o,CHEADER+96)!=3 and get(o,CHEADER+96)!=4:
            return fail(o,1,107)
        # The actual carrier remains linked to its factory until its captured
        # environment and any recorded mapping retirement are both finished.
        # An unknown completion is never replayed using its old nonce.
        if get(o,CHEADER+200)!=0:
            return again(o,609)
        if get(o,CHEADER+192)!=0:
            value_packet(o,31)
            return value(o,w,610)
        if get(o,CHEADER+56)==0:
            if get(o,CHEADER+64)!=0 or get(o,CHEADER+72)!=0:
                return write_pointer(o,609,get(o,CARRIER)+200,1)
            return again(o,606)
        value_packet(o,29)
        within(o,RQ+24,CHEADER+56,24)
        return value(o,w,601)
    if phase==601:
        if value_drop_record(o,29)==False:
            return write_pointer(o,609,get(o,CARRIER)+200,1)
        if get(o,VD_CONSUMED)==0:
            if get(o,VD_PENDING)!=0:
                return write_pointer(o,613,get(o,CARRIER)+192,1)
            return again(o,609)
        zero(o,CHEADER+56,24)
        return memory(o,612,3,CHEADER+56,0,get(o,CARRIER)+56,24)
    if phase==612:
        if get(o,VD_PENDING)!=0:
            return write_pointer(o,609,get(o,CARRIER)+192,1)
        if get(o,VD_STATUS)!=0:
            return write_pointer(o,609,get(o,CARRIER)+200,1)
        return again(o,606)
    if phase==610:
        if value_drop_record(o,31)==False:
            return write_pointer(o,609,get(o,CARRIER)+200,1)
        # A failed retry may report pending=0 before acquiring its own lock.
        # Only a successful actual retry can clear this retained fact.
        if get(o,VD_STATUS)!=0:
            return again(o,609)
        return write_pointer(o,606,get(o,CARRIER)+192,0)
    if phase==613:
        # This call did not consume the held environment. Record the reported
        # mapping, but do not invent permission to discard the original cap
        # after retrying a different retirement obligation.
        return write_pointer(o,609,get(o,CARRIER)+200,1)
    if phase==606:
        if get(o,CHEADER+80)!=0:
            return write_pointer(o,602,get(o,CHEADER+80)+88,get(o,CHEADER+88))
        return write_pointer(o,602,get(o,F)+104,get(o,CHEADER+88))
    if phase==602:
        if get(o,CHEADER+88)!=0:
            return write_pointer(o,603,get(o,CHEADER+88)+80,get(o,CHEADER+80))
        return again(o,603)
    if phase==603:
        put(o,FREEPTR,get(o,CARRIER))
        return fail(o,0,0)
    if phase==609:
        return write_pointer(o,611,get(o,CARRIER)+96,3)
    if phase==611:
        return fail(o,1,107)
    return fail(o,1,107)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,HELD)!=0:
            return unlock(o,900)
        if get(o,GBAD)!=0 and get(o,GPTR)!=0:
            return guard_bad_snapshot(o)
        if get(o,FUTURE_TEMP)!=0:
            cell_packet(o,3)
            within(o,RQ+24,FUTURE_TEMP,24)
            return cell(o,w,901)
        if get(o,RETURN_TEMP)!=0:
            value_packet(o,6)
            within(o,RQ+24,RETURN_TEMP,24)
            return value(o,w,902)
        if get(o,ENV_TEMP)!=0:
            value_packet(o,6)
            within(o,RQ+24,ENV_TEMP,24)
            return value(o,w,903)
        if get(o,M_PIN)!=0:
            value_packet(o,6)
            within(o,RQ+24,M_PIN,24)
            return value(o,w,905)
        if get(o,M_LOGKEY)!=0:
            value_packet(o,6)
            within(o,RQ+24,M_LOGKEY,24)
            return value(o,w,906)
        if get(o,M_LOGSTR)!=0:
            value_packet(o,6)
            within(o,RQ+24,M_LOGSTR,24)
            return value(o,w,907)
        if get(o,M_CBCLASS)!=0:
            value_packet(o,6)
            within(o,RQ+24,M_CBCLASS,24)
            return value(o,w,908)
        if get(o,GPTR)!=0:
            return guard_snapshot(o,1640)
        if get(o,NEWC)!=0:
            if get(o,REGISTERED)!=0:
                return raw_drop(o,w,904,get(o,NEWC))
            put(o,TEMP,get(o,NEWC))
            put(o,NEWC,0)
            return deallocate(o,900,get(o,TEMP))
        return finish(o,get(o,ERROR),get(o,CLASS))
    if phase==901:
        if cell_ok(o)==False:
            put(o,ERROR,1)
            put(o,CLASS,107)
            put(o,CALLBACK_RC,2)
        zero(o,FUTURE_TEMP,24)
        return again(o,900)
    if phase==902:
        if value_ok(o)==False:
            put(o,ERROR,1)
            put(o,CLASS,107)
            put(o,CALLBACK_RC,2)
        zero(o,RETURN_TEMP,24)
        return again(o,900)
    if phase==903:
        if value_ok(o)==False:
            put(o,ERROR,1)
            put(o,CLASS,107)
        zero(o,ENV_TEMP,24)
        return again(o,900)
    if phase==905 or phase==906 or phase==907 or phase==908:
        if value_ok(o)==False:
            guard_failed(o)
        if get(o,M_CUSTODY)!=1:
            put(o,GBAD,1)
            return again(o,900)
        if phase==905:
            zero(o,M_PIN,24)
        elif phase==906:
            zero(o,M_LOGKEY,24)
        elif phase==907:
            zero(o,M_LOGSTR,24)
        else:
            zero(o,M_CBCLASS,24)
        return again(o,900)
    if phase==904:
        put(o,NEWC,0)
        put(o,REGISTERED,0)
        return again(o,900)
    return finish(o,1,107)
def cell_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,choose(get(o,M_DEFER)!=0,FREQUEST6,FREQUEST))
    put(o,RQ+8,op)
    return 0

def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,M_CUSTODY,0)
    put(o,RQ,choose(op>=29,VREQUEST2,VREQUEST))
    if get(o,M_DEFER)!=0:
        put(o,RQ,VREQUEST6)
        if op==5:
            op=91
        elif op==6 or op==29:
            op=78
        elif op==31:
            op=93
        if op>=77:
            put(o,RQ,VREQUEST5)
    put(o,RQ+8,op)
    return 0

def cell(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(o,RQ+8)==3 and get(o,GPTR)!=0:
        put(o,GKIND,1)
        put(o,GNEXT,next)
        put(o,GKEEP,get(o,HELD))
        return guard_snapshot(o,1620)
    if get(o,M_DEFER)!=0:
        put(o,M_NEXT,next)
        return invoke(o,1590,get(w,80),RQ,128,FP,16384,get(o,F)+256,256)
    return invoke(o,next,get(w,80),RQ,128,FP,16384,get(o,F)+256,256)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if (get(o,RQ+8)==6 or get(o,RQ+8)==78) and get(o,GPTR)!=0:
        put(o,GKIND,2)
        put(o,GNEXT,next)
        put(o,GKEEP,get(o,HELD))
        return guard_snapshot(o,1620)
    return invoke(o,next,get(w,72),RQ,128,VP,8192,get(w,112),get(w,120))
def cell_ok(o:mutbuf) -> bool:
    if get(o,M_DEFER)!=0:
        return get(o,FEEDBACK)==0 and get(o,FP)==FREPLY3 and get(o,FP+8)==0 and get(o,M_BAD)==0
    return get(o,FEEDBACK)==0 and get(o,FP)==FREPLY and get(o,FP+8)==0

def value_ok(o:mutbuf) -> bool:
    if get(o,M_DEFER)!=0:
        if get(o,RQ+8)==91:
            return managed_retain_record(o)
        if get(o,RQ+8)==78:
            return get(o,M_CUSTODY)==1 and get(o,GSTATUS)==0
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0

def value_drop_record(o:mutbuf,op:u64) -> bool:
    if get(o,M_DEFER)!=0:
        return managed_drop_record(o,op!=31)
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY2:
        return False
    status=get(o,VP+8)
    pending=get(o,VP+80)
    known=get(o,VP+88)
    consumed=get(o,VP+96)
    if pending>1 or known!=1 or consumed>1:
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        return False
    if op==31 and status==1:
        return False
    if status==1 and pending!=0:
        return False
    if consumed==1 and status!=0 and status!=11:
        return False
    at=16
    while at<128:
        if at!=80 and at!=88 and at!=96 and get(o,VP+at)!=0:
            return False
        at=at+8
    if op==31:
        if consumed!=0 or (status==0 and pending!=0):
            return False
    elif status==0 and (consumed!=1 or pending!=0):
        return False
    put(o,VD_CONSUMED,consumed)
    put(o,VD_PENDING,pending)
    put(o,VD_STATUS,status)
    return True
def guarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase<1620:
        return guard_reserve(o,w,phase)
    if phase<1640:
        return guard_drop(o,w,phase)
    if phase<1660:
        return guard_release(o,w,phase)
    return guard_quarantine(o,w,phase)

def guard_failed(o:mutbuf) -> u64:
    put(o,ERROR,1)
    put(o,CLASS,107)
    put(o,CALLBACK_RC,2)
    return 0

def guard_error(o:mutbuf,kind:u64) -> u32:
    if get(o,OP)==1:
        put(o,THROW_KIND,1)
        put(o,THROW_CLASS,kind)
        if get(o,HELD)!=0:
            return again(o,500)
        return lock(o,500)
    return fail(o,1,kind)

def guard_snapshot(o:mutbuf,next:u64) -> u32:
    zero(o,GSHADOW,GCOUNT*32)
    guard_shadow_current(o,GSHADOW)
    return memory(o,next,3,GSHADOW,0,get(o,GPTR)+128+GCOUNT*64,GCOUNT*32)

def guard_bad_snapshot(o:mutbuf) -> u32:
    zero(o,GSHADOW+256,256)
    guard_shadow_current(o,GSHADOW+256)
    return memory(o,1660,3,GSHADOW,0,get(o,GPTR)+128+GCOUNT*64,GCOUNT*32)

def guard_shadow_current(o:mutbuf,to:u64) -> u64:
    guard_shadow_cap(o,to,1,FUTURE_TEMP)
    guard_shadow_cap(o,to+32,2,RETURN_TEMP)
    guard_shadow_cap(o,to+64,2,ENV_TEMP)
    if get(o,M_DEFER)!=0:
        guard_shadow_cap(o,to+96,2,M_PIN)
        guard_shadow_cap(o,to+128,2,M_LOGKEY)
        guard_shadow_cap(o,to+160,2,M_LOGSTR)
        guard_shadow_cap(o,to+192,2,M_CBCLASS)
    return 0


def guard_reserve(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1600:
        guard_packet(o,0)
        put(o,GREQUEST+96,GCOUNT)
        return guard_call(o,w,1601)
    if phase==1601:
        if guard_record(o,0)==False:
            guard_failed(o)
            return guard_error(o,107)
        if get(o,GOUTPUT+8)!=0:
            return guard_error(o,choose(get(o,GOUTPUT+8)==4,103,107))
        within(o,GCAP,GOUTPUT+16,24)
        return lock(o,1602)
    if phase==1602:
        return memory(o,1603,0,get(o,F)+152,3,GSCAN,8)
    if phase==1603:
        if get(o,GSCAN)==0:
            guard_failed(o)
            return guard_error(o,107)
        return memory(o,1604,0,get(o,GSCAN),3,GNODE,128)
    if phase==1604:
        if get(o,GNODE)!=choose(get(o,M_DEFER)!=0,GOBJECT2,GOBJECT) or get(o,GNODE+8)!=get(o,PID) or get(o,GNODE+16)!=get(o,F):
            guard_failed(o)
            return guard_error(o,107)
        if get(o,GSCAN)!=get(o,GCAP):
            put(o,GSCAN,get(o,GNODE+48))
            return again(o,1603)
        if get(o,GNODE+24)!=get(o,FACTORY_ID+8) or get(o,GNODE+32)!=get(o,FACTORY_ID+16) or get(o,GNODE+56)!=get(o,GCAP+8) or get(o,GNODE+64)!=get(o,GCAP+16):
            guard_failed(o)
            return guard_error(o,107)
        if get(o,GNODE+72)!=0 or get(o,GNODE+80)!=0 or get(o,GNODE+88)!=GCOUNT or get(o,GNODE+96)!=128+96*GCOUNT or get(o,GNODE+112)!=0:
            guard_failed(o)
            return guard_error(o,107)
        put(o,GPTR,get(o,GSCAN))
        # Reservation released the registry lock. Re-observe the live frame
        # head before linking this call's callback frame under the same lock.
        return memory(o,1605,0,get(o,F),3,FHEADER,256)
    if phase==1605:
        return unlock(o,get(o,GNEXT))
    return guard_error(o,107)

def guard_drop(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1620:
        if get(o,HELD)!=0:
            return unlock(o,1620)
        guard_packet(o,1)
        put(o,GREQUEST+64,get(o,GKIND))
        within(o,GREQUEST+72,RQ+24,24)
        return guard_call(o,w,1621)
    if phase==1621:
        put(o,GSTATUS,choose(get(o,GKIND)==1,9,11))
        if guard_record(o,1)==False:
            put(o,GBAD,1)
            guard_failed(o)
        elif get(o,GOUTPUT+56)!=1:
            put(o,GBAD,1)
            guard_failed(o)
        elif get(o,GOUTPUT+8)==0:
            put(o,M_CUSTODY,1)
            put(o,GSTATUS,0)
        else:
            put(o,M_CUSTODY,1)
            guard_failed(o)
        if get(o,GKEEP)!=0:
            return lock(o,1622)
        return again(o,1622)
    if phase==1622:
        at=choose(get(o,GKIND)==1,FP,VP)
        zero(o,at,128)
        put(o,at,choose(get(o,GKIND)==1,choose(get(o,M_DEFER)!=0,FREPLY3,FREPLY),VREPLY))
        if get(o,M_DEFER)!=0 and get(o,GKIND)==1:
            put(o,FP+160,get(o,M_QUEUE))
            put(o,FP+168,get(o,M_UNMAP))
        put(o,at+8,get(o,GSTATUS))
        put(o,FEEDBACK,0)
        return again(o,get(o,GNEXT))
    return guard_error(o,107)

def guard_release(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1640:
        guard_packet(o,2)
        return guard_call(o,w,1641)
    if phase==1641:
        within(o,GLOST,GCAP,24)
        zero(o,GCAP,24)
        put(o,GPTR,0)
        if guard_record(o,2)==False:
            guard_failed(o)
            return lock(o,1670)
        if get(o,GOUTPUT+56)!=1:
            guard_failed(o)
            return lock(o,1670)
        if get(o,GOUTPUT+8)!=0:
            guard_failed(o)
        return again(o,900)
    return guard_error(o,107)

def guard_quarantine(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1660:
        if get(o,HELD)!=0:
            return again(o,1661)
        return lock(o,1661)
    if phase==1661:
        return write_pointer(o,1662,get(o,GPTR)+112,1)
    if phase==1662:
        return write_pointer(o,1663,get(o,GPTR)+72,1)
    if phase==1663:
        # The independently linked shadow now owns the complete unresolved
        # temporary-reference callsite. No original drop may be replayed.
        zero(o,FUTURE_TEMP,24)
        zero(o,RETURN_TEMP,24)
        zero(o,ENV_TEMP,24)
        zero(o,M_PIN,24)
        zero(o,M_LOGKEY,24)
        zero(o,M_LOGSTR,24)
        zero(o,M_CBCLASS,24)
        zero(o,GCAP,24)
        put(o,GPTR,0)
        put(o,GBAD,0)
        guard_failed(o)
        return again(o,900)
    if phase==1670:
        # Release may already have freed an empty guard. Preserve its exact
        # identity in the actual factory; never dereference or replay it.
        return memory(o,1671,3,GLOST,0,get(o,F)+168,24)
    if phase==1671:
        return write_pointer(o,900,get(o,F)+144,1)
    return guard_error(o,107)

def guard_shadow_cap(o:mutbuf,to:u64,kind:u64,at:u64) -> u64:
    if get(o,at)!=0:
        put(o,to,kind)
        within(o,to+8,at,24)
    return 0

def guard_packet(o:mutbuf,op:u64) -> u64:
    zero(o,GREQUEST,192)
    put(o,GREQUEST,choose(get(o,M_DEFER)!=0,GMAGIC2,GMAGIC))
    put(o,GREQUEST+8,op)
    within(o,GREQUEST+16,FACTORY_ID,24)
    if op==1 or op==2:
        within(o,GREQUEST+40,GCAP,24)
    return 0

def guard_call(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(w,216)==0:
        put(o,FEEDBACK,MAX)
        return again(o,next)
    return invoke(o,next,get(w,216),GREQUEST,192,GOUTPUT,128,get(o,WPTR),256)

def guard_record(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,GOUTPUT)!=choose(get(o,M_DEFER)!=0,GREPLY2,GREPLY):
        return False
    status=get(o,GOUTPUT+8)
    pending=get(o,GOUTPUT+40)
    known=get(o,GOUTPUT+48)
    taken=get(o,GOUTPUT+56)
    raw=get(o,GOUTPUT+64)
    if status!=0 and status!=1 and status!=4 and status!=5 and status!=9:
        return False
    if pending>1 or known>1 or taken>1:
        return False
    if known==0 and status!=9:
        return False
    if raw!=0 and raw!=1 and raw!=5 and raw!=6 and raw!=9 and raw!=11:
        return False
    if taken==1 and status!=0 and status!=9:
        return False
    at=88
    if get(o,M_DEFER)!=0:
        if get(o,GOUTPUT+88)>1 or get(o,GOUTPUT+96)>1:
            put(o,M_BAD,1)
            return False
        if get(o,GOUTPUT+88)!=0:
            put(o,M_QUEUE,1)
        if get(o,GOUTPUT+96)!=0:
            put(o,M_UNMAP,1)
        at=104
    while at<128:
        if get(o,GOUTPUT+at)!=0:
            return False
        at=at+8
    if op==0:
        if known!=1 or taken!=0 or raw!=0:
            return False
        if status==0:
            ptr=get(o,GOUTPUT+16)
            return ptr!=0 and ptr<=MAX-(128+96*GCOUNT) and pending==1 and get(o,GOUTPUT+72)==128+96*GCOUNT and get(o,GOUTPUT+80)==GCOUNT
    else:
        if get(o,GOUTPUT+72)!=0 or get(o,GOUTPUT+80)!=0:
            return False
        if status==0 and (known!=1 or raw!=0):
            return False
        if op==3 and taken!=0:
            return False
        if (op==1 or op==2) and status==0 and taken!=1:
            return False
        if op==1 and status==0 and pending!=1:
            return False
    return get(o,GOUTPUT+16)==0 and get(o,GOUTPUT+24)==0 and get(o,GOUTPUT+32)==0 and get(o,GOUTPUT+72)==0 and get(o,GOUTPUT+80)==0

def raw_drop(o:mutbuf,w:mutbuf,next:u64,p:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,get(w,104))
    put(o,8,0)
    put(o,16,p)
    zero(o,24,40)
    return 9

def managed_log_record(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=LREPLY2:
        put(o,M_BAD,1)
        return False
    if get(o,VP+8)>1 or get(o,VP+72)>1 or get(o,VP+80)>1 or get(o,VP+88)>1:
        put(o,M_BAD,1)
        return False
    at=96
    while at<128:
        if get(o,VP+at)!=0:
            put(o,M_BAD,1)
            return False
        at=at+8
    within(o,M_LOGKEY,VP+24,24)
    within(o,M_LOGSTR,VP+48,24)
    if get(o,VP+72)!=0:
        put(o,M_UNMAP,1)
    if get(o,VP+80)!=0:
        put(o,M_QUEUE,1)
    if get(o,VP+88)!=0:
        put(o,M_BAD,1)
        return False
    return True

def managed_cell_record(o:mutbuf) -> u64:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY3 or get(o,FP+160)>1 or get(o,FP+168)>1:
        put(o,M_BAD,1)
        return 0
    if get(o,FP+160)!=0:
        put(o,M_QUEUE,1)
    if get(o,FP+168)!=0:
        put(o,M_UNMAP,1)
    return 0

def managed_drop_record(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY2 or get(o,VP+88)!=1 or get(o,VP+120)!=1:
        put(o,M_BAD,1)
        return False
    consumed=get(o,VP+96)
    mapping=get(o,VP+104)
    queued=get(o,VP+112)
    pending=get(o,VP+80)
    status=get(o,VP+8)
    if consumed>1 or mapping>1 or queued>1 or pending>1:
        put(o,M_BAD,1)
        return False
    if pending!=choose(mapping!=0 or queued!=0,1,0):
        put(o,M_BAD,1)
        return False
    if allow_consumed==False and consumed!=0:
        put(o,M_BAD,1)
        return False
    if consumed!=0 and status!=0 and status!=11:
        put(o,M_BAD,1)
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        put(o,M_BAD,1)
        return False
    if status==0 and allow_consumed and consumed==0:
        put(o,M_BAD,1)
        return False
    at=16
    while at<80:
        if get(o,VP+at)!=0:
            put(o,M_BAD,1)
            return False
        at=at+8
    put(o,VD_CONSUMED,consumed)
    put(o,VD_PENDING,mapping)
    put(o,VD_STATUS,status)
    if queued!=0:
        put(o,M_QUEUE,1)
        if mapping==0 and status==11:
            put(o,VD_STATUS,0)
    if mapping!=0:
        put(o,M_UNMAP,1)
    return True

def managed_adoption_record(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY2 or get(o,VP+88)!=1:
        put(o,M_BAD,1)
        return False
    status=get(o,VP+8)
    pending=get(o,VP+80)
    consumed=get(o,VP+96)
    if pending>1 or consumed>1 or (consumed==1 and status!=0 and status!=11):
        put(o,M_BAD,1)
        return False
    if status==0 and consumed!=1:
        put(o,M_BAD,1)
        return False
    at=16
    while at<128:
        if at!=80 and at!=88 and at!=96 and get(o,VP+at)!=0:
            put(o,M_BAD,1)
            return False
        at=at+8
    put(o,VD_CONSUMED,consumed)
    put(o,VD_PENDING,pending)
    put(o,VD_STATUS,status)
    return True

def managed_retain_record(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY or get(o,VP+88)!=1 or get(o,VP+120)!=1:
        put(o,M_BAD,1)
        return False
    published=get(o,VP+96)
    mapping=get(o,VP+104)
    queued=get(o,VP+112)
    status=get(o,VP+8)
    if published>1 or mapping>1 or queued>1 or get(o,VP+80)!=choose(mapping!=0 or queued!=0,1,0):
        put(o,M_BAD,1)
        return False
    if published==1:
        if get(o,VP+24)==0 or get(o,VP+32)==0 or get(o,VP+40)==0 or (status!=0 and status!=11):
            put(o,M_BAD,1)
            return False
        within(o,ENV_TEMP,VP+24,24)
    elif get(o,VP+24)!=0 or get(o,VP+32)!=0 or get(o,VP+40)!=0:
        put(o,M_BAD,1)
        return False
    if queued!=0:
        put(o,M_QUEUE,1)
    if mapping!=0:
        put(o,M_UNMAP,1)
    return published==1 and mapping==0 and (status==0 or (status==11 and queued!=0))

def valid_callback_reply(o:mutbuf) -> bool:
    at=16
    valid=True
    while at<128:
        if (at<24 or at>40) and get(o,VP+at)!=0:
            valid=False
        at=at+8
    return valid
def same_cap(o:mutbuf,a:u64,b:u64) -> bool:
    return get(o,a)==get(o,b) and get(o,a+8)==get(o,b+8) and get(o,a+16)==get(o,b+16)
def fail(o:mutbuf,status:u64,kind:u64) -> u32:
    put(o,ERROR,status)
    put(o,CLASS,kind)
    return again(o,900)
def finish(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    put(o,24,get(o,CALLBACK_RC))
    if get(o,M_DEFER)!=0:
        put(o,32,get(o,M_UNMAP))
        put(o,40,get(o,M_QUEUE))
        put(o,48,get(o,M_BAD))
    put(o,64,get(o,FREEPTR))
    return 0
def waddress(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 5

def lock(o:mutbuf,next:u64) -> u32:
    put(o,AFTER,next)
    return atom(o,2,10,0,1)
def unlock(o:mutbuf,next:u64) -> u32:
    put(o,AFTER,next)
    put(o,HELD,0)
    return atom(o,3,15,0,0)
def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)
def address(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 4
def invoke(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,51)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9
def random(o:mutbuf,next:u64) -> u32:
    return system(o,next,318,3,RANDOM+get(o,RANDOM_USED),16-get(o,RANDOM_USED),0,0,0,0)
def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6
def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7
def memory(o:mutbuf,next:u64,a:u64,at:u64,b:u64,bt:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,at)
    put(o,16,b)
    put(o,24,bt)
    put(o,32,n)
    return 8
def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)
def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10
def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)
def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
def narrow(n:u64) -> u32:
    return n
'''
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_carrier')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_carrier.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
