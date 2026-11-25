"""Fixed effects for the native multiversion coordinator.

The private entry receives only captured bytes and already-owned companion FDs.
It performs the original locks and invokes actual fixed HIA companions. Public
capability lookup and typed-result rendering are separate enclosing owners.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={

'EXT_REQUEST':int.from_bytes(b'HIAMVEX2','little'),
'BG_MAGIC':int.from_bytes(b'HIAMVBS1','little'),
'VALUE_MAGIC':int.from_bytes(b'HIAMVUO1','little'),
'D_BASE':27000,'D_EXT':27000,'D_START':27008,'D_GN':27016,'D_EN':27024,
'D_MAPPED':27032,'D_WHICH':27040,'D_INDEX':27048,'D_AMOUNT':27056,
'D_VALUE':27064,'D_SIZE':27072,'D_NEXT':27080,'D_GCAP':27104,'D_ECAP':27136,
'D_GID':27168,'D_EID':27176,'D_PTR':27184,'D_LEN':27192,'D_ERROR':27200,
'D_GDATA':27208,'D_EDATA':27216,'D_CAPTURE_GN':27224,'D_CAPTURE_EN':27232,
'D_REPLY':27392,'D_CHUNK':28000,'D_OWNED':27240,'D_FAILED':27248,
'REQUEST':int.from_bytes(b'HIAMVEX1','little'),'REPLY':int.from_bytes(b'HIAMVER1','little'),
'STATE':int.from_bytes(b'HIAMVEW1','little'),'GOBJ':int.from_bytes(b'HIAMVGO1','little'),
'LOBJ':int.from_bytes(b'HIAMVLO1','little'),'COREQ':int.from_bytes(b'HIAMVC02','little'),
'IDREQ':int.from_bytes(b'HIAMVID1','little'),'IDREP':int.from_bytes(b'HIAMVIDR','little'),
'GENREQ':int.from_bytes(b'HIAMVGX1','little'),'GENREP':int.from_bytes(b'HIAMVGD1','little'),
'RETAIN':int.from_bytes(b'HIAGRQ01','little'),'FUTURE':int.from_bytes(b'HIAMVFQ1','little'),
'FUTURE_STATE':int.from_bytes(b'HIAMVFS1','little'),
'DREQ':int.from_bytes(b'HIARREQ1','little'),'DREP':int.from_bytes(b'HIARRES1','little'),
'MREQ':int.from_bytes(b'HIAMVMT1','little'),'MREP':int.from_bytes(b'HIAMVMR1','little'),
'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'WORK':131072,'OUTPUT':40<<20,'GW':512<<20,'GCTRL':500<<20,'GPATH':473<<20,
'GCORE':448<<20,'GABI':456<<20,
'COOR':8192,'IDENTITY':32768,'SLOTS':65536,'PARENT':73728,'DIRECTORY':77824,
'DIR_STAT':82000,'DIR_FDSTAT':82160,'DMETA':82500,
'DSTATE':86016,'DINPUT':90624,'DOUTPUT':94912,
'PHASE':128,'FEEDBACK':136,'OP':144,'ACTION':152,'NEXT':160,'GEN':168,'SLOT':176,
'SUBOP':184,'NOW':192,'FRAME_N':200,'ERROR':208,'TOKEN':216,
'LOCK_OFFSET':224,'LOCK_NEXT':232,'LOCK_ACTION':240,'RELEASE_MASK':248,
'EVENT_ERROR':256,'INDEX':264,'LEASE':272,'TEMP_PTR':280,'TIME':288,
'FRESH':312,'NATIVE_ERROR':320,'METHOD':328,'LOCAL_TOKEN':336,
'RUNTIME_PID':344,'AFTER_ID':352,'AFTER_MEMORY':360,'AFTER_GEN':368,
'LOCK_MODE':376,'LOCK_RESUME':384,'STARTED':392,'DNEXT':400,'DINPUT_N':408,'DTOKEN':416,
'DMODE':424,'DERROR':432,'MEASURE_STAGE':440,'SAVE_GEN':448,'SAVE_SLOT':456,'INITIAL_FAILURE':464,'MEAS_N':472,'PROVISIONAL':480,'RET_HELD':488,'RET_RESULT':496,
'RESULT':512,'STATE_O':4096,'CINPUT':8192,'IREQ':8320,'IOUT':9216,
'GOUT':14336,'GO':18432,'LO':19008,'RINPUT':19520,'ROUT':19648,
'TOKEN_INPUT':20000,'TOKEN_OUTPUT':20128,'RETIRE_RESULT':20800,
'CALL_W':24576,'CALL_O':25088,
'FRAME':1<<20,'MEAS_FRAME':18<<20,'MEAS_WORK':27<<20,'MEAS_OUT':32<<20,
}
SOURCE=r'''
def runtime_effects(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or length(w)<WORK or length(o)<OUTPUT:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase>=1000:
        return extended(s,o,w,phase)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return locking(s,o,w,phase)
    if phase<300:
        return coordinating(s,o,w,phase)
    if phase<400:
        return generation(s,o,w,phase)
    if phase<500:
        return identity(s,o,w,phase)
    if phase<600:
        return retention(s,o,w,phase)
    if phase<700:
        return leases(s,o,w,phase)
    if phase<800:
        return directory(s,o,w,phase)
    if phase<900:
        return token(s,o,w,phase)
    return completing(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word(s,0)!=REQUEST and word(s,0)!=EXT_REQUEST:
        return 4294967293
    ext=word(s,0)==EXT_REQUEST
    if word(s,120)>1 or (ext==False and word(s,8)>13):
        return 4294967293
    if ext and word(s,8)!=2 and word(s,8)!=14:
        return 4294967293
    n=word(s,80)
    parent=word(s,88)
    fn=word(s,96)
    args=word(s,104)
    measure=word(s,112)
    if n>8388608 or parent>4095 or fn>8388608 or args>8388608 or measure>8388608:
        return 4294967293
    gn=0
    en=0
    if ext:
        gn=word(s,224)
        en=word(s,232)
    if n>length(s)-256 or parent>length(s)-256-n or fn>length(s)-256-n-parent or args>length(s)-256-n-parent-fn or measure>length(s)-256-n-parent-fn-args:
        return 4294967293
    rest=length(s)-256-n-parent-fn-args-measure
    if gn>rest or en!=rest-gn:
        return 4294967293
    if ext and word(s,8)==14:
        if n!=0 or parent!=0 or fn!=0 or args!=0 or measure!=0 or gn!=0 or en!=0:
            return 4294967293
    if ext and word(s,8)==2:
        if gn==0 or en==0 or word(s,40)!=0 or word(s,48)!=0:
            return 4294967293
        start=length(s)-gn-en
        if canonical_decimal(s,start,gn)==0 or canonical_decimal(s,start+gn,en)==0:
            return 4294967293
    i=224
    if ext:
        i=240
    while i<256:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    zero(o,128,24320)
    zero(o,D_BASE,384)
    put(o,D_EXT,choose(ext,1,0))
    put(o,D_START,length(s)-gn-en)
    put(o,D_GN,gn)
    put(o,D_EN,en)
    put(o,OP,word(s,8))
    put(o,TOKEN,word(s,64))
    put(o,GEN,NONE)
    put(o,SLOT,NONE)
    put(o,LOCAL_TOKEN,0)
    put(o,RESULT,NONE)
    put(o,RESULT+8,NONE)
    return system(o,1,39,0,0,0,0,0,0,0)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return result(o,w,6)
        put(o,RUNTIME_PID,pid)
        if get(o,OP)!=0:
            if get(w,0)!=STATE or get(w,8)!=pid:
                return result(o,w,1)
            if get(o,OP)==13 and get(w,COOR)==0:
                return finish_context(o,w)
            if get(o,OP)==2:
                return clock(o,5)
            return start_coordinator(s,o,w)
        if get(w,0)!=0:
            return result(o,w,1)
        if word(s,40)<1 or word(s,40)>30000 or word(s,48)<2 or word(s,48)>64 or word(s,56)>1:
            return result(o,w,2)
        if word(s,88)==0 or byte(s,256+word(s,80))!=47:
            return result(o,w,2)
        i=0
        while i<word(s,88):
            if byte(s,256+word(s,80)+i)==0:
                return result(o,w,2)
            i=i+1
        put(w,0,STATE)
        put(w,8,pid)
        put(w,64,NONE)
        put(w,72,NONE)
        put(w,80,NONE)
        put(w,232,NONE)
        put(w,192,word(s,40))
        put(w,200,word(s,48))
        put(w,208,word(s,56))
        put(w,216,word(s,88))
        copy_input(s,256+word(s,80),w,PARENT,word(s,88))
        store(w,PARENT+word(s,88),0)
        copy_input(s,128,w,96,96)
        put(o,INDEX,0)
        return system(o,2,318,1,16,16,0,0,0,0)
    if phase==2:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,2,318,1,16+get(o,INDEX),16-get(o,INDEX),0,0,0,0)
        used=get(o,INDEX)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return admission_failure(o,6)
        used=used+raw
        put(o,INDEX,used)
        if used<16:
            return system(o,2,318,1,16+used,16-used,0,0,0,0)
        if get(w,16)==0 and get(w,24)==0:
            return admission_failure(o,6)
        put(o,INDEX,0)
        return again(o,3)
    if phase==3:
        index=get(o,INDEX)
        if index==3:
            return start_coordinator(s,o,w)
        fd=word(s,16+index*8)
        if fd<3 or fd>2147483647:
            return admission_failure(o,2)
        return system(o,4,72,0,fd,1030,3,0,0,0)
    if phase==4:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return again(o,3)
        if raw<3 or raw>2147483647:
            return admission_failure(o,6)
        index=get(o,INDEX)
        put(w,64+index*8,raw)
        put(o,INDEX,index+1)
        return again(o,3)
    if phase==5:
        put(o,STARTED,get(o,NOW))
        if word(s,120)==0:
            return start_coordinator(s,o,w)
        measurement_frame(s,o,0)
        zero(o,MEAS_WORK,65536)
        return role(o,6,20,3,MEAS_FRAME,get(o,MEAS_N),3,MEAS_OUT,8388608,3,MEAS_WORK,262144)
    if phase==6:
        if get(o,FEEDBACK)!=0 or get(o,MEAS_OUT)!=MREP:
            return result(o,w,9)
        if get(o,MEAS_OUT+8)!=0:
            put(o,NATIVE_ERROR,get(o,MEAS_OUT+16))
            return result(o,w,23)
        return start_coordinator(s,o,w)
    return result(o,w,9)

def admission_failure(o:mutbuf,status:u64) -> u32:
    put(o,INITIAL_FAILURE,status)
    return again(o,902)

def start_coordinator(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,CINPUT,96)
    put(o,CINPUT,COREQ)
    put(o,CINPUT+8,choose(get(o,OP)==14,10,choose(get(o,OP)==12,5,choose(get(o,OP)==13,8,get(o,OP)))))
    put(o,CINPUT+16,get(w,16))
    put(o,CINPUT+24,get(w,24))
    put(o,CINPUT+32,word(s,40))
    put(o,CINPUT+40,word(s,48))
    put(o,CINPUT+48,word(s,56))
    put(o,CINPUT+56,word(s,64))
    put(o,CINPUT+64,word(s,120))
    put(o,CINPUT+72,word(s,72))
    if get(o,OP)==4 or get(o,OP)==5 or get(o,OP)==6 or get(o,OP)==12:
        put(o,CINPUT+32,word(s,16))
        put(o,CINPUT+40,word(s,24))
    if get(o,OP)==0:
        put(o,CINPUT+32,get(w,192))
        put(o,CINPUT+40,get(w,200))
        put(o,CINPUT+48,get(w,208))
    return state_step(o)

def state_step(o:mutbuf) -> u32:
    return role(o,200,14,3,CINPUT,96,3,STATE_O,4096,1,COOR,24576)

def coordinating(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        put(o,ACTION,get(o,FEEDBACK))
        put(o,RELEASE_MASK,get(o,STATE_O+352))
        put(o,EVENT_ERROR,0)
        if get(o,STATE_O+336)!=0:
            row=COOR+17408+(get(o,STATE_O+336)-1)*48
            id=get(w,row+8)
            index=0
            while index<64 and get(w,SLOTS+index*16+8)!=id:
                index=index+1
            if index==64:
                return coordinator_failure(o,27)
            identity_request(o,9,index)
            put(o,IREQ+24,get(w,row))
            put(o,IREQ+32,get(w,row+24))
            put(o,IREQ+40,get(w,row+32))
            return identity_call(o,201)
        return again(o,202)
    if phase==201:
        if identity_ok(o)==0:
            put(o,EVENT_ERROR,29)
            put(w,COOR+112,get(w,IDENTITY+28672))
            put(w,COOR+104,get(w,IDENTITY+28680))
        return again(o,202)
    if phase==202:
        mask=get(o,RELEASE_MASK)
        if mask!=0:
            index=0
            while index<63 and (mask&(1<<index))==0:
                index=index+1
            put(o,SLOT,index)
            put(o,RELEASE_MASK,mask&(NONE^(1<<index)))
            if index==0:
                return detach_generation(o,w,204,0)
            identity_request(o,6,index)
            return identity_call(o,203)
        if get(o,EVENT_ERROR)!=0:
            return coordinator_failure(o,get(o,EVENT_ERROR))
        return dispatch(s,o,w)
    if phase==270:
        return feedback(o,0)
    if phase==203:
        if identity_ok(o)==0:
            return coordinator_failure(o,27)
        return detach_generation(o,w,204,get(o,SLOT))
    if phase==204:
        return again(o,202)
    return result(o,w,9)

def dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    action=get(o,ACTION)
    if action==100:
        return state_step(o)
    if action==101:
        return finish_call(o,w)
    if action>=4294967280:
        return result(o,w,9)
    if action==1 or action==2:
        return start_lock(o,w,action)
    if action==20:
        put(o,SLOT,get(o,STATE_O+40))
        return again(o,300)
    if action==21 or action==22 or action==23:
        put(o,SLOT,get(o,STATE_O+40))
        return load_generation(o,w,310)
    if action==24:
        return measurement(s,o,w)
    if action==25:
        return start_retention(o,w)
    if action==26:
        put(o,SLOT,get(o,STATE_O+168))
        return load_generation(o,w,340)
    if action==30:
        if get(o,STATE_O)==200 and get(o,STARTED)!=0:
            put(o,STATE_O+176,get(o,STARTED))
            return feedback(o,0)
        return clock(o,270)
    if action==31 or action==34:
        return start_lease(s,o,w)
    if action==32:
        return native_call(s,o,w)
    if action==33:
        return again(o,700)
    if action==35 or action==38:
        return start_token(o,w)
    if action==36:
        return again(o,750)
    if action==37:
        if get(o,OP)==14:
            return bg_snapshot(o,w)
        return snapshot(o,w)
    if action==40:
        identity_request(o,1,get(o,STATE_O+168))
        return identity_call(o,400)
    if action==41:
        identity_request(o,2,0)
        return identity_call(o,410)
    return coordinator_failure(o,127)

def locking(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FEEDBACK)==0:
            if get(o,LOCK_ACTION)==2:
                return system(o,103,202,0,get(o,LOCK_OFFSET),129,2147483647,0,0,0)
            if get(o,LOCK_MODE)!=0:
                return again(o,get(o,LOCK_RESUME))
            return locked_observe(s,o,w)
        return system(o,101,202,0,get(o,LOCK_OFFSET),128,1,0,0,0)
    if phase==101:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=NONE-3 and raw!=NONE-10:
            return feedback(o,6)
        return atomic(o,100,2,get(o,LOCK_OFFSET),0,1)
    if phase==102:
        return system(o,103,202,0,get(o,LOCK_OFFSET),129,2147483647,0,0,0)
    if phase==103:
        if get(o,LOCK_MODE)!=0:
            return again(o,get(o,LOCK_RESUME))
        return feedback(o,0)
    if phase==104:
        return token_observed(o,w)
    if phase==105:
        put(o,LOCK_OFFSET,get(o,FEEDBACK))
        if get(o,LOCK_ACTION)==1:
            return atomic(o,100,2,get(o,LOCK_OFFSET),0,1)
        return atomic(o,102,3,get(o,LOCK_OFFSET),0,0)
    return result(o,w,9)

def start_lock(o:mutbuf,w:mutbuf,action:u64) -> u32:
    put(o,LOCK_MODE,0)
    which=get(o,STATE_O+168)
    if which==1:
        return local_lock(o,action,256)
    if which==2:
        return local_lock(o,action,260)
    if which==3:
        if get(o,LEASE)==0:
            return feedback(o,1)
        put(o,LOCK_OFFSET,get(o,LEASE)+88)
    elif which==4:
        if get(o,TOKEN)==0:
            return feedback(o,1)
        put(o,LOCK_OFFSET,get(o,TOKEN)+132)
    else:
        return feedback(o,1)
    put(o,LOCK_ACTION,action)
    if action==1:
        return atomic(o,100,2,get(o,LOCK_OFFSET),0,1)
    return atomic(o,102,3,get(o,LOCK_OFFSET),0,0)

def private_lock(o:mutbuf,action:u64,at:u64,next:u64) -> u32:
    put(o,LOCK_MODE,1)
    put(o,LOCK_RESUME,next)
    return local_lock(o,action,at)

def local_lock(o:mutbuf,action:u64,at:u64) -> u32:
    put(o,LOCK_ACTION,action)
    put(o,0,at)
    put(o,PHASE,105)
    put(o,8,action)
    return 4

def locked_observe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,D_EXT)!=0 and get(o,OP)==2 and get(o,STATE_O+168)==2 and get(o,D_MAPPED)==0:
        put(o,D_MAPPED,1)
        put(o,STATE_O+48,NONE)
        put(o,STATE_O+56,NONE)
        if get(w,COOR+24)==0 and get(w,COOR+48)<64:
            put(o,D_WHICH,0)
            identity_request(o,7,get(w,COOR+48))
            put(o,D_NEXT,1001)
            return identity_call(o,1050)
    if get(o,STATE_O+168)==4:
        return read_token(o,104)
    return feedback(o,0)

def feedback(o:mutbuf,value:u64) -> u32:
    put(o,STATE_O+8,value)
    return state_step(o)

def coordinator_failure(o:mutbuf,value:u64) -> u32:
    put(o,STATE_O+120,value)
    put(o,STATE_O,800)
    return state_step(o)

def generation(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        slot=get(o,SLOT)
        if slot>=64 or get(w,SLOTS+slot*16)!=0:
            return feedback(o,1)
        return allocate(o,301,512)
    if phase==301:
        pointer=get(o,FEEDBACK)
        if pointer==0:
            return feedback(o,4)
        put(o,GEN,pointer)
        zero(o,GO,512)
        put(o,GO,GOBJ)
        put(o,GO+8,get(w,8))
        put(o,GO+16,get(w,272))
        put(o,GO+56,get(o,SLOT))
        put(o,GO+72,1)
        put(o,GO+40,pointer+256)
        put(o,GO+48,65)
        put(o,GO+120,get(w,16))
        put(o,GO+128,pointer)
        return memory(o,302,3,GO,0,pointer,512)
    if phase==302:
        return system(o,303,9,0,0,GW,3,34,NONE,0)
    if phase==303:
        raw=get(o,FEEDBACK)
        if raw>=NEGATIVE:
            return deallocate(o,309,get(o,GEN))
        put(o,GO+32,raw)
        return memory(o,304,3,GO,0,get(o,GEN),256)
    if phase==304:
        return private_lock(o,1,264,322)
    if phase==322:
        slot=get(o,SLOT)
        put(w,SLOTS+slot*16,get(o,GEN))
        put(o,TEMP_PTR,get(w,272))
        put(o,GO+16,get(w,272))
        put(w,272,get(o,GEN))
        return memory(o,323,3,GO,0,get(o,GEN),256)
    if phase==323:
        if get(o,TEMP_PTR)!=0:
            put(o,FRESH,get(o,GEN))
            return memory(o,324,3,FRESH,0,get(o,TEMP_PTR)+24,8)
        return again(o,324)
    if phase==324:
        return private_lock(o,2,264,325)
    if phase==325:
        slot=get(o,SLOT)
        if get(o,OP)==0:
            return clock(o,306)
        identity_request(o,5,slot)
        return identity_call(o,305)
    if phase==305:
        if identity_ok(o)==0:
            return feedback(o,4)
        take_generation_identity(o,w)
        return memory(o,308,3,GO+80,0,get(o,GEN)+80,40)
    if phase==308:
        return clock(o,306)
    if phase==306:
        return begin_generation(s,o,w)
    if phase==307:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        if get(o,GOUT+96)!=NONE:
            put(o,RESULT,get(o,GOUT+96))
        if get(o,GOUT+104)!=NONE:
            put(o,RESULT+8,get(o,GOUT+104))
        return feedback(o,get(o,GOUT+8))
    if phase==309:
        put(o,GEN,0)
        return feedback(o,4)
    if phase==310:
        if get(o,ACTION)==21:
            return generation_op(o,311,1)
        if get(o,ACTION)==22:
            return generation_op(o,311,2)
        return clock(o,312)
    if phase==311:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        return feedback(o,get(o,GOUT+8))
    if phase==312:
        return artifact_path(o,w,313)
    if phase==313:
        put(o,TEMP_PTR,get(o,NOW)+60000000000)
        return memory(o,314,3,TEMP_PTR,0,get(o,GO+32)+GCTRL+104,8)
    if phase==314:
        return generation_op(o,315,3)
    if phase==315:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        if get(o,GOUT+8)==8 and get(o,GOUT+16)==6:
            put(o,STATE_O+264,1)
            return feedback(o,1)
        if get(o,GOUT+8)!=0:
            return feedback(o,get(o,GOUT+8))
        zero(o,RINPUT,64)
        put(o,RINPUT,RETAIN)
        put(o,RINPUT+16,get(o,GO+120))
        put(o,RINPUT+24,get(o,GO+128))
        zero(o,ROUT,64)
        return role(o,316,15,3,RINPUT,64,3,ROUT,64,0,get(o,GO+40),get(o,GO+48))
    if phase==316:
        if get(o,FEEDBACK)!=0:
            put(o,STATE_O+264,1)
            return feedback(o,1)
        put(o,STATE_O+264,1)
        put(o,GO+152,1)
        return memory(o,317,3,GO+152,0,get(o,GEN)+152,8)
    if phase==317:
        return feedback(o,0)
    if phase==318:
        return memory(o,319,0,get(o,LO+32)+GCTRL+120,3,LO+256,16)
    if phase==319:
        cn=get(o,LO+256)
        an=get(o,LO+264)
        if cn==0 or cn>8388608 or an<336 or an>5136:
            return feedback(o,9)
        put(o,FRAME+88,cn)
        put(o,FRAME+96,an)
        return memory(o,320,0,get(o,LO+32)+GCORE,3,FRAME+256+word(s,80),cn)
    if phase==320:
        return memory(o,321,0,get(o,LO+32)+GABI,3,FRAME+256+word(s,80)+get(o,FRAME+88),get(o,FRAME+96))
    if phase==321:
        size=256+word(s,80)+get(o,FRAME+88)+get(o,FRAME+96)
        put(o,FRAME+104,1)
        store(o,FRAME+size,47)
        put(o,FRAME_N,size+1)
        return invoke_generation(o,307)
    if phase==330:
        if identity_ok(o)==0 or get(o,IOUT+80)!=get(o,GO+104):
            return feedback(o,9)
        pn=get(w,224)
        n=get(o,GO+104)
        copy(o,FRAME,w,DIRECTORY,pn)
        store(o,FRAME+pn,47)
        put(o,FRAME+pn+1,7598805615236769127)
        store(o,FRAME+pn+9,111)
        store(o,FRAME+pn+10,110)
        store(o,FRAME+pn+11,45)
        within(o,FRAME+pn+12,IOUT+1536,n)
        store(o,FRAME+pn+12+n,46)
        store(o,FRAME+pn+13+n,115)
        store(o,FRAME+pn+14+n,111)
        put(o,FRESH,pn+15+n)
        return memory(o,331,3,FRAME,0,get(o,GO+32)+GPATH,get(o,FRESH))
    if phase==331:
        return memory(o,332,3,FRESH,0,get(o,GO+32)+GCTRL+160,8)
    if phase==332:
        return again(o,get(o,AFTER_GEN))
    if phase==340:
        sub=get(o,STATE_O+248)
        put(o,SUBOP,sub)
        if sub==0:
            put(o,STATE_O+280,1)
            return feedback(o,0)
        return generation_op(o,345,5)
    if phase==345:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        if get(o,GOUT+16)==6:
            return generation_op(o,342,6)
        return generation_op(o,341,4)
    if phase==341:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        if get(o,GOUT+8)==8 and get(o,GOUT+16)==6:
            return generation_op(o,342,6)
        return again(o,342)
    if phase==342:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        within(o,RETIRE_RESULT,GOUT,4096)
        identity_request(o,12,0)
        return identity_call(o,344)
    if phase==343:
        if get(o,GOUT)!=GENREP or get(o,FEEDBACK)!=get(o,GOUT+8):
            return feedback(o,9)
        if get(o,GOUT+8)==8 and get(o,GOUT+16)==6:
            return generation_op(o,342,6)
        return again(o,342)
    if phase==344:
        if identity_ok(o)==0:
            return feedback(o,9)
        put(o,STATE_O+216,choose((get(o,RETIRE_RESULT+1688)&8)!=0,1,0))
        return feedback(o,get(o,RETIRE_RESULT+8))
    if phase>=350 and phase<370:
        return generation_release(o,w,phase)
    return result(o,w,9)

def load_generation(o:mutbuf,w:mutbuf,next:u64) -> u32:
    slot=get(o,SLOT)
    if slot>=64 or get(w,SLOTS+slot*16)==0:
        return feedback(o,1)
    put(o,GEN,get(w,SLOTS+slot*16))
    return memory(o,next,0,get(o,GEN),3,GO,256)

def begin_generation(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    raw=word(s,80)
    zero(o,FRAME,256)
    put(o,FRAME,GENREQ)
    put(o,FRAME+16,get(w,64))
    put(o,FRAME+24,get(w,72))
    put(o,FRAME+32,get(w,80))
    put(o,FRAME+40,get(w,192))
    put(o,FRAME+48,get(o,NOW)+120000000000)
    put(o,FRAME+56,get(o,NOW)+60000000000)
    put(o,FRAME+64,get(w,208))
    put(o,FRAME+72,choose(get(o,OP)==0,1,0))
    put(o,FRAME+80,raw)
    copy(o,FRAME+128,w,96,96)
    copy_input(s,256,o,FRAME+256,raw)
    if get(o,OP)==0:
        put(o,FRAME+104,1)
        store(o,FRAME+256+raw,47)
        put(o,FRAME_N,257+raw)
        return invoke_generation(o,307)
    # Baseline is immutable and retained for the whole runtime lifetime.
    put(o,AFTER_MEMORY,307)
    return memory(o,318,0,get(w,SLOTS),3,LO,256)

def generation_op(o:mutbuf,next:u64,op:u64) -> u32:
    zero(o,FRAME,256)
    put(o,FRAME,GENREQ)
    put(o,FRAME+8,op)
    put(o,FRAME_N,256)
    return invoke_generation(o,next)

def invoke_generation(o:mutbuf,next:u64) -> u32:
    return role(o,next,12,3,FRAME,get(o,FRAME_N),3,GOUT,4096,0,get(o,GO+32),GW)

def take_generation_identity(o:mutbuf,w:mutbuf) -> u64:
    within(o,GO+80,IOUT+24,24)
    put(o,GO+104,get(o,IOUT+48))
    put(o,GO+112,get(o,IOUT+16))
    put(w,SLOTS+get(o,SLOT)*16+8,get(o,IOUT+16))
    return 0

def identity(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if identity_ok(o)==0:
            return feedback(o,4)
        put(o,STATE_O+304,get(o,IOUT+16))
        return feedback(o,0)
    if phase==410:
        if identity_ok(o)==0:
            return feedback(o,4)
        put(o,STATE_O+304,get(o,IOUT+16))
        if get(o,STATE_O+248)==1:
            identity_request(o,3,0)
            return identity_call(o,411)
        return feedback(o,0)
    if phase==411:
        return feedback(o,choose(identity_ok(o)==1,0,9))
    return result(o,w,9)

def identity_request(o:mutbuf,op:u64,selector:u64) -> u64:
    zero(o,IREQ,64)
    put(o,IREQ,IDREQ)
    put(o,IREQ+8,op)
    put(o,IREQ+16,selector)
    return 0

def identity_call(o:mutbuf,next:u64) -> u32:
    return role(o,next,13,3,IREQ,64,3,IOUT,4096,1,IDENTITY,32768)

def identity_ok(o:mutbuf) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,IOUT)==IDREP and get(o,IOUT+8)==0,1,0)

def clock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    return system(o,900,228,12,1,TIME,0,0,0,0)

def completing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,900,228,12,1,TIME,0,0,0,0)
        if raw!=0 or get(o,TIME+8)>=1000000000 or get(o,TIME)>18446744073:
            return feedback(o,6)
        now=get(o,TIME)*1000000000+get(o,TIME+8)
        if now>NONE-120000000000:
            return feedback(o,6)
        put(o,NOW,now)
        put(o,STATE_O+176,now)
        return again(o,get(o,NEXT))
    if phase>=902 and phase<940:
        return completion_cleanup(o,w,phase)
    if phase>=970 and phase<990:
        return release_lease(o,w,phase)
    if phase>=940 and phase<960:
        return measure_phase(s,o,w,phase)
    return result(o,w,9)

def finish_call(o:mutbuf,w:mutbuf) -> u32:
    if get(o,PROVISIONAL)==3 and get(o,LEASE)!=0:
        return private_lock(o,1,264,970)
    if get(o,PROVISIONAL)!=0 and get(o,LEASE)!=0:
        return again(o,922)
    if get(o,LOCAL_TOKEN)!=0:
        zero(o,TOKEN_INPUT,64)
        put(o,TOKEN_INPUT,FUTURE)
        put(o,TOKEN_INPUT+8,10)
        return role(o,910,16,3,TOKEN_INPUT,64,3,TOKEN_OUTPUT,512,0,get(o,LOCAL_TOKEN),512)
    if get(o,OP)==0 and get(o,STATE_O+120)!=0 and get(w,SLOTS)!=0 and get(w,COOR+512)==0:
        put(o,INITIAL_FAILURE,get(o,STATE_O+120))
        return detach_generation(o,w,902,0)
    if get(o,OP)==12 and get(o,LEASE)!=0:
        return private_lock(o,1,264,970)
    if get(o,OP)==13:
        return finish_context(o,w)
    return result(o,w,get(o,STATE_O+120))

def finish_context(o:mutbuf,w:mutbuf) -> u32:
    if get(w,272)!=0 or get(w,280)!=0 or get(w,312)!=0 or get(w,COOR+80)!=0 or get(w,COOR+88)!=0:
        return result(o,w,5)
    if get(w,DMETA)!=0 and (get(w,DOUTPUT+40)&1)==0:
        return result(o,w,5)
    if get(w,IDENTITY+30000)!=0:
        identity_request(o,11,0)
        return identity_call(o,930)
    return again(o,930)

def completion_cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==902:
        put(o,INDEX,0)
        return again(o,920)
    if phase==910:
        if get(o,FEEDBACK)!=0 or get(o,TOKEN_OUTPUT+8)!=0:
            put(w,320,get(o,LOCAL_TOKEN))
            put(o,LOCAL_TOKEN,0)
            return result(o,w,9)
        return deallocate(o,911,get(o,LOCAL_TOKEN))
    if phase==911:
        put(o,LOCAL_TOKEN,0)
        put(o,TOKEN,0)
        return finish_call(o,w)
    if phase==920:
        index=get(o,INDEX)
        if index==3:
            if get(w,COOR)==0:
                zero(w,0,WORK)
            return result(o,w,get(o,INITIAL_FAILURE))
        fd=get(w,64+index*8)
        put(w,64+index*8,NONE)
        put(o,INDEX,index+1)
        if fd!=NONE and fd>=3 and fd<=2147483647:
            return system(o,921,3,0,fd,0,0,0,0,0)
        return again(o,920)
    if phase==921:
        return again(o,920)
    if phase==922:
        if get(o,LO+160)!=0:
            identity_request(o,8,0)
            within(o,IREQ+24,LO+160,24)
            return identity_call(o,923)
        return again(o,924)
    if phase==923:
        if identity_ok(o)==0:
            put(w,312,1)
            put(w,296,get(o,LEASE))
            put(o,PROVISIONAL,0)
            return result(o,w,9)
        zero(o,LO+160,32)
        return again(o,924)
    if phase==924:
        if get(o,LO+192)!=0:
            identity_request(o,8,0)
            within(o,IREQ+24,LO+192,24)
            return identity_call(o,925)
        return again(o,926)
    if phase==925:
        if identity_ok(o)==0:
            put(w,312,1)
            put(w,296,get(o,LEASE))
            put(o,PROVISIONAL,0)
            return result(o,w,9)
        zero(o,LO+192,32)
        return again(o,926)
    if phase==926:
        return deallocate(o,927,get(o,LEASE))
    if phase==927:
        put(o,LEASE,0)
        put(o,PROVISIONAL,0)
        return finish_call(o,w)
    if phase==930:
        if get(w,IDENTITY+30000)!=0 and identity_ok(o)==0:
            return result(o,w,5)
        put(o,INDEX,0)
        return again(o,931)
    if phase==931:
        index=get(o,INDEX)
        if index==3:
            zero(w,0,WORK)
            return result(o,w,0)
        fd=get(w,64+index*8)
        put(w,64+index*8,NONE)
        put(o,INDEX,index+1)
        if fd!=NONE and fd>=3 and fd<=2147483647:
            return system(o,932,3,0,fd,0,0,0,0,0)
        return again(o,931)
    if phase==932:
        return again(o,931)
    return result(o,w,9)

def release_lease(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==970:
        return memory(o,971,0,get(o,LEASE),3,LO,256)
    if phase==971:
        if get(o,PROVISIONAL)!=3 and get(o,LO+136)!=2:
            put(o,ERROR,5)
            return private_lock(o,2,264,982)
        put(o,GEN,get(o,LO+48))
        return memory(o,972,0,get(o,GEN),3,GO,256)
    if phase==972:
        previous=get(o,LO+24)
        next=get(o,LO+16)
        put(o,TEMP_PTR,next)
        if previous==0:
            put(w,280,next)
            return again(o,973)
        return memory(o,973,3,TEMP_PTR,0,previous+16,8)
    if phase==973:
        next=get(o,LO+16)
        if next!=0:
            put(o,TEMP_PTR,get(o,LO+24))
            return memory(o,974,3,TEMP_PTR,0,next+24,8)
        return again(o,974)
    if phase==974:
        previous=get(o,LO+40)
        next=get(o,LO+32)
        put(o,TEMP_PTR,next)
        if previous==0:
            put(o,GO+64,next)
            return memory(o,975,3,GO+64,0,get(o,GEN)+64,8)
        return memory(o,975,3,TEMP_PTR,0,previous+32,8)
    if phase==975:
        next=get(o,LO+32)
        if next!=0:
            put(o,TEMP_PTR,get(o,LO+40))
            return memory(o,976,3,TEMP_PTR,0,next+40,8)
        return again(o,976)
    if phase==976:
        identity_request(o,8,0)
        within(o,IREQ+24,LO+160,24)
        return identity_call(o,977)
    if phase==977:
        if identity_ok(o)==0:
            put(w,312,1)
            put(o,ERROR,9)
            return private_lock(o,2,264,982)
        identity_request(o,8,0)
        within(o,IREQ+24,LO+192,24)
        return identity_call(o,978)
    if phase==978:
        if identity_ok(o)==0:
            put(w,312,1)
            put(o,ERROR,9)
            return private_lock(o,2,264,982)
        return deallocate(o,979,get(o,LEASE))
    if phase==979:
        put(o,LEASE,0)
        if get(o,GO+72)==0 and get(o,GO+64)==0:
            put(o,AFTER_GEN,981)
            return again(o,350)
        return private_lock(o,2,264,981)
    if phase==981:
        if get(o,PROVISIONAL)==3:
            put(o,PROVISIONAL,0)
            return finish_call(o,w)
        return result(o,w,get(o,STATE_O+120))
    if phase==982:
        return result(o,w,get(o,ERROR))
    return result(o,w,9)

def result(o:mutbuf,w:mutbuf,status:u64) -> u32:
    if get(o,D_FAILED)==0 and (get(o,D_GCAP)!=0 or get(o,D_ECAP)!=0 or (status!=0 and get(o,D_PTR)!=0)):
        put(o,D_ERROR,status)
        return again(o,1190)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,STATE_O+120))
    put(o,24,get(o,STATE_O+104))
    put(o,32,get(w,COOR+48))
    put(o,40,get(o,STATE_O+136))
    put(o,48,get(w,COOR+40))
    put(o,56,get(w,COOR+88))
    put(o,64,get(o,LEASE))
    put(o,72,get(o,NATIVE_ERROR))
    put(o,80,choose(get(o,LEASE)!=0,get(o,LO+72),0))
    put(o,88,choose(get(o,LEASE)!=0,get(o,LO+80),0))
    put(o,96,get(o,RESULT))
    put(o,104,get(o,RESULT+8))
    put(o,112,get(o,RESULT+256))
    put(o,120,RESULT+264)
    put(o,128,get(o,RESULT+320))
    put(o,136,get(o,RESULT+328))
    put(o,144,get(o,D_PTR))
    put(o,152,get(o,D_LEN))
    return 0

def start_retention(o:mutbuf,w:mutbuf) -> u32:
    put(o,SUBOP,get(o,STATE_O+248))
    if get(o,OP)==4 or get(o,OP)==5 or get(o,OP)==6 or get(o,OP)==12:
        put(o,GEN,get(o,LO+48))
    else:
        slot=get(o,STATE_O+168)
        put(o,SLOT,slot)
        if slot>=64 or get(w,SLOTS+slot*16)==0:
            return feedback(o,1)
        put(o,GEN,get(w,SLOTS+slot*16))
    if get(o,SUBOP)==1 and get(o,PROVISIONAL)==1:
        return activate_lease(o,w)
    return generation_lock(o,1,508)

def generation_lock(o:mutbuf,action:u64,next:u64) -> u32:
    put(o,LOCK_MODE,1)
    put(o,LOCK_RESUME,next)
    put(o,LOCK_OFFSET,get(o,GEN)+160)
    put(o,LOCK_ACTION,action)
    if action==1:
        return atomic(o,100,2,get(o,LOCK_OFFSET),0,1)
    return atomic(o,102,3,get(o,LOCK_OFFSET),0,0)

def retention_done(o:mutbuf,value:u64) -> u32:
    if value>=4294967280:
        put(o,NATIVE_ERROR,value)
    put(o,RET_RESULT,value)
    put(o,RET_HELD,0)
    return generation_lock(o,2,509)

def retention(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==508:
        put(o,RET_HELD,1)
        return memory(o,500,0,get(o,GEN),3,GO,256)
    if phase==509:
        raw=get(o,RET_RESULT)
        if raw==0 and get(o,SUBOP)==1:
            put(o,PROVISIONAL,0)
        return feedback(o,raw)
    if phase==500:
        zero(o,RINPUT,64)
        put(o,RINPUT,RETAIN)
        put(o,RINPUT+8,get(o,SUBOP))
        put(o,RINPUT+16,get(o,GO+120))
        put(o,RINPUT+24,get(o,GO+128))
        if get(o,SUBOP)==1 or get(o,SUBOP)==2 or get(o,SUBOP)==6:
            put(o,RINPUT+32,get(o,LO+72))
            put(o,RINPUT+40,get(o,LO+80))
            return role(o,501,15,3,RINPUT,64,0,get(o,LEASE)+96,64,0,get(o,GO+40),get(o,GO+48))
        if get(o,SUBOP)==4:
            put(o,RINPUT+32,get(o,GO+120))
            put(o,RINPUT+40,get(o,GO+128))
        zero(o,ROUT,64)
        return role(o,501,15,3,RINPUT,64,3,ROUT,64,0,get(o,GO+40),get(o,GO+48))
    if phase==501:
        raw=get(o,FEEDBACK)
        if raw==4294967288 and get(o,SUBOP)==1:
            n=get(o,GO+48)
            if n>=NONE-1:
                return retention_done(o,4)
            put(o,FRESH,n+1)
            return allocate(o,502,n+1)
        return retention_done(o,raw)
    if phase==502:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return retention_done(o,4)
        put(o,TEMP_PTR,ptr)
        store(o,ROUT,0)
        return memory(o,503,3,ROUT,0,ptr+get(o,FRESH)-1,1)
    if phase==503:
        return memory(o,504,0,get(o,GO+40),0,get(o,TEMP_PTR),get(o,GO+48))
    if phase==504:
        old=get(o,GO+40)
        put(o,GO+40,get(o,TEMP_PTR))
        put(o,GO+48,get(o,FRESH))
        put(o,TEMP_PTR,old)
        return memory(o,505,3,GO+40,0,get(o,GEN)+40,16)
    if phase==505:
        if get(o,TEMP_PTR)!=get(o,GEN)+256:
            return deallocate(o,506,get(o,TEMP_PTR))
        return again(o,506)
    if phase==506:
        return again(o,500)
    return result(o,w,9)

def start_lease(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,ACTION)==31:
        put(o,SLOT,get(o,STATE_O+168))
        return load_generation(o,w,600)
    return private_lock(o,1,264,622)

def leases(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        return allocate(o,601,256)
    if phase==601:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return feedback(o,4)
        put(o,LEASE,ptr)
        put(o,PROVISIONAL,1)
        zero(o,LO,256)
        put(o,LO,LOBJ)
        put(o,LO+8,get(w,8))
        put(o,LO+48,get(o,GEN))
        put(o,LO+56,get(o,SLOT))
        put(o,LO+64,get(o,GO+112))
        put(o,INDEX,0)
        return system(o,602,318,3,LO+72,16,0,0,0,0)
    if phase==602:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,602,318,3,LO+72+get(o,INDEX),16-get(o,INDEX),0,0,0,0)
        used=get(o,INDEX)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return deallocate(o,619,get(o,LEASE))
        used=used+raw
        put(o,INDEX,used)
        if used<16:
            return system(o,602,318,3,LO+72+used,16-used,0,0,0,0)
        if get(o,LO+72)==0 and get(o,LO+80)==0:
            return deallocate(o,619,get(o,LEASE))
        identity_request(o,5,get(o,SLOT))
        return identity_call(o,603)
    if phase==603:
        if identity_ok(o)==0:
            return deallocate(o,619,get(o,LEASE))
        within(o,LO+160,IOUT+24,24)
        put(o,LO+184,get(o,IOUT+48))
        identity_request(o,5,64)
        return identity_call(o,604)
    if phase==604:
        if identity_ok(o)==0:
            identity_request(o,8,0)
            within(o,IREQ+24,LO+160,24)
            return identity_call(o,618)
        within(o,LO+192,IOUT+24,24)
        put(o,LO+216,get(o,IOUT+48))
        return memory(o,605,3,LO,0,get(o,LEASE),256)
    if phase==605:
        put(o,STATE_O+200,get(o,SLOT))
        put(o,STATE_O+272,get(o,GO+112))
        return feedback(o,0)
    if phase==608:
        return memory(o,609,0,get(o,GEN),3,GO,256)
    if phase==609:
        put(o,LO+16,get(w,280))
        put(o,LO+32,get(o,GO+64))
        put(o,LO+224,1)
        return memory(o,610,3,LO,0,get(o,LEASE),96)
    if phase==610:
        return memory(o,611,3,LO+224,0,get(o,LEASE)+224,8)
    if phase==611:
        put(w,280,get(o,LEASE))
        if get(o,LO+16)!=0:
            put(o,TEMP_PTR,get(o,LEASE))
            return memory(o,612,3,TEMP_PTR,0,get(o,LO+16)+24,8)
        return again(o,612)
    if phase==612:
        if get(o,LO+32)!=0:
            put(o,TEMP_PTR,get(o,LEASE))
            return memory(o,613,3,TEMP_PTR,0,get(o,LO+32)+40,8)
        return again(o,613)
    if phase==613:
        put(o,GO+64,get(o,LEASE))
        return memory(o,614,3,GO+64,0,get(o,GEN)+64,8)
    if phase==614:
        return private_lock(o,2,264,615)
    if phase==615:
        # Publish only ownership links before charging the lease count. A
        # failed count allocation can then unlink this uncharged object; no
        # fallible registry acquisition remains after the count is committed.
        put(o,PROVISIONAL,3)
        return generation_lock(o,1,508)
    if phase==618:
        return deallocate(o,619,get(o,LEASE))
    if phase==619:
        put(o,PROVISIONAL,0)
        put(o,LEASE,0)
        return feedback(o,4)
    if phase==620:
        pointer=get(o,TEMP_PTR)
        if pointer==0:
            put(o,ERROR,1)
            return private_lock(o,2,264,624)
        return memory(o,621,0,pointer,3,LO,256)
    if phase==621:
        if get(o,LO)!=LOBJ or get(o,LO+8)!=get(w,8):
            put(o,ERROR,9)
            return private_lock(o,2,264,624)
        if get(o,TEMP_PTR)==word(s,16):
            if get(o,LO+72)!=word(s,24) or get(o,LO+80)!=word(s,32):
                put(o,ERROR,1)
                return private_lock(o,2,264,624)
            put(o,LEASE,get(o,TEMP_PTR))
            put(o,STATE_O+200,get(o,LO+56))
            put(o,STATE_O+272,get(o,LO+64))
            put(o,GEN,get(o,LO+48))
            put(o,ERROR,0)
            return private_lock(o,2,264,624)
        put(o,TEMP_PTR,get(o,LO+16))
        return again(o,620)
    if phase==622:
        put(o,TEMP_PTR,get(w,280))
        return again(o,620)
    if phase==624:
        return feedback(o,get(o,ERROR))
    if phase==630:
        return read_call_abi(s,o,w)
    if phase==631:
        return find_call_function(s,o,w)
    if phase==632:
        if get(o,FEEDBACK)!=152:
            put(o,NATIVE_ERROR,get(o,FEEDBACK))
            return feedback(o,1)
        return call_actual(o,w)
    if phase==635:
        put(o,PHASE,633)
        put(o,0,get(o,TEMP_PTR))
        put(o,8,get(o,CALL_O+8))
        put(o,16,CALL_O+24)
        return 21
    if phase==633:
        put(o,CALL_W,1)
        put(o,CALL_W+160,get(o,FEEDBACK))
        return role(o,634,17,3,0,0,3,CALL_O,152,3,CALL_W,512)
    if phase==634:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>22:
            return feedback(o,1)
        put(o,RESULT+256,raw)
        within(o,RESULT+264,CALL_O,raw)
        return feedback(o,0)
    return result(o,w,9)

def activate_lease(o:mutbuf,w:mutbuf) -> u32:
    return private_lock(o,1,264,608)

def native_call(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    return memory(o,630,0,get(o,LO+48),3,GO,256)

def read_call_abi(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,GO+152)!=1:
        return feedback(o,1)
    return memory(o,631,0,get(o,GO+32)+GABI,3,FRAME,5136)

def find_call_function(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=word(s,96)
    at=256+word(s,80)+word(s,88)
    count=get(o,FRAME+8)
    if count==0 or count>16:
        return feedback(o,9)
    i=0
    found=False
    while i<count and found==False:
        row=FRAME+16+i*320
        if get(o,row+8)==n:
            k=0
            same=True
            while k<n:
                if byte(s,at+k)!=byte(o,row+32+k):
                    same=False
                k=k+1
            if same:
                found=True
        if found==False:
            i=i+1
    if found==False:
        put(o,NATIVE_ERROR,1)
        return feedback(o,1)
    row=FRAME+16+i*320
    zero(o,CALL_W,512)
    put(o,CALL_W+8,get(o,row+16))
    put(o,CALL_W+16,get(o,row+24))
    within(o,CALL_W+24,row+160,128)
    put(o,INDEX,i)
    return role(o,632,17,2,at+n,word(s,104),3,CALL_O,152,3,CALL_W,512)

def call_actual(o:mutbuf,w:mutbuf) -> u32:
    put(o,AFTER_MEMORY,633)
    return memory(o,635,0,get(o,GO+32)+2048+get(o,INDEX)*8,3,TEMP_PTR,8)

def start_token(o:mutbuf,w:mutbuf) -> u32:
    if get(o,ACTION)==38:
        return allocate(o,800,512)
    if get(o,TOKEN)==0:
        return feedback(o,1)
    return read_token(o,810)

def read_token(o:mutbuf,next:u64) -> u32:
    return memory(o,next,0,get(o,TOKEN),3,TOKEN_OUTPUT,96)

def token_observed(o:mutbuf,w:mutbuf) -> u32:
    if get(o,TOKEN_OUTPUT)!=FUTURE_STATE or get(o,TOKEN_OUTPUT+8)!=get(w,8) or get(o,TOKEN_OUTPUT+80)!=0 or get(o,TOKEN_OUTPUT+64)>2:
        return feedback(o,1)
    value=get(o,TOKEN_OUTPUT+64)
    put(o,STATE_O+184,choose(value==1,1,0))
    put(o,STATE_O+192,choose(value==2,1,0))
    return feedback(o,0)

def token(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==800:
        pointer=get(o,FEEDBACK)
        if pointer==0:
            return feedback(o,4)
        put(o,TOKEN,pointer)
        put(o,LOCAL_TOKEN,pointer)
        zero(o,TOKEN_OUTPUT,512)
        return memory(o,801,3,TOKEN_OUTPUT,0,pointer,512)
    if phase==801:
        zero(o,TOKEN_INPUT,64)
        put(o,TOKEN_INPUT,FUTURE)
        return role(o,802,16,3,TOKEN_INPUT,64,3,TOKEN_OUTPUT,512,0,get(o,TOKEN),512)
    if phase==802:
        if get(o,FEEDBACK)!=0 or get(o,TOKEN_OUTPUT+8)!=0:
            return feedback(o,4)
        put(o,STATE_O+80,get(o,TOKEN))
        return feedback(o,0)
    if phase==810:
        if get(o,TOKEN_OUTPUT)!=FUTURE_STATE or get(o,TOKEN_OUTPUT+8)!=get(w,8) or get(o,TOKEN_OUTPUT+80)!=0:
            return feedback(o,1)
        sub=get(o,STATE_O+248)
        if sub==0:
            return token_observed(o,w)
        if sub==1:
            put(o,TEMP_PTR,2)
            return memory(o,811,3,TEMP_PTR,0,get(o,TOKEN)+64,8)
        put(o,TEMP_PTR,1)
        return memory(o,813,3,TEMP_PTR,0,get(o,TOKEN)+64,8)
    if phase==811:
        put(o,STATE_O+192,1)
        identity_request(o,3,0)
        return identity_call(o,812)
    if phase==812:
        return feedback(o,choose(identity_ok(o)==1,0,9))
    if phase==813:
        put(o,STATE_O+184,1)
        return feedback(o,0)
    return result(o,w,9)

def detach_generation(o:mutbuf,w:mutbuf,next:u64,slot:u64) -> u32:
    put(o,AFTER_GEN,next)
    if slot>=64:
        return coordinator_failure(o,27)
    if get(w,SLOTS+slot*16)==0:
        return again(o,next)
    put(o,GEN,get(w,SLOTS+slot*16))
    return private_lock(o,1,264,350)

def generation_release(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==350:
        return memory(o,351,0,get(o,GEN),3,GO,256)
    if phase==351:
        slot=get(o,GO+56)
        if slot<64 and get(w,SLOTS+slot*16)==get(o,GEN):
            put(w,SLOTS+slot*16,0)
            put(w,SLOTS+slot*16+8,0)
        put(o,GO+72,0)
        return memory(o,352,3,GO+72,0,get(o,GEN)+72,8)
    if phase==352:
        if get(o,GO+64)!=0:
            return private_lock(o,2,264,get(o,AFTER_GEN))
        if get(o,GO+32)!=0:
            return system(o,353,11,0,get(o,GO+32),GW,0,0,0,0)
        put(o,FEEDBACK,0)
        return again(o,353)
    if phase==353:
        if get(o,FEEDBACK)!=0:
            put(w,312,1)
            put(o,NATIVE_ERROR,get(o,FEEDBACK))
            return private_lock(o,2,264,get(o,AFTER_GEN))
        put(o,GO+32,0)
        return memory(o,359,3,GO+32,0,get(o,GEN)+32,8)
    if phase==359:
        if get(o,GO+80)!=0:
            identity_request(o,8,0)
            within(o,IREQ+24,GO+80,24)
            return identity_call(o,354)
        put(o,FEEDBACK,0)
        return again(o,354)
    if phase==354:
        if get(o,GO+80)!=0 and identity_ok(o)==0:
            put(w,312,1)
            return private_lock(o,2,264,get(o,AFTER_GEN))
        if get(o,GO+40)!=get(o,GEN)+256:
            return deallocate(o,355,get(o,GO+40))
        return again(o,355)
    if phase==355:
        previous=get(o,GO+24)
        following=get(o,GO+16)
        put(o,TEMP_PTR,following)
        if previous==0:
            put(w,272,following)
            return again(o,356)
        return memory(o,356,3,TEMP_PTR,0,previous+16,8)
    if phase==356:
        following=get(o,GO+16)
        if following!=0:
            put(o,TEMP_PTR,get(o,GO+24))
            return memory(o,357,3,TEMP_PTR,0,following+24,8)
        return again(o,357)
    if phase==357:
        return deallocate(o,358,get(o,GEN))
    if phase==358:
        put(o,GEN,0)
        return private_lock(o,2,264,get(o,AFTER_GEN))
    return result(o,w,9)

def artifact_path(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,AFTER_GEN,next)
    pn=get(w,224)
    digits=get(o,GO+104)
    if digits==0 or pn>4095 or digits>4095-pn or pn+digits>4080:
        put(o,NATIVE_ERROR,36)
        return feedback(o,1)
    identity_request(o,13,0)
    within(o,IREQ+24,GO+80,24)
    return role(o,330,13,3,IREQ,64,3,IOUT,8192,1,IDENTITY,32768)


def directory(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        put(o,INDEX,0)
        return system(o,701,318,3,ROUT,16,0,0,0,0)
    if phase==701:
        raw=get(o,FEEDBACK)
        used=get(o,INDEX)
        if raw==NONE-3:
            return system(o,701,318,3,ROUT+used,16-used,0,0,0,0)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return feedback(o,6)
        used=used+raw
        put(o,INDEX,used)
        if used<16:
            return system(o,701,318,3,ROUT+used,16-used,0,0,0,0)
        if directory_name(o,w)==0:
            put(w,DMETA+32,0-36)
            return feedback(o,6)
        directory_request(o,w,0,0)
        put(w,DINPUT+32,1)
        within(w,DINPUT+128,DIRECTORY,get(w,224))
        put(o,DINPUT_N,128+get(w,224))
        return directory_submit(o,702)
    if phase==702:
        put(w,DMETA,1)
        return system(o,703,83,1,DIRECTORY,448,0,0,0,0)
    if phase==703:
        raw=get(o,FEEDBACK)
        if raw!=0:
            put(w,DMETA+32,raw)
            return feedback(o,6)
        put(w,240,1)
        return system(o,704,262,20,NONE-99,DIRECTORY,DIR_STAT,256,0,0)
    if phase==704:
        if get(o,FEEDBACK)!=0:
            put(w,DMETA+32,get(o,FEEDBACK))
            return feedback(o,6)
        directory_request(o,w,2,0)
        put(w,DINPUT+32,1)
        put(w,DINPUT+40,get(w,DIR_STAT))
        put(w,DINPUT+48,get(w,DIR_STAT+8))
        return directory_submit(o,705)
    if phase==705:
        put(o,DTOKEN,get(w,DOUTPUT+24))
        return system(o,706,257,4,NONE-99,DIRECTORY,2818048,0,0,0)
    if phase==706:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,706,257,4,NONE-99,DIRECTORY,2818048,0,0,0)
        if raw>=NEGATIVE:
            put(w,DMETA+32,raw)
            directory_request(o,w,5,get(o,DTOKEN))
            return directory_submit(o,713)
        put(w,232,raw)
        directory_request(o,w,3,get(o,DTOKEN))
        put(w,DINPUT+32,raw)
        return directory_submit(o,707)
    if phase==707:
        return system(o,708,5,4,get(w,232),DIR_FDSTAT,0,0,0,0)
    if phase==708:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,708,5,4,get(w,232),DIR_FDSTAT,0,0,0,0)
        if raw!=0:
            put(w,DMETA+32,raw)
            directory_request(o,w,5,get(o,DTOKEN))
            return directory_submit(o,713)
        return system(o,709,262,20,NONE-99,DIRECTORY,DIR_STAT,256,0,0)
    if phase==709:
        if get(o,FEEDBACK)!=0:
            put(w,DMETA+32,get(o,FEEDBACK))
            directory_request(o,w,5,get(o,DTOKEN))
            return directory_submit(o,713)
        directory_request(o,w,4,get(o,DTOKEN))
        put(w,DINPUT+32,get(w,DIR_FDSTAT))
        put(w,DINPUT+40,get(w,DIR_FDSTAT+8))
        put(w,DINPUT+48,get(w,DIR_FDSTAT+24))
        put(w,DINPUT+56,get(w,DIR_STAT))
        put(w,DINPUT+64,get(w,DIR_STAT+8))
        return directory_submit(o,710)
    if phase==710:
        identity_request(o,0,0)
        return identity_call(o,714)
    if phase==713:
        return feedback(o,6)
    if phase==714:
        if identity_ok(o)==0:
            return feedback(o,4)
        identity_request(o,5,0)
        return identity_call(o,715)
    if phase==715:
        if identity_ok(o)==0:
            return feedback(o,4)
        put(o,SLOT,0)
        take_generation_identity(o,w)
        put(o,STATE_O+304,get(o,IOUT+16))
        return memory(o,716,3,GO+80,0,get(o,GEN)+80,40)
    if phase==716:
        identity_request(o,7,64)
        return identity_call(o,717)
    if phase==717:
        if identity_ok(o)==0:
            return feedback(o,9)
        put(w,COOR+40,get(o,IOUT+16))
        put(w,304,1)
        return feedback(o,0)
    if phase>=750 and phase<790:
        return directory_cleanup(s,o,w,phase)
    if phase==790:
        put(w,DINPUT+24,get(o,NOW))
        return role(o,791,19,1,DINPUT,get(o,DINPUT_N),1,DOUTPUT,64,1,DSTATE,4608)
    if phase==791:
        if get(o,FEEDBACK)!=64 or get(w,DOUTPUT)!=DREP:
            return feedback(o,9)
        if get(w,DOUTPUT+8)!=0:
            put(w,DMETA+40,get(w,DOUTPUT+8))
            return feedback(o,6)
        return again(o,get(o,DNEXT))
    return result(o,w,9)

def directory_cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==750:
        put(o,DMODE,0)
        return directory_observe(o,w)
    if phase==751:
        raw=get(o,FEEDBACK)
        directory_request(o,w,9,0)
        if raw==0:
            put(w,DINPUT+40,get(w,DIR_STAT))
            put(w,DINPUT+48,get(w,DIR_STAT+8))
            put(w,DINPUT+56,get(w,DIR_STAT+24))
        else:
            put(w,DINPUT+32,choose(raw==NONE-1,1,2))
            if raw!=NONE-1:
                put(w,DMETA+32,raw)
        return directory_submit(o,752)
    if phase==752:
        put(o,DTOKEN,get(w,DOUTPUT+24))
        if get(w,DOUTPUT+16)==3:
            return system(o,753,5,4,get(w,DOUTPUT+32),DIR_FDSTAT,0,0,0,0)
        return directory_decide(o,w)
    if phase==753:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,753,5,4,get(w,DOUTPUT+32),DIR_FDSTAT,0,0,0,0)
        directory_request(o,w,10,get(o,DTOKEN))
        if raw==0:
            put(w,DINPUT+40,get(w,DIR_FDSTAT))
            put(w,DINPUT+48,get(w,DIR_FDSTAT+8))
        else:
            put(w,DINPUT+32,choose(raw==NONE-1,1,2))
            if raw!=NONE-1:
                put(w,DMETA+32,raw)
        return directory_submit(o,754)
    if phase==754:
        put(o,DTOKEN,get(w,DOUTPUT+24))
        return directory_decide(o,w)
    if phase==755:
        put(w,DMETA+48,get(w,DOUTPUT+32))
        if get(w,DOUTPUT+16)==6:
            put(o,DTOKEN,get(w,DOUTPUT+24))
            return system(o,756,84,1,DIRECTORY,0,0,0,0,0)
        return directory_release(o,w)
    if phase==756:
        raw=get(o,FEEDBACK)
        directory_request(o,w,12,get(o,DTOKEN))
        if raw!=0:
            put(w,DINPUT+32,choose(raw==NONE-1,1,2))
            if raw!=NONE-1:
                put(w,DMETA+32,raw)
        return directory_submit(o,757)
    if phase==757:
        put(w,DMETA+48,get(w,DOUTPUT+32))
        return directory_release(o,w)
    if phase==760:
        directory_request(o,w,6,0)
        return directory_submit(o,761)
    if phase==761:
        if get(w,DOUTPUT+16)==0:
            return feedback(o,0)
        if get(w,DOUTPUT+16)!=4:
            return feedback(o,9)
        put(o,DTOKEN,get(w,DOUTPUT+24))
        fd=get(w,DOUTPUT+32)
        put(w,232,NONE)
        return system(o,762,3,0,fd,0,0,0,0,0)
    if phase==762:
        raw=get(o,FEEDBACK)
        put(w,DMETA+56,raw)
        directory_request(o,w,7,get(o,DTOKEN))
        put(w,DINPUT+32,choose(raw==0,1,0))
        return directory_submit(o,763)
    if phase==763:
        return feedback(o,0)
    return result(o,w,9)

def directory_observe(o:mutbuf,w:mutbuf) -> u32:
    if get(w,DMETA)==0:
        if get(o,DMODE)!=0:
            return snapshot_copy(o,w)
        return feedback(o,0)
    return system(o,751,262,20,NONE-99,DIRECTORY,DIR_STAT,256,0,0)

def directory_decide(o:mutbuf,w:mutbuf) -> u32:
    if get(o,DMODE)!=0:
        return snapshot_copy(o,w)
    directory_request(o,w,11,get(o,DTOKEN))
    return directory_submit(o,755)

def directory_release(o:mutbuf,w:mutbuf) -> u32:
    if get(w,DOUTPUT+16)==8:
        directory_request(o,w,8,0)
        return directory_submit(o,760)
    return feedback(o,0)

def directory_request(o:mutbuf,w:mutbuf,event:u64,token:u64) -> u64:
    zero(w,DINPUT,128)
    put(w,DINPUT,DREQ)
    put(w,DINPUT+8,event)
    put(w,DINPUT+16,token)
    put(w,DINPUT+112,get(w,16))
    put(w,DINPUT+120,get(w,24))
    put(o,DINPUT_N,128)
    return 0

def directory_submit(o:mutbuf,next:u64) -> u32:
    put(o,DNEXT,next)
    return clock(o,790)

def directory_name(o:mutbuf,w:mutbuf) -> u64:
    n=get(w,216)
    if n>4045:
        return 0
    within(w,DIRECTORY,PARENT,n)
    if byte(w,DIRECTORY+n-1)!=47:
        store(w,DIRECTORY+n,47)
        n=n+1
    directory_prefix(w,DIRECTORY+n)
    n=n+17
    i=0
    while i<16:
        c=byte(o,ROUT+i)
        store(w,DIRECTORY+n+i*2,hexadecimal(c>>4))
        store(w,DIRECTORY+n+i*2+1,hexadecimal(c&15))
        i=i+1
    n=n+32
    store(w,DIRECTORY+n,0)
    put(w,224,n)
    return 1

def hexadecimal(n:u64) -> u64:
    return choose(n<10,48+n,87+n)

def snapshot(o:mutbuf,w:mutbuf) -> u32:
    put(o,DMODE,1)
    return directory_observe(o,w)

def snapshot_copy(o:mutbuf,w:mutbuf) -> u32:
    copy(o,FRAME,w,COOR,24576)
    copy(o,FRAME+24576,w,DSTATE,4608)
    copy(o,FRAME+29184,w,SLOTS,1024)
    put(o,RESULT+320,FRAME)
    put(o,RESULT+328,30208)
    return feedback(o,0)


def directory_prefix(w:mutbuf,at:u64) -> u64:
    put(w,at+0,8389209317657635176)
    put(w,at+8,7957695011148363369)
    store(w,at+16,45)
    return 0


def measurement(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    stage=get(o,STATE_O+168)
    put(o,MEASURE_STAGE,stage)
    if stage==0:
        return clock(o,951)
    put(o,SAVE_GEN,get(o,GEN))
    put(o,SAVE_SLOT,get(o,SLOT))
    selected=get(w,COOR+48)
    if selected>=64 or get(w,SLOTS+selected*16)==0:
        return feedback(o,1)
    return memory(o,940,0,get(w,SLOTS+selected*16),3,LO,256)

def measure_phase(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==940:
        return memory(o,941,0,get(o,LO+32)+GCTRL+256,3,26128,128)
    if phase==941:
        return memory(o,942,0,get(o,GO+32)+GCTRL+256,3,26000,128)
    if phase==942:
        return memory(o,943,0,get(o,LO+32)+GCTRL+736,3,26256,32)
    if phase==943:
        if measurement_hash(o,4,26256)==0:
            put(o,NATIVE_ERROR,choose(get(o,MEASURE_STAGE)==2,18,19))
            return feedback(o,1)
        if get(o,MEASURE_STAGE)==1:
            return memory(o,944,0,get(o,GO+32)+GCTRL+736,3,26288,32)
        if measurement_hash(o,2,26192)==0 or measurement_hash(o,3,26064)==0:
            put(o,NATIVE_ERROR,18)
            return feedback(o,1)
        return memory(o,945,0,get(o,GO+32)+GABI,3,FRAME,5136)
    if phase==944:
        if measurement_hash(o,5,26288)==0:
            put(o,NATIVE_ERROR,19)
            return feedback(o,1)
        return measure_run(s,o,w)
    if phase==945:
        node=get(o,MEAS_WORK+184)
        count=get(o,FRAME+8)
        n=get(o,MEAS_FRAME+node+8)
        if count==0 or count>16:
            return feedback(o,9)
        i=0
        while i<count:
            row=FRAME+16+i*320
            fn=get(o,row+8)
            same=fn*4==n
            j=0
            while j<fn and same:
                if read4(o,MEAS_FRAME+node+16+j*4)!=byte(o,row+32+j):
                    same=False
                j=j+1
            if same:
                return feedback(o,0)
            i=i+1
        put(o,NATIVE_ERROR,18)
        return feedback(o,1)
    if phase==951:
        return measure_run(s,o,w)
    if phase==952:
        if get(o,FEEDBACK)!=0 or get(o,MEAS_OUT)!=MREP or get(o,MEAS_OUT+56)!=1:
            return feedback(o,9)
        if get(o,MEAS_OUT+8)!=0:
            put(o,NATIVE_ERROR,get(o,MEAS_OUT+16))
            return feedback(o,1)
        if get(o,MEAS_WORK+64232)!=1:
            put(o,NATIVE_ERROR,20)
            return feedback(o,1)
        return feedback(o,0)
    return result(o,w,9)

def measure_run(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    now=get(o,STATE_O+176)
    start=get(o,STATE_O+72)
    elapsed=choose(now>=start,now-start,NONE)
    measurement_frame(s,o,elapsed)
    zero(o,MEAS_WORK,65536)
    return role(o,952,18,3,MEAS_FRAME,get(o,MEAS_N),3,MEAS_OUT,8388608,3,MEAS_WORK,262144)

def measurement_frame(s:readbuf,o:mutbuf,elapsed:u64) -> u64:
    n=word(s,112)
    zero(o,MEAS_FRAME,64)
    put(o,MEAS_FRAME,MREQ)
    put(o,MEAS_FRAME+8,n)
    at=256+word(s,80)+word(s,88)+word(s,96)+word(s,104)
    copy_input(s,at,o,MEAS_FRAME+64,n)
    size=0
    value=elapsed
    while value!=0:
        store(o,MEAS_FRAME+64+n+size,value&255)
        size=size+1
        value=value>>8
    put(o,MEAS_FRAME+24,size)
    put(o,MEAS_N,64+n+size)
    return 0

def measurement_hash(o:mutbuf,field:u64,expected:u64) -> u64:
    node=get(o,MEAS_WORK+128+field*8)
    if get(o,MEAS_FRAME+node)!=4 or get(o,MEAS_FRAME+node+8)!=256:
        return 0
    i=0
    while i<32:
        value=byte(o,expected+i)
        if read4(o,MEAS_FRAME+node+16+i*8)!=hexadecimal(value>>4) or read4(o,MEAS_FRAME+node+20+i*8)!=hexadecimal(value&15):
            return 0
        i=i+1
    return 1

def read4(o:mutbuf,at:u64) -> u64:
    return byte(o,at)|(byte(o,at+1)<<8)|(byte(o,at+2)<<16)|(byte(o,at+3)<<24)


def role(o:mutbuf,next:u64,action:u64,sk:u64,si:u64,sn:u64,ok:u64,oi:u64,on:u64,wk:u64,wi:u64,wn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,sk)
    put(o,8,si)
    put(o,16,sn)
    put(o,24,ok)
    put(o,32,oi)
    put(o,40,on)
    put(o,48,wk)
    put(o,56,wi)
    put(o,64,wn)
    return narrow(action)

def memory(o:mutbuf,next:u64,sk:u64,si:u64,tk:u64,ti:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,sk)
    put(o,8,si)
    put(o,16,tk)
    put(o,24,ti)
    put(o,32,n)
    return 8

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

def atomic(o:mutbuf,next:u64,action:u64,ptr:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)

def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6

def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def copy(o:mutbuf,to:u64,s:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0

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

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def narrow(n:u64) -> u32:
    return n

def canonical_decimal(s:readbuf,at:u64,n:u64) -> u64:
    if n==0 or (n>1 and byte(s,at)==48):
        return 0
    i=0
    while i<n:
        c=byte(s,at+i)
        if c<48 or c>57:
            return 0
        i=i+1
    return 1

def bg_snapshot(o:mutbuf,w:mutbuf) -> u32:
    zero(o,D_REPLY,256)
    put(o,D_REPLY,BG_MAGIC)
    put(o,D_REPLY+16,choose(get(w,COOR+24)!=0,1,0))
    if get(w,SLOTS)!=0:
        put(o,D_REPLY+16,get(o,D_REPLY+16)|2)
        return memory(o,1100,0,get(w,SLOTS),3,GO,256)
    return again(o,1103)

def decimal_mismatch(o:mutbuf) -> u32:
    put(o,STATE_O+48,NONE)
    put(o,STATE_O+56,NONE)
    return feedback(o,0)

def decimal_failure(o:mutbuf) -> u32:
    # The OS mutex is already held; record custody before the coordinator unwinds.
    put(o,STATE_O+24,get(o,STATE_O+24)|2)
    return coordinator_failure(o,29)

def extended(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1001:
        wanted=get(o,D_GN)
        if get(o,D_WHICH)!=0:
            wanted=get(o,D_EN)
        if wanted!=get(o,D_SIZE):
            return decimal_mismatch(o)
        put(o,D_INDEX,0)
        return again(o,1002)
    if phase==1002:
        n=get(o,D_SIZE)-get(o,D_INDEX)
        if n>2048:
            n=2048
        put(o,D_AMOUNT,n)
        return memory(o,1003,0,get(o,D_VALUE)+96+get(o,D_INDEX),3,D_CHUNK,n)
    if phase==1003:
        at=get(o,D_START)+get(o,D_INDEX)
        if get(o,D_WHICH)!=0:
            at=at+get(o,D_GN)
        i=0
        while i<get(o,D_AMOUNT):
            if byte(o,D_CHUNK+i)!=byte(s,at+i):
                return decimal_mismatch(o)
            i=i+1
        put(o,D_INDEX,get(o,D_INDEX)+get(o,D_AMOUNT))
        if get(o,D_INDEX)<get(o,D_SIZE):
            return again(o,1002)
        if get(o,D_WHICH)==0:
            put(o,D_WHICH,1)
            put(o,D_NEXT,1001)
            identity_request(o,7,64)
            return identity_call(o,1050)
        identity_request(o,5,get(w,COOR+48))
        return identity_call(o,1004)
    if phase==1004:
        if identity_ok(o)==0:
            return decimal_failure(o)
        within(o,D_GCAP,IOUT+24,24)
        put(o,D_GID,get(o,IOUT+16))
        identity_request(o,5,64)
        return identity_call(o,1005)
    if phase==1005:
        if identity_ok(o)==0:
            return decimal_failure(o)
        within(o,D_ECAP,IOUT+24,24)
        put(o,D_EID,get(o,IOUT+16))
        put(o,STATE_O+48,get(o,D_GID))
        put(o,STATE_O+56,get(o,D_EID))
        return feedback(o,0)
    if phase==1050:
        if identity_ok(o)==0:
            if get(o,OP)==2:
                return decimal_failure(o)
            return feedback(o,9)
        n=get(o,IOUT+48)
        if n==0 or n>NONE-96:
            if get(o,OP)==2:
                return decimal_failure(o)
            return feedback(o,9)
        put(o,D_VALUE,get(o,IOUT+16))
        put(o,D_SIZE,n)
        return memory(o,1051,0,get(o,D_VALUE),3,D_CHUNK,96)
    if phase==1051:
        if get(o,D_CHUNK)!=VALUE_MAGIC or get(o,D_CHUNK+8)!=get(w,8) or get(o,D_CHUNK+24)!=get(o,D_SIZE) or get(o,D_CHUNK+16)<96+get(o,D_SIZE):
            if get(o,OP)==2:
                return decimal_failure(o)
            return feedback(o,9)
        return again(o,get(o,D_NEXT))
    if phase==1100:
        if get(o,GO)!=GOBJ or get(o,GO+8)!=get(w,8) or get(o,GO+32)==0:
            return feedback(o,9)
        return memory(o,1101,0,get(o,GO+32)+GCTRL+320,3,D_REPLY+64,32)
    if phase==1101:
        return memory(o,1103,0,get(o,GO+32)+GCTRL+288,3,D_REPLY+96,32)
    if phase==1103:
        slot=get(w,COOR+48)
        if slot>=64:
            return again(o,1110)
        if get(w,SLOTS+slot*16)==0:
            return feedback(o,9)
        put(o,D_REPLY+16,get(o,D_REPLY+16)|4)
        return memory(o,1104,0,get(w,SLOTS+slot*16),3,GO,256)
    if phase==1104:
        if get(o,GO)!=GOBJ or get(o,GO+8)!=get(w,8) or get(o,GO+32)==0:
            return feedback(o,9)
        return memory(o,1105,0,get(o,GO+32)+GCTRL+320,3,D_REPLY+128,32)
    if phase==1105:
        return memory(o,1106,0,get(o,GO+32)+GCTRL+288,3,D_REPLY+160,32)
    if phase==1106:
        return memory(o,1107,0,get(o,GO+32)+GCTRL+736,3,D_REPLY+192,32)
    if phase==1107:
        identity_request(o,7,get(w,COOR+48))
        put(o,D_NEXT,1108)
        return identity_call(o,1050)
    if phase==1108:
        put(o,D_GDATA,get(o,D_VALUE)+96)
        put(o,D_CAPTURE_GN,get(o,D_SIZE))
        return again(o,1110)
    if phase==1110:
        identity_request(o,7,64)
        put(o,D_NEXT,1111)
        return identity_call(o,1050)
    if phase==1111:
        put(o,D_EDATA,get(o,D_VALUE)+96)
        put(o,D_CAPTURE_EN,get(o,D_SIZE))
        gn=get(o,D_CAPTURE_GN)
        en=get(o,D_CAPTURE_EN)
        if gn>NONE-256 or en>NONE-256-gn:
            return feedback(o,4)
        n=256+gn+en
        put(o,D_LEN,n)
        put(o,D_REPLY+24,gn)
        put(o,D_REPLY+32,en)
        put(o,D_REPLY+40,n)
        return allocate(o,1112,n)
    if phase==1112:
        if get(o,FEEDBACK)==0:
            put(o,D_LEN,0)
            return feedback(o,4)
        put(o,D_PTR,get(o,FEEDBACK))
        return memory(o,1113,3,D_REPLY,0,get(o,D_PTR),256)
    if phase==1113:
        if get(o,D_CAPTURE_GN)!=0:
            return memory(o,1114,0,get(o,D_GDATA),0,get(o,D_PTR)+256,get(o,D_CAPTURE_GN))
        return again(o,1114)
    if phase==1114:
        return memory(o,1115,0,get(o,D_EDATA),0,get(o,D_PTR)+256+get(o,D_CAPTURE_GN),get(o,D_CAPTURE_EN))
    if phase==1115:
        return feedback(o,0)
    if phase==1190:
        if get(o,D_GCAP)!=0:
            identity_request(o,8,0)
            within(o,IREQ+24,D_GCAP,24)
            return identity_call(o,1191)
        return again(o,1192)
    if phase==1191:
        if identity_ok(o)==0:
            copy(w,336,o,D_GCAP,24)
            zero(o,D_GCAP,24)
            put(w,312,1)
            put(o,D_ERROR,9)
        else:
            zero(o,D_GCAP,24)
        return again(o,1192)
    if phase==1192:
        if get(o,D_ECAP)!=0:
            identity_request(o,8,0)
            within(o,IREQ+24,D_ECAP,24)
            return identity_call(o,1193)
        return again(o,1194)
    if phase==1193:
        if identity_ok(o)==0:
            copy(w,368,o,D_ECAP,24)
            zero(o,D_ECAP,24)
            put(w,312,1)
            put(o,D_ERROR,9)
        else:
            zero(o,D_ECAP,24)
        return again(o,1194)
    if phase==1194:
        if get(o,D_ERROR)!=0 and get(o,D_PTR)!=0:
            ptr=get(o,D_PTR)
            put(o,D_PTR,0)
            put(o,D_LEN,0)
            return deallocate(o,1195,ptr)
        return again(o,1195)
    if phase==1195:
        put(o,D_FAILED,1)
        return result(o,w,get(o,D_ERROR))
    return result(o,w,9)

'''
def source_program():
 s=SOURCE
 for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
 return s
def main():
 tree=document(source_program(),'multiversion_runtime_effects');p=ROOT/'examples/hia_bootstrap/multiversion_runtime_effects.hepta';p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
