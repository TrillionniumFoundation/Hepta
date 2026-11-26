"""Fixed native BackgroundOptimizer submission and accepted-job ownership."""
from pathlib import Path
from tools import hia_background_retirement_source as R
import ast,re,json
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE
from tools.generate_hia_background_optimizer_value_structure import ERRORS
ROOT=Path(__file__).resolve().parents[1]
C={
'DROP_ACTIVE':976,'DROP_KNOWN':984,'JOB_PENDING':992,'FUTURE_PENDING':1000,'VALUE_PENDING':1008,'QUARANTINE_KIND':1016,
'MAGIC':int.from_bytes(b'HIABSQ01','little'),'REPLY':int.from_bytes(b'HIABSRP1','little'),'CONTEXT':int.from_bytes(b'HIABSSC1','little'),
'VALUE_INPUT':int.from_bytes(b'HIABVQ01','little'),'VALUE_REPLY':int.from_bytes(b'HIABVR01','little'),
'QINPUT':int.from_bytes(b'HIABGQ02','little'),'QREPLY':int.from_bytes(b'HIABGQR1','little'),
'JOB_INPUT':int.from_bytes(b'HIABJO02','little'),'JOB_REPLY':int.from_bytes(b'HIABJOR1','little'),
'PUBLIC_INPUT':int.from_bytes(b'HIABFP01','little'),'PUBLIC_REPLY':int.from_bytes(b'HIABFRP1','little'),
'FREEZE_INPUT':int.from_bytes(b'HIABFZQ1','little'),'FREEZE_REPLY':int.from_bytes(b'HIABFZR1','little'),
'PAYLOAD_INPUT':int.from_bytes(b'HIABPY01','little'),'PAYLOAD_REPLY':int.from_bytes(b'HIABPYR1','little'),
'TRETRY':int.from_bytes(b'HIABTC02','little'),'TINPUT':int.from_bytes(b'HIABTC01','little'),'TCONTEXT':int.from_bytes(b'HIABVC01','little'),'TREPLY':int.from_bytes(b'HIABTV01','little'),
'ADMIT_INPUT':int.from_bytes(b'HIABAD01','little'),'ADMIT_REPLY':int.from_bytes(b'HIABAR01','little'),'JSTATS':int.from_bytes(b'HIANJS01','little'),
'PROVIDER_INPUT':int.from_bytes(b'HIAMVBQ1','little'),'PROVIDER_REPLY':int.from_bytes(b'HIAMVBO1','little'),'SNAPSHOT':int.from_bytes(b'HIAMVBS1','little'),
'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'THRESHOLD':10100891,'TBYTES':96<<20,'OUT':524288,
'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'PID':160,'LOCK':168,'ACCEPTED':176,'ITER':184,'STAGE':192,'KEY_ID':200,
'ENDSEC':208,'ENDNANO':216,'STARTSEC':224,'STARTNANO':232,'T_SRC':240,'T_OUT':248,'RAW_PTR':256,'RAW_N':264,
'FRAME':272,'FRAME_N':280,'FRAME_CAP':288,'JSON_WORK':296,'JSON_WORK_N':304,'ARENA_N':312,'NODE_COUNT':320,'KEY_COUNT':328,'DEPTH':336,
'SNAP_PTR':344,'SNAP_N':352,'SNAP_GEN_N':360,'SNAP_EPOCH_N':368,'SELECT':376,'DREQ':384,'DREQ_N':392,
'ADMWORK':400,'ADMWORK_N':408,'Q_SLOT':416,'KERNEL':424,'T_STUCK':432,'CLEAN':440,'FEEDBACK':448,'SAVED':456,
'WORD':464,'ERRN':472,'REQSIZE':480,'NEWFRAME':488,'OLDNUMBER':896,'UCHAR':920,'USTART':928,'UEND':936,'UCP':944,'PUBTYPE':952,'PUBCLASS':960,'PUBKIND':968,
'P_ROOT':512,'S_ROOT':536,'PACK':560,'PROVIDER':584,'FUSER':608,'FBG':632,'JOB':656,'META':680,'KEY':704,'TEMP':728,'CORE':752,'NEXTNEW':776,
'PUBERROR':800,'GUARD_C':824,'GUARD_O':848,'GUARD_T':872,'CONTROL_N':896,
'TS':2048,'ST':2304,'RQ':4096,'RP':8192,'PUBLIC_OUT':16384,'FREEZE_OUT':81920,'FREEZE_WORK':344064,
'STRUCT_CTX':346112,'INFO':346240,'ADMHEAD':346752,'ADMOUT':347136,'ERR':348160,'SCRATCH':349184,
}
C.update(R.MAGICS)
SOURCE=r'''
def submission(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<8192:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return entering(s,o,w,phase)
    if phase<150:
        return payload(s,o,w,phase)
    if phase<200:
        return structure(s,o,w,phase)
    if phase<300:
        return freezing(s,o,w,phase)
    if phase<400:
        return admission(s,o,w,phase)
    if phase<500:
        return accepting(s,o,w,phase)
    if phase<600:
        return metadata(s,o,w,phase)
    if phase<700:
        return enqueue(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return 4294967293
    at=16
    while at<128:
        used=word_load(s,8)==0 and at>=24 and at<=88
        if used==False and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)<4096 or get(w,56)==0 or get(w,64)==0 or get(w,72)<256:
        return 4294967293
    if get(w,80)==0 or get(w,88)==0 or get(w,96)<256 or get(w,104)==0 or get(w,128)==0:
        return 4294967293
    if get(w,152)==0 or get(w,160)==0 or get(w,168)<1024 or get(w,176)==0:
        return 4294967293
    if get(w,200)==0 or get(w,208)==0 or get(w,216)<256 or get(w,224)==0 or get(w,232)==0 or get(w,240)!=THRESHOLD:
        return 4294967293
    if get(w,248)==0 or get(w,256)==0 or get(w,264)<2048 or get(w,272)==0 or get(w,280)==0:
        return 4294967293
    if get(w,800)==0 or get(w,808)==0 or get(w,816)<256:
        return 4294967293
    if get(w,288)==0 or get(w,312)==0 or get(w,792)>1:
        return 4294967293
    zero(o,128,3968)
    zero(o,FREEZE_WORK,2048)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def entering(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,784)!=0 and get(w,784)!=pid):
            return finish(o,w,6)
        put(o,PID,pid)
        if get(o,OP)==1:
            return lock_queue(o,w)
        return system(o,2,228,12,1,TS,0,0,0,0)
    if phase==2:
        if get(o,FEEDBACK)==MAX-3:
            return system(o,2,228,12,1,TS,0,0,0,0)
        if get(o,FEEDBACK)!=0 or get(o,TS)>=9223372036854775808 or get(o,TS+8)>=1000000000:
            return finish(o,w,8)
        put(o,STARTSEC,get(o,TS))
        put(o,STARTNANO,get(o,TS+8))
        return lock_queue(o,w)
    if phase==3:
        if valid(o,RP,QREPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,6)
        put(o,LOCK,1)
        put(w,784,get(o,PID))
        if get(o,OP)==1:
            if get(w,792)==0:
                return again(o,790)
            from_work(w,o,3072,128,CONTROL_N)
            from_work(w,o,3968,FREEZE_WORK,2048)
            from_work(w,o,6016,ERR,1024)
            from_work(w,o,7040,STRUCT_CTX,128)
            put(o,LOCK,1)
            if get(o,QUARANTINE_KIND)==2:
                put(o,ERROR,9)
                return again(o,790)
            put(o,OP,1)
            put(w,792,0)
            if get(o,ERROR)==0:
                put(o,ERROR,7)
            put(o,CLEAN,0)
            return again(o,700)
        if get(w,792)!=0:
            put(o,ERROR,6)
            return again(o,790)
        if get(o,RP+24)!=0:
            return original_error(o,1)
        put(o,STAGE,get(o,RP+32))
        return memory(o,4,0,get(w,40)+24,3,TS,8)
    if phase==4:
        if get(o,TS)<1 or get(o,TS)>8:
            return fail(o,9,4)
        if get(o,STAGE)>=get(o,TS):
            return original_error(o,2)
        request(o,VALUE_INPUT,4)
        return values(o,w,100,128)
    return fail(o,9,phase)

def lock_queue(o:mutbuf,w:mutbuf) -> u32:
    request(o,QINPUT,10)
    return queue(o,w,3)

def payload(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if value_take(o,P_ROOT)!=0:
            return fail(o,value_failure(o),100)
        put(o,ITER,0)
        return again(o,101)
    if phase==101:
        if get(o,ITER)==3:
            return allocate(o,150,128+THRESHOLD)
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        n=literal(o,RQ+128,100+get(o,ITER))
        put(o,RQ+96,n)
        return values(o,w,102,128+n)
    if phase==102:
        if value_take(o,KEY)!=0:
            return fail(o,value_failure(o),102)
        request(o,VALUE_INPUT,10)
        within(o,RQ+24,P_ROOT,24)
        within(o,RQ+48,KEY,24)
        copy_source(s,o,24+get(o,ITER)*24,RQ+72,24)
        return values(o,w,103,128)
    if phase==103:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,value_failure(o),103)
        return drop_value(o,w,104,KEY)
    if phase==104:
        if clear_value(o,KEY)==0:
            return fail(o,7,104)
        put(o,ITER,get(o,ITER)+1)
        return again(o,101)
    return fail(o,9,phase)

def structure(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==150:
        if get(o,FEEDBACK)==0:
            return fail(o,5,150)
        put(o,T_SRC,get(o,FEEDBACK))
        zero(o,INFO,128)
        put(o,INFO,TINPUT)
        within(o,INFO+16,P_ROOT,24)
        put(o,INFO+48,THRESHOLD)
        return memory(o,151,0,get(w,256)+80,3,INFO+40,8)
    if phase==151:
        return memory(o,152,3,INFO,0,get(o,T_SRC),128)
    if phase==152:
        return memory(o,153,0,get(w,232),0,get(o,T_SRC)+128,THRESHOLD)
    if phase==153:
        return allocate(o,154,TBYTES)
    if phase==154:
        if get(o,FEEDBACK)==0:
            return fail(o,5,154)
        put(o,T_OUT,get(o,FEEDBACK))
        put(o,WORD,0)
        return memory(o,155,3,WORD,0,get(o,T_OUT)+128,8)
    if phase==155:
        zero(o,STRUCT_CTX,128)
        put(o,STRUCT_CTX,TCONTEXT)
        put(o,STRUCT_CTX+8,get(w,8))
        put(o,STRUCT_CTX+16,get(w,16))
        put(o,STRUCT_CTX+24,get(w,24))
        return again(o,160)
    if phase==160:
        return invoke(o,161,get(w,224),768,get(o,T_SRC),128+THRESHOLD,get(o,T_OUT),TBYTES,STRUCT_CTX,128)
    if phase==161:
        put(o,STAGE,get(o,FEEDBACK))
        return memory(o,162,0,get(o,T_OUT),3,INFO,512)
    if phase==162:
        rc=get(o,STAGE)
        if rc==10:
            return again(o,160)
        if rc==4:
            if get(o,INFO)!=get(w,8):
                put(o,T_STUCK,2)
                return fail(o,9,162)
            put(o,0,get(w,8))
            mask=get(o,INFO+8)
            mapped=0
            i=0
            while i<6:
                bank=(mask>>(i*2))&3
                arg=get(o,INFO+16+i*8)
                if bank==1:
                    arg=arg+STRUCT_CTX
                    mapped=mapped|(3<<(i*2))
                elif bank==2:
                    arg=arg+get(o,T_SRC)
                elif bank==3:
                    arg=arg+get(o,T_OUT)
                put(o,16+i*8,arg)
                i=i+1
            put(o,8,mapped)
            put(o,PHASE,163)
            return 9
        if rc!=0 or get(o,INFO)!=TREPLY:
            put(o,T_STUCK,2)
            return fail(o,7,rc)
        status=get(o,INFO+8)
        if status==3:
            put(o,T_STUCK,1)
            if get(o,OP)==1:
                return quarantine(o,w,get(o,INFO+104))
            return fail(o,9,get(o,INFO+104))
        if get(o,OP)==1 and get(o,T_STUCK)==1:
            if status>2:
                put(o,T_STUCK,2)
                return quarantine(o,w,162)
            if get(o,INFO+24)!=0:
                if get(o,S_ROOT)!=0:
                    put(o,T_STUCK,2)
                    return quarantine(o,w,162)
                within(o,S_ROOT,INFO+24,24)
            put(o,T_STUCK,0)
            return again(o,700)
        if status==2:
            return fail(o,choose(get(o,INFO+96)==5,5,7),get(o,INFO+96))
        if status==1:
            put(o,ERRN,structural_error(o,get(o,INFO+16),get(o,INFO+88)))
            return fail(o,1,get(o,INFO+16))
        if status!=0 or get(o,INFO+24)==0:
            return fail(o,9,162)
        within(o,S_ROOT,INFO+24,24)
        return deallocate(o,164,get(o,T_OUT))
    if phase==163:
        put(o,WORD,get(o,FEEDBACK))
        return memory(o,160,3,WORD,0,get(o,T_OUT)+136,8)
    if phase==164:
        put(o,T_OUT,0)
        return deallocate(o,165,get(o,T_SRC))
    if phase==165:
        put(o,T_SRC,0)
        return memory(o,200,0,get(w,256),3,FREEZE_WORK,128)
    return fail(o,9,phase)

def freezing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        request(o,FREEZE_INPUT,0)
        within(o,RQ+24,P_ROOT,24)
        return invoke(o,201,get(w,248),819,RQ,128,FREEZE_OUT,262144,FREEZE_WORK,2048)
    if phase==201:
        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        status=get(o,FREEZE_OUT+8)
        if status!=0:
            if status==1:
                n=get(o,FREEZE_OUT+48)
                if n>1024:
                    return fail(o,9,n)
                within(o,ERR,FREEZE_OUT+128,n)
                put(o,ERRN,n)
                put(o,UCHAR,get(o,FREEZE_OUT+72))
                put(o,USTART,get(o,FREEZE_OUT+80))
                put(o,UEND,get(o,FREEZE_OUT+88))
                put(o,UCP,get(o,FREEZE_OUT+96))
            return fail(o,choose(status==1,1,choose(status==5,5,7)),status)
        if get(o,FREEZE_OUT+16)==0:
            return fail(o,9,201)
        within(o,PACK,FREEZE_OUT+16,24)
        request(o,PAYLOAD_INPUT,6)
        within(o,RQ+24,PACK,24)
        return payload_owner(o,w,202)
    if phase==202:
        if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+40)>8388608:
            return fail(o,7,202)
        put(o,RAW_PTR,get(o,RP+64))
        put(o,RAW_N,get(o,RP+40))
        zero(o,INFO,128)
        return invoke(o,203,get(w,280),816,get(o,RAW_PTR),get(o,RAW_N),ADMOUT,1024,INFO,128)
    if phase==203:
        if valid(o,ADMOUT,JSTATS)==0:
            return fail(o,7,203)
        put(o,NODE_COUNT,get(o,ADMOUT+8))
        put(o,KEY_COUNT,get(o,ADMOUT+16))
        put(o,DEPTH,get(o,ADMOUT+24))
        put(o,ARENA_N,get(o,ADMOUT+32))
        put(o,JSON_WORK_N,get(o,ADMOUT+40))
        if get(o,ARENA_N)>MAX-256-get(o,RAW_N):
            return fail(o,5,203)
        put(o,FRAME_CAP,256+get(o,RAW_N)+get(o,ARENA_N))
        return allocate(o,204,get(o,FRAME_CAP))
    if phase==204:
        if get(o,FEEDBACK)==0:
            return fail(o,5,204)
        put(o,FRAME,get(o,FEEDBACK))
        return memory(o,205,0,get(o,RAW_PTR),0,get(o,FRAME)+256,get(o,RAW_N))
    if phase==205:
        return allocate(o,206,get(o,JSON_WORK_N))
    if phase==206:
        if get(o,FEEDBACK)==0:
            return fail(o,5,206)
        put(o,JSON_WORK,get(o,FEEDBACK))
        zero(o,INFO,128)
        put(o,INFO+48,get(o,NODE_COUNT))
        put(o,INFO+56,get(o,DEPTH))
        put(o,INFO+96,get(o,KEY_COUNT))
        put(o,INFO+104,1)
        return memory(o,207,3,INFO,0,get(o,JSON_WORK),128)
    if phase==207:
        return invoke(o,208,get(w,280),0,get(o,FRAME)+256,get(o,RAW_N),get(o,FRAME)+256+get(o,RAW_N),get(o,ARENA_N),get(o,JSON_WORK),get(o,JSON_WORK_N))
    if phase==208:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,209,0,get(o,FRAME)+256+get(o,RAW_N),3,INFO,64)
    if phase==209:
        n=get(o,INFO+24)
        if n>get(o,ARENA_N):
            return fail(o,9,n)
        put(o,ARENA_N,n)
        put(o,FRAME_N,256+get(o,RAW_N)+n)
        zero(o,ADMHEAD,256)
        put(o,ADMHEAD,ADMIT_INPUT)
        put(o,ADMHEAD+8,3)
        put(o,ADMHEAD+16,get(o,RAW_N))
        put(o,ADMHEAD+24,n)
        from_work(w,o,512,ADMHEAD+80,128)
        return memory(o,210,3,ADMHEAD,0,get(o,FRAME),256)
    if phase==210:
        n=choose(get(o,NODE_COUNT)>131072,get(o,NODE_COUNT),131072)
        put(o,ADMWORK_N,n)
        return allocate(o,211,n)
    if phase==211:
        if get(o,FEEDBACK)==0:
            return fail(o,5,211)
        put(o,ADMWORK,get(o,FEEDBACK))
        return admit(o,w,300)
    return fail(o,9,phase)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        status=admission_status(o)
        if status!=0:
            return fail(o,status,300)
        request(o,PROVIDER_INPUT,1)
        from_work(w,o,176,RQ+16,24)
        return provider_owner(o,w,301)
    if phase==301:
        if valid(o,RP,PROVIDER_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        status=get(o,RP+8)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        if status!=0:
            if status==1 and get(o,PROVIDER)!=0:
                put(o,SNAP_PTR,get(o,RP+24))
                put(o,SNAP_N,get(o,RP+32))
                return fail(o,2,status)
            return fail(o,choose(status==2,5,7),status)
        if get(o,PROVIDER)==0 or get(o,RP+32)<256:
            return fail(o,9,301)
        put(o,SNAP_PTR,get(o,RP+24))
        put(o,SNAP_N,get(o,RP+32))
        return memory(o,302,0,get(o,SNAP_PTR),3,INFO,256)
    if phase==302:
        if get(o,INFO)!=SNAPSHOT or get(o,INFO+40)!=get(o,SNAP_N):
            return fail(o,9,302)
        put(o,SNAP_GEN_N,get(o,INFO+24))
        put(o,SNAP_EPOCH_N,get(o,INFO+32))
        if get(o,SNAP_N)>MAX-get(o,FRAME_N):
            return fail(o,5,302)
        return allocate(o,303,get(o,FRAME_N)+get(o,SNAP_N))
    if phase==303:
        if get(o,FEEDBACK)==0:
            return fail(o,5,303)
        put(o,NEWFRAME,get(o,FEEDBACK))
        return memory(o,304,0,get(o,FRAME),0,get(o,NEWFRAME),get(o,FRAME_N))
    if phase==304:
        return memory(o,305,0,get(o,SNAP_PTR),0,get(o,NEWFRAME)+get(o,FRAME_N),get(o,SNAP_N))
    if phase==305:
        return deallocate(o,306,get(o,FRAME))
    if phase==306:
        put(o,FRAME,get(o,NEWFRAME))
        put(o,NEWFRAME,0)
        put(o,FRAME_N,get(o,FRAME_N)+get(o,SNAP_N))
        put(o,ADMHEAD+8,4)
        put(o,ADMHEAD+64,get(o,SNAP_N))
        return memory(o,307,3,ADMHEAD,0,get(o,FRAME),256)
    if phase==307:
        return admit(o,w,308)
    if phase==308:
        status=admission_status(o)
        if status!=0:
            return fail(o,status,308)
        selected=get(o,ADMOUT+80)
        if selected>1:
            return fail(o,9,selected)
        put(o,SELECT,selected)
        from_work(w,o,512+selected*64,ADMHEAD+80,64)
        put(o,ADMHEAD+8,5)
        return memory(o,309,3,ADMHEAD,0,get(o,FRAME),256)
    if phase==309:
        return admit(o,w,310)
    if phase==310:
        status=admission_status(o)
        if status!=0:
            return fail(o,status,310)
        request(o,PUBLIC_INPUT,4)
        from_work(w,o,104,RQ+16,24)
        from_work(w,o,128,RQ+40,24)
        return public(o,w,400)
    return fail(o,9,phase)

def accepting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if public_take(o,w,FUSER)==0:
            return fail(o,public_failure(o),400)
        request(o,PUBLIC_INPUT,5)
        from_work(w,o,104,RQ+16,24)
        within(o,RQ+40,FUSER,24)
        return public(o,w,401)
    if phase==401:
        if public_take(o,w,FBG)==0:
            return fail(o,public_failure(o),401)
        put(o,DREQ_N,128+get(o,RAW_N))
        return allocate(o,402,get(o,DREQ_N))
    if phase==402:
        if get(o,FEEDBACK)==0:
            return fail(o,5,402)
        put(o,DREQ,get(o,FEEDBACK))
        request(o,JOB_INPUT,10)
        within(o,RQ+24,FBG,24)
        put(o,RQ+72,get(o,RAW_N))
        return memory(o,403,3,RQ,0,get(o,DREQ),128)
    if phase==403:
        return memory(o,404,0,get(o,RAW_PTR),0,get(o,DREQ)+128,get(o,RAW_N))
    if phase==404:
        return invoke(o,405,get(w,56),48,get(o,DREQ),get(o,DREQ_N),RP,2048,get(w,64),get(w,72))
    if phase==405:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)==0:
            return fail(o,dependency_failure(o,JOB_REPLY,4),405)
        within(o,JOB,RP+16,24)
        return deallocate(o,406,get(o,DREQ))
    if phase==406:
        put(o,DREQ,0)
        request(o,PAYLOAD_INPUT,2)
        from_work(w,o,640+get(o,SELECT)*24,RQ+24,24)
        return payload_owner(o,w,407)
    if phase==407:
        if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)==0:
            return fail(o,dependency_failure(o,PAYLOAD_REPLY,4),407)
        within(o,CORE,RP+16,24)
        request(o,JOB_INPUT,7)
        within(o,RQ+24,JOB,24)
        within(o,RQ+48,CORE,24)
        return jobs(o,w,408)
    if phase==408:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+112)!=1:
            return fail(o,7,408)
        zero(o,CORE,24)
        request(o,VALUE_INPUT,4)
        return values(o,w,500,128)
    return fail(o,9,phase)

def metadata(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if value_take(o,META)!=0:
            return fail(o,value_failure(o),500)
        put(o,ITER,0)
        return again(o,501)
    if phase==501:
        index=get(o,ITER)
        if index==13:
            request(o,VALUE_INPUT,24)
            from_work(w,o,312,RQ+24,24)
            from_work(w,o,288,RQ+48,24)
            return values(o,w,600,128)
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        n=literal(o,RQ+128,index)
        put(o,RQ+96,n)
        return values(o,w,502,128+n)
    if phase==502:
        if value_take(o,KEY)!=0:
            return fail(o,value_failure(o),502)
        index=get(o,ITER)
        if index==1 or index==2:
            n=choose(index==1,get(o,SNAP_GEN_N),get(o,SNAP_EPOCH_N))
            if n>MAX-128:
                return fail(o,5,502)
            put(o,DREQ_N,128+n)
            return allocate(o,510,128+n)
        request(o,VALUE_INPUT,2)
        if index==0 or index==3:
            put(o,RQ+8,5)
            from_work(w,o,choose(index==0,312,688),RQ+24,24)
            return values(o,w,503,128)
        if index>=4 and index<=6:
            put(o,RQ+104,4)
            n=hash_hex(o,w,RQ+128,choose(index==6,512,512+get(o,SELECT)*64+(index-4)*32))
        elif index==7 or index==9:
            put(o,RQ+104,2)
            store(o,RQ+128,48)
            n=1
        elif index==8:
            put(o,RQ+104,2)
            n=clock_decimal(o,RQ+128,get(o,STARTSEC),get(o,STARTNANO))
        elif index==10:
            n=0
        else:
            put(o,RQ+104,4)
            n=literal(o,RQ+128,choose(index==11,103,104))
        put(o,RQ+96,n)
        return values(o,w,503,128+n)
    if phase==503:
        if value_take(o,TEMP)!=0:
            return fail(o,value_failure(o),503)
        if get(o,DREQ)!=0:
            return deallocate(o,504,get(o,DREQ))
        return again(o,505)
    if phase==504:
        put(o,DREQ,0)
        return again(o,505)
    if phase==505:
        request(o,VALUE_INPUT,10)
        within(o,RQ+24,META,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,TEMP,24)
        return values(o,w,506,128)
    if phase==506:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,value_failure(o),506)
        return drop_value(o,w,507,KEY)
    if phase==507:
        if clear_value(o,KEY)==0:
            return fail(o,7,507)
        return drop_value(o,w,508,TEMP)
    if phase==508:
        if clear_value(o,TEMP)==0:
            return fail(o,7,508)
        put(o,ITER,get(o,ITER)+1)
        return again(o,501)
    if phase==510:
        if get(o,FEEDBACK)==0:
            return fail(o,5,510)
        put(o,DREQ,get(o,FEEDBACK))
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,2)
        put(o,RQ+96,get(o,DREQ_N)-128)
        return memory(o,511,3,RQ,0,get(o,DREQ),128)
    if phase==511:
        at=get(o,SNAP_PTR)+256
        if get(o,ITER)==2:
            at=at+get(o,SNAP_GEN_N)
        return memory(o,512,0,at,0,get(o,DREQ)+128,get(o,DREQ_N)-128)
    if phase==512:
        return invoke(o,503,get(w,8),48,get(o,DREQ),get(o,DREQ_N),RP,8192,get(w,16),get(w,24))
    return fail(o,9,phase)

def enqueue(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        if value_take(o,NEXTNEW)!=0:
            return fail(o,value_failure(o),600)
        from_work(w,o,312,OLDNUMBER,24)
        to_work(o,w,NEXTNEW,312,24)
        zero(o,NEXTNEW,24)
        request(o,JOB_INPUT,6)
        within(o,RQ+24,JOB,24)
        return jobs(o,w,601)
    if phase==601:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)==0 or get(o,RP+96)!=512:
            return fail(o,7,601)
        put(o,KERNEL,get(o,RP+64))
        request(o,QINPUT,1)
        within(o,RQ+24,JOB,24)
        put(o,RQ+48,get(o,KERNEL))
        put(o,RQ+56,512)
        return queue(o,w,602)
    if phase==602:
        if valid(o,RP,QREPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)>=8:
            return fail(o,7,602)
        slot=get(o,RP+16)
        put(o,Q_SLOT,slot)
        put(o,ACCEPTED,1)
        at=1024+slot*128
        if get(w,at)!=0 or get(w,at+24)!=0 or get(w,at+48)!=0:
            zero(o,JOB,24)
            return quarantine(o,w,602)
        to_work(o,w,JOB,at,24)
        to_work(o,w,META,at+24,24)
        to_work(o,w,FBG,at+48,24)
        zero(o,JOB,24)
        zero(o,FBG,24)
        return system(o,603,228,12,1,TS,0,0,0,0)
    if phase==603:
        if get(o,FEEDBACK)==MAX-3:
            return system(o,603,228,12,1,TS,0,0,0,0)
        if get(o,FEEDBACK)!=0 or get(o,TS)>=9223372036854775808 or get(o,TS+8)>=1000000000:
            zero(o,META,24)
            return fail(o,8,get(o,FEEDBACK))
        put(o,ENDSEC,get(o,TS))
        put(o,ENDNANO,get(o,TS+8))
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,2)
        n=clock_decimal(o,RQ+128,get(o,ENDSEC),get(o,ENDNANO))
        put(o,RQ+96,n)
        return values(o,w,604,128+n)
    if phase==604:
        if value_take(o,TEMP)!=0:
            return accepted_failure(o,value_failure(o),604)
        return create_key(o,w,605,9)
    if phase==605:
        if value_take(o,KEY)!=0:
            return accepted_failure(o,value_failure(o),605)
        request(o,VALUE_INPUT,10)
        within(o,RQ+24,META,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,TEMP,24)
        return values(o,w,606,128)
    if phase==606:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return accepted_failure(o,value_failure(o),606)
        return drop_value(o,w,607,KEY)
    if phase==607:
        if clear_value(o,KEY)==0:
            return accepted_failure(o,7,607)
        return create_key(o,w,608,8)
    if phase==608:
        if value_take(o,KEY)!=0:
            return accepted_failure(o,value_failure(o),608)
        request(o,VALUE_INPUT,9)
        within(o,RQ+24,META,24)
        within(o,RQ+48,KEY,24)
        return values(o,w,609,128)
    if phase==609:
        if value_take(o,GUARD_C)!=0:
            return accepted_failure(o,value_failure(o),609)
        request(o,VALUE_INPUT,24)
        within(o,RQ+24,TEMP,24)
        within(o,RQ+48,GUARD_C,24)
        put(o,RQ+104,1)
        return values(o,w,610,128)
    if phase==610:
        if value_take(o,GUARD_O)!=0:
            return accepted_failure(o,value_failure(o),610)
        return drop_value(o,w,611,KEY)
    if phase==611:
        if clear_value(o,KEY)==0:
            return accepted_failure(o,7,611)
        return create_key(o,w,612,7)
    if phase==612:
        if value_take(o,KEY)!=0:
            return accepted_failure(o,value_failure(o),612)
        request(o,VALUE_INPUT,10)
        within(o,RQ+24,META,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,GUARD_O,24)
        return values(o,w,613,128)
    if phase==613:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return accepted_failure(o,value_failure(o),613)
        zero(o,META,24)
        put(o,CLEAN,0)
        return again(o,700)
    return accepted_failure(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return quarantine(o,w,700)
        if get(o,T_STUCK)!=0:
            if get(o,OP)==1 and get(o,T_STUCK)==1 and get(o,T_SRC)!=0 and get(o,T_OUT)!=0:
                return memory(o,702,0,get(o,T_SRC),3,INFO,128)
            return quarantine(o,w,700)
        if get(o,FREEZE_WORK+96)!=0:
            request(o,FREEZE_INPUT,1)
            return invoke(o,701,get(w,248),819,RQ,128,FREEZE_OUT,262144,FREEZE_WORK,2048)
        return again(o,710)
    if phase==701:
        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0 or get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            return quarantine(o,w,701)
        if get(o,FREEZE_OUT+8)==0 and get(o,FREEZE_OUT+16)!=0:
            if get(o,PACK)!=0:
                return quarantine(o,w,701)
            within(o,PACK,FREEZE_OUT+16,24)
        return again(o,710)
    if phase==702:
        put(o,INFO,TRETRY)
        put(o,INFO+8,2)
        zero(o,INFO+16,24)
        return memory(o,160,3,INFO,0,get(o,T_SRC),128)
    if phase==710:
        index=get(o,CLEAN)
        if index==17:
            put(o,CLEAN,0)
            return again(o,750)
        at=P_ROOT+index*24
        if get(o,at)==0 or (at==FUSER and get(o,ERROR)==0 and get(o,OP)==0) or (at==PROVIDER and get(o,ERROR)==2 and get(o,OP)==0) or (at==PUBERROR and get(o,ERROR)==3 and get(o,OP)==0):
            put(o,CLEAN,index+1)
            return again(o,710)
        put(o,SAVED,at)
        if at==PROVIDER:
            request(o,PROVIDER_INPUT,5)
            within(o,RQ+40,at,24)
            return provider_owner(o,w,711)
        if at==PACK or at==CORE:
            request(o,PAYLOAD_INPUT,3)
            within(o,RQ+24,at,24)
            return payload_owner(o,w,712)
        if at==FUSER or at==FBG:
            release_begin(o)
            request(o,PUBLIC_DROP_INPUT,26)
            from_work(w,o,104,RQ+16,24)
            within(o,RQ+40,at,24)
            return public(o,w,713)
        if at==JOB:
            release_begin(o)
            request(o,JOB_DROP_INPUT,11)
            within(o,RQ+24,at,24)
            return jobs(o,w,714)
        return drop_value(o,w,715,at)
    if phase>=711 and phase<=715:
        done=0
        if phase==713:
            done=release_future(o,get(o,SAVED))
        elif phase==714:
            done=release_job(o,get(o,SAVED))
        elif phase==715:
            done=release_value(o,get(o,SAVED))
        else:
            magic=choose(phase==711,PROVIDER_REPLY,PAYLOAD_REPLY)
            if valid(o,RP,magic)!=0 and get(o,RP+8)==0:
                zero(o,get(o,SAVED),24)
                done=1
        if done==0:
            return quarantine(o,w,phase)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,710)
    if phase==750:
        index=get(o,CLEAN)
        if index==7:
            return again(o,760)
        at=allocation_slot(index)
        put(o,SAVED,at)
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,750)
        return deallocate(o,751,get(o,at))
    if phase==751:
        put(o,get(o,SAVED),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,750)
    if phase==790:
        if get(o,LOCK)==0:
            return finish(o,w,get(o,ERROR))
        request(o,QINPUT,11)
        return queue(o,w,791)
    if phase==791:
        if valid(o,RP,QREPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        put(o,LOCK,0)
        return finish(o,w,get(o,ERROR))
    if phase==792:
        if valid(o,RP,QREPLY)!=0 and get(o,RP+8)==0:
            put(o,LOCK,0)
        return finish(o,w,9)
    if phase==760:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,12)
            return jobs(o,w,761)
        if get(o,FUTURE_PENDING)!=0:
            release_begin(o)
            request(o,PUBLIC_INPUT,20)
            return public(o,w,762)
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return values(o,w,764,128)
        return again(o,790)
    if phase==761:
        if release_job_retry(o)==0:
            return quarantine(o,w,761)
        return again(o,760)
    if phase==762:
        if release_future_retry(o)==0:
            return quarantine(o,w,762)
        release_begin(o)
        request(o,CELL_QUERY_INPUT,21)
        return invoke(o,763,get(w,800),51,RQ,128,RP,16384,get(w,808),get(w,816))
    if phase==763:
        if release_cell_query(o)==0:
            return quarantine(o,w,763)
        return again(o,760)
    if phase==764:
        if release_value_retry(o)==0:
            return quarantine(o,w,764)
        return again(o,760)
    return quarantine(o,w,phase)

def allocation_slot(index:u64) -> u64:
    if index==0:
        return T_SRC
    if index==1:
        return T_OUT
    if index==2:
        return FRAME
    if index==3:
        return JSON_WORK
    if index==4:
        return DREQ
    if index==5:
        return ADMWORK
    return NEWFRAME

def create_key(o:mutbuf,w:mutbuf,next:u64,id:u64) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RQ+104,4)
    n=literal(o,RQ+128,id)
    put(o,RQ+96,n)
    return values(o,w,next,128+n)

def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,8192,get(w,16),get(w,24))
def queue(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,32),51,RQ,128,RP,8192,get(w,40),get(w,48))
def jobs(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,56),51,RQ,128,RP,2048,get(w,64),get(w,72))
def public(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,80),51,RQ,192,PUBLIC_OUT,65536,get(w,88),get(w,96))
def payload_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,200),51,RQ,128,RP,512,get(w,208),get(w,216))
def provider_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,152),51,RQ,128,RP,512,get(w,160),get(w,168))
def admit(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,272),48,get(o,FRAME),get(o,FRAME_N),ADMOUT,1024,get(o,ADMWORK),get(o,ADMWORK_N))
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def value_take(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
        return 1
    if get(o,RP+24)==0 or get(o,at)!=0:
        return 1
    within(o,at,RP+24,24)
    return 0
def value_failure(o:mutbuf) -> u64:
    return dependency_failure(o,VALUE_REPLY,5)
def dependency_failure(o:mutbuf,magic:u64,memory_code:u64) -> u64:
    if valid(o,RP,magic)==0:
        return 7
    return choose(get(o,RP+8)==memory_code,5,7)
def public_take(o:mutbuf,w:mutbuf,at:u64) -> u64:
    if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0:
        return 0
    if get(o,PUBLIC_OUT+8)!=0:
        within(o,PUBERROR,PUBLIC_OUT+72,24)
        put(o,PUBTYPE,get(o,PUBLIC_OUT+8))
        put(o,PUBKIND,get(o,PUBLIC_OUT+16))
        put(o,PUBCLASS,get(o,PUBLIC_OUT+96))
        return 0
    if get(o,PUBLIC_OUT+16)!=2 or get(o,PUBLIC_OUT+24)!=get(w,104) or get(o,PUBLIC_OUT+32)!=get(w,112) or get(o,PUBLIC_OUT+40)!=get(w,120) or get(o,PUBLIC_OUT+48)==0:
        return 0
    within(o,at,PUBLIC_OUT+48,24)
    return 1
def public_failure(o:mutbuf) -> u64:
    if get(o,PUBTYPE)==1 or get(o,PUBTYPE)==2:
        return 3
    return 7
def drop_value(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    release_begin(o)
    request(o,VALUE_DROP_INPUT,29)
    within(o,RQ+24,at,24)
    return values(o,w,next,128)

def clear_value(o:mutbuf,at:u64) -> u64:
    return release_value(o,at)

def admission_status(o:mutbuf) -> u64:
    if valid(o,ADMOUT,ADMIT_REPLY)==0:
        return 7
    if get(o,ADMOUT+8)==0:
        return 0
    n=get(o,ADMOUT+24)
    if n>1024:
        return 9
    within(o,ERR,ADMOUT+128,n)
    put(o,ERRN,n)
    return 1
def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6
def deallocate(o:mutbuf,next:u64,p:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,p)
    return 7
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    put(o,CLEAN,0)
    return again(o,700)
def accepted_failure(o:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,ACCEPTED)!=0:
        zero(o,META,24)
    return fail(o,status,detail)
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    kind=2
    if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)==1:
        kind=1
    if detail==712 and valid(o,RP,PAYLOAD_REPLY)!=0:
        status=get(o,RP+8)
        if status==1 or status==5 or status==6:
            kind=1
    put(o,QUARANTINE_KIND,kind)
    if get(o,ERROR)==0:
        put(o,ERROR,7)
    put(o,DETAIL,detail)
    to_work(o,w,128,3072,CONTROL_N)
    to_work(o,w,FREEZE_WORK,3968,2048)
    to_work(o,w,ERR,6016,1024)
    to_work(o,w,STRUCT_CTX,7040,128)
    put(w,792,1)
    if get(o,LOCK)==0:
        return finish(o,w,9)
    request(o,QINPUT,11)
    return queue(o,w,792)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,ACCEPTED))
    if status==0 and get(o,OP)==0:
        from_work(w,o,104,24,24)
        within(o,48,FUSER,24)
        zero(o,FUSER,24)
    if status==2 and get(o,OP)==0:
        within(o,24,PROVIDER,24)
        put(o,48,get(o,SNAP_N))
        put(o,56,get(o,SNAP_PTR))
        zero(o,PROVIDER,24)
    if status==3 and get(o,OP)==0:
        within(o,24,PUBERROR,24)
        put(o,48,get(o,PUBKIND))
        put(o,56,get(o,PUBTYPE))
        put(o,64,get(o,PUBCLASS))
        zero(o,PUBERROR,24)
    put(o,72,get(o,Q_SLOT))
    put(o,80,get(o,ERRN))
    put(o,88,get(w,792))
    put(o,96,get(o,DETAIL))
    put(o,104,get(o,UCHAR))
    put(o,112,get(o,USTART))
    put(o,120,get(o,UEND))
    if status==1:
        within(o,128,ERR,get(o,ERRN))
    return 0
def hash_hex(o:mutbuf,w:mutbuf,at:u64,start:u64) -> u64:
    i=0
    while i<32:
        b=byte(w,start+i)
        store(o,at+2*i,hex_digit(b>>4))
        store(o,at+2*i+1,hex_digit(b&15))
        i=i+1
    return 64
def hex_digit(n:u64) -> u64:
    return choose(n<10,48+n,87+n)
def digits(o:mutbuf,at:u64,value:u64) -> u64:
    n=0
    while value!=0 or n==0:
        store(o,ST+n,48+value%10)
        value=value//10
        n=n+1
    i=0
    while i<n:
        store(o,at+i,byte(o,ST+n-i-1))
        i=i+1
    return n
def clock_decimal(o:mutbuf,at:u64,seconds:u64,nanos:u64) -> u64:
    if seconds==0:
        return digits(o,at,nanos)
    n=digits(o,at,seconds)
    i=0
    divisor=100000000
    while i<9:
        store(o,at+n+i,48+(nanos//divisor)%10)
        divisor=divisor//10
        i=i+1
    return n+9
'''
LABELS={0:'job',1:'generation',2:'epoch',3:'function',4:'before_sha256',5:'before_input_sha256',6:'original_baseline_sha256',7:'submit_work_ns',8:'submitted_ns',9:'enqueued_ns',10:'work_started_ns',11:'status',12:'reason',100:'candidates',101:'observations',102:'objective',103:'stale',104:'incumbent_snapshot_changed'}
SOURCE+='\n'+R.SOURCE
def source_program():
 s=SOURCE
 for name in ('invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'):
  node=next(x for x in ast.parse(BASE).body if isinstance(x,ast.FunctionDef)and x.name==name)
  s+='\n'+ast.get_source_segment(BASE,node)+'\n'
 def emit(name,raw):
  return '\ndef '+name+'(o:mutbuf,at:u64) -> u64:\n'+''.join('    put(o,at+'+str(i)+','+str(int.from_bytes(raw[i:i+8],"little"))+')\n' for i in range(0,len(raw)-len(raw)%8,8))+''.join('    store(o,at+'+str(i)+','+str(raw[i])+')\n' for i in range(len(raw)-len(raw)%8,len(raw)))+'    return '+str(len(raw))+'\n'
 s+='\ndef literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
 for k in LABELS:s+='    if id=='+str(k)+':\n        return literal_'+str(k)+'(o,at)\n'
 s+='    return 0\n'
 for k,v in LABELS.items():s+=emit('literal_'+str(k),v.encode())
 s+='\ndef original_error(o:mutbuf,id:u64) -> u32:\n    n=0\n'
 for k,v in {1:'coordinator is shut down',2:'finite outstanding job capacity is exhausted'}.items():
  raw=json.dumps({'message':'E_HIA_BACKGROUND: '+v,'type':'BackgroundOptimizationRejected'},sort_keys=True,separators=(',',':')).encode()
  s+='    if id=='+str(k)+':\n        n=original_'+str(k)+'(o,ERR)\n'
 s+='    put(o,ERRN,n)\n    return fail(o,1,id)\n'
 for k,v in {1:'coordinator is shut down',2:'finite outstanding job capacity is exhausted'}.items():
  raw=json.dumps({'message':'E_HIA_BACKGROUND: '+v,'type':'BackgroundOptimizationRejected'},sort_keys=True,separators=(',',':')).encode()
  s+=emit('original_'+str(k),raw)
 s+='\ndef structural_error(o:mutbuf,id:u64,limit:u64) -> u64:\n'
 for k in ERRORS:s+='    if id=='+str(k)+':\n        return structural_'+str(k)+'(o,ERR)\n'
 s+='    if id==9:\n        n=digit_prefix(o,ERR)\n        n=n+digits(o,ERR+n,limit)\n        n=n+digit_suffix(o,ERR+n)\n        return n\n    return 0\n'
 for k,v in ERRORS.items():s+=emit('structural_'+str(k),json.dumps({'message':v,'type':'HIAProgramRejected'},sort_keys=True,separators=(',',':')).encode())
 s+=emit('digit_prefix',b'{"message":"Exceeds the limit (')
 s+=emit('digit_suffix',b' digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit","type":"ValueError"}')
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_submission')
if __name__=='__main__':
 tree=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_submission.hepta';p.write_text(render_assembly(tree))
 print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
