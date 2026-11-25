"""Native BackgroundOptimizer execution continuation.

Development construction only. The generated HIA owns the runtime sequence;
the final closed adapter only performs its fixed native calls and effects.
"""
from pathlib import Path
from tools import hia_background_retirement_source as R
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE
ROOT=Path(__file__).resolve().parents[1]
C={
'MAGIC':int.from_bytes(b'HIABEX01','little'),'REPLY':int.from_bytes(b'HIABER01','little'),'CONTEXT':int.from_bytes(b'HIABEXC1','little'),
'VALUE_INPUT':int.from_bytes(b'HIABVQ01','little'),'VALUE_REPLY':int.from_bytes(b'HIABVR01','little'),
'VALUE_DROP_INPUT':int.from_bytes(b'HIABVQ02','little'),'VALUE_DROP_REPLY':int.from_bytes(b'HIABVR02','little'),
'JOB_DROP_INPUT':int.from_bytes(b'HIABJO03','little'),'JOB_DROP_REPLY':int.from_bytes(b'HIABJOR2','little'),
'DROP_ACTIVE':1104,'DROP_KNOWN':1112,'DROP_TARGET':1120,'VALUE_PENDING':1128,'JOB_PENDING':1136,
'JOB_INPUT':int.from_bytes(b'HIABJO02','little'),'JOB_REPLY':int.from_bytes(b'HIABJOR1','little'),
'PAYLOAD_INPUT':int.from_bytes(b'HIABPY01','little'),'PAYLOAD_REPLY':int.from_bytes(b'HIABPYR1','little'),
'PROVIDER_INPUT':int.from_bytes(b'HIAMVBQ1','little'),'PROVIDER_REPLY':int.from_bytes(b'HIAMVBO1','little'),'SNAPSHOT':int.from_bytes(b'HIAMVBS1','little'),
'REPORT_INPUT':int.from_bytes(b'HIABRP01','little'),'REPORT_REPLY':int.from_bytes(b'HIABRR01','little'),'REPORT_CONTEXT':int.from_bytes(b'HIABRC01','little'),
'KERNEL_INPUT':int.from_bytes(b'HIAMVFQ1','little'),'KERNEL_REPLY':int.from_bytes(b'HIAMVFR1','little'),
'IO_INPUT':int.from_bytes(b'HIABIQ01','little'),'IO_REPLY':int.from_bytes(b'HIABIO01','little'),'IO_CONTEXT':int.from_bytes(b'HIABIC01','little'),
'DECISION_INPUT':int.from_bytes(b'HIABDO01','little'),'DECISION_REPLY':int.from_bytes(b'HIABDRP1','little'),
'QUEUE_INPUT':int.from_bytes(b'HIABGQ02','little'),'QUEUE_REPLY':int.from_bytes(b'HIABGQR1','little'),
'RANK_INPUT':int.from_bytes(b'HIANRK01','little'),'NORM':int.from_bytes(b'HIAVCF01','little'),
'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'OUT':524288,
'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'PID':160,'RESUME':168,'DEST':176,'LITERAL':184,'VOP':192,
'KEY_ID':200,'CONTAINER':208,'OPERAND':232,'OPTIONAL':256,'FOUND':264,'CLEAN':272,'SAVED':280,
'CLOCK_SEC':288,'CLOCK_NS':296,'KERNEL':304,'RAW_PTR':312,'RAW_N':320,'FD':328,'MAP_PTR':336,'MAP_N':344,'FRAME':352,'FRAME_N':360,'RANK_WORK':368,'RANK_WORK_N':376,
'SNAP_PTR':384,'SNAP_N':392,'SNAP_GEN_N':400,'SNAP_EPOCH_N':408,'CMP_PTR':416,'CMP_N':424,'CMP_AT':432,'CMP_RESULT':440,'FEEDBACK':448,
'SNAPSHOT_NEXT':456,'TOKEN_NEXT':464,'VALUE_NEXT':472,'INIT_RESULT':480,'TASK':488,'INPUT_PTR':496,'INPUT_N':504,'IMPORT_NEXT':512,'IMPORT_DEST':520,'DREQ':528,'DREQ_N':536,
'BASE_PTR':544,'BASE_N':552,'RANK_STATUS':560,'RANK_RESULT_PTR':568,'RANK_RESULT_N':576,'CLOCK_NEXT':584,'CLOCK_DEST':592,'MEASURE_START':600,'MEASURE_END':608,'ARG_INDEX':616,
'MODULE':680,'ERROR_FORMAT':688,'PUB_FRAME':696,'PUB_FRAME_N':704,'PUB_GEN_N':712,'PUB_EPOCH_N':720,'PUB_CAND_N':728,'PUB_CAND_PTR':736,'PUB_BUDGET':744,'PUB_HANDOFF':752,'PUB_STATUS':760,'PUB_PTR':768,'PUB_N':776,'PUB_COMMIT':784,'COPY_NEXT':792,'COPY_PTR':800,'COPY_N':808,'COPY_AT':816,'COPY_COUNT':824,'COPY_CAP':832,'DROP_NEXT':856,'DROP_AT':864,'CLOCK_WORD':872,'COMPARE_NEXT':880,'COMPARE_VALUE':888,'COMPARE_FIRST':912,'COMPARE_SIZE':920,'CONTROLLER_NEXT':928,'NESTED':936,'NESTED_PHASE':944,
'CAND_CORE_SHA':1024,'CAND_INPUT_SHA':1056,
'SUBMIT':5032,'RANK_MARGIN':5056,'CAP_VALUE':5080,'DURATION':5104,'SUBMIT_DURATION':5128,'CAP_LESS_SEARCH':5152,'CAP_MARGIN':5176,'MARGIN_LESS_ONE':5200,'COMPARE':5224,'ZERO':5248,'REASON':5272,'SELECTED':5296,'SUM':5320,'SEARCH_OUTSIDE':5344,'PUB_HAND_DELTA':5368,'RUNTIME_DELTA':5392,'RUNTIME_RETURN':5416,'RANK_COSTS':5440,'MARGIN_AFTER_PREPARE':5464,'CANDIDATE_TEMP':5488,
'ADMITTED':624,'SELECTED_SOURCE_PTR':632,'SELECTED_SOURCE_N':640,'RANK_PURE_NEXT':648,'LOCK':656,
'G_META':4096,'G_JOB':4120,'RESULT':4144,'COSTS':4168,'INPUTS':4192,'ARGS':4216,'RANKING':4240,'ERROR_VALUE':4264,
'ENQUEUED':4288,'START':4312,'QUEUE_WAIT':4336,'RANK_START':4360,'RANK_END':4384,'RANK_WALL':4408,
'GEN':4432,'EPOCH':4456,'GEN_NEXT':4480,'TEMP':4504,'TEMP2':4528,'TEMP3':4552,'KEY':4576,'CMP_VALUE':4600,
'OBS':4624,'CANDIDATES':4648,'OBJECTIVE':4672,'CHARGED':4696,'SEARCH':4720,'OUTSIDE':4744,'MARGIN':4768,
'BUDGET':4792,'HANDOFF':4816,'PUB_START':4840,'PUB_END':4864,'PUB_WALL':4888,'PUBLICATION':4912,'PREPARE':4936,'NET':4960,'TOTAL':4984,'RETURN_TIME':5008,
'SOURCE_RECORD':1536,'BASE_PAYLOAD':1560,'PROVIDER':1584,'OLD_SOURCE':1608,'DECISION_ERROR':1632,
'INFO':2048,'TS':2304,'ST':2400,'RQ':16384,'RP':24576,'RP_N':16384,'REPORT_OUT':40960,'REPORT_WORK':49152,'REPORT_SOURCE':81920,
'IO_OUT':98304,'IO_WORK':229376,'RANK_OUT':262144,'DECISION_OUT':262144,'ERR':327680,
}
C.update(R.MAGICS)
SOURCE=r'''
def execute(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return starting(s,o,w,phase)
    if phase<200:
        return ranking(s,o,w,phase)
    if phase<300:
        return publication(s,o,w,phase)
    if phase>=1000 and phase<1100:
        return value_task(o,w,phase)
    if phase>=1100 and phase<1200:
        return clocks(o,w,phase)
    if phase>=1200 and phase<1300:
        return report_task(o,w,phase)
    if phase>=1300 and phase<1400:
        return snapshot_task(o,w,phase)
    if phase>=1400 and phase<1500:
        return import_task(o,w,phase)
    if phase>=1500 and phase<1600:
        return transport_task(o,w,phase)
    if phase>=1600 and phase<1700:
        return rank_task(o,w,phase)
    if phase>=1700 and phase<1900:
        return simple_task(o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return 4294967293
    at=16
    while at<128:
        used=word_load(s,8)==0 and at<=88
        if used==False and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)<1024 or get(w,64)==0:
        return 4294967293
    if get(w,88)==0 or get(w,96)==0 or get(w,104)<256 or get(w,112)==0 or get(w,120)==0 or get(w,128)<256:
        return 4294967293
    if get(w,136)==0 or get(w,144)==0 or get(w,152)<4096 or get(w,160)==0:
        return 4294967293
    if get(w,216)==0 or get(w,224)==0 or get(w,232)<256 or get(w,240)==0:
        return 4294967293
    if get(w,248)<3 or get(w,256)<3 or get(w,264)<3 or get(w,280)==0 or get(w,288)!=10100891:
        return 4294967293
    if get(w,320)==0 or get(w,328)<8192 or get(w,464)>1:
        return 4294967293
    zero(o,128,8064)
    zero(o,IO_WORK,256)
    put(o,OP,word_load(s,8))
    put(o,FD,MAX)
    return system(o,1,39,0,0,0,0,0,0,0)

def starting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,456)!=0 and get(w,456)!=pid):
            return finish(o,w,6)
        put(w,456,pid)
        put(o,PID,pid)
        put(o,0,0)
        put(o,PHASE,50)
        return 4
    if phase==50:
        ptr=get(o,FEEDBACK)
        if ptr==0 or (get(w,464)!=0 and get(w,472)!=ptr):
            return finish(o,w,6)
        put(w,472,ptr)
        if get(o,OP)==1:
            if get(w,464)==0:
                return finish(o,w,0)
            if get(w,480)==2:
                return finish(o,w,6)
            from_work(w,o,512,128,8064)
            from_work(w,o,8576,IO_WORK,256)
            put(o,OP,1)
            put(w,464,0)
            put(w,480,0)
            put(o,CLEAN,0)
            return again(o,2000)
        if get(w,464)!=0:
            return finish(o,w,6)
        return clock_value(o,2,START)
    if phase==2:
        request(o,JOB_INPUT,2)
        copy_source(s,o,16,RQ+24,24)
        return jobs(o,w,3)
    if phase==3:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),3)
        within(o,G_JOB,RP+16,24)
        request(o,JOB_INPUT,6)
        within(o,RQ+24,G_JOB,24)
        return jobs(o,w,4)
    if phase==4:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)==0 or get(o,RP+96)!=512:
            return fail(o,7,4)
        put(o,KERNEL,get(o,RP+64))
        put(o,RAW_PTR,get(o,RP+80))
        put(o,RAW_N,get(o,RP+40))
        request(o,VALUE_INPUT,5)
        copy_source(s,o,40,RQ+24,24)
        return values(o,w,5,128)
    if phase==5:
        if take_value(o,G_META)!=0:
            return fail(o,value_failure(o),5)
        zero(o,REPORT_SOURCE,128)
        put(o,REPORT_SOURCE,REPORT_INPUT)
        within(o,REPORT_SOURCE+24,G_META,24)
        zero(o,REPORT_WORK,32768)
        put(o,REPORT_WORK,REPORT_CONTEXT)
        put(o,REPORT_WORK+8,get(w,8))
        put(o,REPORT_WORK+16,get(w,16))
        put(o,REPORT_WORK+24,get(w,24))
        put(o,REPORT_OUT+128,0)
        return again(o,1200)
    if phase==6:
        return lookup(o,7,RESULT,1,COSTS,0)
    if phase==7:
        return lookup(o,8,G_META,2,ENQUEUED,0)
    if phase==8:
        return arithmetic(o,w,9,QUEUE_WAIT,START,ENQUEUED,1)
    if phase==9:
        return assign(o,10,COSTS,3,QUEUE_WAIT)
    if phase==10:
        return snapshot(o,11)
    if phase==11:
        if get(o,CMP_RESULT)==0:
            return done(o)
        return import_value(o,12,INPUTS,get(o,RAW_PTR),get(o,RAW_N))
    if phase==12:
        return token(o,w,13)
    if phase==13:
        if get(o,INFO)==1:
            return done(o)
        return clock_value(o,14,RANK_START)
    if phase==14:
        request(o,VALUE_INPUT,4)
        return values(o,w,15,128)
    if phase==15:
        if take_value(o,ARGS)!=0:
            return fail(o,value_failure(o),15)
        put(o,ARG_INDEX,0)
        return again(o,16)
    if phase==16:
        index=get(o,ARG_INDEX)
        if index==8:
            return export_value(o,22,ARGS)
        if index==0:
            return lookup(o,17,INPUTS,4,TEMP,0)
        if index==1:
            return lookup(o,17,INPUTS,5,TEMP,0)
        if index==4:
            return lookup(o,17,INPUTS,8,TEMP,0)
        if index==5:
            return lookup(o,18,G_META,9,EPOCH,0)
        request(o,VALUE_INPUT,5)
        at=360
        if index==3:
            at=384
        elif index==6:
            at=408
        elif index==7:
            at=432
        from_work(w,o,at,RQ+24,24)
        return values(o,w,17,128)
    if phase==17:
        if get(o,TEMP)==0:
            if take_value(o,TEMP)!=0:
                return fail(o,value_failure(o),17)
        return assign(o,20,ARGS,arg_key(get(o,ARG_INDEX)),TEMP)
    if phase==18:
        request(o,VALUE_INPUT,24)
        within(o,RQ+24,EPOCH,24)
        from_work(w,o,336,RQ+48,24)
        put(o,RESUME,19)
        put(o,DEST,TEMP)
        return values(o,w,1010,128)
    if phase==19:
        return assign(o,20,ARGS,10,TEMP)
    if phase==20:
        return drop_value(o,w,21,TEMP)
    if phase==21:
        if cleared(o,TEMP)==0:
            return quarantine(o,w,21)
        put(o,ARG_INDEX,get(o,ARG_INDEX)+1)
        return again(o,16)
    if phase==22:
        request(o,JOB_INPUT,8)
        within(o,RQ+24,G_JOB,24)
        put(o,RQ+80,0)
        return jobs(o,w,23)
    if phase==23:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)==0:
            return fail(o,7,23)
        within(o,BASE_PAYLOAD,RP+16,24)
        request(o,PAYLOAD_INPUT,6)
        within(o,RQ+24,BASE_PAYLOAD,24)
        return payload_owner(o,w,24)
    if phase==24:
        if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,7,24)
        put(o,BASE_PTR,get(o,RP+64))
        put(o,BASE_N,get(o,RP+40))
        if get(o,BASE_N)<8:
            return fail(o,7,24)
        return memory(o,25,0,get(o,BASE_PTR),3,INFO,choose(get(o,BASE_N)<64,get(o,BASE_N),64))
    if phase==25:
        if get(o,INFO)==NORM:
            if get(o,BASE_N)<64 or get(o,INFO+8)!=0 or get(o,INFO+16)!=0 or get(o,INFO+24)>4 or get(o,INFO+48)!=0 or get(o,INFO+56)!=0:
                return fail(o,7,25)
            original=get(o,INFO+32)
            core=get(o,INFO+40)
            if original==0 or core==0 or original>8388608 or core>8388608 or get(o,BASE_N)!=64+original+core:
                return fail(o,7,25)
            put(o,BASE_PTR,get(o,BASE_PTR)+64)
            put(o,BASE_N,original)
        return again(o,1600)
    return fail(o,7,phase)

def ranking(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        return arithmetic(o,w,101,RANK_WALL,RANK_END,RANK_START,1)
    if phase==101:
        return assign(o,102,COSTS,13,RANK_WALL)
    if phase==102:
        if get(o,RANK_STATUS)!=0:
            return fail(o,7,get(o,RANK_STATUS))
        status=get(o,RANK_OUT+4000)
        at=get(o,RANK_OUT+4016)
        n=get(o,RANK_OUT+4024)
        if status>2 or at>get(o,RANK_WORK_N) or n>get(o,RANK_WORK_N)-at or get(o,RANK_WORK)==0:
            return fail(o,7,102)
        put(o,RANK_STATUS,status)
        if n==0:
            return fail(o,choose(status==2,2,7),102)
        dest=choose(status==0,RANKING,ERROR_VALUE)
        put(o,ERROR_FORMAT,choose(status==0,0,2))
        return import_value(o,103,dest,get(o,RANK_WORK)+at,n)
    if phase==103:
        if get(o,RANK_STATUS)!=0:
            return fail(o,get(o,RANK_STATUS),103)
        return assign(o,104,RESULT,14,RANKING)
    if phase==104:
        return token(o,w,105)
    if phase==105:
        if get(o,INFO)==1:
            return done(o)
        if get(w,296)==0 or get(w,304)==0 or get(w,312)==0:
            return fail(o,7,105)
        request(o,DECISION_INPUT,0)
        within(o,RQ+16,G_META,24)
        within(o,RQ+40,INPUTS,24)
        within(o,RQ+64,RANKING,24)
        within(o,RQ+88,RANK_WALL,24)
        put(o,NESTED,1)
        return invoke(o,106,get(w,296),51,RQ,128,DECISION_OUT,262144,get(w,304),get(w,312))
    if phase==106:
        if valid(o,DECISION_OUT,DECISION_REPLY)==0:
            return quarantine(o,w,106)
        if get(o,DECISION_OUT+88)!=0:
            return quarantine(o,w,106)
        put(o,NESTED,0)
        status=get(o,DECISION_OUT+8)
        if get(o,DECISION_OUT+24)!=0:
            within(o,SOURCE_RECORD,DECISION_OUT+24,24)
        if get(o,DECISION_OUT+56)!=0:
            within(o,DECISION_ERROR,DECISION_OUT+56,24)
        if status==1:
            if get(o,DECISION_ERROR)==0 or get(o,DECISION_OUT+104)<1 or get(o,DECISION_OUT+104)>3:
                return fail(o,7,106)
            put(o,ERROR_FORMAT,get(o,DECISION_OUT+104))
            request(o,PAYLOAD_INPUT,6)
            within(o,RQ+24,DECISION_ERROR,24)
            return payload_owner(o,w,190)
        if status!=0:
            return fail(o,choose(status>=5 and status<=8,status,7),get(o,DECISION_OUT+96))
        if get(o,DECISION_OUT+16)>1:
            return fail(o,7,106)
        put(o,ADMITTED,get(o,DECISION_OUT+16))
        if get(o,ADMITTED)==0:
            return literal_value(o,w,108,TEMP,31)
        if get(o,SOURCE_RECORD)==0:
            return fail(o,7,106)
        within(o,CAND_CORE_SHA,DECISION_OUT+128,64)
        return lookup(o,120,RANKING,1,RANK_COSTS,0)
    if phase==108:
        return assign(o,109,RESULT,16,TEMP)
    if phase==109:
        return discard(o,w,110,TEMP)
    if phase==110:
        return lookup(o,111,RANKING,15,REASON,1)
    if phase==111:
        if get(o,FOUND)==0:
            return literal_value(o,w,112,REASON,32)
        return again(o,112)
    if phase==112:
        return assign(o,113,RESULT,15,REASON)
    if phase==113:
        return done(o)
    if phase==120:
        return lookup(o,121,RANK_COSTS,36,CHARGED,0)
    if phase==121:
        return lookup(o,122,RANK_COSTS,37,SEARCH,0)
    if phase==122:
        return snapshot(o,123)
    if phase==123:
        if get(o,CMP_RESULT)==0:
            return done(o)
        put(o,MODULE,1)
        return again(o,200)
    if phase==190:
        if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+40)==0:
            return fail(o,7,190)
        return import_value(o,191,ERROR_VALUE,get(o,RP+64),get(o,RP+40))
    if phase==191:
        return fail(o,1,191)
    return fail(o,7,phase)

def publication(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    put(o,MODULE,1)
    return again(o,phase)

def publish_continue(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384 or get(o,MODULE)!=1:
        return 4294967293
    phase=get(o,PHASE)
    if phase>=200 and phase<228:
        return budget(o,w,phase)
    if phase>=228 and phase<242:
        return prepare_publication(o,w,phase)
    if phase>=242 and phase<253:
        return returned_publication(o,w,phase)
    if phase>=253 and phase<300:
        return published_report(o,w,phase)
    if phase>=1000 and phase<1100:
        return value_task(o,w,phase)
    if phase>=1100 and phase<1200:
        return clocks(o,w,phase)
    if phase>=1400 and phase<1500:
        return import_task(o,w,phase)
    if phase>=1700 and phase<1900:
        return simple_task(o,w,phase)
    return cleanup(o,w,phase)

def budget(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        return clock_value(o,201,HANDOFF)
    if phase==201:
        put(o,PUB_HANDOFF,get(o,CLOCK_WORD))
        return lookup(o,202,G_META,22,SUBMIT,0)
    if phase==202:
        return arithmetic(o,w,203,DURATION,HANDOFF,START,1)
    if phase==203:
        return arithmetic(o,w,204,SUBMIT_DURATION,SUBMIT,DURATION,0)
    if phase==204:
        return arithmetic(o,w,205,OUTSIDE,SUBMIT_DURATION,CHARGED,1)
    if phase==205:
        return lookup(o,206,RANKING,17,RANK_MARGIN,0)
    if phase==206:
        return arithmetic(o,w,207,MARGIN,RANK_MARGIN,OUTSIDE,1)
    if phase==207:
        return lookup(o,208,INPUTS,8,OBJECTIVE,0)
    if phase==208:
        return lookup(o,209,OBJECTIVE,18,CAP_VALUE,0)
    if phase==209:
        return arithmetic(o,w,210,CAP_LESS_SEARCH,CAP_VALUE,SEARCH,1)
    if phase==210:
        return arithmetic(o,w,211,CAP_MARGIN,CAP_LESS_SEARCH,OUTSIDE,1)
    if phase==211:
        request(o,VALUE_INPUT,24)
        within(o,RQ+24,MARGIN,24)
        from_work(w,o,336,RQ+48,24)
        put(o,RQ+104,1)
        put(o,RESUME,212)
        put(o,DEST,MARGIN_LESS_ONE)
        return values(o,w,1010,128)
    if phase==212:
        return arithmetic(o,w,213,COMPARE,MARGIN_LESS_ONE,CAP_MARGIN,1)
    if phase==213:
        return first_digit(o,w,214,COMPARE)
    if phase==214:
        source=choose(get(o,COMPARE_FIRST)==45,MARGIN_LESS_ONE,CAP_MARGIN)
        return retain_value(o,w,215,BUDGET,source)
    if phase==215:
        return assign(o,216,COSTS,23,OUTSIDE)
    if phase==216:
        return first_digit(o,w,217,BUDGET)
    if phase==217:
        if get(o,COMPARE_FIRST)==45 or (get(o,COMPARE_FIRST)==48 and get(o,COMPARE_SIZE)==1):
            return word_value(o,w,218,ZERO,0)
        return assign(o,226,COSTS,24,BUDGET)
    if phase==218:
        return assign(o,219,COSTS,24,ZERO)
    if phase==219:
        return literal_value(o,w,220,TEMP,31)
    if phase==220:
        return assign(o,221,RESULT,16,TEMP)
    if phase==221:
        return discard(o,w,222,TEMP)
    if phase==222:
        return literal_value(o,w,223,REASON,33)
    if phase==223:
        return assign(o,224,RESULT,15,REASON)
    if phase==224:
        return done(o)
    if phase==226:
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,BUDGET,24)
        put(o,RQ+112,choose(get(o,COMPARE_SIZE)<32,get(o,COMPARE_SIZE),32))
        return values(o,w,227,128)
    if phase==227:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=2 or get(o,RP+72)==0 or get(o,RP+72)>19 or get(o,RP+64)!=get(o,RP+72):
            return fail(o,value_failure(o),227)
        n=get(o,RP+72)
        x=0
        i=0
        while i<n:
            b=byte(o,RP+8192+i)
            if b<48 or b>57 or x>922337203685477580 or (x==922337203685477580 and b>55):
                return fail(o,7,227)
            x=x*10+b-48
            i=i+1
        if x==0:
            return fail(o,7,227)
        put(o,PUB_BUDGET,x)
        return clock_value(o,228,PUB_START)
    return fail(o,7,phase)

def prepare_publication(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==228:
        return lookup(o,229,G_META,10,GEN,0)
    if phase==229:
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,GEN,24)
        return values(o,w,230,128)
    if phase==230:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=2 or get(o,RP+72)==0:
            return fail(o,value_failure(o),230)
        put(o,PUB_GEN_N,get(o,RP+72))
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,EPOCH,24)
        return values(o,w,231,128)
    if phase==231:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=2 or get(o,RP+72)==0:
            return fail(o,value_failure(o),231)
        put(o,PUB_EPOCH_N,get(o,RP+72))
        request(o,PAYLOAD_INPUT,6)
        within(o,RQ+24,SOURCE_RECORD,24)
        return payload_owner(o,w,232)
    if phase==232:
        if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+40)<64:
            return fail(o,7,232)
        put(o,PUB_CAND_PTR,get(o,RP+64))
        put(o,PUB_CAND_N,get(o,RP+40))
        return memory(o,233,0,get(o,PUB_CAND_PTR),3,INFO,64)
    if phase==233:
        original=get(o,INFO+32)
        core=get(o,INFO+40)
        if get(o,INFO)!=NORM or get(o,INFO+8)!=0 or get(o,INFO+16)!=0 or get(o,INFO+24)>4 or get(o,INFO+48)!=0 or get(o,INFO+56)!=0:
            return fail(o,7,233)
        if original==0 or original>8388608 or core==0 or core>8388608 or get(o,PUB_CAND_N)!=64+original+core:
            return fail(o,7,233)
        put(o,PUB_CAND_PTR,get(o,PUB_CAND_PTR)+64)
        put(o,PUB_CAND_N,original)
        total=128
        if get(o,PUB_GEN_N)>MAX-total:
            return fail(o,5,233)
        total=total+get(o,PUB_GEN_N)
        if get(o,PUB_EPOCH_N)>MAX-total:
            return fail(o,5,233)
        total=total+get(o,PUB_EPOCH_N)
        if original>MAX-total:
            return fail(o,5,233)
        total=total+original
        put(o,PUB_FRAME_N,total)
        return allocate(o,234,total)
    if phase==234:
        if get(o,FEEDBACK)==0:
            return fail(o,5,234)
        put(o,PUB_FRAME,get(o,FEEDBACK))
        request(o,PROVIDER_INPUT,2)
        from_work(w,o,64,RQ+16,24)
        put(o,RQ+40,get(o,KERNEL))
        put(o,RQ+48,512)
        put(o,RQ+56,get(o,PUB_GEN_N))
        put(o,RQ+64,get(o,PUB_EPOCH_N))
        put(o,RQ+72,get(o,PUB_CAND_N))
        put(o,RQ+88,get(o,PUB_BUDGET))
        put(o,RQ+96,get(o,PUB_HANDOFF))
        return memory(o,235,3,RQ,0,get(o,PUB_FRAME),128)
    if phase==235:
        return scalar_copy(o,236,GEN,get(o,PUB_FRAME)+128,get(o,PUB_GEN_N))
    if phase==236:
        return scalar_copy(o,237,EPOCH,get(o,PUB_FRAME)+128+get(o,PUB_GEN_N),get(o,PUB_EPOCH_N))
    if phase==237:
        at=get(o,PUB_FRAME)+128+get(o,PUB_GEN_N)+get(o,PUB_EPOCH_N)
        return memory(o,240,0,get(o,PUB_CAND_PTR),0,at,get(o,PUB_CAND_N))
    if phase==240:
        return invoke(o,241,get(w,40),48,get(o,PUB_FRAME),get(o,PUB_FRAME_N),RP,512,get(w,48),get(w,56))
    if phase==241:
        if valid(o,RP,PROVIDER_REPLY)==0:
            put(o,PUB_STATUS,7)
            put(o,DETAIL,241)
        else:
            if get(o,RP+40)!=0:
                within(o,PROVIDER,RP+40,24)
            put(o,PUB_STATUS,get(o,RP+8))
            put(o,PUB_PTR,get(o,RP+24))
            put(o,PUB_N,get(o,RP+32))
            put(o,PUB_COMMIT,get(o,RP+64))
        return clock_value(o,242,PUB_END)
    return fail(o,7,phase)

def returned_publication(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==242:
        return arithmetic(o,w,243,PUB_WALL,PUB_END,PUB_START,1)
    if phase==243:
        return assign(o,244,COSTS,25,PUB_WALL)
    if phase==244:
        status=get(o,PUB_STATUS)
        if status!=0:
            if status==1 and get(o,PROVIDER)!=0 and get(o,PUB_N)!=0:
                put(o,ERROR_FORMAT,2)
                return import_value(o,290,ERROR_VALUE,get(o,PUB_PTR),get(o,PUB_N))
            return fail(o,choose(status==2,5,7),status)
        if get(o,PROVIDER)==0 or get(o,PUB_N)==0:
            return fail(o,7,244)
        return import_value(o,245,PUBLICATION,get(o,PUB_PTR),get(o,PUB_N))
    if phase==245:
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,246)
    if phase==246:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,7,246)
        put(o,LOCK,1)
        return memory(o,247,0,get(w,320)+664,3,OLD_SOURCE,24)
    if phase==247:
        return memory(o,248,3,SOURCE_RECORD,0,get(w,320)+664,24)
    if phase==248:
        zero(o,SOURCE_RECORD,24)
        return memory(o,249,3,CAND_CORE_SHA,0,get(w,320)+576,32)
    if phase==249:
        return memory(o,250,3,CAND_INPUT_SHA,0,get(w,320)+608,32)
    if phase==250:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,251)
    if phase==251:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,251)
        put(o,LOCK,0)
        return literal_value(o,w,252,TEMP,34)
    if phase==252:
        return assign(o,253,RESULT,16,TEMP)
    return fail(o,7,phase)

def published_report(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==253:
        return discard(o,w,254,TEMP)
    if phase==254:
        return literal_value(o,w,255,REASON,35)
    if phase==255:
        return assign(o,256,RESULT,15,REASON)
    if phase==256:
        return lookup(o,257,RANKING,19,SELECTED,0)
    if phase==257:
        return assign(o,258,RESULT,19,SELECTED)
    if phase==258:
        return assign(o,259,RESULT,21,PUBLICATION)
    if phase==259:
        return lookup(o,260,PUBLICATION,20,PREPARE,0)
    if phase==260:
        return arithmetic(o,w,261,MARGIN_AFTER_PREPARE,MARGIN,PREPARE,1)
    if phase==261:
        return arithmetic(o,w,262,SEARCH_OUTSIDE,SEARCH,OUTSIDE,0)
    if phase==262:
        return arithmetic(o,w,263,TOTAL,SEARCH_OUTSIDE,PREPARE,0)
    if phase==263:
        return arithmetic(o,w,264,PUB_HAND_DELTA,PUB_START,HANDOFF,1)
    if phase==264:
        return arithmetic(o,w,265,RUNTIME_DELTA,PUB_END,HANDOFF,1)
    if phase==265:
        return arithmetic(o,w,266,RUNTIME_RETURN,RUNTIME_DELTA,PREPARE,1)
    if phase==266:
        return assign(o,267,COSTS,26,PREPARE)
    if phase==267:
        return assign(o,268,COSTS,27,MARGIN_AFTER_PREPARE)
    if phase==268:
        return assign(o,269,COSTS,28,TOTAL)
    if phase==269:
        return assign(o,270,COSTS,29,PUB_HAND_DELTA)
    if phase==270:
        return assign(o,271,COSTS,30,RUNTIME_RETURN)
    if phase==271:
        return done(o)
    if phase==290:
        return fail(o,1,290)
    return fail(o,7,phase)

def value_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        n=literal(o,RQ+128,get(o,KEY_ID))
        put(o,RQ+96,n)
        return values(o,w,1001,128+n)
    if phase==1001:
        if take_value(o,KEY)!=0:
            return fail(o,value_failure(o),1001)
        request(o,VALUE_INPUT,get(o,VOP))
        within(o,RQ+24,CONTAINER,24)
        within(o,RQ+48,KEY,24)
        if get(o,VOP)==10:
            within(o,RQ+72,OPERAND,24)
        return values(o,w,1002,128)
    if phase==1002:
        if valid(o,RP,VALUE_REPLY)==0:
            return fail(o,7,1002)
        status=get(o,RP+8)
        put(o,FOUND,choose(status==0,1,0))
        if status!=0 and (status!=3 or get(o,OPTIONAL)==0):
            return fail(o,choose(status==5,5,7),status)
        if get(o,VOP)==9 and status==0:
            if take_value(o,get(o,DEST))!=0:
                return fail(o,7,1002)
        return drop_value(o,w,1003,KEY)
    if phase==1003:
        if cleared(o,KEY)==0:
            return quarantine(o,w,1003)
        return again(o,get(o,RESUME))
    if phase==1010:
        if take_value(o,get(o,DEST))!=0:
            return fail(o,value_failure(o),1010)
        return again(o,get(o,RESUME))
    return fail(o,7,phase)

def clocks(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1100:
        return system(o,1101,228,12,1,TS,0,0,0,0)
    if phase==1101:
        if get(o,FEEDBACK)==MAX-3:
            return again(o,1100)
        if get(o,FEEDBACK)!=0 or get(o,TS)>=9223372036854775808 or get(o,TS+8)>=1000000000:
            return fail(o,8,get(o,FEEDBACK))
        put(o,CLOCK_WORD,get(o,TS)*1000000000+get(o,TS+8))
        put(o,CLOCK_SEC,get(o,TS))
        put(o,CLOCK_NS,get(o,TS+8))
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,2)
        n=clock_decimal(o,RQ+128,get(o,CLOCK_SEC),get(o,CLOCK_NS))
        put(o,RQ+96,n)
        return values(o,w,1102,128+n)
    if phase==1102:
        if take_value(o,get(o,CLOCK_DEST))!=0:
            return fail(o,value_failure(o),1102)
        return again(o,get(o,CLOCK_NEXT))
    return fail(o,7,phase)

def report_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1200:
        return invoke(o,1201,get(w,32),819,REPORT_SOURCE,128,REPORT_OUT,8192,REPORT_WORK,32768)
    if phase==1201:
        rc=get(o,FEEDBACK)
        if rc==10:
            return again(o,1200)
        if rc==4:
            if get(o,REPORT_OUT)!=get(w,8):
                return quarantine(o,w,1201)
            put(o,0,get(w,8))
            mask=get(o,REPORT_OUT+8)
            mapped=0
            i=0
            while i<6:
                bank=(mask>>(i*2))&3
                arg=get(o,REPORT_OUT+16+i*8)
                if bank==1:
                    arg=arg+REPORT_WORK
                    mapped=mapped|(3<<(i*2))
                elif bank==2:
                    arg=arg+REPORT_SOURCE
                    mapped=mapped|(3<<(i*2))
                elif bank==3:
                    arg=arg+REPORT_OUT
                    mapped=mapped|(3<<(i*2))
                put(o,16+i*8,arg)
                i=i+1
            put(o,8,mapped)
            put(o,PHASE,1202)
            return 9
        if rc!=0 or get(o,REPORT_OUT)!=REPORT_REPLY:
            return quarantine(o,w,1201)
        if get(o,REPORT_OUT+8)!=0:
            return fail(o,choose(get(o,REPORT_OUT+8)==5,5,7),get(o,REPORT_OUT+8))
        if get(o,REPORT_OUT+24)==0:
            return fail(o,7,1201)
        within(o,RESULT,REPORT_OUT+24,24)
        put(o,INIT_RESULT,1)
        return again(o,6)
    if phase==1202:
        put(o,REPORT_OUT+136,get(o,FEEDBACK))
        return again(o,1200)
    return fail(o,7,phase)

def snapshot_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1300:
        request(o,PROVIDER_INPUT,1)
        from_work(w,o,64,RQ+16,24)
        return provider_owner(o,w,1301)
    if phase==1301:
        if valid(o,RP,PROVIDER_REPLY)==0:
            return fail(o,7,1301)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        status=get(o,RP+8)
        if status!=0:
            if status==1 and get(o,PROVIDER)!=0:
                put(o,ERROR,1)
                return import_value(o,1399,ERROR_VALUE,get(o,RP+24),get(o,RP+32))
            return fail(o,choose(status==2,5,7),status)
        if get(o,PROVIDER)==0 or get(o,RP+32)<256:
            return fail(o,7,1301)
        put(o,SNAP_PTR,get(o,RP+24))
        put(o,SNAP_N,get(o,RP+32))
        return memory(o,1302,0,get(o,SNAP_PTR),3,INFO,256)
    if phase==1302:
        n=get(o,SNAP_N)
        gn=get(o,INFO+24)
        en=get(o,INFO+32)
        if get(o,INFO)!=SNAPSHOT or get(o,INFO+40)!=n or gn>n-256 or en!=n-256-gn:
            return fail(o,7,1302)
        put(o,SNAP_GEN_N,gn)
        put(o,SNAP_EPOCH_N,en)
        put(o,CMP_RESULT,0)
        if (get(o,INFO+16)&1)!=0:
            return again(o,1390)
        return lookup(o,1303,G_META,10,CMP_VALUE,0)
    if phase==1303:
        put(o,CMP_PTR,get(o,SNAP_PTR)+256)
        put(o,CMP_N,get(o,SNAP_GEN_N))
        put(o,CMP_AT,0)
        put(o,TASK,0)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,CMP_VALUE,24)
        return values(o,w,1310,128)
    if phase==1310:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,value_failure(o),1310)
        if get(o,RP+72)!=get(o,CMP_N):
            return again(o,1380)
        return again(o,1311)
    if phase==1311:
        offset=get(o,CMP_AT)
        n=get(o,CMP_N)-offset
        if n==0:
            put(o,CMP_RESULT,1)
            return again(o,1380)
        if n>8192:
            n=8192
        put(o,INPUT_N,n)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,CMP_VALUE,24)
        put(o,RQ+104,offset)
        put(o,RQ+112,n)
        return values(o,w,1312,128)
    if phase==1312:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)!=get(o,INPUT_N):
            return fail(o,value_failure(o),1312)
        return memory(o,1313,0,get(o,CMP_PTR)+get(o,CMP_AT),3,RQ,get(o,INPUT_N))
    if phase==1313:
        i=0
        while i<get(o,INPUT_N):
            if byte(o,RQ+i)!=byte(o,RP+8192+i):
                return again(o,1380)
            i=i+1
        put(o,CMP_AT,get(o,CMP_AT)+get(o,INPUT_N))
        return again(o,1311)
    if phase==1380:
        return drop_value(o,w,1381,CMP_VALUE)
    if phase==1381:
        if cleared(o,CMP_VALUE)==0:
            return quarantine(o,w,1381)
        if get(o,CMP_RESULT)==0 or get(o,TASK)==1:
            return again(o,1390)
        return lookup(o,1382,G_META,9,CMP_VALUE,0)
    if phase==1382:
        put(o,CMP_PTR,get(o,SNAP_PTR)+256+get(o,SNAP_GEN_N))
        put(o,CMP_N,get(o,SNAP_EPOCH_N))
        put(o,CMP_AT,0)
        put(o,CMP_RESULT,0)
        put(o,TASK,1)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,CMP_VALUE,24)
        return values(o,w,1310,128)
    if phase==1390:
        request(o,PROVIDER_INPUT,5)
        within(o,RQ+40,PROVIDER,24)
        return provider_owner(o,w,1391)
    if phase==1391:
        if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,1391)
        zero(o,PROVIDER,24)
        return again(o,get(o,SNAPSHOT_NEXT))
    if phase==1399:
        return fail(o,1,1399)
    return fail(o,7,phase)

def import_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1400:
        n=get(o,INPUT_N)
        if n>MAX-128:
            return fail(o,5,n)
        put(o,DREQ_N,128+n)
        return allocate(o,1401,128+n)
    if phase==1401:
        if get(o,FEEDBACK)==0:
            return fail(o,5,1401)
        put(o,DREQ,get(o,FEEDBACK))
        request(o,VALUE_INPUT,1)
        put(o,RQ+96,get(o,INPUT_N))
        return memory(o,1402,3,RQ,0,get(o,DREQ),128)
    if phase==1402:
        return memory(o,1403,0,get(o,INPUT_PTR),0,get(o,DREQ)+128,get(o,INPUT_N))
    if phase==1403:
        return invoke(o,1404,get(w,8),48,get(o,DREQ),get(o,DREQ_N),RP,RP_N,get(w,16),get(w,24))
    if phase==1404:
        if take_value(o,get(o,IMPORT_DEST))!=0:
            return fail(o,value_failure(o),1404)
        return deallocate(o,1405,get(o,DREQ))
    if phase==1405:
        put(o,DREQ,0)
        return again(o,get(o,IMPORT_NEXT))
    return fail(o,7,phase)

def transport_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1500:
        return memory(o,1501,0,get(w,224),3,IO_WORK,256)
    if phase==1501:
        request(o,IO_INPUT,0)
        within(o,RQ+24,ARGS,24)
        return invoke(o,1502,get(w,216),819,RQ,128,IO_OUT,131072,IO_WORK,256)
    if phase==1502:
        if valid(o,IO_OUT,IO_REPLY)==0:
            return quarantine(o,w,1502)
        status=get(o,IO_OUT+8)
        if status!=0:
            return fail(o,choose(status==5,5,7),status)
        fd=get(o,IO_OUT+16)
        n=get(o,IO_OUT+24)
        if fd<3 or fd>2147483647 or n==0 or get(o,IO_OUT+32)!=15:
            return fail(o,7,1502)
        put(o,FD,fd)
        put(o,MAP_N,n)
        return system(o,1503,9,0,0,n,1,2,fd,0)
    if phase==1503:
        if get(o,FEEDBACK)>=NEGATIVE:
            return fail(o,choose(get(o,FEEDBACK)==MAX-11,5,8),get(o,FEEDBACK))
        put(o,MAP_PTR,get(o,FEEDBACK))
        fd=get(o,FD)
        put(o,FD,MAX)
        return system(o,1504,3,0,fd,0,0,0,0,0)
    if phase==1504:
        if get(o,FEEDBACK)>=NEGATIVE:
            return fail(o,8,get(o,FEEDBACK))
        return again(o,get(o,RESUME))
    return fail(o,7,phase)

def rank_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1600:
        base=get(o,BASE_N)
        args=get(o,MAP_N)
        if base>MAX-128 or args>MAX-128-base:
            return fail(o,5,1600)
        put(o,FRAME_N,128+base+args)
        return allocate(o,1601,get(o,FRAME_N))
    if phase==1601:
        if get(o,FEEDBACK)==0:
            return fail(o,5,1601)
        put(o,FRAME,get(o,FEEDBACK))
        zero(o,INFO,128)
        put(o,INFO,RANK_INPUT)
        put(o,INFO+8,1)
        put(o,INFO+16,get(o,BASE_N))
        put(o,INFO+24,get(o,MAP_N))
        return memory(o,1602,3,INFO,0,get(o,FRAME),128)
    if phase==1602:
        return memory(o,1603,0,get(o,BASE_PTR),0,get(o,FRAME)+128,get(o,BASE_N))
    if phase==1603:
        return memory(o,1604,0,get(o,MAP_PTR),0,get(o,FRAME)+128+get(o,BASE_N),get(o,MAP_N))
    if phase==1604:
        zero(o,RANK_OUT,65536)
        put(o,RANK_OUT+48,get(w,248))
        put(o,RANK_OUT+56,get(w,256))
        put(o,RANK_OUT+64,get(w,264))
        put(o,RANK_OUT+72,get(w,280))
        put(o,RANK_OUT+80,get(w,288))
        put(o,RANK_OUT+88,get(w,272))
        return system(o,1605,228,12,1,TS,0,0,0,0)
    if phase==1605:
        if get(o,FEEDBACK)==MAX-3:
            return system(o,1605,228,12,1,TS,0,0,0,0)
        if get(o,FEEDBACK)!=0:
            return fail(o,8,get(o,FEEDBACK))
        put(o,RANK_OUT+4096,get(o,TS)*1000000000+get(o,TS+8))
        return invoke(o,1606,get(w,240),48,get(o,FRAME),get(o,FRAME_N),RANK_OUT,65536,0,0)
    if phase==1606:
        put(o,RANK_STATUS,get(o,FEEDBACK))
        put(o,RANK_WORK,get(o,RANK_OUT+40))
        put(o,RANK_WORK_N,get(o,RANK_OUT+16))
        return clock_value(o,100,RANK_END)
    return fail(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1980:
        if valid(o,DECISION_OUT,DECISION_REPLY)==0 or get(o,DECISION_OUT+88)!=0:
            return quarantine(o,w,1980)
        if get(o,DECISION_OUT+24)!=0:
            if get(o,SOURCE_RECORD)!=0:
                return quarantine(o,w,1980)
            within(o,SOURCE_RECORD,DECISION_OUT+24,24)
        if get(o,DECISION_OUT+56)!=0:
            if get(o,DECISION_ERROR)!=0:
                return quarantine(o,w,1980)
            within(o,DECISION_ERROR,DECISION_OUT+56,24)
        put(o,NESTED,0)
        return again(o,2000)
    if phase==1982:
        if valid(o,IO_OUT,IO_REPLY)==0 or get(o,IO_OUT+48)!=0 or get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0:
            return quarantine(o,w,1982)
        return again(o,2000)
    if phase==1999:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,1999)
        put(o,LOCK,0)
        return again(o,2000)
    if phase==2000:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return quarantine(o,w,2000)
        if get(o,NESTED)!=0:
            request(o,DECISION_INPUT,1)
            return invoke(o,1980,get(w,296),51,RQ,128,DECISION_OUT,262144,get(w,304),get(w,312))
        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0:
            request(o,IO_INPUT,1)
            return invoke(o,1982,get(w,216),819,RQ,128,IO_OUT,131072,IO_WORK,256)
        index=get(o,CLEAN)
        if get(o,LOCK)!=0:
            request(o,QUEUE_INPUT,11)
            return queue_owner(o,w,1999)
        if index==60:
            put(o,CLEAN,0)
            return again(o,2100)
        at=G_META+index*24
        if get(o,at)==0 or (at==RESULT or at==ERROR_VALUE) and get(o,OP)==0:
            put(o,CLEAN,index+1)
            return again(o,2000)
        if at==G_JOB:
            put(o,SAVED,at)
            return job_drop(o,w,2002,at)
        put(o,SAVED,at)
        return drop_value(o,w,2001,at)
    if phase==2001:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,2001)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,2000)
    if phase==2002:
        if job_cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,2002)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,2000)
    if phase==2100:
        index=get(o,CLEAN)
        if index==5:
            return again(o,2200)
        at=SOURCE_RECORD+index*24
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,2100)
        put(o,SAVED,at)
        if at==PROVIDER:
            request(o,PROVIDER_INPUT,5)
            within(o,RQ+40,at,24)
            return provider_owner(o,w,2102)
        request(o,PAYLOAD_INPUT,3)
        within(o,RQ+24,at,24)
        return payload_owner(o,w,2101)
    if phase==2101 or phase==2102:
        magic=choose(phase==2101,PAYLOAD_REPLY,PROVIDER_REPLY)
        if valid(o,RP,magic)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,phase)
        zero(o,get(o,SAVED),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,2100)
    if phase==2200:
        if get(o,PUB_FRAME)!=0:
            return deallocate(o,2204,get(o,PUB_FRAME))
        if get(o,DREQ)!=0:
            return deallocate(o,2201,get(o,DREQ))
        return again(o,2202)
    if phase==2204:
        put(o,PUB_FRAME,0)
        return again(o,2200)
    if phase==2201:
        put(o,DREQ,0)
        return again(o,2202)
    if phase==2202:
        if get(o,FRAME)!=0:
            return deallocate(o,2203,get(o,FRAME))
        return again(o,2210)
    if phase==2203:
        put(o,FRAME,0)
        return again(o,2210)
    if phase==2210:
        fd=get(o,FD)
        put(o,FD,MAX)
        if fd!=MAX:
            return system(o,2211,3,0,fd,0,0,0,0,0)
        return again(o,2220)
    if phase==2211:
        if get(o,FEEDBACK)>=NEGATIVE:
            if get(o,ERROR)==0:
                put(o,ERROR,8)
        return again(o,2220)
    if phase==2220:
        if get(o,MAP_PTR)!=0:
            return system(o,2221,11,0,get(o,MAP_PTR),get(o,MAP_N),0,0,0,0)
        return again(o,2230)
    if phase==2221:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,2221)
        put(o,MAP_PTR,0)
        return again(o,2230)
    if phase==2230:
        if get(o,RANK_WORK)!=0:
            return system(o,2231,11,0,get(o,RANK_WORK),get(o,RANK_WORK_N),0,0,0,0)
        return again(o,2240)
    if phase==2231:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,2231)
        put(o,RANK_WORK,0)
        return again(o,2240)
    if phase==2240:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,12)
            return jobs(o,w,2241)
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return values(o,w,2242,128)
        return finish(o,w,get(o,ERROR))
    if phase==2241:
        if release_job_retry(o)==0:
            return quarantine(o,w,2241)
        return again(o,2240)
    if phase==2242:
        if release_value_retry(o)==0:
            return quarantine(o,w,2242)
        return again(o,2240)
    return quarantine(o,w,phase)

def simple_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1700:
        if valid(o,RP,KERNEL_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+32)>2:
            return fail(o,7,1700)
        put(o,INFO,get(o,RP+32))
        return again(o,get(o,TOKEN_NEXT))
    if phase==1800:
        return discard_finished(o,w)
    if phase==1810:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=2 or get(o,RP+64)!=1 or get(o,RP+72)==0:
            return fail(o,value_failure(o),1810)
        put(o,COMPARE_FIRST,byte(o,RP+8192))
        put(o,COMPARE_SIZE,get(o,RP+72))
        return again(o,get(o,COMPARE_NEXT))
    if phase==1820:
        n=get(o,COPY_N)-get(o,COPY_AT)
        if n==0:
            return again(o,get(o,COPY_NEXT))
        if n>8192:
            n=8192
        put(o,COPY_COUNT,n)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,COPY_CAP,24)
        put(o,RQ+104,get(o,COPY_AT))
        put(o,RQ+112,n)
        return values(o,w,1821,128)
    if phase==1821:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+72)!=get(o,COPY_N) or get(o,RP+64)!=get(o,COPY_COUNT):
            return fail(o,value_failure(o),1821)
        return memory(o,1822,3,RP+8192,0,get(o,COPY_PTR)+get(o,COPY_AT),get(o,COPY_COUNT))
    if phase==1822:
        put(o,COPY_AT,get(o,COPY_AT)+get(o,COPY_COUNT))
        return again(o,1820)
    return fail(o,7,phase)

def discard_finished(o:mutbuf,w:mutbuf) -> u32:
    if cleared(o,get(o,DROP_AT))==0:
        return quarantine(o,w,1800)
    return again(o,get(o,DROP_NEXT))
def discard(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    if get(o,at)==0:
        return again(o,next)
    put(o,DROP_NEXT,next)
    put(o,DROP_AT,at)
    return drop_value(o,w,1800,at)
def first_digit(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    request(o,VALUE_INPUT,19)
    within(o,RQ+24,at,24)
    put(o,RQ+112,1)
    put(o,COMPARE_NEXT,next)
    return values(o,w,1810,128)
def scalar_copy(o:mutbuf,next:u64,cap:u64,ptr:u64,n:u64) -> u32:
    within(o,COPY_CAP,cap,24)
    put(o,COPY_PTR,ptr)
    put(o,COPY_N,n)
    put(o,COPY_AT,0)
    put(o,COPY_NEXT,next)
    return again(o,1820)
def literal_value(o:mutbuf,w:mutbuf,next:u64,dest:u64,id:u64) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RQ+104,4)
    n=literal(o,RQ+128,id)
    put(o,RQ+96,n)
    put(o,RESUME,next)
    put(o,DEST,dest)
    return values(o,w,1010,128+n)
def word_value(o:mutbuf,w:mutbuf,next:u64,dest:u64,value:u64) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RQ+104,2)
    n=digits(o,RQ+128,value)
    put(o,RQ+96,n)
    put(o,RESUME,next)
    put(o,DEST,dest)
    return values(o,w,1010,128+n)
def retain_value(o:mutbuf,w:mutbuf,next:u64,dest:u64,source:u64) -> u32:
    request(o,VALUE_INPUT,5)
    within(o,RQ+24,source,24)
    put(o,RESUME,next)
    put(o,DEST,dest)
    return values(o,w,1010,128)
def queue_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,136),51,RQ,128,RP,4096,get(w,144),get(w,152))
def lookup(o:mutbuf,next:u64,container:u64,key:u64,dest:u64,optional:u64) -> u32:
    put(o,RESUME,next)
    put(o,DEST,dest)
    put(o,KEY_ID,key)
    put(o,VOP,9)
    within(o,CONTAINER,container,24)
    put(o,OPTIONAL,optional)
    return again(o,1000)
def assign(o:mutbuf,next:u64,container:u64,key:u64,value:u64) -> u32:
    put(o,RESUME,next)
    put(o,DEST,0)
    put(o,KEY_ID,key)
    put(o,VOP,10)
    within(o,CONTAINER,container,24)
    within(o,OPERAND,value,24)
    put(o,OPTIONAL,0)
    return again(o,1000)
def arithmetic(o:mutbuf,w:mutbuf,next:u64,dest:u64,a:u64,b:u64,operation:u64) -> u32:
    request(o,VALUE_INPUT,24)
    within(o,RQ+24,a,24)
    within(o,RQ+48,b,24)
    put(o,RQ+104,operation)
    put(o,RESUME,next)
    put(o,DEST,dest)
    return values(o,w,1010,128)
def clock_value(o:mutbuf,next:u64,dest:u64) -> u32:
    put(o,CLOCK_NEXT,next)
    put(o,CLOCK_DEST,dest)
    return again(o,1100)
def snapshot(o:mutbuf,next:u64) -> u32:
    put(o,SNAPSHOT_NEXT,next)
    return again(o,1300)
def token(o:mutbuf,w:mutbuf,next:u64) -> u32:
    request(o,KERNEL_INPUT,9)
    put(o,TOKEN_NEXT,next)
    return invoke(o,1700,get(w,160),51,RQ,64,RP,512,get(o,KERNEL),512)
def import_value(o:mutbuf,next:u64,dest:u64,ptr:u64,n:u64) -> u32:
    put(o,IMPORT_NEXT,next)
    put(o,IMPORT_DEST,dest)
    put(o,INPUT_PTR,ptr)
    put(o,INPUT_N,n)
    return again(o,1400)
def export_value(o:mutbuf,next:u64,value:u64) -> u32:
    put(o,RESUME,next)
    return again(o,1500)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,RP_N,get(w,16),get(w,24))
def jobs(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,112),51,RQ,128,RP,2048,get(w,120),get(w,128))
def payload_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,88),51,RQ,128,RP,512,get(w,96),get(w,104))
def provider_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,40),51,RQ,128,RP,512,get(w,48),get(w,56))
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def take_value(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+24)==0 or get(o,at)!=0:
        return 1
    within(o,at,RP+24,24)
    return 0
def value_failure(o:mutbuf) -> u64:
    return choose(valid(o,RP,VALUE_REPLY)!=0 and get(o,RP+8)==5,5,7)
def drop_value(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    put(o,DROP_ACTIVE,1)
    put(o,DROP_KNOWN,0)
    put(o,DROP_TARGET,at)
    request(o,VALUE_DROP_INPUT,29)
    within(o,RQ+24,at,24)
    return values(o,w,next,128)
def cleared(o:mutbuf,at:u64) -> u64:
    return release_value(o,at)

def job_drop(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    put(o,DROP_ACTIVE,1)
    put(o,DROP_KNOWN,0)
    put(o,DROP_TARGET,at)
    request(o,JOB_DROP_INPUT,11)
    within(o,RQ+24,at,24)
    return jobs(o,w,next)
def job_cleared(o:mutbuf,at:u64) -> u64:
    return release_job(o,at)

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
    return again(o,2000)
def done(o:mutbuf) -> u32:
    put(o,CLEAN,0)
    return again(o,2000)
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    if get(o,ERROR)==0:
        put(o,ERROR,7)
    put(o,DETAIL,detail)
    kind=2
    if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)==1:
        kind=1
    if detail==2221 or detail==2231:
        kind=1
    if detail==2101 and valid(o,RP,PAYLOAD_REPLY)!=0:
        status=get(o,RP+8)
        if status==1 or status==5 or status==6:
            kind=1
    put(w,480,kind)
    to_work(o,w,128,512,8064)
    to_work(o,w,IO_WORK,8576,256)
    put(w,464,1)
    return finish(o,w,9)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,INIT_RESULT))
    if get(w,464)==0:
        within(o,24,RESULT,24)
        within(o,48,ERROR_VALUE,24)
        zero(o,RESULT,24)
        zero(o,ERROR_VALUE,24)
    put(o,72,get(w,464))
    put(o,80,get(o,DETAIL))
    put(o,88,get(o,ERROR_FORMAT))
    return 0
def arg_key(index:u64) -> u64:
    if index<2:
        return 4+index
    if index<5:
        return 4+index
    if index==5:
        return 10
    return index+5
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
'''
SOURCE+='\n'+R.selected('release_begin','release_value','release_job','release_job_retry','release_value_retry')
LABELS={1:'costs',2:'enqueued_ns',3:'queue_wait_ns',4:'candidates',5:'observations',6:'function',7:'bridge',8:'objective',9:'epoch',10:'generation',11:'timeout_ms',12:'bridge_timeout_s',13:'rank_call_wall_ns',14:'ranking',15:'reason',16:'status',17:'net_margin_ns',18:'resource_cap_ns',19:'selected_id',20:'prepare_ns',21:'publication',22:'submit_work_ns',23:'coordinator_before_publish_ns',24:'publication_budget_ns',25:'publication_call_wall_ns',26:'publication_prepare_ns',27:'net_margin_before_postcommit_reporting_ns',28:'search_and_preparation_ns',29:'publication_handoff_ns',30:'postcommit_runtime_return_ns',31:'abstained',32:'ranker_abstained',33:'coordinator_work_exhausted_net_or_resource_budget',34:'published',35:'fresh_proof_native_prepare_and_conditional_swap_passed',36:'actual_adapter_ns',37:'total_search_ns'}
def source_program(entry='execute'):
 s=SOURCE
 for name in ('invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'):
  node=next(x for x in ast.parse(BASE).body if isinstance(x,ast.FunctionDef)and x.name==name)
  s+='\n'+ast.get_source_segment(BASE,node)+'\n'
 s+='\ndef literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
 for k in LABELS:s+='    if id=='+str(k)+':\n        return literal_'+str(k)+'(o,at)\n'
 s+='    return 0\n'
 for k,v in LABELS.items():
  raw=v.encode();s+='\ndef literal_'+str(k)+'(o:mutbuf,at:u64) -> u64:\n'
  for at in range(0,len(raw)-len(raw)%8,8):s+='    put(o,at+'+str(at)+','+str(int.from_bytes(raw[at:at+8],'little'))+')\n'
  for at in range(len(raw)-len(raw)%8,len(raw)):s+='    store(o,at+'+str(at)+','+str(raw[at])+')\n'
  s+='    return '+str(len(raw))+'\n'
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 tree=ast.parse(s);functions={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)};chosen=set();todo=[entry]
 while todo:
  name=todo.pop()
  if name in chosen:continue
  chosen.add(name)
  todo.extend(x.func.id for x in ast.walk(functions[name]) if isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id in functions and x.func.id not in chosen)
 order=[entry]+[x.name for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in chosen and x.name!=entry]
 return '\n\n'.join(ast.get_source_segment(s,functions[name])for name in order)+'\n'
def program(entry='execute'):return document(source_program(entry),'background_optimizer_execution')
if __name__=='__main__':
 for entry,suffix in [('execute',''),('publish_continue','_publication')]:
  tree=program(entry);p=ROOT/('examples/hia_bootstrap/background_optimizer_execution'+suffix+'.hepta');p.write_text(render_assembly(tree))
  print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
