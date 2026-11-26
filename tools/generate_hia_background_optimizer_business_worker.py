"""Native fixed business handler for the BackgroundOptimizer pthread.
Development author only. Whole worker qualification remains open.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_execution as E
ROOT=Path(__file__).resolve().parents[1]
C=dict(E.C)
C.update({
'INPUT1':int.from_bytes(b'HIABGWQ1','little'),'INPUT2':int.from_bytes(b'HIABGWQ2','little'),
'CLEAN_INPUT':int.from_bytes(b'HIABGWQ3','little'),'CLEAN_REPLY':int.from_bytes(b'HIABGWR2','little'),
'REPLY':int.from_bytes(b'HIABGWR1','little'),'CONTEXT':int.from_bytes(b'HIABWBC1','little'),
'EXEC_INPUT':int.from_bytes(b'HIABEX01','little'),'EXEC_REPLY':int.from_bytes(b'HIABER01','little'),
'ACCOUNT_INPUT':int.from_bytes(b'HIABACQ1','little'),'ACCOUNT_REPLY':int.from_bytes(b'HIABACR1','little'),
'PUBLIC_INPUT':int.from_bytes(b'HIABFP01','little'),'PUBLIC_REPLY':int.from_bytes(b'HIABFRP1','little'),
'OUT':1048576,'CLOCK_WORD':976,'FUTURE_PENDING':1144,
'POST_EXIT':1152,'DRAIN_READY':1160,'ROW_CLEAN_INDEX':1168,'ROW_CLEAN_SUB':1176,
'WORK_PHASE':704,'OWNED_CURRENT':712,'SLOT':720,'CURRENT_EXISTS':728,'RESULT_PRESENT':736,
'PENDING_FATAL':744,'CATCHING':752,'FAILURE_MODE':760,'DRAIN_COUNT':768,'DRAIN_INDEX':776,'DRAIN_FOUND':784,
'BASE_NEXT':792,'BASE_STATUS':800,'BASE_REASON':808,'PUBLIC_NEXT':816,'PUBLIC_OP':824,'PUBLIC_KIND':832,
'PUBLIC_VALUE':840,'ACCOUNT_NESTED':848,'EXEC_NESTED':856,'WAS_CANCELLED':864,'ERROR_SOURCE':872,
'ERROR_KIND':880,'ERROR_ROUTE':888,'ERROR_TEXT_N':896,'ERROR_TEXT_CP':904,'DROP_NEXT':912,'DROP_AT':920,
'FINALLY_STARTED':928,'ERROR_CAP':936,'COUNTER_NEXT':944,'COUNTER_KEY':952,'REPORT_NEXT':960,'TO_CLEAR':968,
'FALLBACK_NEXT':984,'FAIL_COPY_INDEX':992,'SCALAR_NEXT':1000,'SHARED_INITIALIZED':1008,
'G_META':4096,'G_JOB':4120,'RESULT':4144,'G_FUTURE':4168,'ERROR_VALUE':4192,'COSTS':4216,
'TEMP':4240,'TEMP2':4264,'TEMP3':4288,'KEY':4312,'CMP_VALUE':4336,'TIME_VALUE':4360,
'REASON':4384,'DETAIL_VALUE':4408,'CLASS_VALUE':4432,'MESSAGE_VALUE':4456,'FAILURE_VALUE':4480,
'FAIL_COPY':4504,'WORK_STARTED':4528,'NATIVE_ERROR':4552,'NUMBER':4576,'ZERO_VALUE':4600,
'COUNT_VALUE':4624,'COUNTER_VALUE':4648,'OLD_META':4672,'OLD_FUTURE':4696,'OLD_JOB':4720,
'STATUS_VALUE':4744,'PHASE_VALUE':4768,'FLAG_VALUE':4792,'FIELD_VALUE':4816,'PROVIDER':4840,
'CAP_END':4864,'ROW':6144,'ROWS':8192,'RQ':16384,'RP':32768,'RP_N':16384,
'REPORT_OUT':65536,'REPORT_WORK':73728,'REPORT_SOURCE':114688,'PUBLIC_OUT':131072,
'CHILD_OUT':524288,'ERR':196608,
})
LABELS=dict(E.LABELS)
LABELS.update({
100:'work_started_ns',101:'rejected',102:'stale',103:'cancelled',104:'cancelled',105:'detail',
106:'class',107:'type',108:'message',109:'worker_unavailable',110:'interrupted',
111:'worker_interrupted_after_publication',112:'publication_committed',113:'worker_failure',
114:'phase',115:'job',116:'completion_callback_failures',117:'cancellation_failures',
118:'dequeue',119:'execute',120:'cancel',121:'complete',122:'exception text unavailable',
123:'MemoryError',124:'',125:'RuntimeError',126:'native background dependency failed',
127:'source-stage failure',128:'HIAProgramRejected',129:'code',130:'CancelledError',
131:'TimeoutError',132:'InvalidStateError',133:'TypeError',134:'ValueError',
135:'OverflowError',136:'OSError'})
SOURCE=r'''
def business(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return main_step(s,o,w,phase)
    if phase<200:
        return final_step(s,o,w,phase)
    if phase<300:
        return complete_step(s,o,w,phase)
    if phase>=300 and phase<700:
        put(o,MODULE,1)
        return again(o,phase)
    return shared_step(s,o,w,phase)
def business_failure(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384 or get(o,MODULE)!=1:
        return 4294967293
    phase=get(o,PHASE)
    if phase>=300 and phase<700:
        return failure_step(s,o,w,phase)
    return shared_step(s,o,w,phase)
def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128:
        return 4294967293
    magic=word_load(s,0)
    if magic!=INPUT2 and magic!=CLEAN_INPUT:
        return 4294967293
    op=word_load(s,8)
    if op<1 or op>3 or word_load(s,112)!=0 or word_load(s,120)!=0:
        return 4294967293
    if magic==CLEAN_INPUT and op!=3:
        return 4294967293
    if op==3:
        at=16
        while at<128:
            if word_load(s,at)!=0:
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
    if get(w,168)==0 or get(w,176)==0 or get(w,184)<256 or get(w,192)==0:
        return 4294967293
    if get(w,216)==0 or get(w,224)==0 or get(w,232)<16384 or get(w,240)==0 or get(w,248)==0 or get(w,256)<4096:
        return 4294967293
    if get(w,384)==0 or get(w,392)==0 or get(w,400)<256:
        return 4294967293
    if get(w,288)==0 or get(w,320)==0 or get(w,328)<8192:
        return 4294967293
    if op==3:
        if magic==CLEAN_INPUT:
            return post_exit_begin(o,w)
        return 4294967293
    if get(w,376)!=0 or get(w,464)!=0:
        return 4294967293
    zero(o,128,8064)
    zero(o,ROWS,1152)
    put(o,OP,op)
    put(o,SLOT,MAX)
    if word_load(s,16)!=0:
        if word_load(s,40)==0 or word_load(s,48)!=512 or word_load(s,56)>=8:
            return 4294967293
        copy_source(s,o,16,G_JOB,24)
        put(o,KERNEL,word_load(s,40))
        put(o,SLOT,word_load(s,56))
        put(o,CURRENT_EXISTS,1)
    elif op==1:
        return 4294967293
    if op==1 and (word_load(s,96)!=0 or word_load(s,104)!=1 or word_load(s,88)>=1000000000):
        return 4294967293
    put(o,WORK_PHASE,118)
    return system(o,1,39,0,0,0,0,0,0,0)
def post_exit_begin(o:mutbuf,w:mutbuf) -> u32:
    if get(w,488)!=1 or get(w,496)!=1 or get(w,376)!=1 or get(w,464)!=1 or get(w,480)!=1:
        return 4294967293
    if get(o,LOCK)!=0 or get(o,EXEC_NESTED)!=0 or get(o,ACCOUNT_NESTED)!=0:
        return 4294967293
    if get(o,DROP_ACTIVE)!=1 or get(o,DROP_KNOWN)!=1 or get(o,DRAIN_COUNT)>9 or get(o,OWNED_CURRENT)>1:
        return 4294967293
    if get(o,DRAIN_COUNT)!=0 and get(o,DRAIN_READY)!=1:
        return 4294967293
    put(o,OP,3)
    put(o,POST_EXIT,1)
    put(o,MODULE,0)
    put(o,CLEAN,0)
    put(o,ROW_CLEAN_INDEX,0)
    put(o,ROW_CLEAN_SUB,0)
    put(o,DROP_ACTIVE,0)
    put(o,DROP_KNOWN,0)
    if get(o,OWNED_CURRENT)==0:
        zero(o,G_JOB,24)
        zero(o,G_META,24)
        zero(o,G_FUTURE,24)
    return again(o,4000)
def main_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,456)!=0 and get(w,456)!=pid):
            return terminal(o,w,6)
        put(w,456,pid)
        put(w,376,1)
        put(o,PID,pid)
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,2)
    if phase==2:
        if queue_valid(o)==0:
            return quarantine(o,w,2)
        put(o,LOCK,1)
        if get(o,CURRENT_EXISTS)==0:
            return again(o,5)
        return memory(o,3,0,get(w,320)+1024+get(o,SLOT)*128,3,ROW,72)
    if phase==3:
        if same_cap(o,G_JOB,ROW)==0 or get(o,ROW+24)==0 or get(o,ROW+48)==0:
            return quarantine(o,w,3)
        within(o,G_META,ROW+24,24)
        within(o,G_FUTURE,ROW+48,24)
        if get(o,OP)==2:
            return again(o,5)
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,2)
        n=clock_decimal(o,RQ+128,word_load(s,80),word_load(s,88))
        put(o,RQ+96,n)
        put(o,RESUME,4)
        put(o,DEST,WORK_STARTED)
        return values(o,w,1010,128+n)
    if phase==4:
        return assign(o,5,G_META,100,WORK_STARTED)
    if phase==5:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,6)
    if phase==6:
        if queue_valid(o)==0:
            return quarantine(o,w,6)
        put(o,LOCK,0)
        if get(o,OP)==2:
            put(o,ERROR_KIND,107)
            put(o,ERROR_ROUTE,300)
            return again(o,3100)
        put(o,WORK_PHASE,119)
        return token(o,w,10)
    if phase==10:
        if get(o,INFO)==1:
            return again(o,20)
        request(o,EXEC_INPUT,0)
        within(o,RQ+16,G_JOB,24)
        within(o,RQ+40,G_META,24)
        within(o,RQ+64,G_FUTURE,24)
        put(o,RQ+88,get(o,SLOT))
        put(o,EXEC_NESTED,1)
        return invoke(o,11,get(w,216),51,RQ,128,CHILD_OUT,524288,get(w,224),get(w,232))
    if phase==11:
        if valid(o,CHILD_OUT,EXEC_REPLY)==0 or get(o,CHILD_OUT+72)!=0:
            return quarantine(o,w,11)
        put(o,EXEC_NESTED,0)
        status=get(o,CHILD_OUT+8)
        if get(o,CHILD_OUT+24)!=0:
            within(o,RESULT,CHILD_OUT+24,24)
        if get(o,CHILD_OUT+48)!=0:
            within(o,ERROR_VALUE,CHILD_OUT+48,24)
        if status==0:
            put(o,RESULT_PRESENT,get(o,CHILD_OUT+16))
            return token(o,w,20)
        if status==1 or status==2:
            if get(o,ERROR_VALUE)==0:
                return quarantine(o,w,11)
            put(o,ERROR_FORMAT,get(o,CHILD_OUT+88))
            if status==2:
                put(o,PENDING_FATAL,1)
                return again(o,100)
            return token(o,w,30)
        if status==5:
            put(o,ERROR_KIND,103)
            put(o,ERROR_ROUTE,30)
            return again(o,3100)
        return quarantine(o,w,11)
    if phase==20:
        if get(o,INFO)!=1:
            return again(o,100)
        put(o,WORK_PHASE,120)
        return public_call(o,w,21,8,0,0)
    if phase==21:
        if public_valid(o)==0:
            return quarantine(o,w,21)
        if get(o,PUBLIC_OUT+8)!=0:
            return public_error(o,w,22)
        put(o,RESULT_PRESENT,0)
        return again(o,100)
    if phase==22:
        if get(o,ERROR)==2:
            put(o,PENDING_FATAL,1)
            return again(o,100)
        return token(o,w,30)
    if phase==30:
        if get(o,INFO)==2:
            put(o,PENDING_FATAL,1)
            return again(o,100)
        put(o,CATCHING,1)
        return snapshot(o,31)
    if phase==31:
        put(o,BASE_STATUS,choose(get(o,CMP_RESULT)!=0,101,102))
        return error_fields(o,w,32)
    if phase==32:
        if get(o,RESULT)!=0:
            return again(o,33)
        return base_report(o,w,33,get(o,BASE_STATUS),0)
    if phase==33:
        return literal_value(o,w,34,STATUS_VALUE,get(o,BASE_STATUS))
    if phase==34:
        return assign(o,35,RESULT,16,STATUS_VALUE)
    if phase==35:
        return assign(o,36,RESULT,15,CLASS_VALUE)
    if phase==36:
        return assign(o,37,RESULT,105,DETAIL_VALUE)
    if phase==37:
        put(o,RESULT_PRESENT,1)
        put(o,CATCHING,0)
        return again(o,100)
    return quarantine(o,w,phase)
def final_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        put(o,FINALLY_STARTED,1)
        if get(o,LOCK)!=0:
            return token(o,w,102)
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,101)
    if phase==101:
        if queue_valid(o)==0:
            return quarantine(o,w,101)
        put(o,LOCK,1)
        return token(o,w,102)
    if phase==102:
        if get(o,RESULT_PRESENT)==0 and get(o,INFO)!=1:
            return again(o,110)
        if get(o,RESULT)==0:
            return base_report(o,w,103,103,104)
        return again(o,103)
    if phase==103:
        return account(o,w,104)
    if phase==104:
        if account_valid(o)==0:
            return quarantine(o,w,104)
        put(o,ACCOUNT_NESTED,0)
        if get(o,CHILD_OUT+8)==5:
            put(o,ERROR_KIND,103)
            put(o,ERROR_ROUTE,300)
            request(o,QUEUE_INPUT,11)
            return queue_owner(o,w,108)
        if get(o,CHILD_OUT+8)!=0:
            return quarantine(o,w,104)
        return again(o,110)
    if phase==108:
        if queue_valid(o)==0:
            return quarantine(o,w,108)
        put(o,LOCK,0)
        return again(o,3100)
    if phase==110:
        request(o,QUEUE_INPUT,3)
        put(o,RQ+16,get(o,SLOT))
        within(o,RQ+24,G_JOB,24)
        return queue_owner(o,w,111)
    if phase==111:
        if queue_valid(o)==0 or get(o,RP+56)!=1 or get(o,RP+64)!=1 or same_cap(o,G_JOB,RP+512)==0:
            return quarantine(o,w,111)
        put(o,OWNED_CURRENT,1)
        zero(o,ROW,72)
        return memory(o,112,3,ROW,0,get(w,320)+1024+get(o,SLOT)*128,72)
    if phase==112:
        return notify_condition(o,w,113)
    if phase==113:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,114)
    if phase==114:
        if queue_valid(o)==0:
            return quarantine(o,w,114)
        put(o,LOCK,0)
        put(o,FINALLY_STARTED,0)
        if get(o,PENDING_FATAL)!=0:
            return again(o,300)
        if get(o,RESULT_PRESENT)!=0:
            put(o,WORK_PHASE,121)
            return public_call(o,w,201,12,1,RESULT)
        return done(o)
    return quarantine(o,w,phase)
def complete_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==201:
        if public_valid(o)==0:
            return quarantine(o,w,201)
        if get(o,PUBLIC_OUT+8)!=0:
            return public_error(o,w,202)
        return done(o)
    if phase==202:
        return again(o,300)
    return quarantine(o,w,phase)
def shared_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
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
    if phase>=1600 and phase<1700:
        return public_step(o,w,phase)
    if phase>=1700 and phase<1900:
        return simple_task(o,w,phase)
    if phase>=3000 and phase<3100:
        return error_text_step(o,w,phase)
    if phase>=3100 and phase<3200:
        return builtin_step(o,w,phase)
    if phase>=3200 and phase<3300:
        return base_step(o,w,phase)
    if phase>=3300 and phase<3400:
        return counter_step(o,w,phase)
    if phase>=3400 and phase<3500:
        return failure_copy_step(o,w,phase)
    if phase>=3500 and phase<3600:
        return new_error_step(o,w,phase)
    return cleanup(o,w,phase)
'''

SOURCE+=r'''
def queue_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,136),51,RQ,128,RP,4096,get(w,144),get(w,152))
def queue_valid(o:mutbuf) -> u64:
    return choose(valid(o,RP,QUEUE_REPLY)!=0 and get(o,RP+8)==0,1,0)
def public_valid(o:mutbuf) -> u64:
    return choose(valid(o,PUBLIC_OUT,PUBLIC_REPLY)!=0,1,0)
def public_call(o:mutbuf,w:mutbuf,next:u64,op:u64,kind:u64,value:u64) -> u32:
    if op==26:
        return public_drop_at(o,w,next,G_FUTURE)
    request(o,choose(op==26,PUBLIC_DROP_INPUT,PUBLIC_INPUT),op)
    if op==26:
        release_begin(o)
    from_work(w,o,192,RQ+16,24)
    within(o,RQ+40,G_FUTURE,24)
    if value!=0:
        within(o,RQ+64,value,24)
    put(o,RQ+96,kind)
    return invoke(o,next,get(w,168),51,RQ,192,PUBLIC_OUT,65536,get(w,176),get(w,184))
def public_drop_at(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    request(o,PUBLIC_DROP_INPUT,26)
    release_begin(o)
    from_work(w,o,192,RQ+16,24)
    within(o,RQ+40,at,24)
    return invoke(o,next,get(w,168),51,RQ,192,PUBLIC_OUT,65536,get(w,176),get(w,184))
def public_error(o:mutbuf,w:mutbuf,next:u64) -> u32:
    status=get(o,PUBLIC_OUT+8)
    kind=get(o,PUBLIC_OUT+16)
    if status!=1 and status!=2:
        return quarantine(o,w,1600)
    put(o,ERROR,status)
    put(o,ERROR_ROUTE,next)
    if kind==200:
        if get(o,PUBLIC_OUT+72)==0 or get(o,NATIVE_ERROR)!=0:
            return quarantine(o,w,1600)
        within(o,NATIVE_ERROR,PUBLIC_OUT+72,24)
        put(o,ERROR_FORMAT,2)
        return again(o,3500)
    if status!=1 or kind<100 or kind>107 or get(o,PUBLIC_OUT+72)!=0:
        return quarantine(o,w,1601)
    put(o,ERROR_KIND,kind)
    return again(o,3100)
def public_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    return quarantine(o,w,phase)
def account(o:mutbuf,w:mutbuf,next:u64) -> u32:
    request(o,ACCOUNT_INPUT,0)
    within(o,RQ+24,G_JOB,24)
    within(o,RQ+48,G_META,24)
    within(o,RQ+72,RESULT,24)
    within(o,RQ+96,G_FUTURE,24)
    put(o,ACCOUNT_NESTED,1)
    return invoke(o,next,get(w,240),51,RQ,128,CHILD_OUT,524288,get(w,248),get(w,256))
def account_valid(o:mutbuf) -> u64:
    return choose(valid(o,CHILD_OUT,ACCOUNT_REPLY)!=0 and get(o,CHILD_OUT+56)==0,1,0)
def notify_condition(o:mutbuf,w:mutbuf,next:u64) -> u32:
    store(o,INFO,1)
    store(o,INFO+1,0)
    store(o,INFO+2,0)
    store(o,INFO+3,0)
    put(o,CONTROLLER_NEXT,next)
    return memory(o,1890,3,INFO,0,get(w,144)+132,4)
def same_cap(o:mutbuf,a:u64,b:u64) -> u64:
    return choose(get(o,a)==get(o,b) and get(o,a+8)==get(o,b+8) and get(o,a+16)==get(o,b+16),1,0)
def error_fields(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,FALLBACK_NEXT,next)
    return lookup(o,3000,ERROR_VALUE,106,CLASS_VALUE,1)
def error_text_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3000:
        if get(o,FOUND)==0:
            return lookup(o,3001,ERROR_VALUE,107,CLASS_VALUE,0)
        return again(o,3001)
    if phase==3001:
        request(o,VALUE_INPUT,7)
        within(o,RQ+24,CLASS_VALUE,24)
        return values(o,w,3002,128)
    if phase==3002:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=4:
            return quarantine(o,w,3002)
        return lookup(o,3003,ERROR_VALUE,108,MESSAGE_VALUE,0)
    if phase==3003:
        request(o,VALUE_INPUT,7)
        within(o,RQ+24,MESSAGE_VALUE,24)
        return values(o,w,3004,128)
    if phase==3004:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=4:
            return quarantine(o,w,3004)
        n=get(o,RP+72)
        if n>8192:
            n=8192
        put(o,ERROR_TEXT_N,n)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,MESSAGE_VALUE,24)
        put(o,RQ+112,n)
        return values(o,w,3005,128)
    if phase==3005:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)!=get(o,ERROR_TEXT_N):
            return fail(o,value_failure(o),3005)
        n=get(o,ERROR_TEXT_N)
        at=0
        count=0
        while at<n and count<2048:
            b=byte(o,RP+8192+at)
            size=1
            if b>=240:
                size=4
            elif b>=224:
                size=3
            elif b>=192:
                size=2
            if size>n-at:
                return quarantine(o,w,3005)
            at=at+size
            count=count+1
        within(o,ERR,RP+8192,at)
        put(o,ERROR_TEXT_N,at)
        return discard(o,w,3006,DETAIL_VALUE)
    if phase==3006:
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        n=get(o,ERROR_TEXT_N)
        put(o,RQ+96,n)
        within(o,RQ+128,ERR,n)
        put(o,DEST,DETAIL_VALUE)
        put(o,RESUME,get(o,FALLBACK_NEXT))
        return values(o,w,1010,128+n)
    return quarantine(o,w,phase)
def builtin_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3100:
        if get(o,NATIVE_ERROR)!=0:
            return quarantine(o,w,3100)
        request(o,VALUE_INPUT,4)
        return values(o,w,3101,128)
    if phase==3101:
        if take_value(o,NATIVE_ERROR)!=0:
            return quarantine(o,w,3101)
        kind=get(o,ERROR_KIND)
        id=125
        if kind==100:
            id=130
        elif kind==101:
            id=131
        elif kind==102:
            id=132
        elif kind==103:
            id=123
        elif kind==104:
            id=133
        elif kind==105:
            id=134
        elif kind==106:
            id=135
        return literal_value(o,w,3102,TEMP,id)
    if phase==3102:
        return assign(o,3103,NATIVE_ERROR,106,TEMP)
    if phase==3103:
        return discard(o,w,3104,TEMP)
    if phase==3104:
        return literal_value(o,w,3105,TEMP,choose(get(o,ERROR_KIND)==107,126,124))
    if phase==3105:
        return assign(o,3106,NATIVE_ERROR,108,TEMP)
    if phase==3106:
        return discard(o,w,3107,TEMP)
    if phase==3107:
        put(o,ERROR_FORMAT,2)
        return again(o,3500)
    return quarantine(o,w,phase)
def new_error_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3500:
        return discard(o,w,3501,ERROR_VALUE)
    if phase==3501:
        within(o,ERROR_VALUE,NATIVE_ERROR,24)
        zero(o,NATIVE_ERROR,24)
        if get(o,ERROR_ROUTE)==30:
            return token(o,w,30)
        return again(o,get(o,ERROR_ROUTE))
    return quarantine(o,w,phase)
def base_report(o:mutbuf,w:mutbuf,next:u64,status:u64,reason:u64) -> u32:
    if get(o,RESULT)!=0:
        return again(o,next)
    put(o,REPORT_NEXT,next)
    put(o,BASE_STATUS,status)
    put(o,BASE_REASON,reason)
    return again(o,3200)
def base_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3200:
        return literal_value(o,w,3201,STATUS_VALUE,get(o,BASE_STATUS))
    if phase==3201:
        return assign(o,3202,G_META,16,STATUS_VALUE)
    if phase==3202:
        if get(o,BASE_REASON)==0:
            return assign(o,3204,G_META,15,CLASS_VALUE)
        return literal_value(o,w,3203,REASON,get(o,BASE_REASON))
    if phase==3203:
        return assign(o,3204,G_META,15,REASON)
    if phase==3204:
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
    return quarantine(o,w,phase)
def counter(o:mutbuf,w:mutbuf,next:u64,key:u64) -> u32:
    put(o,COUNTER_NEXT,next)
    put(o,COUNTER_KEY,key)
    return again(o,3300)
def counter_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3300:
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,3301)
    if phase==3301:
        if queue_valid(o)==0:
            return quarantine(o,w,3301)
        put(o,LOCK,1)
        return lookup(o,3302,FAILURE_VALUE,get(o,COUNTER_KEY),COUNT_VALUE,0)
    if phase==3302:
        request(o,VALUE_INPUT,24)
        within(o,RQ+24,COUNT_VALUE,24)
        from_work(w,o,288,RQ+48,24)
        put(o,RESUME,3303)
        put(o,DEST,COUNTER_VALUE)
        return values(o,w,1010,128)
    if phase==3303:
        return assign(o,3304,FAILURE_VALUE,get(o,COUNTER_KEY),COUNTER_VALUE)
    if phase==3304:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,3305)
    if phase==3305:
        if queue_valid(o)==0:
            return quarantine(o,w,3305)
        put(o,LOCK,0)
        return discard(o,w,3306,COUNTER_VALUE)
    if phase==3306:
        return discard(o,w,get(o,COUNTER_NEXT),COUNT_VALUE)
    return quarantine(o,w,phase)
def failure_copy(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,BASE_NEXT,next)
    put(o,FAIL_COPY_INDEX,0)
    return discard(o,w,3400,FAIL_COPY)
def failure_copy_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3400:
        request(o,VALUE_INPUT,4)
        return values(o,w,3401,128)
    if phase==3401:
        if take_value(o,FAIL_COPY)!=0:
            return fail(o,value_failure(o),3401)
        return again(o,3402)
    if phase==3402:
        i=get(o,FAIL_COPY_INDEX)
        if i==5:
            return again(o,get(o,BASE_NEXT))
        key=failure_key(i)
        return lookup(o,3403,FAILURE_VALUE,key,FIELD_VALUE,0)
    if phase==3403:
        return assign(o,3404,FAIL_COPY,failure_key(get(o,FAIL_COPY_INDEX)),FIELD_VALUE)
    if phase==3404:
        put(o,FAIL_COPY_INDEX,get(o,FAIL_COPY_INDEX)+1)
        return discard(o,w,3402,FIELD_VALUE)
    return quarantine(o,w,phase)
def failure_key(i:u64) -> u64:
    if i==0:
        return 107
    if i==1:
        return 105
    if i==2:
        return 114
    if i==3:
        return 115
    return 117
def literal_value(o:mutbuf,w:mutbuf,next:u64,dest:u64,id:u64) -> u32:
    put(o,RESUME,next)
    put(o,DEST,dest)
    put(o,LITERAL,id)
    if get(o,dest)!=0:
        return drop_value(o,w,1850,dest)
    return literal_create(o,w)
def literal_create(o:mutbuf,w:mutbuf) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RQ+104,4)
    n=literal(o,RQ+128,get(o,LITERAL))
    put(o,RQ+96,n)
    return values(o,w,1010,128+n)
def flag_value(o:mutbuf,w:mutbuf,next:u64,dest:u64,value:u64) -> u32:
    put(o,RESUME,next)
    put(o,DEST,dest)
    put(o,LITERAL,value)
    if get(o,dest)!=0:
        return drop_value(o,w,1860,dest)
    return flag_create(o,w)
def flag_create(o:mutbuf,w:mutbuf) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RQ+104,1)
    put(o,RQ+112,get(o,LITERAL))
    return values(o,w,1010,128)
def null_value(o:mutbuf,w:mutbuf,next:u64,dest:u64) -> u32:
    request(o,VALUE_INPUT,2)
    put(o,RESUME,next)
    put(o,DEST,dest)
    return values(o,w,1010,128)
def simple_task(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1700:
        if valid(o,RP,KERNEL_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+32)>2:
            return fail(o,7,1700)
        put(o,INFO,get(o,RP+32))
        return again(o,get(o,TOKEN_NEXT))
    if phase==1800:
        if cleared(o,get(o,DROP_AT))==0:
            return quarantine(o,w,1800)
        return again(o,get(o,DROP_NEXT))
    if phase==1850:
        if cleared(o,get(o,DEST))==0:
            return quarantine(o,w,1850)
        return literal_create(o,w)
    if phase==1860:
        if cleared(o,get(o,DEST))==0:
            return quarantine(o,w,1860)
        return flag_create(o,w)
    if phase==1890:
        return system(o,1891,202,0,get(w,144)+132,129,2147483647,0,0,0)
    if phase==1891:
        if get(o,FEEDBACK)>=NEGATIVE:
            return quarantine(o,w,1891)
        return again(o,get(o,CONTROLLER_NEXT))
    return quarantine(o,w,phase)
'''

C['COMMITTED']=1024
SOURCE+=r'''
def failure_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase<350:
        return failure_header(o,w,phase)
    if phase<400:
        return failure_drain(o,w,phase)
    if phase<500:
        return failure_jobs(o,w,phase)
    return failure_release(o,w,phase)
def failure_header(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        put(o,FAILURE_MODE,1)
        if get(o,LOCK)!=0:
            request(o,QUEUE_INPUT,11)
            return queue_owner(o,w,301)
        return again(o,302)
    if phase==301:
        if queue_valid(o)==0:
            return quarantine(o,w,301)
        put(o,LOCK,0)
        return again(o,302)
    if phase==302:
        if get(o,ERROR_VALUE)==0:
            put(o,ERROR_KIND,107)
            put(o,ERROR_ROUTE,303)
            return again(o,3100)
        return again(o,303)
    if phase==303:
        return error_fields(o,w,304)
    if phase==304:
        request(o,VALUE_INPUT,4)
        return values(o,w,305,128)
    if phase==305:
        if take_value(o,FAILURE_VALUE)!=0:
            return quarantine(o,w,305)
        return assign(o,306,FAILURE_VALUE,107,CLASS_VALUE)
    if phase==306:
        return assign(o,307,FAILURE_VALUE,105,DETAIL_VALUE)
    if phase==307:
        return literal_value(o,w,308,PHASE_VALUE,get(o,WORK_PHASE))
    if phase==308:
        return assign(o,309,FAILURE_VALUE,114,PHASE_VALUE)
    if phase==309:
        if get(o,G_META)!=0:
            return lookup(o,310,G_META,115,NUMBER,0)
        return null_value(o,w,310,NUMBER)
    if phase==310:
        return assign(o,311,FAILURE_VALUE,115,NUMBER)
    if phase==311:
        return word_value(o,w,312,ZERO_VALUE,0)
    if phase==312:
        return assign(o,313,FAILURE_VALUE,116,ZERO_VALUE)
    if phase==313:
        return assign(o,314,FAILURE_VALUE,117,ZERO_VALUE)
    if phase==314:
        return retain_value(o,w,315,FAIL_COPY,FAILURE_VALUE)
    if phase==315:
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,316)
    if phase==316:
        if queue_valid(o)==0 or get(w,512)!=0:
            return quarantine(o,w,316)
        put(o,LOCK,1)
        request(o,QUEUE_INPUT,6)
        return queue_owner(o,w,350)
    return quarantine(o,w,phase)
def failure_drain(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==350:
        if queue_valid(o)==0 or get(o,RP+56)>8 or get(o,RP+64)!=1:
            return quarantine(o,w,350)
        put(o,DRAIN_COUNT,get(o,RP+56))
        put(o,DRAIN_INDEX,0)
        return again(o,351)
    if phase==351:
        i=get(o,DRAIN_INDEX)
        if i==get(o,DRAIN_COUNT):
            return again(o,357)
        dest=ROWS+i*128
        within(o,dest,RP+512+i*64,24)
        put(o,dest+96,get(o,RP+512+i*64+24))
        put(o,dest+104,get(o,RP+512+i*64+40))
        if get(o,dest+104)>=8:
            return quarantine(o,w,351)
        return memory(o,352,0,get(w,320)+1024+get(o,dest+104)*128,3,ROW,72)
    if phase==352:
        dest=ROWS+get(o,DRAIN_INDEX)*128
        if same_cap(o,dest,ROW)==0 or get(o,ROW+24)==0 or get(o,ROW+48)==0:
            return quarantine(o,w,352)
        within(o,dest+24,ROW+24,48)
        if get(o,OWNED_CURRENT)==0 and get(o,G_JOB)!=0 and same_cap(o,G_JOB,ROW)!=0:
            within(o,dest+72,RESULT,24)
            zero(o,RESULT,24)
            zero(o,G_JOB,24)
            zero(o,G_META,24)
            zero(o,G_FUTURE,24)
            put(o,DRAIN_FOUND,1)
        zero(o,ROW,72)
        return memory(o,353,3,ROW,0,get(w,320)+1024+get(o,dest+104)*128,72)
    if phase==353:
        put(o,DRAIN_INDEX,get(o,DRAIN_INDEX)+1)
        return again(o,351)
    if phase==357:
        if get(o,OWNED_CURRENT)!=0:
            n=get(o,DRAIN_COUNT)
            if n>=9:
                return quarantine(o,w,357)
            dest=ROWS+n*128
            within(o,dest,G_JOB,24)
            within(o,dest+24,G_META,24)
            within(o,dest+48,G_FUTURE,24)
            within(o,dest+72,RESULT,24)
            put(o,dest+96,get(o,KERNEL))
            put(o,dest+104,get(o,SLOT))
            zero(o,G_JOB,24)
            zero(o,G_META,24)
            zero(o,G_FUTURE,24)
            zero(o,RESULT,24)
            put(o,DRAIN_COUNT,n+1)
            put(o,OWNED_CURRENT,0)
        elif get(o,G_JOB)!=0:
            return quarantine(o,w,357)
        return memory(o,358,3,FAIL_COPY,1,512,24)
    if phase==358:
        zero(o,FAIL_COPY,24)
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,359)
    if phase==359:
        if queue_valid(o)==0:
            return quarantine(o,w,359)
        put(o,LOCK,0)
        put(o,DRAIN_READY,1)
        put(o,DRAIN_INDEX,0)
        put(o,CURRENT_EXISTS,0)
        return again(o,400)
    return quarantine(o,w,phase)
def failure_jobs(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if get(o,DRAIN_INDEX)==get(o,DRAIN_COUNT):
            return done(o)
        src=ROWS+get(o,DRAIN_INDEX)*128
        within(o,G_JOB,src,24)
        within(o,G_META,src+24,24)
        within(o,G_FUTURE,src+48,24)
        within(o,RESULT,src+72,24)
        put(o,KERNEL,get(o,src+96))
        put(o,SLOT,get(o,src+104))
        zero(o,src,96)
        put(o,CURRENT_EXISTS,1)
        put(o,OWNED_CURRENT,1)
        request(o,JOB_INPUT,6)
        within(o,RQ+24,G_JOB,24)
        return jobs(o,w,401)
    if phase==401:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+72)==0:
            return quarantine(o,w,401)
        return memory(o,402,0,get(o,RP+72)+32,3,INFO,8)
    if phase==402:
        if get(o,INFO)!=0:
            return public_call(o,w,403,14,0,0)
        return again(o,404)
    if phase==403:
        if public_valid(o)==0 or get(o,PUBLIC_OUT+8)!=0:
            return quarantine(o,w,403)
        if get(o,PUBLIC_OUT+96)!=0:
            return row_cleanup(o)
        return again(o,404)
    if phase==404:
        request(o,KERNEL_INPUT,8)
        return invoke(o,405,get(w,160),51,RQ,64,RP,512,get(o,KERNEL),512)
    if phase==405:
        if valid(o,RP,KERNEL_REPLY)==0 or get(o,RP+8)!=0:
            return counter(o,w,406,117)
        return again(o,406)
    if phase==406:
        return token(o,w,407)
    if phase==407:
        put(o,COMMITTED,choose(get(o,INFO)==2,1,0))
        if get(o,RESULT)==0:
            return base_report(o,w,408,101,109)
        return again(o,408)
    if phase==408:
        return literal_value(o,w,409,STATUS_VALUE,choose(get(o,COMMITTED)!=0,110,101))
    if phase==409:
        return assign(o,410,RESULT,16,STATUS_VALUE)
    if phase==410:
        return literal_value(o,w,411,REASON,choose(get(o,COMMITTED)!=0,111,109))
    if phase==411:
        return assign(o,412,RESULT,15,REASON)
    if phase==412:
        return flag_value(o,w,413,FLAG_VALUE,get(o,COMMITTED))
    if phase==413:
        return assign(o,414,RESULT,112,FLAG_VALUE)
    if phase==414:
        if get(o,COMMITTED)!=0:
            return null_value(o,w,415,TEMP)
        return again(o,417)
    if phase==415:
        return assign(o,416,RESULT,19,TEMP)
    if phase==416:
        return discard(o,w,417,TEMP)
    if phase==417:
        return failure_copy(o,w,418)
    if phase==418:
        return assign(o,419,RESULT,113,FAIL_COPY)
    if phase==419:
        return discard(o,w,420,FAIL_COPY)
    if phase==420:
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,421)
    if phase==421:
        if queue_valid(o)==0:
            return quarantine(o,w,421)
        put(o,LOCK,1)
        return account(o,w,422)
    if phase==422:
        if account_valid(o)==0 or get(o,CHILD_OUT+8)!=0:
            return quarantine(o,w,422)
        put(o,ACCOUNT_NESTED,0)
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,423)
    if phase==423:
        if queue_valid(o)==0:
            return quarantine(o,w,423)
        put(o,LOCK,0)
        return public_call(o,w,424,12,1,RESULT)
    if phase==424:
        if public_valid(o)==0:
            return quarantine(o,w,424)
        status=get(o,PUBLIC_OUT+8)
        if status==0:
            return row_cleanup(o)
        if status!=1 and status!=2:
            return quarantine(o,w,424)
        if get(o,PUBLIC_OUT+16)==200 and get(o,PUBLIC_OUT+72)!=0:
            within(o,NATIVE_ERROR,PUBLIC_OUT+72,24)
        return discard(o,w,425,NATIVE_ERROR)
    if phase==425:
        return counter(o,w,426,116)
    if phase==426:
        return row_cleanup(o)
    return quarantine(o,w,phase)
def row_cleanup(o:mutbuf) -> u32:
    put(o,CLEAN,0)
    return again(o,600)
def failure_release(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        at=G_META+get(o,CLEAN)*24
        if at>=CAP_END:
            put(o,CURRENT_EXISTS,0)
            put(o,OWNED_CURRENT,0)
            put(o,DRAIN_INDEX,get(o,DRAIN_INDEX)+1)
            return again(o,400)
        if at==ERROR_VALUE or at==FAILURE_VALUE or get(o,at)==0:
            put(o,CLEAN,get(o,CLEAN)+1)
            return again(o,600)
        put(o,SAVED,at)
        if at==G_JOB:
            return job_drop(o,w,602,at)
        if at==G_FUTURE:
            return public_call(o,w,603,26,0,0)
        return drop_value(o,w,601,at)
    if phase==601:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,601)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,600)
    if phase==602:
        if release_job(o,G_JOB)==0:
            return quarantine(o,w,602)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,600)
    if phase==603:
        if release_future(o,G_FUTURE)==0:
            return quarantine(o,w,603)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,600)
    return quarantine(o,w,phase)
'''

C['CAP_END']=4840
SOURCE+=r'''
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    phase=get(o,PHASE)
    if get(o,DROP_ACTIVE)!=0:
        return again(o,3990)
    if status!=5 or get(o,FAILURE_MODE)!=0 or (phase>=3100 and phase<3200):
        return again(o,3990)
    put(o,ERROR_KIND,103)
    route=300
    if (get(o,WORK_PHASE)==119 or get(o,WORK_PHASE)==120) and get(o,FINALLY_STARTED)==0 and get(o,CATCHING)==0:
        route=30
    put(o,ERROR_ROUTE,route)
    return again(o,3100)
def done(o:mutbuf) -> u32:
    put(o,CLEAN,0)
    return again(o,4000)
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    kind=2
    if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)==1:
        kind=1
    put(w,480,kind)
    put(w,504,get(o,PHASE))
    put(o,DETAIL,detail)
    put(w,464,1)
    if get(o,LOCK)!=0:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,3991)
    return terminal(o,w,2)
def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3990:
        return quarantine(o,w,get(o,DETAIL))
    if phase==3991:
        if queue_valid(o)!=0:
            put(o,LOCK,0)
        return terminal(o,w,2)
    if phase==4000:
        if get(o,LOCK)!=0 or get(o,EXEC_NESTED)!=0 or get(o,ACCOUNT_NESTED)!=0:
            return quarantine(o,w,4000)
        at=G_META+get(o,CLEAN)*24
        if at>=CAP_END:
            if get(o,POST_EXIT)!=0:
                return again(o,4070)
            return again(o,4050)
        if get(o,at)==0:
            put(o,CLEAN,get(o,CLEAN)+1)
            return again(o,4000)
        put(o,SAVED,at)
        if at==G_META or at==G_JOB or at==G_FUTURE:
            if get(o,OWNED_CURRENT)==0:
                return quarantine(o,w,4000)
        if at==G_JOB:
            return job_drop(o,w,4002,G_JOB)
        if at==G_FUTURE:
            return public_call(o,w,4003,26,0,0)
        return drop_value(o,w,4001,at)
    if phase==4001:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,4001)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,4000)
    if phase==4002:
        if release_job(o,G_JOB)==0:
            return quarantine(o,w,4002)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,4000)
    if phase==4003:
        if release_future(o,G_FUTURE)==0:
            return quarantine(o,w,4003)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,4000)
    if phase==4050:
        if get(o,PROVIDER)!=0:
            request(o,PROVIDER_INPUT,5)
            within(o,RQ+40,PROVIDER,24)
            return provider_owner(o,w,4051)
        if get(o,DREQ)!=0:
            return deallocate(o,4052,get(o,DREQ))
        return again(o,4060)
    if phase==4051:
        if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,4051)
        zero(o,PROVIDER,24)
        return again(o,4050)
    if phase==4052:
        put(o,DREQ,0)
        return again(o,4050)
    if phase==4060:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,12)
            return jobs(o,w,4061)
        if get(o,FUTURE_PENDING)!=0:
            release_begin(o)
            request(o,PUBLIC_INPUT,20)
            return invoke(o,4062,get(w,168),51,RQ,192,PUBLIC_OUT,65536,get(w,176),get(w,184))
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return values(o,w,4064,128)
        if get(o,POST_EXIT)!=0:
            put(w,464,0)
            put(w,480,0)
            put(w,504,0)
            put(o,DRAIN_COUNT,0)
            put(o,DRAIN_INDEX,0)
            put(o,DRAIN_READY,0)
            put(o,OWNED_CURRENT,0)
            return terminal(o,w,0)
        return terminal(o,w,choose(get(o,FAILURE_MODE)!=0,1,0))
    if phase==4061:
        if release_job_retry(o)==0:
            return quarantine(o,w,4061)
        return again(o,4060)
    if phase==4062:
        if release_future_retry(o)==0:
            return quarantine(o,w,4062)
        release_begin(o)
        request(o,CELL_QUERY_INPUT,21)
        return invoke(o,4063,get(w,384),51,RQ,128,RP,16384,get(w,392),get(w,400))
    if phase==4063:
        if release_cell_query(o)==0:
            return quarantine(o,w,4063)
        return again(o,4060)
    if phase==4064:
        if release_value_retry(o)==0:
            return quarantine(o,w,4064)
        return again(o,4060)
    if phase==4070:
        if get(o,POST_EXIT)!=1:
            return quarantine(o,w,4070)
        row=get(o,ROW_CLEAN_INDEX)
        if row>=get(o,DRAIN_COUNT):
            return again(o,4050)
        sub=get(o,ROW_CLEAN_SUB)
        if sub>=4:
            put(o,ROW_CLEAN_SUB,0)
            put(o,ROW_CLEAN_INDEX,row+1)
            return again(o,4070)
        at=ROWS+row*128+sub*24
        put(o,SAVED,at)
        if get(o,at)==0:
            put(o,ROW_CLEAN_SUB,sub+1)
            return again(o,4070)
        if sub==0:
            return job_drop(o,w,4071,at)
        if sub==2:
            return public_drop_at(o,w,4072,at)
        return drop_value(o,w,4073,at)
    if phase==4071:
        if release_job(o,get(o,SAVED))==0:
            return quarantine(o,w,4071)
        put(o,ROW_CLEAN_SUB,get(o,ROW_CLEAN_SUB)+1)
        return again(o,4070)
    if phase==4072:
        if release_future(o,get(o,SAVED))==0:
            return quarantine(o,w,4072)
        put(o,ROW_CLEAN_SUB,get(o,ROW_CLEAN_SUB)+1)
        return again(o,4070)
    if phase==4073:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,4073)
        put(o,ROW_CLEAN_SUB,get(o,ROW_CLEAN_SUB)+1)
        return again(o,4070)
    return quarantine(o,w,phase)
def terminal(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,choose(get(o,OP)==3,CLEAN_REPLY,REPLY))
    put(o,8,status)
    put(o,16,get(w,464))
    put(o,24,get(o,DETAIL))
    if get(w,464)==0:
        put(w,376,0)
    return 0
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    if next>=300 and next<700:
        put(o,MODULE,1)
    elif next<300:
        put(o,MODULE,0)
    return 10
'''
def source_program(entry='business'):
    own={n.name:ast.get_source_segment(SOURCE,n)for n in ast.parse(SOURCE).body if isinstance(n,ast.FunctionDef)}
    fallback={}
    for text in (E.SOURCE,E.BASE,E.R.SOURCE):
        for n in ast.parse(text).body:
            if isinstance(n,ast.FunctionDef)and n.name not in fallback:
                fallback[n.name]=ast.get_source_segment(text,n)
    for name,text in fallback.items():
        if name not in own:own[name]=text
    own['value_task']=own['value_task'].replace('    if phase==1000:\n','    if phase==1000:\n        if get(o,DEST)!=0 and get(o,get(o,DEST))!=0:\n            return drop_value(o,w,1008,get(o,DEST))\n',1)
    own['value_task']=own['value_task'].replace('    if phase==1010:\n','    if phase==1008:\n        if cleared(o,get(o,DEST))==0:\n            return quarantine(o,w,1008)\n        return again(o,1000)\n    if phase==1010:\n',1)
    own['report_task']=own['report_task'].replace('return again(o,6)','return again(o,get(o,REPORT_NEXT))')
    own['snapshot_task']=own['snapshot_task'].replace('ERROR_VALUE','NATIVE_ERROR')
    own['snapshot_task']=own['snapshot_task'].replace('    if phase==1399:\n        return fail(o,1,1399)','    if phase==1399:\n        put(o,ERROR_ROUTE,300)\n        return again(o,3500)')
    # The two fixed policies share helpers but keep their active control families separate.
    shared=own['shared_step']
    failure_shared=shared.replace('def shared_step(', 'def failure_shared(')
    for a,b in [(1100,1200),(1300,1400),(1400,1500)]:
        helper={1100:'clocks',1300:'snapshot_task',1400:'import_task'}[a]
        failure_shared=failure_shared.replace('    if phase>='+str(a)+' and phase<'+str(b)+':\n        return '+helper+'(o,w,phase)\n','')
    own['failure_shared']=failure_shared
    own['business_failure']=own['business_failure'].replace('return shared_step(s,o,w,phase)','return failure_shared(s,o,w,phase)')
    own['literal']='def literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
    groups=[list(LABELS.items())[i:i+8]for i in range(0,len(LABELS),8)]
    for i,group in enumerate(groups):
        own['literal']+='    if id<='+str(group[-1][0])+':\n        return literal_group_'+str(i)+'(o,at,id)\n'
        text='def literal_group_'+str(i)+'(o:mutbuf,at:u64,id:u64) -> u64:\n'
        for key,value in group:
            raw=value.encode()
            text+='    if id=='+str(key)+':\n'
            for at in range(0,len(raw)-len(raw)%8,8):text+='        put(o,at+'+str(at)+','+str(int.from_bytes(raw[at:at+8],'little'))+')\n'
            for at in range(len(raw)-len(raw)%8,len(raw)):text+='        store(o,at+'+str(at)+','+str(raw[at])+')\n'
            text+='        return '+str(len(raw))+'\n'
        own['literal_group_'+str(i)]=text+'    return 0\n'
    own['literal']+='    return 0\n'
    s='\n\n'.join(own.values())+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
    tree=ast.parse(s);functions={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
    chosen=set();todo=[entry]
    while todo:
        name=todo.pop()
        if name in chosen:continue
        chosen.add(name)
        todo.extend(x.func.id for x in ast.walk(functions[name])if isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id in functions and x.func.id not in chosen)
    order=[entry]+[x.name for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in chosen and x.name!=entry]
    return '\n\n'.join(ast.get_source_segment(s,functions[name])for name in order)+'\n'
def program(entry='business'):return document(source_program(entry),'background_optimizer_business_worker')
if __name__=='__main__':
    for entry,suffix in [('business',''),('business_failure','_failure')]:
        tree=program(entry);p=ROOT/('examples/hia_bootstrap/background_optimizer_business_worker'+suffix+'.hepta')
        p.write_text(render_assembly(tree))
        print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
