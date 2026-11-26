"""Fixed native accounting: real queue custody, observations, freezing and ledger."""
from pathlib import Path
from tools import hia_background_retirement_source as R
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE
ROOT=Path(__file__).resolve().parents[1]
C={
'DROP_ACTIVE':800,'DROP_KNOWN':808,'JOB_PENDING':816,'FUTURE_PENDING':824,'VALUE_PENDING':832,'QUARANTINE_KIND':840,
'MAGIC':int.from_bytes(b'HIABACQ1','little'),'REPLY':int.from_bytes(b'HIABACR1','little'),'CONTEXT':int.from_bytes(b'HIABACC1','little'),
'VALUE_INPUT':int.from_bytes(b'HIABVQ01','little'),'VALUE_REPLY':int.from_bytes(b'HIABVR01','little'),
'JOB_INPUT':int.from_bytes(b'HIABJO01','little'),'JOB_REPLY':int.from_bytes(b'HIABJOR1','little'),
'LEDGER_INPUT':int.from_bytes(b'HIABLG01','little'),'LEDGER_REPLY':int.from_bytes(b'HIABLGR1','little'),
'REPORT_INPUT':int.from_bytes(b'HIABRP02','little'),'REPORT_REPLY':int.from_bytes(b'HIABRR01','little'),'REPORT_CONTEXT':int.from_bytes(b'HIABRC01','little'),'REPORT_OBSERVE':int.from_bytes(b'HIABROQ1','little'),
'PUBLIC_INPUT':int.from_bytes(b'HIABFP01','little'),'PUBLIC_REPLY':int.from_bytes(b'HIABFRP1','little'),
'CELL_INPUT':int.from_bytes(b'HIABFQ01','little'),'CELL_REPLY':int.from_bytes(b'HIABFR01','little'),
'KERNEL_INPUT':int.from_bytes(b'HIAMVFQ1','little'),'KERNEL_REPLY':int.from_bytes(b'HIAMVFR1','little'),
'FREEZE_INPUT':int.from_bytes(b'HIABFZQ1','little'),'FREEZE_REPLY':int.from_bytes(b'HIABFZR1','little'),'FREEZE_CONTEXT':int.from_bytes(b'HIABFZC1','little'),
'PAYLOAD_INPUT':int.from_bytes(b'HIABPY01','little'),'PAYLOAD_REPLY':int.from_bytes(b'HIABPYR1','little'),
'DEC_INPUT':int.from_bytes(b'HIAMVU01','little'),'DEC_REPLY':int.from_bytes(b'HIAMVUR1','little'),
'QUEUE_STATE':int.from_bytes(b'HIABGQS1','little'),
'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'ALREADY':160,'G_JOB':168,'G_META':192,'G_RESULT':216,'G_FUTURE':240,
'R_RESULT':264,'R_RECEIPT':288,'R_COST':312,'FROZEN':336,'DECIMAL':360,'KEY':384,'TIME_VALUE':408,'FEEDBACK':448,
'STAGE':456,'PTR':464,'DYNAMIC':472,'DYNAMIC_N':480,'OFFSET':488,'KERNEL':496,'STATUS_CAP':528,'STATUS_INDEX':552,'CLEAN':560,'SAVED':568,
'ERRN':576,'UCHAR':584,'USTART':592,'UEND':600,'UCP':608,'FROZEN_N':616,'PID':648,'QUARANTINED':656,'TIME_SEC':664,'TIME_NSEC':672,
'PUB_ERROR':696,'SETTLED':720,'TID':728,'STATUS_VALUE':752,'CONTROL_N':896,
'TS':2048,'ST':2304,'RQ':4096,'RP':8192,'RP_N':73728,'PUBLIC_OUT':81920,
'REPORT_OUT':147456,'REPORT_WORK':155648,'FREEZE_WORK':188416,'REPORT_SOURCE':190464,'ERR':191488,'FREEZE_OUT':196608,'OUT':524288}
C.update(R.MAGICS)
SOURCE=r'''
def account(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<4096:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return prepare(s,o,w,phase)
    if phase<200:
        return clock_value(s,o,w,phase)
    if phase<300:
        return reporting(s,o,w,phase)
    if phase<400:
        return freezing(s,o,w,phase)
    if phase<500:
        return conversion(s,o,w,phase)
    if phase<600:
        return settlement(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return 4294967293
    at=16
    while at<128:
        used=word_load(s,8)==0 and at>=24 and at<=112
        if used==False and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)<2048:
        return 4294967293
    if get(w,64)==0 or get(w,72)==0 or get(w,80)<4096:
        return 4294967293
    if get(w,88)==0 or get(w,96)==0 or get(w,104)<256:
        return 4294967293
    if get(w,112)==0 or get(w,120)==0 or get(w,128)<256 or get(w,136)==0:
        return 4294967293
    if get(w,160)==0 or get(w,168)==0 or get(w,176)==0 or get(w,184)<256:
        return 4294967293
    if get(w,192)==0 or get(w,200)==0 or get(w,208)<256:
        return 4294967293
    if get(w,224)==0 or get(w,232)==0 or get(w,240)<4096 or get(w,248)>1:
        return 4294967293
    zero(o,128,3968)
    zero(o,FREEZE_WORK,2048)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def prepare(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,216)!=0 and get(w,216)!=pid):
            return finish(o,6)
        put(w,216,pid)
        put(o,PID,pid)
        if get(o,OP)==1:
            if get(w,248)==0:
                return finish(o,0)
            from_work(w,o,256,128,CONTROL_N)
            from_work(w,o,1152,FREEZE_WORK,2048)
            from_work(w,o,3200,ERR,896)
            if get(o,QUARANTINE_KIND)==2:
                return finish(o,9)
            put(w,248,0)
            put(o,QUARANTINED,0)
            put(o,OP,1)
            put(o,CLEAN,0)
            return again(o,700)
        if get(w,248)!=0:
            return finish(o,6)
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        tid=get(o,FEEDBACK)
        if tid<2 or tid>=NEGATIVE:
            return finish(o,8)
        put(o,TID,tid)
        return memory(o,3,0,get(w,232),3,TS,176)
    if phase==3:
        if get(o,TS)!=QUEUE_STATE or get(o,TS+8)!=get(o,PID) or get(o,TS+160)!=get(o,TID) or (get(o,TS+128)&4294967295)==0:
            return finish(o,6)
        request(o,LEDGER_INPUT,4)
        copy_source(s,o,24,RQ+24,24)
        return ledger(o,w,10)
    if phase==10:
        if valid(o,RP,LEDGER_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        if get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
        if get(o,RP+48)>1:
            return fail(o,9,10)
        put(o,ALREADY,get(o,RP+48))
        if get(o,ALREADY)!=0:
            return finish(o,0)
        return system(o,11,228,12,1,TS,0,0,0,0)
    if phase==11:
        if get(o,FEEDBACK)==MAX-3:
            return system(o,11,228,12,1,TS,0,0,0,0)
        if get(o,FEEDBACK)!=0 or get(o,TS)>=9223372036854775808 or get(o,TS+8)>=1000000000:
            return fail(o,8,get(o,FEEDBACK))
        put(o,TIME_SEC,get(o,TS))
        put(o,TIME_NSEC,get(o,TS+8))
        request(o,JOB_INPUT,2)
        copy_source(s,o,24,RQ+24,24)
        return jobs(o,w,12)
    if phase==12:
        if valid(o,RP,JOB_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        if get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
        within(o,G_JOB,RP+16,24)
        request(o,JOB_INPUT,6)
        within(o,RQ+24,G_JOB,24)
        return jobs(o,w,13)
    if phase==13:
        if valid(o,RP,JOB_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)==0 or get(o,RP+96)!=512:
            return fail(o,7,13)
        put(o,KERNEL,get(o,RP+64))
        request(o,VALUE_INPUT,5)
        copy_source(s,o,48,RQ+24,24)
        return values(o,w,14,128)
    if phase==14:
        if value_take(o,G_META)!=0:
            return fail(o,value_failure(o),14)
        request(o,VALUE_INPUT,5)
        copy_source(s,o,72,RQ+24,24)
        return values(o,w,15,128)
    if phase==15:
        if value_take(o,G_RESULT)!=0:
            return fail(o,value_failure(o),15)
        request(o,PUBLIC_INPUT,5)
        from_work(w,o,136,RQ+16,24)
        copy_source(s,o,96,RQ+40,24)
        return public(o,w,16)
    if phase==16:
        if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        if get(o,PUBLIC_OUT+8)!=0:
            within(o,PUB_ERROR,PUBLIC_OUT+72,24)
            return fail(o,7,get(o,PUBLIC_OUT+16))
        if get(o,PUBLIC_OUT+16)!=2 or get(o,PUBLIC_OUT+24)!=get(w,136) or get(o,PUBLIC_OUT+32)!=get(w,144) or get(o,PUBLIC_OUT+40)!=get(w,152):
            return fail(o,9,16)
        within(o,G_FUTURE,PUBLIC_OUT+48,24)
        request(o,CELL_INPUT,6)
        within(o,RQ+24,G_FUTURE,24)
        return invoke(o,17,get(w,192),51,RQ,128,RP,16384,get(w,200),get(w,208))
    if phase==17:
        if valid(o,RP,CELL_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)!=get(o,KERNEL):
            return fail(o,7,17)
        return again(o,100)
    return fail(o,9,phase)

def clock_value(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        put(o,RQ+96,6)
        put(o,RQ+128,126917885259630)
        return values(o,w,101,134)
    if phase==101:
        if value_take(o,KEY)!=0:
            return fail(o,value_failure(o),101)
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,2)
        n=clock_decimal(o,RQ+128,get(o,TIME_SEC),get(o,TIME_NSEC))
        put(o,RQ+96,n)
        return values(o,w,102,128+n)
    if phase==102:
        if value_take(o,TIME_VALUE)!=0:
            return fail(o,value_failure(o),102)
        request(o,VALUE_INPUT,10)
        within(o,RQ+24,G_META,24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,TIME_VALUE,24)
        return values(o,w,103,128)
    if phase==103:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,value_failure(o),103)
        zero(o,REPORT_SOURCE,128)
        put(o,REPORT_SOURCE,REPORT_INPUT)
        put(o,REPORT_SOURCE+8,1)
        within(o,REPORT_SOURCE+24,G_META,24)
        within(o,REPORT_SOURCE+48,G_RESULT,24)
        zero(o,REPORT_WORK,128)
        put(o,REPORT_WORK,REPORT_CONTEXT)
        put(o,REPORT_WORK+8,get(w,8))
        put(o,REPORT_WORK+16,get(w,16))
        put(o,REPORT_WORK+24,get(w,24))
        put(o,REPORT_OUT+128,0)
        return again(o,200)
    return fail(o,9,phase)

def reporting(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        return invoke(o,201,get(w,32),819,REPORT_SOURCE,128,REPORT_OUT,8192,REPORT_WORK,32768)
    if phase==201:
        rc=get(o,FEEDBACK)
        if rc==10:
            return again(o,200)
        if rc==4:
            if get(o,REPORT_OUT)!=get(w,8):
                return fail(o,9,201)
            mask=get(o,REPORT_OUT+8)
            mapped=0
            i=0
            while i<6:
                selector=(mask>>(i*2))&3
                at=get(o,REPORT_OUT+16+i*8)
                if selector!=0:
                    mapped=mapped|(3<<(i*2))
                    if selector==1:
                        at=at+REPORT_WORK
                    elif selector==2:
                        at=at+REPORT_SOURCE
                    else:
                        at=at+REPORT_OUT
                put(o,16+i*8,at)
                i=i+1
            put(o,0,get(w,8))
            put(o,8,mapped)
            put(o,PHASE,202)
            return 9
        if rc==11:
            if get(o,REPORT_OUT)!=REPORT_OBSERVE or get(o,REPORT_OUT+8)<1 or get(o,REPORT_OUT+8)>2:
                put(o,ERROR,9)
                put(o,DETAIL,211)
                put(o,REPORT_OUT+136,1)
                return again(o,200)
            put(o,STAGE,get(o,REPORT_OUT+8))
            if get(o,STAGE)==1:
                request(o,KERNEL_INPUT,9)
                return invoke(o,203,get(w,160),51,RQ,64,RP,512,get(o,KERNEL),512)
            request(o,PUBLIC_INPUT,9)
            from_work(w,o,136,RQ+16,24)
            within(o,RQ+40,G_FUTURE,24)
            return public(o,w,204)
        if rc!=0 or get(o,REPORT_OUT)!=REPORT_REPLY:
            return fail(o,7,rc)
        status=get(o,REPORT_OUT+8)
        if status!=0:
            if get(o,ERROR)==0:
                put(o,ERROR,choose(status==5,5,7))
                put(o,DETAIL,status)
            return again(o,700)
        within(o,R_RESULT,REPORT_OUT+24,24)
        within(o,R_RECEIPT,REPORT_OUT+48,24)
        within(o,R_COST,REPORT_OUT+72,24)
        if get(o,R_RESULT)==0 or get(o,R_RECEIPT)==0 or get(o,R_COST)==0:
            return fail(o,9,201)
        if get(o,ERROR)!=0:
            return again(o,700)
        zero(o,FREEZE_WORK,2048)
        return memory(o,300,0,get(w,48),3,FREEZE_WORK,128)
    if phase==202:
        put(o,REPORT_OUT+136,get(o,FEEDBACK))
        return again(o,200)
    if phase==203:
        if valid(o,RP,KERNEL_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+32)>2:
            put(o,ERROR,7)
            put(o,DETAIL,203)
            put(o,REPORT_OUT+136,1)
        else:
            put(o,REPORT_OUT+136,0)
            put(o,REPORT_OUT+144,choose(get(o,RP+32)==2,1,0))
        return again(o,200)
    if phase==204:
        if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0 or get(o,PUBLIC_OUT+8)!=0 or get(o,PUBLIC_OUT+16)!=5 or get(o,PUBLIC_OUT+96)>2:
            put(o,ERROR,7)
            put(o,DETAIL,204)
            if valid(o,PUBLIC_OUT,PUBLIC_REPLY)!=0:
                within(o,PUB_ERROR,PUBLIC_OUT+72,24)
            put(o,REPORT_OUT+136,1)
        else:
            put(o,REPORT_OUT+136,0)
            put(o,REPORT_OUT+144,get(o,PUBLIC_OUT+96))
        return again(o,200)
    return fail(o,9,phase)

def freezing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,FREEZE_WORK)!=FREEZE_CONTEXT or get(o,FREEZE_WORK+8)!=get(w,8) or get(o,FREEZE_WORK+16)!=get(w,16) or get(o,FREEZE_WORK+24)!=get(w,24) or get(o,FREEZE_WORK+96)!=0:
            return fail(o,9,300)
        request(o,FREEZE_INPUT,0)
        within(o,RQ+24,R_RECEIPT,24)
        return invoke(o,301,get(w,40),819,RQ,128,FREEZE_OUT,262144,FREEZE_WORK,2048)
    if phase==301:
        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        status=get(o,FREEZE_OUT+8)
        if status==0:
            within(o,FROZEN,FREEZE_OUT+16,24)
            put(o,FROZEN_N,get(o,FREEZE_OUT+40))
            if get(o,FROZEN)==0:
                return fail(o,9,301)
            request(o,VALUE_INPUT,19)
            within(o,RQ+24,R_COST,24)
            return values(o,w,400,128)
        if status==1:
            n=get(o,FREEZE_OUT+48)
            if n>896:
                return fail(o,9,301)
            within(o,ERR,FREEZE_OUT+128,n)
            put(o,ERRN,n)
            put(o,UCHAR,get(o,FREEZE_OUT+72))
            put(o,USTART,get(o,FREEZE_OUT+80))
            put(o,UEND,get(o,FREEZE_OUT+88))
            put(o,UCP,get(o,FREEZE_OUT+96))
        return fail(o,status,get(o,FREEZE_OUT+64))
    return fail(o,9,phase)

def conversion(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=2:
            return fail(o,value_failure(o),400)
        n=get(o,RP+72)
        if n==0 or n>MAX-128:
            return fail(o,5,n)
        put(o,DYNAMIC_N,128+n)
        return allocate(o,401,128+n)
    if phase==401:
        p=get(o,FEEDBACK)
        if p==0:
            return fail(o,5,401)
        put(o,DYNAMIC,p)
        request(o,DEC_INPUT,1)
        put(o,RQ+72,get(o,DYNAMIC_N)-128)
        return memory(o,402,3,RQ,0,p,128)
    if phase==402:
        put(o,OFFSET,0)
        return again(o,403)
    if phase==403:
        n=get(o,DYNAMIC_N)-128
        if get(o,OFFSET)==n:
            return invoke(o,406,get(w,168),48,get(o,DYNAMIC),get(o,DYNAMIC_N),RP,512,get(w,176),get(w,184))
        chunk=n-get(o,OFFSET)
        if chunk>65536:
            chunk=65536
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,R_COST,24)
        put(o,RQ+104,get(o,OFFSET))
        put(o,RQ+112,chunk)
        put(o,PTR,chunk)
        return values(o,w,404,128)
    if phase==404:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)!=get(o,PTR) or get(o,RP+72)!=get(o,DYNAMIC_N)-128:
            return fail(o,7,404)
        if get(o,OFFSET)==0 and byte(o,RP+8192)==45:
            return fail(o,9,404)
        return memory(o,405,3,RP+8192,0,get(o,DYNAMIC)+128+get(o,OFFSET),get(o,PTR))
    if phase==405:
        put(o,OFFSET,get(o,OFFSET)+get(o,PTR))
        return again(o,403)
    if phase==406:
        if valid(o,RP,DEC_REPLY)==0:
            return fail(o,7,406)
        if get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
        within(o,DECIMAL,RP+16,24)
        request(o,VALUE_INPUT,2)
        put(o,RQ+104,4)
        put(o,RQ+96,6)
        put(o,RQ+128,126948300911731)
        return values(o,w,500,134)
    return fail(o,9,phase)

def settlement(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if value_take(o,STATUS_CAP)!=0:
            return fail(o,value_failure(o),500)
        request(o,VALUE_INPUT,9)
        within(o,RQ+24,R_RESULT,24)
        within(o,RQ+48,STATUS_CAP,24)
        return values(o,w,501,128)
    if phase==501:
        if value_take(o,STATUS_VALUE)!=0:
            return fail(o,value_failure(o),501)
        if get(o,RP+16)!=4:
            return fail(o,9,501)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,STATUS_VALUE,24)
        return values(o,w,502,128)
    if phase==502:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+72)>11:
            return fail(o,9,502)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,STATUS_VALUE,24)
        put(o,RQ+112,get(o,RP+72))
        return values(o,w,503,128)
    if phase==503:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,7,503)
        status=status_number(o,RP+8192,get(o,RP+72))
        if status>=6:
            return fail(o,9,503)
        put(o,STATUS_INDEX,status)
        request(o,LEDGER_INPUT,1)
        within(o,RQ+24,G_JOB,24)
        within(o,RQ+48,FROZEN,24)
        within(o,RQ+72,DECIMAL,24)
        put(o,RQ+96,status)
        return ledger(o,w,504)
    if phase==504:
        if valid(o,RP,LEDGER_REPLY)==0:
            return fail(o,7,504)
        if get(o,RP+40)==1:
            zero(o,FROZEN,24)
            put(o,SETTLED,1)
        put(o,ALREADY,get(o,RP+48))
        if get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
        if get(o,SETTLED)==0 and get(o,ALREADY)==0:
            return fail(o,9,504)
        return again(o,700)
    return fail(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return quarantine(o,w,700)
        if get(o,FREEZE_WORK+96)!=0:
            request(o,FREEZE_INPUT,1)
            return invoke(o,701,get(w,40),819,RQ,128,FREEZE_OUT,262144,FREEZE_WORK,2048)
        return again(o,710)
    if phase==701:
        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0 or get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            return quarantine(o,w,701)
        if get(o,FREEZE_OUT+8)==0 and get(o,FREEZE_OUT+16)!=0:
            if get(o,FROZEN)!=0:
                return quarantine(o,w,701)
            within(o,FROZEN,FREEZE_OUT+16,24)
        return again(o,710)
    if phase==710:
        index=get(o,CLEAN)
        if index>=14:
            return again(o,730)
        at=G_JOB+index*24
        if index==11:
            at=STATUS_VALUE
        if index==12:
            at=STATUS_CAP
        if index==13:
            at=PUB_ERROR
        if get(o,at)==0:
            put(o,CLEAN,index+1)
            return again(o,710)
        put(o,SAVED,at)
        if index==0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,11)
            within(o,RQ+24,at,24)
            return jobs(o,w,711)
        if index==3:
            release_begin(o)
            request(o,PUBLIC_DROP_INPUT,26)
            from_work(w,o,136,RQ+16,24)
            within(o,RQ+40,at,24)
            return public(o,w,712)
        if index==7:
            request(o,PAYLOAD_INPUT,3)
            within(o,RQ+24,at,24)
            return invoke(o,713,get(o,FREEZE_WORK+56),51,RQ,128,RP,512,get(o,FREEZE_WORK+64),get(o,FREEZE_WORK+72))
        if index==8:
            request(o,DEC_INPUT,3)
            within(o,RQ+24,at,24)
            return invoke(o,714,get(w,168),51,RQ,128,RP,512,get(w,176),get(w,184))
        release_begin(o)
        request(o,VALUE_DROP_INPUT,29)
        within(o,RQ+24,at,24)
        return values(o,w,715,128)
    if phase>=711 and phase<=715:
        done=0
        if phase==711:
            done=release_job(o,get(o,SAVED))
        elif phase==712:
            done=release_future(o,get(o,SAVED))
        elif phase==715:
            done=release_value(o,get(o,SAVED))
        else:
            magic=choose(phase==713,PAYLOAD_REPLY,DEC_REPLY)
            if valid(o,RP,magic)!=0 and get(o,RP+8)==0:
                zero(o,get(o,SAVED),24)
                done=1
        if done==0:
            return quarantine(o,w,phase)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,710)
    if phase==730:
        if get(o,DYNAMIC)!=0:
            return deallocate(o,731,get(o,DYNAMIC))
        return again(o,740)
    if phase==731:
        put(o,DYNAMIC,0)
        put(o,DYNAMIC_N,0)
        return again(o,740)
    if phase==740:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,12)
            return jobs(o,w,741)
        if get(o,FUTURE_PENDING)!=0:
            release_begin(o)
            request(o,PUBLIC_INPUT,20)
            return public(o,w,742)
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return values(o,w,744,128)
        return finish(o,get(o,ERROR))
    if phase==741:
        if release_job_retry(o)==0:
            return quarantine(o,w,741)
        return again(o,740)
    if phase==742:
        if release_future_retry(o)==0:
            return quarantine(o,w,742)
        release_begin(o)
        request(o,CELL_QUERY_INPUT,21)
        return invoke(o,743,get(w,192),51,RQ,128,RP,16384,get(w,200),get(w,208))
    if phase==743:
        if release_cell_query(o)==0:
            return quarantine(o,w,743)
        return again(o,740)
    if phase==744:
        if release_value_retry(o)==0:
            return quarantine(o,w,744)
        return again(o,740)
    return quarantine(o,w,phase)

def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,RP_N,get(w,16),get(w,24))
def jobs(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,88),51,RQ,128,RP,2048,get(w,96),get(w,104))
def ledger(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,64),51,RQ,128,RP,8192,get(w,72),get(w,80))
def public(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,112),51,RQ,192,PUBLIC_OUT,65536,get(w,120),get(w,128))
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
    if valid(o,RP,VALUE_REPLY)!=0 and get(o,RP+8)==5:
        return 5
    return 7
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
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    kind=2
    if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)==1:
        kind=1
    if detail==713 and valid(o,RP,PAYLOAD_REPLY)!=0:
        status=get(o,RP+8)
        if status==1 or status==5 or status==6:
            kind=1
    if detail==714 and valid(o,RP,DEC_REPLY)!=0:
        status=get(o,RP+8)
        if status==1 or status==5 or status==6:
            kind=1
    put(o,QUARANTINE_KIND,kind)
    put(o,QUARANTINED,1)
    to_work(o,w,128,256,CONTROL_N)
    to_work(o,w,FREEZE_WORK,1152,2048)
    to_work(o,w,ERR,3200,896)
    put(w,248,1)
    put(o,QUARANTINED,1)
    put(o,DETAIL,detail)
    return finish(o,9)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,ALREADY))
    put(o,24,get(o,SETTLED))
    put(o,48,get(o,ERRN))
    put(o,56,get(o,QUARANTINED))
    put(o,64,get(o,DETAIL))
    put(o,72,get(o,UCHAR))
    put(o,80,get(o,USTART))
    put(o,88,get(o,UEND))
    put(o,96,get(o,UCP))
    if status==1:
        within(o,128,ERR,get(o,ERRN))
    return 0
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
SOURCE+='\n'+R.SOURCE
def source_program():
 s=SOURCE
 statuses=('published','abstained','stale','rejected','cancelled','interrupted')
 s+='\ndef status_number(o:mutbuf,at:u64,n:u64) -> u64:\n'
 for i,status in enumerate(statuses):
  expr=' and '.join('byte(o,at+'+str(k)+')=='+str(c)for k,c in enumerate(status.encode()))
  s+='    if n=='+str(len(status))+' and '+expr+':\n        return '+str(i)+'\n'
 s+='    return 6\n'
 tree=ast.parse(BASE)
 for name in ('invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'):
  node=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name==name)
  s+='\n'+ast.get_source_segment(BASE,node)+'\n'
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_account')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/background_optimizer_account.hepta';tree=program();p.write_text(render_assembly(tree))
 print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
