"""Complete detached BG snapshot from the actual queue, worker and owned ledger."""
from pathlib import Path
from tools import hia_background_retirement_source as R
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,BAD=4294967293,
 PHASE=256,ERROR=264,DETAIL=272,OP=280,LOCK=288,FINISHED=296,QUAR=304,
 QMAX=320,QCLOSED=328,QPEND=336,QQUEUED=344,QACTIVE=352,ALIVE=360,
 NROWS=368,RECENT_COUNT=376,OUTCOME_MASK=384,ORDERCOUNT=392,ORDER=400,
 CREATE_INDEX=448,INDEX=488,ROWINDEX=496,ROW_N=504,STREAMKIND=512,MAP=520,MAPN=528,
 GDICT=544,GKEYID=552,GVALUE=560,GAFTER=568,DROP_AT=576,DROP_AFTER=584,
 ENUM_INDEX=592,CLEAN=616,CLEAN_KIND=624,CLEAN_AT=632,
 DROP_ACTIVE=640,DROP_KNOWN=648,VALUE_PENDING=656,JOB_PENDING=664,
 ROOT=768,COST=792,OUTCOMES=816,RECENT=840,FAILURE=864,ACTIVENUM=888,
 KEY=912,TEMP=936,EKEY=960,EVALUE=984,ACTIVE_JOB=1008,META=1032,FAILBORROW=1056,
 QHEAD=2048,SMALL=3500,FEEDBACK=3840,RQ=8192,RP=16384,ROWS=32768,
 LOUT=65536,WOUT=73728,QOUT=81920,SUBCAP=98304)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABSPQ1',REPLY='HIABSPR1',CONTEXT='HIABSPC1',VQ='HIABVQ01',VR='HIABVR01',
 QQ='HIABGQ04',QR='HIABGQR2',QCTX='HIABGQS1',LQ='HIABLG02',LR='HIABLGR1',
 WQ='HIABGW01',WR='HIABGWO1',JQ='HIABJO01',JR='HIABJOR1',
 DQ='HIAMVU01',DR='HIAMVUR1',BQ='HIABPY01',BR='HIABPYR1',SUBCTX='HIABSSC1').items()})
C.update(R.MAGICS)
SOURCE=r"""
def snapshot(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<262144 or length(w)<8192:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<40:
        return capture(s,o,w,phase)
    if phase<100:
        return failure_copy(s,o,w,phase)
    if phase<200:
        return receipts(s,o,w,phase)
    if phase<300:
        return fields(s,o,w,phase)
    if phase<700:
        return releasing(s,o,w,phase)
    if phase<1000:
        return cleanup(s,o,w,phase)
    return mutation(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return BAD
    at=16
    while at<128:
        if word_load(s,at)!=0:
            return BAD
        at=at+8
    if get(w,0)!=CONTEXT:
        return BAD
    at=8
    while at<=152:
        minimum=256
        if at==32 or at==56:
            minimum=4096
        elif at==80:
            minimum=512
        if get(w,at)==0 or get(w,at+8)==0 or get(w,at+16)<minimum or get(w,at+8)>MAX-get(w,at+16):
            return BAD
        at=at+24
    if get(w,176)==0 or get(w,184)<8192 or get(w,176)>MAX-get(w,184):
        return BAD
    if get(w,192)==0 or get(w,200)<16384 or get(w,192)>MAX-get(w,200):
        return BAD
    if get(w,208)<2 or get(w,208)>2147483647 or get(w,216)>2:
        return BAD
    at=224
    while at<256:
        if get(w,at)!=0:
            return BAD
        at=at+8
    zero(o,256,3840)
    zero(o,ROWS,3456)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FEEDBACK)!=get(w,208):
            return finish(o,6)
        if get(o,OP)==1:
            if get(w,216)==0:
                return finish(o,0)
            if get(w,216)==2:
                put(o,QUAR,2)
                return finish(o,9)
            from_work(w,o,256,256,3840)
            from_work(w,o,4096,ROWS,3456)
            put(w,216,0)
            put(o,QUAR,0)
            put(o,OP,1)
            put(o,CLEAN,0)
            if get(o,LOCK)!=0:
                return quarantine(o,w,2,1)
            return again(o,700)
        if get(w,216)!=0:
            return finish(o,6)
        request(o,QQ,10)
        return queue(o,w,2)
    if phase==2:
        if okay(o,QOUT,QR)==False or get(o,QOUT+8)!=0:
            return fail(o,7,get(o,QOUT+8))
        put(o,LOCK,1)
        return memory(o,3,0,get(w,40),3,QHEAD,176)
    if phase==3:
        if get(o,QHEAD)!=QCTX or get(o,QHEAD+8)!=get(w,208) or get(o,QHEAD+24)<1 or get(o,QHEAD+24)>8:
            return fail(o,7,3)
        put(o,QMAX,get(o,QHEAD+24))
        return memory(o,31,0,get(w,176),3,SUBCAP,8192)
    if phase==31:
        if get(o,SUBCAP)!=SUBCTX or get(o,SUBCAP+8)!=get(w,8) or get(o,SUBCAP+16)!=get(w,16) or get(o,SUBCAP+24)!=get(w,24):
            return fail(o,7,31)
        if get(o,SUBCAP+32)!=get(w,32) or get(o,SUBCAP+40)!=get(w,40) or get(o,SUBCAP+48)!=get(w,48):
            return fail(o,7,31)
        request(o,QQ,5)
        return queue(o,w,4)
    if phase==4:
        if okay(o,QOUT,QR)==False:
            return fail(o,7,get(o,FEEDBACK))
        n=get(o,QOUT+56)
        owned=get(o,QOUT+64)
        flags=get(o,QOUT+120)
        if n>1 or owned!=choose(n==1,1,0) or flags>7:
            put(o,QUAR,2)
            return fail(o,9,4)
        if n==1:
            within(o,ACTIVE_JOB,QOUT+512,24)
        if (flags&4)!=0:
            put(o,JOB_PENDING,1)
        if (flags&2)!=0:
            put(o,QUAR,2)
            return fail(o,9,4)
        if get(o,QOUT+8)!=0:
            return fail(o,choose(get(o,QOUT+8)==5,5,7),get(o,QOUT+8))
        put(o,QCLOSED,get(o,QOUT+24))
        put(o,QPEND,get(o,QOUT+32))
        put(o,QQUEUED,get(o,QOUT+40))
        put(o,QACTIVE,get(o,QOUT+48))
        if get(o,QCLOSED)>1 or get(o,QPEND)>get(o,QMAX) or get(o,QQUEUED)>get(o,QPEND):
            return fail(o,7,4)
        if get(o,QACTIVE)==MAX:
            if n!=0:
                return fail(o,7,4)
            return scalar(o,w,7,0,0,0)
        slot=get(o,QACTIVE)
        if slot>=8 or n!=1 or get(o,ACTIVE_JOB)==0 or get(o,QOUT+512+40)!=slot:
            return fail(o,7,4)
        at=SUBCAP+1024+slot*128
        if get(o,at)==0 or get(o,at+24)==0:
            return fail(o,7,4)
        within(o,META,at+24,24)
        return scalar(o,w,5,4,0,40)
    if phase==5:
        if take_value(o,KEY)==False:
            return value_failure(o)
        request(o,VQ,9)
        within(o,RQ+24,META,24)
        within(o,RQ+48,KEY,24)
        return value(o,w,7,128)
    if phase==7:
        if take_value(o,ACTIVENUM)==False:
            return value_failure(o)
        if get(o,QACTIVE)!=MAX and get(o,RP+16)!=2:
            return fail(o,7,7)
        if get(o,KEY)!=0:
            return drop(o,w,KEY,8)
        return again(o,8)
    if phase==8:
        request(o,LQ,2)
        zero(o,LOUT,8192)
        return invoke(o,9,get(w,56),51,RQ,128,LOUT,8192,get(w,64),get(w,72))
    if phase==9:
        if okay(o,LOUT,LR)==False:
            return fail(o,7,get(o,FEEDBACK))
        n=get(o,LOUT+32)
        if n>72:
            put(o,QUAR,2)
            return fail(o,9,n)
        put(o,NROWS,n)
        within(o,ROWS,LOUT+4096,n*48)
        if get(o,LOUT+8)!=0:
            return fail(o,choose(get(o,LOUT+8)==4,5,7),get(o,LOUT+8))
        recent=get(o,LOUT+16)
        mask=get(o,LOUT+24)
        ordered=get(o,LOUT+64)
        if recent>64 or n!=8+recent or mask>63 or ordered>6:
            return fail(o,7,9)
        put(o,RECENT_COUNT,recent)
        put(o,OUTCOME_MASK,mask)
        put(o,ORDERCOUNT,ordered)
        within(o,ORDER,LOUT+72,ordered*8)
        seen=0
        i=0
        while i<ordered:
            id=get(o,ORDER+i*8)
            if id>=6 or (seen&(1<<id))!=0:
                return fail(o,7,9)
            seen=seen|(1<<id)
            i=i+1
        if seen!=mask:
            return fail(o,7,9)
        i=0
        while i<n:
            at=ROWS+i*48
            if get(o,at)!=choose(i<8,1,2) or get(o,at+8)!=choose(i<8,i,i-8) or get(o,at+16)==0:
                return fail(o,7,9)
            if i<8 and get(o,at+40)==0:
                return fail(o,7,9)
            i=i+1
        request(o,WQ,3)
        return invoke(o,10,get(w,80),51,RQ,128,WOUT,8192,get(w,88),get(w,96))
    if phase==10:
        if okay(o,WOUT,WR)==False or get(o,WOUT+8)!=0 or get(o,WOUT+24)>5:
            return fail(o,7,10)
        state=get(o,WOUT+24)
        put(o,ALIVE,choose(state==1 or state==2,1,0))
        return memory(o,11,0,get(w,192)+512,3,FAILBORROW,24)
    if phase==11:
        put(o,CREATE_INDEX,0)
        return again(o,12)
    if phase==12:
        i=get(o,CREATE_INDEX)
        if i==4:
            return again(o,40)
        request(o,VQ,choose(i==3,3,4))
        return value(o,w,13,128)
    if phase==13:
        if take_value(o,ROOT+get(o,CREATE_INDEX)*24)==False:
            return value_failure(o)
        put(o,CREATE_INDEX,get(o,CREATE_INDEX)+1)
        return again(o,12)
    return fail(o,7,phase)

def failure_copy(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        if get(o,FAILBORROW)==0 and get(o,FAILBORROW+8)==0 and get(o,FAILBORROW+16)==0:
            return scalar(o,w,41,0,0,0)
        request(o,VQ,7)
        within(o,RQ+24,FAILBORROW,24)
        return value(o,w,42,128)
    if phase==41:
        if take_value(o,FAILURE)==False:
            return value_failure(o)
        return again(o,100)
    if phase==42:
        if value_ok(o)==False:
            return value_failure(o)
        if get(o,RP+16)==0:
            request(o,VQ,5)
            within(o,RQ+24,FAILBORROW,24)
            return value(o,w,41,128)
        if get(o,RP+16)!=6:
            return fail(o,7,42)
        request(o,VQ,4)
        return value(o,w,43,128)
    if phase==43:
        if take_value(o,FAILURE)==False:
            return value_failure(o)
        put(o,ENUM_INDEX,0)
        return again(o,44)
    if phase==44:
        request(o,VQ,23)
        within(o,RQ+24,FAILBORROW,24)
        put(o,RQ+104,get(o,ENUM_INDEX))
        put(o,RQ+112,1)
        return value(o,w,45,128)
    if phase==45:
        if value_ok(o)==False:
            return value_failure(o)
        n=get(o,RP+64)
        if n==0:
            return again(o,100)
        if n!=1:
            return fail(o,7,45)
        within(o,EKEY,RP+8192+16,24)
        within(o,EVALUE,RP+8192+40,24)
        if get(o,EKEY)==0 or get(o,EVALUE)==0:
            return fail(o,7,45)
        request(o,VQ,10)
        within(o,RQ+24,FAILURE,24)
        within(o,RQ+48,EKEY,24)
        within(o,RQ+72,EVALUE,24)
        return value(o,w,46,128)
    if phase==46:
        if value_ok(o)==False:
            return value_failure(o)
        return drop(o,w,EKEY,47)
    if phase==47:
        return drop(o,w,EVALUE,48)
    if phase==48:
        put(o,ENUM_INDEX,get(o,ENUM_INDEX)+1)
        return again(o,44)
    return fail(o,7,phase)

def receipts(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        i=get(o,INDEX)
        ordered=get(o,ORDERCOUNT)
        if i==2+ordered+get(o,RECENT_COUNT):
            put(o,INDEX,0)
            return again(o,200)
        row=i
        kind=1
        if i>=2 and i<2+ordered:
            row=2+get(o,ORDER+(i-2)*8)
        elif i>=2+ordered:
            row=8+i-2-ordered
            kind=2
        put(o,ROWINDEX,row)
        put(o,STREAMKIND,kind)
        n=get(o,ROWS+row*48+40)
        if n>MAX-512:
            return fail(o,5,100)
        put(o,ROW_N,n)
        put(o,MAPN,n+512)
        return mapping(o,101,n+512)
    if phase==101:
        p=get(o,FEEDBACK)
        if p==0 or p>=NEGATIVE:
            put(o,MAPN,0)
            return fail(o,5,p)
        put(o,MAP,p)
        kind=get(o,STREAMKIND)
        request(o,choose(kind==1,DQ,BQ),choose(kind==1,8,4))
        within(o,RQ+24,ROWS+get(o,ROWINDEX)*48+16,24)
        if kind==2:
            put(o,RQ+56,get(o,ROW_N))
        at=choose(kind==1,128,152)
        return invoke(o,102,get(w,at),3,RQ,128,p,get(o,MAPN),get(w,at+8),get(w,at+16))
    if phase==102:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,103,0,get(o,MAP),3,SMALL,128)
    if phase==103:
        kind=get(o,STREAMKIND)
        if get(o,SMALL)!=choose(kind==1,DR,BR) or get(o,SMALL+8)!=0 or get(o,SMALL+40)!=get(o,ROW_N):
            return fail(o,7,103)
        if kind==2 and get(o,SMALL+48)!=get(o,ROW_N):
            return fail(o,7,103)
        request(o,VQ,choose(kind==1,2,1))
        put(o,RQ+96,get(o,ROW_N))
        if kind==1:
            put(o,RQ+104,2)
        return memory(o,104,3,RQ,0,get(o,MAP)+384,128)
    if phase==104:
        return invoke(o,105,get(w,8),48,get(o,MAP)+384,128+get(o,ROW_N),RP,16384,get(w,16),get(w,24))
    if phase==105:
        if take_value(o,TEMP)==False:
            return value_failure(o)
        return system(o,106,11,0,get(o,MAP),get(o,MAPN),0,0,0,0)
    if phase==106:
        if get(o,FEEDBACK)!=0:
            put(o,QUAR,1)
            return fail(o,8,get(o,FEEDBACK))
        zero(o,MAP,16)
        if get(o,STREAMKIND)==2:
            request(o,VQ,16)
            within(o,RQ+24,RECENT,24)
            within(o,RQ+48,TEMP,24)
            return value(o,w,108,128)
        row=get(o,ROWINDEX)
        if row<2:
            return field(o,COST,10+row,TEMP,107)
        return field(o,OUTCOMES,30+row-2,TEMP,107)
    if phase==107:
        return drop(o,w,TEMP,109)
    if phase==108:
        if value_ok(o)==False:
            return value_failure(o)
        return drop(o,w,TEMP,109)
    if phase==109:
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,100)
    return fail(o,7,phase)

def fields(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        i=get(o,INDEX)
        if i==14:
            put(o,FINISHED,1)
            return again(o,500)
        if i==0:
            return field(o,COST,12,OUTCOMES,202)
        if i==1:
            return scalar(o,w,201,2,64,0)
        if i==2:
            return field(o,COST,14,RECENT,202)
        if i==3:
            return scalar(o,w,201,4,0,21)
        if i==4:
            return scalar(o,w,201,1,0,0)
        if i==5:
            return scalar(o,w,201,4,0,20)
        if i==6:
            return scalar(o,w,201,1,get(o,QCLOSED),0)
        if i==7:
            return scalar(o,w,201,2,get(o,QMAX),0)
        if i==8:
            return scalar(o,w,201,2,get(o,QPEND),0)
        if i==9:
            return scalar(o,w,201,2,get(o,QQUEUED),0)
        if i==10:
            return field(o,ROOT,5,ACTIVENUM,202)
        if i==11:
            return scalar(o,w,201,1,get(o,ALIVE),0)
        if i==12:
            return field(o,ROOT,7,COST,202)
        return field(o,ROOT,8,FAILURE,202)
    if phase==201:
        if take_value(o,TEMP)==False:
            return value_failure(o)
        i=get(o,INDEX)
        if i<5:
            return field(o,COST,12+i,TEMP,202)
        return field(o,ROOT,i-5,TEMP,202)
    if phase==202:
        if get(o,TEMP)!=0:
            return drop(o,w,TEMP,203)
        return again(o,203)
    if phase==203:
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,200)
    return fail(o,7,phase)

def releasing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,LOCK)!=0:
            request(o,QQ,11)
            return queue(o,w,501)
        if get(o,QUAR)!=0:
            return quarantine(o,w,get(o,QUAR),get(o,DETAIL))
        put(o,CLEAN,0)
        return again(o,700)
    if phase==501:
        if okay(o,QOUT,QR)==False or get(o,QOUT+8)!=0:
            return quarantine(o,w,2,501)
        put(o,LOCK,0)
        return again(o,500)
    return fail(o,7,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return quarantine(o,w,2,700)
        i=get(o,CLEAN)
        if i>=10:
            put(o,CLEAN,0)
            return again(o,720)
        at=ROOT+i*24
        if at==ROOT and get(o,FINISHED)==1 and get(o,ERROR)==0:
            put(o,CLEAN,i+1)
            return again(o,700)
        if get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,700)
        put(o,CLEAN_AT,at)
        release_begin(o)
        request(o,VALUE_DROP_INPUT,29)
        within(o,RQ+24,at,24)
        return value(o,w,701,128)
    if phase==701:
        if release_value(o,get(o,CLEAN_AT))==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),get(o,RP+8))
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,700)
    if phase==720:
        i=get(o,CLEAN)
        if i>=get(o,NROWS):
            return again(o,740)
        at=ROWS+i*48
        if get(o,at+16)==0:
            put(o,CLEAN,i+1)
            return again(o,720)
        kind=get(o,at)
        if kind!=1 and kind!=2:
            return quarantine(o,w,2,720)
        put(o,CLEAN_AT,at)
        put(o,CLEAN_KIND,kind)
        request(o,choose(kind==1,DQ,BQ),3)
        within(o,RQ+24,at+16,24)
        slot=choose(kind==1,128,152)
        return invoke(o,721,get(w,slot),51,RQ,128,RP,16384,get(w,slot+8),get(w,slot+16))
    if phase==721:
        if okay(o,RP,choose(get(o,CLEAN_KIND)==1,DR,BR))==False:
            return quarantine(o,w,2,get(o,FEEDBACK))
        status=get(o,RP+8)
        if status!=0:
            return quarantine(o,w,choose(status==1 or status==5 or status==6,1,2),status)
        zero(o,get(o,CLEAN_AT),48)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,720)
    if phase==740:
        if get(o,ACTIVE_JOB)==0:
            return again(o,750)
        release_begin(o)
        request(o,JOB_DROP_INPUT,11)
        within(o,RQ+24,ACTIVE_JOB,24)
        return invoke(o,741,get(w,104),51,RQ,128,RP,16384,get(w,112),get(w,120))
    if phase==741:
        if release_job(o,ACTIVE_JOB)==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),get(o,RP+8))
        return again(o,750)
    if phase==750:
        if get(o,MAP)==0:
            return again(o,760)
        return system(o,751,11,0,get(o,MAP),get(o,MAPN),0,0,0,0)
    if phase==751:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,1,get(o,FEEDBACK))
        zero(o,MAP,16)
        return again(o,760)
    if phase==760:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_DROP_INPUT,12)
            return invoke(o,761,get(w,104),51,RQ,128,RP,16384,get(w,112),get(w,120))
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return value(o,w,762,128)
        return finish(o,get(o,ERROR))
    if phase==761:
        if release_job_retry(o)==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),get(o,RP+8))
        return again(o,760)
    if phase==762:
        if release_value_retry(o)==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),get(o,RP+8))
        return again(o,760)
    return quarantine(o,w,2,phase)

def mutation(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        return scalar(o,w,1001,4,0,get(o,GKEYID))
    if phase==1001:
        if take_value(o,KEY)==False:
            return value_failure(o)
        request(o,VQ,10)
        within(o,RQ+24,get(o,GDICT),24)
        within(o,RQ+48,KEY,24)
        within(o,RQ+72,get(o,GVALUE),24)
        return value(o,w,1002,128)
    if phase==1002:
        if value_ok(o)==False:
            return value_failure(o)
        return drop(o,w,KEY,get(o,GAFTER))
    if phase==1100:
        if release_value(o,get(o,DROP_AT))==0:
            put(o,QUAR,choose(get(o,DROP_KNOWN)==1,1,2))
            return fail(o,7,get(o,RP+8))
        return again(o,get(o,DROP_AFTER))
    return fail(o,7,phase)

def field(o:mutbuf,dict:u64,key:u64,val:u64,next:u64) -> u32:
    put(o,GDICT,dict)
    put(o,GKEYID,key)
    put(o,GVALUE,val)
    put(o,GAFTER,next)
    return again(o,1000)
def drop(o:mutbuf,w:mutbuf,at:u64,next:u64) -> u32:
    put(o,DROP_AT,at)
    put(o,DROP_AFTER,next)
    release_begin(o)
    request(o,VALUE_DROP_INPUT,29)
    within(o,RQ+24,at,24)
    return value(o,w,1100,128)
def scalar(o:mutbuf,w:mutbuf,next:u64,kind:u64,number:u64,id:u64) -> u32:
    request(o,VQ,2)
    put(o,RQ+104,kind)
    n=0
    if kind==1:
        put(o,RQ+112,number)
    elif kind==2:
        n=decimal(o,RQ+128,number)
    elif kind==4:
        n=literal(o,RQ+128,id)
    put(o,RQ+96,n)
    return value(o,w,next,128+n)
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,16384,get(w,16),get(w,24))
def queue(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,32),51,RQ,128,QOUT,4096,get(w,40),get(w,48))
def okay(o:mutbuf,at:u64,magic:u64) -> bool:
    return get(o,FEEDBACK)==0 and get(o,at)==magic
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(okay(o,at,magic),1,0)
def value_ok(o:mutbuf) -> bool:
    return okay(o,RP,VR) and get(o,RP+8)==0
def take_value(o:mutbuf,at:u64) -> bool:
    if value_ok(o)==False or get(o,RP+24)==0:
        return False
    within(o,at,RP+24,24)
    return True
def value_failure(o:mutbuf) -> u32:
    if okay(o,RP,VR)==False:
        return fail(o,7,get(o,FEEDBACK))
    return fail(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,500)
def quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,256,256,3840)
    to_work(o,w,ROWS,4096,3456)
    put(w,216,kind)
    return finish(o,9)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0 and get(o,FINISHED)==1:
        put(o,16,1)
        within(o,24,ROOT,24)
        zero(o,ROOT,24)
    put(o,48,get(o,QUAR))
    put(o,56,get(o,DETAIL))
    return 0
def decimal(o:mutbuf,at:u64,value:u64) -> u64:
    n=0
    while value!=0 or n==0:
        store(o,SMALL+n,48+value%10)
        value=value//10
        n=n+1
    i=0
    while i<n:
        store(o,at+i,byte(o,SMALL+n-i-1))
        i=i+1
    return n
"""
LABELS={0:'schema',1:'closed',2:'max_pending',3:'outstanding',4:'queued',5:'active_job',6:'worker_alive',7:'cost_accounting',8:'worker_failure',
10:'settled_jobs',11:'observed_submit_and_worker_ns',12:'execution_outcomes_at_accounting',13:'recent_limit',14:'recent_jobs',15:'scope',16:'supplied_prior_search_summed_again',
20:'hepta.hia.background-optimization.v1',21:'submission plus worker elapsed before settlement; queue wait separate; outer lifecycle excluded',
30:'published',31:'abstained',32:'stale',33:'rejected',34:'cancelled',35:'interrupted',40:'job'}
def source_program(symbolic=False):
    names={'mapping','request','invoke','memory','system','again','to_work','from_work','within','zero','get','put','choose'}
    helpers='\n'.join(ast.unparse(f)for f in ast.parse(BASE).body if isinstance(f,ast.FunctionDef)and f.name in names)
    s=SOURCE+'\n'+R.selected('release_begin','release_value','release_job','release_job_retry','release_value_retry')+'\n'+helpers+'\ndef literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
    for id,label in sorted(LABELS.items()):
        raw=label.encode();s+=f'    if id=={id}:\n'
        for i in range(0,len(raw),8):s+=f'        put(o,at+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        s+=f'        return {len(raw)}\n'
    s+='    return 0\n'
    if not symbolic:
     for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
    return s
def program():return document(source_program(),'background_optimizer_snapshot')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_snapshot.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
