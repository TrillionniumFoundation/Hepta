"""Actual value -> lossless native stream -> capture -> checked freezer -> payload."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIABFZQ1','little'),'REPLY':int.from_bytes(b'HIABFZR1','little'),
'CONTEXT':int.from_bytes(b'HIABFZC1','little'),'IO_REQUEST':int.from_bytes(b'HIABIQ01','little'),
'IO_REPLY':int.from_bytes(b'HIABIO01','little'),'IO_CONTEXT':int.from_bytes(b'HIABIC01','little'),
'FREEZE_REQUEST':int.from_bytes(b'HIABJF01','little'),'FREEZE_REPLY':int.from_bytes(b'HIABJR01','little'),
'PAYLOAD_REQUEST':int.from_bytes(b'HIABPY01','little'),'PAYLOAD_REPLY':int.from_bytes(b'HIABPYR1','little'),
'SIZES':int.from_bytes(b'HIANJS01','little'),'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'CAP':160,'FD':184,'RAW':192,'RAWN':200,
'FRAME':208,'FRAMEN':216,'ARENAN':224,'WORK':232,'WORKN':240,'EMIT':248,'EMITN':256,
'FROZEN':264,'ARENACAP':272,'NODES':280,'KEYS':288,'DEPTH':296,'STATWORK':304,'ERRN':312,
'QUARANTINED':320,'CLEAN':328,'SAVED':336,'PID':344,'UCHAR':352,'USTART':360,'UEND':368,'UCP':376,'FEEDBACK':448,
'ST':512,'SW':768,'RQ':1024,'IOC':2048,'RP':4096,'ERR':8192,'IOO':65536,'OUT':262144}
C.update({'MODERN':384,'QUARANTINE_KIND':392,'VALUE_PENDING':400})
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {'NEW_MAGIC':'HIABFZQ2','NEW_REPLY':'HIABFZR2','NEW_CONTEXT':'HIABFZC2','NEW_IO_REQUEST':'HIABIQ02','NEW_IO_REPLY':'HIABIO02','NEW_IO_CONTEXT':'HIABIC02'}.items()})
SOURCE=r'''
def freeze_value(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<2048:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return capture_stream(s,o,w,phase)
    if phase<200:
        return capture_arena(s,o,w,phase)
    if phase<300:
        return freezing(s,o,w,phase)
    if phase<400:
        return publishing(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or (word_load(s,0)!=MAGIC and word_load(s,0)!=NEW_MAGIC) or word_load(s,8)>1:
        return 4294967293
    at=16
    while at<128:
        used=word_load(s,8)==0 and at>=24 and at<=40
        if used==False and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    modern=word_load(s,0)==NEW_MAGIC
    if get(w,0)!=choose(modern,NEW_CONTEXT,CONTEXT) or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)==0 or get(w,64)==0 or get(w,72)<256:
        return 4294967293
    if (get(w,80)!=0 and get(w,80)<640) or get(w,80)>2147483647 or get(w,96)>1:
        return 4294967293
    if get(w,120)!=0:
        return 4294967293
    if (modern==False and (get(w,104)!=0 or get(w,112)!=0)) or (modern and (get(w,104)>2 or get(w,112)>1)):
        return 4294967293
    zero(o,128,16256)
    put(o,MODERN,choose(modern,1,0))
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def capture_stream(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,88)!=0 and get(w,88)!=pid):
            return finish(o,6)
        put(o,PID,pid)
        put(w,88,pid)
        if get(o,OP)==1:
            if get(w,96)==0:
                return finish(o,0)
            from_work(w,o,128,128,320)
            from_work(w,o,512,IOC,256)
            from_work(w,o,768,ERR,896)
            put(w,96,0)
            put(o,QUARANTINED,0)
            put(o,OP,1)
            put(o,CLEAN,0)
            if get(o,MODERN)!=0:
                zero(w,104,16)
                if get(o,QUARANTINE_KIND)==2:
                    return quarantine(o,w,get(o,DETAIL))
                put(o,QUARANTINE_KIND,0)
            return again(o,700)
        if get(w,96)!=0:
            return finish(o,6)
        zero(o,IOC,256)
        put(o,IOC,choose(get(o,MODERN)!=0,NEW_IO_CONTEXT,IO_CONTEXT))
        put(o,IOC+8,get(w,8))
        put(o,IOC+16,get(w,16))
        put(o,IOC+24,get(w,24))
        request(o,choose(get(o,MODERN)!=0,NEW_IO_REQUEST,IO_REQUEST),0)
        copy_source(s,o,24,RQ+24,24)
        return invoke(o,2,get(w,32),819,RQ,128,IOO,131072,IOC,256)
    if phase==2:
        if get(o,MODERN)!=0:
            if io_response(o)==0:
                if get(o,ERROR)==0:
                    put(o,ERROR,9)
                return quarantine(o,w,get(o,FEEDBACK))
        if get(o,FEEDBACK)!=0 or get(o,IOO)!=choose(get(o,MODERN)!=0,NEW_IO_REPLY,IO_REPLY):
            return fail(o,7,get(o,FEEDBACK))
        if get(o,IOO+8)!=0:
            status=get(o,IOO+8)
            code=7
            if status==5 or (status==7 and get(o,IOO+40)==5):
                code=5
            elif status==8:
                code=8
            put(o,ERROR,code)
            put(o,DETAIL,get(o,IOO+40))
            return again(o,700)
        if get(o,IOO+16)==MAX or get(o,IOO+32)!=15 or get(o,IOO+24)==0:
            return fail(o,9,2)
        put(o,FD,get(o,IOO+16)+1)
        put(o,RAWN,get(o,IOO+24))
        return system(o,3,9,0,0,get(o,RAWN),1,2,get(o,FD)-1,0)
    if phase==3:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,RAW,raw)
        zero(o,SW,128)
        return invoke(o,4,get(w,40),816,get(o,RAW),get(o,RAWN),ST,64,SW,128)
    if phase==4:
        if get(o,FEEDBACK)!=0 or get(o,ST)!=SIZES or get(o,ST+48)!=get(o,RAWN):
            return fail(o,7,get(o,FEEDBACK))
        put(o,NODES,get(o,ST+8))
        put(o,KEYS,get(o,ST+16))
        put(o,DEPTH,get(o,ST+24))
        put(o,ARENACAP,get(o,ST+32))
        wn=get(o,ST+40)
        if get(o,ARENACAP)>MAX-16384 or get(o,RAWN)>MAX-128:
            return fail(o,5,0)
        if get(o,ARENACAP)>MAX-128-get(o,RAWN):
            return fail(o,5,0)
        if wn<get(o,ARENACAP)+16384:
            wn=get(o,ARENACAP)+16384
        if wn<131072:
            wn=131072
        put(o,WORKN,wn)
        put(o,FRAMEN,128+get(o,RAWN)+get(o,ARENACAP))
        return mapping(o,100,get(o,FRAMEN))
    return fail(o,9,phase)

def capture_arena(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,FRAME,raw)
        return memory(o,101,0,get(o,RAW),0,raw+128,get(o,RAWN))
    if phase==101:
        return mapping(o,102,get(o,WORKN))
    if phase==102:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,WORK,raw)
        zero(o,SW,128)
        put(o,SW+48,get(o,NODES))
        put(o,SW+56,get(o,DEPTH))
        put(o,SW+96,get(o,KEYS))
        put(o,SW+104,1)
        return memory(o,103,3,SW,0,get(o,WORK),128)
    if phase==103:
        return invoke(o,104,get(w,40),0,get(o,RAW),get(o,RAWN),get(o,FRAME)+128+get(o,RAWN),get(o,ARENACAP),get(o,WORK),get(o,WORKN))
    if phase==104:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,105,0,get(o,FRAME)+128+get(o,RAWN),3,ST,64)
    if phase==105:
        n=get(o,ST+24)
        if n<64 or n>get(o,ARENACAP) or get(o,ST+8)!=get(o,NODES):
            return fail(o,9,105)
        put(o,ARENAN,n)
        request(o,FREEZE_REQUEST,0)
        put(o,RQ+24,get(o,RAWN))
        put(o,RQ+32,n)
        put(o,RQ+40,get(w,80))
        return memory(o,200,3,RQ,0,get(o,FRAME),128)
    return fail(o,9,phase)

def freezing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        return invoke(o,201,get(w,48),48,get(o,FRAME),128+get(o,RAWN)+get(o,ARENAN),RP,1024,get(o,WORK),get(o,WORKN))
    if phase==201:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=FREEZE_REPLY:
            return fail(o,7,get(o,FEEDBACK))
        status=get(o,RP+8)
        if status==1:
            n=get(o,RP+32)
            if n>896:
                return fail(o,9,n)
            put(o,ERRN,n)
            put(o,UCHAR,get(o,RP+40))
            put(o,USTART,get(o,RP+48))
            put(o,UEND,get(o,RP+56))
            put(o,UCP,get(o,RP+64))
            within(o,ERR,RP+128,n)
            return fail(o,1,get(o,RP+16))
        if status!=0 or get(o,RP+24)>MAX-128:
            return fail(o,9,status)
        put(o,FROZEN,get(o,RP+24))
        put(o,EMITN,128+get(o,FROZEN))
        return mapping(o,202,get(o,EMITN))
    if phase==202:
        raw=get(o,FEEDBACK)
        if raw==0 or raw>=NEGATIVE:
            return fail(o,5,raw)
        put(o,EMIT,raw)
        put(o,ST,1)
        return memory(o,203,3,ST,0,get(o,FRAME)+8,8)
    if phase==203:
        return invoke(o,204,get(w,48),0,get(o,FRAME),128+get(o,RAWN)+get(o,ARENAN),get(o,EMIT),get(o,EMITN),get(o,WORK),get(o,WORKN))
    if phase==204:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,205,0,get(o,EMIT),3,ST,64)
    if phase==205:
        if get(o,ST)!=FREEZE_REPLY or get(o,ST+8)!=0 or get(o,ST+24)!=get(o,FROZEN):
            return fail(o,9,205)
        request(o,PAYLOAD_REQUEST,1)
        put(o,RQ+72,get(o,FROZEN))
        return memory(o,300,3,RQ,0,get(o,EMIT),128)
    return fail(o,9,phase)

def publishing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return invoke(o,301,get(w,56),48,get(o,EMIT),get(o,EMITN),RP,512,get(w,64),get(w,72))
    if phase==301:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY:
            return fail(o,7,get(o,FEEDBACK))
        if get(o,RP+8)!=0:
            return fail(o,choose(get(o,RP+8)==4,5,7),get(o,RP+8))
        within(o,CAP,RP+16,24)
        if get(o,CAP)==0 or get(o,RP+40)!=get(o,FROZEN):
            return fail(o,9,301)
        return again(o,700)
    return fail(o,9,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        retained=get(o,IOC+32)!=0 or get(o,IOC+40)!=0 or get(o,IOC+64)!=0
        if get(o,MODERN)!=0 and (get(o,IOC+88)!=0 or get(o,IOC+96)!=0 or get(o,IOC+104)!=0):
            retained=True
        if retained:
            request(o,choose(get(o,MODERN)!=0,NEW_IO_REQUEST,IO_REQUEST),1)
            return invoke(o,701,get(w,32),819,RQ,128,IOO,131072,IOC,256)
        if get(o,ERROR)!=0 and get(o,CAP)!=0:
            request(o,PAYLOAD_REQUEST,3)
            within(o,RQ+24,CAP,24)
            return invoke(o,702,get(w,56),51,RQ,128,RP,512,get(w,64),get(w,72))
        return again(o,710)
    if phase==701:
        if get(o,MODERN)!=0:
            if io_response(o)==0:
                return quarantine(o,w,get(o,FEEDBACK))
            put(o,VALUE_PENDING,0)
            put(o,QUARANTINE_KIND,0)
        if get(o,FEEDBACK)!=0 or get(o,IOO)!=choose(get(o,MODERN)!=0,NEW_IO_REPLY,IO_REPLY) or get(o,IOO+48)!=0 or get(o,IOC+32)!=0 or get(o,IOC+40)!=0 or get(o,IOC+64)!=0:
            return quarantine(o,w,get(o,FEEDBACK))
        return again(o,700)
    if phase==702:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY or get(o,RP+8)!=0:
            if get(o,MODERN)!=0:
                known=get(o,FEEDBACK)==0 and get(o,RP)==PAYLOAD_REPLY
                status=get(o,RP+8)
                retryable=known and (status==1 or status==5 or status==6)
                put(o,QUARANTINE_KIND,choose(retryable,1,2))
            return quarantine(o,w,get(o,RP+8))
        zero(o,CAP,24)
        return again(o,700)
    if phase==710:
        at=EMIT
        if get(o,CLEAN)==1:
            at=WORK
        if get(o,CLEAN)==2:
            at=FRAME
        if get(o,CLEAN)==3:
            at=RAW
        if get(o,CLEAN)>=4:
            return again(o,720)
        if get(o,at)==0:
            put(o,CLEAN,get(o,CLEAN)+1)
            return again(o,710)
        put(o,SAVED,at)
        return system(o,711,11,0,get(o,at),get(o,at+8),0,0,0,0)
    if phase==711:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,get(o,FEEDBACK))
        zero(o,get(o,SAVED),16)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,710)
    if phase==720:
        if get(o,FD)!=0:
            fd=get(o,FD)-1
            if get(o,MODERN)!=0:
                return system(o,721,436,0,fd,fd,0,0,0,0)
            put(o,FD,0)
            return system(o,721,3,0,fd,0,0,0,0,0)
        return finish(o,get(o,ERROR))
    if phase==721:
        if get(o,MODERN)!=0:
            if get(o,FEEDBACK)!=0:
                put(o,QUARANTINE_KIND,1)
                return quarantine(o,w,get(o,FEEDBACK))
            put(o,FD,0)
            return finish(o,get(o,ERROR))
        if get(o,FEEDBACK)!=0:
            put(o,ERROR,8)
            put(o,DETAIL,get(o,FEEDBACK))
            return again(o,700)
        return finish(o,get(o,ERROR))
    return fail(o,9,phase)

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,DETAIL,detail)
    if get(o,MODERN)!=0:
        if get(o,QUARANTINE_KIND)==0:
            put(o,QUARANTINE_KIND,1)
        put(w,104,get(o,QUARANTINE_KIND))
        put(w,112,get(o,VALUE_PENDING))
    to_work(o,w,128,128,320)
    to_work(o,w,IOC,512,256)
    to_work(o,w,ERR,768,896)
    put(w,96,1)
    put(o,QUARANTINED,1)
    return finish(o,9)

def io_response(o:mutbuf) -> u64:
    put(o,QUARANTINE_KIND,2)
    if get(o,FEEDBACK)!=0 or get(o,IOO)!=NEW_IO_REPLY or get(o,IOO+48)>1 or get(o,IOO+56)>2 or get(o,IOO+64)>1:
        return 0
    retained=get(o,IOO+48)
    kind=get(o,IOO+56)
    pending=get(o,IOO+64)
    if retained==0:
        if kind!=0 or pending!=0 or get(o,IOC+32)!=0 or get(o,IOC+40)!=0 or get(o,IOC+64)!=0:
            return 0
        if get(o,IOC+88)!=0 or get(o,IOC+96)!=0 or get(o,IOC+104)!=0:
            return 0
        put(o,QUARANTINE_KIND,0)
        put(o,VALUE_PENDING,0)
        return 1
    if kind==0:
        return 0
    put(o,QUARANTINE_KIND,kind)
    put(o,VALUE_PENDING,pending)
    return 0

def mapping(o:mutbuf,next:u64,n:u64) -> u32:
    return system(o,next,9,0,0,n,3,34,MAX,0)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def invoke(o:mutbuf,next:u64,fn:u64,mask:u64,s:u64,sn:u64,d:u64,dn:u64,w:u64,wn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,mask)
    put(o,16,s)
    put(o,24,sn)
    put(o,32,d)
    put(o,40,dn)
    put(o,48,w)
    put(o,56,wn)
    return 9
def memory(o:mutbuf,next:u64,a:u64,at:u64,b:u64,bt:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,at)
    put(o,16,b)
    put(o,24,bt)
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
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    put(o,CLEAN,0)
    return again(o,700)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,choose(get(o,MODERN)!=0,NEW_REPLY,REPLY))
    put(o,8,status)
    if status==0:
        within(o,16,CAP,24)
        put(o,40,get(o,FROZEN))
        zero(o,CAP,24)
    put(o,56,get(o,QUARANTINED))
    put(o,64,get(o,DETAIL))
    if get(o,MODERN)!=0 and get(o,QUARANTINED)!=0:
        put(o,104,get(o,QUARANTINE_KIND))
        put(o,112,get(o,VALUE_PENDING))
    if status==1:
        n=get(o,ERRN)
        put(o,48,n)
        put(o,72,get(o,UCHAR))
        put(o,80,get(o,USTART))
        put(o,88,get(o,UEND))
        put(o,96,get(o,UCP))
        within(o,128,ERR,n)
    return 0
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10
def to_work(o:mutbuf,w:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(o,at+i))
        i=i+1
    return 0
def from_work(w:mutbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(w,at+i))
        i=i+1
    return 0
def copy_source(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
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
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(n>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def main():
 d=document(source_program(),'background_optimizer_value_freeze')
 p=ROOT/'examples/hia_bootstrap/background_optimizer_value_freeze.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
