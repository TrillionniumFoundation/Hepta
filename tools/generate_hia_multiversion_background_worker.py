from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'INPUT3':int.from_bytes(b'HIABGW03','little'),'INPUT2':int.from_bytes(b'HIABGW02','little'),'QUEUE_INPUT3':int.from_bytes(b'HIABGQ03','little'),'HANDLER_INPUT2':int.from_bytes(b'HIABGWQ2','little'),'TAKE_SEC':360,'TAKE_NS':368,'TAKE_ERROR':376,'TAKE_VALID':384,'INPUT': 3544428870306449736, 'OUTPUT': 3553154594584480072, 'STATE_MAGIC': 3554280494491322696, 'QUEUE_INPUT': 3544422273236683080, 'QUEUE_REPLY': 3553992422444845384, 'HANDLER_INPUT': 3553717544537901384, 'HANDLER_REPLY': 3553999019514612040, 'NONE': 18446744073709551615, 'NEGATIVE': 18446744073709547521, 'PHASE': 128, 'OP': 136, 'NEXT': 144, 'ERR': 256, 'VALUE': 264, 'STATE': 272, 'TID': 280, 'TERMINAL': 288, 'JOINING': 296, 'CALLER': 304, 'JNI': 312, 'FAIL_PHASE': 328, 'FAIL_CODE': 336, 'ACTIVE': 344, 'SYSRET': 448, 'RQ': 1024, 'RP': 1280, 'JREF': 1792, 'QRP': 2048}
SOURCE=r'''
def worker(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<8192 or length(w)<512:
        return 4294967293
    magic=readword(s,0)
    if magic!=INPUT and magic!=INPUT2 and magic!=INPUT3:
        return 4294967293
    if readword(s,8)>5 or (magic==INPUT2 and readword(s,8)!=0) or (magic==INPUT3 and readword(s,8)!=3) or valid(s)==0:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        zero(o,128,384)
        put(o,OP,readword(s,8))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        pid=get(o,SYSRET)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,65)
        if get(o,OP)==0:
            if get(w,0)!=0 or readword(s,16)==0 or readword(s,24)==0 or readword(s,32)<4096 or readword(s,40)==0:
                return finish(o,4)
            zero(w,0,512)
            put(w,0,STATE_MAGIC)
            put(w,8,pid)
            put(w,64,readword(s,16))
            put(w,72,readword(s,24))
            put(w,80,readword(s,32))
            put(w,88,readword(s,40))
            put(w,96,readword(s,48))
            put(w,104,readword(s,56))
            if magic==INPUT2:
                put(w,112,1)
            save(o,w)
            return finish(o,0)
        if get(w,0)!=STATE_MAGIC or get(w,8)!=pid:
            return finish(o,65)
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        if get(o,SYSRET)==0 or get(o,SYSRET)>=NEGATIVE:
            return finish(o,65)
        put(o,CALLER,get(o,SYSRET))
        return lock(o,100)
    if phase>=20 and phase<=23:
        return lock_phase(o,phase)
    if phase==100:
        if get(w,152)!=0:
            return release(o,w,65)
        op=get(o,OP)
        if op==1:
            if get(w,24)!=0:
                return release(o,w,4)
            put(w,24,1)
            put(o,PHASE,101)
            return 6
        if op==2 or (op==3 and magic==INPUT3 and get(w,24)==3):
            if get(w,24)==0 or get(w,24)==5:
                return release(o,w,4)
            if get(w,24)==4:
                return release(o,w,0)
            if get(w,32)==get(o,CALLER) and get(w,32)!=0:
                put(o,VALUE,1)
                return release(o,w,0)
            if get(w,48)!=0:
                return unlock(o,170)
            put(w,48,1)
            put(w,132,0)
            return unlock(o,180)
        if op==3:
            return release(o,w,0)
        if op==4:
            if get(w,24)!=1 or get(w,32)!=0:
                return release(o,w,4)
            put(w,32,get(o,CALLER))
            put(w,24,2)
            return unlock(o,500)
        if op==5:
            if get(w,24)!=0 and get(w,24)!=4 and get(w,24)!=5:
                return release(o,w,4)
            if get(w,48)!=0:
                return release(o,w,4)
            put(w,152,1)
            return release(o,w,0)
        return release(o,w,4)
    if phase==101:
        raw=get(o,SYSRET)
        if raw!=0:
            put(w,24,5)
            put(o,VALUE,raw)
            return release(o,w,6)
        return release(o,w,0)
    if phase==170:
        return system(o,171,202,1,132,128,0,0,0,0)
    if phase==171:
        raw=get(o,SYSRET)
        if raw!=0 and raw!=NONE-3 and raw!=NONE-10:
            put(o,ERR,65)
            return lock(o,190)
        return lock(o,100)
    if phase==180:
        put(o,PHASE,181)
        return 7
    if phase==181:
        put(o,JNI,get(o,SYSRET))
        return lock(o,182)
    if phase==182:
        put(w,48,0)
        status=0
        if get(o,JNI)==0:
            put(w,24,4)
        else:
            status=6
            put(o,VALUE,get(o,JNI))
        put(o,ERR,status)
        put(w,132,1)
        return system(o,190,202,1,132,129,2147483647,0,0,0)
    if phase==190:
        return release(o,w,get(o,ERR))
    if phase==500:
        return queue_call(o,w,501,7)
    if phase==501:
        if queue_ok(o)==0:
            return failed(o,501)
        return queue_call(o,w,502,2)
    if phase==502:
        if get(w,112)!=0 and get(o,SYSRET)==0 and get(o,QRP)==QUEUE_REPLY and get(o,QRP+56)==1 and get(o,QRP+64)==0:
            copy_within(o,QRP+512,JREF,64)
            put(o,ACTIVE,1)
            put(o,TAKE_SEC,get(o,QRP+88))
            put(o,TAKE_NS,get(o,QRP+96))
            put(o,TAKE_ERROR,get(o,QRP+104))
            put(o,TAKE_VALID,get(o,QRP+112))
        if queue_ok(o)==0:
            return failed(o,502)
        if get(o,QRP+16)==NONE:
            return queue_call(o,w,550,8)
        if get(o,QRP+56)!=1 or get(o,QRP+64)!=0:
            return failed(o,502)
        if get(w,112)!=0 and (get(o,TAKE_VALID)!=1 or get(o,TAKE_ERROR)!=0 or get(o,TAKE_NS)>=1000000000):
            return failed(o,502)
        copy_within(o,QRP+512,JREF,64)
        put(o,ACTIVE,1)
        return handler(o,w,503,1)
    if phase==503:
        if get(o,SYSRET)!=0 or get(o,RP)!=HANDLER_REPLY or get(o,RP+8)>1:
            return failed(o,503)
        if get(o,RP+8)==1:
            return queue_call(o,w,550,8)
        put(o,ACTIVE,0)
        return queue_call(o,w,502,2)
    if phase==530:
        return handler(o,w,531,2)
    if phase==531:
        put(o,ERR,65)
        return queue_call(o,w,550,8)
    if phase==550:
        if queue_ok(o)==0:
            put(o,ERR,65)
        return lock(o,551)
    if phase==551:
        put(w,40,get(o,ERR))
        put(w,24,3)
        return release(o,w,get(o,ERR))
    if phase==900:
        return finish(o,get(o,ERR))
    return finish(o,65)

def failed(o:mutbuf,phase:u64) -> u32:
    put(o,FAIL_PHASE,phase)
    put(o,FAIL_CODE,get(o,SYSRET))
    return again(o,530)
def queue_ok(o:mutbuf) -> u64:
    return choose(get(o,SYSRET)==0 and get(o,QRP)==QUEUE_REPLY and get(o,QRP+8)==0,1,0)
def queue_call(o:mutbuf,w:mutbuf,next:u64,op:u64) -> u32:
    zero(o,RQ,128)
    put(o,RQ,QUEUE_INPUT)
    if op==2 and get(w,112)!=0:
        put(o,RQ,QUEUE_INPUT3)
        put(o,TAKE_SEC,0)
        put(o,TAKE_NS,0)
        put(o,TAKE_ERROR,0)
        put(o,TAKE_VALID,0)
    put(o,RQ+8,op)
    zero(o,QRP,128)
    return invoke(o,next,get(w,64),RQ,128,QRP,4096,get(w,72),get(w,80))
def handler(o:mutbuf,w:mutbuf,next:u64,op:u64) -> u32:
    zero(o,RQ,128)
    put(o,RQ,HANDLER_INPUT)
    if get(w,112)!=0:
        put(o,RQ,HANDLER_INPUT2)
        put(o,RQ+80,get(o,TAKE_SEC))
        put(o,RQ+88,get(o,TAKE_NS))
        put(o,RQ+96,get(o,TAKE_ERROR))
        put(o,RQ+104,get(o,TAKE_VALID))
    put(o,RQ+8,op)
    if get(o,ACTIVE)!=0:
        copy_within(o,JREF,RQ+16,48)
    put(o,RQ+64,get(o,FAIL_PHASE))
    put(o,RQ+72,get(o,FAIL_CODE))
    zero(o,RP,128)
    return invoke(o,next,get(w,88),RQ,128,RP,128,get(w,96),get(w,104))
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
    return 4
def valid(s:readbuf) -> u64:
    op=readword(s,8)
    at=16
    while at<128:
        used=choose(op==0 and at<=56,1,0)
        if used==0 and readword(s,at)!=0:
            return 0
        at=at+8
    return 1
def save(o:mutbuf,w:mutbuf) -> u64:
    put(o,STATE,get(w,24))
    put(o,TID,get(w,32))
    put(o,TERMINAL,get(w,40))
    put(o,JOINING,get(w,48))
    return 0
def release(o:mutbuf,w:mutbuf,status:u64) -> u32:
    put(o,ERR,status)
    save(o,w)
    return unlock(o,900)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,OUTPUT)
    put(o,8,status)
    put(o,16,get(o,VALUE))
    put(o,24,get(o,STATE))
    put(o,32,get(o,TID))
    put(o,40,get(o,TERMINAL))
    put(o,48,get(o,JOINING))
    return 0
def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PHASE,20)
    put(o,0,128)
    put(o,8,0)
    put(o,16,1)
    return 2
def unlock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PHASE,22)
    put(o,0,128)
    put(o,8,0)
    return 3
def lock_phase(o:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(o,SYSRET)==0:
            return again(o,get(o,NEXT))
        return system(o,21,202,1,128,128,1,0,0,0)
    if phase==21:
        if get(o,SYSRET)!=0 and get(o,SYSRET)!=NONE-3 and get(o,SYSRET)!=NONE-10:
            return finish(o,65)
        return lock(o,get(o,NEXT))
    if phase==22:
        return system(o,23,202,1,128,129,1,0,0,0)
    return again(o,get(o,NEXT))
def system(o:mutbuf,next:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,number)
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
def choose(c:bool,a:u64,b:u64) -> u64:
    if c:return a
    return b
def readword(s:readbuf,at:u64) -> u64:
    return word_load(s,at)
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
def copy_within(w:mutbuf,at:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,dest+i,byte(w,at+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    result=document(source_program(),'multiversion_background_worker')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_worker.hepta'
    p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),flush=True)
if __name__=='__main__':main()
