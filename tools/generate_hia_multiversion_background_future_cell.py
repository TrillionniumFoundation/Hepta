"""Owned independent Future cells and shared-value ResultBoxes.

The policy owns context tokens, independent nonce handles and in-flight pins.
Its only effects are the captured Future/value owners and fixed mechanical
allocation, copies, futexes and system calls. This is not the BG decision owner.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={
'MAGIC':int.from_bytes(b'HIABFQ01','little'),'MAGIC2':int.from_bytes(b'HIABFQ02','little'),'MAGIC3':int.from_bytes(b'HIABFQ03','little'),'REPLY':int.from_bytes(b'HIABFR01','little'),
'STATE':int.from_bytes(b'HIABFS01','little'),'OBJECT':int.from_bytes(b'HIABFO01','little'),
'NMAGIC':int.from_bytes(b'HIABFN01','little'),'PMAGIC':int.from_bytes(b'HIABFA01','little'),
'BOXMAGIC':int.from_bytes(b'HIABFB01','little'),'FREQUEST':int.from_bytes(b'HIAMVFQ1','little'),
'FREPLY':int.from_bytes(b'HIAMVFR1','little'),'FREQUEST2':int.from_bytes(b'HIAMVFQ2','little'),'VREQUEST':int.from_bytes(b'HIABVQ01','little'),
'VREPLY':int.from_bytes(b'HIABVR01','little'),'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'PHASE':128,'OP':136,'HELD':144,'ERROR':152,'AFTER':160,'PID':168,'OBJ':176,'CAP':184,
'CURSOR':192,'NEWOBJ':200,'NEWREF':208,'RESULT':216,'TAG0':224,'TAG1':232,'RANDOM_USED':240,
'ACTIVE':248,'PINPTR':256,'NEXT':264,'NEWBOX':272,'RETAINED_VALUE':280,'VALUE_RESULT':304,
'VALUE_KIND':328,'KERNEL_STATUS':336,'KERNEL_STATE':344,'KERNEL_TOKEN':352,
'KERNEL_VALUE':360,'KERNEL_SEEN':368,'KERNEL_CAUGHT':376,'BORROWED':384,'FINAL_STAGE':392,
'FINAL_FAILED':400,'TEMP':408,'RANDOM':416,'FEEDBACK':448,'RESTORE':456,'BOXPTR':464,'CALL_OP':472,
'RUNNING':480,'NOTIFIED':488,'COMPLETION_MODE':496,'VALUE_CLASS':504,'NODE':512,'HEADER':640,'BOX':768,'PIN':1024,'SAVED':1152,'RQ':4096,'FP':6144,'VP':8192,'OUT':16384}
SOURCE=r'''

def background_future_cell(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return locks(s,o,w,phase)
    if phase<200:
        return lookup(s,o,w,phase)
    if phase<300:
        return create(s,o,w,phase)
    if phase<400:
        return attach(s,o,w,phase)
    if phase<500:
        return release(s,o,w,phase)
    if phase<600:
        return execute(s,o,w,phase)
    if phase<700:
        return retire(s,o,w,phase)
    if phase<800:
        return pins(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128:
        return 4294967293
    op=readword(s,8)
    if readword(s,0)==MAGIC:
        if op>13:
            return 4294967293
    elif readword(s,0)==MAGIC2:
        if op!=14:
            return 4294967293
    elif readword(s,0)==MAGIC3:
        if op<15 or op>19:
            return 4294967293
    else:
        return 4294967293
    at=16
    while at<128:
        used=False
        if op==0 and at>=24 and at<=48:
            used=True
        if op==2 or op==3 or (op>=6 and op<=12):
            if at>=24 and at<=40:
                used=True
        if op>=15 and op<=19 and at>=24 and at<=40:
            used=True
        if (op==15 or op==16) and ((at>=48 and at<=64) or at==80):
            used=True
        if op==14 and at==24:
            used=True
        if op==10 and (at==104 or at==112):
            used=True
        if op==11 and ((at>=48 and at<=64) or at==80):
            used=True
        if op==12 and ((at>=48 and at<=64) or at==80):
            used=True
        if used==False and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if op==4:
        return 4294967293
    if op==10 and readword(s,112)>1:
        return 4294967293
    if (op==11 or op==15 or op==16) and (readword(s,80)<1 or readword(s,80)>3):
        return 4294967293
    if op==12 and readword(s,48)==0:
        return 4294967293
    zero(o,128,OUT-128)
    put(o,OP,op)
    return system(o,1,39,0,0,0,0,0,0,0)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,w,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,0)!=0 or readword(s,24)==0 or readword(s,32)==0 or readword(s,40)==0 or readword(s,48)<256:
                return finish(o,w,5)
            zero(w,0,256)
            put(w,0,STATE)
            put(w,8,pid)
            put(w,64,readword(s,24))
            put(w,72,readword(s,32))
            put(w,80,readword(s,40))
            put(w,88,readword(s,48))
            return finish(o,w,0)
        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,w,5)
        return lock(o,20)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,AFTER))
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return system(o,12,24,0,0,0,0,0,0,0)
        return atom(o,2,10,0,1)
    if phase==12:
        return atom(o,2,10,0,1)
    if phase==15:
        return system(o,16,202,1,32,129,2147483647,0,0,0)
    if phase==16:
        return again(o,get(o,AFTER))
    if phase==20:
        if get(w,24)!=0:
            return fail(o,5)
        op=get(o,OP)
        if op==5:
            if get(w,16)!=0 or get(w,40)!=0 or get(w,48)!=0:
                return fail(o,5)
            put(w,24,1)
            return fail(o,0)
        if op==13:
            put(o,CURSOR,get(w,40))
            return again(o,180)
        if op==1:
            return allocate(o,200,1024)
        if op==14:
            put(o,CURSOR,get(w,48))
            return again(o,160)
        put(o,CAP,readword(s,24))
        put(o,CURSOR,get(w,16))
        return again(o,100)
    return fail(o,9)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,1)
        return memory(o,101,0,get(o,CURSOR),3,NODE,96)
    if phase==101:
        if get(o,NODE)!=NMAGIC or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        if get(o,CURSOR)!=get(o,CAP):
            put(o,CURSOR,get(o,NODE+24))
            return again(o,100)
        if get(o,NODE+48)!=readword(s,32) or get(o,NODE+56)!=readword(s,40):
            return fail(o,1)
        put(o,OBJ,get(o,NODE+8))
        return memory(o,102,0,get(o,OBJ),3,HEADER,128)
    if phase==102:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+32)==0 or get(o,HEADER+96)!=1:
            return fail(o,9)
        op=get(o,OP)
        if op==2:
            return again(o,300)
        if op==3:
            return again(o,400)
        if op==6:
            put(o,BORROWED,get(o,OBJ)+512)
            return fail(o,0)
        put(o,NEXT,500)
        return address(o,700,PIN)
    if phase==160:
        if get(o,CURSOR)==0:
            return fail(o,1)
        put(o,OBJ,get(o,CURSOR))
        return memory(o,161,0,get(o,OBJ),3,HEADER,160)
    if phase==161:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+120)!=1:
            return fail(o,9)
        if get(o,OBJ)+512!=readword(s,24):
            put(o,CURSOR,get(o,HEADER+136))
            return again(o,160)
        if get(o,HEADER+96)!=1 or (get(o,HEADER+32)==0 and get(o,HEADER+56)==0):
            return fail(o,1)
        return again(o,300)
    if phase==180:
        if get(o,CURSOR)==0:
            return fail(o,0)
        put(o,OBJ,get(o,CURSOR))
        return memory(o,181,0,get(o,OBJ),3,HEADER,128)
    if phase==181:
        if get(o,HEADER+96)==3 and get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            return write_pointer(o,182,get(o,OBJ)+96,2)
        put(o,CURSOR,get(o,HEADER+48))
        return again(o,180)
    if phase==182:
        return unlock(o,610)
    return fail(o,9)

def create(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWOBJ,get(o,FEEDBACK))
        put(o,OBJ,get(o,FEEDBACK))
        zero(o,RQ,1024)
        put(o,RQ,OBJECT)
        put(o,RQ+8,get(o,PID))
        put(o,RQ+16,1024)
        return memory(o,201,3,RQ,0,get(o,OBJ),1024)
    if phase==201:
        value_packet(o,21)
        return value(o,w,202)
    if phase==202:
        if value_ok(o)==False:
            return fail(o,choose(get(o,VP+8)==5,4,9))
        return memory(o,203,3,VP+24,0,get(o,OBJ)+64,24)
    if phase==203:
        future_packet(o,0)
        return future(o,w,204)
    if phase==204:
        if future_ok(o)==False or get(o,FP+8)!=0:
            return fail(o,9)
        return write_pointer(o,205,get(o,OBJ)+104,1)
    if phase==205:
        return write_pointer(o,206,get(o,OBJ)+96,1)
    if phase==206:
        return again(o,300)
    return fail(o,9)

def attach(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return memory(o,301,0,get(o,OBJ),3,HEADER,128)
    if phase==301:
        return allocate(o,302,96)
    if phase==302:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWREF,get(o,FEEDBACK))
        put(o,RANDOM_USED,0)
        return random(o,303)
    if phase==303:
        raw=get(o,FEEDBACK)
        used=get(o,RANDOM_USED)
        if raw==MAX-3:
            return random(o,303)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return fail(o,6)
        used=used+raw
        put(o,RANDOM_USED,used)
        if used<16:
            return random(o,303)
        if get(o,RANDOM)==0 and get(o,RANDOM+8)==0:
            return fail(o,6)
        put(o,TAG0,get(o,RANDOM))
        put(o,TAG1,get(o,RANDOM+8))
        zero(o,NODE,96)
        put(o,NODE,NMAGIC)
        put(o,NODE+8,get(o,OBJ))
        put(o,NODE+24,get(w,16))
        put(o,NODE+40,get(o,HEADER+32))
        put(o,NODE+48,get(o,TAG0))
        put(o,NODE+56,get(o,TAG1))
        put(o,NODE+64,get(o,PID))
        return memory(o,304,3,NODE,0,get(o,NEWREF),96)
    if phase==304:
        if get(w,16)!=0:
            return write_pointer(o,305,get(w,16)+16,get(o,NEWREF))
        return again(o,305)
    if phase==305:
        if get(o,HEADER+32)!=0:
            return write_pointer(o,306,get(o,HEADER+32)+32,get(o,NEWREF))
        return again(o,306)
    if phase==306:
        return write_pointer(o,307,get(o,OBJ)+32,get(o,NEWREF))
    if phase==307:
        put(w,16,get(o,NEWREF))
        put(o,RESULT,get(o,NEWREF))
        put(o,NEWREF,0)
        if get(o,NEWOBJ)!=0:
            return write_pointer(o,308,get(o,OBJ)+136,get(w,48))
        return fail(o,0)
    if phase==308:
        if get(w,48)!=0:
            return write_pointer(o,309,get(w,48)+128,get(o,OBJ))
        return again(o,309)
    if phase==309:
        put(w,48,get(o,OBJ))
        return write_pointer(o,310,get(o,OBJ)+120,1)
    if phase==310:
        put(o,NEWOBJ,0)
        return fail(o,0)
    return fail(o,9)

def release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if get(o,NODE+16)!=0:
            return write_pointer(o,401,get(o,NODE+16)+24,get(o,NODE+24))
        put(w,16,get(o,NODE+24))
        return again(o,401)
    if phase==401:
        if get(o,NODE+24)!=0:
            return write_pointer(o,402,get(o,NODE+24)+16,get(o,NODE+16))
        return again(o,402)
    if phase==402:
        if get(o,NODE+32)!=0:
            return write_pointer(o,403,get(o,NODE+32)+40,get(o,NODE+40))
        return write_pointer(o,403,get(o,OBJ)+32,get(o,NODE+40))
    if phase==403:
        if get(o,NODE+40)!=0:
            return write_pointer(o,404,get(o,NODE+40)+32,get(o,NODE+32))
        return again(o,404)
    if phase==404:
        return deallocate(o,405,get(o,CAP))
    if phase==405:
        return memory(o,406,0,get(o,OBJ),3,HEADER,128)
    if phase==406:
        if get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            return again(o,600)
        return fail(o,0)
    return fail(o,9)

def execute(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        return unlock(o,501)
    if phase==501:
        op=get(o,OP)
        if op==11 or op==15 or op==16:
            future_packet(o,choose(op==11,5,15))
            return future(o,w,518)
        kernel=5
        if op==7:
            kernel=1
        elif op==8:
            kernel=3
        elif op==10:
            kernel=6
        elif op==12:
            kernel=4
        elif op==17:
            kernel=13
        elif op==18:
            kernel=14
        elif op==19:
            kernel=15
        future_packet(o,kernel)
        if op==10:
            put(o,RQ+16,readword(s,104))
            put(o,RQ+24,readword(s,112))
        if op==12:
            put(o,RQ+16,readword(s,48))
            put(o,RQ+24,readword(s,56))
            put(o,RQ+32,readword(s,64))
            put(o,RQ+40,readword(s,80))
        return future(o,w,510)
    if phase==510:
        if future_ok(o)==False:
            return fail(o,9)
        save_kernel(o)
        if (get(o,OP)==10 or get(o,OP)==19) and get(o,KERNEL_STATUS)==0 and get(o,KERNEL_STATE)==2:
            put(o,BOXPTR,get(o,KERNEL_VALUE))
            return memory(o,511,0,get(o,BOXPTR),3,BOX,64)
        return fail(o,0)
    if phase==511:
        if get(o,BOX)!=BOXMAGIC or get(o,BOX+8)!=get(o,PID) or get(o,BOX+16)<1 or get(o,BOX+16)>6:
            return fail(o,9)
        put(o,VALUE_KIND,get(o,BOX+16))
        put(o,VALUE_CLASS,get(o,BOX+48))
        value_packet(o,5)
        within(o,RQ+24,BOX+24,24)
        return value(o,w,512)
    if phase==512:
        if value_ok(o)==False:
            return fail(o,choose(get(o,VP+8)==5,4,9))
        within(o,VALUE_RESULT,VP+24,24)
        return fail(o,0)
    if phase==518:
        if future_ok(o)==False or get(o,FP+8)!=0:
            return fail(o,9)
        if get(o,FP+24)!=0:
            save_kernel(o)
            if get(o,OP)==15 or get(o,OP)==16:
                put(o,KERNEL_STATUS,6)
            return fail(o,0)
        value_packet(o,5)
        copy_input(s,48,o,RQ+24,24)
        return value(o,w,520)
    if phase==520:
        if value_ok(o)==False:
            return fail(o,choose(get(o,VP+8)==1,1,choose(get(o,VP+8)==5,4,9)))
        within(o,RETAINED_VALUE,VP+24,24)
        return allocate(o,521,128)
    if phase==521:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWBOX,get(o,FEEDBACK))
        zero(o,BOX,128)
        put(o,BOX,BOXMAGIC)
        put(o,BOX+8,get(o,PID))
        kind=readword(s,80)
        if get(o,OP)==15:
            kind=1
        elif get(o,OP)==16:
            kind=kind+3
        put(o,BOX+16,kind)
        put(o,BOX+48,readword(s,80))
        within(o,BOX+24,RETAINED_VALUE,24)
        return memory(o,522,3,BOX,0,get(o,NEWBOX),128)
    if phase==522:
        kernel=2
        if get(o,OP)==15:
            kernel=11
        elif get(o,OP)==16:
            kernel=12
        future_packet(o,kernel)
        put(o,RQ+16,get(o,NEWBOX))
        return future(o,w,523)
    if phase==523:
        if future_ok(o)==False:
            return fail(o,9)
        save_kernel(o)
        future_packet(o,5)
        return future(o,w,524)
    if phase==524:
        if future_ok(o)==False or get(o,FP+8)!=0:
            return fail(o,9)
        if get(o,FP+24)==2 and get(o,FP+16)==get(o,NEWBOX):
            put(o,NEWBOX,0)
            zero(o,RETAINED_VALUE,24)
        return fail(o,0)
    return fail(o,9)

def retire(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        return write_pointer(o,601,get(o,OBJ)+40,0)
    if phase==601:
        return write_pointer(o,602,get(o,OBJ)+48,get(w,40))
    if phase==602:
        if get(w,40)!=0:
            return write_pointer(o,603,get(w,40)+40,get(o,OBJ))
        return again(o,603)
    if phase==603:
        put(w,40,get(o,OBJ))
        return write_pointer(o,604,get(o,OBJ)+96,2)
    if phase==604:
        return unlock(o,610)
    if phase==610:
        return memory(o,617,0,get(o,OBJ),3,HEADER,160)
    if phase==617:
        if get(o,HEADER+104)==0:
            return again(o,620)
        return memory(o,611,0,get(o,OBJ)+512+32,3,BOXPTR,8)
    if phase==611:
        if get(o,HEADER+112)!=0:
            return again(o,618)
        future_packet(o,10)
        return future(o,w,612)
    if phase==612:
        if future_ok(o)==False or get(o,FP+8)!=0:
            put(o,FINAL_FAILED,1)
            return lock(o,680)
        return write_pointer(o,618,get(o,OBJ)+112,1)
    if phase==618:
        if get(o,BOXPTR)!=0:
            return memory(o,613,0,get(o,BOXPTR),3,BOX,128)
        return again(o,620)
    if phase==613:
        if get(o,BOX)!=BOXMAGIC or get(o,BOX+8)!=get(o,PID):
            put(o,FINAL_FAILED,1)
            return lock(o,680)
        value_packet(o,6)
        within(o,RQ+24,BOX+24,24)
        return value(o,w,614)
    if phase==614:
        if value_ok(o)==False:
            put(o,FINAL_FAILED,1)
            return lock(o,680)
        return write_pointer(o,615,get(o,OBJ)+512+32,0)
    if phase==615:
        return deallocate(o,616,get(o,BOXPTR))
    if phase==616:
        put(o,BOXPTR,0)
        return again(o,620)
    if phase==620:
        return memory(o,621,0,get(o,OBJ)+64,3,BOX,24)
    if phase==621:
        if get(o,BOX)==0:
            return lock(o,650)
        value_packet(o,22)
        within(o,RQ+24,BOX,24)
        return value(o,w,622)
    if phase==622:
        if value_ok(o)==False:
            put(o,FINAL_FAILED,1)
            return lock(o,680)
        zero(o,BOX,24)
        return memory(o,623,3,BOX,0,get(o,OBJ)+64,24)
    if phase==623:
        return lock(o,650)
    if phase==650:
        return memory(o,651,0,get(o,OBJ),3,HEADER,160)
    if phase==651:
        if get(o,HEADER+40)!=0:
            return write_pointer(o,652,get(o,HEADER+40)+48,get(o,HEADER+48))
        put(w,40,get(o,HEADER+48))
        return again(o,652)
    if phase==652:
        if get(o,HEADER+48)!=0:
            return write_pointer(o,653,get(o,HEADER+48)+40,get(o,HEADER+40))
        return again(o,653)
    if phase==653:
        if get(o,HEADER+120)!=0:
            if get(o,HEADER+128)!=0:
                return write_pointer(o,655,get(o,HEADER+128)+136,get(o,HEADER+136))
            put(w,48,get(o,HEADER+136))
            return again(o,655)
        return deallocate(o,654,get(o,OBJ))
    if phase==655:
        if get(o,HEADER+136)!=0:
            return write_pointer(o,656,get(o,HEADER+136)+128,get(o,HEADER+128))
        return again(o,656)
    if phase==656:
        return deallocate(o,654,get(o,OBJ))
    if phase==654:
        put(o,OBJ,0)
        return fail(o,get(o,ERROR))
    if phase==680:
        return write_pointer(o,681,get(o,OBJ)+96,3)
    if phase==681:
        return fail(o,9)
    return fail(o,9)

def pins(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        put(o,PINPTR,get(o,FEEDBACK))
        zero(o,PIN,64)
        put(o,PIN+8,get(o,HEADER+56))
        put(o,PIN+16,get(o,OBJ))
        put(o,PIN+24,PMAGIC)
        put(o,PIN+32,get(o,PID))
        if get(o,HEADER+56)!=0:
            return write_pointer(o,701,get(o,HEADER+56),get(o,PINPTR))
        return again(o,701)
    if phase==701:
        return write_pointer(o,702,get(o,OBJ)+56,get(o,PINPTR))
    if phase==702:
        put(o,ACTIVE,1)
        return again(o,get(o,NEXT))
    if phase==710:
        if get(o,PIN+24)!=PMAGIC or get(o,PIN+32)!=get(o,PID):
            return fail(o,9)
        put(o,OBJ,get(o,PIN+16))
        if get(o,PIN)!=0:
            return write_pointer(o,711,get(o,PIN)+8,get(o,PIN+8))
        return write_pointer(o,711,get(o,OBJ)+56,get(o,PIN+8))
    if phase==711:
        if get(o,PIN+8)!=0:
            return write_pointer(o,712,get(o,PIN+8),get(o,PIN))
        return again(o,712)
    if phase==712:
        put(o,ACTIVE,0)
        return memory(o,713,0,get(o,OBJ),3,HEADER,128)
    if phase==713:
        if get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            return again(o,600)
        return fail(o,get(o,ERROR))
    return fail(o,9)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,RETAINED_VALUE)!=0:
            value_packet(o,6)
            within(o,RQ+24,RETAINED_VALUE,24)
            return value(o,w,901)
        if get(o,NEWBOX)!=0:
            ptr=get(o,NEWBOX)
            put(o,NEWBOX,0)
            return deallocate(o,900,ptr)
        if get(o,NEWREF)!=0:
            ptr=get(o,NEWREF)
            put(o,NEWREF,0)
            return deallocate(o,900,ptr)
        if get(o,NEWOBJ)!=0:
            put(o,OBJ,get(o,NEWOBJ))
            put(o,NEWOBJ,0)
            # Even partial construction is retained on the retirement list
            # until its actual value context token has been released.
            return again(o,600)
        if get(o,ACTIVE)!=0:
            if get(o,HELD)==0:
                return lock(o,710)
            return again(o,710)
        if get(o,HELD)!=0:
            return unlock(o,980)
        return again(o,980)
    if phase==901:
        if value_ok(o)==False:
            put(o,FINAL_FAILED,1)
            put(o,ERROR,9)
            if get(o,HELD)!=0:
                return unlock(o,980)
            return finish(o,w,9)
        zero(o,RETAINED_VALUE,24)
        return again(o,900)
    if phase==980:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,9)

def save_kernel(o:mutbuf) -> u64:
    put(o,KERNEL_STATUS,get(o,FP+8))
    put(o,KERNEL_VALUE,get(o,FP+16))
    put(o,KERNEL_STATE,get(o,FP+24))
    put(o,KERNEL_TOKEN,get(o,FP+32))
    put(o,KERNEL_SEEN,get(o,FP+48))
    put(o,KERNEL_CAUGHT,get(o,FP+56))
    put(o,RUNNING,get(o,FP+72))
    put(o,NOTIFIED,get(o,FP+80))
    put(o,COMPLETION_MODE,get(o,FP+88))
    return 0
def future_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,choose(op>=11,FREQUEST2,FREQUEST))
    put(o,RQ+8,op)
    return 0
def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    return 0
def future(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,64),RQ,64,FP,512,get(o,OBJ)+512,512)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,VP,8192,get(w,80),get(w,88))
def future_ok(o:mutbuf) -> bool:
    return get(o,FP)==FREPLY and get(o,FEEDBACK)==get(o,FP+8) and (get(o,FP+8)<=6 or (get(o,RQ)==FREQUEST2 and get(o,FP+8)==7) or get(o,FP+8)==65)
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0
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
def fail(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,900)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    result=get(o,RESULT)
    t0=get(o,TAG0)
    t1=get(o,TAG1)
    borrowed=get(o,BORROWED)
    if get(o,OP)==7 or get(o,OP)==8 or get(o,OP)==17 or get(o,OP)==18:
        borrowed=get(o,KERNEL_VALUE)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,result)
    put(o,24,choose(result!=0,t0,0))
    put(o,32,choose(result!=0,t1,0))
    put(o,40,get(o,KERNEL_STATUS))
    put(o,48,get(o,KERNEL_STATE))
    put(o,56,get(o,KERNEL_TOKEN))
    put(o,64,borrowed)
    put(o,72,get(o,VALUE_KIND))
    within(o,80,VALUE_RESULT,24)
    put(o,104,get(o,KERNEL_SEEN))
    put(o,112,get(o,KERNEL_CAUGHT))
    put(o,120,get(o,FINAL_FAILED))
    if get(o,OP)>=15:
        put(o,128,get(o,RUNNING))
        put(o,136,get(o,NOTIFIED))
        put(o,144,get(o,COMPLETION_MODE))
        put(o,152,get(o,VALUE_CLASS))
    return 0
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
def main():
 d=document(source_program(),'multiversion_background_future_cell')
 p=ROOT/'examples/hia_bootstrap/multiversion_background_future_cell.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
