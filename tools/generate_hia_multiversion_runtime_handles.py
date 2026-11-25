"""Owned runtime/lease capabilities with in-flight pins and fixed HIA finalizers."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={
'MAGIC':int.from_bytes(b'HIAMVHQ1','little'),'REPLY':int.from_bytes(b'HIAMVHR1','little'),
'STATE':int.from_bytes(b'HIAMVHW1','little'),'OBJECT':int.from_bytes(b'HIAMVHO1','little'),
'NODE_MAGIC':int.from_bytes(b'HIAMVHN1','little'),'PIN_MAGIC':int.from_bytes(b'HIAMVHP1','little'),
'EFFECTS':int.from_bytes(b'HIAMVEX1','little'),'PUBLIC_EFFECTS':int.from_bytes(b'HIAMVEX3','little'),'EFFECT_REPLY':int.from_bytes(b'HIAMVER1','little'),
'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'OUT':96<<20,'MAX_FRAME':20<<20,
'CHILD_O':1<<20,'CHILD_I':41<<20,'SAVED':64<<20,'SAVE_DATA':65<<20,
'PHASE':128,'OP':136,'HELD':144,'ERROR':152,'RESUME':160,'PID':168,'OBJ':176,
'CAP':184,'CURSOR':192,'KIND':200,'N':208,'NEWOBJ':216,'NEWNODE':224,
'RUNTIME':232,'LEASE_OBJ':240,'NODE_TARGET':248,'NODE_MODE':256,'NODE_NEXT':264,
'NEXT':272,'AFTER':280,'PINPTR':288,'ACTIVE':296,'CHILD_RC':304,'INNER':312,
'RESULT':320,'TAG0':328,'TAG1':336,'RETURN_KIND':344,'RETIRE_OBJ':352,
'RESTORE':360,'NEXT_OBJ':368,'FEEDBACK':376,'FRAME_N':384,'CALL_KIND':392,
'RANDOM_USED':400,'REGISTERED':408,'RETIRE_NEXT':416,'RETAINED':424,
'NODE_PTR':432,'NODE_TAG0':440,'NODE_TAG1':448,'RETRY_SCAN':456,
'SAVED_N':464,'SAVED_AT':472,'INTERNAL_PTR':480,'FINAL_RC':488,'SAVED_CALL_N':496,'SAVED_CALL_AT':504,
'NODE':1024,'HEADER':1152,'TEMP':1344,'RANDOM':1360,'PIN':1440,
'INTERNAL':1536,'OTHER':1664,'ZERO':65536}
_control_names=list(C)[list(C).index('PHASE'):list(C).index('NODE')]
_control_offsets=[C[k] for k in _control_names]
assert len(_control_offsets)==len(set(_control_offsets))
assert all(n>=128 and n%8==0 and n+8<=1024 for n in _control_offsets)
SOURCE=r'''
def runtime_handles(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return locking(s,o,w,phase)
    if phase<200:
        return lookup(s,o,w,phase)
    if phase<300:
        return creation(s,o,w,phase)
    if phase<400:
        return attach(s,o,w,phase)
    if phase<500:
        return release(s,o,w,phase)
    if phase<600:
        return execute(s,o,w,phase)
    if phase<700:
        return retirement(s,o,w,phase)
    if phase<800:
        return pins(s,o,w,phase)
    return completing(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or word(s,0)!=MAGIC or word(s,8)>7:
        return 4294967293
    op=word(s,8)
    n=word(s,72)
    if n!=length(s)-128 or n>MAX_FRAME:
        return 4294967293
    if (op==1 or op==4) and n<256:
        return 4294967293
    if op!=1 and op!=4 and n!=0:
        return 4294967293
    i=16
    while i<128:
        used=i==72
        if op==2 or op==3 or op==4 or op==6:
            if i>=24 and i<=40:
                used=True
        if used==False and word(s,i)!=0:
            return 4294967293
        i=i+8
    if op==1 and ((word(s,128)!=EFFECTS and word(s,128)!=PUBLIC_EFFECTS) or word(s,136)!=0):
        return 4294967293
    zero(o,64,8192-64)
    put(o,OP,op)
    put(o,N,n)
    return system(o,1,39,0,0,0,0,0,0,0)

def locking(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,w,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,0)!=0:
                return finish(o,w,5)
            zero(w,0,256)
            put(w,0,STATE)
            put(w,8,pid)
            return finish(o,w,0)
        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,w,5)
        return lock(o,20)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,RESUME))
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=NONE-3 and raw!=NONE-10:
            put(w,88,raw)
            return system(o,12,24,0,0,0,0,0,0,0)
        return atom(o,10,2,0,1)
    if phase==12:
        return atom(o,10,2,0,1)
    if phase==15:
        return system(o,16,202,1,32,129,2147483647,0,0,0)
    if phase==16:
        return again(o,get(o,RESUME))
    if phase==20:
        if get(w,24)!=0:
            return fail(o,5)
        op=get(o,OP)
        if op==5:
            if get(w,16)!=0 or get(w,40)!=0 or get(w,64)!=0:
                return fail(o,5)
            put(w,24,1)
            return fail(o,0)
        if op==7:
            put(o,RETRY_SCAN,get(w,40))
            return again(o,180)
        if op==1:
            put(o,CALL_KIND,1)
            put(o,KIND,1)
            return allocate(o,200,131328)
        put(o,CAP,word(s,24))
        put(o,CURSOR,get(w,16))
        return again(o,100)
    return fail(o,9)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,1)
        return memory(o,101,0,get(o,CURSOR),3,NODE,96)
    if phase==101:
        if get(o,NODE)!=NODE_MAGIC or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        if get(o,CURSOR)!=get(o,CAP):
            put(o,CURSOR,get(o,NODE+24))
            return again(o,100)
        if get(o,NODE+72)!=0 or get(o,NODE+48)!=word(s,32) or get(o,NODE+56)!=word(s,40):
            return fail(o,1)
        put(o,OBJ,get(o,NODE+8))
        return memory(o,102,0,get(o,OBJ),3,HEADER,192)
    if phase==102:
        kind=get(o,HEADER+24)
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or kind<1 or kind>2 or get(o,HEADER+128)!=1:
            return fail(o,9)
        if get(o,HEADER+32)==0:
            return fail(o,9)
        put(o,KIND,kind)
        put(o,RETURN_KIND,kind)
        op=get(o,OP)
        if op==2:
            put(o,NODE_TARGET,get(o,OBJ))
            put(o,NODE_MODE,0)
            put(o,NODE_NEXT,360)
            return allocate(o,220,96)
        if op==3:
            put(o,AFTER,440)
            return again(o,400)
        if op==6:
            return fail(o,0)
        if op!=4 or valid_command(s,o,kind)==0:
            return fail(o,3)
        put(o,RUNTIME,choose(kind==1,get(o,OBJ),get(o,HEADER+64)))
        put(o,CALL_KIND,choose(kind==1,3,4))
        put(o,INNER,word(s,136))
        if kind==1 and word(s,136)==3:
            put(o,CALL_KIND,2)
        put(o,NEXT,120)
        return address(o,700,PIN)
    if phase==120:
        if get(o,CALL_KIND)==2:
            put(o,KIND,2)
            return allocate(o,200,352)
        return again(o,500)
    if phase==180:
        if get(o,RETRY_SCAN)==0:
            return fail(o,0)
        put(o,OBJ,get(o,RETRY_SCAN))
        return memory(o,181,0,get(o,OBJ),3,HEADER,192)
    if phase==181:
        if get(o,HEADER+128)==3 and get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            put(o,RETIRE_OBJ,get(o,OBJ))
            put(o,RETAINED,0)
            return write_pointer(o,607,get(o,OBJ)+128,2)
        put(o,RETRY_SCAN,get(o,HEADER+48))
        return again(o,180)
    return fail(o,9)

def valid_command(s:readbuf,o:mutbuf,kind:u64) -> u64:
    if word(s,128)!=EFFECTS and word(s,128)!=PUBLIC_EFFECTS:
        return 0
    op=word(s,136)
    if kind==1:
        if op!=1 and op!=2 and op!=3 and op!=7 and op!=8 and op!=9 and op!=10 and op!=11 and (op!=14 or word(s,128)!=PUBLIC_EFFECTS):
            return 0
        if op==1 or op==2:
            if word(s,216)!=0 or word(s,224)!=0 or word(s,232)!=0:
                return 0
            if op==1 and word(s,240)!=0:
                return 0
        elif get(o,N)!=256:
            return 0
    else:
        if op!=4 and op!=5 and op!=6:
            return 0
        if word(s,208)!=0 or word(s,216)!=0 or word(s,240)!=0 or word(s,248)!=0:
            return 0
        if op!=4 and get(o,N)!=256:
            return 0
    return 1

def creation(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return fail(o,4)
        put(o,NEWOBJ,ptr)
        put(o,OBJ,ptr)
        size=choose(get(o,KIND)==1,131328,352)
        zero(o,ZERO,size)
        put(o,ZERO,OBJECT)
        put(o,ZERO+8,get(o,PID))
        put(o,ZERO+16,size)
        put(o,ZERO+24,get(o,KIND))
        if get(o,KIND)==2:
            put(o,ZERO+64,get(o,RUNTIME))
        return memory(o,201,3,ZERO,0,ptr,size)
    if phase==201:
        put(o,NODE_TARGET,get(o,OBJ))
        put(o,NODE_MODE,0)
        put(o,NODE_NEXT,230)
        return allocate(o,220,96)
    if phase==220:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWNODE,get(o,FEEDBACK))
        put(o,NODE_PTR,get(o,FEEDBACK))
        put(o,RANDOM_USED,0)
        return random(o,221)
    if phase==221:
        raw=get(o,FEEDBACK)
        used=get(o,RANDOM_USED)
        if raw==NONE-3:
            return random(o,221)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return fail(o,6)
        used=used+raw
        put(o,RANDOM_USED,used)
        if used<16:
            return random(o,221)
        if get(o,RANDOM)==0 and get(o,RANDOM+8)==0:
            return fail(o,6)
        put(o,TAG0,get(o,RANDOM))
        put(o,TAG1,get(o,RANDOM+8))
        put(o,NODE_TAG0,get(o,TAG0))
        put(o,NODE_TAG1,get(o,TAG1))
        return again(o,get(o,NODE_NEXT))
    if phase==230:
        return write_pointer(o,231,get(o,OBJ)+144,get(w,64))
    if phase==231:
        if get(w,64)!=0:
            return write_pointer(o,232,get(w,64)+136,get(o,OBJ))
        return again(o,232)
    if phase==232:
        put(w,64,get(o,OBJ))
        put(o,NEWOBJ,0)
        put(o,REGISTERED,1)
        if get(o,KIND)==1:
            put(o,RUNTIME,get(o,OBJ))
            return again(o,500)
        put(o,LEASE_OBJ,get(o,OBJ))
        put(o,NODE_PTR,get(o,OBJ)+256)
        put(o,NODE_TARGET,get(o,RUNTIME))
        put(o,NODE_MODE,1)
        put(o,NODE_NEXT,233)
        return again(o,300)
    if phase==233:
        put(o,OBJ,get(o,LEASE_OBJ))
        return again(o,500)
    return fail(o,9)

def attach(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return memory(o,301,0,get(o,NODE_TARGET),3,HEADER,192)
    if phase==301:
        zero(o,NODE,96)
        put(o,NODE,NODE_MAGIC)
        put(o,NODE+8,get(o,NODE_TARGET))
        put(o,NODE+24,get(w,16))
        put(o,NODE+40,get(o,HEADER+32))
        put(o,NODE+48,get(o,NODE_TAG0))
        put(o,NODE+56,get(o,NODE_TAG1))
        put(o,NODE+64,get(o,PID))
        put(o,NODE+72,get(o,NODE_MODE))
        return memory(o,302,3,NODE,0,get(o,NODE_PTR),96)
    if phase==302:
        if get(w,16)!=0:
            return write_pointer(o,303,get(w,16)+16,get(o,NODE_PTR))
        return again(o,303)
    if phase==303:
        if get(o,HEADER+32)!=0:
            return write_pointer(o,304,get(o,HEADER+32)+32,get(o,NODE_PTR))
        return again(o,304)
    if phase==304:
        return write_pointer(o,305,get(o,NODE_TARGET)+32,get(o,NODE_PTR))
    if phase==305:
        put(w,16,get(o,NODE_PTR))
        return again(o,get(o,NODE_NEXT))
    if phase==360:
        put(o,NODE_PTR,get(o,NEWNODE))
        put(o,NODE_TARGET,get(o,OBJ))
        put(o,NODE_MODE,0)
        put(o,NODE_NEXT,361)
        return again(o,300)
    if phase==361:
        put(o,RESULT,get(o,NEWNODE))
        put(o,NEWNODE,0)
        return fail(o,0)
    if phase==362:
        put(o,NODE_PTR,get(o,NEWNODE))
        put(o,NODE_TARGET,get(o,OBJ))
        put(o,NODE_MODE,0)
        put(o,NODE_TAG0,get(o,TAG0))
        put(o,NODE_TAG1,get(o,TAG1))
        put(o,NODE_NEXT,363)
        return again(o,300)
    if phase==363:
        put(o,RESULT,get(o,NEWNODE))
        put(o,RETURN_KIND,get(o,KIND))
        put(o,NEWNODE,0)
        put(o,REGISTERED,0)
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
        if get(o,NODE+72)==0:
            return deallocate(o,405,get(o,CAP))
        return again(o,405)
    if phase==405:
        return memory(o,406,0,get(o,OBJ),3,HEADER,192)
    if phase==406:
        return again(o,get(o,AFTER))
    if phase==440:
        if get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            return retire(o,w,get(o,OBJ))
        return fail(o,0)
    if phase==450:
        put(o,NEXT_OBJ,0)
        if get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            put(o,NEXT_OBJ,get(o,OBJ))
        return deallocate(o,451,get(o,RETIRE_OBJ))
    if phase==451:
        put(o,RETIRE_OBJ,0)
        if get(o,NEXT_OBJ)!=0:
            put(o,OBJ,get(o,NEXT_OBJ))
            put(o,NEXT_OBJ,0)
            return retire(o,w,get(o,OBJ))
        return fail(o,get(o,ERROR))
    return fail(o,9)

def execute(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        return memory(o,501,2,128,3,CHILD_I,get(o,N))
    if phase==501:
        if get(o,CALL_KIND)==4:
            return memory(o,504,0,get(o,OBJ)+80,3,CHILD_I+16,24)
        return again(o,504)
    if phase==504:
        put(o,FRAME_N,get(o,N))
        return unlock(o,505)
    if phase==505:
        zero(o,CHILD_O,1024)
        return effects(o,506)
    if phase==506:
        put(o,CHILD_RC,get(o,FEEDBACK))
        if get(o,CHILD_O)!=EFFECT_REPLY:
            zero(o,CHILD_O,1024)
            put(o,CHILD_O,EFFECT_REPLY)
            put(o,CHILD_O+8,get(o,CHILD_RC))
            put(o,CHILD_O+96,NONE)
            put(o,CHILD_O+104,NONE)
        if get(o,CALL_KIND)==2 and get(o,CHILD_RC)==0:
            return memory(o,507,3,CHILD_O+64,0,get(o,OBJ)+80,8)
        return again(o,510)
    if phase==507:
        return memory(o,508,3,CHILD_O+80,0,get(o,OBJ)+88,16)
    if phase==508:
        put(o,CHILD_O+64,0)
        put(o,CHILD_O+80,0)
        put(o,CHILD_O+88,0)
        return again(o,510)
    if phase==510:
        put(o,RESTORE,1)
        n=get(o,CHILD_O+136)
        at=get(o,CHILD_O+128)
        if n>31457280 or at>41943040 or n>41943040-at:
            return fail(o,9)
        put(o,SAVED_N,n)
        put(o,SAVED_AT,at)
        calln=get(o,CHILD_O+112)
        callat=get(o,CHILD_O+120)
        if calln>4096 or callat>41943040 or calln>41943040-callat:
            return fail(o,9)
        put(o,SAVED_CALL_N,calln)
        put(o,SAVED_CALL_AT,callat)
        return memory(o,511,3,CHILD_O,3,SAVED,1024)
    if phase==511:
        if get(o,SAVED_N)!=0:
            return memory(o,512,3,CHILD_O+get(o,SAVED_AT),3,SAVE_DATA,get(o,SAVED_N))
        return again(o,512)
    if phase==512:
        if get(o,SAVED_CALL_N)!=0:
            return memory(o,515,3,CHILD_O+get(o,SAVED_CALL_AT),3,SAVED+2048,get(o,SAVED_CALL_N))
        return again(o,515)
    if phase==515:
        return lock(o,513)
    if phase==513:
        kind=get(o,CALL_KIND)
        if kind==1 or kind==2:
            if get(o,CHILD_RC)!=0:
                return retire(o,w,get(o,OBJ))
            return write_pointer(o,514,get(o,OBJ)+128,1)
        return fail(o,0)
    if phase==514:
        return again(o,362)
    return fail(o,9)

def retire(o:mutbuf,w:mutbuf,obj:u64) -> u32:
    put(o,RETIRE_OBJ,obj)
    put(o,OBJ,obj)
    return write_pointer(o,600,obj+128,2)

def retirement(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
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
        return again(o,607)
    if phase==607:
        return memory(o,608,0,get(o,OBJ),3,HEADER,192)
    if phase==608:
        put(o,KIND,get(o,HEADER+24))
        put(o,RUNTIME,choose(get(o,KIND)==1,get(o,OBJ),get(o,HEADER+64)))
        if get(o,KIND)==1:
            return memory(o,609,0,get(o,OBJ)+256,3,TEMP,8)
        if get(o,HEADER+80)==0:
            return again(o,620)
        zero(o,CHILD_I,256)
        put(o,CHILD_I,EFFECTS)
        put(o,CHILD_I+8,12)
        put(o,CHILD_I+72,NONE)
        within(o,CHILD_I+16,HEADER+80,24)
        put(o,FRAME_N,256)
        return unlock(o,612)
    if phase==609:
        if get(o,TEMP)==0:
            return again(o,620)
        zero(o,CHILD_I,256)
        put(o,CHILD_I,EFFECTS)
        put(o,CHILD_I+8,13)
        put(o,CHILD_I+72,NONE)
        put(o,FRAME_N,256)
        return unlock(o,612)
    if phase==612:
        return effects(o,613)
    if phase==613:
        put(o,FINAL_RC,get(o,FEEDBACK))
        return lock(o,614)
    if phase==614:
        if get(o,FINAL_RC)!=0:
            put(o,RETAINED,1)
            return write_pointer(o,619,get(o,OBJ)+128,3)
        return again(o,620)
    if phase==619:
        put(o,RETIRE_OBJ,0)
        if get(o,OP)==3 or get(o,OP)==7:
            put(o,ERROR,9)
        return fail(o,get(o,ERROR))
    if phase==620:
        # Never reuse neighbours captured before the unlocked finalizer.
        return memory(o,621,0,get(o,OBJ),3,HEADER,192)
    if phase==621:
        if get(o,HEADER+40)!=0:
            return write_pointer(o,622,get(o,HEADER+40)+48,get(o,HEADER+48))
        put(w,40,get(o,HEADER+48))
        return again(o,622)
    if phase==622:
        if get(o,HEADER+48)!=0:
            return write_pointer(o,623,get(o,HEADER+48)+40,get(o,HEADER+40))
        return again(o,623)
    if phase==623:
        if get(o,HEADER+136)!=0:
            return write_pointer(o,624,get(o,HEADER+136)+144,get(o,HEADER+144))
        put(w,64,get(o,HEADER+144))
        return again(o,624)
    if phase==624:
        if get(o,HEADER+144)!=0:
            return write_pointer(o,625,get(o,HEADER+144)+136,get(o,HEADER+136))
        return again(o,625)
    if phase==625:
        if get(o,KIND)==2:
            put(o,INTERNAL_PTR,get(o,OBJ)+256)
            return memory(o,626,0,get(o,INTERNAL_PTR),3,NODE,96)
        return deallocate(o,629,get(o,OBJ))
    if phase==626:
        if get(o,NODE)!=NODE_MAGIC or get(o,NODE+72)!=1 or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        put(o,OBJ,get(o,NODE+8))
        put(o,CAP,get(o,INTERNAL_PTR))
        put(o,AFTER,450)
        return again(o,400)
    if phase==629:
        put(o,RETIRE_OBJ,0)
        return fail(o,get(o,ERROR))
    return fail(o,9)

def pins(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        put(o,PINPTR,get(o,FEEDBACK))
        zero(o,PIN,64)
        put(o,PIN+8,get(o,HEADER+56))
        put(o,PIN+16,get(o,OBJ))
        put(o,PIN+24,PIN_MAGIC)
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
        if get(o,PIN+24)!=PIN_MAGIC or get(o,PIN+32)!=get(o,PID):
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
        return memory(o,713,0,get(o,OBJ),3,HEADER,192)
    if phase==713:
        if get(o,HEADER+32)==0 and get(o,HEADER+56)==0:
            return retire(o,w,get(o,OBJ))
        return fail(o,get(o,ERROR))
    return fail(o,9)

def completing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,NEWNODE)!=0:
            ptr=get(o,NEWNODE)
            put(o,NEWNODE,0)
            return deallocate(o,900,ptr)
        if get(o,NEWOBJ)!=0:
            ptr=get(o,NEWOBJ)
            put(o,NEWOBJ,0)
            return deallocate(o,900,ptr)
        if get(o,ACTIVE)!=0:
            if get(o,HELD)==0:
                return lock(o,710)
            return again(o,710)
        if get(o,HELD)!=0:
            return unlock(o,980)
        return again(o,980)
    if phase==980:
        if get(o,RESTORE)!=0:
            return memory(o,981,3,SAVED,3,CHILD_O,1024)
        return finish(o,w,get(o,ERROR))
    if phase==981:
        if get(o,SAVED_N)!=0:
            return memory(o,982,3,SAVE_DATA,3,CHILD_O+get(o,SAVED_AT),get(o,SAVED_N))
        return again(o,982)
    if phase==982:
        if get(o,SAVED_CALL_N)!=0:
            return memory(o,983,3,SAVED+2048,3,CHILD_O+get(o,SAVED_CALL_AT),get(o,SAVED_CALL_N))
        return again(o,983)
    if phase==983:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,9)

def fail(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,900)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    result=get(o,RESULT)
    t0=get(o,TAG0)
    t1=get(o,TAG1)
    kind=get(o,RETURN_KIND)
    child=get(o,CHILD_RC)
    restore=get(o,RESTORE)
    retained=get(o,RETAINED)
    final=get(o,FINAL_RC)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    put(o,24,result)
    put(o,32,choose(result!=0,t0,0))
    put(o,40,choose(result!=0,t1,0))
    put(o,48,child)
    put(o,56,choose(restore!=0,CHILD_O,0))
    put(o,64,choose(restore!=0,1024,0))
    put(o,72,retained)
    put(o,80,final)
    put(o,88,get(w,8))
    return 0

def effects(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,3)
    put(o,8,CHILD_I)
    put(o,16,get(o,FRAME_N))
    put(o,24,3)
    put(o,32,CHILD_O)
    put(o,40,41943040)
    put(o,48,0)
    put(o,56,get(o,RUNTIME)+256)
    put(o,64,131072)
    return 12

def lock(o:mutbuf,next:u64) -> u32:
    put(o,RESUME,next)
    return atom(o,10,2,0,1)

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,RESUME,next)
    put(o,HELD,0)
    return atom(o,15,3,0,0)

def atom(o:mutbuf,next:u64,action:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)

def address(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 4

def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6

def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7

def random(o:mutbuf,next:u64) -> u32:
    return system(o,next,318,3,RANDOM+get(o,RANDOM_USED),16-get(o,RANDOM_USED),0,0,0,0)

def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)

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

def within(w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
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
'''
def source_program():
 source=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
  source=re.sub(r'\b'+key+r'\b',str(value),source)
 return source
def main():
 d=document(source_program(),'multiversion_runtime_handles')
 p=ROOT/'examples/hia_bootstrap/multiversion_runtime_handles.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']),flush=True)
if __name__=='__main__':main()
