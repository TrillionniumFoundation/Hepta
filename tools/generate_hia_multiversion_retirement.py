"""HIA retirement effects for the same private native generation holder.

The entry is private to the native runtime. It consumes the actual image
workspace, never a caller's resource facts. It transfers captured acquisition
history into the existing HIA retirement state owner without reopening the
path or executing an already completed effect. Subsequent native and disk
effects are authorized only by that owner's actual preclaim receipts.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={
'NONE':(1<<64)-1,'MINUS2':(1<<64)-2,'MINUS4':(1<<64)-4,'NEGATIVE':(1<<64)-4095,
'IMAGE_MAGIC':int.from_bytes(b'HIAMVIS1','little'),'INPUT_MAGIC':int.from_bytes(b'HIAMVRT1','little'),
'OWNER_MAGIC':int.from_bytes(b'HIAMVRS1','little'),'RESULT_MAGIC':int.from_bytes(b'HIAMVTR1','little'),
'INPUT_DIAGNOSTIC':int.from_bytes(b'HIAMVRT2','little'),'RESULT_DIAGNOSTIC':int.from_bytes(b'HIAMVTR2','little'),'EXTENDED':4408,
'INPUT_LOADER':int.from_bytes(b'HIAMVRT3','little'),'RESULT_LOADER':int.from_bytes(b'HIAMVTR3','little'),
'LIB_FUNCTION':4416,'LIB_POINTER':4424,'LIB_RAW_N':4432,'LIB_TEXT_N':4440,'LIB_CAPTURE':4448,'LIB_CAPTURE_ERROR':4456,'LIB_AMOUNT':4464,'LIB_BASE':4472,
'LIB_IOV':(6<<20)+10880,'LIB_REMOTE':(6<<20)+10912,'LIB_RAW':(6<<20)+12288,'LIB_TEXT':(6<<20)+16384,
'REQUEST_MAGIC':int.from_bytes(b'HIARREQ1','little'),'REPLY_MAGIC':int.from_bytes(b'HIARRES1','little'),
'PHASE':4096,'OWNER':4104,'OP':4112,'GEN':4120,'INIT':4128,'FENCED':4136,'ERROR':4144,'TOKEN':4152,'ATTEMPT':4160,
'NEXT':4168,'EVENT':4176,'NONCEA':4184,'NONCEB':4192,'FLAGS':4200,'TRANSITIONS':4208,'OBSERVATION':4216,'REQUEST_N':4224,
'ACTION':4232,'CLAIM':4240,'VALUE':4248,'CREATOR':4256,'SAVEDRAW':4264,'LIBERR':4272,'FDERR':4280,'DISKERR':4288,
'PINERR':4296,'CLEARED':4304,'FDATTEMPT':4320,'PATH_N':4352,'EFFECTS':4360,'RANDOM_USED':4368,
'ATTESTED_VALID':4376,'FENCE_RETURN':4384,'FENCE_EVENT':4392,'FENCE_RAW':4400,
'ATTESTED':(6<<20)+10240,'FENCE_REPLY':(6<<20)+10752,
'STATE':6<<20,'REQUEST':(6<<20)+4608,'REPLY':(6<<20)+9000,'TIME':(6<<20)+9088,'STAT':(6<<20)+9120,'FDSTAT':(6<<20)+9280
}
POLICY=r'''
def retire(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<167772160 or length(o)<768 or length(s)!=24:
        return 4294967293
    if (readword(s,0)!=INPUT_MAGIC and readword(s,0)!=INPUT_DIAGNOSTIC and readword(s,0)!=INPUT_LOADER) or readword(s,8)<1 or readword(s,8)>2:
        return 4294967293
    if get(w,16)!=IMAGE_MAGIC or (get(w,0)!=999 and get(w,0)!=902):
        return 4294967293
    phase=get(w,PHASE)
    if phase==0:
        if get(w,OWNER)!=0 and get(w,OWNER)!=OWNER_MAGIC:
            return 4294967293
        if get(w,OWNER)==OWNER_MAGIC and get(w,GEN)!=readword(s,16):
            return 4294967293
        put(w,EXTENDED,choose(readword(s,0)==INPUT_LOADER,2,choose(readword(s,0)==INPUT_DIAGNOSTIC,1,0)))
        put(w,OP,readword(s,8))
        return system(o,w,2,39,0,0,0,0,0,0,0)
    if phase==2:
        if get(w,8)!=get(w,24) or get(w,8)==0:
            return result(o,w,65)
        if get(w,OWNER)==0:
            return initialize(s,o,w)
        if get(w,CREATOR)!=get(w,8) or get(w,FENCED)!=0:
            return result(o,w,65)
        if get(w,INIT)!=2:
            return fence(o,w,1)
        return start_operation(o,w)
    if phase==3:
        raw=get(w,8)
        used=get(w,RANDOM_USED)
        if raw==MINUS4:
            return system(o,w,3,318,1,NONCEA+used,16-used,0,0,0,0)
        if raw==0 or raw>=NEGATIVE or raw>16-used:
            return fence(o,w,raw)
        used=used+raw
        put(w,RANDOM_USED,used)
        if used<16:
            return system(o,w,3,318,1,NONCEA+used,16-used,0,0,0,0)
        if get(w,NONCEA)==0 and get(w,NONCEB)==0:
            return fence(o,w,2)
        request(w,0,0)
        attach_path(w)
        return submit(o,w,100)
    if phase==9000:
        raw=get(w,8)
        if raw==MINUS4:
            return system(o,w,9000,228,4,1,TIME,0,0,0,0)
        if raw!=0 or get(w,TIME+8)>=1000000000:
            return fence(o,w,raw)
        put(w,REQUEST+24,get(w,TIME)*1000000000+get(w,TIME+8))
        put(w,PHASE,9001)
        put(o,0,REQUEST)
        put(o,8,get(w,REQUEST_N))
        put(o,16,REPLY)
        put(o,24,64)
        put(o,32,STATE)
        put(o,40,4608)
        return 2
    if phase==9001:
        if receipt(w)==0:
            return fence(o,w,3)
        put(w,PHASE,get(w,NEXT))
        return dispatch(o,w,get(w,NEXT))
    return dispatch(o,w,phase)

def initialize(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,40)!=NONE or get(w,104)>1 or get(w,112)>1 or get(w,120)>1 or get(w,192)>1:
        return result(o,w,65)
    if get(w,112)==1:
        if get(w,104)!=1 or get(w,32)==NONE or get(w,120)!=0:
            return result(o,w,65)
        if get(w,512)!=get(w,656) or get(w,520)!=get(w,664) or get(w,800)!=get(w,656) or get(w,808)!=get(w,664):
            return result(o,w,65)
    if get(w,120)==1 and (get(w,32)==NONE or get(w,112)!=0):
        return result(o,w,65)
    i=0
    while i<4096 and byte(w,8192+i)!=0:
        i=i+1
    if i==0 or i>4095:
        return result(o,w,65)
    put(w,PATH_N,i)
    put(w,GEN,readword(s,16))
    put(w,CREATOR,get(w,24))
    put(w,OWNER,OWNER_MAGIC)
    put(w,INIT,1)
    put(w,FENCED,0)
    put(w,ERROR,0)
    put(w,LIBERR,0)
    put(w,LIB_FUNCTION,0)
    put(w,LIB_POINTER,0)
    put(w,LIB_RAW_N,0)
    put(w,LIB_TEXT_N,0)
    put(w,LIB_CAPTURE,0)
    put(w,LIB_CAPTURE_ERROR,0)
    put(w,LIB_AMOUNT,0)
    put(w,LIB_BASE,0)
    put(w,FDERR,0)
    put(w,DISKERR,0)
    put(w,PINERR,0)
    put(w,CLEARED,0)
    put(w,FDATTEMPT,0)
    put(w,TRANSITIONS,0)
    put(w,FLAGS,0)
    put(w,RANDOM_USED,0)
    put(w,ATTESTED_VALID,0)
    put(w,FENCE_RETURN,0)
    put(w,FENCE_EVENT,0)
    put(w,FENCE_RAW,0)
    zero(w,ATTESTED,512)
    zero(w,FENCE_REPLY,64)
    zero(w,STATE,4608)
    return system(o,w,3,318,1,NONCEA,16,0,0,0,0)

def dispatch(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase>=100 and phase<200:
        return adopt(o,w,phase)
    if phase>=200 and phase<210:
        return release_native(o,w,phase)
    if phase>=210 and phase<230:
        return release_disk(o,w,phase)
    if phase==230:
        return result(o,w,0)
    return fence(o,w,4)

def adopt(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(w,104)==0:
            return attach(o,w)
        request(w,2,0)
        inode(w,REQUEST+32)
        return submit(o,w,101)
    if phase==101:
        put(w,TOKEN,get(w,CLAIM))
        if get(w,32)==NONE:
            return adopt_abort(o,w)
        request(w,3,get(w,TOKEN))
        put(w,REQUEST+32,get(w,32))
        return submit(o,w,102)
    if phase==102:
        if get(w,112)==0:
            return adopt_abort(o,w)
        request(w,4,get(w,TOKEN))
        put(w,REQUEST+32,get(w,656))
        put(w,REQUEST+40,get(w,664))
        put(w,REQUEST+48,get(w,680))
        put(w,REQUEST+56,get(w,800))
        put(w,REQUEST+64,get(w,808))
        return submit(o,w,103)
    if phase==103:
        return attach(o,w)
    if phase==104:
        if get(w,120)==0:
            if get(w,32)!=NONE:
                return fence(o,w,5)
            return attach(o,w)
        request(w,6,0)
        return submit(o,w,105)
    if phase==105:
        if get(w,ACTION)!=4 or get(w,VALUE)!=get(w,32):
            return fence(o,w,6)
        request(w,7,get(w,CLAIM))
        put(w,REQUEST+32,get(w,192))
        return submit(o,w,106)
    if phase==106:
        return attach(o,w)
    if phase==107:
        put(w,INIT,2)
        return start_operation(o,w)
    return fence(o,w,7)

def adopt_abort(o:mutbuf,w:mutbuf) -> u32:
    request(w,5,get(w,TOKEN))
    return submit(o,w,104)

def attach(o:mutbuf,w:mutbuf) -> u32:
    request(w,20,0)
    inode(w,REQUEST+32)
    put(w,REQUEST+56,choose(get(w,56)!=0,1,0))
    put(w,REQUEST+64,choose(get(w,48)!=NONE,1,0))
    put(w,REQUEST+72,choose(get(w,48)!=NONE,get(w,48),0))
    put(w,REQUEST+80,get(w,GEN))
    attach_path(w)
    return submit(o,w,107)

def inode(w:mutbuf,at:u64) -> u64:
    if (get(w,536)&61440)==32768:
        put(w,at,1)
        put(w,at+8,get(w,512))
        put(w,at+16,get(w,520))
    return 0

def start_operation(o:mutbuf,w:mutbuf) -> u32:
    if get(w,OP)==2:
        request(w,1,0)
        return submit(o,w,230)
    request(w,21,0)
    return submit(o,w,200)

def release_native(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(w,ACTION)==0:
            return begin_disk(o,w)
        if get(w,ACTION)!=7:
            return fence(o,w,8)
        put(w,TOKEN,get(w,CLAIM))
        put(w,EFFECTS,get(w,VALUE))
        zero(w,2048,128)
        put(w,CLEARED,1)
        if (get(w,EFFECTS)&1)!=0:
            put(w,PHASE,206)
            return 4
        return close_native_fd(o,w)
    if phase==201:
        raw=get(w,8)
        if raw==0:
            put(w,56,0)
        else:
            put(w,LIBERR,raw)
        if raw!=0:
            if get(w,LIB_FUNCTION)!=0:
                put(w,PHASE,207)
                return 5
            put(w,LIB_CAPTURE,2)
        return library_complete(o,w)
    if phase==202:
        return close_native_fd(o,w)
    if phase==203:
        raw=get(w,8)
        if raw==0:
            put(w,48,NONE)
        else:
            put(w,FDERR,raw)
        request(w,22,get(w,TOKEN))
        put(w,REQUEST+32,2)
        put(w,REQUEST+40,choose(raw==0,1,0))
        return submit(o,w,204)
    if phase==204:
        return finish_native(o,w)
    if phase==205:
        return begin_disk(o,w)
    if phase==206:
        put(w,LIB_FUNCTION,get(w,8))
        put(w,PHASE,201)
        put(o,0,get(w,56))
        return 3
    if phase==207:
        put(w,LIB_POINTER,get(w,8))
        if get(w,8)==0:
            put(w,LIB_CAPTURE,2)
            return library_complete(o,w)
        put(w,PHASE,208)
        return 6
    if phase==208:
        put(w,LIB_BASE,get(w,8))
        return library_read(o,w)
    if phase==209:
        raw=get(w,8)
        if raw==MINUS4:
            return library_read(o,w)
        if raw==0 or raw>=NEGATIVE or raw>get(w,LIB_AMOUNT):
            put(w,LIB_CAPTURE,2)
            put(w,LIB_CAPTURE_ERROR,raw)
            return library_complete(o,w)
        used=get(w,LIB_RAW_N)
        i=0
        while i<raw:
            if byte(w,LIB_RAW+used+i)==0:
                put(w,LIB_RAW_N,used+i)
                library_text(w)
                return library_complete(o,w)
            i=i+1
        used=used+raw
        put(w,LIB_RAW_N,used)
        if used==4096:
            library_text(w)
            return library_complete(o,w)
        return library_read(o,w)
    return fence(o,w,9)

def library_complete(o:mutbuf,w:mutbuf) -> u32:
    request(w,22,get(w,TOKEN))
    put(w,REQUEST+32,1)
    put(w,REQUEST+40,choose(get(w,LIBERR)==0,1,0))
    return submit(o,w,202)

def library_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,LIB_RAW_N)
    pointer=get(w,LIB_POINTER)
    if used>=4096 or pointer>NONE-used:
        put(w,LIB_CAPTURE,2)
        put(w,LIB_CAPTURE_ERROR,NONE)
        return library_complete(o,w)
    pointer=pointer+used
    amount=4096-(pointer&4095)
    if amount>256:
        amount=256
    if amount>4096-used:
        amount=4096-used
    put(w,LIB_AMOUNT,amount)
    put(w,LIB_IOV,get(w,LIB_BASE)+LIB_RAW+used)
    put(w,LIB_IOV+8,amount)
    put(w,LIB_REMOTE,pointer)
    put(w,LIB_REMOTE+8,amount)
    return system(o,w,209,310,68,get(w,CREATOR),LIB_IOV,1,LIB_REMOTE,1,0)

def continuation(value:u64) -> bool:
    return value>=128 and value<=191

def library_unit(w:mutbuf,at:u64,left:u64) -> u64:
    a=byte(w,LIB_RAW+at)
    if a<128:
        return 1
    if a>=194 and a<=223 and left>=2:
        if continuation(byte(w,LIB_RAW+at+1)):
            return 2
    if a>=224 and a<=239 and left>=3:
        b=byte(w,LIB_RAW+at+1)
        c=byte(w,LIB_RAW+at+2)
        low=choose(a==224,160,128)
        high=choose(a==237,159,191)
        if b>=low and b<=high and continuation(c):
            return 3
    if a>=240 and a<=244 and left>=4:
        b=byte(w,LIB_RAW+at+1)
        c=byte(w,LIB_RAW+at+2)
        d=byte(w,LIB_RAW+at+3)
        low=choose(a==240,144,128)
        high=choose(a==244,143,191)
        if b>=low and b<=high and continuation(c) and continuation(d):
            return 4
    return 0

def library_text(w:mutbuf) -> u64:
    at=0
    written=0
    characters=0
    n=get(w,LIB_RAW_N)
    while at<n and characters<1024:
        size=library_unit(w,at,n-at)
        if size==0:
            cp=56320+byte(w,LIB_RAW+at)
            store(w,LIB_TEXT+written,224|(cp>>12))
            store(w,LIB_TEXT+written+1,128|((cp>>6)&63))
            store(w,LIB_TEXT+written+2,128|(cp&63))
            written=written+3
            at=at+1
        else:
            i=0
            while i<size:
                store(w,LIB_TEXT+written+i,byte(w,LIB_RAW+at+i))
                i=i+1
            written=written+size
            at=at+size
        characters=characters+1
    put(w,LIB_TEXT_N,written)
    put(w,LIB_CAPTURE,1)
    return 0

def close_native_fd(o:mutbuf,w:mutbuf) -> u32:
    if (get(w,EFFECTS)&2)!=0:
        put(w,FDATTEMPT,1)
        return system(o,w,203,3,0,get(w,48),0,0,0,0,0)
    return finish_native(o,w)

def finish_native(o:mutbuf,w:mutbuf) -> u32:
    request(w,23,get(w,TOKEN))
    return submit(o,w,205)

def begin_disk(o:mutbuf,w:mutbuf) -> u32:
    put(w,DISKERR,0)
    request(w,26,0)
    return submit(o,w,210)

def release_disk(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==210:
        put(w,ATTEMPT,get(w,CLAIM))
        return system(o,w,211,262,20,NONE-99,8192,STAT,256,0,0)
    if phase==211:
        raw=get(w,8)
        request(w,9,0)
        if raw==0:
            put(w,REQUEST+32,0)
            put(w,REQUEST+40,get(w,STAT))
            put(w,REQUEST+48,get(w,STAT+8))
            put(w,REQUEST+56,get(w,STAT+24))
        else:
            put(w,REQUEST+32,choose(raw==MINUS2,1,2))
            if raw!=MINUS2:
                put(w,DISKERR,raw)
        return submit(o,w,212)
    if phase==212:
        if get(w,ACTION)==3:
            put(w,TOKEN,get(w,CLAIM))
            return system(o,w,213,5,4,get(w,VALUE),FDSTAT,0,0,0,0)
        return disk_decision(o,w)
    if phase==213:
        raw=get(w,8)
        if raw==MINUS4:
            return system(o,w,213,5,4,get(w,VALUE),FDSTAT,0,0,0,0)
        request(w,10,get(w,TOKEN))
        if raw==0:
            put(w,REQUEST+32,0)
            put(w,REQUEST+40,get(w,FDSTAT))
            put(w,REQUEST+48,get(w,FDSTAT+8))
        else:
            put(w,REQUEST+32,choose(raw==MINUS2,1,2))
            if raw!=MINUS2:
                put(w,DISKERR,raw)
        return submit(o,w,214)
    if phase==214:
        return disk_decision(o,w)
    if phase==215:
        if get(w,ACTION)==5:
            put(w,TOKEN,get(w,CLAIM))
            return system(o,w,216,87,1,8192,0,0,0,0,0)
        return release_path(o,w)
    if phase==216:
        raw=get(w,8)
        request(w,25,get(w,TOKEN))
        if raw==0:
            put(w,REQUEST+32,0)
        else:
            put(w,REQUEST+32,choose(raw==MINUS2,1,2))
            if raw!=MINUS2:
                put(w,DISKERR,raw)
        return submit(o,w,217)
    if phase==217:
        return release_path(o,w)
    if phase==220:
        request(w,6,0)
        return submit(o,w,221)
    if phase==221:
        if get(w,ACTION)==0:
            return query(o,w)
        if get(w,ACTION)!=4:
            return fence(o,w,10)
        put(w,TOKEN,get(w,CLAIM))
        put(w,120,1)
        return system(o,w,222,3,0,get(w,VALUE),0,0,0,0,0)
    if phase==222:
        raw=get(w,8)
        put(w,192,choose(raw==0,1,0))
        if raw!=0:
            put(w,PINERR,raw)
        request(w,7,get(w,TOKEN))
        put(w,REQUEST+32,choose(raw==0,1,0))
        return submit(o,w,223)
    if phase==223:
        return query(o,w)
    return fence(o,w,11)

def disk_decision(o:mutbuf,w:mutbuf) -> u32:
    request(w,24,get(w,CLAIM))
    put(w,REQUEST+32,get(w,ATTEMPT))
    return submit(o,w,215)

def release_path(o:mutbuf,w:mutbuf) -> u32:
    if get(w,ACTION)==8:
        request(w,8,0)
        return submit(o,w,220)
    return query(o,w)

def query(o:mutbuf,w:mutbuf) -> u32:
    request(w,1,0)
    return submit(o,w,230)

def request(w:mutbuf,event:u64,token:u64) -> u64:
    zero(w,REQUEST,128)
    put(w,REQUEST,REQUEST_MAGIC)
    put(w,REQUEST+8,event)
    put(w,REQUEST+16,token)
    put(w,REQUEST+112,get(w,NONCEA))
    put(w,REQUEST+120,get(w,NONCEB))
    put(w,REQUEST_N,128)
    put(w,EVENT,event)
    return 0

def attach_path(w:mutbuf) -> u64:
    copyw(w,REQUEST+128,8192,get(w,PATH_N))
    put(w,REQUEST_N,128+get(w,PATH_N))
    return 0

def submit(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,NEXT,next)
    return system(o,w,9000,228,4,1,TIME,0,0,0,0)

def receipt(w:mutbuf) -> u64:
    if get(w,8)!=64 or get(w,REPLY)!=REPLY_MAGIC or get(w,REPLY+8)!=0:
        return 0
    action=get(w,REPLY+16)
    flags=get(w,REPLY+40)
    observed=get(w,REPLY+56)
    claimed=get(w,REPLY+24)
    if action>8 or flags>15 or observed>6:
        return 0
    if action>0 and action<8 and claimed==0:
        return 0
    event=get(w,EVENT)
    if allowed(event,action)==0:
        return 0
    if get(w,STATE+16)!=get(w,REPLY+48) or get(w,STATE+440)!=get(w,NONCEA) or get(w,STATE+448)!=get(w,NONCEB):
        return 0
    put(w,ACTION,action)
    put(w,CLAIM,claimed)
    put(w,VALUE,get(w,REPLY+32))
    put(w,FLAGS,flags)
    put(w,OBSERVATION,observed)
    put(w,TRANSITIONS,get(w,TRANSITIONS)+1)
    copyw(w,ATTESTED,STATE,512)
    put(w,ATTESTED_VALID,1)
    return 1

def allowed(event:u64,action:u64) -> u64:
    if event==2:
        return choose(action==1 or action==2,1,0)
    if event==3:
        return choose(action==3,1,0)
    if event==6:
        return choose(action==0 or action==4,1,0)
    if event==9:
        return choose(action==0 or action==3,1,0)
    if event==21:
        return choose(action==0 or action==7,1,0)
    if event==24:
        return choose(action==0 or action==5 or action==8,1,0)
    if event==25:
        return choose(action==0 or action==8,1,0)
    return choose(action==0,1,0)

def fence(o:mutbuf,w:mutbuf,raw:u64) -> u32:
    if get(w,FENCED)==0:
        put(w,FENCE_RETURN,get(w,8))
        put(w,FENCE_EVENT,get(w,EVENT))
        put(w,FENCE_RAW,raw)
        copyw(w,FENCE_REPLY,REPLY,64)
    put(w,FENCED,1)
    put(w,FLAGS,0)
    if get(w,ERROR)==0:
        put(w,ERROR,raw)
    return result(o,w,65)

def result(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,768)
    put(o,0,choose(get(w,EXTENDED)==2,RESULT_LOADER,choose(get(w,EXTENDED)==1,RESULT_DIAGNOSTIC,RESULT_MAGIC)))
    put(o,8,status)
    put(o,16,get(w,OP))
    put(o,24,get(w,FLAGS))
    put(o,32,get(w,GEN))
    put(o,40,get(w,PATH_N))
    put(o,48,get(w,0))
    put(o,56,get(w,FENCED))
    put(o,64,get(w,ERROR))
    put(o,72,get(w,LIBERR))
    put(o,80,get(w,FDERR))
    put(o,88,get(w,DISKERR))
    put(o,96,get(w,PINERR))
    put(o,104,get(w,CLEARED))
    put(o,112,get(w,FDATTEMPT))
    put(o,120,get(w,TRANSITIONS))
    captured=STATE
    if get(w,FENCED)!=0:
        captured=ATTESTED
    i=0
    while i<512:
        store(o,128+i,byte(w,captured+i))
        i=i+1
    if get(w,EXTENDED)>=1:
        put(o,640,get(w,ATTESTED_VALID))
        put(o,648,get(w,FENCE_RETURN))
        put(o,656,get(w,FENCE_EVENT))
        put(o,664,get(w,FENCE_RAW))
        i=0
        while i<64:
            store(o,672+i,byte(w,FENCE_REPLY+i))
            i=i+1
    if get(w,EXTENDED)==2:
        put(o,736,get(w,LIB_TEXT_N))
        put(o,744,get(w,LIB_CAPTURE))
        put(o,752,get(w,LIB_RAW_N))
        put(o,760,get(w,LIB_CAPTURE_ERROR))
    put(w,PHASE,0)
    return 0

def system(o:mutbuf,w:mutbuf,next:u64,number:u64,pointers:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,PHASE,next)
    put(o,0,number)
    put(o,8,pointers)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def zero(w:mutbuf,at:u64,count:u64) -> u64:
    i=0
    while i<count:
        store(w,at+i,0)
        i=i+1
    return 0

def copyw(w:mutbuf,target:u64,source:u64,count:u64) -> u64:
    i=0
    while i<count:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0

def readword(s:readbuf,at:u64) -> u64:
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

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
    import re
    s=POLICY
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        s=re.sub(r'\b'+name+r'\b',str(value),s)
    return s
def main():
    tree=document(source_program(),'multiversion_retirement')
    p=ROOT/'examples/hia_bootstrap/multiversion_retirement.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
