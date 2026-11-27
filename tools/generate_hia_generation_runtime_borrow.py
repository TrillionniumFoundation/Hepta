"""Actual Runtime-object custody of the installed native resources.

Registration retains the installed global resources and both enclosing native
lifetime guards. Retirement is called by the new carrier only after the actual
Runtime effects owner is retired, outside the carrier mutex and before freeing
the real Runtime object. No public request chooses an entry or context.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,NEG=(1<<64)-4095,
 OUT=262144,REGISTER_OUT=(96<<20)+32768,ANCHOR_OFFSET=7341056,
 PH=128,FB=136,OP=144,STATUS=152,DETAIL=160,KNOWN=168,PENDING=176,REMOVED=184,
 RETIRED=192,HELD=200,NEXT=208,PID=216,OBJECT_PTR=224,RECORD_PTR=232,
 CURSOR=240,ANCHOR_PTR=248,REGISTERED=256,ABORTING=264,CLAIMED=272,
 NONCE0=280,NONCE1=288,SAVE=296,GLOBAL_PHASE=304,COUNT=312,GUARDS=320,
 SELF=512,ROOT_ENTRY=520,GLOBAL_ENTRY=528,HANDLES_ENTRY=536,
 ANCHOR=1024,RECORD=1536,HEADER=2048,TEMP=2304,TIMESPEC=2560,
 RQ=4096,CHILD=32768)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 Q='HIARTLQ1',R='HIARTLR1',OWNER='HIAGLOW1',A='HIARTLC1',REC='HIARTLN1',
 GLOBAL_Q='HIAGGIQ1',GLOBAL_R='HIAGGIR1',
 HANDLES_Q='HIAMVHA1',HANDLES_R='HIAMVHA2',NATIVE_OBJECT='HIAMVHO1').items()})
SOURCE=r'''
def lifetime(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if r==0 or r>=NEG or get(w,0)!=OWNER or get(w,8)!=r or get(w,16)!=get(o,SELF):
            return BAD
        if get(w,24)!=get(o,ROOT_ENTRY) or get(w,32)!=get(o,HANDLES_ENTRY) or get(w,80)!=1:
            return BAD
        put(o,PID,r)
        if get(o,OP)==0:
            request(o,HANDLES_Q,6)
            put(o,RQ+16,1)
            copy_source(s,o,24,RQ+24,24)
            put(o,PH,2)
            return 12
        put(o,OBJECT_PTR,word(s,24))
        return lock(o,20)
    if phase==2:
        if r!=0 or get(o,CHILD)!=HANDLES_R or get(o,CHILD+96)!=1 or get(o,CHILD+104)!=0:
            put(o,KNOWN,0)
            return finish(o,9,2)
        if get(o,CHILD+8)!=0:
            return finish(o,get(o,CHILD+8),get(o,CHILD+80))
        if get(o,CHILD+16)!=1 or get(o,CHILD+40)==0:
            put(o,KNOWN,0)
            return finish(o,9,3)
        put(o,OBJECT_PTR,get(o,CHILD+40))
        put(o,NONCE0,get(o,CHILD+24))
        put(o,NONCE1,get(o,CHILD+32))
        return lock(o,20)
    if phase==10:
        if r==0:
            put(o,HELD,1)
            return again(o,get(o,NEXT))
        put(o,TIMESPEC,0)
        put(o,TIMESPEC+8,10000000)
        return system(o,11,202,193,64,128,1,TIMESPEC,0,0)
    if phase==11:
        if r!=0 and r!=MAX-3 and r!=MAX-10 and r!=MAX-109:
            return system(o,12,24,0,0,0,0,0,0,0)
        return atom(o,10,2)
    if phase==12:
        return atom(o,10,2)
    if phase==15:
        return system(o,16,202,1,64,129,2147483647,0,0,0)
    if phase==16:
        return again(o,get(o,NEXT))
    if phase>=20 and phase<40:
        return admission(o,w,phase)
    if phase>=40 and phase<60:
        return registering(o,w,phase)
    if phase>=60 and phase<90:
        return retiring(o,w,phase)
    if phase==90:
        return reply(o)
    return finish(o,9,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)!=2048 or word(s,0)!=Q or word(s,8)>2:
        return BAD
    op=word(s,8)
    if op==0 and length(o)<REGISTER_OUT:
        return BAD
    i=16
    while i<128:
        used=False
        if op==0 and i>=24 and i<=40:
            used=True
        if op==1 and i==24:
            used=True
        if used==False and word(s,i)!=0:
            return BAD
        i=i+8
    if op!=2 and word(s,24)==0:
        return BAD
    zero(o,128,384)
    zero(o,ANCHOR,512)
    zero(o,RECORD,256)
    put(o,OP,op)
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def admission(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(w,1088)==0:
            if get(w,1096)!=0:
                return quarantine(o,20)
            if get(o,OP)==0:
                return finish(o,6,20)
            put(o,RETIRED,1)
            return finish(o,0,0)
        if get(w,1096)!=8388608 or get(w,1088)>MAX-8388608:
            return quarantine(o,21)
        put(o,ANCHOR_PTR,get(w,1088)+ANCHOR_OFFSET)
        return memory(o,21,0,get(o,ANCHOR_PTR),3,ANCHOR,512)
    if phase==21:
        if get(o,ANCHOR)==0:
            if get(o,OP)!=0:
                put(o,RETIRED,1)
                return finish(o,0,0)
            i=0
            while i<512:
                if get(o,ANCHOR+i)!=0:
                    return quarantine(o,22)
                i=i+8
            put(o,ANCHOR,A)
            put(o,ANCHOR+8,get(o,PID))
            put(o,ANCHOR+16,get(o,SELF))
            put(o,ANCHOR+24,get(o,GLOBAL_ENTRY))
            return anchor_save(o,22)
        if get(o,ANCHOR)!=A or get(o,ANCHOR+8)!=get(o,PID) or get(o,ANCHOR+16)!=get(o,SELF) or get(o,ANCHOR+24)!=get(o,GLOBAL_ENTRY):
            return quarantine(o,23)
        return again(o,22)
    if phase==22:
        put(o,COUNT,get(o,ANCHOR+48))
        if get(o,OP)==2:
            return finish(o,0,0)
        put(o,CURSOR,get(o,ANCHOR+40))
        return again(o,23)
    if phase==23:
        if get(o,CURSOR)==0:
            if get(o,OP)==1:
                put(o,RETIRED,1)
                return finish(o,0,0)
            return again(o,40)
        put(o,RECORD_PTR,get(o,CURSOR))
        return memory(o,24,0,get(o,CURSOR),3,RECORD,256)
    if phase==24:
        if record_valid(o)==False:
            return quarantine(o,24)
        if get(o,RECORD+24)!=get(o,OBJECT_PTR):
            put(o,CURSOR,get(o,RECORD+40))
            return again(o,23)
        if get(o,OP)==0:
            return finish(o,6,25)
        if get(o,RECORD+48)==4:
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return finish(o,9,get(o,RECORD+136))
        if get(o,RECORD+48)!=2 and get(o,RECORD+48)!=3:
            put(o,PENDING,1)
            return finish(o,6,26)
        return memory(o,25,0,get(o,OBJECT_PTR),3,HEADER,192)
    if phase==25:
        if get(o,HEADER)!=NATIVE_OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+24)!=1 or get(o,HEADER+128)!=2 or get(o,HEADER+32)!=0 or get(o,HEADER+56)!=0:
            return finish(o,6,27)
        return again(o,60)
    return quarantine(o,phase)

def registering(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(o,FB)
    if phase==40:
        if get(w,80)!=1 or get(w,112)!=1 or get(w,1144)!=2 or get(w,72)==MAX or get(w,1208)==MAX or get(o,ANCHOR+48)==MAX:
            return finish(o,6,40)
        put(w,72,get(w,72)+1)
        put(w,1208,get(w,1208)+1)
        put(o,GUARDS,1)
        return system(o,41,9,0,0,4096,3,34,MAX,0)
    if phase==41:
        if r==0 or r>=NEG:
            put(w,72,get(w,72)-1)
            put(w,1208,get(w,1208)-1)
            put(o,GUARDS,0)
            return finish(o,5,r)
        put(o,RECORD_PTR,r)
        zero(o,RECORD,256)
        put(o,RECORD,REC)
        put(o,RECORD+8,get(o,PID))
        put(o,RECORD+16,get(o,SELF))
        put(o,RECORD+24,get(o,OBJECT_PTR))
        put(o,RECORD+40,get(o,ANCHOR+40))
        put(o,RECORD+48,1)
        put(o,RECORD+80,1)
        put(o,RECORD+88,1)
        put(o,RECORD+112,get(o,NONCE0))
        put(o,RECORD+120,get(o,NONCE1))
        put(o,RECORD+144,r)
        put(o,RECORD+152,4096)
        return memory(o,42,3,RECORD,0,get(o,RECORD_PTR),256)
    if phase==42:
        if get(o,ANCHOR+40)!=0:
            return pointer(o,43,get(o,ANCHOR+40)+32,get(o,RECORD_PTR))
        return again(o,43)
    if phase==43:
        put(o,ANCHOR+40,get(o,RECORD_PTR))
        put(o,ANCHOR+48,get(o,ANCHOR+48)+1)
        put(o,COUNT,get(o,ANCHOR+48))
        return anchor_save(o,44)
    if phase==44:
        return unlock(o,45)
    if phase==45:
        request(o,GLOBAL_Q,2)
        return global_call(o,46)
    if phase==46:
        if global_reply(o)==False:
            put(o,KNOWN,0)
            put(o,RECORD+48,4)
            put(o,RECORD+136,46)
            put(o,PENDING,1)
            return lock(o,49)
        if get(o,CHILD+96)==1:
            if get(o,CHILD+24)==0:
                put(o,KNOWN,0)
                put(o,RECORD+48,4)
                put(o,RECORD+136,47)
                put(o,PENDING,1)
                return lock(o,49)
            within(o,RECORD+56,CHILD+24,24)
            put(o,RECORD+104,get(o,CHILD+152))
        if get(o,CHILD+88)!=1:
            put(o,KNOWN,0)
            put(o,RECORD+48,4)
            put(o,RECORD+136,48)
            put(o,PENDING,1)
            return lock(o,49)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,CHILD+16)!=2 or get(o,RECORD+56)==0:
            put(o,ABORTING,1)
            put(o,STATUS,choose(get(o,CHILD+8)==0,7,get(o,CHILD+8)))
            put(o,DETAIL,get(o,CHILD+112))
            put(o,RECORD+48,3)
            return lock(o,49)
        put(o,RECORD+48,2)
        put(o,REGISTERED,1)
        return lock(o,49)
    if phase==49:
        return record_save(o,50)
    if phase==50:
        if get(o,KNOWN)==0:
            return finish(o,9,get(o,RECORD+136))
        if get(o,ABORTING)!=0:
            return again(o,60)
        return finish(o,0,0)
    return quarantine(o,phase)

def retiring(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(o,FB)
    if phase==60:
        put(o,RECORD+48,5)
        put(o,CLAIMED,1)
        return record_save(o,61)
    if phase==61:
        return unlock(o,62)
    if phase==62:
        if get(o,RECORD+56)!=0:
            request(o,GLOBAL_Q,3)
            within(o,RQ+24,RECORD+56,24)
            put(o,GLOBAL_PHASE,3)
            return global_call(o,63)
        if get(o,RECORD+96)!=0:
            request(o,GLOBAL_Q,4)
            put(o,GLOBAL_PHASE,4)
            return global_call(o,63)
        return lock(o,70)
    if phase==63:
        if global_reply(o)==False or get(o,CHILD+88)!=1:
            put(o,RECORD+48,4)
            put(o,RECORD+136,63)
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return lock(o,68)
        if get(o,GLOBAL_PHASE)==3 and get(o,CHILD+96)==1:
            zero(o,RECORD+56,24)
        if get(o,GLOBAL_PHASE)==4 and get(o,CHILD+96)!=0:
            put(o,RECORD+48,4)
            put(o,RECORD+136,64)
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return lock(o,68)
        put(o,RECORD+96,get(o,CHILD+80))
        if get(o,RECORD+56)!=0 or get(o,RECORD+96)!=0:
            put(o,RECORD+48,3)
            put(o,RECORD+128,get(o,CHILD+8))
            put(o,RECORD+136,get(o,CHILD+112))
            put(o,PENDING,1)
            return lock(o,68)
        return lock(o,70)
    if phase==68:
        return record_save(o,69)
    if phase==69:
        put(o,CLAIMED,0)
        return finish(o,9,get(o,RECORD+136))
    if phase==70:
        return record_save(o,76)
    if phase==76:
        return memory(o,77,0,get(o,ANCHOR_PTR),3,ANCHOR,512)
    if phase==77:
        return memory(o,78,0,get(o,RECORD_PTR)+32,3,RECORD+32,16)
    if phase==78:
        if get(o,ANCHOR)!=A or get(o,ANCHOR+8)!=get(o,PID) or get(o,ANCHOR+16)!=get(o,SELF) or get(o,ANCHOR+48)==0:
            return quarantine_record(o,78)
        if get(o,RECORD+80)!=1 or get(o,RECORD+88)!=1 or get(w,72)==0 or get(w,1208)==0:
            return quarantine_record(o,71)
        return system(o,72,11,0,get(o,RECORD_PTR),4096,0,0,0,0)
    if phase==72:
        if r!=0:
            put(o,RECORD+48,3)
            put(o,RECORD+136,r)
            put(o,PENDING,1)
            return record_save(o,69)
        if get(o,RECORD+32)!=0:
            return pointer(o,73,get(o,RECORD+32)+40,get(o,RECORD+40))
        put(o,ANCHOR+40,get(o,RECORD+40))
        return again(o,73)
    if phase==73:
        if get(o,RECORD+40)!=0:
            return pointer(o,74,get(o,RECORD+40)+32,get(o,RECORD+32))
        return again(o,74)
    if phase==74:
        if get(o,ANCHOR+48)==0:
            return quarantine(o,74)
        put(o,ANCHOR+48,get(o,ANCHOR+48)-1)
        put(o,COUNT,get(o,ANCHOR+48))
        return anchor_save(o,75)
    if phase==75:
        put(w,72,get(w,72)-1)
        put(w,1208,get(w,1208)-1)
        put(o,GUARDS,0)
        put(o,CLAIMED,0)
        put(o,RECORD_PTR,0)
        put(o,RETIRED,1)
        put(o,REMOVED,1)
        put(o,PENDING,0)
        return finish(o,get(o,STATUS),get(o,DETAIL))
    return quarantine(o,phase)

def record_valid(o:mutbuf) -> bool:
    return get(o,RECORD)==REC and get(o,RECORD+8)==get(o,PID) and get(o,RECORD+16)==get(o,SELF) and get(o,RECORD+144)==get(o,RECORD_PTR) and get(o,RECORD+152)==4096
def global_reply(o:mutbuf) -> bool:
    return get(o,FB)==0 and get(o,CHILD)==GLOBAL_R and get(o,CHILD+80)<=1 and get(o,CHILD+88)<=1 and get(o,CHILD+96)<=1 and get(o,CHILD+104)<=1
def record_save(o:mutbuf,next:u64) -> u32:
    return memory(o,next,3,RECORD+48,0,get(o,RECORD_PTR)+48,208)
def anchor_save(o:mutbuf,next:u64) -> u32:
    return memory(o,next,3,ANCHOR,0,get(o,ANCHOR_PTR),512)
def quarantine_record(o:mutbuf,detail:u64) -> u32:
    put(o,RECORD+48,4)
    put(o,RECORD+136,detail)
    put(o,PENDING,1)
    put(o,KNOWN,0)
    return record_save(o,69)
def quarantine(o:mutbuf,detail:u64) -> u32:
    put(o,KNOWN,0)
    put(o,PENDING,1)
    return finish(o,9,detail)
def finish(o:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,STATUS)==0:
        put(o,STATUS,status)
        put(o,DETAIL,detail)
    if get(o,HELD)!=0:
        return unlock(o,90)
    return reply(o)
def reply(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,REGISTERED))
    put(o,48,get(o,OBJECT_PTR))
    put(o,80,get(o,PENDING))
    put(o,88,get(o,KNOWN))
    put(o,96,get(o,REMOVED))
    put(o,104,get(o,RETIRED))
    put(o,112,get(o,DETAIL))
    put(o,120,get(o,COUNT))
    return 0
def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    return atom(o,10,2)
def unlock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,HELD,0)
    return atom(o,15,3)
def atom(o:mutbuf,next:u64,action:u64) -> u32:
    put(o,PH,next)
    return narrow(action)
def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    zero(o,CHILD,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def global_call(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 9
def pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)
def memory(o:mutbuf,next:u64,sk:u64,si:u64,tk:u64,ti:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sk)
    put(o,8,si)
    put(o,16,tk)
    put(o,24,ti)
    put(o,32,n)
    return 8
def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1
def word(s:readbuf,at:u64) -> u64:
    x=0
    i=0
    while i<8:
        x=x|(byte(s,at+i)<<(i*8))
        i=i+1
    return x
def get(w:mutbuf,at:u64) -> u64:
    x=0
    i=0
    while i<8:
        x=x|(byte(w,at+i)<<(i*8))
        i=i+1
    return x
def put(w:mutbuf,at:u64,x:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(x>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
def within(w:mutbuf,dst:u64,src:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,dst+i,byte(w,src+i))
        i=i+1
    return 0
def copy_source(s:readbuf,o:mutbuf,src:u64,dst:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dst+i,byte(s,src+i))
        i=i+1
    return 0
def choose(ok:bool,a:u64,b:u64) -> u64:
    if ok:
        return a
    return b
def narrow(n:u64) -> u32:
    return n
'''
def source_program():
 text=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
 return text
def main():
 tree=document(source_program(),'generation_runtime_borrow')
 path=ROOT/'examples/hia_bootstrap/generation_runtime_borrow.hepta';path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
