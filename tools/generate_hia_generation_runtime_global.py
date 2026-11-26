"""Trusted root initialization of the sole installed native resource bundle.

The new private entry owns root words 1088/1096 only. It captures fixed native
entries mechanically, holds an actual root active guard, and admits no request
paths, descriptors, pointers or artifact claims.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIAGGIQ1','little'),R=int.from_bytes(b'HIAGGIR1','little'),
 OWNER=int.from_bytes(b'HIAGLOW1','little'),TAG=int.from_bytes(b'HIAGGM01','little'),
 RQ=int.from_bytes(b'HIANGRQ1','little'),RR=int.from_bytes(b'HIANGRR1','little'),
 BAD=4294967293,NONE=(1<<64)-1,WORK=8<<20,CONTROL=7<<20,OUT=147456,
 PH=128,FB=136,OP=144,STATUS=152,DETAIL=160,PENDING=168,KNOWN=176,
 CONSUMED=184,RETIRED=192,HELD=200,DELIVERED=208,AFTER=216,
 SAVE_SLOT=224,SAVE_NEXT=232,PID=240,RETURN_STATE=248,RETURN_COUNT=256,
 SELF=512,ENTRY=520,RESOURCE_ENTRY=528,ROOT_ENTRY=536,VALUE_ENTRY=544,
 GP=1088,GN=1096,M=1024,MS=1064,STAGE=1072,M_GUARD=1080,
 CAP=1088,STARTED=1112,DUP_INDEX=1120,TOOLS=1128,TP=1152,TN=1160,TF=1168,
 SOURCEFD=1176,NONCE=1184,DIGITS=1192,BANK_BITS=1200,BANK_READY=1208,
 LAST_STATUS=1216,LAST_DETAIL=1224,UNKNOWN_FD=1232,RESULT=2048,
 REQUEST=4096,CHILD=16384)
SOURCE=r'''
def global_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if r==0 or failed(r):
            return fail_unlocked(o,1,r)
        put(o,PID,r)
        if get(w,0)!=OWNER or get(w,8)!=r or get(w,16)!=get(o,SELF):
            return BAD
        if get(w,24)!=get(o,ROOT_ENTRY) or get(w,40)!=get(o,VALUE_ENTRY):
            return BAD
        if get(w,48)!=get(o,SELF)+512 or get(w,56)!=256 or get(w,664)==0 or get(w,80)!=1:
            return BAD
        return lock(o,2)
    if phase==2:
        if r==0:
            put(o,HELD,1)
            return locked(s,o,w)
        if r!=1:
            return fail_unlocked(o,5,r)
        put(o,768,0)
        put(o,776,10000000)
        return system(o,3,202,193,64,128,1,768,0,0)
    if phase==3:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            return fail_unlocked(o,1,r)
        return lock(o,2)
    if phase==10:
        if r==0 or failed(r):
            put(w,72,get(w,72)-1)
            put(w,112,0)
            return finish(o,w,1,r)
        put(w,GP,r)
        put(w,GN,WORK)
        zero(o,M,512)
        put(o,M,TAG)
        put(o,M+8,get(o,PID))
        put(o,M+16,get(o,SELF))
        put(o,M+24,get(o,ENTRY))
        put(o,M+32,get(o,RESOURCE_ENTRY))
        put(o,MS,1)
        put(o,M_GUARD,1)
        put(o,STAGE,20)
        return initialize(o,w)
    if phase==11:
        if r!=0:
            return quarantine(o,w,r)
        if get(o,M)!=TAG or get(o,M+8)!=get(o,PID) or get(o,M+16)!=get(o,SELF):
            return quarantine(o,w,11)
        if get(o,M+24)!=get(o,ENTRY) or get(o,M+32)!=get(o,RESOURCE_ENTRY) or get(o,M_GUARD)!=1:
            return quarantine(o,w,12)
        return existing(s,o,w)
    if phase==20:
        if resource_reply(o,r)==0:
            return quarantine(o,w,20)
        if get(o,CHILD+88)!=1:
            return quarantine(o,w,get(o,CHILD+112))
        if get(o,CHILD+8)!=0 or get(o,CHILD+16)!=2 or get(o,CHILD+80)!=0:
            if get(o,CHILD+104)==1:
                put(o,STARTED,3)
            return initial_failure(o,w,get(o,CHILD+8),get(o,CHILD+112))
        put(o,STARTED,2)
        put(o,STAGE,30)
        return initialize(o,w)
    if phase==30:
        if resource_reply(o,r)==0:
            return quarantine(o,w,30)
        if get(o,CHILD+96)==1:
            if cap_shape(o,CHILD+24)==0:
                return quarantine(o,w,31)
            within(o,CAP,CHILD+24,24)
        if get(o,CHILD+88)!=1:
            return quarantine(o,w,32)
        if get(o,CHILD+8)!=0 or get(o,CHILD+16)!=2 or get(o,CHILD+80)!=0 or get(o,CAP)==0:
            return initial_failure(o,w,get(o,CHILD+8),get(o,CHILD+112))
        i=0
        while i<3:
            fd=get(o,CHILD+48+i*8)
            if fd<3 or fd>2147483647:
                return quarantine(o,w,33)
            put(o,TOOLS+i*8,fd)
            i=i+1
        if get(o,CHILD+72)>2147483647 or get(o,CHILD+128)==0 or get(o,CHILD+136)!=10100891:
            return quarantine(o,w,34)
        if get(o,CHILD+144)>2147483647 or get(o,CHILD+152)==0 or get(o,CHILD+160)!=4300:
            return quarantine(o,w,35)
        put(o,TP,get(o,CHILD+128))
        put(o,TN,get(o,CHILD+136))
        put(o,TF,get(o,CHILD+144))
        put(o,SOURCEFD,get(o,CHILD+72))
        put(o,NONCE,get(o,CHILD+152))
        put(o,DIGITS,get(o,CHILD+160))
        put(o,STAGE,40)
        return initialize(o,w)
    if phase==40:
        if r<3 or r>2147483647:
            return initial_failure(o,w,1,r)
        index=get(o,DUP_INDEX)
        put(w,88+index*8,r)
        put(o,BANK_BITS,get(o,BANK_BITS)|(1<<index))
        put(o,DUP_INDEX,index+1)
        return initialize(o,w)
    if phase==44:
        if resource_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,44)
        if get(o,CHILD+96)==1:
            zero(o,CAP,24)
        if get(o,CHILD+96)!=1:
            return initial_failure(o,w,get(o,CHILD+8),get(o,CHILD+112))
        put(o,STAGE,45)
        if get(o,CHILD+80)!=0 or get(o,CHILD+8)!=0:
            put(o,PENDING,1)
            return finish(o,w,1,get(o,CHILD+112))
        return initialize(o,w)
    if phase==45:
        if resource_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,45)
        if get(o,CHILD+80)!=0 or get(o,CHILD+8)!=0 or get(o,CHILD+16)!=2:
            put(o,PENDING,1)
            return finish(o,w,1,get(o,CHILD+112))
        put(o,MS,2)
        put(o,STAGE,0)
        return finish(o,w,0,0)
    if phase==60:
        if resource_reply(o,r)==0:
            return quarantine(o,w,60)
        within(o,RESULT,CHILD,168)
        put(o,RETURN_COUNT,get(o,CHILD+120))
        put(o,CONSUMED,get(o,CHILD+96))
        if get(o,CHILD+96)==1 and get(o,OP)==2:
            if cap_shape(o,CHILD+24)==0:
                return quarantine(o,w,61)
            put(o,DELIVERED,1)
        if get(o,CHILD+88)!=1:
            return quarantine(o,w,62)
        put(o,PENDING,get(o,CHILD+80))
        return finish(o,w,get(o,CHILD+8),get(o,CHILD+112))
    if phase==100:
        if resource_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,100)
        put(o,RETURN_COUNT,get(o,CHILD+120))
        if get(o,CHILD+8)==6 and get(o,CHILD+16)==2 and get(o,CHILD+80)==0:
            put(o,MS,2)
            return finish(o,w,6,get(o,CHILD+120))
        put(o,MS,3)
        if get(o,CHILD+104)!=1 or get(o,CHILD+80)!=0:
            put(o,STAGE,110)
            put(o,PENDING,1)
            return finish(o,w,1,get(o,CHILD+112))
        put(o,STARTED,3)
        put(o,STAGE,120)
        return closing(o,w)
    if phase==101:
        if resource_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,101)
        if get(o,CHILD+96)==1:
            zero(o,CAP,24)
        if get(o,CAP)!=0:
            put(o,PENDING,1)
            return finish(o,w,1,get(o,CHILD+112))
        put(o,STAGE,110)
        return closing(o,w)
    if phase==110:
        if resource_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,110)
        if get(o,CHILD+104)!=1 or get(o,CHILD+80)!=0:
            put(o,PENDING,1)
            return finish(o,w,1,get(o,CHILD+112))
        put(o,STARTED,3)
        put(o,STAGE,120)
        return closing(o,w)
    if phase==120 or phase==121:
        if phase==120 and r==18446744073709551578:
            return system(o,121,3,0,get(w,get(o,SAVE_SLOT)),0,0,0,0,0)
        if r!=0:
            if phase==121:
                put(o,UNKNOWN_FD,get(w,get(o,SAVE_SLOT)))
                put(w,get(o,SAVE_SLOT),0)
                return quarantine(o,w,r)
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,get(o,SAVE_SLOT),0)
        return closing(o,w)
    if phase==190:
        if r!=0:
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,GP,0)
        put(w,GN,0)
        if get(w,72)==0:
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return finish(o,w,5,190)
        put(w,72,get(w,72)-1)
        zero(w,88,40)
        put(o,MS,4)
        put(o,RETURN_STATE,4)
        put(o,RETIRED,1)
        put(o,PENDING,0)
        if get(o,OP)==1:
            put(o,CONSUMED,1)
        return finish(o,w,get(o,STATUS),get(o,DETAIL))
    if phase==850:
        if r!=0:
            put(o,KNOWN,0)
            put(o,PENDING,1)
            put(o,STATUS,5)
            put(o,DETAIL,r)
        return unlock(o)
    if phase==900:
        put(o,HELD,0)
        return system(o,901,202,1,64,129,2147483647,0,0,0)
    if phase==901:
        return reply(o)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word(s,0)!=Q or word(s,8)>4 or length(o)<OUT or length(w)!=2048:
        return BAD
    i=16
    while i<128:
        if word(s,8)!=3 or i<24 or i>40:
            if word(s,i)!=0:
                return BAD
        i=i+8
    zero(o,144,368)
    zero(o,M,512)
    zero(o,RESULT,192)
    put(o,OP,word(s,8))
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def locked(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,64)!=1 or get(w,80)!=1:
        return finish(o,w,8,0)
    if get(w,GP)==0:
        if get(w,GN)!=0:
            return quarantine(o,w,13)
        if get(o,OP)==1 or get(o,OP)==4:
            put(o,RETURN_STATE,4)
            put(o,RETIRED,1)
            return finish(o,w,0,0)
        if get(o,OP)!=0 or get(w,112)!=0 or get(w,72)!=0:
            return finish(o,w,6,0)
        i=88
        while i<112:
            if get(w,i)!=0:
                return finish(o,w,6,i)
            i=i+8
        put(w,72,1)
        put(w,112,2)
        return system(o,10,9,0,0,WORK,3,34,NONE,0)
    if get(w,GN)!=WORK or get(w,GP)>NONE-WORK:
        return quarantine(o,w,14)
    return memory(o,11,0,get(w,GP)+CONTROL,3,M,512)

def existing(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(o,OP)
    state=get(o,MS)
    if state==5:
        put(o,KNOWN,0)
        put(o,PENDING,1)
        return finish(o,w,5,get(o,LAST_DETAIL))
    if op==0:
        return finish(o,w,6,0)
    if op==2:
        if state!=2 or get(w,112)!=1:
            return finish(o,w,6,0)
        return resource(o,w,60,2)
    if op==3:
        if state!=2 and state!=3:
            return finish(o,w,6,0)
        request(o,3)
        copy_source(s,o,24,REQUEST+24,24)
        return resource_call(o,w,60)
    if op==4 and state==2:
        return resource(o,w,60,4)
    if op==4 and state==1:
        return initialize(o,w)
    if state==2:
        if get(w,72)!=1:
            return finish(o,w,6,get(w,72))
        return resource(o,w,100,1)
    if state==1 and op==1:
        put(o,MS,3)
        put(o,STAGE,100)
    if get(o,MS)!=3:
        return finish(o,w,8,0)
    return closing(o,w)

def initialize(o:mutbuf,w:mutbuf) -> u32:
    stage=get(o,STAGE)
    if stage==20:
        put(o,STARTED,1)
        return resource(o,w,20,0)
    if stage==30:
        return resource(o,w,30,2)
    if stage==40:
        if get(o,DUP_INDEX)<3:
            return system(o,40,72,0,get(o,TOOLS+get(o,DUP_INDEX)*8),1030,3,0,0,0)
        put(w,112,1)
        put(w,120,0)
        put(o,BANK_READY,1)
        put(o,STAGE,44)
        stage=44
    if stage==44:
        if get(o,CAP)==0:
            return quarantine(o,w,46)
        request(o,3)
        within(o,REQUEST+24,CAP,24)
        return resource_call(o,w,44)
    if stage==45:
        return resource(o,w,45,4)
    return quarantine(o,w,47)

def initial_failure(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    if status==0:
        status=1
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    put(o,MS,3)
    put(o,STAGE,100)
    return closing(o,w)

def closing(o:mutbuf,w:mutbuf) -> u32:
    put(o,MS,3)
    stage=get(o,STAGE)
    if get(o,CAP)!=0:
        request(o,3)
        within(o,REQUEST+24,CAP,24)
        return resource_call(o,w,101)
    if get(o,STARTED)!=3:
        put(o,STAGE,110)
        return resource(o,w,110,1)
    put(w,112,2)
    put(o,STAGE,120)
    i=0
    while i<3:
        if get(w,88+i*8)!=0:
            put(o,SAVE_SLOT,88+i*8)
            return system(o,120,436,0,get(w,88+i*8),get(w,88+i*8),0,0,0,0)
        i=i+1
    put(o,STAGE,190)
    return system(o,190,11,0,get(w,GP),WORK,0,0,0,0)

def resource_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=RR:
        return 0
    if get(o,CHILD+88)>1 or get(o,CHILD+96)>1 or get(o,CHILD+80)>1 or get(o,CHILD+104)>1:
        return 0
    return 1

def cap_shape(o:mutbuf,at:u64) -> u64:
    if get(o,at)==0 or get(o,at+8)==0 or get(o,at+16)==0:
        return 0
    return 1

def request(o:mutbuf,op:u64) -> u64:
    zero(o,REQUEST,128)
    zero(o,CHILD,192)
    put(o,REQUEST,RQ)
    put(o,REQUEST+8,op)
    return 0

def resource(o:mutbuf,w:mutbuf,next:u64,op:u64) -> u32:
    request(o,op)
    return resource_call(o,w,next)

def resource_call(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,MS,5)
    put(o,KNOWN,0)
    put(o,PENDING,1)
    return finish(o,w,5,detail)

def finish(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,STATUS)==0:
        put(o,STATUS,status)
        put(o,DETAIL,detail)
    if get(o,MS)==1 or get(o,MS)==3 or get(o,MS)==5:
        put(o,PENDING,1)
    if get(o,RETURN_STATE)==0:
        put(o,RETURN_STATE,get(o,MS))
    if get(w,GP)!=0 and get(w,GN)==WORK:
        put(o,LAST_STATUS,get(o,STATUS))
        put(o,LAST_DETAIL,get(o,DETAIL))
        return memory(o,850,3,M,0,get(w,GP)+CONTROL,512)
    return unlock(o)

def unlock(o:mutbuf) -> u32:
    put(o,PH,900)
    return 3

def fail_unlocked(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    return reply(o)

def reply(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,RETURN_STATE))
    put(o,80,get(o,PENDING))
    put(o,88,get(o,KNOWN))
    put(o,96,get(o,CONSUMED))
    put(o,104,get(o,RETIRED))
    put(o,112,get(o,DETAIL))
    put(o,120,get(o,RETURN_COUNT))
    if get(o,DELIVERED)==1:
        within(o,24,RESULT+24,56)
        within(o,128,RESULT+128,40)
    else:
        zero(o,128,40)
    return 0

def lock(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 2

def memory(o:mutbuf,next:u64,sb:u64,sa:u64,db:u64,da:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sb)
    put(o,8,sa)
    put(o,16,db)
    put(o,24,da)
    put(o,32,n)
    return 7

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

def failed(value:u64) -> bool:
    return value>=18446744073709547521
def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
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
def within(w:mutbuf,to:u64,from_at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,from_at+i))
        i=i+1
    return 0
def copy_source(s:readbuf,o:mutbuf,si:u64,oi:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,oi+i,byte(s,si+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    tree=document(source_program(),'generation_runtime_global')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_global.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
