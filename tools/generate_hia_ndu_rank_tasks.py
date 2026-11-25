"""Native dynamic-arena continuations for the complete NDU rank owner.

Only HIA chooses operations, frames, role arguments, extents, deadlines and
ownership. The fixed mechanical bridge performs memory movement, allocation,
raw syscalls and calls to source-bound roles; it has no rank decisions.
Grow action 2 preserves the last role/syscall feedback, updates the private
arena pointer/extent, and sets ALLOC_FAILED on failure.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
CONSTANTS={
 'NONE':(1<<64)-1,'MAXSIZE':(1<<63)-1,
 'PHASE':0,'FEEDBACK':8,'CAPACITY':16,'TOP':24,'PERMANENT':32,
 'NORMALIZER_FD':48,'PROOF_FD':56,'SOURCE_ROOT_FD':64,'THRESHOLD_PTR':72,'THRESHOLD_N':80,'INT_DIGITS':88,'PAYLOAD_CTX':96,'CANCEL_WORD':104,'ALLOC_FAILED':112,
 'TASK':128,'STEP':136,'RESUME':144,'BASE':152,'INPUT_REGION':160,'INPUT_AT':168,'INPUT_N':176,'ARENA_AT':184,'ARENA_N':192,'ROOT_NODE':200,
 'PARAM':208,'PARAM2':216,'PARAM3':224,'PARAM4':232,'PARAM5':240,'PARAM6':248,
 'DESC':256,'ROLE_ID':264,'SELECTORS':272,'ARG0':280,
 'RET_STATUS':512,'RET_AT':520,'RET_N':528,'RET_ARENA':536,'RET_ARENA_N':544,'RET_AUX':552,'RET_WORK':560,'RET_WORK_N':568,
 'V0':600,'V1':608,'V2':616,'V3':624,'V4':632,'V5':640,'V6':648,'V7':656,'V8':664,'V9':672,'V10':680,'V11':688,
 'META':2048,'SMALL_WORK':2176,'DIGEST_OUT':3072,
 'JSON_ROLE':1,'CANONICAL_ROLE':2,'SNAPSHOT_ROLE':3,'STRUCTURE_ROLE':4,'FREEZE_ROLE':5,'ADMISSION_ROLE':6,'BINARY64_ROLE':7,'FORMAT_ROLE':8,'COST_ROLE':9,'BUDGET_ROLE':10,'UNCHANGED_ROLE':11,'BINDING_ROLE':12,'SELECTION_ROLE':13,'REPORT_ROLE':14,'SHA_ROLE':15,'PROCESS_ROLE':16,'NATIVE_DIGITS':3544411265436830024,'NATIVE_ROLE':17,'PAYLOAD_ROLE':18,'NATIVE_ERROR_ROLE':19,'CAPTURE_ROLE':20,
 'T_DECODE':1,'T_CANONICAL':2,'T_PROCESS':3,'T_SHA':4,'T_REPORT':5,'T_CALL':6,'T_ASSEMBLE':7,'T_FD_READ':8,
 'FRAME_HEADER':54528,'FRAME_PARTS':55296,'FRAME_COUNT':56832,'FRAME_HEADER_N':56840,
 'FREEZE_REQUEST':int.from_bytes(b'HIABJF01','little'),'FREEZE_REPLY':int.from_bytes(b'HIABJR01','little'),
 'CANON_REQUEST':int.from_bytes(b'HIANJQ01','little'),'CANON_REPLY':int.from_bytes(b'HIANKJ01','little'),
 'JSON_SIZE':int.from_bytes(b'HIANJS01','little'),'PROCESS_REQUEST':int.from_bytes(b'HIANPS01','little'),'PROCESS_REPLY':int.from_bytes(b'HIANPO01','little'),'REPORT_REPLY':int.from_bytes(b'HIANPR01','little')
}
SOURCE=r'''
def rank_tasks(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<65536:
        return 4294967293
    task=get(o,TASK)
    if task==T_DECODE:
        return decode(s,o,w)
    if task==T_CANONICAL:
        return canonical(s,o,w)
    if task==T_PROCESS:
        return process(s,o,w)
    if task==T_SHA:
        return hash_bytes(s,o,w)
    if task==T_REPORT:
        return report(s,o,w)
    if task==T_CALL:
        return pure_call(s,o,w)
    if task==T_ASSEMBLE:
        return assemble(s,o,w)
    if task==T_FD_READ:
        return fd_read(s,o,w)
    return finish(o,4)

def finish(o:mutbuf,status:u64) -> u32:
    put(o,RET_STATUS,status)
    put(o,TASK,0)
    put(o,PHASE,get(o,RESUME))
    return 3

def needed(o:mutbuf,w:mutbuf,n:u64) -> bool:
    if n>MAXSIZE or get(o,ALLOC_FAILED)!=0:
        put(o,ALLOC_FAILED,1)
        return False
    if n<=length(w):
        return True
    capacity=length(w)
    if capacity<1048576:
        capacity=1048576
    while capacity<n:
        if capacity>MAXSIZE//2:
            capacity=n
        else:
            capacity=capacity*2
    if capacity>MAXSIZE-4095:
        capacity=MAXSIZE-4095
    if capacity<n:
        put(o,ALLOC_FAILED,1)
        return False
    put(o,DESC,(capacity+4095)&18446744073709547520)
    return False

def need_result(o:mutbuf) -> u32:
    if get(o,ALLOC_FAILED)!=0:
        return finish(o,3)
    return 2

def call(o:mutbuf,role:u64,sr:u64,sp:u64,sn:u64,orr:u64,op:u64,on:u64,wr:u64,wp:u64,wn:u64) -> u32:
    put(o,ROLE_ID,role)
    put(o,SELECTORS,sr|(orr<<4)|(wr<<8))
    put(o,ARG0,sp)
    put(o,ARG0+8,sn)
    put(o,ARG0+16,op)
    put(o,ARG0+24,on)
    put(o,ARG0+32,wp)
    put(o,ARG0+40,wn)
    return 4

def move(o:mutbuf,dr:u64,dp:u64,sr:u64,sp:u64,n:u64) -> u32:
    put(o,SELECTORS,dr|(sr<<2))
    put(o,ARG0,dp)
    put(o,ARG0+8,sp)
    put(o,ARG0+16,n)
    return 5

def syscall(o:mutbuf,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,ROLE_ID,nr)
    put(o,SELECTORS,mask)
    put(o,ARG0,a)
    put(o,ARG0+8,b)
    put(o,ARG0+16,c)
    put(o,ARG0+24,d)
    put(o,ARG0+32,e)
    put(o,ARG0+40,f)
    return 1

def decode(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    if step==0:
        zero(o,SMALL_WORK,128)
        put(o,STEP,1)
        return call(o,decode_role(o),get(o,INPUT_REGION),get(o,INPUT_AT),get(o,INPUT_N),3,META,64,3,SMALL_WORK,128)
    if step==1:
        if get(o,FEEDBACK)!=0 or get(o,META)!=JSON_SIZE:
            return finish(o,1)
        ac=get(o,META+32)
        wc=get(o,META+40)
        base=get(o,BASE)
        if ac>MAXSIZE-base or wc>MAXSIZE-base-ac:
            put(o,ALLOC_FAILED,1)
            return finish(o,3)
        if needed(o,w,base+ac+wc)==False:
            return need_result(o)
        put(o,V0,base+ac)
        put(o,V1,wc)
        zero(w,base+ac,128)
        put(w,base+ac+48,get(o,META+8))
        put(w,base+ac+56,get(o,META+24))
        put(w,base+ac+96,get(o,META+16))
        put(w,base+ac+104,1)
        put(o,STEP,2)
        return call(o,decode_role(o),get(o,INPUT_REGION),get(o,INPUT_AT),get(o,INPUT_N),1,base,ac,1,base+ac,wc)
    if step==2:
        if get(o,FEEDBACK)!=0:
            return finish(o,1)
        base=get(o,BASE)
        n=get(w,base+24)
        if n<64 or n>get(o,META+32):
            return finish(o,4)
        put(o,RET_ARENA,base)
        put(o,RET_ARENA_N,n)
        put(o,RET_AT,get(o,INPUT_AT))
        put(o,RET_N,get(o,INPUT_N))
        put(o,TOP,base+n)
        return finish(o,0)
    return finish(o,4)

def decode_role(o:mutbuf) -> u64:
    if get(o,PARAM)==1:
        return CAPTURE_ROLE
    return JSON_ROLE

def fd_read(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        fd=get(o,PARAM)
        if fd<3 or fd>2147483647:
            return finish(o,4)
        put(o,V0,fd)
        put(o,V1,get(o,PARAM2))
        put(o,V2,0)
        put(o,V3,0)
        put(o,STEP,1)
        return 3
    if step==1:
        n=get(o,V1)
        if base>MAXSIZE or n>MAXSIZE-base:
            put(o,V3,3)
            put(o,STEP,8)
            return 3
        if needed(o,w,base+n)==False:
            if get(o,ALLOC_FAILED)!=0:
                put(o,V3,3)
                put(o,STEP,8)
                return 3
            return 2
        put(o,STEP,2)
        return 3
    if step==2:
        at=get(o,V2)
        if at==get(o,V1):
            put(o,STEP,8)
            return 3
        amount=get(o,V1)-at
        if amount>65536:
            amount=65536
        put(o,V4,amount)
        put(o,STEP,3)
        return syscall(o,17,4,get(o,V0),base+at,amount,at,0,0)
    if step==3:
        value=get(o,FEEDBACK)
        if value==18446744073709551612:
            put(o,STEP,2)
            return 3
        if value==0 or value>get(o,V4):
            put(o,V3,4)
            put(o,STEP,8)
            return 3
        put(o,V2,get(o,V2)+value)
        put(o,STEP,2)
        return 3
    if step==8:
        fd=get(o,V0)
        put(o,V0,NONE)
        put(o,STEP,9)
        return syscall(o,3,0,fd,0,0,0,0,0)
    if step==9:
        if get(o,FEEDBACK)!=0 and get(o,V3)==0:
            put(o,V3,4)
        if get(o,V3)!=0:
            return finish(o,get(o,V3))
        put(o,TOP,base+get(o,V1))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,V1))
        return finish(o,0)
    return finish(o,4)

def canonical(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        jn=get(o,INPUT_N)
        an=get(o,ARENA_N)
        if jn>MAXSIZE-base-128 or an>MAXSIZE-base-128-jn:
            return finish(o,3)
        total=128+jn+an
        count=get(w,get(o,ARENA_AT)+8)
        wc=131072+count
        if an+16384>wc:
            wc=an+16384
        if wc>MAXSIZE-base-total:
            return finish(o,3)
        if needed(o,w,base+total+wc)==False:
            return need_result(o)
        put(o,V0,total)
        put(o,V1,base+total)
        put(o,V2,wc)
        zero(w,base,128)
        put(w,base,CANON_REQUEST)
        if get(o,PARAM)==1:
            put(w,base,FREEZE_REQUEST)
            put(w,base+40,get(o,INT_DIGITS))
        put(w,base+16,get(o,ROOT_NODE))
        put(w,base+24,jn)
        put(w,base+32,an)
        put(o,STEP,1)
        return move(o,1,base+128,get(o,INPUT_REGION),get(o,INPUT_AT),jn)
    if step==1:
        put(o,STEP,2)
        return move(o,1,base+128+get(o,INPUT_N),1,get(o,ARENA_AT),get(o,ARENA_N))
    if step==2:
        put(o,STEP,3)
        return call(o,canonical_role(o),1,base,get(o,V0),3,META,1024,1,get(o,V1),get(o,V2))
    if step==3:
        if get(o,FEEDBACK)==4294967280:
            return finish(o,2)
        if get(o,FEEDBACK)!=0 or get(o,META)!=canonical_reply(o):
            return finish(o,4)
        if get(o,PARAM)==1 and get(o,META+8)!=0:
            n=get(o,META+32)
            if n==0 or n>896:
                return finish(o,4)
            put(o,V4,n)
            put(o,STEP,6)
            return move(o,1,base,3,META+128,n)
        n=get(o,META+canonical_count(o))
        at=get(o,V1)+get(o,V2)
        if n>MAXSIZE-at-canonical_header(o):
            return finish(o,3)
        if needed(o,w,at+canonical_header(o)+n)==False:
            return need_result(o)
        put(o,V3,at)
        put(o,V4,n)
        put(w,base+8,1)
        put(o,STEP,4)
        return call(o,canonical_role(o),1,base,get(o,V0),1,at,n+canonical_header(o),1,get(o,V1),get(o,V2))
    if step==4:
        if get(o,FEEDBACK)!=0 or get(w,get(o,V3))!=canonical_reply(o) or get(w,get(o,V3)+canonical_count(o))!=get(o,V4):
            return finish(o,4)
        put(o,STEP,5)
        return move(o,1,base,1,get(o,V3)+canonical_header(o),get(o,V4))
    if step==6:
        put(o,TOP,base+get(o,V4))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,V4))
        return finish(o,7)
    if step==5:
        put(o,TOP,base+get(o,V4))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,V4))
        return finish(o,0)
    return finish(o,4)

def canonical_role(o:mutbuf) -> u64:
    if get(o,PARAM)==1:
        return FREEZE_ROLE
    return CANONICAL_ROLE

def canonical_header(o:mutbuf) -> u64:
    if get(o,PARAM)==1:
        return 128
    return 64

def canonical_reply(o:mutbuf) -> u64:
    if get(o,PARAM)==1:
        return FREEZE_REPLY
    return CANON_REPLY

def canonical_count(o:mutbuf) -> u64:
    if get(o,PARAM)==1:
        return 24
    return 8

def assemble(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        count=get(o,FRAME_COUNT)
        if count>64 or get(o,FRAME_HEADER_N)>768:
            return finish(o,4)
        total=get(o,FRAME_HEADER_N)
        i=0
        while i<count:
            n=get(o,FRAME_PARTS+i*24+16)
            if n>MAXSIZE-total:
                return finish(o,3)
            total=total+n
            i=i+1
        if total>MAXSIZE-base:
            return finish(o,3)
        if needed(o,w,base+total)==False:
            return need_result(o)
        put(o,V0,total)
        put(o,V1,0)
        put(o,V2,get(o,FRAME_HEADER_N))
        put(o,STEP,1)
        return move(o,1,base,3,FRAME_HEADER,get(o,FRAME_HEADER_N))
    if step==1:
        i=get(o,V1)
        if i==get(o,FRAME_COUNT):
            put(o,TOP,base+get(o,V0))
            put(o,RET_AT,base)
            put(o,RET_N,get(o,V0))
            return finish(o,0)
        descriptor=FRAME_PARTS+i*24
        n=get(o,descriptor+16)
        put(o,V1,i+1)
        put(o,V2,get(o,V2)+n)
        return move(o,1,base+get(o,V2)-n,get(o,descriptor),get(o,descriptor+8),n)
    return finish(o,4)

def process(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        n=get(o,INPUT_N)
        if n>MAXSIZE-base-128-20971520:
            return finish(o,3)
        if needed(o,w,base+128+n+20971520)==False:
            return need_result(o)
        put(o,V0,base+128+n)
        put(o,V2,NONE)
        put(o,V3,NONE)
        put(o,V6,0)
        zero(w,base,128)
        put(w,base,PROCESS_REQUEST)
        put(w,base+8,get(o,PARAM))
        put(w,base+16,get(o,PARAM2))
        put(w,base+24,get(o,PARAM3))
        put(w,base+32,n)
        put(w,base+40,get(o,PARAM4))
        put(w,base+48,get(o,PARAM5))
        put(w,base+64,get(o,PARAM6))
        put(o,STEP,1)
        return move(o,1,base+128,get(o,INPUT_REGION),get(o,INPUT_AT),n)
    if step==1:
        put(o,STEP,2)
        return call(o,PROCESS_ROLE,1,base,128+get(o,INPUT_N),3,META,128,1,get(o,V0),20971520)
    if step==2:
        if get(o,FEEDBACK)>5 or get(o,META)!=PROCESS_REPLY or get(o,META+8)!=get(o,FEEDBACK):
            return finish(o,4)
        put(o,V7,get(o,META+24))
        put(o,RET_AUX,get(o,META+24))
        put(o,RET_WORK,get(o,META+8))
        if get(o,META+8)!=0:
            if get(o,META+8)==2:
                return finish(o,5)
            return finish(o,6)
        put(o,V2,get(o,META+48))
        put(o,V3,get(o,META+56))
        put(o,V4,get(o,META+64))
        put(o,V5,get(o,META+72))
        put(o,STEP,3)
        return 3
    if step==3:
        if get(o,V4)>MAXSIZE-base or get(o,V5)>MAXSIZE-base-get(o,V4):
            put(o,V6,3)
            put(o,STEP,8)
            return 3
        if needed(o,w,base+get(o,V4)+get(o,V5))==False:
            if get(o,ALLOC_FAILED)!=0:
                put(o,V6,3)
                put(o,STEP,8)
                return 3
            return 2
        put(o,V9,0)
        put(o,V10,0)
        put(o,STEP,4)
        return 3
    if step==4:
        if get(o,V10)>1:
            put(o,STEP,8)
            return 3
        n=get(o,V4+get(o,V10)*8)
        at=get(o,V9)
        if at==n:
            put(o,V10,get(o,V10)+1)
            put(o,V9,0)
            return 3
        amount=n-at
        if amount>65536:
            amount=65536
        target=base+at
        if get(o,V10)==1:
            target=target+get(o,V4)
        put(o,V11,amount)
        put(o,STEP,5)
        return syscall(o,17,4,get(o,V2+get(o,V10)*8),target,amount,at,0,0)
    if step==5:
        value=get(o,FEEDBACK)
        if value==18446744073709551612:
            put(o,STEP,4)
            return 3
        if value==0 or value>get(o,V11):
            put(o,V6,4)
            put(o,STEP,8)
            return 3
        put(o,V9,get(o,V9)+value)
        put(o,STEP,4)
        return 3
    if step==8:
        if get(o,V2)!=NONE:
            fd=get(o,V2)
            put(o,V2,NONE)
            put(o,STEP,9)
            return syscall(o,3,0,fd,0,0,0,0,0)
        put(o,STEP,10)
        return 3
    if step==9:
        if get(o,FEEDBACK)!=0:
            put(o,V6,4)
        put(o,STEP,10)
        return 3
    if step==10:
        if get(o,V3)!=NONE:
            fd=get(o,V3)
            put(o,V3,NONE)
            put(o,STEP,11)
            return syscall(o,3,0,fd,0,0,0,0,0)
        put(o,STEP,12)
        return 3
    if step==11:
        if get(o,FEEDBACK)!=0:
            put(o,V6,4)
        put(o,STEP,12)
        return 3
    if step==12:
        if get(o,V6)!=0:
            return finish(o,get(o,V6))
        put(o,TOP,base+get(o,V4)+get(o,V5))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,V4))
        put(o,RET_ARENA,base+get(o,V4))
        put(o,RET_ARENA_N,get(o,V5))
        put(o,RET_AUX,get(o,V7))
        return finish(o,0)
    return finish(o,4)

def hash_bytes(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        if get(o,INPUT_N)>2305843009213693951:
            return finish(o,4)
        if needed(o,w,base+65552+1184)==False:
            return need_result(o)
        put(o,V0,0)
        put(o,V1,0)
        store(w,base,0)
        put(o,STEP,1)
        return call(o,SHA_ROLE,1,base,1,3,DIGEST_OUT,32,1,base+65552,1184)
    if step==1:
        if get(o,FEEDBACK)!=0:
            return finish(o,4)
        put(o,V0,get(o,V0)+get(o,V1))
        if get(o,V0)==get(o,INPUT_N):
            store(w,base,2)
            put(o,STEP,4)
            return call(o,SHA_ROLE,1,base,1,3,DIGEST_OUT,32,1,base+65552,1184)
        amount=get(o,INPUT_N)-get(o,V0)
        if amount>65536:
            amount=65536
        put(o,V1,amount)
        store(w,base,1)
        put(o,STEP,2)
        return move(o,1,base+1,get(o,INPUT_REGION),get(o,INPUT_AT)+get(o,V0),amount)
    if step==2:
        put(o,STEP,1)
        return call(o,SHA_ROLE,1,base,1+get(o,V1),3,DIGEST_OUT,32,1,base+65552,1184)
    if step==4:
        if get(o,FEEDBACK)!=32:
            return finish(o,4)
        put(o,TOP,base)
        put(o,RET_AT,DIGEST_OUT)
        put(o,RET_N,32)
        return finish(o,0)
    return finish(o,4)

def report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        end=get(o,INPUT_AT)+get(o,INPUT_N)
        if get(o,INPUT_REGION)!=1 or end<get(o,INPUT_AT):
            return finish(o,4)
        if end<base:
            end=base
        if needed(o,w,end+4096)==False:
            return need_result(o)
        put(o,V0,end)
        put(w,get(o,INPUT_AT)+16,0)
        put(o,STEP,1)
        return call(o,REPORT_ROLE,1,get(o,INPUT_AT),get(o,INPUT_N),3,META,64,1,end,4096)
    if step==1:
        if get(o,FEEDBACK)!=0 or get(o,META)!=REPORT_REPLY:
            return finish(o,4)
        n=get(o,META+8)
        at=get(o,V0)+4096
        if n>MAXSIZE-at-64:
            return finish(o,3)
        if needed(o,w,at+64+n)==False:
            return need_result(o)
        put(o,V1,at)
        put(o,V2,n)
        put(w,get(o,INPUT_AT)+16,1)
        put(o,STEP,2)
        return call(o,REPORT_ROLE,1,get(o,INPUT_AT),get(o,INPUT_N),1,at,64+n,1,get(o,V0),4096)
    if step==2:
        if get(o,FEEDBACK)!=0 or get(w,get(o,V1))!=REPORT_REPLY or get(w,get(o,V1)+8)!=get(o,V2):
            return finish(o,4)
        put(o,STEP,3)
        return move(o,1,base,1,get(o,V1)+64,get(o,V2))
    if step==3:
        put(o,TOP,base+get(o,V2))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,V2))
        return finish(o,0)
    return finish(o,4)

def pure_call(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    step=get(o,STEP)
    base=get(o,BASE)
    if step==0:
        on=get(o,PARAM3)
        wn=get(o,PARAM2)
        if get(o,PARAM)==NATIVE_ROLE and wn<201326592:
            return finish(o,4)
        if on>MAXSIZE-base or wn>MAXSIZE-base-on:
            return finish(o,3)
        if needed(o,w,base+on+wn)==False:
            return need_result(o)
        amount=wn
        if amount>128:
            amount=128
        zero(w,base+on,amount)
        if get(o,PARAM)==NATIVE_ROLE:
            put(w,base+on+24,get(o,SOURCE_ROOT_FD))
            put(w,base+on+32,get(o,CANCEL_WORD))
            put(w,base+on+2240,NATIVE_DIGITS)
            put(w,base+on+2248,get(o,INT_DIGITS))
        put(o,STEP,1)
        return call(o,get(o,PARAM),get(o,INPUT_REGION),get(o,INPUT_AT),get(o,INPUT_N),1,base,on,1,base+on,wn)
    if step==1:
        put(o,RET_AUX,get(o,FEEDBACK))
        put(o,RET_AT,base)
        put(o,RET_N,get(o,PARAM3))
        put(o,RET_WORK,base+get(o,PARAM3))
        put(o,RET_WORK_N,get(o,PARAM2))
        put(o,TOP,base+get(o,PARAM3))
        if get(o,PARAM5)!=0:
            put(o,TOP,base+get(o,PARAM3)+get(o,PARAM2))
        return finish(o,0)
    return finish(o,4)

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

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
'''
def source_program():
 text=SOURCE
 for key,value in sorted(CONSTANTS.items(),key=lambda x:-len(x[0])):
  text=re.sub(r'\b'+key+r'\b',str(value),text)
 return text
def program():return document(source_program(),'ndu_rank_tasks')
if __name__=='__main__':
 path=ROOT/'examples/hia_bootstrap/ndu_rank_tasks.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
