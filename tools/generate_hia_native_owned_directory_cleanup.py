"""Native owned-directory recursive cleanup with captured FD identity.

Every directory level owns a native frame and FD. Paths are single leaf names
relative to held directories; neither a fixed recursion depth nor a total-path
limit is imposed. The fixed bridge performs only selected syscalls and copies.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIARMTQ1','little'),R=int.from_bytes(b'HIARMTR1','little'),
 CTX=int.from_bytes(b'HIARMCX1','little'),BAD=4294967293,NONE=(1<<64)-1,
 PH=128,FB=136,OP=144,STATUS=152,ERROR=160,PENDING=168,RETIRED=176,KNOWN=184,
 PID=192,SELF=200,AFTER=208,HELD=216,DETAIL=224,
 STATE=32,STAGE=40,ROOTFD=48,PARENTFD=56,LEAF=64,LEAFN=72,LEAFEXT=80,TOP=88,
 ROOTDEV=96,ROOTINO=104,FDS=112,MAPS=120,VISITED=128,REMOVED=136,DEPTH=144,
 ROOT_REMOVED=152,PRIMARY=160,FAILPH=168,CLEANERR=176,ABORT=184,CLOSE_MODE=192,
 UNKNOWN=200,SOURCE_ROOT=256,SOURCE_PARENT=264,CHILDFD=280,NEWFRAME=288,
 ENTRY_PTR=304,ENTRY_N=312,RECLEN=320,ENTRY_DEV=336,ENTRY_INO=344,
 CLOSE_NEXT=360,CLOSE_KIND=368,SAVED_PARENT=376,PREV=392,
 PERM_NEXT=400,PERM_KIND=408,PERM_FD=416,PERM_DEV=424,PERM_INO=432,PERM_MODE=440,
 PERM_USED=448,PERM_FAILURE=456,PERM_PATH=1600,PERM_DIGITS=1680,
 PROC0=int.from_bytes(b'/proc/se','little'),PROC1=int.from_bytes(b'lf/fd/\0\0','little'),
 FRAME=512,STAT1=768,STAT2=1024,ENTRY=4096,FRAME_SIZE=36864,BUFFER_SIZE=32768)
SOURCE=r'''
def rmtree(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        return system(o,2,39,0,0,0,0,0,0,0)
    if phase==2:
        if r<2 or r>2147483647:
            put(o,STATUS,4)
            put(o,ERROR,r)
            put(o,RETIRED,1)
            return reply(o,w)
        put(o,PID,r)
        if get(w,0)!=0:
            if get(w,0)!=CTX or get(w,8)!=r or get(w,16)!=get(o,SELF):
                return BAD
        return lock(o,3)
    if phase==3:
        if r==0:
            put(o,HELD,1)
            return locked(s,o,w)
        if r!=1:
            return BAD
        put(o,272,0)
        put(o,280,1000000)
        return system(o,4,202,193,24,128,1,272,0,0)
    if phase==4:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            put(o,STATUS,4)
            put(o,ERROR,r)
            return reply(o,w)
        return lock(o,3)
    if phase==10:
        return drive(s,o,w)
    if phase>=100 and phase<=109:
        return capture(s,o,w,phase,r)
    if phase>=110 and phase<=155:
        return walk(s,o,w,phase,r)
    if phase>=190 and phase<=212:
        return finish_directory(s,o,w,phase,r)
    if phase>=300 and phase<=321:
        return pop_frame(s,o,w,phase,r)
    if phase>=700 and phase<=715:
        return permission_result(s,o,w,phase,r)
    if phase==901:
        if r!=0:
            return pending(o,w,r,901)
        put(w,NEWFRAME,0)
        put(w,MAPS,get(w,MAPS)-1)
        return again(o,10)
    if phase==902:
        if r!=0:
            return pending(o,w,r,902)
        put(w,LEAF,0)
        put(w,LEAFEXT,0)
        put(w,MAPS,get(w,MAPS)-1)
        return again(o,10)
    if phase==950:
        if r==18446744073709551578:
            put(w,CLOSE_MODE,1)
            return system(o,951,3,0,closing_fd(w),0,0,0,0,0)
        return closed(o,w,r,False)
    if phase==951:
        return closed(o,w,r,True)
    if phase==980:
        put(o,HELD,0)
        return system(o,981,202,1,24,129,2147483647,0,0,0)
    if phase==981:
        if failed(r) and get(o,STATUS)==0:
            put(o,STATUS,11)
            put(o,ERROR,r)
        return reply(o,w)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)!=65536 or length(w)!=4096:
        return BAD
    if word_load(s,0)!=Q or word_load(s,8)>2:
        return BAD
    op=word_load(s,8)
    start=16
    if op==0:
        n=word_load(s,32)
        if word_load(s,16)>2147483647 or word_load(s,24)>2147483647:
            return BAD
        if n==0 or n>9223372036854771679 or n!=length(s)-128:
            return BAD
        i=0
        while i<n:
            c=byte(s,128+i)
            if c==0 or c==47:
                return BAD
            i=i+1
        if n==1 and byte(s,128)==46:
            return BAD
        if n==2 and byte(s,128)==46 and byte(s,129)==46:
            return BAD
        start=40
    elif length(s)!=128:
        return BAD
    i=start
    while i<128:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    zero(o,144,368)
    put(o,OP,op)
    put(o,KNOWN,1)
    put(o,PH,1)
    return 15

def locked(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,0)==0:
        i=0
        while i<4096:
            if i!=24 and get(w,i)!=0:
                put(o,STATUS,6)
                return unlock(o)
            i=i+8
        zero(w,32,4064)
        put(w,8,get(o,PID))
        put(w,16,get(o,SELF))
        put(w,STATE,1)
        put(w,ROOTFD,NONE)
        put(w,PARENTFD,NONE)
        put(w,CHILDFD,NONE)
        put(w,PERM_FD,NONE)
        put(w,0,CTX)
    if get(w,STATE)==4:
        put(o,STATUS,11)
        put(o,PENDING,1)
        put(o,KNOWN,0)
        return unlock(o)
    if get(w,STATE)==3:
        if get(o,OP)==0:
            put(o,STATUS,6)
        else:
            put(o,RETIRED,1)
            put(o,STATUS,choose(get(w,PRIMARY)!=0,4,0))
            put(o,ERROR,get(w,PRIMARY))
        return unlock(o)
    if get(o,OP)==0:
        if get(w,STAGE)!=0:
            put(o,STATUS,6)
            return unlock(o)
        put(w,SOURCE_ROOT,word_load(s,16))
        put(w,SOURCE_PARENT,word_load(s,24))
        put(w,LEAFN,word_load(s,32))
        put(w,STAGE,10)
    else:
        if get(o,OP)==2:
            put(w,ABORT,1)
            put(w,STAGE,900)
        else:
            put(w,PRIMARY,0)
            put(w,FAILPH,0)
            put(w,CLEANERR,0)
            if get(w,STAGE)==0:
                put(w,ABORT,1)
                put(w,STAGE,900)
        put(w,STATE,1)
        put(w,PERM_USED,0)
    return drive(s,o,w)

def drive(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    stage=get(w,STAGE)
    if stage==10:
        return system(o,100,72,0,get(w,SOURCE_ROOT),1030,3,0,0,0)
    if stage==11:
        return system(o,101,72,0,get(w,SOURCE_PARENT),1030,3,0,0,0)
    if stage==12:
        n=(get(w,LEAFN)+4096)&18446744073709547520
        put(w,LEAFEXT,n)
        return system(o,102,9,0,0,n,3,34,NONE,0)
    if stage==13:
        return memory(o,103,2,128,0,get(w,LEAF),get(w,LEAFN))
    if stage==14:
        return system(o,104,5,4,get(w,ROOTFD),STAT1,0,0,0,0)
    if stage==15:
        return system(o,105,262,16,get(w,PARENTFD),get(w,LEAF),STAT2,256,0,0)
    if stage==16:
        return system(o,106,9,0,0,FRAME_SIZE,3,34,NONE,0)
    if stage==17:
        return system(o,108,257,4,get(w,ROOTFD),1536,720896,0,0,0)
    if stage==18:
        return system(o,109,5,4,get(w,CHILDFD),STAT2,0,0,0,0)
    if stage==100:
        return system(o,110,217,0,get(w,FRAME+16),get(w,FRAME+80),BUFFER_SIZE,0,0,0)
    if stage==110:
        if get(w,FRAME+64)>=get(w,FRAME+56):
            put(w,STAGE,100)
            return drive(s,o,w)
        n=get(w,FRAME+56)-get(w,FRAME+64)
        if n<24:
            return pending(o,w,18446744073709551611,110)
        return memory(o,111,0,get(w,FRAME+80)+get(w,FRAME+64),3,ENTRY,n)
    if stage==120:
        return system(o,121,262,16,get(w,FRAME+16),get(w,ENTRY_PTR),STAT1,256,0,0)
    if stage==130:
        return system(o,131,257,0,get(w,FRAME+16),get(w,ENTRY_PTR),720896,0,0,0)
    if stage==140:
        return system(o,141,5,4,get(w,CHILDFD),STAT2,0,0,0,0)
    if stage==150:
        return system(o,151,9,0,0,FRAME_SIZE,3,34,NONE,0)
    if stage==160:
        return system(o,155,263,0,get(w,FRAME+16),get(w,ENTRY_PTR),0,0,0,0)
    if stage==190:
        return system(o,191,8,0,get(w,FRAME+16),0,0,0,0,0)
    if stage==200:
        return system(o,200,262,16,get(w,FRAME+96),get(w,FRAME+24),STAT1,256,0,0)
    if stage==205:
        return system(o,205,5,4,get(w,FRAME+16),STAT2,0,0,0,0)
    if stage==210:
        return system(o,210,263,0,get(w,FRAME+96),get(w,FRAME+24),512,0,0,0)
    if stage==300:
        if get(w,FRAME+16)!=NONE:
            return start_close(o,w,3,310)
        put(w,STAGE,310)
        return drive(s,o,w)
    if stage==310:
        put(w,PREV,get(w,FRAME))
        return system(o,310,11,0,get(w,TOP),FRAME_SIZE,0,0,0,0)
    if stage==320:
        return memory(o,321,0,get(w,TOP),1,FRAME,256)
    if stage>=700 and stage<=714:
        return permission_drive(o,w,stage)
    if stage==900:
        return retire_resources(o,w)
    return pending(o,w,18446744073709551594,stage)

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        if failed(r):
            return abort_failure(s,o,w,r,100)
        put(w,ROOTFD,r)
        put(w,FDS,get(w,FDS)+1)
        put(w,STAGE,11)
        return drive(s,o,w)
    if phase==101:
        if failed(r):
            return abort_failure(s,o,w,r,101)
        put(w,PARENTFD,r)
        put(w,FDS,get(w,FDS)+1)
        put(w,STAGE,12)
        return drive(s,o,w)
    if phase==102:
        if failed(r):
            put(w,LEAFEXT,0)
            return abort_failure(s,o,w,r,102)
        put(w,LEAF,r)
        put(w,MAPS,get(w,MAPS)+1)
        put(w,STAGE,13)
        return drive(s,o,w)
    if phase==103:
        if r!=0:
            return quarantine(o,w,r,103)
        put(w,STAGE,14)
        return drive(s,o,w)
    if phase==104:
        if failed(r):
            return abort_failure(s,o,w,r,104)
        if (get(w,STAT1+24)&61440)!=16384:
            return abort_failure(s,o,w,18446744073709551596,104)
        put(w,ROOTDEV,get(w,STAT1))
        put(w,ROOTINO,get(w,STAT1+8))
        put(w,STAGE,15)
        return drive(s,o,w)
    if phase==105:
        if failed(r):
            return abort_failure(s,o,w,r,105)
        if get(w,STAT2)!=get(w,ROOTDEV) or get(w,STAT2+8)!=get(w,ROOTINO) or (get(w,STAT2+24)&61440)!=16384:
            return abort_failure(s,o,w,18446744073709551500,105)
        put(w,1536,46)
        put(w,STAGE,17)
        return drive(s,o,w)
    if phase==108:
        if failed(r):
            if permission_errno(r):
                return permission_start(o,w,r,108,0,17)
            return abort_failure(s,o,w,r,108)
        put(w,CHILDFD,r)
        put(w,FDS,get(w,FDS)+1)
        put(w,STAGE,18)
        return drive(s,o,w)
    if phase==109:
        if failed(r):
            return abort_failure(s,o,w,r,109)
        if get(w,STAT2)!=get(w,ROOTDEV) or get(w,STAT2+8)!=get(w,ROOTINO) or (get(w,STAT2+24)&61440)!=16384:
            return abort_failure(s,o,w,18446744073709551500,109)
        put(w,STAGE,16)
        return drive(s,o,w)
    if phase==106:
        if failed(r):
            return abort_failure(s,o,w,r,106)
        put(w,TOP,r)
        put(w,MAPS,get(w,MAPS)+1)
        put(w,DEPTH,1)
        put(w,PERM_USED,0)
        zero(w,FRAME,256)
        put(w,FRAME+8,FRAME_SIZE)
        put(w,FRAME+16,get(w,CHILDFD))
        put(w,CHILDFD,NONE)
        put(w,FRAME+24,get(w,LEAF))
        put(w,FRAME+32,get(w,LEAFN))
        put(w,FRAME+40,get(w,ROOTDEV))
        put(w,FRAME+48,get(w,ROOTINO))
        put(w,FRAME+72,1)
        put(w,FRAME+80,r+256)
        put(w,FRAME+96,get(w,PARENTFD))
        put(w,STAGE,100)
        return memory(o,107,1,FRAME,0,get(w,TOP),256)
    if phase==107:
        if r!=0:
            return quarantine(o,w,r,107)
        return drive(s,o,w)
    return BAD

def walk(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==110:
        if failed(r):
            return permission_start(o,w,r,110,1,100)
        if r>BUFFER_SIZE:
            return quarantine(o,w,r,110)
        if r==0:
            put(w,STAGE,200)
            return drive(s,o,w)
        put(w,FRAME+56,r)
        put(w,FRAME+64,0)
        put(w,STAGE,110)
        return drive(s,o,w)
    if phase==111:
        if r!=0:
            return quarantine(o,w,r,111)
        size=get(o,ENTRY+16)&65535
        if size<24 or size>get(w,FRAME+56)-get(w,FRAME+64):
            return pending(o,w,18446744073709551611,111)
        i=19
        while i<size and byte(o,ENTRY+i)!=0:
            if byte(o,ENTRY+i)==47:
                return pending(o,w,18446744073709551611,111)
            i=i+1
        if i==size or i==19:
            return pending(o,w,18446744073709551611,111)
        n=i-19
        put(w,RECLEN,size)
        if n==1 and byte(o,ENTRY+19)==46:
            return next_entry(o,w)
        if n==2 and byte(o,ENTRY+19)==46 and byte(o,ENTRY+20)==46:
            return next_entry(o,w)
        put(w,ENTRY_PTR,get(w,FRAME+80)+get(w,FRAME+64)+19)
        put(w,ENTRY_N,n)
        put(w,VISITED,get(w,VISITED)+1)
        put(w,STAGE,120)
        return drive(s,o,w)
    if phase==121:
        if r==18446744073709551614:
            return next_entry(o,w)
        if failed(r):
            return permission_start(o,w,r,121,2,120)
        if (get(w,STAT1+24)&61440)==16384:
            put(w,ENTRY_DEV,get(w,STAT1))
            put(w,ENTRY_INO,get(w,STAT1+8))
            put(w,STAGE,130)
        else:
            put(w,STAGE,160)
        return drive(s,o,w)
    if phase==131:
        if failed(r):
            put(w,STAGE,120)
            return permission_start(o,w,r,131,2,120)
        put(w,CHILDFD,r)
        put(w,FDS,get(w,FDS)+1)
        put(w,STAGE,140)
        return drive(s,o,w)
    if phase==141:
        if failed(r):
            return pending(o,w,r,141)
        if get(w,STAT2)!=get(w,ENTRY_DEV) or get(w,STAT2+8)!=get(w,ENTRY_INO) or (get(w,STAT2+24)&61440)!=16384:
            put(w,PRIMARY,18446744073709551500)
            put(w,FAILPH,141)
            return start_close(o,w,4,145)
        put(w,STAGE,150)
        return drive(s,o,w)
    if phase==145:
        put(w,STAGE,120)
        return pending(o,w,get(w,PRIMARY),145)
    if phase==151:
        if failed(r):
            return pending(o,w,r,151)
        put(w,NEWFRAME,r)
        put(w,MAPS,get(w,MAPS)+1)
        put(w,FRAME+64,get(w,FRAME+64)+get(w,RECLEN))
        put(w,SAVED_PARENT,get(w,FRAME+16))
        return memory(o,152,1,FRAME,0,get(w,TOP),256)
    if phase==152:
        if r!=0:
            return quarantine(o,w,r,152)
        previous=get(w,TOP)
        current=get(w,NEWFRAME)
        zero(w,FRAME,256)
        put(w,FRAME,previous)
        put(w,FRAME+8,FRAME_SIZE)
        put(w,FRAME+16,get(w,CHILDFD))
        put(w,CHILDFD,NONE)
        put(w,FRAME+24,get(w,ENTRY_PTR))
        put(w,FRAME+32,get(w,ENTRY_N))
        put(w,FRAME+40,get(w,ENTRY_DEV))
        put(w,FRAME+48,get(w,ENTRY_INO))
        put(w,DEPTH,get(w,DEPTH)+1)
        put(w,PERM_USED,0)
        put(w,FRAME+72,get(w,DEPTH))
        put(w,FRAME+80,current+256)
        put(w,FRAME+96,get(w,SAVED_PARENT))
        put(w,TOP,current)
        put(w,NEWFRAME,0)
        put(w,STAGE,100)
        return memory(o,153,1,FRAME,0,current,256)
    if phase==153:
        if r!=0:
            return quarantine(o,w,r,153)
        return drive(s,o,w)
    if phase==155:
        if r!=0 and r!=18446744073709551614:
            return permission_start(o,w,r,155,2,120)
        if r==0:
            put(w,REMOVED,get(w,REMOVED)+1)
        return next_entry(o,w)
    return BAD

def finish_directory(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==191:
        if r!=0:
            return pending(o,w,r,191)
        put(w,FRAME+56,0)
        put(w,FRAME+64,0)
        put(w,STAGE,100)
        return drive(s,o,w)
    if phase==200:
        if r==18446744073709551614:
            put(w,STAGE,205)
            return drive(s,o,w)
        if failed(r):
            return permission_start(o,w,r,200,3,200)
        if get(w,STAT1)!=get(w,FRAME+40) or get(w,STAT1+8)!=get(w,FRAME+48) or (get(w,STAT1+24)&61440)!=16384:
            return pending(o,w,18446744073709551500,200)
        put(w,STAGE,210)
        return drive(s,o,w)
    if phase==205:
        if failed(r):
            return pending(o,w,r,205)
        if get(w,STAT2+16)!=0:
            put(w,STAGE,200)
            return pending(o,w,18446744073709551500,205)
        put(w,STAGE,300)
        return drive(s,o,w)
    if phase==210:
        if r==18446744073709551614:
            put(w,STAGE,205)
            return drive(s,o,w)
        if r!=0:
            put(w,STAGE,200)
            if permission_errno(r):
                return permission_start(o,w,r,210,3,200)
            if r==18446744073709551577 or r==18446744073709551599:
                put(w,STAGE,190)
            return pending(o,w,r,210)
        put(w,REMOVED,get(w,REMOVED)+1)
        if get(w,DEPTH)==1:
            put(w,ROOT_REMOVED,1)
        put(w,STAGE,300)
        return drive(s,o,w)
    return BAD

def pop_frame(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==300:
        return drive(s,o,w)
    if phase==310:
        if r!=0:
            return pending(o,w,r,310)
        put(w,MAPS,get(w,MAPS)-1)
        put(w,TOP,get(w,PREV))
        put(w,DEPTH,get(w,DEPTH)-1)
        put(w,PERM_USED,0)
        zero(w,FRAME,256)
        if get(w,TOP)==0:
            put(w,STAGE,900)
            return drive(s,o,w)
        put(w,STAGE,320)
        return drive(s,o,w)
    if phase==321:
        if r!=0:
            return quarantine(o,w,r,321)
        put(w,STAGE,choose(get(w,ABORT)!=0,900,110))
        return drive(s,o,w)
    return BAD

def retire_resources(o:mutbuf,w:mutbuf) -> u32:
    if get(w,PERM_FD)!=NONE:
        return start_close(o,w,5,900)
    if get(w,CHILDFD)!=NONE:
        return start_close(o,w,4,900)
    if get(w,NEWFRAME)!=0:
        return system(o,901,11,0,get(w,NEWFRAME),FRAME_SIZE,0,0,0,0)
    if get(w,TOP)!=0:
        put(w,STAGE,300)
        return again(o,10)
    if get(w,ROOTFD)!=NONE:
        return start_close(o,w,1,900)
    if get(w,PARENTFD)!=NONE:
        return start_close(o,w,2,900)
    if get(w,LEAF)!=0:
        return system(o,902,11,0,get(w,LEAF),get(w,LEAFEXT),0,0,0,0)
    if get(w,FDS)!=0 or get(w,MAPS)!=0 or get(w,DEPTH)!=0:
        return quarantine(o,w,900,900)
    put(w,STATE,3)
    put(w,STAGE,0)
    put(o,RETIRED,1)
    put(o,STATUS,choose(get(w,PRIMARY)!=0,4,0))
    put(o,ERROR,get(w,PRIMARY))
    return unlock(o)

def start_close(o:mutbuf,w:mutbuf,kind:u64,next:u64) -> u32:
    put(w,CLOSE_KIND,kind)
    put(w,CLOSE_NEXT,next)
    put(w,STAGE,950)
    if get(w,CLOSE_MODE)==1:
        return system(o,951,3,0,closing_fd(w),0,0,0,0,0)
    return system(o,950,436,0,closing_fd(w),closing_fd(w),0,0,0,0)

def closing_fd(w:mutbuf) -> u64:
    kind=get(w,CLOSE_KIND)
    if kind==1:
        return get(w,ROOTFD)
    if kind==2:
        return get(w,PARENTFD)
    if kind==3:
        return get(w,FRAME+16)
    if kind==5:
        return get(w,PERM_FD)
    return get(w,CHILDFD)

def closed(o:mutbuf,w:mutbuf,r:u64,uncertain:bool) -> u32:
    if r!=0:
        if uncertain:
            put(w,UNKNOWN,get(w,CLOSE_KIND))
            return quarantine(o,w,r,951)
        return pending(o,w,r,950)
    kind=get(w,CLOSE_KIND)
    if kind==1:
        put(w,ROOTFD,NONE)
    elif kind==2:
        put(w,PARENTFD,NONE)
    elif kind==3:
        put(w,FRAME+16,NONE)
    elif kind==5:
        put(w,PERM_FD,NONE)
    else:
        put(w,CHILDFD,NONE)
    put(w,FDS,get(w,FDS)-1)
    next=get(w,CLOSE_NEXT)
    put(w,CLOSE_KIND,0)
    put(w,CLOSE_NEXT,0)
    put(w,STAGE,next)
    if next==145:
        return again(o,145)
    return again(o,10)


def permission_errno(error:u64) -> bool:
    return error==18446744073709551615 or error==18446744073709551603

def permission_start(o:mutbuf,w:mutbuf,error:u64,phase:u64,kind:u64,next:u64) -> u32:
    if permission_errno(error)==False or get(w,PERM_USED)!=0:
        return pending(o,w,error,phase)
    if get(w,PERM_FD)!=NONE:
        return quarantine(o,w,error,phase)
    put(w,PERM_USED,1)
    put(w,PERM_KIND,kind)
    put(w,PERM_NEXT,next)
    put(w,PERM_FAILURE,0)
    put(w,STAGE,700)
    return permission_drive(o,w,700)

def permission_drive(o:mutbuf,w:mutbuf,stage:u64) -> u32:
    kind=get(w,PERM_KIND)
    if stage==700:
        fd=get(w,FRAME+16)
        if kind==0:
            fd=get(w,ROOTFD)
        elif kind==3 and get(w,DEPTH)>1:
            fd=get(w,FRAME+96)
        return system(o,701,91,0,fd,448,0,0,0,0)
    if stage==702:
        return system(o,703,262,16,get(w,FRAME+16),get(w,ENTRY_PTR),STAT1,256,0,0)
    if stage==704:
        return system(o,705,257,0,get(w,FRAME+16),get(w,ENTRY_PTR),2752512,0,0,0)
    if stage==706:
        return system(o,707,5,4,get(w,PERM_FD),STAT2,0,0,0,0)
    if stage==708:
        return system(o,709,452,4,get(w,PERM_FD),1560,448,4096,0,0)
    if stage==710:
        return system(o,711,91,0,get(w,FRAME+16),448,0,0,0,0)
    if stage==712:
        return system(o,713,90,1,PERM_PATH,448,0,0,0,0)
    if stage==714:
        put(w,STAGE,get(w,PERM_NEXT))
        if get(w,PERM_FAILURE)!=0:
            return pending(o,w,get(w,PERM_FAILURE),714)
        return again(o,10)
    return quarantine(o,w,stage,700)

def permission_result(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==701:
        if r!=0:
            return pending(o,w,r,701)
        kind=get(w,PERM_KIND)
        if kind==0 or kind==1:
            put(w,STAGE,get(w,PERM_NEXT))
            return drive(s,o,w)
        if kind==3:
            if get(w,DEPTH)==1:
                put(w,STAGE,get(w,PERM_NEXT))
            else:
                put(w,STAGE,710)
        else:
            put(w,STAGE,702)
        return drive(s,o,w)
    if phase==703:
        if r==18446744073709551614:
            return next_entry(o,w)
        if failed(r):
            return pending(o,w,r,703)
        mode=get(w,STAT1+24)&61440
        if mode==40960:
            put(w,STAGE,get(w,PERM_NEXT))
            return drive(s,o,w)
        put(w,PERM_DEV,get(w,STAT1))
        put(w,PERM_INO,get(w,STAT1+8))
        put(w,PERM_MODE,mode)
        put(w,STAGE,704)
        return drive(s,o,w)
    if phase==705:
        if r==18446744073709551614:
            return next_entry(o,w)
        if failed(r):
            return pending(o,w,r,705)
        put(w,PERM_FD,r)
        put(w,FDS,get(w,FDS)+1)
        put(w,STAGE,706)
        return drive(s,o,w)
    if phase==707:
        if failed(r):
            return pending(o,w,r,707)
        if get(w,STAT2)!=get(w,PERM_DEV) or get(w,STAT2+8)!=get(w,PERM_INO) or (get(w,STAT2+24)&61440)!=get(w,PERM_MODE):
            put(w,PERM_FAILURE,18446744073709551500)
            return start_close(o,w,5,714)
        put(w,STAGE,708)
        return drive(s,o,w)
    if phase==709:
        if r==18446744073709551578 or r==18446744073709551594:
            permission_fd_path(w)
            put(w,STAGE,712)
            return drive(s,o,w)
        if r!=0:
            return pending(o,w,r,709)
        return start_close(o,w,5,714)
    if phase==711:
        if r!=0:
            return pending(o,w,r,711)
        put(w,STAGE,get(w,PERM_NEXT))
        return drive(s,o,w)
    if phase==713:
        if r!=0:
            return pending(o,w,r,713)
        return start_close(o,w,5,714)
    return BAD

def permission_fd_path(w:mutbuf) -> u64:
    zero(w,PERM_PATH,64)
    put(w,PERM_PATH,PROC0)
    put(w,PERM_PATH+8,PROC1)
    value=get(w,PERM_FD)
    n=0
    while value>=10:
        quotient=(value*3435973837)>>35
        store(w,PERM_DIGITS+n,48+value-quotient*10)
        value=quotient
        n=n+1
    store(w,PERM_DIGITS+n,48+value)
    n=n+1
    i=0
    while i<n:
        store(w,PERM_PATH+14+i,byte(w,PERM_DIGITS+n-i-1))
        i=i+1
    return 0

def abort_failure(s:readbuf,o:mutbuf,w:mutbuf,error:u64,phase:u64) -> u32:
    put(w,PRIMARY,error)
    put(w,FAILPH,phase)
    put(w,ABORT,1)
    put(w,STAGE,900)
    return drive(s,o,w)

def pending(o:mutbuf,w:mutbuf,error:u64,phase:u64) -> u32:
    if get(w,PRIMARY)==0:
        put(w,PRIMARY,error)
        put(w,FAILPH,phase)
    else:
        put(w,CLEANERR,error)
    put(w,STATE,2)
    put(o,STATUS,11)
    put(o,ERROR,get(w,PRIMARY))
    put(o,PENDING,1)
    return unlock(o)

def quarantine(o:mutbuf,w:mutbuf,error:u64,phase:u64) -> u32:
    put(w,STATE,4)
    put(w,UNKNOWN,choose(get(w,UNKNOWN)!=0,get(w,UNKNOWN),phase))
    put(w,CLEANERR,error)
    if get(w,PRIMARY)==0:
        put(w,PRIMARY,error)
        put(w,FAILPH,phase)
    put(o,STATUS,11)
    put(o,ERROR,get(w,PRIMARY))
    put(o,PENDING,1)
    put(o,KNOWN,0)
    return unlock(o)

def next_entry(o:mutbuf,w:mutbuf) -> u32:
    put(w,PERM_USED,0)
    put(w,FRAME+64,get(w,FRAME+64)+get(w,RECLEN))
    put(w,STAGE,110)
    return again(o,10)

def lock(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 2

def unlock(o:mutbuf) -> u32:
    put(o,PH,980)
    return 3

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10

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

def memory(o:mutbuf,next:u64,sb:u64,so:u64,db:u64,do:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sb)
    put(o,8,so)
    put(o,16,db)
    put(o,24,do)
    put(o,32,n)
    return 8

def reply(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,ERROR))
    put(o,24,get(w,FAILPH))
    put(o,32,get(o,KNOWN))
    put(o,40,get(o,PENDING))
    put(o,48,get(o,RETIRED))
    put(o,56,get(w,ROOT_REMOVED))
    put(o,64,get(w,FDS))
    put(o,72,get(w,MAPS))
    put(o,80,get(w,VISITED))
    put(o,88,get(w,REMOVED))
    put(o,96,get(w,DEPTH))
    put(o,104,get(w,CLEANERR))
    return 0

def failed(value:u64) -> bool:
    return value>=18446744073709547521

def choose(condition:bool,a:u64,b:u64) -> u64:
    if condition:
        return a
    return b

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    # Persisted close retry does not reconstruct or duplicate an owned FD.
    needle='    if stage==900:\n        return retire_resources(o,w)\n'
    assert source.count(needle)==1
    source=source.replace(needle,'''    if stage==950:
        if get(w,CLOSE_MODE)==1:
            return system(o,951,3,0,closing_fd(w),0,0,0,0,0)
        return system(o,950,436,0,closing_fd(w),closing_fd(w),0,0,0,0)
'''+needle)
    for name,value in sorted(C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'native_owned_directory_cleanup')
    path=ROOT/'examples/hia_bootstrap/native_owned_directory_cleanup.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),
          sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
