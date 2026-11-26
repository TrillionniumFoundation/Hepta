"""Native gettempdir cache, live environment capture and real filesystem probe.

The fixed enclosing owner owns this context until explicit retirement. Request
frames carry only an operation, never an environment or callback pointer.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAGIC=int.from_bytes(b'HIAGTDQ1','little'),REPLY=int.from_bytes(b'HIAGTDR1','little'),
 CTX=int.from_bytes(b'HIAGTDC1','little'),CODEC=int.from_bytes(b'HIAGTCQ1','little'),CREPLY=int.from_bytes(b'HIAGTCR1','little'),
 ABS=int.from_bytes(b'HIAGPAN1','little'),ABORT=int.from_bytes(b'HIAGPAQ1','little'),AREPLY=int.from_bytes(b'HIAGPAR1','little'),
 NAME0=int.from_bytes(b'TMPDIR=','little'),NAME1=int.from_bytes(b'TEMP=','little'),NAME2=int.from_bytes(b'TMP=','little'),
 DEFAULT0=int.from_bytes(b'/tmp','little'),DEFAULT1=int.from_bytes(b'/var/tmp','little'),DEFAULT2=int.from_bytes(b'/usr/tmp','little'),
 BLAT=int.from_bytes(b'blat','little'),BAD=4294967293,NONE=(1<<64)-1,SMAX=(1<<63)-1,WORK=204800,
 PH=128,FB=136,OP=144,PID=152,SELF=160,HELD=168,STATUS=176,ERROR=184,WHERE=192,
 RETURN_FD=200,RETURN_N=208,PENDING=216,RETIRED=224,HEADER=512,CHILD=1024)
SOURCE=r'''
def tempdir(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if r<2 or r>2147483647:
            put(o,STATUS,4)
            put(o,ERROR,r)
            return reply(o,w)
        put(o,PID,r)
        if get(w,0)!=0:
            if get(w,0)!=CTX or get(w,8)!=r or get(w,16)!=get(o,SELF):
                return BAD
        put(o,0,24)
        put(o,8,0)
        put(o,16,1)
        put(o,PH,2)
        return 2
    if phase==2:
        if r==0:
            put(o,HELD,1)
            return locked(o,w)
        if r!=1:
            return BAD
        put(o,256,0)
        put(o,264,1000000)
        return system(o,3,202,193,24,128,1,256,0,0)
    if phase==3:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            put(o,STATUS,4)
            put(o,ERROR,r)
            return reply(o,w)
        put(o,0,24)
        put(o,8,0)
        put(o,16,1)
        put(o,PH,2)
        return 2
    if phase>=10 and phase<=16:
        return environment(o,w,phase,r)
    if phase>=50 and phase<=53:
        return capture_cwd(o,w,phase,r)
    if phase==80:
        if failed(r):
            return failed_get(o,w,4,r,80)
        slot=get(o,240)
        put(w,slot,r)
        put(w,slot+8,get(o,248))
        return again(o,get(o,272))
    if phase>=100 and phase<=116:
        return candidate(o,w,phase,r)
    if phase>=117 and phase<=124:
        return probe(o,w,phase,r)
    if phase>=700 and phase<=721:
        return cleanup(o,w,phase,r)
    if phase==730:
        if r==18446744073709551578:
            put(w,528,1)
            return system(o,731,3,0,get(w,552),0,0,0,0,0)
        return again(o,get(w,544))
    if phase==731:
        if r!=0:
            put(w,560,get(w,536))
            put(w,64,r)
            put(o,ERROR,r)
            return quarantine(o,w,731)
        return again(o,get(w,544))
    if phase==800:
        if failed(r):
            put(o,STATUS,4)
            put(o,ERROR,r)
            put(o,WHERE,800)
        else:
            put(o,RETURN_FD,r)
            put(o,RETURN_N,get(w,48))
        return unlock(o,w)
    if phase==900:
        put(o,HELD,0)
        return system(o,901,202,1,24,129,1,0,0,0)
    if phase==901:
        if failed(r) and get(o,STATUS)==0:
            put(o,STATUS,11)
            put(o,ERROR,r)
            put(o,WHERE,901)
        return reply(o,w)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=32 or length(o)!=4096 or length(w)!=WORK:
        return BAD
    if word_load(s,0)!=MAGIC or word_load(s,8)>2 or word_load(s,16)!=0 or word_load(s,24)!=0:
        return BAD
    zero(o,144,368)
    put(o,OP,word_load(s,8))
    put(o,RETURN_FD,NONE)
    put(o,PH,4)
    return 15

def start_after_facts(o:mutbuf) -> u32:
    return system(o,1,39,0,0,0,0,0,0,0)

def locked(o:mutbuf,w:mutbuf) -> u32:
    if get(w,0)==0:
        i=0
        while i<4096:
            if i!=24 and get(w,i)!=0:
                put(o,STATUS,6)
                return unlock(o,w)
            i=i+8
        zero(w,32,4064)
        put(w,8,get(o,PID))
        put(w,16,get(o,SELF))
        put(w,32,1)
        put(w,40,NONE)
        put(w,96,NONE)
        put(w,112,NONE)
        put(w,512,NONE)
        put(w,0,CTX)
    if get(w,0)!=CTX or get(w,8)!=get(o,PID) or get(w,16)!=get(o,SELF):
        put(o,STATUS,6)
        return unlock(o,w)
    op=get(o,OP)
    state=get(w,32)
    if state==4:
        put(o,STATUS,11)
        put(o,PENDING,1)
        return unlock(o,w)
    if state==3:
        if op==0:
            put(o,STATUS,6)
        else:
            put(o,RETIRED,1)
        return unlock(o,w)
    if op==1:
        put(w,56,0)
        put(w,64,0)
        put(w,72,0)
        put(w,488,4)
        return again(o,700)
    if op==2:
        put(w,56,0)
        put(w,64,0)
        put(w,72,0)
        put(w,488,3)
        return again(o,700)
    if state==2:
        put(o,STATUS,11)
        put(o,ERROR,get(w,64))
        put(o,WHERE,get(w,72))
        put(o,PENDING,1)
        return unlock(o,w)
    if get(w,40)!=NONE:
        return duplicate(o,w)
    put(w,56,0)
    put(w,64,0)
    put(w,72,0)
    put(w,80,0)
    put(w,160,0)
    put(o,PH,10)
    return 5

def environment(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==10:
        if r==NONE:
            return failed_get(o,w,4,18446744073709551594,10)
        put(w,128,r)
        if r==0:
            return begin_cwd(o,w)
        return env_key(o,w)
    if phase==11:
        if r==0:
            return next_key(o,w)
        put(w,144,r)
        put(w,152,0)
        return peek(o,12,r,1)
    if phase==12:
        key=get(w,160)
        at=get(w,152)
        code=NAME0
        n=7
        if key==1:
            code=NAME1
            n=5
        elif key==2:
            code=NAME2
            n=4
        if r!=((code>>(at*8))&255):
            put(w,136,get(w,136)+1)
            return peek(o,11,get(w,128)+get(w,136)*8,8)
        at=at+1
        put(w,152,at)
        if at<n:
            return peek(o,12,get(w,144)+at,1)
        put(w,176,0)
        return peek(o,13,get(w,144)+n,1)
    if phase==13:
        n=get(w,176)
        if r==0:
            if n==0:
                return next_key(o,w)
            slot=192+get(w,160)*24
            put(w,slot+16,n)
            return allocate(o,14,slot,128+n)
        if n>=SMAX-128:
            return failed_get(o,w,4,18446744073709551604,13)
        put(w,176,n+1)
        return peek(o,13,get(w,144)+get(w,152)+n+1,1)
    if phase==14:
        frame(o,0,get(w,176))
        return memory(o,15,3,HEADER,0,get(w,192+get(w,160)*24),128)
    if phase==15:
        return memory(o,16,0,get(w,144)+get(w,152),0,get(w,192+get(w,160)*24)+128,get(w,176))
    if phase==16:
        return next_key(o,w)
    return BAD

def env_key(o:mutbuf,w:mutbuf) -> u32:
    put(w,136,0)
    return peek(o,11,get(w,128),8)

def next_key(o:mutbuf,w:mutbuf) -> u32:
    put(w,160,get(w,160)+1)
    if get(w,160)==3:
        return begin_cwd(o,w)
    return env_key(o,w)


def begin_cwd(o:mutbuf,w:mutbuf) -> u32:
    zero(w,4096,200704)
    zero(o,HEADER,32)
    put(o,HEADER,ABORT)
    return role(o,50,12,3,HEADER,32,1,1024,128,1,4096,200704)

def capture_cwd(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==50:
        if r!=0 or get(w,1024)!=AREPLY or get(w,1080)>1 or get(w,1096)!=0:
            return quarantine(o,w,50)
        if get(w,1080)==1:
            put(w,432,1)
        if get(w,1032)==0:
            if get(w,1056)>2147483647 or get(w,1072)!=15 or get(w,1080)!=0:
                return quarantine(o,w,50)
            put(w,512,get(w,1056))
            put(w,520,get(w,1064))
            return again(o,100)
        where=get(w,1048)
        if get(w,1032)==4 and get(w,1080)==0:
            if where==5 or (where>=100 and where<=118):
                put(w,1312,0)
                return system(o,51,319,1,1312,3,0,0,0,0)
        return failed_get(o,w,4,get(w,1040),50)
    if phase==51:
        if failed(r):
            return failed_get(o,w,4,r,51)
        put(w,512,r)
        put(w,520,1)
        put(w,1344,46)
        return system(o,52,18,4,r,1344,1,0,0,0)
    if phase==52:
        if r!=1:
            return failed_get(o,w,4,r,52)
        return system(o,53,72,0,get(w,512),1033,15,0,0,0)
    if phase==53:
        if r!=0:
            return failed_get(o,w,4,r,53)
        return again(o,100)
    return BAD


def candidate(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        index=get(w,80)
        if index>=7:
            return failed_get(o,w,8,18446744073709551614,100)
        if index==6:
            if get(w,512)==NONE:
                return quarantine(o,w,100)
            put(w,112,get(w,512))
            put(w,120,get(w,520))
            put(w,512,NONE)
            put(w,520,0)
            return fs_input(o,w)
        n=0
        if index<3:
            slot=192+index*24
            n=get(w,slot+16)
            if n==0:
                put(w,80,index+1)
                return again(o,100)
            put(w,264,get(w,slot))
        else:
            n=8
            value=DEFAULT1
            if index==3:
                n=4
                value=DEFAULT0
            elif index==5:
                value=DEFAULT2
            elif index==6:
                n=1
                value=46
            frame(o,0,n)
            put(o,HEADER+128,value)
            put(w,264,0)
        put(w,272,n)
        if n>(SMAX-128)//3:
            return failed_get(o,w,4,18446744073709551604,100)
        return allocate(o,101,288,128+3*n)
    if phase==101:
        source=choose(get(w,264)==0,3,0)
        pointer=choose(get(w,264)==0,HEADER,get(w,264))
        return role(o,102,13,source,pointer,128+get(w,272),0,get(w,288),get(w,296),1,1280,32)
    if phase==102:
        if r!=0:
            return quarantine(o,w,102)
        return memory(o,103,0,get(w,288),3,CHILD,129)
    if phase==103:
        if get(o,CHILD)!=CREPLY or get(o,CHILD+8)!=0:
            return quarantine(o,w,103)
        n=get(o,CHILD+16)
        if n>get(w,296)-128:
            return quarantine(o,w,103)
        put(w,280,n)
        if get(w,80)<3 and n==1 and byte(o,CHILD+128)==46:
            put(w,1312,0)
            return system(o,105,319,1,1312,3,0,0,0,0)
        zero(o,HEADER,32)
        put(o,HEADER,ABS)
        put(o,HEADER+16,n)
        return memory(o,108,3,HEADER,0,get(w,288)+96,32)
    if phase==108:
        zero(w,4096,200704)
        return role(o,104,12,0,get(w,288)+96,32+get(w,280),1,1024,128,1,4096,200704)
    if phase==104:
        if r!=0 or get(w,1024)!=AREPLY or get(w,1096)!=0:
            return quarantine(o,w,104)
        if get(w,1080)>1:
            return quarantine(o,w,104)
        if get(w,1080)==1:
            put(w,432,1)
        if get(w,1032)!=0:
            where=get(w,1048)
            if get(w,80)==6 and get(w,1032)==4 and get(w,1080)==0:
                if where==5 or (where>=100 and where<=118):
                    put(w,1312,0)
                    return system(o,105,319,1,1312,3,0,0,0,0)
            return failed_get(o,w,4,get(w,1040),104)
        fd=get(w,1056)
        if fd>2147483647 or get(w,1072)!=15 or get(w,1080)!=0:
            return quarantine(o,w,104)
        put(w,112,fd)
        put(w,120,get(w,1064))
        return fs_input(o,w)
    if phase==105:
        if failed(r):
            return failed_get(o,w,4,r,105)
        put(w,112,r)
        put(w,120,1)
        put(w,1344,46)
        return system(o,106,18,4,r,1344,1,0,0,0)
    if phase==106:
        if r!=1:
            return failed_get(o,w,4,r,106)
        return system(o,107,72,0,get(w,112),1033,15,0,0,0)
    if phase==107:
        if r!=0:
            return failed_get(o,w,4,r,107)
        return fs_input(o,w)
    if phase==110:
        frame(o,1,get(w,120))
        put(w,408,0)
        return memory(o,111,3,HEADER,0,get(w,320),128)
    if phase==111:
        return read_path(o,w)
    if phase==112:
        if r==18446744073709551612:
            return read_path(o,w)
        if failed(r) or r==0 or r>get(w,120)-get(w,408):
            return failed_get(o,w,4,r,112)
        put(w,408,get(w,408)+r)
        if get(w,408)<get(w,120):
            return read_path(o,w)
        return allocate(o,113,336,144+get(w,120))
    if phase==113:
        return role(o,114,13,0,get(w,320),128+get(w,120),0,get(w,336),get(w,344),1,1280,32)
    if phase==114:
        if r!=0:
            return quarantine(o,w,114)
        return memory(o,115,0,get(w,336),3,CHILD,128)
    if phase==115:
        if get(o,CHILD)!=CREPLY or get(o,CHILD+8)!=0:
            return quarantine(o,w,115)
        n=get(o,CHILD+16)
        if n==0 or n>get(w,120):
            return quarantine(o,w,115)
        put(w,424,n)
        return peek(o,116,get(w,336)+128+n-1,1)
    if phase==116:
        put(w,440,get(w,424)+choose(r==47,0,1))
        put(w,480,0)
        put(w,472,0)
        if r!=47:
            put(o,HEADER,47)
            return memory(o,117,3,HEADER,0,get(w,336)+128+get(w,424),1)
        return again(o,117)
    return BAD

def fs_input(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,120)
    if n>SMAX-144:
        return failed_get(o,w,4,18446744073709551604,109)
    return allocate(o,110,320,128+n)

def read_path(o:mutbuf,w:mutbuf) -> u32:
    return system(o,112,17,0,get(w,112),get(w,320)+128+get(w,408),get(w,120)-get(w,408),get(w,408),0,0)

def probe(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==117:
        return system(o,120,318,1,1536+get(w,472),64-get(w,472),0,0,0,0)
    if phase==120:
        if r==18446744073709551612:
            return again(o,117)
        if failed(r) or r==0 or r>64-get(w,472):
            return failed_get(o,w,4,r,120)
        put(w,472,get(w,472)+r)
        if get(w,472)<64:
            return again(o,117)
        i=0
        while i<8:
            value=get(w,1536+i*8)%37
            ch=95
            if value<26:
                ch=97+value
            elif value<36:
                ch=48+value-26
            store(w,1600+i,ch)
            i=i+1
        store(w,1608,0)
        return memory(o,121,1,1600,0,get(w,336)+128+get(w,440),9)
    if phase==121:
        return system(o,122,257,0,18446744073709551516,get(w,336)+128,655554,384,0,0)
    if phase==122:
        if failed(r):
            if r==18446744073709551599:
                put(w,480,get(w,480)+1)
                if get(w,480)<20:
                    put(w,472,0)
                    return again(o,117)
            put(w,488,1)
            return again(o,700)
        put(w,96,r)
        put(w,104,1)
        put(w,464,0)
        return system(o,123,5,4,r,2048,0,0,0,0)
    if phase==123:
        if failed(r):
            put(w,488,1)
            return again(o,700)
        put(w,448,get(w,2048))
        put(w,456,get(w,2056))
        put(w,464,1)
        put(w,1616,BLAT)
        return system(o,124,1,4,get(w,96),1616,4,0,0,0)
    if phase==124:
        if r==18446744073709551612:
            return system(o,124,1,4,get(w,96),1616,4,0,0,0)
        put(w,488,choose(failed(r),1,2))
        return again(o,700)
    return BAD

def cleanup(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==700:
        if get(w,432)!=0:
            zero(o,HEADER,32)
            put(o,HEADER,ABORT)
            put(o,HEADER+8,1)
            return role(o,701,12,3,HEADER,32,1,1024,128,1,4096,200704)
        return again(o,703)
    if phase==701:
        if r!=0 or get(w,1024)!=AREPLY or get(w,1096)!=0:
            return quarantine(o,w,701)
        if get(w,1032)!=0 or get(w,1080)!=0:
            return pending(o,w,get(w,1040),701)
        put(w,432,0)
        return again(o,703)
    if phase==703:
        if get(w,96)!=NONE and get(w,464)==0:
            return system(o,704,5,4,get(w,96),2048,0,0,0,0)
        return again(o,705)
    if phase==704:
        if failed(r):
            return pending(o,w,r,704)
        put(w,448,get(w,2048))
        put(w,456,get(w,2056))
        put(w,464,1)
        return again(o,705)
    if phase==705:
        if get(w,96)!=NONE:
            return close_private(o,w,706,96)
        return again(o,707)
    if phase==706:
        if r!=0:
            return pending(o,w,r,706)
        put(w,96,NONE)
        return again(o,707)
    if phase==707:
        if get(w,104)!=0:
            return system(o,708,262,16,18446744073709551516,get(w,336)+128,2048,256,0,0)
        return again(o,710)
    if phase==708:
        if r==18446744073709551614:
            put(w,104,0)
            if get(w,488)==2:
                put(w,488,1)
            return again(o,710)
        if failed(r):
            return pending(o,w,r,708)
        if get(w,464)!=1:
            return quarantine(o,w,708)
        if get(w,2048)!=get(w,448) or get(w,2056)!=get(w,456):
            put(w,104,0)
            if get(w,488)==2:
                put(w,488,1)
            return again(o,710)
        return system(o,709,87,0,get(w,336)+128,0,0,0,0,0)
    if phase==709:
        if r!=0 and r!=18446744073709551614:
            return pending(o,w,r,709)
        put(w,104,0)
        return again(o,710)
    if phase==710:
        if get(w,488)==2 and get(w,40)==NONE:
            put(w,40,get(w,112))
            put(w,48,get(w,120))
            put(w,112,NONE)
        if get(w,112)!=NONE:
            return close_private(o,w,711,112)
        return again(o,720)
    if phase==711:
        if r!=0:
            return pending(o,w,r,711)
        put(w,112,NONE)
        return again(o,720)
    if phase==720:
        if get(w,488)!=1 and get(w,512)!=NONE:
            return close_private(o,w,721,512)
        put(w,496,288)
        return again(o,712)
    if phase==721:
        if r!=0:
            return pending(o,w,r,721)
        put(w,512,NONE)
        put(w,520,0)
        put(w,496,288)
        return again(o,712)
    if phase==712:
        return unmap_next(o,w)
    if phase==714:
        if r!=0:
            return pending(o,w,r,714)
        slot=get(w,496)
        put(w,slot,0)
        put(w,slot+8,0)
        if slot>=192 and slot<=240:
            put(w,slot+16,0)
        return unmap_next(o,w)
    if phase==715:
        if get(w,488)==4 and get(w,40)!=NONE:
            return close_private(o,w,716,40)
        return cleanup_done(o,w)
    if phase==716:
        if r!=0:
            return pending(o,w,r,716)
        put(w,40,NONE)
        put(w,48,0)
        return cleanup_done(o,w)
    return BAD

def close_private(o:mutbuf,w:mutbuf,next:u64,slot:u64) -> u32:
    put(w,536,slot)
    put(w,544,next)
    put(w,552,get(w,slot))
    if get(w,528)==1:
        return system(o,731,3,0,get(w,slot),0,0,0,0,0)
    return system(o,730,436,0,get(w,slot),get(w,slot),0,0,0,0)

def unmap_next(o:mutbuf,w:mutbuf) -> u32:
    slot=get(w,496)
    if slot==288:
        if get(w,288)!=0:
            return system(o,714,11,0,get(w,288),get(w,296),0,0,0,0)
        slot=320
    if slot==320:
        if get(w,320)!=0:
            put(w,496,320)
            return system(o,714,11,0,get(w,320),get(w,328),0,0,0,0)
        slot=336
    if slot==336:
        if get(w,336)!=0:
            put(w,496,336)
            return system(o,714,11,0,get(w,336),get(w,344),0,0,0,0)
        slot=192
    if get(w,488)!=1:
        while slot<=240:
            put(w,496,slot)
            if get(w,slot)!=0:
                return system(o,714,11,0,get(w,slot),get(w,slot+8),0,0,0,0)
            put(w,slot+16,0)
            slot=slot+24
    return again(o,715)

def cleanup_done(o:mutbuf,w:mutbuf) -> u32:
    next=get(w,488)
    if next==1:
        put(w,80,get(w,80)+1)
        return again(o,100)
    if next==4:
        put(w,32,3)
        put(o,RETIRED,1)
    else:
        put(w,32,1)
    if next==2:
        return duplicate(o,w)
    put(o,STATUS,get(w,56))
    put(o,ERROR,get(w,64))
    put(o,WHERE,get(w,72))
    return unlock(o,w)

def failed_get(o:mutbuf,w:mutbuf,status:u64,error:u64,where:u64) -> u32:
    put(w,56,status)
    put(w,64,error)
    put(w,72,where)
    put(w,488,3)
    return again(o,700)

def pending(o:mutbuf,w:mutbuf,error:u64,where:u64) -> u32:
    put(w,32,2)
    put(w,56,11)
    put(w,64,error)
    put(w,72,where)
    put(w,488,3)
    put(o,STATUS,11)
    put(o,ERROR,error)
    put(o,WHERE,where)
    put(o,PENDING,1)
    return unlock(o,w)

def quarantine(o:mutbuf,w:mutbuf,where:u64) -> u32:
    put(w,32,4)
    put(w,72,where)
    put(o,STATUS,11)
    put(o,WHERE,where)
    put(o,PENDING,1)
    return unlock(o,w)

def duplicate(o:mutbuf,w:mutbuf) -> u32:
    return system(o,800,72,0,get(w,40),1030,0,0,0,0)

def unlock(o:mutbuf,w:mutbuf) -> u32:
    put(o,0,24)
    put(o,8,0)
    put(o,PH,900)
    return 3

def reply(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,ERROR))
    put(o,24,get(o,WHERE))
    put(o,32,get(o,RETURN_FD))
    put(o,40,get(o,RETURN_N))
    if get(o,RETURN_FD)!=NONE:
        put(o,48,15)
    put(o,56,get(o,PENDING))
    if get(w,0)==CTX:
        if get(w,40)!=NONE:
            put(o,64,1)
    put(o,72,get(o,RETIRED))
    put(o,80,choose(get(w,32)==4,0,1))
    put(o,88,get(w,32))
    put(o,96,get(w,80))
    return 0

def frame(o:mutbuf,mode:u64,n:u64) -> u64:
    zero(o,HEADER,128)
    put(o,HEADER,CODEC)
    put(o,HEADER+8,mode)
    put(o,HEADER+16,n)
    return 0

def allocate(o:mutbuf,next:u64,slot:u64,size:u64) -> u32:
    put(o,240,slot)
    put(o,248,size)
    put(o,272,next)
    return system(o,80,9,0,0,size,3,34,NONE,0)

def peek(o:mutbuf,next:u64,pointer:u64,width:u64) -> u32:
    put(o,PH,next)
    put(o,0,pointer)
    put(o,8,width)
    return 9

def memory(o:mutbuf,next:u64,source:u64,at:u64,dest:u64,to:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,source)
    put(o,8,at)
    put(o,16,dest)
    put(o,24,to)
    put(o,32,n)
    return 8

def role(o:mutbuf,next:u64,action:u64,sp:u64,so:u64,sn:u64,op:u64,oo:u64,on:u64,wp:u64,wo:u64,wn:u64) -> u32:
    put(o,PH,next)
    put(o,0,sp)
    put(o,8,so)
    put(o,16,sn)
    put(o,24,op)
    put(o,32,oo)
    put(o,40,on)
    put(o,48,wp)
    put(o,56,wo)
    put(o,64,wn)
    return action

def system(o:mutbuf,next:u64,nr:u64,selectors:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,nr)
    put(o,8,selectors)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10

def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)

def put(o:mutbuf,at:u64,value:u64) -> u64:
    word_store(o,at,value)
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0

def failed(value:u64) -> bool:
    return value>=18446744073709547521
'''
def source_program():
    source=SOURCE.replace('    if phase==1:\n','    if phase==4:\n        return start_after_facts(o)\n    if phase==1:\n',1)
    for key,value in sorted(C.items(),key=lambda row:-len(row[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_tempdir')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_tempdir.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
