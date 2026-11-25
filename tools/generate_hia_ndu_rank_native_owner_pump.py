"""NDU-only bounded pipe pump; HIA owns process-group lifetime and one absolute deadline."""
from pathlib import Path
import re
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C={'NONE':2**64-1,'EINTR':2**64-4,'EAGAIN':2**64-11,'ECHILD':2**64-10,'EPIPE':2**64-32,
'WORK':5<<20,'MAGIC':int.from_bytes(b'HIANBP01','little'),'REPLY':int.from_bytes(b'HIANPR01','little'),
'CLOCK':32768,'STAT':32832,'SIGNAL':33024,'IGNORE':33120,'MASK_WORD':33800,'MASK_OLD':33808,'MASK_PENDING':33816,'MASK_ZERO':33824,'SIGPIPE_OLD':33152,'DEFAULT_SIGNAL':33184,'WAITINFO':33216,'WAITSTATUS':33344,
'PIPES':33408,'POLL':33536,'ERRBUF':33728,'ARGV':65536,'ENVP':65600,'COMMAND':65728,'ENV':65824,
'EMPTY':66000,'NANOSLEEP':66016,'OUT':1048576,'ERR':2097184,'LIMIT':1048577}
SOURCE=r'''
def pump(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if safe_cancel_phase(phase) and get(w,336)!=0:
        return reject(o,w,6,0,0)
    if phase==0:
        return begin(s,o,w)
    if phase<30:
        return setup(s,o,w,phase,result)
    if phase>=30 and phase<50:
        return parent(o,w,phase,result)
    if phase>=50 and phase<70:
        return child(o,w,phase,result)
    if phase>=70 and phase<100:
        return capture(s,o,w,phase,result)
    if phase>=110 and phase<140:
        return cleanup(o,w,phase,result)
    if phase>=150 and phase<170:
        return finish_phase(o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or word_load(s,0)!=MAGIC:
        return 4294967293
    n=word_load(s,24)
    if n>1048576 or n!=length(s)-128 or word_load(s,8)<3 or word_load(s,8)>2147483647 or word_load(s,16)==0:
        return 4294967293
    i=32
    while i<128:
        if word_load(s,i)!=0:
            return 4294967293
        i=i+8
    base=get(w,16)
    cancel=get(w,336)
    zero(w,24,16360)
    put(w,16,base)
    put(w,336,cancel)
    put(w,24,word_load(s,8))
    put(w,32,word_load(s,16))
    put(w,40,n)
    put(w,64,0)
    i=0
    while i<10:
        put(w,256+i*8,NONE)
        i=i+1
    return call(o,w,1,13,48,17,0,SIGNAL,8,0,0)

def setup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        if failed(result) or get(w,SIGNAL)!=0:
            return reject(o,w,3,1,result)
        return call(o,w,2,39,0,0,0,0,0,0,0)
    if phase==2:
        if failed(result):
            return reject(o,w,3,2,result)
        put(w,48,result)
        zero(w,WAITINFO,128)
        return call(o,w,3,247,48,1,result,WAITINFO,16777221,0,0)
    if phase==3:
        if result!=ECHILD:
            return reject(o,w,3,3,result)
        return call(o,w,4,72,0,get(w,24),1030,3,0,0,0)
    if phase==4:
        if failed(result):
            return reject(o,w,3,4,result)
        put(w,320,result)
        return call(o,w,5,72,0,result,1034,0,0,0,0)
    if phase==5:
        if failed(result) or (result&15)!=15:
            return reject(o,w,3,5,result)
        return call(o,w,6,5,12,get(w,320),STAT,0,0,0,0)
    if phase==6:
        if failed(result) or (word_load(w,STAT+24)&61440)!=32768 or get(w,STAT+48)==0 or get(w,STAT+48)>134217728:
            return reject(o,w,3,6,result)
        put(w,MASK_WORD,4096)
        zero(w,MASK_ZERO,16)
        put(w,160,0)
        return make_pipe(o,w)
    if phase==8:
        if failed(result):
            return reject(o,w,3,8,result)
        index=get(w,160)*2
        put(w,256+index*8,get32(w,PIPES))
        put(w,264+index*8,get32(w,PIPES+4))
        put(w,168,index)
        return normalize(o,w)
    if phase==9:
        if failed(result):
            return reject(o,w,3,9,result)
        index=get(w,168)
        old=get(w,256+index*8)
        put(w,256+index*8,result)
        return call(o,w,10,3,0,old,0,0,0,0,0)
    if phase==10:
        if failed(result):
            return reject(o,w,3,10,result)
        return normalized(o,w)
    if phase==11:
        if failed(result):
            return reject(o,w,3,11,result)
        put(w,160,get(w,160)+1)
        if get(w,160)<4:
            return make_pipe(o,w)
        return call(o,w,12,228,12,1,CLOCK,0,0,0,0)
    if phase==12:
        if failed(result):
            return reject(o,w,3,12,result)
        put(w,88,now(w))
        if get(w,336)!=0:
            return reject(o,w,6,0,0)
        if get(w,88)>=get(w,32):
            return reject(o,w,1,0,0)
        arguments(w)
        return call(o,w,13,57,0,0,0,0,0,0,0)
    if phase==13:
        if failed(result):
            return reject(o,w,3,13,result)
        if result==0:
            return call(o,w,50,112,0,0,0,0,0,0,0)
        put(w,64,result)
        put(w,72,1)
        put(w,160,0)
        return close_child_ends(o,w)
    return 4294967293

def make_pipe(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,8,293,3,PIPES,524288,0,0,0,0)

def normalize(o:mutbuf,w:mutbuf) -> u32:
    fd=get(w,256+get(w,168)*8)
    if fd<3:
        return call(o,w,9,72,0,fd,1030,3,0,0,0)
    return normalized(o,w)

def normalized(o:mutbuf,w:mutbuf) -> u32:
    index=get(w,168)
    if (index&1)==0:
        put(w,168,index+1)
        return normalize(o,w)
    pair=get(w,160)
    parent_index=choose(pair==0,1,pair*2)
    return call(o,w,11,72,0,get(w,256+parent_index*8),4,2048,0,0,0)

def parent(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==30:
        if failed(result):
            return reject(o,w,3,30,result)
        put(w,160,get(w,160)+1)
        return close_child_ends(o,w)
    if phase==31:
        if failed(result):
            return reject(o,w,3,31,result)
        return tick(o,w)
    return 4294967293

def close_child_ends(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,160)
    if i<4:
        index=choose(i==0,0,i*2+1)
        fd=get(w,256+index*8)
        put(w,256+index*8,NONE)
        return call(o,w,30,3,0,fd,0,0,0,0,0)
    if get(w,40)==0:
        fd=get(w,264)
        put(w,264,NONE)
        return call(o,w,31,3,0,fd,0,0,0,0,0)
    return tick(o,w)

def child(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==68:
        if result==EINTR:
            return child_error_write(o,w)
        if failed(result)==False and result>0 and result<=8-get(w,192):
            put(w,192,get(w,192)+result)
            if get(w,192)<8:
                return child_error_write(o,w)
        return call(o,w,69,60,0,127,0,0,0,0,0)
    if phase==69:
        return 4294967293
    if failed(result):
        return child_error(o,w,result)
    if phase==50:
        return call(o,w,51,157,0,1,9,0,0,0,0)
    if phase==51:
        return call(o,w,52,110,0,0,0,0,0,0,0)
    if phase==52:
        if result!=get(w,48):
            return child_error(o,w,5)
        return call(o,w,53,33,0,get(w,256),0,0,0,0,0)
    if phase==53:
        return call(o,w,54,33,0,get(w,280),1,0,0,0,0)
    if phase==54:
        return call(o,w,55,33,0,get(w,296),2,0,0,0,0)
    if phase==55:
        zero(w,DEFAULT_SIGNAL,32)
        return call(o,w,56,13,12,13,DEFAULT_SIGNAL,0,8,0,0)
    if phase==56:
        return call(o,w,59,13,12,25,DEFAULT_SIGNAL,0,8,0,0)
    if phase==59:
        return call(o,w,57,436,0,3,4294967295,4,0,0,0)
    if phase==57:
        return call(o,w,58,322,252,get(w,320),EMPTY,ARGV,ENVP,4096,0)
    return child_error(o,w,result)

def child_error(o:mutbuf,w:mutbuf,raw:u64) -> u32:
    put(w,ERRBUF,raw)
    put(w,192,0)
    return child_error_write(o,w)

def child_error_write(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,68,1,12,get(w,312),ERRBUF+get(w,192),8-get(w,192),0,0,0)

def tick(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,70,228,12,1,CLOCK,0,0,0,0)

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==70:
        if failed(result):
            return reject(o,w,3,70,result)
        put(w,88,now(w))
        if get(w,88)>=get(w,32):
            return reject(o,w,1,0,0)
        if get(w,264)!=NONE:
            return call(o,w,77,14,60,0,MASK_WORD,MASK_OLD,8,0,0)
        put(w,160,0)
        return read_next(o,w)
    if phase==71:
        put(w,176,result)
        if result==EPIPE and (get(w,MASK_PENDING)&4096)==0:
            return call(o,w,79,128,51,MASK_WORD,0,MASK_ZERO,8,0,0)
        return restore_mask(o,w)
    if phase==77:
        if failed(result):
            return reject(o,w,3,77,result)
        put(w,96,1)
        return call(o,w,78,127,3,MASK_PENDING,8,0,0,0,0)
    if phase==78:
        if failed(result):
            return reject(o,w,3,78,result)
        return call(o,w,71,1,4,get(w,264),128+get(w,120),minimum(65536,get(w,40)-get(w,120)),0,0,0)
    if phase==79:
        if result==EINTR:
            return call(o,w,79,128,51,MASK_WORD,0,MASK_ZERO,8,0,0)
        if result!=13 and result!=EAGAIN:
            put(w,104,4)
            put(w,128,79)
            put(w,136,result)
        return restore_mask(o,w)
    if phase==80:
        if failed(result):
            return reject(o,w,4,80,result)
        put(w,96,0)
        if get(w,104)!=0:
            return start_cleanup(o,w)
        return written(o,w,get(w,176))
    if phase==72:
        if failed(result):
            return reject(o,w,3,72,result)
        put(w,160,0)
        return read_next(o,w)
    if phase==73:
        if result==EINTR or result==EAGAIN:
            return next_stream(o,w)
        if failed(result):
            return reject(o,w,3,73,result)
        which=get(w,160)
        if result==0:
            put(w,544+which*8,1)
            fd=get(w,272+which*16)
            put(w,272+which*16,NONE)
            put(w,168,which)
            return call(o,w,74,3,0,fd,0,0,0,0,0)
        current=get(w,512+which*8)
        cap=choose(which==2,8,LIMIT)
        if result>cap-current:
            return reject(o,w,3,73,0)
        put(w,512+which*8,current+result)
        if which<2 and current+result>=LIMIT:
            return reject(o,w,2,0,0)
        if which==2 and current+result==8:
            return reject(o,w,5,0,get(w,ERRBUF))
        return next_stream(o,w)
    if phase==74:
        if failed(result):
            return reject(o,w,3,74,result)
        return next_stream(o,w)
    if phase==75:
        if result==EINTR:
            return tick(o,w)
        if failed(result):
            if result==ECHILD:
                put(w,72,0)
            return reject(o,w,4,75,result)
        pid=get32(w,WAITINFO+16)
        if pid!=0 and pid!=get(w,64):
            put(w,72,0)
            return reject(o,w,4,75,0)
        if pid!=0:
            put(w,80,1)
        if get(w,80)!=0 and get(w,544)!=0 and get(w,552)!=0 and get(w,560)!=0 and get(w,264)==NONE:
            return start_cleanup(o,w)
        poll_table(w)
        left=get(w,32)-get(w,88)
        timeout=(minimum(left,10000000)+999999)//1000000
        return call(o,w,76,7,3,POLL,4,timeout,0,0,0)
    if phase==76:
        if failed(result) and result!=EINTR:
            return reject(o,w,3,76,result)
        return tick(o,w)
    return 4294967293

def safe_cancel_phase(phase:u64) -> bool:
    if phase>=30 and phase<50:
        return True
    if phase<70 or phase>=100:
        return False
    return phase!=71 and phase!=77 and phase!=78 and phase!=79 and phase!=80

def restore_mask(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,80,14,12,2,MASK_OLD,0,8,0,0)

def written(o:mutbuf,w:mutbuf,result:u64) -> u32:
    if result==EINTR or result==EAGAIN:
        put(w,160,0)
        return read_next(o,w)
    if result==EPIPE or result==0:
        fd=get(w,264)
        put(w,264,NONE)
        return call(o,w,72,3,0,fd,0,0,0,0,0)
    if failed(result) or result>get(w,40)-get(w,120):
        return reject(o,w,3,71,result)
    put(w,120,get(w,120)+result)
    if get(w,120)==get(w,40):
        fd=get(w,264)
        put(w,264,NONE)
        return call(o,w,72,3,0,fd,0,0,0,0,0)
    put(w,160,0)
    return read_next(o,w)

def read_next(o:mutbuf,w:mutbuf) -> u32:
    which=get(w,160)
    if which==3:
        zero(w,WAITINFO,128)
        return call(o,w,75,247,48,1,get(w,64),WAITINFO,16777221,0,0)
    if get(w,544+which*8)!=0:
        return next_stream(o,w)
    current=get(w,512+which*8)
    cap=choose(which==2,8,LIMIT)
    at=choose(which==0,OUT,choose(which==1,ERR,ERRBUF))
    return call(o,w,73,0,12,get(w,272+which*16),at+current,minimum(4096,cap-current),0,0,0)

def next_stream(o:mutbuf,w:mutbuf) -> u32:
    put(w,160,get(w,160)+1)
    return read_next(o,w)

def poll_table(w:mutbuf) -> u64:
    put(w,POLL,get(w,264)&4294967295)
    if get(w,264)!=NONE:
        put(w,POLL,get(w,264)|17179869184)
    i=0
    while i<3:
        fd=get(w,272+i*16)
        put(w,POLL+8+i*8,fd&4294967295)
        if fd!=NONE:
            put(w,POLL+8+i*8,fd|4294967296)
        i=i+1
    return 0

def reject(o:mutbuf,w:mutbuf,status:u64,where:u64,raw:u64) -> u32:
    if get(w,104)==0:
        put(w,104,status)
        put(w,128,where)
        put(w,136,raw)
    return start_cleanup(o,w)

def start_cleanup(o:mutbuf,w:mutbuf) -> u32:
    if get(w,64)!=0 and get(w,72)!=0 and get(w,200)==0:
        zero(w,WAITINFO,128)
        return call(o,w,110,247,48,1,get(w,64),WAITINFO,16777221,0,0)
    return close_fds(o,w)

def cleanup(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==110:
        if result==EINTR:
            zero(w,WAITINFO,128)
            return call(o,w,110,247,48,1,get(w,64),WAITINFO,16777221,0,0)
        if failed(result):
            put(w,72,0)
            put(w,104,4)
            put(w,128,110)
            put(w,136,result)
            return close_fds(o,w)
        pid=get32(w,WAITINFO+16)
        if pid!=0 and pid!=get(w,64):
            put(w,72,0)
            put(w,104,4)
            return close_fds(o,w)
        put(w,200,1)
        return call(o,w,111,62,0,0-get(w,64),9,0,0,0,0)
    if phase==111:
        if result==18446744073709551613:
            put(w,240,1)
            return call(o,w,116,62,0,get(w,64),9,0,0,0,0)
        if failed(result):
            put(w,104,4)
            put(w,128,111)
            put(w,136,result)
        return call(o,w,112,228,12,1,CLOCK,0,0,0,0)
    if phase==116:
        if failed(result):
            put(w,104,4)
            put(w,128,116)
            put(w,136,result)
        return call(o,w,112,228,12,1,CLOCK,0,0,0,0)
    if phase==112:
        if failed(result):
            put(w,104,4)
            put(w,128,112)
            return close_fds(o,w)
        put(w,88,now(w))
        put(w,208,get(w,88)+2000000000)
        return reap(o,w)
    if phase==113:
        if result==EINTR:
            return call(o,w,114,228,12,1,CLOCK,0,0,0,0)
        if result==get(w,64):
            put(w,72,0)
            put(w,216,1)
            status=get32(w,WAITSTATUS)
            put(w,224,status)
            if (status&127)==0:
                put(w,232,(status>>8)&255)
            else:
                put(w,232,0-(status&127))
            return close_fds(o,w)
        if result!=0:
            put(w,104,4)
            put(w,128,113)
            put(w,136,result)
            put(w,72,0)
            return close_fds(o,w)
        return call(o,w,114,228,12,1,CLOCK,0,0,0,0)
    if phase==114:
        if failed(result):
            put(w,104,4)
            put(w,128,114)
            return close_fds(o,w)
        put(w,88,now(w))
        if get(w,88)>=get(w,208):
            put(w,104,4)
            put(w,128,114)
            return close_fds(o,w)
        put(w,NANOSLEEP,0)
        put(w,NANOSLEEP+8,minimum(1000000,get(w,208)-get(w,88)))
        return call(o,w,115,35,3,NANOSLEEP,0,0,0,0,0)
    if phase==115:
        return reap(o,w)
    return 4294967293

def reap(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,113,61,12,get(w,64),WAITSTATUS,1,0,0,0)

def close_fds(o:mutbuf,w:mutbuf) -> u32:
    put(w,160,0)
    return close_next(o,w)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,160)
    while i<9:
        fd=get(w,256+i*8)
        put(w,160,i+1)
        if fd!=NONE:
            put(w,256+i*8,NONE)
            return call(o,w,150,3,0,fd,0,0,0,0,0)
        i=i+1
    if get(w,96)!=0:
        put(w,96,0)
        return call(o,w,151,14,12,2,MASK_OLD,0,8,0,0)
    return call(o,w,152,228,12,1,CLOCK,0,0,0,0)

def finish_phase(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==150:
        if failed(result):
            put(w,104,4)
            put(w,128,150)
            put(w,136,result)
        return close_next(o,w)
    if phase==151:
        if failed(result):
            put(w,104,4)
            put(w,128,151)
            put(w,136,result)
        return call(o,w,152,228,12,1,CLOCK,0,0,0,0)
    if phase==152:
        if failed(result)==False:
            put(w,88,now(w))
        zero(o,0,128)
        put(o,0,REPLY)
        put(o,8,get(w,104))
        put(o,16,get(w,128))
        put(o,24,get(w,136))
        put(o,32,get(w,512))
        put(o,40,get(w,520))
        put(o,48,get(w,232))
        put(o,56,get(w,64))
        put(o,64,get(w,216))
        put(o,72,get(w,544)|(get(w,552)<<1)|(get(w,560)<<2))
        put(o,80,get(w,120))
        put(o,88,get(w,88))
        put(o,96,OUT)
        put(o,104,ERR)
        put(o,112,get(w,200))
        put(o,120,get(w,224))
        return 0
    return 4294967293

def arguments(w:mutbuf) -> u64:
    i=0
    while i<4:
        put(w,ARGV+i*8,0)
        put(w,ENVP+i*8,0)
        i=i+1
    command(w,COMMAND)
    put(w,ARGV,get(w,16)+COMMAND)
    at=environment(w,ENV)
    put(w,ENVP,get(w,16)+ENV)
    put(w,ENVP+8,get(w,16)+ENV+7)
    put(w,ENVP+16,get(w,16)+ENV+16)
    put(w,EMPTY,0)
    return 0

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,next)
    put(o,0,nr)
    put(o,8,a)
    put(o,16,b)
    put(o,24,c)
    put(o,32,d)
    put(o,40,e)
    put(o,48,f)
    put(o,56,flags)
    return 1

def now(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def failed(v:u64) -> bool:
    return v>=18446744073709547520

def minimum(a:u64,b:u64) -> u64:
    return choose(a<b,a,b)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def get32(w:mutbuf,at:u64) -> u64:
    return byte(w,at)|(byte(w,at+1)<<8)|(byte(w,at+2)<<16)|(byte(w,at+3)<<24)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,at+i,0)
        i=i+8
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
'''
def literal(name,raw):
    out=[f'def {name}(w:mutbuf,at:u64) -> u64:']
    for i in range(0,len(raw)//8*8,8):out.append(f'    word_store(w,at+{i},{int.from_bytes(raw[i:i+8],"little")})')
    for i in range(len(raw)//8*8,len(raw)):out.append(f'    store(w,at+{i},{raw[i]})')
    out.append(f'    return at+{len(raw)}');return '\n'.join(out)
def program():
    s=SOURCE+'\n\n'+literal('command',b'hia-ndu-evaluator\0')+'\n\n'+literal('environment',b'LANG=C\0LC_ALL=C\0PYTHONIOENCODING=utf-8\0')
    for name,v in C.items():s=re.sub(r'\b'+name+r'\b',str(v),s)
    return s
def main():
    d=document(program(),'ndu_rank_native_owner_pump');p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_pump.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
