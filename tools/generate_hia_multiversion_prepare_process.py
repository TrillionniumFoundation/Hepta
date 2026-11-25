"""Fixed-role HIA preparation process capture with one absolute deadline.

The caller supplies an already captured immutable executable capability and a
private cancellation word. No path lookup or shell is performed by this owner.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAGIC=int.from_bytes(b'HIAMVPS1','little'),REPLY=int.from_bytes(b'HIAMVPO1','little'),
       NONE=(1<<64)-1,NEG4=(1<<64)-4,NEG11=(1<<64)-11,WORK=20<<20,
       INPUT=1<<20,IO=262144,CLOCK=32768,STAT=32832,PIPE=33024,POLL=33152,WAITINFO=33280,EXECERR=33408,WAITSTATUS=33536,
       COMMAND=65536,ARGV=131072,ENVP=131136,EMPTY=131200,ENV=131216)
TEXT={1:'hia-admit-agent-json',2:'hia-native-scalar-proof',3:'hia-build-shared',4:'hia-verify-core-json'}
SOURCE=r'''
def process(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        return begin(s,o,w)
    if phase<40:
        return setup(s,o,w,phase,result)
    if phase>=50 and phase<60:
        return parent_start(o,w,phase,result)
    if phase>=60 and phase<80:
        return child(o,w,phase,result)
    if phase>=90 and phase<100:
        return normalized(o,w,phase,result)
    if phase>=100 and phase<120:
        return capture(o,w,phase,result)
    if phase>=120 and phase<140:
        return terminal(o,w,phase,result)
    if phase>=150 and phase<160:
        return sealing(o,w,phase,result)
    if phase>=180 and phase<190:
        return cleanup(o,w,phase,result)
    if phase>=200 and phase<210:
        return guarded(o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or readword(s,0)!=MAGIC:
        return 4294967293
    role=readword(s,8)
    n=readword(s,32)
    pn=readword(s,56)
    if role<1 or role>4 or readword(s,16)<3 or readword(s,16)>2147483647 or readword(s,24)==0:
        return 4294967293
    if n>16777408 or (role!=2 and n>8388608):
        return 4294967293
    if readword(s,40)>67108864 or readword(s,48)>67108864 or pn>4095:
        return 4294967293
    if role!=3 and pn!=0:
        return 4294967293
    if n>length(s)-128 or pn!=length(s)-128-n:
        return 4294967293
    if role==3 and (pn==0 or byte(s,128+n)!=47):
        return 4294967293
    if readword(s,64)!=0 and (readword(s,64)&7)!=0:
        return 4294967293
    i=72
    while i<128:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    i=0
    while i<pn:
        if byte(s,128+n+i)==0:
            return 4294967293
        i=i+1
    zero(w,64,16320)
    put(w,160,role)
    put(w,168,readword(s,16))
    put(w,176,readword(s,24))
    put(w,184,readword(s,64))
    put(w,192,n)
    put(w,200,pn)
    put(w,208,readword(s,40))
    put(w,216,readword(s,48))
    i=0
    while i<10:
        put(w,256+i*8,NONE)
        i=i+1
    return call(o,w,1,228,4,1,CLOCK,0,0,0,0)

def setup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        if failed(result):
            return fail(o,w,3,result)
        now=now_ns(w)
        put(w,112,now)
        put(w,120,now)
        if now>=get(w,176):
            return fail(o,w,1,0)
        put(w,0,2)
        return 2
    if phase==2:
        if result==1:
            return fail(o,w,2,0)
        copy_input(s,128,w,INPUT,get(w,192)+get(w,200))
        return call(o,w,3,72,0,get(w,168),1030,3,0,0,0)
    if phase==3:
        if failed(result):
            return fail(o,w,3,result)
        put(w,328,result)
        return call(o,w,4,72,0,result,1034,0,0,0,0)
    if phase==4:
        if result!=15:
            return fail(o,w,3,result)
        zero(w,STAT,144)
        return call(o,w,5,5,4,get(w,328),STAT,0,0,0,0)
    if phase==5:
        if failed(result):
            return fail(o,w,3,result)
        if (getn(w,STAT+24,4)&61440)!=32768 or get(w,STAT+16)!=0 or get(w,STAT+48)==0 or get(w,STAT+48)>8388608:
            return fail(o,w,3,0)
        return call(o,w,6,39,0,0,0,0,0,0,0)
    if phase==6:
        if failed(result):
            return fail(o,w,3,result)
        put(w,232,result)
        put(w,EMPTY,0)
        return call(o,w,7,319,1,EMPTY,3,0,0,0,0)
    if phase==7:
        if failed(result):
            return fail(o,w,3,result)
        put(w,256,result)
        return normalize(o,w,0,8)
    if phase==8:
        put(w,224,0)
        return write_input(o,w)
    if phase==9:
        if result==NEG4:
            return guard(o,w,30)
        if failed(result) or result==0 or result>get(w,192)-get(w,224):
            return fail(o,w,3,result)
        put(w,224,get(w,224)+result)
        if get(w,224)<get(w,192):
            return guard(o,w,30)
        return call(o,w,10,8,0,get(w,256),0,0,0,0,0)
    if phase==10:
        if result!=0:
            return fail(o,w,3,result)
        return call(o,w,11,72,0,get(w,256),1033,15,0,0,0)
    if phase==11:
        if failed(result):
            return fail(o,w,3,result)
        return call(o,w,12,72,0,get(w,256),1034,0,0,0,0)
    if phase==12:
        if result!=15:
            return fail(o,w,3,result)
        return call(o,w,13,319,1,EMPTY,3,0,0,0,0)
    if phase==13:
        if failed(result):
            return fail(o,w,3,result)
        put(w,296,result)
        return normalize(o,w,5,14)
    if phase==14:
        return call(o,w,15,91,0,get(w,296),384,0,0,0,0)
    if phase==15:
        if failed(result):
            return fail(o,w,3,result)
        return call(o,w,16,319,1,EMPTY,3,0,0,0,0)
    if phase==16:
        if failed(result):
            return fail(o,w,3,result)
        put(w,304,result)
        return normalize(o,w,6,17)
    if phase==17:
        return call(o,w,18,91,0,get(w,304),384,0,0,0,0)
    if phase==18:
        if failed(result):
            return fail(o,w,3,result)
        put(w,416,0)
        return create_pipe(o,w)
    if phase==20:
        if failed(result):
            return fail(o,w,3,result)
        index=pipe_index(get(w,416))
        put(w,256+index*8,getn(w,PIPE,4))
        put(w,264+index*8,getn(w,PIPE+4,4))
        return normalize(o,w,index,21)
    if phase==21:
        index=pipe_index(get(w,416))
        return call(o,w,22,72,0,get(w,256+index*8),4,2048,0,0,0)
    if phase==22:
        if failed(result):
            return fail(o,w,3,result)
        return normalize(o,w,pipe_index(get(w,416))+1,23)
    if phase==23:
        put(w,416,get(w,416)+1)
        if get(w,416)<3:
            return create_pipe(o,w)
        return guard(o,w,24)
    if phase==24:
        arguments(w)
        return call(o,w,25,57,0,0,0,0,0,0,0)
    if phase==25:
        if failed(result):
            return fail(o,w,3,result)
        if result==0:
            return call(o,w,60,109,0,0,0,0,0,0,0)
        put(w,88,result)
        return call(o,w,50,109,0,result,result,0,0,0,0)
    if phase==30:
        return write_input(o,w)
    return 4294967293

def write_input(o:mutbuf,w:mutbuf) -> u32:
    if get(w,224)==get(w,192):
        return call(o,w,10,8,0,get(w,256),0,0,0,0,0)
    return call(o,w,9,1,4,get(w,256),INPUT+get(w,224),get(w,192)-get(w,224),0,0,0)

def pipe_index(which:u64) -> u64:
    if which==2:
        return 7
    return 1+which*2

def create_pipe(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,20,293,1,PIPE,524288,0,0,0,0)

def normalize(o:mutbuf,w:mutbuf,index:u64,after:u64) -> u32:
    fd=get(w,256+index*8)
    if fd>=3:
        put(w,0,after)
        put(w,8,0)
        return 3
    put(w,352,index)
    put(w,360,after)
    return call(o,w,90,72,0,fd,1030,3,0,0,0)

def normalized(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==90:
        if failed(result):
            return fail(o,w,3,result)
        index=get(w,352)
        old=get(w,256+index*8)
        put(w,256+index*8,result)
        return call(o,w,91,3,0,old,0,0,0,0,0)
    if phase==91:
        if failed(result):
            return fail(o,w,3,result)
        put(w,0,get(w,360))
        put(w,8,0)
        return 3
    return 4294967293

def parent_start(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==50:
        fd=get(w,272)
        put(w,272,NONE)
        return call(o,w,51,3,0,fd,0,0,0,0,0)
    if phase==51:
        fd=get(w,288)
        put(w,288,NONE)
        return call(o,w,52,3,0,fd,0,0,0,0,0)
    if phase==52:
        fd=get(w,320)
        put(w,320,NONE)
        return call(o,w,53,3,0,fd,0,0,0,0,0)
    if phase==53:
        return guard(o,w,100)
    return 4294967293

def child(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase>=70:
        if phase==70:
            if result==NEG4:
                return child_error_write(o,w)
            if failed(result)==False and result>0 and result<=8-get(w,224):
                put(w,224,get(w,224)+result)
                if get(w,224)<8:
                    return child_error_write(o,w)
        return call(o,w,79,60,0,127,0,0,0,0,0)
    if failed(result):
        return child_error(o,w,result)
    if phase==60:
        return call(o,w,61,157,0,1,9,0,0,0,0)
    if phase==61:
        return call(o,w,62,110,0,0,0,0,0,0,0)
    if phase==62:
        if result!=get(w,232):
            return child_error(o,w,5)
        return call(o,w,63,33,0,get(w,256),0,0,0,0,0)
    if phase==63:
        return call(o,w,64,33,0,get(w,272),1,0,0,0,0)
    if phase==64:
        return call(o,w,65,33,0,get(w,288),2,0,0,0,0)
    if phase==65:
        return call(o,w,66,436,0,3,4294967295,4,0,0,0)
    if phase==66:
        return call(o,w,67,322,84,get(w,328),EMPTY,ARGV,ENVP,4096,0)
    return child_error(o,w,result)

def child_error(o:mutbuf,w:mutbuf,raw:u64) -> u32:
    put(w,EXECERR,raw)
    put(w,224,0)
    return child_error_write(o,w)

def child_error_write(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,70,1,4,get(w,320),EXECERR+get(w,224),8-get(w,224),0,0,0)

def capture(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==100:
        put(w,416,0)
        return read_stream(o,w)
    if phase==101:
        if result==NEG4:
            return guard(o,w,105)
        if result==NEG11:
            return next_stream(o,w)
        if failed(result):
            return fail(o,w,3,result)
        which=get(w,416)
        if result==0:
            put(w,512+which*8,1)
            return next_stream(o,w)
        if which==2:
            if result>8-get(w,152):
                return fail(o,w,3,0)
            copy(w,IO,EXECERR+get(w,152),result)
            put(w,152,get(w,152)+result)
            return next_stream(o,w)
        if result>get(w,208+which*8)-get(w,136+which*8):
            return fail(o,w,4,0)
        put(w,424,result)
        put(w,432,0)
        return write_stream(o,w)
    if phase==102:
        if result==NEG4:
            return guard(o,w,106)
        if failed(result) or result==0 or result>get(w,424)-get(w,432):
            return fail(o,w,3,result)
        put(w,432,get(w,432)+result)
        which=get(w,416)
        put(w,136+which*8,get(w,136+which*8)+result)
        if get(w,432)<get(w,424):
            return guard(o,w,106)
        return next_stream(o,w)
    if phase==103:
        if result==NEG4:
            return guard(o,w,107)
        if failed(result):
            if result==18446744073709551606:
                put(w,88,0)
            return fail(o,w,3,result)
        pid=getn(w,WAITINFO+16,4)
        if pid!=0 and pid!=get(w,88):
            return fail(o,w,3,0)
        if pid!=0:
            put(w,104,1)
        if get(w,104)!=0 and get(w,512)!=0 and get(w,520)!=0 and get(w,528)!=0:
            return call(o,w,120,61,4,get(w,88),WAITSTATUS,0,0,0,0)
        return guard(o,w,108)
    if phase==104:
        if failed(result) and result!=NEG4:
            return fail(o,w,3,result)
        return guard(o,w,100)
    if phase==105:
        return read_stream(o,w)
    if phase==106:
        return write_stream(o,w)
    if phase==107:
        return observe(o,w)
    if phase==108:
        i=0
        while i<3:
            fd=get(w,256+pipe_index(i)*8)
            if get(w,512+i*8)!=0:
                fd=4294967295
            put(w,POLL+i*8,fd|4294967296)
            i=i+1
        left=get(w,176)-get(w,120)
        timeout=10
        if left<10000000:
            timeout=1
            while left>=1000000:
                timeout=timeout+1
                left=left-1000000
        return call(o,w,104,7,1,POLL,3,timeout,0,0,0)
    return 4294967293

def read_stream(o:mutbuf,w:mutbuf) -> u32:
    which=get(w,416)
    if get(w,512+which*8)!=0:
        return next_stream(o,w)
    if which==2:
        room=8-get(w,152)
    else:
        room=get(w,208+which*8)-get(w,136+which*8)
    if room==0:
        room=1
    if room>65536:
        room=65536
    fd=get(w,256+pipe_index(which)*8)
    return call(o,w,101,0,4,fd,IO,room,0,0,0)

def write_stream(o:mutbuf,w:mutbuf) -> u32:
    fd=get(w,296+get(w,416)*8)
    return call(o,w,102,1,4,fd,IO+get(w,432),get(w,424)-get(w,432),0,0,0)

def next_stream(o:mutbuf,w:mutbuf) -> u32:
    put(w,416,get(w,416)+1)
    if get(w,416)<3:
        return read_stream(o,w)
    return observe(o,w)

def observe(o:mutbuf,w:mutbuf) -> u32:
    zero(w,WAITINFO,128)
    return call(o,w,103,247,16,1,get(w,88),WAITINFO,16777221,0,0)

def terminal(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==127:
        return call(o,w,120,61,4,get(w,88),WAITSTATUS,0,0,0,0)
    if phase==120 or phase==132:
        if result==NEG4:
            if phase==120:
                return guard(o,w,127)
            return call(o,w,phase,61,4,get(w,88),WAITSTATUS,0,0,0,0)
        if result!=get(w,88):
            if phase==120:
                if result==18446744073709551606:
                    put(w,88,0)
                return fail(o,w,3,result)
            if get(w,80)==0:
                put(w,80,3)
                put(w,72,result)
        else:
            put(w,96,1)
            put(w,480,getn(w,WAITSTATUS,4))
        if phase==132 or get(w,80)!=0:
            return start_cleanup(o,w)
        if get(w,152)!=0:
            if get(w,152)!=8:
                put(w,80,3)
            else:
                put(w,80,5)
                put(w,488,get(w,EXECERR))
            return start_cleanup(o,w)
        return call(o,w,150,72,0,get(w,296),1033,15,0,0,0)
    if phase==130:
        return call(o,w,131,62,0,get(w,88),9,0,0,0,0)
    if phase==131:
        return call(o,w,132,61,4,get(w,88),WAITSTATUS,0,0,0,0)
    return 4294967293

def sealing(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==150:
        if failed(result):
            return fail(o,w,3,result)
        return call(o,w,151,72,0,get(w,296),1034,0,0,0,0)
    if phase==151:
        if result!=15:
            return fail(o,w,3,result)
        return call(o,w,152,72,0,get(w,304),1033,15,0,0,0)
    if phase==152:
        if failed(result):
            return fail(o,w,3,result)
        return call(o,w,153,72,0,get(w,304),1034,0,0,0,0)
    if phase==153:
        if result!=15:
            return fail(o,w,3,result)
        return call(o,w,154,228,4,1,CLOCK,0,0,0,0)
    if phase==154:
        if failed(result):
            return fail(o,w,3,result)
        put(w,120,now_ns(w))
        if get(w,120)>=get(w,176):
            return fail(o,w,1,0)
        put(w,496,15)
        return start_cleanup(o,w)
    return 4294967293

def fail(o:mutbuf,w:mutbuf,status:u64,raw:u64) -> u32:
    if get(w,80)==0:
        put(w,80,status)
        put(w,72,raw)
    if get(w,88)!=0 and get(w,96)==0:
        return call(o,w,130,62,0,0-get(w,88),9,0,0,0,0)
    return start_cleanup(o,w)

def start_cleanup(o:mutbuf,w:mutbuf) -> u32:
    put(w,400,0)
    return cleanup(o,w,180,0)

def cleanup(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==182:
        if failed(result)==False:
            put(w,120,now_ns(w))
        return finish(o,w)
    i=get(w,400)
    while i<10:
        fd=get(w,256+i*8)
        put(w,400,i+1)
        if fd!=NONE and (get(w,80)!=0 or (i!=5 and i!=6)):
            put(w,256+i*8,NONE)
            return call(o,w,181,3,0,fd,0,0,0,0,0)
        i=i+1
    return call(o,w,182,228,4,1,CLOCK,0,0,0,0)

def guard(o:mutbuf,w:mutbuf,after:u64) -> u32:
    put(w,440,after)
    return call(o,w,200,228,4,1,CLOCK,0,0,0,0)

def guarded(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==200:
        if failed(result):
            return fail(o,w,3,result)
        put(w,120,now_ns(w))
        if get(w,120)>=get(w,176):
            return fail(o,w,1,0)
        put(w,0,201)
        return 2
    if phase==201:
        if result==1:
            return fail(o,w,2,0)
        put(w,0,get(w,440))
        put(w,8,0)
        return 3
    return 4294967293

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(w,80))
    put(o,16,get(w,88))
    put(o,24,get(w,480))
    put(o,32,get(w,488))
    put(o,40,get(w,72))
    put(o,48,NONE)
    put(o,56,NONE)
    if get(w,80)==0:
        put(o,48,get(w,296))
        put(o,56,get(w,304))
        put(w,296,NONE)
        put(w,304,NONE)
    put(o,64,get(w,136))
    put(o,72,get(w,144))
    put(o,80,get(w,112))
    put(o,88,get(w,120))
    put(o,96,get(w,96))
    put(o,104,get(w,512)|(get(w,520)<<1)|(get(w,528)<<2))
    put(o,112,get(w,496))
    return 0

def arguments(w:mutbuf) -> u64:
    role=get(w,160)
    at=COMMAND
    if role==1:
        at=text_normalizer(w,at)
    elif role==2:
        at=text_proof(w,at)
    elif role==3:
        at=text_build(w,at)
    else:
        at=text_diagnostic(w,at)
    store(w,at,0)
    put(w,ARGV,get(w,16)+COMMAND)
    put(w,ARGV+8,0)
    put(w,ARGV+16,0)
    if role==3:
        copy(w,INPUT+get(w,192),at+1,get(w,200))
        store(w,at+1+get(w,200),0)
        put(w,ARGV+8,get(w,16)+at+1)
    put(w,EMPTY,0)
    store(w,ENV,80)
    store(w,ENV+1,65)
    store(w,ENV+2,84)
    store(w,ENV+3,72)
    store(w,ENV+4,61)
    store(w,ENV+5,0)
    put(w,ENVP,get(w,16)+ENV)
    put(w,ENVP+8,0)
    return 0

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,next)
    put(o,0,nr)
    put(o,8,flags)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def now_ns(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def failed(v:u64) -> bool:
    return v>=18446744073709547520

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def copy(w:mutbuf,si:u64,oi:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,oi+i,byte(w,si+i))
        i=i+1
    return 0

def copy_input(s:readbuf,si:u64,w:mutbuf,oi:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,oi+i,byte(s,si+i))
        i=i+1
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def getn(w:mutbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
def source_program():
    text=SOURCE
    for name,word in [('normalizer',TEXT[1]),('proof',TEXT[2]),('build',TEXT[3]),('diagnostic',TEXT[4])]:
        text+='\ndef text_'+name+'(w:mutbuf,at:u64) -> u64:\n'
        for i,c in enumerate(word.encode()):text+='    store(w,at+'+str(i)+','+str(c)+')\n'
        text+='    return at+'+str(len(word))+'\n'
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text
def main():
    t=document(source_program(),'multiversion_prepare_process');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_process.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),sum(len(b['ops']) for f in t['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()

