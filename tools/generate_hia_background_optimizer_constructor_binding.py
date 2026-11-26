"""Actual verification, scalar selection and runtime binding for BG construction.

This is the ordered constructor segment after typed options and live Path
construction. The enclosing constructor owns the actual runtime class carrier,
all captured contexts and input capabilities. No verification or identity fact
is accepted from a public request. New source is not native-qualified yet.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
from tools import hia_background_retirement_source as retirement
from tools import hia_background_provider_retirement_source as provider_retirement

ROOT=Path(__file__).resolve().parents[1]
C={
 'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'PID':160,'QUAR':168,
 'PNORM':256,'NN':280,'FUNCTION':288,'RUNTIME':320,'PSNAPSHOT':352,'PERROR':384,'ERROR_N':408,
 'VERIFY_ACTIVE':416,'NESTED':424,'NESTED_N':432,'NORM_PTR':440,
 'FRAME':464,'FRAME_N':472,'ARENA_PTR':480,'ARENA_CAP':488,'ARENA_N':496,'WORK_PTR':504,'WORK_N':512,
 'CORE_N':520,'CORE_PTR':528,'ORIGINAL_N':536,'ORIGINAL_PTR':544,'FUNCTION_N':552,
 'CURSOR':560,'CHUNK':568,'NODES':576,'KEYS':584,'DEPTH':592,'SNAP_PTR':600,'SNAP_N':608,
 'HPTR':624,'HN':632,'HDST':640,'HAFTER':648,'HCURSOR':656,'CLEAN':664,'DESTROY_AT':672,
 'DROP_ACTIVE':680,'DROP_KNOWN':688,'VALUE_PENDING':696,'ERRID':704,'ERROR_FORMAT':712,
 'ERR_N':720,'ERR_PTR':728,'FAMILY':736,'SUCCESS':744,'PUBLIC_INPUT':752,'PROVIDER_PENDING':760,'CORE_SHA':768,'INPUT_SHA':800,
 'FEEDBACK':3840,'RQ':4096,'RP':8192,'HEAD':49152,'NORM_HEADER':49664,'SNAP_HEADER':49728,
 'CHECK_HEADER':50176,'SMALL':51200,'ERRBUF':53248,'HBUF':65536,'HOUT':131072,
 'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'BAD':4294967293,'OUT':262144,
}
C.update(retirement.MAGICS)
C.update({k:int.from_bytes(v.encode(),'little') for k,v in {
 'MAGIC':'HIABCBQ1','VERIFIED':'HIABCBQ2','PUBLIC':'HIABCBQ3','PUBLIC_VERIFIED':'HIABCBQ4','REPLY':'HIABCBR1','CONTEXT':'HIABCBX1',
 'VREQUEST':'HIABVQ01','VREPLY':'HIABVR01','BREQUEST':'HIABPY01','BREPLY':'HIABPYR1',
 'YREQUEST':'HIABVFY3','YVERIFIED':'HIABVFY4','YREPLY':'HIABVFR2','YCONTEXT':'HIABVYC2',
 'MREQUEST':'HIAMVBQ1','MCAPTURE':'HIAMVBQ2','MTYPED':'HIAMVBQ3','MREPLY':'HIAMVBO1','PROVIDER_TYPED_REPLY':'HIAMVBO2','SNAPSHOT':'HIAMVBS1',
 'CHECK_REQUEST':'HIABCCQ1','CHECK_REPLY':'HIABCCR1','SIZES':'HIANJS01','NORM':'HIAVCF01',
}.items()})
ERRORS={
 6:'function must name a public scalar entrypoint',
 7:'supplied immutable baseline does not bind the runtime baseline',
 9:'current native source is untracked; observations cannot be silently rebased',
}
SOURCE=r'''
def constructor_binding(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return entering(s,o,w,phase)
    if phase<100:
        return verification(s,o,w,phase)
    if phase<200:
        return selection(s,o,w,phase)
    if phase<300:
        return runtime_binding(s,o,w,phase)
    if phase>=600 and phase<700:
        return hashing(o,w,phase)
    if phase>=700 and phase<800:
        return errors(o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or (word_load(s,0)!=MAGIC and word_load(s,0)!=VERIFIED and word_load(s,0)!=PUBLIC and word_load(s,0)!=PUBLIC_VERIFIED) or word_load(s,8)>1:
        return BAD
    i=16
    while i<128:
        used=word_load(s,8)==0 and i>=24 and i<=88
        if (word_load(s,0)==VERIFIED or word_load(s,0)==PUBLIC_VERIFIED) and word_load(s,8)==0 and i>=96 and i<=112:
            used=True
        if used==False and word_load(s,i)!=0:
            return BAD
        i=i+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)<256:
        return BAD
    if get(w,64)==0 or get(w,72)==0 or get(w,80)<768 or get(w,88)==0 or get(w,96)==0:
        return BAD
    if get(w,80)<1024 and word_load(s,0)!=PUBLIC and word_load(s,0)!=PUBLIC_VERIFIED:
        return BAD
    if get(w,104)<3 or get(w,112)==0 or get(w,120)!=10100891:
        return BAD
    i=128
    while i<=168:
        if get(w,i)==0:
            return BAD
        i=i+8
    if (get(w,176)!=0 and get(w,176)<640) or get(w,176)>2147483647 or get(w,192)>1 or get(w,208)>2:
        return BAD
    i=216
    while i<256:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,128,1920)
    put(o,OP,word_load(s,8))
    family=0
    if word_load(s,0)==VERIFIED or word_load(s,0)==PUBLIC_VERIFIED:
        family=1
    put(o,FAMILY,family)
    public_input=0
    if word_load(s,0)==PUBLIC or word_load(s,0)==PUBLIC_VERIFIED:
        public_input=1
    put(o,PUBLIC_INPUT,public_input)
    return system(o,1,39,0,0,0,0,0,0,0)

def entering(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,184)!=0 and get(w,184)!=pid):
            return finish(o,w,6)
        put(o,PID,pid)
        put(w,184,pid)
        put(o,0,0)
        put(o,PHASE,2)
        return 4
    if phase==2:
        pointer=get(o,FEEDBACK)
        if pointer==0 or (get(w,192)!=0 and get(w,200)!=pointer):
            return finish(o,w,6)
        put(w,200,pointer)
        if get(o,OP)==1:
            if get(w,192)==0:
                return finish(o,w,0)
            if get(w,208)!=1:
                return finish(o,w,6)
            from_work(w,o,256,128,1920)
            put(o,OP,1)
            put(o,QUAR,0)
            put(w,192,0)
            put(w,208,0)
            return again(o,1000)
        if get(w,192)!=0:
            return finish(o,w,6)
        return mapping(o,20,262144)
    return fail(o,7,phase)

def verification(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        pointer=get(o,FEEDBACK)
        if bad_pointer(pointer):
            return fail(o,5,pointer)
        put(o,NESTED,pointer)
        put(o,NESTED_N,262144)
        zero(w,4096,4096)
        put(w,4096,YCONTEXT)
        put(w,4104,get(w,8))
        put(w,4112,get(w,16))
        put(w,4120,get(w,24))
        put(w,4128,get(w,128))
        put(w,4136,get(w,88))
        put(w,4144,get(w,136))
        put(w,4152,get(w,40))
        put(w,4160,get(w,48))
        put(w,4168,get(w,56))
        put(w,4176,get(w,176))
        put(w,4184,get(w,104))
        put(w,4192,get(w,112))
        put(w,4200,get(w,120))
        put(w,4208,get(w,144))
        put(w,4216,get(w,152))
        put(w,4224,get(w,160))
        put(w,4232,get(w,168))
        request(o,choose(get(o,FAMILY)==0,YREQUEST,YVERIFIED),0)
        copy_source(s,o,24,RQ+24,24)
        if get(o,FAMILY)!=0:
            copy_source(s,o,96,RQ+48,24)
        put(o,VERIFY_ACTIVE,2)
        return invoke(o,21,get(w,32),259,RQ,128,pointer,262144,4096,4096)
    if phase==21:
        if get(o,FEEDBACK)!=0:
            return isolate(o,w,2,get(o,FEEDBACK))
        return memory(o,22,0,get(o,NESTED),3,HEAD,128)
    if phase==22:
        if get(o,HEAD)!=YREPLY or get(o,HEAD+56)>1 or get(o,HEAD+64)>2 or get(o,HEAD+72)>1:
            return isolate(o,w,2,22)
        if get(o,HEAD+56)!=0:
            if get(o,HEAD+64)!=1:
                return isolate(o,w,2,22)
            put(o,VERIFY_ACTIVE,1)
            return isolate(o,w,1,22)
        if get(o,HEAD+64)!=0 or get(o,HEAD+72)!=0:
            return isolate(o,w,2,22)
        put(o,VERIFY_ACTIVE,0)
        status=get(o,HEAD+8)
        if status<=2:
            if get(o,HEAD+16)==0 or get(o,HEAD+40)==0:
                return isolate(o,w,2,23)
            if status!=0:
                within(o,PERROR,HEAD+16,24)
                put(o,ERROR_N,get(o,HEAD+40))
                put(o,ERROR_FORMAT,status)
                put(o,ERROR,1)
                return again(o,1000)
            within(o,PNORM,HEAD+16,24)
            put(o,NN,get(o,HEAD+40))
            if get(o,OP)==1:
                return again(o,1000)
            request(o,BREQUEST,6)
            within(o,RQ+24,PNORM,24)
            return payload(o,w,23,128)
        if status==5 or status==6 or status==7 or status==8:
            return fail(o,status,get(o,HEAD+48))
        return isolate(o,w,2,24)
    if phase==23:
        if payload_ok(o)==False or get(o,RP+40)!=get(o,NN) or get(o,RP+64)==0 or get(o,NN)<64:
            return fail(o,7,25)
        put(o,NORM_PTR,get(o,RP+64))
        return memory(o,24,0,get(o,NORM_PTR),3,NORM_HEADER,64)
    if phase==24:
        on=get(o,NORM_HEADER+32)
        cn=get(o,NORM_HEADER+40)
        if get(o,NORM_HEADER)!=NORM or get(o,NORM_HEADER+8)!=0 or get(o,NORM_HEADER+16)!=0 or get(o,NORM_HEADER+24)>4 or get(o,NORM_HEADER+48)!=0 or get(o,NORM_HEADER+56)!=0:
            return fail(o,7,26)
        if on==0 or on>8388608 or cn==0 or cn>8388608 or on>get(o,NN)-64 or cn!=get(o,NN)-64-on:
            return fail(o,7,27)
        put(o,ORIGINAL_N,on)
        put(o,ORIGINAL_PTR,get(o,NORM_PTR)+64)
        put(o,CORE_N,cn)
        put(o,CORE_PTR,get(o,NORM_PTR)+64+on)
        request(o,VREQUEST,5)
        copy_source(s,o,48,RQ+24,24)
        return value(o,w,25,128)
    if phase==25:
        if value_ok(o)==False or get(o,RP+24)==0:
            return fail(o,value_failure(o),25)
        within(o,FUNCTION,RP+24,24)
        request(o,VREQUEST,7)
        within(o,RQ+24,FUNCTION,24)
        return value(o,w,26,128)
    if phase==26:
        if value_ok(o)==False:
            return fail(o,value_failure(o),26)
        if get(o,RP+16)!=4 or get(o,RP+72)>get(o,CORE_N):
            return reject(o,6)
        put(o,FUNCTION_N,get(o,RP+72))
        zero(o,SMALL,128)
        return invoke(o,100,get(w,88),816,get(o,CORE_PTR),get(o,CORE_N),HEAD,64,SMALL,128)
    return fail(o,7,phase)

def selection(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FEEDBACK)!=0 or get(o,HEAD)!=SIZES or get(o,HEAD+48)!=get(o,CORE_N) or get(o,HEAD+56)!=0:
            return fail(o,7,100)
        if get(o,HEAD+8)==0 or get(o,HEAD+32)<64 or get(o,HEAD+40)<128:
            return fail(o,7,101)
        put(o,NODES,get(o,HEAD+8))
        put(o,KEYS,get(o,HEAD+16))
        put(o,DEPTH,get(o,HEAD+24))
        put(o,ARENA_CAP,get(o,HEAD+32))
        wn=get(o,HEAD+40)
        if wn<get(o,NODES):
            wn=get(o,NODES)
        put(o,WORK_N,wn)
        return mapping(o,101,get(o,ARENA_CAP))
    if phase==101:
        if bad_pointer(get(o,FEEDBACK)):
            return fail(o,5,get(o,FEEDBACK))
        put(o,ARENA_PTR,get(o,FEEDBACK))
        return mapping(o,102,get(o,WORK_N))
    if phase==102:
        if bad_pointer(get(o,FEEDBACK)):
            return fail(o,5,get(o,FEEDBACK))
        put(o,WORK_PTR,get(o,FEEDBACK))
        zero(o,SMALL,128)
        put(o,SMALL+48,get(o,NODES))
        put(o,SMALL+56,get(o,DEPTH))
        put(o,SMALL+96,get(o,KEYS))
        put(o,SMALL+104,1)
        return memory(o,103,3,SMALL,0,get(o,WORK_PTR),128)
    if phase==103:
        return invoke(o,104,get(w,88),0,get(o,CORE_PTR),get(o,CORE_N),get(o,ARENA_PTR),get(o,ARENA_CAP),get(o,WORK_PTR),get(o,WORK_N))
    if phase==104:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,get(o,FEEDBACK))
        return memory(o,105,0,get(o,ARENA_PTR),3,HEAD,64)
    if phase==105:
        an=get(o,HEAD+24)
        if an<64 or an>get(o,ARENA_CAP) or get(o,HEAD+8)==0 or get(o,HEAD+8)>get(o,NODES):
            return fail(o,7,105)
        put(o,ARENA_N,an)
        cn=get(o,CORE_N)
        fn=get(o,FUNCTION_N)
        if an>MAX-128-cn or fn>MAX-128-cn-an:
            return fail(o,5,106)
        put(o,FRAME_N,128+cn+an+fn)
        return mapping(o,106,get(o,FRAME_N))
    if phase==106:
        if bad_pointer(get(o,FEEDBACK)):
            return fail(o,5,get(o,FEEDBACK))
        put(o,FRAME,get(o,FEEDBACK))
        zero(o,CHECK_HEADER,128)
        put(o,CHECK_HEADER,CHECK_REQUEST)
        put(o,CHECK_HEADER+16,get(o,CORE_N))
        put(o,CHECK_HEADER+24,get(o,ARENA_N))
        put(o,CHECK_HEADER+32,get(o,FUNCTION_N))
        return memory(o,107,3,CHECK_HEADER,0,get(o,FRAME),128)
    if phase==107:
        return memory(o,108,0,get(o,CORE_PTR),0,get(o,FRAME)+128,get(o,CORE_N))
    if phase==108:
        put(o,CURSOR,0)
        return memory(o,109,0,get(o,ARENA_PTR),0,get(o,FRAME)+128+get(o,CORE_N),get(o,ARENA_N))
    if phase==109:
        remaining=get(o,FUNCTION_N)-get(o,CURSOR)
        if remaining==0:
            return check(o,112,get(o,FRAME),get(o,FRAME_N),get(o,WORK_PTR),get(o,WORK_N),48)
        n=remaining
        if n>8192:
            n=8192
        put(o,CHUNK,n)
        request(o,VREQUEST,19)
        within(o,RQ+24,FUNCTION,24)
        put(o,RQ+104,get(o,CURSOR))
        put(o,RQ+112,n)
        return value(o,w,110,128)
    if phase==110:
        if value_ok(o)==False or get(o,RP+16)!=4 or get(o,RP+56)!=get(o,CURSOR) or get(o,RP+64)!=get(o,CHUNK) or get(o,RP+72)!=get(o,FUNCTION_N):
            return fail(o,7,110)
        at=get(o,FRAME)+128+get(o,CORE_N)+get(o,ARENA_N)+get(o,CURSOR)
        return memory(o,111,3,RP+8192,0,at,get(o,CHUNK))
    if phase==111:
        put(o,CURSOR,get(o,CURSOR)+get(o,CHUNK))
        return again(o,109)
    if phase==112:
        if check_reply(o)==False:
            return fail(o,7,112)
        if get(o,HEAD+8)!=0:
            if get(o,HEAD+16)!=6:
                return fail(o,7,113)
            return reject(o,6)
        return system(o,113,11,0,get(o,FRAME),get(o,FRAME_N),0,0,0,0)
    if phase==113:
        if get(o,FEEDBACK)!=0:
            return isolate(o,w,1,get(o,FEEDBACK))
        zero(o,FRAME,16)
        request(o,choose(get(o,PUBLIC_INPUT)!=0,MCAPTURE,MREQUEST),3)
        copy_source(s,o,72,RQ+16,24)
        return provider(o,w,200)
    return fail(o,7,phase)

def runtime_binding(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if provider_reply(o)==False:
            return isolate(o,w,2,200)
        status=get(o,RP+8)
        if get(o,RP+40)!=0:
            if get(o,RP+16)!=3 or get(o,RUNTIME)!=0:
                return isolate(o,w,2,201)
            within(o,RUNTIME,RP+40,24)
        if get(o,PUBLIC_INPUT)!=0:
            if get(o,RP+80)!=0:
                return isolate(o,w,2,200)
            if get(o,RP+88)!=0:
                put(o,PROVIDER_PENDING,1)
                return isolate(o,w,choose(get(o,RP+72)==1,1,2),200)
            if get(o,RP+72)!=1:
                return isolate(o,w,2,200)
        if status!=0:
            return fail(o,choose(status==2,5,7),status)
        if get(o,RP+16)!=3 or get(o,RP+24)!=0 or get(o,RP+32)!=0 or get(o,RUNTIME)==0:
            return isolate(o,w,2,201)
        request(o,choose(get(o,PUBLIC_INPUT)!=0,MTYPED,MREQUEST),1)
        within(o,RQ+16,RUNTIME,24)
        return provider(o,w,201)
    if phase==201:
        if provider_reply(o)==False:
            return isolate(o,w,2,202)
        status=get(o,RP+8)
        if get(o,RP+40)!=0:
            within(o,PSNAPSHOT,RP+40,24)
            put(o,SNAP_PTR,get(o,RP+24))
            put(o,SNAP_N,get(o,RP+32))
        if get(o,PUBLIC_INPUT)!=0:
            if get(o,RP+80)!=0:
                return isolate(o,w,2,202)
            if get(o,RP+88)!=0:
                put(o,PROVIDER_PENDING,1)
                return isolate(o,w,choose(get(o,RP+72)==1,1,2),202)
            if get(o,RP+72)!=1:
                return isolate(o,w,2,202)
        if status!=0:
            if status==1 and get(o,PSNAPSHOT)!=0 and get(o,SNAP_PTR)!=0 and get(o,SNAP_N)!=0:
                put(o,ERROR_FORMAT,3)
                put(o,ERR_PTR,get(o,SNAP_PTR))
                put(o,ERR_N,get(o,SNAP_N))
                return again(o,710)
            return fail(o,choose(status==2,5,7),status)
        if get(o,RP+16)!=1 or get(o,PSNAPSHOT)==0 or get(o,SNAP_PTR)==0 or get(o,SNAP_N)<256:
            return fail(o,7,203)
        return memory(o,202,0,get(o,SNAP_PTR),3,SNAP_HEADER,256)
    if phase==202:
        n=get(o,SNAP_N)
        gn=get(o,SNAP_HEADER+24)
        en=get(o,SNAP_HEADER+32)
        if get(o,SNAP_HEADER)!=SNAPSHOT or get(o,SNAP_HEADER+8)!=0 or get(o,SNAP_HEADER+16)>7 or get(o,SNAP_HEADER+40)!=n or get(o,SNAP_HEADER+48)!=0 or get(o,SNAP_HEADER+56)!=0 or gn>n-256 or en!=n-256-gn:
            return fail(o,7,204)
        i=224
        while i<256:
            if get(o,SNAP_HEADER+i)!=0:
                return fail(o,7,205)
            i=i+8
        if (get(o,SNAP_HEADER+16)&1)!=0 or (get(o,SNAP_HEADER+16)&2)==0:
            return reject(o,7)
        return hash_start(o,get(o,CORE_PTR),get(o,CORE_N),CORE_SHA,203)
    if phase==203:
        if same_bytes(o,SNAP_HEADER+64,CORE_SHA,32)==False:
            return reject(o,7)
        return hash_start(o,get(o,ORIGINAL_PTR),get(o,ORIGINAL_N),INPUT_SHA,204)
    if phase==204:
        if get(o,SNAP_N)>MAX-128:
            return fail(o,5,206)
        put(o,FRAME_N,128+get(o,SNAP_N))
        return mapping(o,205,get(o,FRAME_N))
    if phase==205:
        if bad_pointer(get(o,FEEDBACK)):
            return fail(o,5,get(o,FEEDBACK))
        put(o,FRAME,get(o,FEEDBACK))
        zero(o,CHECK_HEADER,128)
        put(o,CHECK_HEADER,CHECK_REQUEST)
        put(o,CHECK_HEADER+8,1)
        put(o,CHECK_HEADER+40,get(o,SNAP_N))
        within(o,CHECK_HEADER+64,CORE_SHA,32)
        within(o,CHECK_HEADER+96,INPUT_SHA,32)
        return memory(o,206,3,CHECK_HEADER,0,get(o,FRAME),128)
    if phase==206:
        return memory(o,207,0,get(o,SNAP_PTR),0,get(o,FRAME)+128,get(o,SNAP_N))
    if phase==207:
        return check(o,208,get(o,FRAME),get(o,FRAME_N),SMALL,128,816)
    if phase==208:
        if check_reply(o)==False:
            return fail(o,7,208)
        if get(o,HEAD+8)!=0:
            id=get(o,HEAD+16)
            if id!=7 and id!=9:
                return fail(o,7,209)
            return reject(o,id)
        put(o,SUCCESS,1)
        return again(o,1000)
    return fail(o,7,phase)

def hash_start(o:mutbuf,ptr:u64,n:u64,dest:u64,after:u64) -> u32:
    put(o,HPTR,ptr)
    put(o,HN,n)
    put(o,HDST,dest)
    put(o,HAFTER,after)
    put(o,HCURSOR,0)
    return again(o,600)
def hashing(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        store(o,HBUF,0)
        return invoke(o,601,get(w,96),307,HBUF,1,HOUT,32,8192,1184)
    if phase==601:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,601)
        return again(o,602)
    if phase==602:
        n=get(o,HN)-get(o,HCURSOR)
        if n==0:
            store(o,HBUF,2)
            return invoke(o,605,get(w,96),307,HBUF,1,HOUT,32,8192,1184)
        if n>65535:
            n=65535
        put(o,CHUNK,n)
        store(o,HBUF,1)
        return memory(o,603,0,get(o,HPTR)+get(o,HCURSOR),3,HBUF+1,n)
    if phase==603:
        return invoke(o,604,get(w,96),307,HBUF,1+get(o,CHUNK),HOUT,32,8192,1184)
    if phase==604:
        if get(o,FEEDBACK)!=0:
            return fail(o,7,604)
        put(o,HCURSOR,get(o,HCURSOR)+get(o,CHUNK))
        return again(o,602)
    if phase==605:
        if get(o,FEEDBACK)!=32:
            return fail(o,7,605)
        within(o,get(o,HDST),HOUT,32)
        return again(o,get(o,HAFTER))
    return fail(o,7,phase)

def reject(o:mutbuf,id:u64) -> u32:
    put(o,ERRID,id)
    return again(o,700)
def errors(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        n=error_text(o,get(o,ERRID))
        if n==0:
            return fail(o,7,700)
        put(o,ERROR_FORMAT,2)
        request(o,BREQUEST,1)
        put(o,RQ+72,n)
        within(o,RQ+128,ERRBUF,n)
        return payload(o,w,701,128+n)
    if phase==701:
        if payload_ok(o)==False or get(o,RP+16)==0:
            return fail(o,choose(get(o,RP+8)==4,5,7),701)
        within(o,PERROR,RP+16,24)
        put(o,ERROR_N,get(o,RP+40))
        put(o,ERROR,1)
        return again(o,1000)
    if phase==710:
        n=get(o,ERR_N)
        if n>MAX-128:
            return fail(o,5,710)
        put(o,FRAME_N,128+n)
        return mapping(o,711,get(o,FRAME_N))
    if phase==711:
        if bad_pointer(get(o,FEEDBACK)):
            return fail(o,5,get(o,FEEDBACK))
        put(o,FRAME,get(o,FEEDBACK))
        request(o,BREQUEST,1)
        put(o,RQ+72,get(o,ERR_N))
        return memory(o,712,3,RQ,0,get(o,FRAME),128)
    if phase==712:
        return memory(o,713,0,get(o,ERR_PTR),0,get(o,FRAME)+128,get(o,ERR_N))
    if phase==713:
        return invoke(o,701,get(w,40),48,get(o,FRAME),get(o,FRAME_N),RP,512,get(w,48),get(w,56))
    return fail(o,7,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        if get(o,PROVIDER_PENDING)!=0:
            if get(o,OP)!=1:
                return isolate(o,w,1,1060)
            request(o,MTYPED,6)
            return provider(o,w,1060)
        if get(o,VERIFY_ACTIVE)!=0:
            if get(o,VERIFY_ACTIVE)!=1 or get(o,OP)!=1:
                return isolate(o,w,2,1000)
            request(o,choose(get(o,FAMILY)==0,YREQUEST,YVERIFIED),1)
            put(o,VERIFY_ACTIVE,2)
            return invoke(o,21,get(w,32),259,RQ,128,get(o,NESTED),262144,4096,4096)
        if get(o,SUCCESS)==0 or get(o,ERROR)!=0:
            if get(o,FUNCTION)!=0:
                release_begin(o)
                request(o,VALUE_DROP_INPUT,29)
                within(o,RQ+24,FUNCTION,24)
                return value(o,w,1001,128)
        put(o,CLEAN,0)
        return again(o,1010)
    if phase==1001:
        if release_value(o,FUNCTION)==0:
            return drop_isolate(o,w,1001)
        put(o,CLEAN,0)
        return again(o,1010)
    if phase==1010:
        i=get(o,CLEAN)
        if i==2:
            return again(o,1020)
        at=choose(i==0,PNORM,PERROR)
        keep=(i==0 and get(o,SUCCESS)!=0 and get(o,ERROR)==0) or (i==1 and get(o,ERROR)==1)
        if keep or get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,1010)
        put(o,DESTROY_AT,at)
        request(o,BREQUEST,3)
        within(o,RQ+24,at,24)
        return payload(o,w,1011,128)
    if phase==1011:
        if payload_ok(o)==False:
            known=valid(o,RP,BREPLY)!=0 and (get(o,RP+8)==1 or get(o,RP+8)==5 or get(o,RP+8)==6)
            return isolate(o,w,choose(known,1,2),1011)
        zero(o,get(o,DESTROY_AT),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,1010)
    if phase==1020:
        if get(o,PSNAPSHOT)!=0:
            request(o,choose(get(o,PUBLIC_INPUT)!=0,MTYPED,MREQUEST),5)
            within(o,RQ+40,PSNAPSHOT,24)
            return provider(o,w,1021)
        return again(o,1030)
    if phase==1021:
        if get(o,PUBLIC_INPUT)!=0:
            pending=provider_release(o,PSNAPSHOT)
            if pending!=0:
                return isolate(o,w,pending,1021)
        elif provider_ack(o)==False:
            return isolate(o,w,2,1021)
        zero(o,PSNAPSHOT,24)
        return again(o,1030)
    if phase==1030:
        if (get(o,SUCCESS)==0 or get(o,ERROR)!=0) and get(o,RUNTIME)!=0:
            request(o,choose(get(o,PUBLIC_INPUT)!=0,MTYPED,MREQUEST),4)
            within(o,RQ+16,RUNTIME,24)
            return provider(o,w,1031)
        put(o,CLEAN,0)
        return again(o,1040)
    if phase==1031:
        if get(o,PUBLIC_INPUT)!=0:
            pending=provider_release(o,RUNTIME)
            if pending!=0:
                return isolate(o,w,pending,1031)
        elif provider_ack(o)==False:
            return isolate(o,w,2,1031)
        zero(o,RUNTIME,24)
        put(o,CLEAN,0)
        return again(o,1040)
    if phase==1040:
        i=get(o,CLEAN)
        if i==4:
            return again(o,1050)
        at=FRAME
        n=get(o,FRAME_N)
        if i==1:
            at=ARENA_PTR
            n=get(o,ARENA_CAP)
        elif i==2:
            at=WORK_PTR
            n=get(o,WORK_N)
        elif i==3:
            at=NESTED
            n=get(o,NESTED_N)
        if get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,1040)
        put(o,DESTROY_AT,at)
        return system(o,1041,11,0,get(o,at),n,0,0,0,0)
    if phase==1041:
        if get(o,FEEDBACK)!=0:
            return isolate(o,w,1,get(o,FEEDBACK))
        put(o,get(o,DESTROY_AT),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,1040)
    if phase==1050:
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return value(o,w,1051,128)
        return finish(o,w,get(o,ERROR))
    if phase==1051:
        if release_value_retry(o)==0:
            return drop_isolate(o,w,1051)
        return finish(o,w,get(o,ERROR))
    if phase==1060:
        pending=provider_release_retry(o)
        if pending!=0:
            return isolate(o,w,pending,1060)
        return again(o,1000)
    return isolate(o,w,2,phase)

def drop_isolate(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    known=get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)==1
    kind=choose(known,1,2)
    return isolate(o,w,kind,detail)
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,1000)
def isolate(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    if get(o,ERROR)==0 and get(o,SUCCESS)==0:
        put(o,ERROR,9)
    put(o,DETAIL,detail)
    put(o,QUAR,kind)
    to_work(o,w,128,256,1920)
    put(w,192,1)
    put(w,208,kind)
    return finish(o,w,9)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    quarantined=get(o,QUAR)
    detail=get(o,DETAIL)
    zero(o,0,128)
    zero(o,128,128)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0 and get(o,SUCCESS)!=0:
        within(o,16,PNORM,24)
        put(o,40,get(o,NN))
        within(o,48,RUNTIME,24)
        within(o,72,FUNCTION,24)
        within(o,144,CORE_SHA,32)
        within(o,176,INPUT_SHA,32)
        zero(o,PNORM,24)
        zero(o,RUNTIME,24)
        zero(o,FUNCTION,24)
        put(o,SUCCESS,0)
    elif status==1:
        within(o,96,PERROR,24)
        put(o,120,get(o,ERROR_N))
        put(o,128,get(o,ERROR_FORMAT))
        zero(o,PERROR,24)
    put(o,208,quarantined)
    put(o,216,detail)
    if status!=9 and get(w,192)==0:
        put(w,208,0)
    return 0
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,32768,get(w,16),get(w,24))
def payload(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,40),51,RQ,n,RP,512,get(w,48),get(w,56))
def provider(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,64),51,RQ,128,RP,128,get(w,72),get(w,80))
def check(o:mutbuf,next:u64,sp:u64,sn:u64,wp:u64,wn:u64,mask:u64) -> u32:
    invoke(o,next,0,mask,sp,sn,HEAD,128,wp,wn)
    return 11
def value_ok(o:mutbuf) -> bool:
    return valid(o,RP,VREPLY)!=0 and get(o,RP+8)==0
def payload_ok(o:mutbuf) -> bool:
    return valid(o,RP,BREPLY)!=0 and get(o,RP+8)==0
def value_failure(o:mutbuf) -> u64:
    return choose(valid(o,RP,VREPLY)!=0 and get(o,RP+8)==5,5,6)
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def provider_reply(o:mutbuf) -> bool:
    if get(o,PUBLIC_INPUT)!=0:
        return provider_typed_valid(o) and get(o,RP+64)==0
    if valid(o,RP,MREPLY)==0 or get(o,RP+8)>3 or get(o,RP+64)!=0:
        return False
    at=72
    while at<128:
        if get(o,RP+at)!=0:
            return False
        at=at+8
    return True
def provider_ack(o:mutbuf) -> bool:
    if provider_reply(o)==False or get(o,RP+8)!=0 or get(o,RP+16)!=4:
        return False
    at=24
    while at<64:
        if get(o,RP+at)!=0:
            return False
        at=at+8
    return True
def check_reply(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,HEAD)!=CHECK_REPLY or get(o,HEAD+8)>1:
        return False
    at=24
    while at<128:
        if get(o,HEAD+at)!=0:
            return False
        at=at+8
    return (get(o,HEAD+8)==0)==(get(o,HEAD+16)==0)
def same_bytes(o:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(o,a+i)!=byte(o,b+i):
            return False
        i=i+1
    return True
def bad_pointer(n:u64) -> bool:
    return n==0 or n>=NEGATIVE
'''

def source_program():
    names={'mapping','request','invoke','memory','system','again','to_work','from_work',
           'copy_source','within','zero','get','put','choose'}
    helpers='\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body
                      if isinstance(f,ast.FunctionDef)and f.name in names)
    text=SOURCE+'\n'+helpers+'\n'+retirement.selected('release_begin','release_value','release_value_retry')
    text+='\n'+provider_retirement.SOURCE
    text+='\ndef error_text(o:mutbuf,id:u64) -> u64:\n'
    for ident,message in ERRORS.items():
        raw=json.dumps({'class':'BackgroundOptimizationRejected','message':'E_HIA_BACKGROUND: '+message},
                       sort_keys=True,separators=(',',':')).encode()
        text+=f'    if id=={ident}:\n'
        for at in range(0,len(raw),8):
            value=int.from_bytes(raw[at:at+8].ljust(8,b'\0'),'little')
            text+=f'        put(o,ERRBUF+{at},{value})\n'
        text+=f'        return {len(raw)}\n'
    text+='    return 0\n'
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text

def program():return document(source_program(),'background_optimizer_constructor_binding')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_constructor_binding.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),
          sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
