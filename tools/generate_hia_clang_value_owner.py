"""Actual private bind, public byte handoff and exception capability transfer."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        return bound(s,o,w)
    if phase==2:
        return origin_duplicated(o,w)
    if phase==3:
        return origin_stated(o,w)
    if phase>=200 and phase<400:
        return 104
    if phase>=100 and phase<200:
        return 100
    if phase>=500 and phase<700:
        return 101
    if phase==700:
        return finish(o,w)
    if phase>=800 and phase<1000:
        return 102
    if phase>=1000 and phase<1200:
        return 103
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    mode=get(w,A_MODE)
    if mode==0:
        if get(w,A_STATE)!=0:
            return 4294967293
        put(w,A_STATE,6)
        a_request(w,A_V6,21)
        return a_value(w,1,128)
    if mode>=3:
        return exception(s,o,w)
    if mode==2:
        if get(w,A_STATE)==5:
            return finish(o,w)
        if get(w,A_STATE)==0:
            return 4294967293
        put(w,A_STATE,4)
        put(w,A_CLEAN_ERROR,0)
        put(w,A_CLEAN_ERRNO,0)
        put(w,A_CLEAN_INDEX,0)
        put(w,A_MAP_INDEX,0)
        return jump(w,800)
    if get(w,A_STATE)!=1:
        return 4294967293
    if length(s)<256 or (word(s,0)!=A_REQUEST and word(s,0)!=A_PUBLIC_REQUEST) or word(s,8)!=0:
        return 4294967293
    cn=word(s,40)
    an=word(s,48)
    pn=word(s,56)
    structured=word(s,88)
    if cn==0 or cn>8388608 or an>5136 or pn==0 or structured!=0:
        return 4294967293
    if cn>length(s)-256 or an>length(s)-256-cn or pn!=length(s)-256-cn-an:
        return 4294967293
    if word(s,64)==0:
        return 4294967293
    if word(s,0)==A_REQUEST:
        if word(s,16)!=0:
            return 4294967293
    elif word(s,16)>2 or word(s,24)>1 or word(s,32)>1:
        return 4294967293
    i=96
    while i<256:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    if word(s,0)==A_PUBLIC_REQUEST:
        put(w,A_TARGET,word(s,16))
        put(w,A_COMPILE_KIND,word(s,24))
        put(w,A_LAYOUT,word(s,32))
    put(w,A_CORE_N,cn)
    put(w,A_ABI_N,an)
    put(w,A_PATH_N,pn)
    put(w,A_STRUCTURED_N,structured)
    put(w,A_STATE,2)
    put(w,ERROR,0)
    put(w,ERROR_NO,0)
    a_request(w,A_V5,91)
    i=0
    while i<24:
        store(w,A_RQ+24+i,byte(s,64+i))
        i=i+1
    return a_value(w,100,128)

def bound(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,A_BIND_REPLY)
    if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1:
        put(w,A_UNKNOWN,1)
        put(o,8,19)
        return 0
    if get(w,A_VR+24)!=0:
        a_within(w,A_TOKEN,A_VR+24,24)
        put(w,A_TOKEN_HELD,1)
    if get(w,A_VR+8)!=0 or get(w,A_TOKEN_HELD)!=1:
        put(o,8,16)
        put(o,16,get(w,A_VR+8))
        put(o,88,1)
        return 0
    if word(s,0)==A_BIND2:
        return call(o,w,2,72,word(s,40),1030,0,0,0,0,0)
    return bound_success(o,w)

def bound_success(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,A_BIND_REPLY)
    put(w,A_STATE,1)
    put(o,88,1)
    put(o,96,1)
    return 0

def bound_error(o:mutbuf,w:mutbuf,error:u64,detail:u64) -> u32:
    clear(o,0,128)
    put(o,0,A_BIND_REPLY)
    put(o,8,error)
    put(o,16,detail)
    put(o,88,1)
    return 0

def origin_duplicated(o:mutbuf,w:mutbuf) -> u32:
    r=get(w,RESULT)
    if failed(r):
        return bound_error(o,w,12,errno(r))
    put(w,A_ORIGIN_FD,r)
    put(w,A_ORIGIN_HELD,1)
    clear(w,A_STAT,144)
    return call(o,w,3,5,r,a_at(w,A_STAT),0,0,0,0,0)

def origin_stated(o:mutbuf,w:mutbuf) -> u32:
    if failed(get(w,RESULT)):
        return bound_error(o,w,12,errno(get(w,RESULT)))
    if (get(w,A_STAT+24)&61440)!=16384:
        return bound_error(o,w,12,20)
    return bound_success(o,w)

def exception(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word(s,0)!=A_EXCEPTION or word(s,8)>1:
        return 4294967293
    i=16
    while i<128:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    clear(o,0,128)
    put(o,0,A_EXCEPTION_REPLY)
    put(o,88,choose(get(w,A_UNKNOWN)==0,1,0))
    put(o,104,get(w,A_CLEAN_ERROR))
    if get(w,A_REFS+15*32+24)==1:
        put(o,16,2)
        if word(s,8)==0:
            i=0
            while i<24:
                store(o,24+i,byte(w,A_REFS+15*32+i))
                i=i+1
            clear(w,A_REFS+15*32,32)
            put(o,96,1)
    return 0

def finish(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,512)
    if get(w,A_INNER_ACTIVE)==1:
        i=0
        while i<512:
            store(o,i,byte(w,A_INNER_OUT+i))
            i=i+1
        n=get(w,A_INNER_OUT+80)
        if n>1048576 or n>length(o)-512:
            return 4294967293
        i=0
        while i<n:
            store(o,512+i,byte(w,A_INNER_OUT+512+i))
            i=i+1
    else:
        put(o,88,NONE)
        put(o,96,NONE)
        put(o,56,get(w,A_CORE_N))
        put(o,64,get(w,A_ABI_N))
        put(o,72,get(w,A_PATH_N))
    put(o,0,A_REPLY)
    if get(w,ERROR)!=0:
        put(o,8,get(w,ERROR))
        put(o,16,get(w,ERROR_NO))
    if get(w,A_INNER_ACTIVE)==1 and get(w,A_INNER_RETIRED)==0:
        put(o,104,get(w,A_INNER_WORK+288))
        i=0
        while i<32:
            store(o,128+i,byte(w,A_INNER_WORK+1664+i))
            i=i+1
        put(o,320,get(w,A_INNER_WORK+1696))
        put(o,328,get(w,A_INNER_WORK+296))
    else:
        clear(o,104,8)
        clear(o,128,32)
        clear(o,320,16)
    clear(o,384,128)
    complete=get(w,A_STATE)==5 and get(w,A_UNKNOWN)==0
    put(o,336,choose(complete,0,choose(get(w,A_UNKNOWN)==0,1,2)))
    put(o,344,choose(get(w,A_UNKNOWN)==0,1,0))
    put(o,352,choose(complete,1,0))
    put(o,360,choose(complete,0,1))
    put(o,368,get(w,A_CLEAN_ERROR))
    put(o,376,get(w,A_CLEAN_ERRNO))
    return 0
'''
if __name__=='__main__':write_module('clang_value_owner',SOURCE)
