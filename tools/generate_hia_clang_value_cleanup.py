"""Explicit actual-ACK retirement, deferred Value drops and retained failures."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if get(w,A_UNKNOWN)!=0:
        return jump(w,700)
    if phase==800:
        if get(w,A_WHICH_ACTIVE)==1:
            clear(w,A_RQ,32)
            put(w,A_RQ,0x3130485743414948)
            put(w,A_RQ+8,1)
            return a_invoke(w,805,5,a_at(w,A_RQ),32,a_at(w,A_WHICH_OUT),128,a_at(w,A_WHICH_WORK),4096)
        if get(w,A_INNER_ACTIVE)==1 and get(w,A_INNER_RETIRED)==0:
            clear(w,A_RQ,256)
            put(w,A_RQ,choose(get(w,A_ORIGIN_HELD)==1,A_RAW_ORIGIN_REQUEST,A_RAW_REQUEST))
            put(w,A_RQ+8,1)
            return a_invoke(w,801,choose(get(w,A_ORIGIN_HELD)==1,6,2),a_at(w,A_RQ),256,a_at(w,A_INNER_OUT),512,a_at(w,A_INNER_WORK),536870912)
        return jump(w,810)
    if phase==801:
        if get(w,RESULT)!=0 or get(w,A_INNER_OUT)!=A_RAW_REPLY:
            return a_unknown(w,801)
        if get(w,A_INNER_OUT+344)!=1:
            return a_unknown(w,802)
        if get(w,A_INNER_OUT+352)!=1 or get(w,A_INNER_OUT+360)!=0:
            a_clean_error(w,get(w,A_INNER_OUT+368),get(w,A_INNER_OUT+376))
            return jump(w,700)
        put(w,A_INNER_RETIRED,1)
        return jump(w,810)
    if phase==805:
        if get(w,RESULT)!=0 or get(w,A_WHICH_OUT)!=0x3130525743414948 or get(w,A_WHICH_OUT+64)!=1:
            return a_unknown(w,805)
        if get(w,A_WHICH_OUT+72)!=1 or get(w,A_WHICH_OUT+56)!=0:
            a_clean_error(w,16,get(w,A_WHICH_OUT+16))
            return jump(w,700)
        put(w,A_WHICH_ACTIVE,0)
        return jump(w,800)
    if phase==810:
        return maps(o,w)
    if phase==811:
        if get(w,RESULT)!=0:
            a_clean_error(w,12,errno(get(w,RESULT)))
            return jump(w,700)
        clear(w,map_slot(get(w,A_MAP_INDEX)),16)
        put(w,A_MAP_INDEX,get(w,A_MAP_INDEX)+1)
        return maps(o,w)
    if phase==812:
        return origin_close(o,w)
    if phase==813:
        r=get(w,RESULT)
        if failed(r):
            if errno(r)==38:
                put(w,A_CLOSE_METHOD,1)
                return origin_close(o,w)
            a_clean_error(w,12,errno(r))
            return jump(w,700)
        put(w,A_ORIGIN_FD,0)
        put(w,A_ORIGIN_HELD,0)
        return jump(w,820)
    if phase==814:
        if failed(get(w,RESULT)):
            put(w,A_CLOSE_UNKNOWN,1)
            return a_unknown(w,814)
        put(w,A_ORIGIN_FD,0)
        put(w,A_ORIGIN_HELD,0)
        return jump(w,820)
    if phase==820:
        return values(w)
    if phase==821:
        return dropped(w)
    if phase==830:
        if get(w,A_TOKEN_HELD)==0:
            return jump(w,840)
        a_request(w,A_V5,92)
        a_within(w,A_RQ+24,A_TOKEN,24)
        return a_value(w,831,128)
    if phase==831:
        if drop_valid(w)==False:
            return a_unknown(w,831)
        if get(w,A_VR+96)==1:
            clear(w,A_TOKEN,24)
            put(w,A_TOKEN_HELD,0)
        if get(w,A_VR+104)!=0:
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_TOKEN_HELD)!=0:
            a_clean_error(w,16,get(w,A_VR+8))
            return jump(w,700)
        return jump(w,840)
    if phase==840:
        if get(w,A_TOKEN_PENDING)!=0:
            a_request(w,A_V5,93)
            return a_value(w,841,128)
        put(w,A_STATE,5)
        return jump(w,700)
    if phase==841:
        if drop_valid(w)==False or get(w,A_VR+96)!=0:
            return a_unknown(w,841)
        if get(w,A_VR+104)!=0:
            a_clean_error(w,16,get(w,A_VR+8))
            return jump(w,700)
        put(w,A_TOKEN_PENDING,0)
        put(w,A_STATE,5)
        return jump(w,700)
    return 4294967293

def map_slot(index:u64) -> u64:
    if index==0:
        return A_RAW_MAP
    if index==1:
        return A_FS_MAP
    if index==2:
        return A_FRAME
    return A_PATH_MAP

def maps(o:mutbuf,w:mutbuf) -> u32:
    index=get(w,A_MAP_INDEX)
    while index<4:
        at=map_slot(index)
        if get(w,at)!=0:
            put(w,A_MAP_INDEX,index)
            return call(o,w,811,11,get(w,at),get(w,at+8),0,0,0,0,0)
        index=index+1
    return jump(w,812)

def origin_close(o:mutbuf,w:mutbuf) -> u32:
    if get(w,A_ORIGIN_HELD)==0:
        return jump(w,820)
    if get(w,A_CLOSE_UNKNOWN)!=0:
        return a_unknown(w,812)
    fd=get(w,A_ORIGIN_FD)
    if get(w,A_CLOSE_METHOD)==1:
        return call(o,w,814,3,fd,0,0,0,0,0,0)
    return call(o,w,813,436,fd,fd,0,0,0,0,0)

def values(w:mutbuf) -> u32:
    index=get(w,A_CLEAN_INDEX)
    while index<40:
        if get(w,A_REFS+index*32+24)==1:
            put(w,A_CLEAN_INDEX,index)
            a_request(w,A_V5,78)
            a_arg(w,index,24)
            return a_value(w,821,128)
        index=index+1
    return jump(w,830)

def drop_valid(w:mutbuf) -> bool:
    return get(w,RESULT)==0 and get(w,A_VR)==A_R2 and get(w,A_VR+88)==1 and get(w,A_VR+96)<=1 and get(w,A_VR+80)<=1 and get(w,A_VR+104)<=1 and get(w,A_VR+112)<=1 and get(w,A_VR+120)==1

def dropped(w:mutbuf) -> u32:
    if drop_valid(w)==False:
        return a_unknown(w,821)
    consumed=get(w,A_VR+96)
    if consumed==1:
        clear(w,A_REFS+get(w,A_CLEAN_INDEX)*32,32)
        put(w,A_CLEAN_INDEX,get(w,A_CLEAN_INDEX)+1)
    if get(w,A_VR+104)!=0:
        put(w,A_TOKEN_PENDING,1)
    if consumed==0:
        a_clean_error(w,16,get(w,A_VR+8))
        return jump(w,700)
    return jump(w,820)
'''
if __name__=='__main__':write_module('clang_value_cleanup',SOURCE)
