"""Native log cleanup preserves exact consumed, mapping and unknown facts."""
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==2500:
        index=get(w,L_CLEAN_INDEX)
        while index!=0:
            index=index-1
            put(w,L_CLEAN_INDEX,index)
            if get(w,L_REFS+index*32+24)!=0:
                return l_drop(w,2501,index)
        if get(w,L_VALUE_PENDING)!=0:
            l_request(w,L_Q5,93)
            return l_value(w,2502,128)
        return jump(w,2510)
    if phase==2501:
        if l_dropped(w,get(w,L_CLEAN_INDEX))==False:
            return log_pending(w,2501)
        return jump(w,2500)
    if phase==2502:
        if l_valid(w,L_V2)==False or get(w,L_VR+88)!=1 or get(w,L_VR+104)>1 or get(w,L_VR+112)>1 or get(w,L_VR+120)!=1:
            put(w,L_UNKNOWN,1)
            return log_pending(w,2502)
        put(w,L_VALUE_PENDING,get(w,L_VR+104))
        put(w,L_QUEUE,get(w,L_QUEUE)|get(w,L_VR+112))
        if get(w,L_VALUE_PENDING)!=0:
            return log_pending(w,2502)
        return jump(w,2510)
    if phase==2510:
        if get(w,L_FD_UNKNOWN)!=0:
            return log_pending(w,2510)
        if get(w,L_FD_HELD)!=0:
            return call(o,w,2511,436,get(w,L_FD),get(w,L_FD),0,0,0,0,0)
        return jump(w,2520)
    if phase==2511:
        if r==NONE-37:
            return call(o,w,2512,3,get(w,L_FD),0,0,0,0,0,0)
        if r!=0:
            return log_pending(w,errno(r))
        put(w,L_FD_HELD,0)
        put(w,L_FD,0)
        return jump(w,2520)
    if phase==2512:
        if r!=0:
            put(w,L_FD_UNKNOWN,1)
            put(w,L_UNKNOWN,1)
            return log_pending(w,errno(r))
        put(w,L_FD_HELD,0)
        put(w,L_FD,0)
        return jump(w,2520)
    if phase==2520:
        if get(w,L_CWD_ACTIVE)==0:
            put(w,L_MAP_INDEX,0)
            return jump(w,2530)
        clear(w,L_RQ,32)
        put(w,L_RQ,L_CWD_REQUEST)
        put(w,L_RQ+8,1)
        return p_invoke(w,2521,R_LOG_CWD,p_at(w,L_RQ),32,p_at(w,L_VR),128,p_at(w,L_CWD_WORK),200704)
    if phase==2521:
        if r!=0 or get(w,L_VR)!=L_CWD_REPLY or get(w,L_VR+72)!=0:
            put(w,L_UNKNOWN,1)
            return log_pending(w,2521)
        if get(w,L_VR+56)!=0:
            return log_pending(w,2521)
        put(w,L_CWD_ACTIVE,0)
        put(w,L_MAP_INDEX,0)
        return jump(w,2530)
    if phase==2530:
        index=get(w,L_MAP_INDEX)
        while index<6:
            slot=L_IN+index*16
            if get(w,slot)!=0:
                put(w,L_MAP_INDEX,index)
                return call(o,w,2531,11,get(w,slot),get(w,slot+8),0,0,0,0,0)
            index=index+1
        return jump(w,2540)
    if phase==2531:
        if r!=0:
            return log_pending(w,errno(r))
        slot=L_IN+get(w,L_MAP_INDEX)*16
        put(w,slot,0)
        put(w,slot+8,0)
        put(w,L_MAP_INDEX,get(w,L_MAP_INDEX)+1)
        return jump(w,2530)
    if phase==2540:
        if get(w,L_RETIRING)!=0 and l_logger(w) and get(w,L_LOG_CLOSED)==0:
            clear(w,L_RQ,128)
            put(w,L_RQ,L_LOG_REQUEST)
            put(w,L_RQ+8,3)
            return p_invoke(w,2541,R_LOG_OWNER,p_at(w,L_RQ),128,p_at(w,L_VR),128,p_at(w,L_LOG_WORK),65536)
        return log_complete(w)
    if phase==2541:
        if r!=0 or get(w,L_VR)!=L_LOG_REPLY or get(w,L_VR+88)!=1 or get(w,L_VR+72)!=0:
            put(w,L_UNKNOWN,1)
            return log_pending(w,2541)
        put(w,L_QUEUE,get(w,L_QUEUE)|get(w,L_VR+112))
        if get(w,L_VR+96)!=1 or get(w,L_VR+48)!=0 or get(w,L_VR+56)!=0 or get(w,L_VR+64)!=0 or get(w,L_VR+104)!=0:
            return log_pending(w,2541)
        put(w,L_LOG_CLOSED,1)
        return log_complete(w)
    return 4294967293

def log_pending(w:mutbuf,detail:u64) -> u32:
    put(w,P_CLEAN_ERROR,E_CLEANUP)
    put(w,P_CLEAN_ERRNO,detail)
    if get(w,L_UNKNOWN)!=0:
        put(w,P_UNKNOWN,1)
    put(w,L_RETIRING,1)
    return jump(w,999)

def log_complete(w:mutbuf) -> u32:
    if get(w,L_UNKNOWN)!=0:
        return log_pending(w,2590)
    put(w,L_ACTIVE,0)
    put(w,RESULT,0)
    if get(w,L_ERROR)!=0:
        return p_fail(w,get(w,L_ERROR),get(w,L_DETAIL))
    return jump(w,get(w,L_NEXT))
'''
if __name__=='__main__':write_module('clang_origin_log_retire',SOURCE)
