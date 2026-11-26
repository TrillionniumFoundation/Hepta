"""Native log initialization and retirement precede arbitrary compiler coercion."""
from tools.generate_hia_clang_value_log_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==2300:
        if word(s,0)!=A_LOG_REQUEST or get(w,A_STATE)!=2:
            return a_unknown(w,2300)
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1 or get(w,A_VR+88)!=1 or get(w,A_VR+96)>1:
            return a_unknown(w,2300)
        if get(w,A_VR+96)==1:
            if a_capture(w,0,A_VR+24)==False:
                return a_unknown(w,2300)
        if get(w,A_VR+8)!=0 or get(w,A_REFS+24)!=1:
            return a_value_failed(w,2300)
        if get(w,A_LOG_WORK)!=0:
            return a_unknown(w,2300)
        clear(w,A_RQ,128)
        clear(w,A_VR,128)
        put(w,A_RQ,A_LOG_BIND)
        put(w,A_RQ+8,get(w,A_VALUE_ENTRY))
        put(w,A_RQ+16,get(w,A_VALUE_WORK))
        put(w,A_RQ+24,get(w,A_VALUE_WORK_N))
        put(w,A_RQ+32,get(w,64))
        i=0
        while i<24:
            store(w,A_RQ+40+i,byte(s,96+i))
            i=i+1
        return alog_call(w,2301,A_LOG_CHILD_BIND)
    if phase==2301:
        if alog_valid(w)==False or alog_bound(w)==False:
            return a_unknown(w,2301)
        if get(w,A_VR+104)!=0 or get(w,A_VR+112)!=0:
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_VR+8)!=0:
            if get(w,A_VR+8)==2:
                return alog_reject(w)
            if get(w,A_VR+8)==5 and (get(w,A_VR+16)==5 or get(w,A_VR+16)==12):
                return a_fail(w,18,12)
            return a_fail(w,16,2301)
        if get(w,A_VR+40)!=1 or get(w,A_VR+48)!=1 or get(w,A_VR+56)!=0 or get(w,A_VR+64)!=0 or get(w,A_VR+104)!=0:
            a_clean_error(w,16,2301)
            return a_fail(w,16,2301)
        put(w,A_SELECTED,0)
        return a_simple(w,101,A_V6,7,0)
    if phase==2302:
        if alog_bound(w)==False:
            return a_unknown(w,2302)
        clear(w,A_RQ,128)
        clear(w,A_VR,128)
        put(w,A_RQ,A_LOG_CALL)
        put(w,A_RQ+8,3)
        return alog_call(w,2303,A_LOG_CHILD_CALL)
    if phase==2303:
        if alog_valid(w)==False:
            return a_unknown(w,2303)
        if get(w,A_VR+104)!=0 or get(w,A_VR+112)!=0:
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_VR+96)!=1 or get(w,A_VR+48)!=0 or get(w,A_VR+56)!=0 or get(w,A_VR+64)!=0 or get(w,A_VR+104)!=0:
            a_clean_error(w,16,get(w,A_VR+8))
            return jump(w,700)
        if alog_live(w):
            return a_unknown(w,2303)
        return jump(w,get(w,A_LOG_RETURN))
    return 4294967293
'''
if __name__=='__main__':write_module('clang_value_log_binding',SOURCE)
