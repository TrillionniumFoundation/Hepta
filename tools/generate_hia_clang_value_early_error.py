"""Private early exception construction under the real active Clang owner lock.

The only caller is a fixed native origin hook after actual capture failure.
The returned capability is borrowed; the log owner must take its own reference.
"""
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PHASE)==513 and get(w,E_EARLY)==0:
        if length(s)==64 and word(s,0)==0x31454c5643414948:
            return begin_log(s,o,w)
        return begin(s,o,w)
    if get(w,E_EARLY)==2 and get(w,PHASE)>=1811 and get(w,PHASE)<=1840:
        return log_step(o,w)
    if get(w,PHASE)==1800 and get(w,E_EARLY)==1:
        return finish_early(o,w)
    if get(w,PHASE)==1803 and get(w,E_EARLY)==1:
        put(w,A_UNKNOWN,1)
        return finish_early(o,w)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)!=128 or length(w)!=A_WORK or word(s,0)!=0x3148455643414948:
        return 4294967293
    i=8
    while i<64:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    if get(w,0)!=A_CONTEXT or get(w,8)!=get(w,A_BASE) or get(w,24)!=A_WORK or get(w,120)!=1:
        return 4294967293
    if get(w,A_TOKEN_HELD)!=1 or get(w,A_STATE)!=2 or get(w,A_INNER_ACTIVE)!=1 or get(w,A_INNER_RETIRED)!=0:
        return 4294967293
    if get(w,ERROR)!=0 or get(w,A_ERROR_SELECTOR)!=0 or get(w,E_STARTED)!=0 or get(w,A_REFS+15*32+24)!=0:
        return 4294967293
    index=get(w,A_INNER_WORK+840)
    if index>2 or get(w,A_INNER_WORK+696)!=843:
        return 4294967293
    error=get(w,A_INNER_WORK+16)
    if error!=choose(index==2,7,4):
        return 4294967293
    at=A_INNER_WORK+2300000+index*256
    if get(w,at)!=0x3130524143414948 or (get(w,at+8)==0 and get(w,at+136)==0 and get(w,at+24)==1):
        return 4294967293
    put(w,E_EARLY_PHASE,get(w,PHASE))
    put(w,E_EARLY_RESULT,get(w,RESULT))
    put(w,E_EARLY_ERROR,get(w,ERROR))
    put(w,E_EARLY_ERRNO,get(w,ERROR_NO))
    put(w,E_EARLY_STATE,get(w,A_STATE))
    put(w,E_EARLY_SELECTOR,get(w,A_ERROR_SELECTOR))
    put(w,E_EARLY_RESERVED,0)
    put(w,E_EARLY,1)
    put(w,E_STARTED,1)
    put(w,ERROR,error)
    put(w,ERROR_NO,10000+get(w,A_INNER_WORK+24))
    put(w,A_ERROR_SELECTOR,get(w,ERROR_NO))
    return jump(w,1200)

def finish_early(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,0x5248455643414948)
    status=0
    if get(w,A_UNKNOWN)!=0:
        status=19
    elif get(w,A_REFS+15*32+24)!=1 or get(w,E_PLAN_INDEX)!=get(w,E_PLAN_COUNT) or get(w,E_BAD)!=0:
        status=16
    put(o,8,status)
    put(o,88,choose(get(w,A_UNKNOWN)==0,1,0))
    put(o,104,get(w,A_CLEAN_ERROR))
    if status==0:
        put(o,16,2)
        i=0
        while i<24:
            store(o,24+i,byte(w,A_REFS+15*32+i))
            i=i+1
    put(w,PHASE,get(w,E_EARLY_PHASE))
    put(w,RESULT,get(w,E_EARLY_RESULT))
    put(w,ERROR,get(w,E_EARLY_ERROR))
    put(w,ERROR_NO,get(w,E_EARLY_ERRNO))
    put(w,A_STATE,get(w,E_EARLY_STATE))
    put(w,A_ERROR_SELECTOR,get(w,E_EARLY_SELECTOR))
    put(w,E_EARLY,0)
    return 0
def begin_log(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)!=128 or length(w)!=A_WORK:
        return 4294967293
    if word(s,8)!=0 or word(s,16)!=0 or word(s,48)!=0 or word(s,56)!=0 or word(s,24)==0:
        return 4294967293
    if get(w,0)!=A_CONTEXT or get(w,8)!=get(w,A_BASE) or get(w,24)!=A_WORK or get(w,120)!=1:
        return 4294967293
    if get(w,A_TOKEN_HELD)!=1 or get(w,A_STATE)!=2 or get(w,A_INNER_ACTIVE)!=1 or get(w,A_INNER_RETIRED)!=0:
        return 4294967293
    if log_reserve(w)==False:
        return 4294967293
    put(w,E_EARLY_PHASE,get(w,PHASE))
    put(w,E_EARLY_RESULT,get(w,RESULT))
    put(w,E_EARLY_ERROR,get(w,ERROR))
    put(w,E_EARLY_ERRNO,get(w,ERROR_NO))
    put(w,E_EARLY_STATE,get(w,A_STATE))
    put(w,E_EARLY_SELECTOR,get(w,A_ERROR_SELECTOR))
    put(w,E_LOG_STATUS,0)
    put(w,E_LOG_COMMIT,0)
    put(w,E_LOG_STARTED,get(w,E_STARTED))
    put(w,E_EARLY,2)
    a_request(w,A_V5,91)
    i=0
    while i<24:
        store(w,A_RQ+24+i,byte(s,24+i))
        i=i+1
    return a_value(w,1811,128)

def log_reserve(w:mutbuf) -> bool:
    i=32
    count=0
    while i<64:
        if get(w,A_REFS+i*32+24)==0:
            put(w,E_LOG_NEW+count*8,i)
            count=count+1
            if count==3:
                return True
        i=i+1
    return False

def log_unknown(o:mutbuf,w:mutbuf) -> u32:
    put(w,A_UNKNOWN,1)
    put(w,E_LOG_STATUS,19)
    return finish_log(o,w)

def log_rejected(o:mutbuf,w:mutbuf) -> u32:
    put(w,E_LOG_STATUS,16)
    return finish_log(o,w)

def log_chain(w:mutbuf) -> u32:
    a_request(w,A_V5,106)
    a_arg(w,get(w,E_LOG_NEW),24)
    if get(w,A_REFS+15*32+24)==1:
        a_arg(w,15,48)
    else:
        a_arg(w,get(w,E_LOG_TMP),48)
    put(w,A_RQ+104,1)
    return a_value(w,1813,128)

def log_drop(w:mutbuf,slot:u64) -> bool:
    if a_cap_drop_valid(w)==False:
        put(w,A_UNKNOWN,1)
        return False
    if get(w,A_VR+96)==1:
        clear(w,A_REFS+slot*32,32)
    if get(w,A_VR+8)!=0 or get(w,A_VR+80)!=0 or get(w,A_VR+104)!=0 or get(w,A_VR+112)!=0:
        a_clean_error(w,16,get(w,A_VR+8))
        put(w,A_TOKEN_PENDING,1)
    return get(w,A_VR+96)==1

def log_commit(w:mutbuf) -> u32:
    if get(w,A_REFS+15*32+24)==1:
        a_within(w,A_REFS+get(w,E_LOG_OLD)*32,A_REFS+15*32,32)
    a_within(w,A_REFS+15*32,A_REFS+get(w,E_LOG_NEW)*32,32)
    clear(w,A_REFS+get(w,E_LOG_NEW)*32,32)
    put(w,E_STARTED,1)
    put(w,E_LOG_COMMIT,1)
    if get(w,A_REFS+get(w,E_LOG_OLD)*32+24)==1:
        return a_simple(w,1816,A_V5,78,get(w,E_LOG_OLD))
    return jump(w,1817)

def log_step(o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==1840:
        return log_unknown(o,w)
    if phase==1811 or phase==1812:
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1:
            return log_unknown(o,w)
        slot=choose(phase==1811,get(w,E_LOG_NEW),get(w,E_LOG_TMP))
        if get(w,A_VR+24)!=0:
            if a_capture(w,slot,A_VR+24)==False:
                return log_unknown(o,w)
        if get(w,A_VR+8)!=0:
            return log_rejected(o,w)
        if get(w,A_REFS+slot*32+24)!=1:
            return log_unknown(o,w)
        if phase==1811 and get(w,A_REFS+15*32+24)==0:
            a_request(w,A_V6,2)
            return a_value(w,1812,128)
        return log_chain(w)
    if phase==1813:
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1 or get(w,A_VR+88)!=1 or get(w,A_VR+96)>1:
            return log_unknown(o,w)
        if get(w,A_VR+96)==1:
            if a_capture(w,get(w,E_LOG_OLD),A_VR+24)==False:
                return log_unknown(o,w)
        elif get(w,A_VR+24)!=0:
            return log_unknown(o,w)
        if get(w,A_VR+8)!=0:
            return log_rejected(o,w)
        if get(w,A_VR+64)!=1 or get(w,A_REFS+get(w,E_LOG_OLD)*32+24)!=1:
            return log_unknown(o,w)
        return a_simple(w,1814,A_V5,78,get(w,E_LOG_OLD))
    if phase==1814 or phase==1815:
        slot=choose(phase==1814,get(w,E_LOG_OLD),get(w,E_LOG_TMP))
        if log_drop(w,slot)==False:
            return log_rejected(o,w)
        if phase==1814 and get(w,A_REFS+get(w,E_LOG_TMP)*32+24)==1:
            return a_simple(w,1815,A_V5,78,get(w,E_LOG_TMP))
        return log_commit(w)
    if phase==1816:
        if log_drop(w,get(w,E_LOG_OLD))==False:
            return log_rejected(o,w)
        return finish_log(o,w)
    if phase==1817:
        return finish_log(o,w)
    return log_unknown(o,w)

def log_pending(w:mutbuf) -> u64:
    if get(w,A_UNKNOWN)!=0 or get(w,A_TOKEN_PENDING)!=0:
        return 1
    i=0
    while i<3:
        if get(w,A_REFS+get(w,E_LOG_NEW+i*8)*32+24)!=0:
            return 1
        i=i+1
    return 0

def finish_log(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,0x52454c5643414948)
    put(o,8,get(w,E_LOG_STATUS))
    if get(w,A_UNKNOWN)!=0:
        put(o,8,19)
    put(o,80,log_pending(w))
    put(o,88,choose(get(w,A_UNKNOWN)==0,1,0))
    put(o,96,get(w,E_LOG_COMMIT))
    put(o,104,get(w,A_CLEAN_ERROR))
    put(o,112,get(w,A_CLEAN_ERRNO))
    if get(w,E_LOG_COMMIT)==1 and get(w,A_REFS+15*32+24)==1:
        put(o,16,2)
        i=0
        while i<24:
            store(o,24+i,byte(w,A_REFS+15*32+i))
            i=i+1
    if get(w,E_LOG_COMMIT)==0:
        put(w,E_STARTED,get(w,E_LOG_STARTED))
    put(w,PHASE,get(w,E_EARLY_PHASE))
    put(w,RESULT,get(w,E_EARLY_RESULT))
    put(w,ERROR,get(w,E_EARLY_ERROR))
    put(w,ERROR_NO,get(w,E_EARLY_ERRNO))
    put(w,A_STATE,get(w,E_EARLY_STATE))
    put(w,A_ERROR_SELECTOR,get(w,E_EARLY_SELECTOR))
    put(w,E_EARLY,0)
    return 0

'''
if __name__=='__main__':write_module('clang_value_early_error',SOURCE)
